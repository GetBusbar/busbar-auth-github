// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-owned login: it holds its own client secret and makes its token exchange through its

use crate::guard::{collect_allowed_hosts, sanitize_hop_header, vet_hop_url, Refused};
use crate::{
    build_github_authorize_url, build_orgs_get, build_orgs_page_get, build_principal,
    build_token_exchange, build_userinfo_get, next_link, parse_access_token, parse_org_groups,
    parse_user, GhUser, GitHubConfig,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use busbar_contract::abi::sdk::cred::{self, Cred, FormBody, SettingsError};
use busbar_contract::abi::sdk::exchange::{Exchange as Wire, Request};
use busbar_contract::auth::{LoginHop, Principal};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A settings decoder error as the contract's instance-relative line: `settings.<path>: <reason>`

fn settings_line(e: &SettingsError) -> String {
    let text = e.to_string();
    let reason = text.strip_prefix("settings: ").unwrap_or(&text);
    if e.path().is_empty() {
        format!("settings: {reason}")
    } else {
        format!("settings.{}: {reason}", e.path())
    }
}

/// The per-hop request timeout.
pub const HOP_TIMEOUT_MS: u64 = 10_000;
/// The most `/user/orgs` pages read per login (requests ask for 100 entries per page; replies remain

pub const MAX_ORG_PAGES: usize = 10;
/// The bound on the hops one callback sends: the token exchange, `/user`, and the org pages.
pub const MAX_HOPS: usize = 2 + MAX_ORG_PAGES;
/// The most a hop's reply body may carry: 256 KiB, the auth kind's bound on a token or userinfo

pub const MAX_HOP_REPLY_BYTES: usize = 256 * 1024;

/// One hop, rendered as it goes on the wire: method, target, the public header fields in order
/// (lowercase names), the bearer (the chip's), the form body (its secret the chip's), the timeout.
#[derive(Clone, PartialEq, Eq)]
pub struct HopRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// The absolute URL.
    pub target: String,
    /// The public header fields, in order.
    pub fields: Vec<(String, String)>,
    /// The access token an authenticated hop presents: sealed in as `authorization: Bearer` first
    /// (right after `content-type` on a hop that has one, where 1.5.5's http stack wrote it).
    pub bearer: Option<Cred>,
    /// The `application/x-www-form-urlencoded` body (empty for a GET). The token exchange's
    /// carries the client secret sealed; its public values (the code, the verifier) are wiped
    /// with it.
    pub body: FormBody,
    /// The hop's timeout.
    pub timeout_ms: u64,
}

impl fmt::Debug for HopRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field(
                "fields",
                &self.fields.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .field("bearer", &self.bearer.is_some())
            .field("body", &self.body)
            .finish()
    }
}

/// `url` as the need's target (scheme and authority) and the request target (path and query).
pub(crate) fn split(url: &str) -> Option<(&str, String)> {
    let host_at = url.find("://")? + 3;
    let path_at = url[host_at..]
        .find(['/', '?'])
        .map_or(url.len(), |i| host_at + i);
    let (origin, path) = url.split_at(path_at);
    let path = match path.as_bytes().first() {
        None => "/".to_string(),
        Some(b'?') => format!("/{path}"),
        Some(_) => path.to_string(),
    };
    Some((origin, path))
}

impl HopRequest {
    /// The SDK exchange that sends this hop: the public fields framed as they are, the bearer

    #[must_use]
    pub fn wire(&self, reply_limit: usize) -> Option<Wire> {
        let Some((_, target)) = split(&self.target) else {
            tracing::warn!(
                module = "github",
                "github login: a hop URL has no scheme and authority to split"
            );
            return None;
        };
        let body = match self.body.encoded() {
            Ok(body) => body,
            Err(_) => {
                tracing::warn!(
                    module = "github",
                    "github login: the hop's form body could not be encoded"
                );
                return None;
            }
        };
        let at = self
            .fields
            .iter()
            .position(|(n, _)| n == "content-type")
            .map_or(0, |i| i + 1);
        let sealed = self
            .bearer
            .iter()
            .map(|b| (at, b"authorization".to_vec(), b.bearer()))
            .collect();
        let request = Request {
            method: self.method.clone().into_bytes(),
            target: target.into_bytes(),
            fields: self
                .fields
                .iter()
                .map(|(n, v)| (n.clone().into_bytes(), v.clone().into_bytes()))
                .collect(),
            body: Vec::new(),
            timeout_ms: self.timeout_ms,
        };
        match Wire::request_with(request, sealed, Some(body)) {
            Ok(w) => Some(w.reply_limit(reply_limit)),
            Err(e) => {
                tracing::warn!(module = "github", error = ?e, "github login: the hop request was refused");
                None
            }
        }
    }
}

/// The reply header fields the step machine reads, and no others: GitHub's rate-limit answer
/// (`retry-after`, `x-ratelimit-remaining`, `x-ratelimit-reset`) and its pagination (`link`). Every
/// other field the far end sent is dropped where the reply is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplyFields {
    /// `retry-after`.
    pub retry_after: Option<String>,
    /// `x-ratelimit-remaining`.
    pub ratelimit_remaining: Option<String>,
    /// `x-ratelimit-reset` (Unix seconds).
    pub ratelimit_reset: Option<String>,
    /// `link` (RFC 8288).
    pub link: Option<String>,
}

impl ReplyFields {
    /// The kept fields of a reply's field block, names matched case-insensitively. Repeated Link

    pub fn kept<'a>(fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Self {
        let mut kept = Self::default();
        for (name, value) in fields {
            if name.eq_ignore_ascii_case(b"link") {
                if let Ok(value) = std::str::from_utf8(value) {
                    match &mut kept.link {
                        Some(link) => {
                            link.push_str(", ");
                            link.push_str(value.trim());
                        }
                        None => kept.link = Some(value.trim().to_string()),
                    }
                }
                continue;
            }
            let slot = match name.to_ascii_lowercase().as_slice() {
                b"retry-after" => &mut kept.retry_after,
                b"x-ratelimit-remaining" => &mut kept.ratelimit_remaining,
                b"x-ratelimit-reset" => &mut kept.ratelimit_reset,
                _ => continue,
            };
            if slot.is_none() {
                *slot = std::str::from_utf8(value)
                    .ok()
                    .map(|v| v.trim().to_string());
            }
        }
        kept
    }
}

/// What the far end answered.
#[derive(Clone, PartialEq, Eq)]
pub struct HopResponse {
    /// The HTTP status.
    pub status: u16,
    /// The header fields the step machine reads ([`ReplyFields`]).
    pub fields: ReplyFields,
    /// The body bytes, wiped on drop: the token response carries the access token.
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for HopResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// What a one-shot exchange answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// Not yet: the wake fires when it is; re-issue the same request then.
    Pending,
    /// The response.
    Ready(HopResponse),
    /// No response: refused, connect, TLS, timeout or an unreadable body.
    Unreachable,
}

/// The one-shot exchange over the plugin's own need (the SDK's `exchange()` in the door).
pub trait Exchange {
    /// Send `request` (or, re-issued, answer its stored result).
    fn exchange(&mut self, request: &HopRequest) -> Fetched;
}

/// Where one `drive` left the login.
#[derive(Debug, Clone, PartialEq)]
pub enum LoginStep {
    /// Waiting on an exchange.
    Pending,
    /// Identified.
    Identity(Principal),
    /// The IdP answered and the sign-in is declined.
    BadCredential,
    /// The IdP could not be reached, or the login could not finish.
    Outage {
        /// The seconds the IdP asked to be left alone for (its `Retry-After`, or its rate-limit
        /// reset), when it named any.
        retry_after: Option<u64>,
    },
    /// A hop body's `id_token` is not bound to the nonce minted at begin (400
    /// "Sign-in couldn't be verified"; the auth ABI's `LOGIN_SECURITY_CHECK_FAILED`).
    SecurityCheckFailed,
}

/// The state kept per flow between hops, owned by the flow.
#[derive(Default)]
struct FlowState {
    access_token: Option<Cred>,
    user: Option<GhUser>,
    /// The org groups the pages read so far gave.
    orgs: Vec<String>,
    /// The org pages read so far.
    pages: usize,
    /// The hop the next answer is the answer of (the one sent last).
    hop: Hop,
}

/// The callback's inputs and the last hop answer the step machine reads, every credential among
/// them wiped on drop.
#[derive(Default)]
struct Callback {
    code: Option<Zeroizing<String>>,
    redirect_uri: Option<String>,
    code_verifier: Option<Zeroizing<String>>,
    /// The unconsumed answer: status, kept fields, body and request URL (the base for relative
    /// pagination). The body is wiped when consumed, before issuing or parking the next hop.
    answer: Option<(u16, ReplyFields, Zeroizing<String>, String)>,
}

/// One login in flight: the callback's inputs, the step machine's state, the hop parked on a

pub struct LoginFlow {
    req: Callback,
    state: FlowState,
    turns: usize,
    inflight: Option<HopRequest>,
    done: Option<LoginStep>,
    /// The nonce the kernel minted at begin (`CompleteLoginIn.nonce`), bound to any `id_token`.
    nonce: Option<Zeroizing<String>>,
}

impl fmt::Debug for LoginFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFlow")
            .field("turns", &self.turns)
            .field("inflight", &self.inflight)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

/// The GitHub login, holding its own client secret.
pub struct GithubLogin {
    cfg: GitHubConfig,
    client_secret: Option<Cred>,
    allowed_hosts: HashSet<String>,
}

impl fmt::Debug for GithubLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubLogin")
            .field("client_id", &self.cfg.client_id)
            .finish_non_exhaustive()
    }
}

impl GithubLogin {
    /// Build the login from its settings and the client secret the kernel resolved from

    pub fn open(settings: &str, client_secret: Option<&str>) -> Result<Self, String> {
        if settings.trim().is_empty() {
            return Err("settings: empty: the github plugin requires client_id".to_string());
        }
        let cfg: GitHubConfig =
            cred::settings(settings.as_bytes()).map_err(|e| settings_line(&e))?;
        let raw: Value = serde_json::from_str(settings)
            .map_err(|_| "settings: not a JSON document".to_string())?;
        if cfg.client_id.is_empty() {
            return Err("settings.client_id: empty".to_string());
        }

        if cfg.fetch_orgs
            && !cfg
                .scopes
                .iter()
                .any(|s| matches!(s.as_str(), "read:org" | "write:org" | "admin:org" | "user"))
        {
            return Err("settings.scopes: fetch_orgs reads /user/orgs, which needs the read:org scope (or write:org, admin:org, user): add it, or set fetch_orgs: false".to_string());
        }
        for (key, url) in [
            ("api_base", &cfg.api_base),
            ("authorize_base", &cfg.authorize_base),
            ("token_base", &cfg.token_base),
        ] {
            let http = url.starts_with("https://") || url.starts_with("http://");
            if !http || busbar_contract::net::extract_normalized_host(url).is_none() {
                return Err(format!("settings.{key}: not an http(s) URL with a host"));
            }
        }
        if cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| p.trim().is_empty())
        {
            return Err(
                "settings.ca_cert_pem: blank: omit it, or give a PEM certificate".to_string(),
            );
        }
        if cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| !p.contains("-----BEGIN CERTIFICATE-----"))
        {
            return Err(
                "settings.ca_cert_pem: not a PEM certificate (no -----BEGIN CERTIFICATE----- line)"
                    .to_string(),
            );
        }

        for key in ["token_base", "api_base"] {
            if raw.get(key).is_none() {
                return Err(format!(
                    "settings.{key}: must be written out: the hop allowlist is built only from URLs in the settings"
                ));
            }
        }

        let client_secret = client_secret.filter(|s| !s.is_empty()).map(|s| {
            Cred::captured(Zeroizing::new(s.as_bytes().to_vec())).secure_for(&cfg.token_base)
        });
        Ok(Self {
            cfg,
            client_secret,
            allowed_hosts: collect_allowed_hosts(&raw),
        })
    }

    /// Whether the settings name an operator CA (`ca_cert_pem`; `open` refuses a blank one): the

    #[must_use]
    pub fn anchored(&self) -> bool {
        self.cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| !p.is_empty())
    }

    /// The parsed config.
    #[must_use]
    pub fn config(&self) -> &GitHubConfig {
        &self.cfg
    }

    /// Start a login: the GitHub authorize URL.
    #[must_use]
    pub fn begin_login(
        &self,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
        scopes: &[String],
    ) -> String {
        build_github_authorize_url(&self.cfg, redirect_uri, state, code_challenge, scopes)
    }

    /// A new flow for one callback, with the nonce the kernel minted at begin.
    #[must_use]
    pub fn start(
        &self,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> LoginFlow {
        LoginFlow {
            req: Callback {
                code: code.map(|c| Zeroizing::new(c.to_string())),
                redirect_uri: redirect_uri.map(str::to_string),
                code_verifier: code_verifier.map(|v| Zeroizing::new(v.to_string())),
                answer: None,
            },
            state: FlowState::default(),
            turns: 0,
            inflight: None,
            done: None,
            nonce: nonce.map(|n| Zeroizing::new(n.to_string())),
        }
    }

    /// Run `flow` as far as it goes without waiting: the hop loop, over `ex`.
    pub fn drive(&self, flow: &mut LoginFlow, ex: &mut dyn Exchange) -> LoginStep {
        if let Some(done) = &flow.done {
            return done.clone();
        }
        loop {
            let request = match flow.inflight.take() {
                Some(parked) => parked,
                None => match self.step(flow) {
                    Turn::Identify(p) => return finish(flow, LoginStep::Identity(p)),
                    Turn::Decline => return finish(flow, LoginStep::BadCredential),

                    Turn::Outage { retry_after } => {
                        return finish(flow, LoginStep::Outage { retry_after })
                    }
                    Turn::Exchange(mut hop) => {
                        if flow.turns >= MAX_HOPS {
                            wipe_hop(&mut hop);
                            tracing::warn!(
                                module = "github",
                                "github login: hop limit ({MAX_HOPS}) spent without an identity"
                            );
                            return finish(flow, LoginStep::Outage { retry_after: None });
                        }
                        flow.turns += 1;
                        let rendered = self.render(&hop, flow.state.access_token.as_ref());
                        wipe_hop(&mut hop);
                        match rendered {
                            Ok(r) => r,

                            Err(Refused) => {
                                return finish(flow, LoginStep::Outage { retry_after: None })
                            }
                        }
                    }
                },
            };
            match ex.exchange(&request) {
                Fetched::Pending => {
                    flow.inflight = Some(request);
                    return LoginStep::Pending;
                }
                Fetched::Unreachable => {
                    tracing::warn!(
                        module = "github",
                        hop = flow.state.hop.path(),
                        "github login: the hop could not be made (refused, connect, TLS, timeout, or a request that could not be framed)"
                    );
                    return finish(flow, LoginStep::Outage { retry_after: None });
                }
                Fetched::Ready(mut resp) => {
                    if resp.body.len() > MAX_HOP_REPLY_BYTES {
                        tracing::warn!(
                            module = "github",
                            bytes = resp.body.len(),
                            "github login: a hop reply passed the {MAX_HOP_REPLY_BYTES}-byte cap"
                        );
                        return finish(flow, LoginStep::Outage { retry_after: None });
                    }
                    let body = text_of(std::mem::take(&mut *resp.body));

                    if !id_token_nonce_binds(&body, flow.nonce.as_ref().map(|n| n.as_str())) {
                        tracing::warn!(module = "github", "github login: a hop body's id_token is not bound to the nonce minted at begin");
                        return finish(flow, LoginStep::SecurityCheckFailed);
                    }
                    flow.req.answer = Some((
                        resp.status,
                        std::mem::take(&mut resp.fields),
                        body,
                        request.target,
                    ));
                }
            }
        }
    }

    /// The `complete_login` step machine, over the flow's own state.
    fn step(&self, flow: &mut LoginFlow) -> Turn {
        let Some((status, fields, body, request_url)) = flow.req.answer.take() else {
            let req = &flow.req;

            let (Some(code), Some(redirect_uri), Some(code_verifier)) = (
                given(req.code.as_deref().map(String::as_str)),
                given(req.redirect_uri.as_deref()),
                given(req.code_verifier.as_deref().map(String::as_str)),
            ) else {
                tracing::info!(module = "github", "github login: declined, the callback lacks its code, redirect_uri or code_verifier (or one is empty)");
                return Turn::Decline;
            };
            return Turn::Exchange(build_token_exchange(
                &self.cfg,
                code,
                redirect_uri,
                code_verifier,
            ));
        };
        let body = body.as_str();

        let hop = flow.state.hop;

        if !(200..300).contains(&status) {
            let turn = refused_answer(hop, status, &fields, body);
            flow.state = FlowState::default();
            return turn;
        }
        match hop {
            Hop::Token => {
                let Some(token) = parse_access_token(body) else {
                    flow.state = FlowState::default();
                    return token_refusal(body);
                };
                flow.state = FlowState {
                    access_token: Some(token.secure_for(&self.cfg.api_base)),
                    hop: Hop::User,
                    ..FlowState::default()
                };
                Turn::Exchange(build_userinfo_get(&self.cfg))
            }
            Hop::User => {
                let Some(user) = parse_user(body) else {
                    tracing::warn!(
                        module = "github",
                        hop = hop.path(),
                        "github login: /user answered 2xx with no user (a login and a numeric id)"
                    );
                    flow.state = FlowState::default();
                    return Turn::Outage { retry_after: None };
                };
                if !self.cfg.fetch_orgs {
                    flow.state = FlowState::default();
                    return Turn::Identify(build_principal(&user, Vec::new()));
                }
                flow.state.user = Some(user);
                flow.state.hop = Hop::Orgs;
                Turn::Exchange(build_orgs_get(&self.cfg))
            }
            Hop::Orgs => {
                let state = std::mem::take(&mut flow.state);
                let (Some(user), Some(groups)) = (state.user, parse_org_groups(body)) else {
                    tracing::warn!(
                        module = "github",
                        hop = hop.path(),
                        "github login: /user/orgs answered 2xx with no org list"
                    );
                    return Turn::Outage { retry_after: None };
                };
                let mut orgs = state.orgs;
                orgs.extend(groups);
                let pages = state.pages + 1;

                match fields.link.as_deref().and_then(next_link) {
                    None => {}
                    Some(_) if pages >= MAX_ORG_PAGES => tracing::warn!(
                        module = "github",
                        pages,
                        "github login: the org list is truncated at {MAX_ORG_PAGES} pages: org groups past it are not granted"
                    ),
                    Some(next) => {
                        let Some(next) = next_on_origin(next, &request_url, &self.cfg.api_base) else {
                            tracing::warn!(
                                module = "github",
                                "github login: /user/orgs answered an invalid or foreign-origin next link; login cannot finish"
                            );
                            return Turn::Outage { retry_after: None };
                        };
                        flow.state = FlowState {
                            access_token: state.access_token,
                            user: Some(user),
                            orgs,
                            pages,
                            hop: Hop::Orgs,
                        };
                        return Turn::Exchange(build_orgs_page_get(next.as_str()));
                    }
                }
                Turn::Identify(build_principal(&user, orgs))
            }
        }
    }

    /// Render a hop up to the send: vet the URL, seal the client secret into the named form

    fn render(&self, hop: &LoginHop, bearer: Option<&Cred>) -> Result<HopRequest, Refused> {
        vet_hop_url(&hop.url, &self.allowed_hosts)?;

        if bearer.is_some_and(|b| !b.is_field_value()) {
            tracing::warn!(
                module = "github",
                header = "authorization",
                "github login: hop refused, a header value has a control byte"
            );
            return Err(Refused);
        }
        let field = hop.secret_form_field.as_deref();
        let mut body = FormBody::new();
        let mut sealed = false;
        for (k, v) in &hop.form {
            if Some(k.as_str()) == field {
                if let Some(secret) = &self.client_secret {
                    body = body.sealed(k, secret);
                    sealed = true;
                }
            } else {
                body = body.public(k, v);
            }
        }
        if let (Some(field), Some(secret), false) = (field, &self.client_secret, sealed) {
            body = body.sealed(field, secret);
            sealed = true;
        }
        let method = match hop.method.as_str() {
            m if !m.is_empty() && m.bytes().all(|b| b.is_ascii_alphabetic()) => m.to_string(),
            _ => {
                tracing::warn!(
                    module = "github",
                    "github login: hop refused, method is not a non-empty alphabetic token"
                );
                return Err(Refused);
            }
        };

        let mut fields = Vec::new();
        if !hop.form.is_empty() || sealed {
            fields.push((
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
        }
        for (name, value) in &hop.headers {
            fields.push(sanitize_hop_header(name, value)?);
        }
        if !fields.iter().any(|(n, _)| n == "accept") {
            fields.push(("accept".to_string(), "*/*".to_string()));
        }
        Ok(HopRequest {
            method,
            target: hop.url.clone(),
            fields,
            bearer: bearer.cloned(),
            body,
            timeout_ms: HOP_TIMEOUT_MS,
        })
    }
}

/// A reply body as text, moved, never copied: valid UTF-8 is the buffer itself; otherwise the

fn text_of(bytes: Vec<u8>) -> Zeroizing<String> {
    match String::from_utf8(bytes) {
        Ok(text) => Zeroizing::new(text),
        Err(e) => {
            let mut bytes = e.into_bytes();
            let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
            bytes.zeroize();
            text
        }
    }
}

/// A callback value, `None` when absent or empty.
fn given(v: Option<&str>) -> Option<&str> {
    v.filter(|v| !v.is_empty())
}

/// What one turn of the step machine decided.
enum Turn {
    /// Send this hop.
    Exchange(LoginHop),
    /// Identified.
    Identify(Principal),
    /// The IdP declined the sign-in.
    Decline,
    /// The IdP could not answer, or answered something that is no sign-in answer.
    Outage {
        /// The IdP's retry hint, in seconds.
        retry_after: Option<u64>,
    },
}

/// The hops of a GitHub login.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Hop {
    /// The token exchange.
    #[default]
    Token,
    /// `GET /user`.
    User,
    /// `GET /user/orgs`.
    Orgs,
}

impl Hop {
    /// The hop as a log names it (never the URL string).
    fn path(self) -> &'static str {
        match self {
            Hop::Token => "/login/oauth/access_token",
            Hop::User => "/user",
            Hop::Orgs => "/user/orgs",
        }
    }
}

/// Resolve a next-page reference against the page that supplied it, then require the API's

fn next_on_origin(next: &str, request: &str, base: &str) -> Option<url::Url> {
    let mut next = url::Url::parse(request).ok()?.join(next).ok()?;
    let base = url::Url::parse(base).ok()?;
    if next.origin() != base.origin() || !next.username().is_empty() || next.password().is_some() {
        return None;
    }
    next.set_fragment(None);
    Some(next)
}

/// Whether a reply is GitHub's rate limit: it names a `retry-after`, or no requests remain.
fn rate_limited(fields: &ReplyFields) -> bool {
    fields.retry_after.is_some() || fields.ratelimit_remaining.as_deref() == Some("0")
}

/// The IdP's retry hint, in seconds at `now`: its `retry-after` (delta seconds), else, when no

fn retry_hint(fields: &ReplyFields, now: u64) -> Option<u64> {
    if let Some(after) = fields.retry_after.as_deref().and_then(secs) {
        return Some(after);
    }
    if fields.ratelimit_remaining.as_deref() == Some("0") {
        return fields
            .ratelimit_reset
            .as_deref()
            .and_then(secs)
            .map(|reset| reset.saturating_sub(now));
    }
    None
}

/// Strict delta seconds; the full accepted u64 is preserved for the host to interpret.
fn secs(v: &str) -> Option<u64> {
    (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .then(|| v.parse::<u64>().ok())
        .flatten()
}

/// Absolute resets require a usable wall clock. A delta Retry-After remains meaningful when

fn retry_hint_at(fields: &ReplyFields, at: std::time::SystemTime) -> Option<u64> {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(now) => retry_hint(fields, now.as_secs()),
        Err(_) => {
            tracing::warn!(
                module = "github",
                "github login: wall clock unavailable; omitting any absolute rate-limit reset hint"
            );
            fields.retry_after.as_deref().and_then(secs)
        }
    }
}

/// An IdP error code as a log may print it: the code when it is `[a-z0-9_]{1,64}`, else

fn loggable(code: &str) -> &str {
    let plain = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if plain {
        code
    } else {
        "<unrecognised>"
    }
}

fn refused_answer(hop: Hop, status: u16, fields: &ReplyFields, body: &str) -> Turn {
    let path = hop.path();
    if status >= 500 || status == 429 {
        let retry_after = retry_hint_at(fields, std::time::SystemTime::now());
        tracing::warn!(
            module = "github",
            status,
            hop = path,
            retry_after,
            "github login: the identity provider is unavailable"
        );
        return Turn::Outage { retry_after };
    }
    if status == 403 && rate_limited(fields) {
        let retry_after = retry_hint_at(fields, std::time::SystemTime::now());
        tracing::warn!(
            module = "github",
            status,
            hop = path,
            retry_after,
            "github login: GitHub's API rate limit is spent"
        );
        return Turn::Outage { retry_after };
    }
    match hop {
        Hop::Token => {
            if let (400 | 401, Some(code)) = (
                status,
                github_error(body).filter(|code| {
                    matches!(
                        code.as_str(),
                        "invalid_request"
                            | "invalid_client"
                            | "invalid_grant"
                            | "unauthorized_client"
                            | "unsupported_grant_type"
                            | "invalid_scope"
                    )
                }),
            ) {
                let code = loggable(&code);
                if matches!(code, "invalid_client" | "unauthorized_client") {
                    tracing::warn!(
                        module = "github",
                        status,
                        error = code,
                        "github login: declined, the token endpoint refused this client (check client_id and client_secret)"
                    );
                } else {
                    tracing::info!(
                        module = "github",
                        status,
                        error = code,
                        "github login: declined, the token endpoint refused the code"
                    );
                }
                return Turn::Decline;
            }
            tracing::warn!(
                module = "github",
                status,
                hop = path,
                "github login: the token endpoint answered a status that is no credential error"
            );
            Turn::Outage { retry_after: None }
        }
        Hop::User | Hop::Orgs => {
            if status == 401 {
                tracing::info!(
                    module = "github",
                    status,
                    hop = path,
                    "github login: declined, GitHub did not accept the access token"
                );
                return Turn::Decline;
            }
            if status == 403 && hop == Hop::Orgs {
                tracing::warn!(
                    module = "github",
                    status,
                    hop = path,
                    "github login: /user/orgs answered 403: the access token lacks the read:org scope (check the OAuth App and the scopes setting)"
                );
                return Turn::Outage { retry_after: None };
            }
            tracing::warn!(
                module = "github",
                status,
                hop = path,
                "github login: the GitHub API answered a status that is no sign-in answer"
            );
            Turn::Outage { retry_after: None }
        }
    }
}

/// GitHub's `error` code from a token response body (JSON `error` or form `error=`), if any.
fn github_error(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(trimmed).ok()?;
        return v.get("error").and_then(Value::as_str).map(str::to_string);
    }
    if trimmed.starts_with('[') {
        return None;
    }
    trimmed
        .split('&')
        .find_map(|p| p.strip_prefix("error="))
        .map(str::to_string)
}

/// The token endpoint's codes that are the user's own: a bad or expired code, an invalid grant.
const USER_TOKEN_ERRORS: [&str; 3] = ["bad_verification_code", "invalid_grant", "expired_token"];
/// The token endpoint's codes that are the operator's: the OAuth App's credentials, its callback

const OPERATOR_TOKEN_ERRORS: [&str; 3] = [
    "incorrect_client_credentials",
    "redirect_uri_mismatch",
    "application_suspended",
];

/// The turn a 2xx token reply carrying no access token is (GitHub answers a refused exchange with

fn token_refusal(body: &str) -> Turn {
    let Some(code) = github_error(body) else {
        tracing::warn!(
            module = "github",
            "github login: the token endpoint answered 2xx with neither an access_token nor an error"
        );
        return Turn::Outage { retry_after: None };
    };
    let code = loggable(&code);
    if USER_TOKEN_ERRORS.contains(&code) {
        tracing::info!(
            module = "github",
            error = code,
            "github login: declined, the token endpoint refused the code"
        );
        return Turn::Decline;
    }
    if OPERATOR_TOKEN_ERRORS.contains(&code) {
        tracing::warn!(
            module = "github",
            error = code,
            "github login: the token endpoint refused this client: the operator's configuration (check client_id, client_secret, the OAuth App's callback URL and that the app is not suspended)"
        );
    } else {
        tracing::warn!(
            module = "github",
            error = code,
            "github login: the token endpoint answered an error that is no declined sign-in"
        );
    }
    Turn::Outage { retry_after: None }
}

fn finish(flow: &mut LoginFlow, step: LoginStep) -> LoginStep {
    flow.inflight = None;
    flow.state = FlowState::default();
    flow.req = Callback::default();
    flow.done = Some(step.clone());
    step
}

/// Wipe the plugin-owned values of a described hop once it is rendered: `LoginHop.form` carries

fn wipe_hop(hop: &mut LoginHop) {
    for (_, v) in &mut hop.form {
        v.zeroize();
    }
}

/// The nonce binding (a constant-time compare): a body

fn id_token_nonce_binds(body: &str, minted: Option<&str>) -> bool {
    #[derive(Default)]
    enum TokenField {
        #[default]
        Missing,
        Present(Value),
    }
    impl<'de> serde::Deserialize<'de> for TokenField {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            serde::Deserialize::deserialize(d).map(Self::Present)
        }
    }
    /// Only the `id_token` member is read: the rest of the body (an access token) is skipped,
    /// never copied.
    #[derive(serde::Deserialize)]
    struct IdToken {
        #[serde(default)]
        id_token: TokenField,
    }
    let body = body.trim();
    if body.starts_with('{') {
        let parsed = match serde_json::from_str::<IdToken>(body) {
            Ok(parsed) => parsed,

            Err(error) => return !error.is_data(),
        };
        return match parsed.id_token {
            TokenField::Missing => true,
            TokenField::Present(Value::String(token)) => {
                token_nonce_binds(&Zeroizing::new(token), minted)
            }
            TokenField::Present(_) => false,
        };
    }

    if body.starts_with('[') {
        return true;
    }
    for pair in body.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if crate::form_decode(name).as_slice() == b"id_token" {
            let token = crate::form_decode(value);
            let Ok(token) = std::str::from_utf8(&token) else {
                return false;
            };
            if !token_nonce_binds(token, minted) {
                return false;
            }
        }
    }
    true
}

/// An actually present id_token must carry the expected nonce, whatever the response encoding.
fn token_nonce_binds(id_token: &str, minted: Option<&str>) -> bool {
    let claimed = id_token
        .split('.')
        .nth(1)
        .and_then(|seg| URL_SAFE_NO_PAD.decode(seg).ok())
        .map(Zeroizing::new)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|claims| {
            claims
                .get("nonce")
                .and_then(Value::as_str)
                .map(|n| Zeroizing::new(n.to_string()))
        });
    match (claimed, minted) {
        (Some(n), Some(m)) => busbar_contract::constant_time_eq(n.as_str(), m),
        _ => false,
    }
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;

#[cfg(test)]
mod clock_tests {
    use super::*;
    #[test]
    fn unavailable_wall_clock_warns_and_preserves_only_delta_seconds() {
        let before_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        let cap = busbar_test_kit::warn_capture::WarnCapture::default();
        let mut fields = ReplyFields {
            ratelimit_remaining: Some("0".into()),
            ratelimit_reset: Some(u64::MAX.to_string()),
            ..ReplyFields::default()
        };
        assert_eq!(
            tracing::subscriber::with_default(cap.clone(), || retry_hint_at(&fields, before_epoch)),
            None
        );
        assert!(cap.contains("wall clock unavailable"));
        fields.retry_after = Some(u64::MAX.to_string());
        assert_eq!(retry_hint_at(&fields, before_epoch), Some(u64::MAX));
    }
}
