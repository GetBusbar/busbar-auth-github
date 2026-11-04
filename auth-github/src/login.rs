// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-owned login: it holds its own client secret and makes its token exchange through its
//! own need, one-shot `exchange()` per hop.
//!
//! The plugin runs the hop loop itself, sans-IO: [`GithubLogin::drive`] turns the step machine over
//! one flow's own state, renders each hop (vetting its URL, injecting `client_secret`, sanitising its
//! headers), and hands it to an [`Exchange`], which answers [`Fetched::Pending`] until the response
//! is in. A pending exchange returns [`LoginStep::Pending`] with the flow parked on that hop; the
//! next `drive` re-issues the SAME request (a one-shot exchange answers its stored result on the
//! re-issue, never sending twice).
//!
//! What the answer means:
//!
//! | answer | step |
//! |---|---|
//! | an identity reached | [`LoginStep::Identity`] |
//! | a credential error, declined (`LOGIN_BAD_CREDENTIAL`) | [`LoginStep::BadCredential`] |
//! | the IdP not answering, a hop refused or unreachable, the hop limit spent (`LOGIN_OUTAGE`) | [`LoginStep::Outage`] |
//! | a hop body's `id_token` nonce mismatch (`LOGIN_SECURITY_CHECK_FAILED`) | [`LoginStep::SecurityCheckFailed`] |
//!
//! The HTTP status each verdict is answered with is the host's, not this plugin's.
//!
//! Any HTTP status the IdP answers is fed back to the step machine, per hop (OWNER-SIGNED
//! 2026-10-30: only a credential error is a declined sign-in). The token endpoint's `400`/`401`
//! carrying an RFC 6749 §5.2 `error`, and a revoked token's `401` from `/user` or `/user/orgs`, are
//! declined. A `5xx`, a `429`, GitHub's `403` rate limit, a `403` on `/user/orgs` (the token lacks
//! `read:org`), a redirect, a `404`, a `408` or any other status is the IdP not answering:
//! [`LoginStep::Outage`], which the host answers 503, retryable, carrying the IdP's retry hint
//! (`retry-after` seconds or HTTP-date, or the seconds to `x-ratelimit-reset`) when it gave one.
//!
//! The auth ABI adapter is [`crate::door`]: it calls [`GithubLogin::open`],
//! [`GithubLogin::begin_login`], [`GithubLogin::start`] and [`GithubLogin::drive`], keeping one
//! [`LoginFlow`] per ticket and each [`Exchange`] one framed `exchange()` over the plugin's need.

use crate::guard::{
    collect_allowed_hosts, sanitize_hop_header, secure_or_private, vet_hop_url, Refused,
};
use crate::{
    build_github_authorize_url, build_orgs_get, build_orgs_page_get, build_principal,
    build_token_exchange, build_userinfo_get, parse_access_token, parse_org_groups, parse_user,
    read_link, GhUser, GitHubConfig,
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
/// (`settings: <reason>` for the document), every value in it written `***`.
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
/// The most `/user/orgs` pages read per login (requests ask for [`crate::ORGS_PER_PAGE`] entries a
/// page, and a page carrying more is refused). A next link left after the last is logged as a
/// truncated org list, and the login identifies with the orgs read.
pub const MAX_ORG_PAGES: usize = 10;
/// The bound on the hops one callback sends: the token exchange, `/user`, and the org pages.
pub const MAX_HOPS: usize = 2 + MAX_ORG_PAGES;
/// The most a hop's reply body may carry: 256 KiB, the auth kind's bound on a token or userinfo
/// endpoint's answer (the exchange refuses past it, `reply_limit`; `drive` checks it again). A
/// GitHub token response or `/user` is under 2 KiB; a full 100-entry `/user/orgs` page is ~100 KiB.
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
    /// sealed in as `authorization` first (after a `content-type`), the form encoded by the SDK
    /// into the body it sends, the reply bounded by `reply_limit`. `None`: the URL has no scheme
    /// and authority, the form could not be encoded, or the exchange refused the request.
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
/// other field the far end sent is dropped where the reply is read. These are exactly the names
/// the door's needs declare kept ([`KEPT_REPLY_FIELDS`]).
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

/// The response head fields [`ReplyFields`] reads (lower-case), and so the ones the door's needs
/// name under `KEEP_NAMED`: the host hands the plugin these and no others.
pub const KEPT_REPLY_FIELDS: [&str; 4] = [
    "link",
    "retry-after",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
];

impl ReplyFields {
    /// The kept fields of a reply's field block, names matched case-insensitively. Repeated Link
    /// lines are one comma-separated list, a line that is not UTF-8 kept in it as one U+FFFD (so
    /// the list reads as unreadable, never as absent); other fields keep the first UTF-8 value.
    pub fn kept<'a>(fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Self {
        let mut kept = Self::default();
        for (name, value) in fields {
            if name.eq_ignore_ascii_case(b"link") {
                let value = std::str::from_utf8(value).map_or("\u{fffd}", str::trim);
                match &mut kept.link {
                    Some(link) => {
                        link.push_str(", ");
                        link.push_str(value);
                    }
                    None => kept.link = Some(value.to_string()),
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
/// pending exchange, and the answer once reached (a re-call is served from it, never re-run: an
/// authorization code redeems once).
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
    /// `browser_login.client_secret`, which arrives in `OpenIn.secrets`, never in `settings`: a
    /// `client_secret` key in the settings is refused (`deny_unknown_fields`).
    ///
    /// No secret (`None` or empty) is NOT a refusal: a headless-only provider has no `browser_login`
    /// block, and a hop's `client_secret` field is then dropped. A redirect method missing its secret
    /// is refused by the kernel.
    ///
    /// # Errors
    /// Empty or invalid settings (a decoder error keeps serde's text only when it names a key, never
    /// a value); an empty `client_id`; `fetch_orgs` with no scope that reads orgs; a base that is not
    /// an http(s) URL with a host; a `token_base` or `api_base` on plain `http` to a host that is not
    /// loopback or private (the hop guard would refuse every hop to it); a `ca_cert_pem` that is
    /// blank or no PEM certificate; a `token_base` or `api_base` not written out (the hop allowlist is
    /// built only from the URLs written in the settings, so every hop to a defaulted base would be
    /// refused).
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
            let Some(host) = busbar_contract::net::extract_normalized_host(url).filter(|_| http)
            else {
                return Err(format!("settings.{key}: not an http(s) URL with a host"));
            };
            if key != "authorize_base" && !secure_or_private(url, &host) {
                return Err(format!(
                    "settings.{key}: plain http to a host that is not loopback or private: use https"
                ));
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
    /// hops then go out on the need that trusts it beside the public roots.
    #[must_use]
    pub fn anchored(&self) -> bool {
        self.cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
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
        // OWNER-SIGNED 2026-10-30: only a credential error is a declined sign-in; every other
        // answer that is no 2xx is the IdP not answering this hop, an outage (the host answers
        // 503, retryable); the step carries the IdP's retry hint when it gave one.
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

                let next = match fields.link.as_deref().map(read_link) {
                    None => None,
                    Some(Some(next)) => next,
                    Some(None) => {
                        tracing::warn!(
                            module = "github",
                            pages,
                            "github login: /user/orgs answered a Link field that cannot be read: org groups past this page are not granted"
                        );
                        None
                    }
                };
                if let Some(next) = next {
                    let Some(next) = next_on_origin(next, &request_url, &self.cfg.api_base) else {
                        tracing::warn!(
                            module = "github",
                            "github login: /user/orgs answered an invalid or foreign-origin next link; login cannot finish"
                        );
                        return Turn::Outage { retry_after: None };
                    };
                    if pages < MAX_ORG_PAGES {
                        flow.state = FlowState {
                            access_token: state.access_token,
                            user: Some(user),
                            orgs,
                            pages,
                            hop: Hop::Orgs,
                        };
                        return Turn::Exchange(build_orgs_page_get(next.as_str()));
                    }
                    tracing::warn!(
                        module = "github",
                        pages,
                        "github login: the org list is truncated at {MAX_ORG_PAGES} pages: org groups past it are not granted"
                    );
                }
                Turn::Identify(build_principal(&user, orgs))
            }
        }
    }

    /// Render a hop up to the send: vet the URL, seal the client secret into the named form
    /// field (or drop the placeholder when there is none), and lay out the fields as the http
    /// stack wrote them (`content-type` first when the hop has a form body, the hop's sanitised
    /// headers, then the default `accept: */*` when the hop set none). An authenticated hop carries
    /// `bearer`, which the chip writes as `authorization` first (after `content-type`, if any).
    ///
    /// The plugin never holds the secret's or the bearer's bytes here: the body is a [`FormBody`]
    /// the SDK encodes at the wire.
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
/// lossy text, the bytes it was read from wiped.
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
/// scheme, host and effective port. Userinfo is never accepted from an untrusted next link.
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

/// The IdP's retry hint, in seconds at `now` (Unix seconds): its `retry-after` (delta seconds, else
/// an HTTP-date, as the seconds from `now` to it), else, when no requests remain, the seconds to
/// its `x-ratelimit-reset`.
fn retry_hint(fields: &ReplyFields, now: u64) -> Option<u64> {
    if let Some(after) = fields.retry_after.as_deref() {
        if let Some(after) = secs(after) {
            return Some(after);
        }
        if let Some(at) = http_date(after) {
            return Some(at.saturating_sub(now));
        }
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

/// An RFC 9110 §5.6.7 HTTP-date as Unix seconds: the IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`)
/// and the two obsolete forms a recipient must read, RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`,
/// a two-digit year below 70 read as 20xx) and asctime (`Sun Nov  6 08:49:37 1994`). Anything
/// else, or a date before 1970, is `None`.
fn http_date(v: &str) -> Option<u64> {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const LONG_DAYS: [&str; 7] = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let number = |s: &str, len: std::ops::RangeInclusive<usize>| {
        (len.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    let month = |s: &str| MONTHS.iter().position(|m| *m == s).map(|m| m as u64 + 1);
    let time = |s: &str| {
        let mut it = s.split(':');
        let (h, m, sec) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() {
            return None;
        }
        Some((number(h, 2..=2)?, number(m, 2..=2)?, number(sec, 2..=2)?))
    };
    let parts: Vec<&str> = v.split_ascii_whitespace().collect();
    let (year, mon, day, (h, m, sec)) = match *parts.as_slice() {
        [wd, day, mon, year, t, "GMT"] if DAYS.iter().any(|d| wd.strip_suffix(',') == Some(*d)) => {
            (
                number(year, 4..=4)?,
                month(mon)?,
                number(day, 2..=2)?,
                time(t)?,
            )
        }
        [wd, date, t, "GMT"] if LONG_DAYS.iter().any(|d| wd.strip_suffix(',') == Some(*d)) => {
            let mut it = date.split('-');
            let (day, mon, yy) = (it.next()?, it.next()?, it.next()?);
            if it.next().is_some() {
                return None;
            }
            let yy = number(yy, 2..=2)?;
            let year = if yy < 70 { 2000 + yy } else { 1900 + yy };
            (year, month(mon)?, number(day, 2..=2)?, time(t)?)
        }
        [wd, mon, day, t, year] if DAYS.contains(&wd) => (
            number(year, 4..=4)?,
            month(mon)?,
            number(day, 1..=2)?,
            time(t)?,
        ),
        _ => return None,
    };
    if !(1970..=9999).contains(&year) || !(1..=31).contains(&day) || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    let (y, mp) = if mon <= 2 {
        (year - 1, mon + 9)
    } else {
        (year, mon - 3)
    };
    let (era, yoe) = (y / 400, y % 400);
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86_400 + h * 3_600 + m * 60 + sec)
}

/// The IdP's retry hint at the wall-clock time `at`. Absolute times (an HTTP-date `retry-after`, a
/// reset) require a usable wall clock. A delta Retry-After remains meaningful when the clock is
/// unavailable; never reinterpret an absolute time as a delay from epoch zero.
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

/// The most bytes of an IdP error code a log prints.
const MAX_LOGGED_CODE_BYTES: usize = 64;

/// An IdP error code as a log may print it: the code when it is `[a-z0-9_]` and at most
/// [`MAX_LOGGED_CODE_BYTES`] long, else `<unrecognised>` (a far-end string is never logged raw).
fn loggable(code: &str) -> &str {
    let plain = !code.is_empty()
        && code.len() <= MAX_LOGGED_CODE_BYTES
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if plain {
        code
    } else {
        "<unrecognised>"
    }
}

/// The turn a hop's non-2xx answer is (OWNER-SIGNED 2026-10-30: only credential errors are a
/// declined sign-in):
///
/// * any hop: a 5xx or 429 is the IdP unavailable, an outage carrying its retry hint;
/// * the token endpoint: a 400/401 carrying a §5.2 `error` (JSON or form) is declined, unless the
///   code is the operator's ([`OPERATOR_TOKEN_ERRORS`], an outage at warn); anything else is an
///   outage;
/// * `/user`, `/user/orgs`: a 401 (the token is not accepted) is declined; a 403 that is GitHub's
///   rate limit is an outage carrying its retry hint; any other 403 on `/user/orgs` is the token
///   lacking `read:org`, the operator's to fix (an outage, at warn); anything else is an outage.
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
            let code = if matches!(status, 400 | 401) {
                github_error(body)
            } else {
                None
            };
            let code = code.as_deref().map(loggable);
            if let Some(code) = code.filter(|code| OPERATOR_TOKEN_ERRORS.contains(code)) {
                tracing::warn!(
                    module = "github",
                    status,
                    error = code,
                    "github login: the token endpoint refused this client: the operator's configuration (check client_id, client_secret, the OAuth App's callback URL and that the app is not suspended)"
                );
                return Turn::Outage { retry_after: None };
            }
            if let Some(code) = code.filter(|code| RFC6749_TOKEN_ERRORS.contains(code)) {
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

/// GitHub's `error` code from a token response body (JSON `error` or form `error=`), if any. Only
/// the `error` member is decoded: the access token beside it is skipped, never copied.
fn github_error(body: &str) -> Option<String> {
    /// The `error` member alone; every other member is ignored unread.
    #[derive(serde::Deserialize)]
    struct ErrorMember {
        error: Option<String>,
    }
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str::<ErrorMember>(trimmed).ok()?.error;
    }
    if trimmed.starts_with('[') {
        return None;
    }
    trimmed
        .split('&')
        .find_map(|p| p.strip_prefix("error="))
        .map(str::to_string)
}

/// The RFC 6749 §5.2 error codes a `400`/`401` token answer declines the sign-in with.
const RFC6749_TOKEN_ERRORS: [&str; 6] = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
];
/// The token endpoint's codes that are the user's own: a bad or expired code, an invalid grant.
const USER_TOKEN_ERRORS: [&str; 3] = ["bad_verification_code", "invalid_grant", "expired_token"];
/// The token endpoint's codes that are the operator's: the OAuth App's credentials, its callback
/// URL, the app itself.
const OPERATOR_TOKEN_ERRORS: [&str; 3] = [
    "incorrect_client_credentials",
    "redirect_uri_mismatch",
    "application_suspended",
];

/// The turn a 2xx token reply carrying no usable access token is (GitHub answers a refused exchange
/// with HTTP 200 and an `error`), OWNER-SIGNED 2026-10-30: only the user's own code is a declined
/// sign-in (at info); the operator's misconfiguration is an outage at warn; any other code, and a
/// reply with neither a bearer token nor an error (empty, HTML, not JSON, another `token_type`), is
/// an outage.
fn token_refusal(body: &str) -> Turn {
    let Some(code) = github_error(body) else {
        tracing::warn!(
            module = "github",
            "github login: the token endpoint answered 2xx with neither a bearer access_token nor an error"
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
/// the code and the verifier, in the contract's plain `String`s. Its headers are public.
fn wipe_hop(hop: &mut LoginHop) {
    for (_, v) in &mut hop.form {
        v.zeroize();
    }
}

/// The `id_token` member of a token answer: absent, a string (wiped on drop), or any other value.
#[derive(Default)]
enum Member {
    #[default]
    Absent,
    Str(Zeroizing<String>),
    Other,
}

#[derive(serde::Deserialize)]
struct IdTokenMember {
    #[serde(default, deserialize_with = "member")]
    id_token: Member,
}

fn member<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Member, D::Error> {
    use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Member;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_str<E>(self, v: &str) -> Result<Member, E> {
            Ok(Member::Str(Zeroizing::new(v.to_string())))
        }
        fn visit_string<E>(self, v: String) -> Result<Member, E> {
            Ok(Member::Str(Zeroizing::new(v)))
        }
        fn visit_bool<E>(self, _: bool) -> Result<Member, E> {
            Ok(Member::Other)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Member, E> {
            Ok(Member::Other)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Member, E> {
            Ok(Member::Other)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Member, E> {
            Ok(Member::Other)
        }
        fn visit_unit<E>(self) -> Result<Member, E> {
            Ok(Member::Other)
        }
        fn visit_none<E>(self) -> Result<Member, E> {
            Ok(Member::Other)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Member, A::Error> {
            while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(Member::Other)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Member, A::Error> {
            while s.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Member::Other)
        }
    }
    d.deserialize_any(V)
}

/// The nonce binding (a constant-time compare): a body with no `id_token` binds trivially; one
/// with an `id_token` binds only when its payload's `nonce` claim (base64url, no signature check:
/// that is the IdP module's job) equals `minted`. A repeated or non-string `id_token` never binds.
fn id_token_nonce_binds(body: &str, minted: Option<&str>) -> bool {
    let body = body.trim();
    if body.starts_with('{') {
        let parsed = match serde_json::from_str::<IdTokenMember>(body) {
            Ok(parsed) => parsed,
            Err(error) => return !error.is_data(),
        };
        return match parsed.id_token {
            Member::Absent => true,
            Member::Str(token) => token_nonce_binds(&token, minted),
            Member::Other => false,
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

/// The `nonce` claim of an `id_token` payload, alone: the other claims are skipped, never copied.
#[derive(serde::Deserialize)]
struct NonceClaim {
    #[serde(default, deserialize_with = "member")]
    nonce: Member,
}

/// An actually present id_token must carry the expected nonce, whatever the response encoding. Its
/// payload must be a JSON object holding exactly one string `nonce`.
fn token_nonce_binds(id_token: &str, minted: Option<&str>) -> bool {
    let claimed = id_token
        .split('.')
        .nth(1)
        .and_then(|seg| URL_SAFE_NO_PAD.decode(seg).ok())
        .map(Zeroizing::new)
        .filter(|bytes| bytes.trim_ascii_start().starts_with(b"{"))
        .and_then(|bytes| serde_json::from_slice::<NonceClaim>(&bytes).ok())
        .and_then(|claims| match claims.nonce {
            Member::Str(nonce) => Some(nonce),
            Member::Absent | Member::Other => None,
        });
    match (claimed, minted) {
        (Some(n), Some(m)) => busbar_contract::constant_time_eq(n.as_str(), m),
        _ => false,
    }
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
