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
//! | module `Identify` | [`LoginStep::Identity`] |
//! | module `Reject` ("Sign-in was declined", 401) | [`LoginStep::BadCredential`] |
//! | hop refused or unreachable ("Couldn't reach your provider", 502) | [`LoginStep::Outage`] |
//! | hop limit spent / `Authorize` on the callback (502) | [`LoginStep::Outage`] |
//! | a hop body's `id_token` nonce mismatch ("Sign-in couldn't be verified", 400) | [`LoginStep::SecurityCheckFailed`] |
//!
//! Any HTTP status the IdP answers is fed back to the step machine: a revoked token's `401` from
//! `/user` is a declined sign-in, not an outage. A `5xx` or `429` is the IdP unable to answer:
//! [`LoginStep::Outage`], which the host answers 503, retryable.
//!
//! The auth ABI adapter is [`crate::door`]: it calls [`GithubLogin::open`],
//! [`GithubLogin::begin_login`], [`GithubLogin::start`] and [`GithubLogin::drive`], keeping one
//! [`LoginFlow`] per ticket and each [`Exchange`] one framed `exchange()` over the plugin's need.

use crate::guard::{collect_allowed_hosts, sanitize_hop_header, vet_hop_url, Refused};
use crate::{
    build_github_authorize_url, build_orgs_get, build_principal, build_token_exchange,
    build_userinfo_get, is_json_array, parse_access_token, parse_org_groups, parse_user, GhUser,
    GitHubConfig,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use busbar_contract::abi::sdk::auth_kit::json_error;
use busbar_contract::abi::sdk::cred::{Cred, FormBody};
use busbar_contract::abi::sdk::exchange::{Exchange as Wire, Request};
use busbar_contract::auth::{LoginHop, LoginOutcome, Principal};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// What a settings decoder error is about (`abi::sdk::auth_kit::json_error`'s lead).
const SETTINGS: &str = "invalid github plugin config";

/// The per-hop request timeout.
pub const HOP_TIMEOUT_MS: u64 = 10_000;
/// The bound on `complete_login` turns per callback.
pub const MAX_HOPS: usize = 6;
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
    /// The access token an authenticated hop presents: sealed in as `authorization: Bearer` right
    /// after `content-type`, where 1.5.5's http stack wrote it.
    pub bearer: Option<Cred>,
    /// The `application/x-www-form-urlencoded` body (empty for a GET). The token exchange's
    /// carries the client secret sealed; its public values (the code, the verifier) are wiped
    /// with it.
    pub body: FormBody,
    /// The hop's timeout.
    pub timeout_ms: u64,
}

impl fmt::Debug for HopRequest {
    // The body's secret and the bearer are the chip's: only names and presence are formatted.
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
    /// sealed in as `authorization` after `content-type`, the form encoded by the SDK into the body
    /// it sends, the reply bounded by `reply_limit`. `None`: the URL has no scheme and authority,
    /// the form could not be encoded, or the exchange refused the request.
    #[must_use]
    pub fn wire(&self, reply_limit: usize) -> Option<Wire> {
        let Some((_, target)) = split(&self.target) else {
            tracing::warn!(
                module = "github",
                "github login: a hop URL has no scheme and authority to split"
            );
            return None;
        };
        let body = self.body.encoded().ok()?;
        let sealed = self
            .bearer
            .iter()
            .map(|b| (1, b"authorization".to_vec(), b.bearer()))
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

/// What the far end answered.
#[derive(Clone, PartialEq, Eq)]
pub struct HopResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body bytes, wiped on drop: the token response carries the access token.
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for HopResponse {
    // The body is the token response (the access token) or a profile: never formatted.
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
    Outage,
    /// A hop body's `id_token` is not bound to the nonce minted at begin (400
    /// "Sign-in couldn't be verified"; the auth ABI's `LOGIN_SECURITY_CHECK_FAILED`).
    SecurityCheckFailed,
}

/// The state kept per flow between hops, owned by the flow.
#[derive(Default)]
struct FlowState {
    access_token: Option<Cred>,
    user: Option<GhUser>,
}

/// The callback's inputs and the last hop answer the step machine reads, every credential among
/// them wiped on drop.
#[derive(Default)]
struct Callback {
    code: Option<Zeroizing<String>>,
    redirect_uri: Option<String>,
    code_verifier: Option<Zeroizing<String>>,
    /// The last answer: its status and body (the token response carries the access token).
    answer: Option<(u16, Zeroizing<String>)>,
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
    // The code, verifier and access token are credential material: never formatted.
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
    /// Empty or invalid settings (a decoder error keeps serde's text only when it
    /// names a key, never a value); a `ca_cert_pem` that is no PEM certificate; a `token_base` or `api_base` not written out (the hop allowlist is built only from
    /// the URLs written in the settings, so every hop to a defaulted base would be refused).
    pub fn open(settings: &str, client_secret: Option<&str>) -> Result<Self, String> {
        if settings.trim().is_empty() {
            return Err("github plugin requires config (client_id); none provided".to_string());
        }
        let cfg: GitHubConfig = serde_json::from_str(settings).map_err(json_error(SETTINGS))?;
        let raw: Value = serde_json::from_str(settings).map_err(json_error(SETTINGS))?;
        if cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| !p.is_empty() && !p.contains("-----BEGIN CERTIFICATE-----"))
        {
            return Err(
                "settings.ca_cert_pem: not a PEM certificate (no -----BEGIN CERTIFICATE----- line)"
                    .to_string(),
            );
        }
        // `authorize_base` is a browser redirect, never a hop: it may stay at its default.
        for key in ["token_base", "api_base"] {
            if raw.get(key).is_none() {
                return Err(format!(
                    "settings: `{key}` must be written out: the hop allowlist is built only from URLs in the settings"
                ));
            }
        }
        // The secret goes only to the token endpoint: an `https` one requires a secured connection.
        let client_secret = client_secret.filter(|s| !s.is_empty()).map(|s| {
            Cred::captured(Zeroizing::new(s.as_bytes().to_vec())).secure_for(&cfg.token_base)
        });
        Ok(Self {
            cfg,
            client_secret,
            allowed_hosts: collect_allowed_hosts(&raw),
        })
    }

    /// Whether the settings name an operator CA (`ca_cert_pem`, non-empty): the hops then go out on
    /// the need that trusts it beside the public roots. Read as the host reads a `trust_from`
    /// path: an empty value names nothing.
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
                None => {
                    if flow.turns >= MAX_HOPS {
                        tracing::warn!(
                            module = "github",
                            "github login: hop limit ({MAX_HOPS}) spent without an identity"
                        );
                        return finish(flow, LoginStep::Outage);
                    }
                    flow.turns += 1;
                    match self.step(flow) {
                        LoginOutcome::Identify(p) => return finish(flow, LoginStep::Identity(p)),
                        LoginOutcome::Reject => return finish(flow, LoginStep::BadCredential),
                        // The step has already said why.
                        LoginOutcome::Outage => return finish(flow, LoginStep::Outage),
                        LoginOutcome::Exchange(mut hop) => {
                            let rendered = self.render(&hop, flow.state.access_token.as_ref());
                            wipe_hop(&mut hop);
                            match rendered {
                                Ok(r) => r,
                                // The guard has already said why.
                                Err(Refused) => return finish(flow, LoginStep::Outage),
                            }
                        }
                        _ => {
                            tracing::warn!(module = "github", "github login: the step machine asked for an outcome this login cannot serve");
                            return finish(flow, LoginStep::Outage);
                        }
                    }
                }
            };
            match ex.exchange(&request) {
                Fetched::Pending => {
                    flow.inflight = Some(request);
                    return LoginStep::Pending;
                }
                Fetched::Unreachable => return finish(flow, LoginStep::Outage),
                Fetched::Ready(mut resp) => {
                    if resp.body.len() > MAX_HOP_REPLY_BYTES {
                        tracing::warn!(
                            module = "github",
                            bytes = resp.body.len(),
                            "github login: a hop reply passed the {MAX_HOP_REPLY_BYTES}-byte cap"
                        );
                        return finish(flow, LoginStep::Outage);
                    }
                    let body = text_of(std::mem::take(&mut *resp.body));
                    // NONCE BINDING: a hop body carrying an
                    // `id_token` must carry the nonce minted at begin, before any identity is
                    // trusted. GitHub issues no id_token, so this never fires against github.com.
                    if !id_token_nonce_binds(&body, flow.nonce.as_ref().map(|n| n.as_str())) {
                        tracing::warn!(module = "github", "github login: a hop body's id_token is not bound to the nonce minted at begin");
                        return finish(flow, LoginStep::SecurityCheckFailed);
                    }
                    flow.req.answer = Some((resp.status, body));
                    if flow.turns >= MAX_HOPS {
                        tracing::warn!(
                            module = "github",
                            "github login: hop limit ({MAX_HOPS}) spent without an identity"
                        );
                        return finish(flow, LoginStep::Outage);
                    }
                }
            }
        }
    }

    /// The `complete_login` step machine, over the flow's own state.
    fn step(&self, flow: &mut LoginFlow) -> LoginOutcome {
        let req = &flow.req;
        let Some((status, body)) = &req.answer else {
            let (Some(code), Some(redirect_uri), Some(code_verifier)) = (
                req.code.as_deref(),
                req.redirect_uri.as_deref(),
                req.code_verifier.as_deref(),
            ) else {
                tracing::info!(module = "github", "github login: declined, the callback lacks its code, redirect_uri or code_verifier");
                return LoginOutcome::Reject;
            };
            return LoginOutcome::Exchange(build_token_exchange(
                &self.cfg,
                code,
                redirect_uri,
                code_verifier,
            ));
        };
        let correlated = req
            .code_verifier
            .as_deref()
            .or(req.code.as_deref())
            .is_some_and(|s| !s.is_empty());
        let (status, body) = (*status, body.as_str());
        if !correlated {
            tracing::info!(
                module = "github",
                "github login: declined, the callback has neither a code_verifier nor a code"
            );
            return LoginOutcome::Reject;
        }
        // An identity provider that could not answer (5xx) or asks to be retried later (429) is
        // an outage, never a declined credential: the host answers 503, retryable, and
        // the cause is logged here.
        if status >= 500 || status == 429 {
            let hop = hop_name(&flow.state);
            tracing::warn!(
                module = "github",
                status = status,
                hop,
                "github login: the identity provider is unavailable"
            );
            flow.state = FlowState::default();
            return LoginOutcome::Outage;
        }
        if !(200..300).contains(&status) {
            let hop = hop_name(&flow.state);
            tracing::info!(
                module = "github",
                status = status,
                hop,
                "github login: declined, non-2xx answer"
            );
            flow.state = FlowState::default();
            return LoginOutcome::Reject;
        }
        if let Some(token) = parse_access_token(body) {
            let hop = build_userinfo_get(&self.cfg);
            flow.state = FlowState {
                access_token: Some(token.secure_for(&self.cfg.api_base)),
                user: None,
            };
            return LoginOutcome::Exchange(hop);
        }
        if is_json_array(body) {
            let state = std::mem::take(&mut flow.state);
            let Some(user) = state.user else {
                tracing::info!(
                    module = "github",
                    "github login: declined, an org list arrived before the user"
                );
                return LoginOutcome::Reject;
            };
            let Some(groups) = parse_org_groups(body) else {
                tracing::info!(
                    module = "github",
                    "github login: declined, /user/orgs answered a malformed list"
                );
                return LoginOutcome::Reject;
            };
            return LoginOutcome::Identify(build_principal(&user, groups));
        }
        let Some(user) = parse_user(body) else {
            if flow.state.access_token.is_none() {
                // The token hop: GitHub answered no access_token.
                match github_error(body) {
                    None => tracing::info!(
                        module = "github",
                        "github login: declined, the token endpoint answered no access_token"
                    ),
                    Some(e) if e == "bad_verification_code" => tracing::info!(
                        module = "github",
                        error = ?e,
                        "github login: declined, the token endpoint refused the code"
                    ),
                    Some(e) => tracing::warn!(
                        module = "github",
                        error = ?e,
                        "github login: the token endpoint refused the exchange (check client_id, client_secret and redirect_uri)"
                    ),
                }
            } else {
                tracing::info!(
                    module = "github",
                    "github login: declined, /user answered without a login or id"
                );
            }
            flow.state = FlowState::default();
            return LoginOutcome::Reject;
        };
        if !self.cfg.fetch_orgs {
            flow.state = FlowState::default();
            return LoginOutcome::Identify(build_principal(&user, Vec::new()));
        }
        if flow.state.access_token.is_none() {
            tracing::info!(
                module = "github",
                "github login: declined, no access token held at /user"
            );
            return LoginOutcome::Reject;
        }
        let hop = build_orgs_get(&self.cfg);
        flow.state.user = Some(user);
        LoginOutcome::Exchange(hop)
    }

    /// Render a hop up to the send: vet the URL, seal the client secret into the named form
    /// field (or drop the placeholder when there is none), and lay out the fields as the http
    /// stack wrote them (`content-type` first, the hop's sanitised headers, then the default
    /// `accept: */*` when the hop set none). An authenticated hop carries `bearer`, which the chip
    /// writes as `authorization` after `content-type`.
    ///
    /// The plugin never holds the secret's or the bearer's bytes here: the body is a [`FormBody`]
    /// the SDK encodes at the wire.
    fn render(&self, hop: &LoginHop, bearer: Option<&Cred>) -> Result<HopRequest, Refused> {
        vet_hop_url(&hop.url, &self.allowed_hosts)?;
        // A token that would split the request fails the hop closed (an outage).
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
        }
        let method = match hop.method.as_str() {
            m if !m.is_empty() && m.bytes().all(|b| b.is_ascii_alphabetic()) => m.to_string(),
            _ => "POST".to_string(),
        };
        let mut fields = vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
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

/// Which hop a held state means the last answer came from (never the URL string).
fn hop_name(state: &FlowState) -> &'static str {
    match (&state.access_token, &state.user) {
        (None, _) => "/login/oauth/access_token",
        (Some(_), None) => "/user",
        (Some(_), Some(_)) => "/user/orgs",
    }
}

/// GitHub's `error` code from a token response body (JSON `error` or form `error=`), if any.
fn github_error(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(trimmed).ok()?;
        return v.get("error").and_then(Value::as_str).map(str::to_string);
    }
    trimmed
        .split('&')
        .find_map(|p| p.strip_prefix("error="))
        .map(str::to_string)
}

fn finish(flow: &mut LoginFlow, step: LoginStep) -> LoginStep {
    flow.inflight = None;
    flow.state = FlowState::default();
    flow.req = Callback::default();
    flow.done = Some(step.clone());
    step
}

/// Wipe the plugin-owned values of a described hop once it is rendered: `LoginHop.form` carries
/// the code and the verifier, in the contract's plain `String`s.
fn wipe_hop(hop: &mut LoginHop) {
    for (_, v) in hop.form.iter_mut().chain(hop.headers.iter_mut()) {
        v.zeroize();
    }
}

/// The nonce binding (a constant-time compare): a body
/// with no `id_token` binds trivially; one with an `id_token` binds only when its payload's `nonce`
/// claim (base64url, no signature check: that is the IdP module's job) equals `minted`.
fn id_token_nonce_binds(body: &str, minted: Option<&str>) -> bool {
    /// Only the `id_token` member is read: the rest of the body (an access token) is skipped,
    /// never copied.
    #[derive(serde::Deserialize)]
    struct IdToken {
        id_token: Option<String>,
    }
    let Some(id_token) = serde_json::from_str::<IdToken>(body)
        .ok()
        .and_then(|t| t.id_token)
        .map(Zeroizing::new)
    else {
        return true;
    };
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
