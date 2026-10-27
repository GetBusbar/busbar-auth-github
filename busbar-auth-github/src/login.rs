// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN-OWNED LOGIN (busbar THE DESIGN §6.7: an IdP login holds its own client secret and makes
//! its token exchange through its own need; §5 Drivers: github through a one-shot `exchange()`).
//!
//! In 1.5.5 the CORE ran the hop loop: it called `complete_login`, executed each described hop
//! (vetting its URL, injecting `client_secret`, sanitising its headers), and fed the response back.
//! Here the plugin runs that loop itself, sans-IO: [`GithubLogin::drive`] turns the 1.5.5 step
//! machine over one flow's own state, renders each hop exactly as 1.5.5's core did, and hands it to an
//! [`Exchange`], which answers [`Fetched::Pending`] until the response is in. A pending exchange
//! returns [`LoginStep::Pending`] with the flow parked on that hop; the next `drive` re-issues the
//! SAME request (a one-shot exchange answers its stored result on the re-issue, never sending twice).
//!
//! What the answer means, as 1.5.5 rendered it:
//!
//! | 1.5.5 core | here |
//! |---|---|
//! | module `Identify` | [`LoginStep::Identity`] |
//! | module `Reject` ("Sign-in was declined", 401) | [`LoginStep::BadCredential`] |
//! | hop refused or unreachable ("Couldn't reach your provider", 502) | [`LoginStep::Outage`] |
//! | hop limit spent / `Authorize` on the callback (502) | [`LoginStep::Outage`] |
//! | a hop body's `id_token` nonce mismatch ("Sign-in couldn't be verified", 400) | [`LoginStep::SecurityCheckFailed`] |
//!
//! Any HTTP status the IdP answers is fed back to the step machine, as 1.5.5 did: a revoked token's
//! `401` from `/user` is a declined sign-in, not an outage. A `5xx` or `429` is the IdP unable to
//! answer: [`LoginStep::Outage`], which the host answers 503, retryable (ruling 2026-10-27; 1.5.5
//! declined it).
//!
//! THE AUTH ABI ADAPTER is [`crate::door`]: it calls [`GithubLogin::open`],
//! [`GithubLogin::begin_login`], [`GithubLogin::start`] and [`GithubLogin::drive`], keeping one
//! [`LoginFlow`] per ticket and each [`Exchange`] one framed `exchange()` over the plugin's need.

use crate::guard::{collect_allowed_hosts, sanitize_hop_header, vet_hop_url, Refused};
use crate::held::Held;
use crate::{
    build_github_authorize_url, build_orgs_get, build_principal, build_token_exchange,
    build_userinfo_get, is_json_array, parse_access_token, parse_org_groups, parse_user, GhUser,
    GitHubConfig,
};
use busbar_contract::auth::{CompleteLogin, LoginHop, LoginHttpResponse, LoginOutcome, Principal};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// 1.5.5's per-hop request timeout (`HOP_TIMEOUT_SECS = 10`).
pub const HOP_TIMEOUT_MS: u64 = 10_000;
/// 1.5.5's bound on `complete_login` turns per callback (`MAX_HOPS = 6`).
pub const MAX_HOPS: usize = 6;
/// The most a hop's reply body may carry: 1 MiB, the bound busbar-auth-oidc puts on a token
/// endpoint's answer. A GitHub token response, `/user` or a 100-entry `/user/orgs` is a few KiB.
pub const MAX_HOP_REPLY_BYTES: usize = 1024 * 1024;

/// One hop, rendered as 1.5.5's core put it on the wire: method, target, header fields in order
/// (lowercase names), the form-encoded body, the timeout.
#[derive(Clone, PartialEq, Eq)]
pub struct HopRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// The absolute URL.
    pub target: String,
    /// The header fields, in order. The values are wiped on drop: `authorization` carries the
    /// bearer.
    pub fields: Vec<(String, Zeroizing<String>)>,
    /// The `application/x-www-form-urlencoded` body (empty for a GET), wiped on drop: the token
    /// exchange's carries the client secret, the code and the verifier.
    pub body: Zeroizing<Vec<u8>>,
    /// The hop's timeout.
    pub timeout_ms: u64,
}

impl fmt::Debug for HopRequest {
    // The body carries the client secret and the fields a bearer: neither is ever formatted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field(
                "fields",
                &self.fields.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish()
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
    /// A hop body's `id_token` is not bound to the nonce minted at begin (1.5.5's 400
    /// "Sign-in couldn't be verified"; the auth ABI's `LOGIN_SECURITY_CHECK_FAILED`).
    SecurityCheckFailed,
}

/// The state 1.5.5 kept per flow between hops (its `PendingLogin`), owned by the flow.
#[derive(Default)]
struct FlowState {
    access_token: Option<Held<String>>,
    user: Option<GhUser>,
}

/// One login in flight: the callback's inputs, the step machine's state, the hop parked on a
/// pending exchange, and the answer once reached (a re-call is served from it, never re-run: an
/// authorization code redeems once).
pub struct LoginFlow {
    req: CompleteLogin,
    state: FlowState,
    turns: usize,
    inflight: Option<HopRequest>,
    done: Option<LoginStep>,
    /// The nonce the kernel minted at begin (`CompleteLoginIn.nonce`), bound to any `id_token`.
    nonce: Option<Held<String>>,
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
    client_secret: Option<Held<String>>,
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
    /// Build the login from its settings (the module config 1.5.5's `open` took, same keys, same
    /// refusal texts) and the client secret the kernel resolved from `browser_login.client_secret`
    /// (busbar v1.5.5 `config/mod.rs:627-646`, resolved core-side at `auth/token.rs:264-276`), which
    /// arrives in `OpenIn.secrets`, never in `settings`: a `client_secret` key in the settings is
    /// refused (`deny_unknown_fields`), exactly as 1.5.5's plugin refused it.
    ///
    /// No secret (`None` or empty) is NOT a refusal: 1.5.5 opened the plugin for a headless-only
    /// provider with no `browser_login` block, and a hop's `client_secret` field was then dropped
    /// (`auth/token.rs:944`). A redirect method missing its secret is refused by the kernel, as 1.5.5
    /// refused it (`validate_browser_login_secret`, `auth/token.rs:264`, `:813`).
    ///
    /// # Errors
    /// Empty or invalid settings (1.5.5's texts; a decoder error keeps serde's text only when it
    /// names a key, never a value); a set `ca_cert_pem` (it has no delivery
    /// channel); a `token_base` or `api_base` not written out (the hop allowlist is built only from
    /// the URLs written in the settings, so every hop to a defaulted base would be refused).
    pub fn open(settings: &str, client_secret: Option<&str>) -> Result<Self, String> {
        if settings.trim().is_empty() {
            return Err("github plugin requires config (client_id); none provided".to_string());
        }
        let cfg: GitHubConfig = serde_json::from_str(settings).map_err(settings_err)?;
        let raw: Value = serde_json::from_str(settings).map_err(settings_err)?;
        if cfg.ca_cert_pem.is_some() {
            return Err(
                "github ca_cert_pem is not yet supported; omit it or use a system-trusted cert"
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
        Ok(Self {
            cfg,
            client_secret: client_secret
                .filter(|s| !s.is_empty())
                .map(|s| Held::new(s.to_string())),
            allowed_hosts: collect_allowed_hosts(&raw),
        })
    }

    /// The parsed config.
    #[must_use]
    pub fn config(&self) -> &GitHubConfig {
        &self.cfg
    }

    /// Start a login: the GitHub authorize URL (1.5.5 `begin_login`).
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

    /// A new flow for one callback (what 1.5.5's core put in the first `CompleteLogin`), with the
    /// nonce the kernel minted at begin (1.5.5 kept it in the login cookie).
    #[must_use]
    pub fn start(
        &self,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> LoginFlow {
        LoginFlow {
            req: CompleteLogin {
                code: code.map(str::to_string),
                redirect_uri: redirect_uri.map(str::to_string),
                code_verifier: code_verifier.map(str::to_string),
                ..Default::default()
            },
            state: FlowState::default(),
            turns: 0,
            inflight: None,
            done: None,
            nonce: nonce.map(|n| Held::new(n.to_string())),
        }
    }

    /// Run `flow` as far as it goes without waiting: 1.5.5's core hop loop, over `ex`.
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
                            let rendered = self.render(&hop);
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
                Fetched::Ready(resp) => {
                    if resp.body.len() > MAX_HOP_REPLY_BYTES {
                        tracing::warn!(
                            module = "github",
                            bytes = resp.body.len(),
                            "github login: a hop reply passed the {MAX_HOP_REPLY_BYTES}-byte cap"
                        );
                        return finish(flow, LoginStep::Outage);
                    }
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    // 1.5.5's core NONCE BINDING, now the plugin's: a hop body carrying an
                    // `id_token` must carry the nonce minted at begin, before any identity is
                    // trusted. GitHub issues no id_token, so this never fires against github.com.
                    if !id_token_nonce_binds(
                        &body,
                        flow.nonce.as_ref().map(|n| n.reveal().as_str()),
                    ) {
                        tracing::warn!(module = "github", "github login: a hop body's id_token is not bound to the nonce minted at begin");
                        return finish(flow, LoginStep::SecurityCheckFailed);
                    }
                    wipe_answer(&mut flow.req);
                    flow.req.token_response = Some(LoginHttpResponse {
                        status: resp.status,
                        body,
                    });
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

    /// 1.5.5's `complete_login` step machine (v1.0.3), over the flow's own state.
    fn step(&self, flow: &mut LoginFlow) -> LoginOutcome {
        let req = &flow.req;
        let Some(resp) = &req.token_response else {
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
            .clone()
            .or_else(|| req.code.clone())
            .is_some_and(|s| !s.is_empty());
        if !correlated {
            tracing::info!(
                module = "github",
                "github login: declined, the callback has neither a code_verifier nor a code"
            );
            return LoginOutcome::Reject;
        }
        // An identity provider that could not answer (5xx) or asks to be retried later (429) is
        // an outage, never a declined credential: the host answers 503, retryable (ruling
        // 2026-10-27), and the cause is logged here.
        if resp.status >= 500 || resp.status == 429 {
            let hop = hop_name(&flow.state);
            tracing::warn!(
                module = "github",
                status = resp.status,
                hop,
                "github login: the identity provider is unavailable"
            );
            flow.state = FlowState::default();
            return LoginOutcome::Outage;
        }
        if !(200..300).contains(&resp.status) {
            let hop = hop_name(&flow.state);
            tracing::info!(
                module = "github",
                status = resp.status,
                hop,
                "github login: declined, non-2xx answer"
            );
            flow.state = FlowState::default();
            return LoginOutcome::Reject;
        }
        if let Some(token) = parse_access_token(&resp.body) {
            let hop = build_userinfo_get(&self.cfg, &token);
            flow.state = FlowState {
                access_token: Some(Held::new(token)),
                user: None,
            };
            return LoginOutcome::Exchange(hop);
        }
        if is_json_array(&resp.body) {
            let state = std::mem::take(&mut flow.state);
            let Some(user) = state.user else {
                tracing::info!(
                    module = "github",
                    "github login: declined, an org list arrived before the user"
                );
                return LoginOutcome::Reject;
            };
            let Some(groups) = parse_org_groups(&resp.body) else {
                tracing::info!(
                    module = "github",
                    "github login: declined, /user/orgs answered a malformed list"
                );
                return LoginOutcome::Reject;
            };
            return LoginOutcome::Identify(build_principal(&user, groups));
        }
        let Some(user) = parse_user(&resp.body) else {
            if flow.state.access_token.is_none() {
                // The token hop: GitHub answered no access_token.
                match github_error(&resp.body) {
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
        let Some(token) = &flow.state.access_token else {
            tracing::info!(
                module = "github",
                "github login: declined, no access token held at /user"
            );
            return LoginOutcome::Reject;
        };
        let hop = build_orgs_get(&self.cfg, token.reveal());
        flow.state.user = Some(user);
        LoginOutcome::Exchange(hop)
    }

    /// 1.5.5's `execute_hop`, up to the send: vet the URL, inject the secret into the named form
    /// field (or drop the placeholder when there is none), form-encode, and lay out the fields as the
    /// http stack wrote them (`content-type` first, the hop's sanitised headers, then the default
    /// `accept: */*` when the hop set none).
    ///
    /// The form is laid out as borrows of the hop's values and the held secret, so the secret is
    /// never copied before the one wiped body it is encoded into.
    fn render(&self, hop: &LoginHop) -> Result<HopRequest, Refused> {
        vet_hop_url(&hop.url, &self.allowed_hosts)?;
        let mut form: Vec<(&str, &str)> = hop
            .form
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if let Some(field) = hop.secret_form_field.as_deref() {
            match &self.client_secret {
                Some(secret) => {
                    let secret = secret.reveal().as_str();
                    if let Some(slot) = form.iter_mut().find(|(k, _)| *k == field) {
                        slot.1 = secret;
                    } else {
                        form.push((field, secret));
                    }
                }
                None => form.retain(|(k, _)| *k != field),
            }
        }
        let method = match hop.method.as_str() {
            m if !m.is_empty() && m.bytes().all(|b| b.is_ascii_alphabetic()) => m.to_string(),
            _ => "POST".to_string(),
        };
        let mut fields = vec![(
            "content-type".to_string(),
            Zeroizing::new("application/x-www-form-urlencoded".to_string()),
        )];
        for (name, value) in &hop.headers {
            fields.push(sanitize_hop_header(name, value)?);
        }
        if !fields.iter().any(|(n, _)| n == "accept") {
            fields.push(("accept".to_string(), Zeroizing::new("*/*".to_string())));
        }
        let mut body = form_encode(&form);
        Ok(HopRequest {
            method,
            target: hop.url.clone(),
            fields,
            // Moves the encoded buffer, no copy.
            body: Zeroizing::new(std::mem::take(&mut *body).into_bytes()),
            timeout_ms: HOP_TIMEOUT_MS,
        })
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
    wipe_answer(&mut flow.req);
    flow.done = Some(step.clone());
    step
}

/// Wipe and clear the last hop answer the step machine read (the token response carries the
/// access token): `LoginHttpResponse.body` is the contract's plain `String`, so it is wiped here.
fn wipe_answer(req: &mut CompleteLogin) {
    if let Some(mut answer) = req.token_response.take() {
        answer.body.zeroize();
    }
}

/// Wipe the plugin-owned values of a described hop once it is rendered: `LoginHop.form` carries
/// the code and the verifier and `LoginHop.headers` the bearer, in the contract's plain `String`s.
fn wipe_hop(hop: &mut LoginHop) {
    for (_, v) in hop.form.iter_mut().chain(hop.headers.iter_mut()) {
        v.zeroize();
    }
}

/// The text of a settings decoder error. `serde_json::Error`'s own `Display` quotes an offending
/// VALUE (`invalid type: integer `12345678``), which may be a secret pasted into the wrong key, so
/// it is kept only when it names a KEY (a missing or unknown field, spelled from the schema and the
/// key); otherwise the class of failure and where (busbar-auth-oauth's `json_err` shape).
fn settings_err(e: serde_json::Error) -> String {
    const WHAT: &str = "invalid github plugin config";
    let text = e.to_string();
    if e.is_data() && (text.starts_with("missing field `") || text.starts_with("unknown field `")) {
        return format!("{WHAT}: {text}");
    }
    let class = match e.classify() {
        serde_json::error::Category::Io => "the input could not be read",
        serde_json::error::Category::Syntax => "it is not well-formed JSON",
        serde_json::error::Category::Data => "a field is missing or has the wrong type",
        serde_json::error::Category::Eof => "it ends before the JSON does",
    };
    let (line, column) = (e.line(), e.column());
    format!("{WHAT}: {class} (line {line}, column {column}; the decoder's text is withheld)")
}

/// 1.5.5's nonce binding (`extract_id_token` + `id_token_nonce` + a constant-time compare): a body
/// with no `id_token` binds trivially; one with an `id_token` binds only when its payload's `nonce`
/// claim (base64url, no signature check: that is the IdP module's job) equals `minted`.
fn id_token_nonce_binds(body: &str, minted: Option<&str>) -> bool {
    let Some(id_token) = serde_json::from_str::<Value>(body).ok().and_then(|v| {
        v.get("id_token")
            .and_then(Value::as_str)
            .map(str::to_string)
    }) else {
        return true;
    };
    let claimed = id_token
        .split('.')
        .nth(1)
        .and_then(b64url_decode)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|claims| {
            claims
                .get("nonce")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    match (claimed, minted) {
        (Some(n), Some(m)) => busbar_contract::constant_time_eq(&n, m),
        _ => false,
    }
}

/// base64url without padding, strict as 1.5.5's `URL_SAFE_NO_PAD` decoder: no `=`, no length of
/// `4k+1`, and the unused trailing bits must be zero.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => {
                if acc & 0b11 != 0 {
                    return None;
                }
                out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]);
            }
            _ => {
                if acc & 0b1111 != 0 {
                    return None;
                }
                out.push((acc >> 4) as u8);
            }
        }
    }
    Some(out)
}

/// Whether `b` is written as itself in a form value (ASCII alphanumerics and `*-._`).
const fn form_kept(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_')
}

/// How many bytes `v` takes form-encoded.
fn form_len(v: &str) -> usize {
    v.bytes()
        .map(|b| if form_kept(b) || b == b' ' { 1 } else { 3 })
        .sum()
}

/// `application/x-www-form-urlencoded`, as 1.5.5's http stack encoded a form (`serde_urlencoded`):
/// ASCII alphanumerics and `*-._` literal, space as `+`, every other byte `%XX` uppercase. Built
/// in ONE buffer sized to the exact length first (busbar-auth-oauth's `form`), so no growth frees a
/// partial copy of the secret the form carries, and held wiped on drop.
#[must_use]
pub fn form_encode(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let len = pairs
        .iter()
        .map(|(k, v)| form_len(k) + 1 + form_len(v))
        .sum::<usize>()
        + pairs.len().saturating_sub(1);
    let mut out = Zeroizing::new(String::with_capacity(len));
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        for (j, part) in [k, v].into_iter().enumerate() {
            if j == 1 {
                out.push('=');
            }
            for b in part.bytes() {
                if form_kept(b) {
                    out.push(char::from(b));
                } else if b == b' ' {
                    out.push('+');
                } else {
                    out.push('%');
                    out.push(char::from(HEX[usize::from(b >> 4)]));
                    out.push(char::from(HEX[usize::from(b & 0x0f)]));
                }
            }
        }
    }
    debug_assert_eq!(out.len(), len);
    out
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
