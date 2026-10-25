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
//! `401` from `/user` is a declined sign-in, not an outage.
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

/// 1.5.5's per-hop request timeout (`HOP_TIMEOUT_SECS = 10`).
pub const HOP_TIMEOUT_MS: u64 = 10_000;
/// 1.5.5's bound on `complete_login` turns per callback (`MAX_HOPS = 6`).
pub const MAX_HOPS: usize = 6;

/// One hop, rendered as 1.5.5's core put it on the wire: method, target, header fields in order
/// (lowercase names), the form-encoded body, the timeout.
#[derive(Clone, PartialEq, Eq)]
pub struct HopRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// The absolute URL.
    pub target: String,
    /// The header fields, in order.
    pub fields: Vec<(String, String)>,
    /// The `application/x-www-form-urlencoded` body (empty for a GET).
    pub body: Vec<u8>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body bytes.
    pub body: Vec<u8>,
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
    /// Empty or invalid settings (1.5.5's texts).
    pub fn open(settings: &str, client_secret: Option<&str>) -> Result<Self, String> {
        if settings.trim().is_empty() {
            return Err("github plugin requires config (client_id); none provided".to_string());
        }
        let cfg: GitHubConfig = serde_json::from_str(settings)
            .map_err(|e| format!("invalid github plugin config: {e}"))?;
        let raw: Value = serde_json::from_str(settings)
            .map_err(|e| format!("invalid github plugin config: {e}"))?;
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
                            "github login: hop limit ({MAX_HOPS}) spent without an identity"
                        );
                        return finish(flow, LoginStep::Outage);
                    }
                    flow.turns += 1;
                    match self.step(flow) {
                        LoginOutcome::Identify(p) => return finish(flow, LoginStep::Identity(p)),
                        LoginOutcome::Reject => return finish(flow, LoginStep::BadCredential),
                        LoginOutcome::Exchange(hop) => match self.render(&hop) {
                            Ok(r) => r,
                            // The guard has already said why.
                            Err(Refused) => return finish(flow, LoginStep::Outage),
                        },
                        _ => {
                            tracing::warn!("github login: the step machine asked for an outcome this login cannot serve");
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
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    // 1.5.5's core NONCE BINDING, now the plugin's: a hop body carrying an
                    // `id_token` must carry the nonce minted at begin, before any identity is
                    // trusted. GitHub issues no id_token, so this never fires against github.com.
                    if !id_token_nonce_binds(
                        &body,
                        flow.nonce.as_ref().map(|n| n.reveal().as_str()),
                    ) {
                        tracing::warn!("github login: a hop body's id_token is not bound to the nonce minted at begin");
                        return finish(flow, LoginStep::SecurityCheckFailed);
                    }
                    flow.req.token_response = Some(LoginHttpResponse {
                        status: resp.status,
                        body,
                    });
                    if flow.turns >= MAX_HOPS {
                        tracing::warn!(
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
                tracing::info!("github login: declined, the callback lacks its code, redirect_uri or code_verifier");
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
                "github login: declined, the callback has neither a code_verifier nor a code"
            );
            return LoginOutcome::Reject;
        }
        if !(200..300).contains(&resp.status) {
            let hop = hop_name(&flow.state);
            tracing::info!(
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
                tracing::info!("github login: declined, an org list arrived before the user");
                return LoginOutcome::Reject;
            };
            let Some(groups) = parse_org_groups(&resp.body) else {
                tracing::info!("github login: declined, /user/orgs answered a malformed list");
                return LoginOutcome::Reject;
            };
            return LoginOutcome::Identify(build_principal(&user, groups));
        }
        let Some(user) = parse_user(&resp.body) else {
            if flow.state.access_token.is_none() {
                // The token hop: GitHub answered no access_token.
                match github_error(&resp.body) {
                    None => tracing::info!(
                        "github login: declined, the token endpoint answered no access_token"
                    ),
                    Some(e) if e == "bad_verification_code" => tracing::info!(
                        error = ?e,
                        "github login: declined, the token endpoint refused the code"
                    ),
                    Some(e) => tracing::warn!(
                        error = ?e,
                        "github login: the token endpoint refused the exchange (check client_id, client_secret and redirect_uri)"
                    ),
                }
            } else {
                tracing::info!("github login: declined, /user answered without a login or id");
            }
            flow.state = FlowState::default();
            return LoginOutcome::Reject;
        };
        if !self.cfg.fetch_orgs {
            flow.state = FlowState::default();
            return LoginOutcome::Identify(build_principal(&user, Vec::new()));
        }
        let Some(token) = &flow.state.access_token else {
            tracing::info!("github login: declined, no access token held at /user");
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
    fn render(&self, hop: &LoginHop) -> Result<HopRequest, Refused> {
        vet_hop_url(&hop.url, &self.allowed_hosts)?;
        let mut form: Vec<(String, String)> = hop.form.clone();
        if let Some(field) = hop.secret_form_field.as_deref() {
            match &self.client_secret {
                Some(secret) => {
                    if let Some(slot) = form.iter_mut().find(|(k, _)| k == field) {
                        slot.1 = secret.reveal().clone();
                    } else {
                        form.push((field.to_string(), secret.reveal().clone()));
                    }
                }
                None => form.retain(|(k, _)| k != field),
            }
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
            body: form_encode(&form).into_bytes(),
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
    flow.done = Some(step.clone());
    step
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

/// `application/x-www-form-urlencoded`, as 1.5.5's http stack encoded a form (`serde_urlencoded`):
/// ASCII alphanumerics and `*-._` literal, space as `+`, every other byte `%XX` uppercase.
#[must_use]
pub fn form_encode(pairs: &[(String, String)]) -> String {
    fn enc(s: &str, out: &mut String) {
        for &b in s.as_bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        enc(k, &mut out);
        out.push('=');
        enc(v, &mut out);
    }
    out
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
