// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **GitHub-OAuth login module** for busbar — a login-capable auth PLUGIN that establishes identity
//! from a GitHub sign-in. Unlike the OIDC module, GitHub issues an OPAQUE access token and NO
//! `id_token` JWT, so there is nothing to verify offline against a JWKS: identity comes from GitHub's
//! REST API (`/user`, `/user/orgs`). The busbar `LoginModule` ABI (auth ABI v2, 1.5.2 token-exchange)
//! already supports exactly this via the MULTI-HOP [`LoginOutcome::Exchange`] mechanism — the module
//! DESCRIBES an HTTP hop, the CORE executes it and feeds the response back into `complete_login`,
//! bounded to a few hops.
//!
//! ## The hop sequence this module drives
//!
//! 1. `begin_login` → [`LoginOutcome::Authorize`]: the GitHub authorize URL (`client_id`,
//!    `redirect_uri`, `scope`, `state`, PKCE `code_challenge`+`S256`). NO `client_secret`.
//! 2. `complete_login` (has `code`, no token response) → [`LoginOutcome::Exchange`]: `POST` to
//!    `.../login/oauth/access_token` with `client_id`+`code`+`redirect_uri`+`code_verifier` and
//!    `secret_form_field = Some("client_secret")` so the CORE injects the confidential-client secret.
//! 3. `complete_login` (token response fed back) → [`LoginOutcome::Exchange`]: `GET` `.../user`.
//! 4. `complete_login` (`/user` fed back) → [`LoginOutcome::Exchange`]: `GET` `.../user/orgs`
//!    (skipped when `fetch_orgs = false`, in which case identity is established here).
//! 5. `complete_login` (`/user/orgs` fed back) → [`LoginOutcome::Identify`]: `github:<login>` with
//!    `github:org/<org-login>` groups.
//!
//! The confidential-client SECRET is the CORE's alone — it is injected only into the token-exchange
//! hop via `secret_form_field`; the module writes the KEY, never the VALUE. The module asserts
//! IDENTITY only (`github:<login>` + org groups); busbar's `auth.role_bindings.github:` resolves those
//! groups to policy AFTER.
//!
//! ## Authenticated GET hops (auth ABI v2)
//!
//! [`busbar_contract::auth::LoginHop`] carries a `headers` field (auth ABI v2), and GitHub REQUIRES an
//! `Authorization: Bearer <token>` and a `User-Agent` header on every REST call. [`userinfo_headers`]
//! computes those headers; [`build_userinfo_get`] and [`build_orgs_get`] attach them directly to the
//! `/user` and `/user/orgs` hops. The CORE sanitizes and attaches them (CR/LF/NUL + hop-control
//! headers rejected; host must be operator-allowlisted) before executing the hop.
//!
//! ## 1.6.0: the plugin runs its own hops
//!
//! On busbar 1.6.0 the plugin holds its own client secret and runs the hop chain itself over its own
//! need ([`login`]: the same step machine, driven over a one-shot pending exchange; [`guard`]: the
//! hop guard 1.5.5's core applied). [`door`] is the auth kind's door over it: a compiled-in build
//! links [`door`], and the `busbar-auth-github-plugin` image exports it. [`GithubModule`] is
//! the 1.5.5 core-driven shape of the same steps, kept for a custom build that links it statically.

#![forbid(unsafe_code)]

mod door;
mod guard;
mod held;
mod login;

/// THE DOOR: this plugin's one public item (BUSBAR-1.6.0.md l.3567, Crate shape).
pub use door::door;

use crate::held::Held;
use busbar_contract::auth::{
    AuthModule, AuthVerdict, BeginLogin, CompleteLogin, LoginHop, LoginHttpResponse, LoginModule,
    LoginOutcome, Principal,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// The default OAuth scopes requested: `read:org` (to enumerate the caller's org memberships → groups)
/// and `read:user` (the profile `/user` read). Operators can override via `scopes`, and `begin_login`
/// additionally folds in any request-time extra scopes.
fn default_scopes() -> Vec<String> {
    vec!["read:org".to_string(), "read:user".to_string()]
}
/// Default REST API base (`api.github.com`). Overridden for GitHub Enterprise Server (GHES), whose
/// REST API lives at `https://<host>/api/v3`.
fn default_api_base() -> String {
    "https://api.github.com".to_string()
}
/// The public GitHub web base shared by the authorize and token endpoint defaults (both `github.com`;
/// each is overridden to `https://<host>` for GHES). Single source so the two defaults can't drift.
const GITHUB_WEB_BASE: &str = "https://github.com";
/// Default web base for the authorize endpoint (`github.com`). Overridden to `https://<host>` for GHES.
fn default_authorize_base() -> String {
    GITHUB_WEB_BASE.to_string()
}
/// Default web base for the token endpoint (`github.com`). Overridden to `https://<host>` for GHES.
fn default_token_base() -> String {
    GITHUB_WEB_BASE.to_string()
}
fn default_true() -> bool {
    true
}

/// The operator's `auth.modules.github.config` (equivalently the `browser_login`-bearing chain
/// entry's config) settings, deserialized from the JSON the engine passes to the plugin's `open`.
///
/// `#[serde(deny_unknown_fields)]` makes a typo'd/stray operator key a loud boot failure, never a
/// silent no-op. All non-required fields are `#[serde(default)]` so the config is additive-friendly.
/// The confidential-client `client_secret` is DELIBERATELY absent — the CORE holds it
/// (`browser_login.client_secret`) and injects it into the token-exchange hop, exactly like OIDC.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubConfig {
    /// The GitHub OAuth App / GitHub App **client id** (required). Presented on the authorize URL and
    /// the token exchange. The matching client SECRET is never here.
    pub client_id: String,
    /// OAuth scopes to request. Default `["read:org", "read:user"]`. `read:org` is what lets the org
    /// hop enumerate memberships into groups; drop it (and set `fetch_orgs: false`) for login-only.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// REST API base. Default `https://api.github.com`. For **GitHub Enterprise Server** set this to
    /// `https://<ghes-host>/api/v3`.
    #[serde(default = "default_api_base")]
    pub api_base: String,
    /// Web base for the **authorize** endpoint. Default `https://github.com`. For GHES set to
    /// `https://<ghes-host>`.
    #[serde(default = "default_authorize_base")]
    pub authorize_base: String,
    /// Web base for the **token** endpoint. Default `https://github.com`. For GHES set to
    /// `https://<ghes-host>`.
    #[serde(default = "default_token_base")]
    pub token_base: String,
    /// Whether to chain the `/user/orgs` hop and populate `github:org/<org>` groups. Default `true`.
    /// `false` establishes identity from `/user` alone (no groups) and saves a hop.
    #[serde(default = "default_true")]
    pub fetch_orgs: bool,
    /// An ADDITIONAL trusted root CA certificate (PEM) for a GHES instance behind an internal CA whose
    /// endpoints don't chain to a public root. Optional. NOTE: on the committed 1.5.2 ABI the CORE (not
    /// this module) executes every hop, so this value has no delivery channel to the hop executor yet;
    /// it is accepted here so the config is forward-compatible and a GHES operator's intent is captured.
    #[serde(default)]
    #[allow(dead_code)] // accepted for `deny_unknown_fields`; no hop executor reads it yet
    pub ca_cert_pem: Option<String>,
}

/// The authorize endpoint URL (`{authorize_base}/login/oauth/authorize`).
fn authorize_endpoint(cfg: &GitHubConfig) -> String {
    format!(
        "{}/login/oauth/authorize",
        cfg.authorize_base.trim_end_matches('/')
    )
}
/// The token endpoint URL (`{token_base}/login/oauth/access_token`).
fn token_endpoint(cfg: &GitHubConfig) -> String {
    format!(
        "{}/login/oauth/access_token",
        cfg.token_base.trim_end_matches('/')
    )
}
/// The `/user` endpoint URL (`{api_base}/user`).
fn user_endpoint(cfg: &GitHubConfig) -> String {
    format!("{}/user", cfg.api_base.trim_end_matches('/'))
}
/// The `/user/orgs` endpoint URL (`{api_base}/user/orgs?per_page=100`). GitHub paginates this list at
/// 30 entries/page by default; `per_page=100` raises the cap so a user in up to 100 orgs keeps ALL
/// their `github:org/<org>` groups. RESIDUAL LIMIT: the committed 1.5.2 hop ABI feeds back only a
/// single response body and carries no Link-header channel, so this module cannot follow pagination
/// past page 1 — a user in >100 orgs still loses memberships beyond the first 100. Revisit if the ABI
/// grows a way to chain paginated hops.
fn orgs_endpoint(cfg: &GitHubConfig) -> String {
    format!(
        "{}/user/orgs?per_page=100",
        cfg.api_base.trim_end_matches('/')
    )
}

/// Percent-encode `s` for a URL QUERY-component value (RFC 3986 unreserved kept literal, everything
/// else `%`-escaped). Used only for the authorize URL; the token-exchange form is encoded by the CORE.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The space-delimited `scope` value: the configured scopes plus any request-time extras, order
/// preserved and de-duplicated.
fn scope_value(cfg: &GitHubConfig, extra: &[String]) -> String {
    let mut scopes: Vec<String> = Vec::new();
    for s in cfg.scopes.iter().chain(extra.iter()) {
        if !s.is_empty() && !scopes.iter().any(|x| x == s) {
            scopes.push(s.clone());
        }
    }
    scopes.join(" ")
}

/// Build the GitHub **authorization-code** authorize URL: `response_type=code`, `client_id`,
/// `redirect_uri`, `scope` (configured + request-time extras), `state`, and PKCE `code_challenge` +
/// `code_challenge_method=S256`. Structurally cannot contain a `client_secret` — the begin path is
/// public and the secret is the CORE's alone.
///
/// GitHub supports S256 PKCE on the web authorization-code flow (2024+); the `code_challenge` the CORE
/// minted is always sent. A GitHub OAuth App that has not opted into PKCE simply ignores it, and the
/// paired `code_verifier` still rides the token exchange harmlessly. See the crate README's PKCE note.
fn build_github_authorize_url(
    cfg: &GitHubConfig,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    extra_scopes: &[String],
) -> String {
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        authorize_endpoint(cfg),
        pct(&cfg.client_id),
        pct(redirect_uri),
        pct(&scope_value(cfg, extra_scopes)),
        pct(state),
        pct(code_challenge),
    )
}

/// Build the token-exchange hop the CORE executes: `POST` to the token endpoint with `client_id`,
/// `code`, `redirect_uri`, and the PKCE `code_verifier`. The `client_secret` is an EMPTY placeholder
/// keyed by `secret_form_field` — the module writes the KEY, the CORE injects the VALUE, so the secret
/// is structurally core-only.
///
/// NOTE: GitHub's token endpoint returns `application/x-www-form-urlencoded` UNLESS the request sends
/// `Accept: application/json`. This hop sets no `headers` (simpler than relying on an `Accept` header
/// surviving every GitHub App / GHES configuration), so [`parse_access_token`] accepts BOTH shapes to
/// stay robust either way.
fn build_token_exchange(
    cfg: &GitHubConfig,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> LoginHop {
    LoginHop {
        method: "POST".to_string(),
        url: token_endpoint(cfg),
        form: vec![
            ("client_id".to_string(), cfg.client_id.clone()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("code_verifier".to_string(), code_verifier.to_string()),
            // Placeholder ONLY — the CORE overwrites this value with the real confidential-client
            // secret. The plugin writes the key, never the value.
            ("client_secret".to_string(), String::new()),
        ],
        secret_form_field: Some("client_secret".to_string()),
        headers: Vec::new(),
    }
}

/// The request headers the CORE attaches to an authenticated GitHub REST hop: `Authorization:
/// Bearer <token>`, the mandatory `User-Agent` (GitHub rejects a UA-less request), and the `Accept`
/// GitHub recommends. The access token is NOT the confidential-client secret — it is derived by this
/// module from the token-exchange response and is fine for the module to author directly onto the
/// hop's `headers` field (auth ABI v2).
fn userinfo_headers(access_token: &str) -> Vec<(String, String)> {
    vec![
        (
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        ),
        ("User-Agent".to_string(), "busbar".to_string()),
        (
            "Accept".to_string(),
            "application/vnd.github+json".to_string(),
        ),
    ]
}

/// Build the `/user` profile GET hop (no secret), with the `Authorization: Bearer <access_token>` +
/// `User-Agent` + `Accept` headers ([`userinfo_headers`]) attached via the ABI v2 `headers` field. The
/// CORE sanitizes and sends them.
fn build_userinfo_get(cfg: &GitHubConfig, access_token: &str) -> LoginHop {
    LoginHop {
        method: "GET".to_string(),
        url: user_endpoint(cfg),
        form: Vec::new(),
        secret_form_field: None,
        headers: userinfo_headers(access_token),
    }
}

/// Build the `/user/orgs` GET hop (no secret), with the same authenticated headers as
/// [`build_userinfo_get`].
fn build_orgs_get(cfg: &GitHubConfig, access_token: &str) -> LoginHop {
    LoginHop {
        method: "GET".to_string(),
        url: orgs_endpoint(cfg),
        form: Vec::new(),
        secret_form_field: None,
        headers: userinfo_headers(access_token),
    }
}

/// A GitHub `/user` profile, reduced to what identity needs.
#[derive(Debug, Clone, PartialEq)]
struct GhUser {
    /// The GitHub username (`login`) — the handle used in the `github:<login>` identity of record.
    pub login: String,
    /// The IMMUTABLE numeric account id. A `login` can be renamed, released and re-registered by
    /// someone else; this cannot. Surfaced as the `github:id/<id>` role so operators have something
    /// stable to bind to — see [`build_principal`].
    pub id: i64,
    /// Optional display name.
    pub name: Option<String>,
}

/// Parse the access token out of a token-endpoint response body, accepting BOTH the JSON shape
/// (`{"access_token": "..."}`) and the `application/x-www-form-urlencoded` shape
/// (`access_token=...&scope=...&token_type=bearer`) GitHub returns without an `Accept: application/json`
/// header. Returns `None` when absent — which covers GitHub's fail-CLOSED case where the token endpoint
/// answers `HTTP 200` with an `{"error": "..."}` body (a bad/expired code), so a missing token is
/// treated as a rejection, never a success with an empty token.
fn parse_access_token(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(trimmed).ok()?;
        return v
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    // form-urlencoded: split on '&', find access_token=...
    for pair in trimmed.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some("access_token") {
            if let Some(val) = it.next() {
                let val = form_decode(val);
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded` value decode (`+` → space, `%XX` → byte). Sufficient for
/// a GitHub access token / scope value; not a general-purpose decoder.
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a GitHub `/user` response body into a [`GhUser`]. Fail-CLOSED: a missing/empty `login`, a
/// missing numeric `id`, or non-JSON yields `None` (→ the caller `Reject`s).
fn parse_user(body: &str) -> Option<GhUser> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let login = v
        .get("login")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?
        .to_string();
    // Required: a genuine /user body always carries a numeric `id`, so its absence means a
    // malformed/foreign body → fail closed. It used to be parsed purely as that shape check and
    // then discarded; it is KEPT now, because it is the only stable thing GitHub gives us about an
    // account (see `GhUser::id` and `build_principal`).
    let id = v.get("id").and_then(Value::as_i64)?;
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(GhUser { login, id, name })
}

/// Parse a GitHub `/user/orgs` response (a JSON array of org objects) into `github:org/<org-login>`
/// group strings. Fail-CLOSED: malformed JSON or a non-array body yields `None` so the caller can
/// `Reject` — a truncated orgs response must NOT be mistaken for "no orgs" and silently drop the user's
/// org groups (which would lock them out of org-gated roles). A VALID empty array is `Some(vec![])`
/// (login succeeds with zero groups). Individual entries lacking a non-empty `login` are skipped.
fn parse_org_groups(body: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let arr = v.as_array()?;
    Some(
        arr.iter()
            .filter_map(|o| o.get("login").and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(|org| format!("github:org/{org}"))
            .collect(),
    )
}

/// Assemble the identity [`Principal`] from the parsed `/user` and org groups: id `github:<login>`,
/// display name (the profile `name`, falling back to the `login`), and the `github:org/<org>` groups.
///
/// The principal id stays `github:<login>`: it is the documented, human-readable identity operators
/// already bind roles to in `auth.role_bindings.github:`, and changing it would silently break every
/// existing binding and every persisted `user:github:<login>` group at once.
///
/// But a login is NOT a safe thing to anchor identity on, and saying "renaming is rare, just re-bind"
/// understates it. GitHub RELEASES a handle when an account is renamed or deleted, and anyone may then
/// register it. A departed employee's handle, taken by an outsider, produces the identical principal
/// id and inherits that person's role bindings, per-user group, pools and budgets — with nothing
/// anywhere reporting a change of person.
///
/// So the stable numeric account id is emitted ALONGSIDE, as the `github:id/<id>` role. That is
/// purely additive: every existing login binding keeps working untouched, and an operator can bind to
/// `github:id/12345` and migrate at their own pace. New deployments should prefer it.
///
/// WHAT THIS DOES AND DOES NOT FIX, because the difference is easy to overread. It narrows WHO GETS
/// GRANTED: a binding on `github:id/<id>` cannot be inherited by whoever re-registers the handle,
/// because core matches roles by exact lookup and the impostor carries a different numeric role. It
/// does NOT separate the BUCKETS: the enforcement subject is still `principal.id`, so the
/// re-registered handle continues to land on the same `user:github:<login>` group, usage ledger and
/// budget as its previous owner. Separating those means changing the principal id, which is the
/// breaking change this deliberately avoids.
///
/// `github:org/<org>` has the same weakness, being likewise a renameable slug. Closing that one needs
/// the org's numeric id threaded through `parse_org_groups`, a payload change rather than a one-line
/// addition.
fn build_principal(user: &GhUser, org_groups: Vec<String>) -> Principal {
    let mut p = Principal::from_id(format!("github:{}", user.login));
    p.name = Some(user.name.clone().unwrap_or_else(|| user.login.clone()));
    // FIRST, so it is the one an operator reading a principal sees before the org list.
    p.roles = Vec::with_capacity(org_groups.len() + 1);
    p.roles.push(format!("github:id/{}", user.id));
    p.roles.extend(org_groups);
    p
}

/// Convenience for tests: both bodies at once: `/user` JSON (required) + optional
/// `/user/orgs` JSON → an [`LoginOutcome`]. Missing/invalid `/user` is a fail-closed `Reject`.
#[cfg(test)]
fn identity_from_user_and_orgs(user_body: &str, orgs_body: Option<&str>) -> LoginOutcome {
    let Some(user) = parse_user(user_body) else {
        return LoginOutcome::Reject;
    };
    let groups = match orgs_body {
        // Fail-closed: a present-but-malformed /user/orgs body Rejects rather than dropping groups.
        Some(body) => match parse_org_groups(body) {
            Some(g) => g,
            None => return LoginOutcome::Reject,
        },
        None => Vec::new(),
    };
    LoginOutcome::Identify(build_principal(&user, groups))
}

/// Per-flow state threaded across the authenticated hops. The multi-hop `complete_login` ABI feeds the
/// module only the LATEST hop response, but the opaque access token (seen once, in the token-exchange
/// response) is needed to author the SECOND authenticated GET, and the `/user` identity (seen at the
/// `/user` response) is needed to build the final `Principal` at the `/user/orgs` response. This holds
/// both across the hop chain.
/// How long a half-finished flow's state is kept. The core abandons a hop chain without re-entering
/// this module whenever a hop itself fails to execute (an upstream 5xx, a timeout, hop-limit
/// exhaustion), so the entry inserted before that hop is never removed by any code path here. Left
/// unbounded, every abandoned flow retained a LIVE GitHub access token for the process lifetime and
/// an anonymous caller could grow the map without limit just by starting flows and letting the
/// second hop fail. Generous against a real browser round trip, far short of a token's usefulness.
const PENDING_TTL_SECS: u64 = 600;

/// A hard ceiling, independent of the TTL, so a burst cannot outrun the sweep.
const PENDING_MAX: usize = 4096;

#[derive(Debug, Clone)]
struct PendingLogin {
    /// The opaque GitHub bearer, wrapped so a stray `{:?}` on this struct, or on the map that holds
    /// it, cannot print it. Nothing formats these today; this is to keep it that way.
    access_token: Held<String>,
    user: Option<GhUser>,
    /// When this entry was stashed, for the TTL sweep.
    inserted_at: Instant,
}

/// The runtime GitHub login module. Verify-path (`AuthModule`) is a deliberate `Pass` (a GitHub opaque
/// bearer cannot be verified offline; identity is established through the LOGIN flow, which mints a
/// busbar key the `tokens` module then verifies). The login path (`LoginModule`) drives the hop chain.
struct GithubModule {
    cfg: GitHubConfig,
    /// Per-flow hop state keyed by the flow correlator (see [`correlation_key`]).
    pending: Mutex<HashMap<String, PendingLogin>>,
}

impl GithubModule {
    pub fn new(cfg: GitHubConfig) -> Self {
        Self {
            cfg,
            pending: Mutex::new(HashMap::new()),
        }
    }
}

/// The per-flow correlation key used to thread [`PendingLogin`] across `complete_login` calls. The
/// CORE holds the PKCE `code_verifier` (and the OAuth `code`) for the flow's duration; whichever it
/// echoes back on the token-response feedback calls is the stable per-flow key. Falls back through
/// `code_verifier → code` — the only two correlators that are per-flow-UNIQUE.
///
/// DELIBERATELY EXCLUDES `redirect_uri`: it is a DEPLOYMENT-WIDE CONSTANT (every flow shares the same
/// value), so keying on it would collapse all concurrent flows onto ONE shared pending-map slot and let
/// them overwrite each other's stashed token + identity across accounts. Only `code_verifier`/`code`
/// distinguish one in-flight flow from another.
///
/// FAIL-CLOSED: returns `None` when both per-flow correlators are absent/empty. An empty-string
/// fallback key would make every uncorrelatable concurrent flow share one `""` slot and
/// interleave/overwrite each other's stashed token + identity. An uncorrelatable multi-hop flow
/// cannot be safely threaded, so the hop handlers `Reject` on `None` instead.
fn correlation_key(req: &CompleteLogin) -> Option<String> {
    req.code_verifier
        .clone()
        .or_else(|| req.code.clone())
        .filter(|s| !s.is_empty())
}

impl AuthModule for GithubModule {
    fn name(&self) -> &'static str {
        "github"
    }

    /// GitHub access tokens are OPAQUE and cannot be verified offline, and the verify path has no hop
    /// mechanism — so a presented bearer is NOT this module's to judge: `Pass` (defer to the next chain
    /// module / the busbar key the login flow minted). Never `Reject` (that would break the chain for
    /// every non-GitHub credential).
    fn authenticate(&self, _candidate: Option<&str>) -> AuthVerdict {
        AuthVerdict::Pass
    }

    fn cacheable(&self) -> bool {
        false
    }
}

impl LoginModule for GithubModule {
    /// Start browser login: return the GitHub authorize URL (with the CORE-minted `state` and PKCE
    /// `code_challenge`). GitHub CSRF/state is the CORE's job; the module only echoes what the ABI
    /// passes. No confidential-client secret is on this path.
    fn begin_login(&self, req: &BeginLogin) -> LoginOutcome {
        let url = build_github_authorize_url(
            &self.cfg,
            &req.redirect_uri,
            &req.state,
            &req.code_challenge,
            &req.scopes,
        );
        LoginOutcome::Authorize(url)
    }

    /// Drive one step of the GitHub hop chain. Which step is inferred from the SHAPE of the fed-back
    /// response (the ABI carries no step counter):
    ///  * no `token_response` → the token-exchange `POST` hop.
    ///  * response has `access_token` (JSON or form-encoded) → stash it, emit the `/user` GET hop.
    ///  * response is a `/user` object (`login`) → stash the user; emit `/user/orgs` GET (or `Identify`
    ///    now when `fetch_orgs = false`).
    ///  * response is a `/user/orgs` array → build identity from the stashed user + parsed org groups.
    ///
    /// Every non-2xx, missing token, missing `login`, or malformed JSON is a fail-closed `Reject`.
    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        let Some(resp) = &req.token_response else {
            return self.begin_exchange(req);
        };
        // A feedback call must be threadable to its per-flow state; an uncorrelatable one fails closed
        // rather than sharing a slot with other flows (see [`correlation_key`]).
        let Some(key) = correlation_key(req) else {
            return LoginOutcome::Reject;
        };
        if !(200..300).contains(&resp.status) {
            // Terminal fail-closed: drop any state stashed for this flow so the map can't leak.
            self.pending.lock().unwrap().remove(&key);
            return LoginOutcome::Reject;
        }

        // Step by response shape. Token responses carry `access_token`; the `/user` response is a JSON
        // object with `login`; the `/user/orgs` response is a JSON array.
        if let Some(token) = parse_access_token(&resp.body) {
            return self.after_token(&key, token);
        }
        if is_json_array(&resp.body) {
            return self.after_orgs(&key, &resp.body);
        }
        self.after_userinfo(&key, resp)
    }
}

impl GithubModule {
    /// First `complete_login` call: require the `code`+`redirect_uri`+`code_verifier` triple and emit
    /// the token-exchange `POST` (the CORE injects `client_secret`). A callback missing any of the
    /// triple fails closed.
    fn begin_exchange(&self, req: &CompleteLogin) -> LoginOutcome {
        let (Some(code), Some(redirect_uri), Some(code_verifier)) = (
            req.code.as_deref(),
            req.redirect_uri.as_deref(),
            req.code_verifier.as_deref(),
        ) else {
            return LoginOutcome::Reject;
        };
        LoginOutcome::Exchange(build_token_exchange(
            &self.cfg,
            code,
            redirect_uri,
            code_verifier,
        ))
    }

    /// Token-exchange response was fed back: stash the opaque access token and emit the `/user` GET,
    /// bearer-authenticated with that token.
    fn after_token(&self, key: &str, token: String) -> LoginOutcome {
        let hop = build_userinfo_get(&self.cfg, &token);
        let mut pending = self.pending.lock().unwrap();
        Self::sweep(&mut pending);
        if pending.len() >= PENDING_MAX {
            // At the ceiling with nothing sweepable, refuse rather than grow. Every entry here
            // holds a live GitHub bearer, so unbounded growth is both a memory problem and a
            // credential-retention one.
            return LoginOutcome::Reject;
        }
        pending.insert(
            key.to_string(),
            PendingLogin {
                access_token: Held::new(token),
                user: None,
                inserted_at: Instant::now(),
            },
        );
        LoginOutcome::Exchange(hop)
    }

    /// Drop entries older than the TTL.
    ///
    /// Every removal path in this module runs only when the core calls back into it. The core
    /// abandons a hop chain WITHOUT re-entering the module whenever a hop itself fails to execute
    /// (an upstream 5xx, a timeout, hop-limit exhaustion), so the entry stashed before that hop was
    /// never removed by anything. That leaked a live access token per abandoned flow, for the
    /// process lifetime, and let an anonymous caller grow the map without limit by starting flows
    /// and letting the second hop fail. Swept on insert, which is the only path that grows the map.
    fn sweep(pending: &mut HashMap<String, PendingLogin>) {
        let ttl = std::time::Duration::from_secs(PENDING_TTL_SECS);
        let now = Instant::now();
        pending.retain(|_, e| now.saturating_duration_since(e.inserted_at) < ttl);
    }

    /// `/user` response was fed back: parse `login`/`id` (fail-closed on missing `login`). When
    /// `fetch_orgs` is on, stash the user and emit the `/user/orgs` GET; otherwise establish identity
    /// with no org groups now.
    fn after_userinfo(&self, key: &str, resp: &LoginHttpResponse) -> LoginOutcome {
        let Some(user) = parse_user(&resp.body) else {
            // Terminal fail-closed: drop the token stashed at the token step so the map can't leak.
            self.pending.lock().unwrap().remove(key);
            return LoginOutcome::Reject;
        };
        if !self.cfg.fetch_orgs {
            self.pending.lock().unwrap().remove(key);
            return LoginOutcome::Identify(build_principal(&user, Vec::new()));
        }
        let mut pending = self.pending.lock().unwrap();
        // Fail-closed: no stashed entry means the token step never ran for this key (a flow-state loss
        // or an out-of-order /user body). Fabricating a default empty-token `PendingLogin` would emit
        // a `/user/orgs` hop with an empty `Bearer`, so this rejects instead, mirroring `after_orgs`.
        let Some(entry) = pending.get_mut(key) else {
            return LoginOutcome::Reject;
        };
        entry.user = Some(user);
        // The `/user/orgs` GET is authenticated with the SAME opaque access token stashed at the token
        // step, attached via the ABI v2 `headers` field.
        LoginOutcome::Exchange(build_orgs_get(&self.cfg, entry.access_token.reveal()))
    }

    /// `/user/orgs` array was fed back: pair the stashed `/user` identity with the parsed
    /// `github:org/<org>` groups → `Identify`. A missing stashed user (a flow-state loss) fails closed.
    fn after_orgs(&self, key: &str, body: &str) -> LoginOutcome {
        // `remove` up front makes EVERY path below terminal-clean (no leak on either Reject or Identify).
        let entry = self.pending.lock().unwrap().remove(key);
        let Some(user) = entry.and_then(|p| p.user) else {
            return LoginOutcome::Reject;
        };
        // Fail-closed: a malformed /user/orgs body Rejects rather than dropping the user's org groups.
        let Some(groups) = parse_org_groups(body) else {
            return LoginOutcome::Reject;
        };
        LoginOutcome::Identify(build_principal(&user, groups))
    }
}

/// Whether a body's first non-whitespace char is `[` (a JSON array — the `/user/orgs` shape).
pub(crate) fn is_json_array(body: &str) -> bool {
    body.trim_start().starts_with('[')
}

#[cfg(test)]
mod tests;
