// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **GitHub-OAuth login module** for busbar — a login-capable auth PLUGIN that establishes identity
//! from a GitHub sign-in. Unlike the OIDC module, GitHub issues an OPAQUE access token and NO
//! `id_token` JWT, so there is nothing to verify offline against a JWKS: identity comes from GitHub's
//! REST API (`/user`, `/user/orgs`).
//!
//! ## The hop sequence
//!
//! 1. `begin_login`: the GitHub authorize URL (`client_id`, `redirect_uri`, `scope`, `state`, PKCE
//!    `code_challenge`+`S256`). NO `client_secret`.
//! 2. The callback's `code` + `redirect_uri` + `code_verifier` → a [`LoginHop`]: `POST` to
//!    `.../login/oauth/access_token`, its `client_secret` field named by `secret_form_field`.
//! 3. The token response → `GET .../user`, bearer-authenticated.
//! 4. The `/user` response → `GET .../user/orgs` (skipped when `fetch_orgs = false`, in which case
//!    identity is established here).
//! 5. The `/user/orgs` response → `github:<login>` with `github:id/<id>` and `github:org/<org-login>`
//!    groups.
//!
//! The module asserts IDENTITY only; busbar's `auth.role_bindings.github:` resolves those groups to
//! policy AFTER.
//!
//! ## The plugin runs its own hops
//!
//! The plugin holds its own client secret and runs the hop chain itself over its own need
//! ([`login`]: the step machine, driven over a one-shot pending exchange, which injects the secret
//! into the named form field; [`guard`]: the hop guard). [`door`] is the auth
//! kind's door over it: a compiled-in build links [`door::door`], and the `busbar-auth-github-plugin`
//! image exports it. The `build_*` helpers below DESCRIBE each hop as the contract's [`LoginHop`];
//! [`login`] renders and sends it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod door;
pub mod guard;
pub mod login;

use busbar_contract::abi::sdk::cred::{json_reply, Cred};
use busbar_contract::auth::{LoginHop, Principal};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

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
/// silent no-op. [`login::GithubLogin::open`] further refuses a `token_base` or `api_base` not
/// written out (the hop allowlist is built only from the URLs in the settings) and a
/// `ca_cert_pem` that is no PEM certificate. The confidential-client `client_secret` is DELIBERATELY absent: the kernel
/// resolves `browser_login.client_secret` and hands it to the plugin beside the settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubConfig {
    /// The GitHub OAuth App / GitHub App **client id** (required). Presented on the authorize URL and
    /// the token exchange. The matching client SECRET is never here.
    pub client_id: String,
    /// OAuth scopes to request. Default `["read:org", "read:user"]`. `read:org` is what lets the org
    /// hop enumerate memberships into groups; drop it (and set `fetch_orgs: false`) for login-only.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// REST API base, e.g. `https://api.github.com`; for **GitHub Enterprise Server**
    /// `https://<ghes-host>/api/v3`. Must be written out in the settings (the parsed default is
    /// not on the hop allowlist, so `open` refuses settings without it).
    #[serde(default = "default_api_base")]
    pub api_base: String,
    /// Web base for the **authorize** endpoint. Default `https://github.com`. For GHES set to
    /// `https://<ghes-host>`.
    #[serde(default = "default_authorize_base")]
    pub authorize_base: String,
    /// Web base for the **token** endpoint, e.g. `https://github.com`; for GHES
    /// `https://<ghes-host>`. Must be written out in the settings, as `api_base`.
    #[serde(default = "default_token_base")]
    pub token_base: String,
    /// Whether to chain the `/user/orgs` hop and populate `github:org/<org>` groups. Default `true`.
    /// `false` establishes identity from `/user` alone (no groups) and saves a hop.
    #[serde(default = "default_true")]
    pub fetch_orgs: bool,
    /// An ADDITIONAL trusted root CA certificate (PEM) for a GHES instance behind an internal CA,
    /// layered on top of the public roots, never a replacement. The host's connector does the TLS:
    /// the hops go out on the need whose `trust_from` is this setting. A value with no PEM
    /// certificate in it is refused at validate/open, named.
    #[serde(default)]
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
/// The `/user/orgs` endpoint URL (`{api_base}/user/orgs?per_page=100`): its first page. GitHub
/// paginates this list (30 entries a page by default; `per_page=100` is its most). The login follows
/// each page's `Link: rel="next"` ([`next_link`]) on the API's origin, up to
/// [`login::MAX_ORG_PAGES`] pages (1000 orgs); past that the org list is logged as truncated.
fn orgs_endpoint(cfg: &GitHubConfig) -> String {
    format!(
        "{}/user/orgs?per_page=100",
        cfg.api_base.trim_end_matches('/')
    )
}

/// Percent-encode `s` for a URL QUERY-component value (RFC 3986 unreserved kept literal, everything
/// else `%`-escaped). Used only for the authorize URL; the token-exchange form is encoded by the
/// SDK's `FormBody`.
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
/// `code_challenge_method=S256`. Structurally cannot contain a `client_secret`: the begin path is
/// public.
///
/// GitHub supports S256 PKCE on the web authorization-code flow (2024+); the `code_challenge` the
/// kernel minted is always sent. A GitHub OAuth App that has not opted into PKCE simply ignores it, and the
/// paired `code_verifier` still rides the token exchange harmlessly. See the crate README's PKCE note.
pub fn build_github_authorize_url(
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

/// Build the token-exchange hop: `POST` to the token endpoint with `client_id`, `code`,
/// `redirect_uri`, and the PKCE `code_verifier`. The `client_secret` is an EMPTY placeholder keyed by
/// `secret_form_field`: the step machine writes the KEY, and [`login`]'s renderer seals the client
/// secret (the chip's `Cred`) into that slot of the form body (or drops the field when no secret
/// was given).
///
/// NOTE: GitHub's token endpoint returns `application/x-www-form-urlencoded` UNLESS the request sends
/// `Accept: application/json`. This hop sets no `headers` (simpler than relying on an `Accept` header
/// surviving every GitHub App / GHES configuration), so [`parse_access_token`] accepts BOTH shapes to
/// stay robust either way.
pub fn build_token_exchange(
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
            // Placeholder ONLY: the renderer overwrites this value with the held client secret.
            ("client_secret".to_string(), String::new()),
        ],
        secret_form_field: Some("client_secret".to_string()),
        headers: Vec::new(),
    }
}

/// The public request headers of an authenticated GitHub REST hop: the mandatory `User-Agent`
/// (GitHub rejects a UA-less request) and the `Accept` GitHub recommends. Its `Authorization:
/// Bearer <token>` is the chip's, sealed in ahead of them when the hop is rendered.
pub fn userinfo_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), "busbar".to_string()),
        (
            "Accept".to_string(),
            "application/vnd.github+json".to_string(),
        ),
    ]
}

/// Build the `/user` profile GET hop, with the `User-Agent` + `Accept` headers
/// ([`userinfo_headers`]); the bearer is sealed in when it is rendered.
pub fn build_userinfo_get(cfg: &GitHubConfig) -> LoginHop {
    LoginHop {
        method: "GET".to_string(),
        url: user_endpoint(cfg),
        form: Vec::new(),
        secret_form_field: None,
        headers: userinfo_headers(),
    }
}

/// Build the `/user/orgs` GET hop, with the same headers as [`build_userinfo_get`].
pub fn build_orgs_get(cfg: &GitHubConfig) -> LoginHop {
    LoginHop {
        method: "GET".to_string(),
        url: orgs_endpoint(cfg),
        form: Vec::new(),
        secret_form_field: None,
        headers: userinfo_headers(),
    }
}

/// Build the GET hop of a later `/user/orgs` page: `url` is the previous page's `Link: rel="next"`
/// (the login checks it is on the API's origin; the hop guard vets it as every hop), with the same
/// headers as [`build_orgs_get`].
pub fn build_orgs_page_get(url: &str) -> LoginHop {
    LoginHop {
        method: "GET".to_string(),
        url: url.to_string(),
        form: Vec::new(),
        secret_form_field: None,
        headers: userinfo_headers(),
    }
}

/// The target of an RFC 8288 `Link` field's `rel="next"` link (`<url>; rel="next", ...`), if any.
/// A `rel` may list several relation types (`rel="next last"`); its name and value are matched
/// ASCII case-insensitively.
pub fn next_link(link: &str) -> Option<&str> {
    let mut rest = link;
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        let close = after.find('>')?;
        let target = &after[..close];
        let params_end = after[close + 1..]
            .find('<')
            .map_or(after.len(), |i| close + 1 + i);
        let params = &after[close + 1..params_end];
        let is_next = params.split(';').any(|p| {
            let Some((name, value)) = p.split_once('=') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("rel")
                && value
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .trim_matches('"')
                    .split_ascii_whitespace()
                    .any(|r| r.eq_ignore_ascii_case("next"))
        });
        if is_next {
            return Some(target.trim());
        }
        rest = &after[close + 1..];
    }
    None
}

/// A GitHub `/user` profile, reduced to what identity needs.
#[derive(Debug, Clone, PartialEq)]
pub struct GhUser {
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
/// header. The token is captured into the chip's [`Cred`] as it is read (the plugin never holds it
/// as text). Returns `None` when absent — which covers GitHub's fail-CLOSED case where the token endpoint
/// answers `HTTP 200` with an `{"error": "..."}` body (a bad/expired code), so a missing token is
/// treated as a rejection, never a success with an empty token. A JSON array (the `/user/orgs` shape)
/// is never a token response, so its text can never reach the form branch.
pub fn parse_access_token(body: &str) -> Option<Cred> {
    /// Only `access_token` is read, captured as the parser meets it.
    #[derive(Deserialize)]
    struct TokenReply {
        access_token: Option<Cred>,
    }
    let trimmed = body.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return json_reply::<TokenReply>(trimmed.as_bytes())
            .ok()?
            .access_token
            .filter(|t| !t.is_empty());
    }
    for pair in trimmed.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some("access_token") {
            if let Some(val) = it.next() {
                let val = form_decode(val);
                if !val.is_empty() {
                    return Some(Cred::captured(val));
                }
            }
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded` value decode (`+` → space, `%XX` → byte), into a
/// buffer wiped on drop, sized once so no growth leaves a copy behind. Sufficient for a GitHub
/// access token / scope value; not a general-purpose decoder.
fn form_decode(s: &str) -> Zeroizing<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
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
    out
}

/// Parse a GitHub `/user` response body into a [`GhUser`]. Fail-CLOSED: a missing/empty `login`, a
/// missing numeric `id`, or non-JSON yields `None` (→ the caller `Reject`s).
pub fn parse_user(body: &str) -> Option<GhUser> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let login = v
        .get("login")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?
        .to_string();
    // Required: a genuine /user body always carries a numeric `id`, so its absence means a
    // malformed/foreign body → fail closed. It is also KEPT: it is the only stable thing GitHub
    // gives us about an account (see `GhUser::id` and `build_principal`).
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
pub fn parse_org_groups(body: &str) -> Option<Vec<String>> {
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
/// `github:id/12345`. New deployments should prefer it.
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
pub fn build_principal(user: &GhUser, org_groups: Vec<String>) -> Principal {
    let mut p = Principal::from_id(format!("github:{}", user.login));
    p.name = Some(user.name.clone().unwrap_or_else(|| user.login.clone()));
    // FIRST, so it is the one an operator reading a principal sees before the org list.
    p.roles = Vec::with_capacity(org_groups.len() + 1);
    p.roles.push(format!("github:id/{}", user.id));
    p.roles.extend(org_groups);
    p
}

/// Whether a body's first non-whitespace char is `[` (a JSON array — the `/user/orgs` shape).
pub(crate) fn is_json_array(body: &str) -> bool {
    body.trim_start().starts_with('[')
}

#[cfg(test)]
mod tests;
