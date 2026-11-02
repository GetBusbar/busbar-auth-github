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
fn default_scopes() -> Vec<String> {
    vec!["read:org".to_string(), "read:user".to_string()]
}
/// Default REST API base (`api.github.com`). Overridden for GitHub Enterprise Server (GHES), whose
fn default_api_base() -> String {
    "https://api.github.com".to_string()
}
/// The public GitHub web base shared by the authorize and token endpoint defaults (both `github.com`;
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
    /// certificate in it, or a blank one, is refused at validate/open, named.
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
fn orgs_endpoint(cfg: &GitHubConfig) -> String {
    format!(
        "{}/user/orgs?per_page=100",
        cfg.api_base.trim_end_matches('/')
    )
}

/// Percent-encode `s` for a URL QUERY-component value (RFC 3986 unreserved kept literal, everything
fn pct(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 0x0f)]));
            }
        }
    }
    out
}

/// The space-delimited `scope` value: the configured scopes plus `extra` (the door passes none),
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
        headers: vec![("Accept".to_string(), "application/json".to_string())],
    }
}

/// The public request headers of an authenticated GitHub REST hop: the mandatory `User-Agent`
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
pub fn parse_access_token(body: &str) -> Option<Cred> {
    /// Only `access_token` is read, captured as the parser meets it.
    #[derive(Deserialize)]
    struct TokenReply {
        access_token: Option<Cred>,
    }
    let trimmed = body.trim();
    if trimmed.starts_with('[') {
        return None;
    }
    if trimmed.starts_with('{') {
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

/// The most bytes a GitHub login (a user's or an org's) may hold here; GitHub's own limit is 39.
pub const MAX_LOGIN_BYTES: usize = 64;
/// The most characters of a profile `name` kept; a longer one is cut.
pub const MAX_NAME_CHARS: usize = 256;

/// Whether `login` is one a GitHub reply can carry: non-empty, at most [`MAX_LOGIN_BYTES`], no
fn plain_login(login: &str) -> bool {
    !login.is_empty() && login.len() <= MAX_LOGIN_BYTES && !login.chars().any(char::is_control)
}

/// Parse a GitHub `/user` response body into a [`GhUser`]. Fail-CLOSED: a missing, empty or
pub fn parse_user(body: &str) -> Option<GhUser> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let login = v
        .get("login")
        .and_then(Value::as_str)
        .filter(|s| plain_login(s))?
        .to_string();

    let id = v.get("id").and_then(Value::as_i64)?;
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && !s.chars().any(|c| {
                    c.is_control()
                        || matches!(
                            c,
                            // Unicode 17.0 General_Category=Cf, plus the line/paragraph separators.
                            '\u{00ad}'
                                | '\u{0600}'..='\u{0605}'
                                | '\u{061c}'
                                | '\u{06dd}'
                                | '\u{070f}'
                                | '\u{0890}'..='\u{0891}'
                                | '\u{08e2}'
                                | '\u{180e}'
                                | '\u{200b}'..='\u{200f}'
                                | '\u{2028}'..='\u{202e}'
                                | '\u{2060}'..='\u{2064}'
                                | '\u{2066}'..='\u{206f}'
                                | '\u{feff}'
                                | '\u{fff9}'..='\u{fffb}'
                                | '\u{110bd}'
                                | '\u{110cd}'
                                | '\u{13430}'..='\u{1343f}'
                                | '\u{1bca0}'..='\u{1bca3}'
                                | '\u{1d173}'..='\u{1d17a}'
                                | '\u{e0001}'
                                | '\u{e0020}'..='\u{e007f}'
                        )
                })
        })
        .map(|s| s.chars().take(MAX_NAME_CHARS).collect());
    Some(GhUser { login, id, name })
}

/// Parse a GitHub `/user/orgs` response (a JSON array of org objects) into `github:org/<org-login>`
pub fn parse_org_groups(body: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let mut groups = Vec::new();
    for org in v.as_array()? {
        match org.get("login").and_then(Value::as_str) {
            Some(login) if plain_login(login) => groups.push(format!("github:org/{login}")),
            _ => return None,
        }
    }
    Some(groups)
}

/// Assemble the identity [`Principal`] from the parsed `/user` and org groups: id `github:<login>`,
pub fn build_principal(user: &GhUser, org_groups: Vec<String>) -> Principal {
    let mut p = Principal::from_id(format!("github:{}", user.login));
    p.name = Some(user.name.clone().unwrap_or_else(|| user.login.clone()));

    p.roles = Vec::with_capacity(org_groups.len() + 1);
    p.roles.push(format!("github:id/{}", user.id));
    p.roles.extend(org_groups);
    p
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod diagnostics;
