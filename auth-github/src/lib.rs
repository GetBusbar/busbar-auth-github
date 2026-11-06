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
//! 5. The `/user/orgs` response → provider-scoped numeric user and organization
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
/// and `read:user` (the profile `/user` read). Operators can override via `scopes`; the door asks
/// for the configured scopes plus any the host requests at begin time.
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
    /// Whether to chain `/user/orgs` and populate immutable organization grants. Default `true`.
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
/// paginates this list (30 entries a page by default; `per_page=100` is its most). The login follows
/// each page's `Link: rel="next"` ([`read_link`]) on the API's origin, up to
/// [`login::MAX_ORG_PAGES`] pages, each subject to the reply byte cap and to [`ORGS_PER_PAGE`]
/// entries; past that the org list is logged as truncated.
fn orgs_endpoint(cfg: &GitHubConfig) -> String {
    format!(
        "{}/user/orgs?per_page={ORGS_PER_PAGE}",
        cfg.api_base.trim_end_matches('/')
    )
}

/// The org entries one `/user/orgs` page is asked for (`per_page`, GitHub's most). A page that
/// carries more is no answer GitHub gives to that request: [`parse_org_groups`] refuses it, which
/// bounds the groups one login can assert at [`login::MAX_ORG_PAGES`] pages of this many.
pub const ORGS_PER_PAGE: usize = 100;

/// Percent-encode `s` for a URL QUERY-component value (RFC 3986 unreserved kept literal, everything
/// else `%`-escaped). Used only for the authorize URL; the token-exchange form is encoded by the
/// SDK's `FormBody`.
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

/// The space-delimited `scope` value: the configured scopes plus `extra` (the host's requested scopes),
/// order preserved and de-duplicated.
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
/// `redirect_uri`, `scope` (the configured scopes, plus `extra_scopes`: the host's requested scopes), `state`, and PKCE `code_challenge` +
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
/// `secret_form_field`: [`login`]'s renderer seals the client secret (the chip's `Cred`) into that
/// slot of the form body (or drops the field when no secret was given).
///
/// GitHub's token endpoint answers `application/x-www-form-urlencoded` UNLESS the request sends
/// `Accept: application/json`, which this hop sends. [`parse_access_token`] still reads BOTH shapes,
/// for a GitHub App or GHES that answers the form anyway. The form is 1.5.5's, byte for byte (no
/// `grant_type`: GitHub's endpoint does not ask for it).
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

/// An RFC 7230 `tchar` ([`guard::is_tchar`]): what a link-param name or bare value is made of.
fn is_tchar(c: char) -> bool {
    u8::try_from(c).is_ok_and(guard::is_tchar)
}

/// Read an RFC 8288 `Link` field for its `rel="next"` link (`<url>; rel="next", ...`):
/// `Some(Some(target))` at the first link whose first `rel` names `next`, `Some(None)` when the
/// field is read to its end with none, `None` when it cannot be read before a next link is found
/// (not `<URI-Reference>` link-values with `;` params, separated by `,`). A `rel` may list several
/// relation types (`rel="next last"`); its name and value are matched ASCII case-insensitively.
/// Only a link's FIRST `rel` parameter counts (RFC 8288 §3.3), and a quoted value is read as one
/// quoted-string (a `;`, `,` or `<` inside it is not syntax).
pub(crate) fn read_link(link: &str) -> Option<Option<&str>> {
    const OWS: [char; 2] = [' ', '\t'];
    let mut rest = link;
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        if rest.is_empty() {
            return Some(None);
        }
        let after = rest.strip_prefix('<')?;
        let close = after.find('>')?;
        let target = &after[..close];
        rest = &after[close + 1..];
        let mut rel: Option<bool> = None;
        loop {
            rest = rest.trim_start_matches(OWS);
            let Some(param) = rest.strip_prefix(';') else {
                break;
            };
            rest = param.trim_start_matches(OWS);
            let name_end = rest.find(|c: char| !is_tchar(c)).unwrap_or(rest.len());
            let name = &rest[..name_end];
            if name.is_empty() {
                return None;
            }
            rest = rest[name_end..].trim_start_matches(OWS);
            let mut value = String::new();
            if let Some(v) = rest.strip_prefix('=') {
                rest = v.trim_start_matches(OWS);
                if let Some(quoted) = rest.strip_prefix('"') {
                    let mut chars = quoted.char_indices();
                    let mut end = None;
                    while let Some((at, c)) = chars.next() {
                        match c {
                            '\\' => value.push(chars.next()?.1),
                            '"' => {
                                end = Some(at);
                                break;
                            }
                            c => value.push(c),
                        }
                    }
                    rest = &quoted[end? + 1..];
                } else {
                    let end = rest.find(|c: char| !is_tchar(c)).unwrap_or(rest.len());
                    value.push_str(&rest[..end]);
                    rest = &rest[end..];
                }
            }
            if rel.is_none() && name.eq_ignore_ascii_case("rel") {
                rel = Some(
                    value
                        .split_ascii_whitespace()
                        .any(|r| r.eq_ignore_ascii_case("next")),
                );
            }
        }
        if rel == Some(true) {
            return Some(Some(target.trim()));
        }
        rest = rest.trim_start_matches(OWS);
        if !(rest.is_empty() || rest.starts_with(',')) {
            return None;
        }
    }
}

/// A GitHub `/user` profile, reduced to what identity needs.
#[derive(Debug, Clone, PartialEq)]
pub struct GhUser {
    /// The GitHub username (`login`), retained only as display metadata.
    pub login: String,
    /// The IMMUTABLE numeric account id. A `login` can be renamed, released and re-registered by
    /// someone else; this cannot. Used in the provider-qualified subject and user grant so operators have something
    /// stable to bind to — see [`build_principal`].
    pub id: u64,
    /// Optional display name.
    pub name: Option<String>,
}

/// Parse the access token out of a token-endpoint response body, accepting BOTH the JSON shape
/// (`{"access_token": "..."}`) and the `application/x-www-form-urlencoded` shape
/// (`access_token=...&scope=...&token_type=bearer`) GitHub returns without an `Accept: application/json`
/// header. The token is captured into the chip's [`Cred`] as it is read; the enclosing response is
/// wiped when its step consumes it, before the next hop. Returns `None` when absent, which covers
/// GitHub's fail-CLOSED case where the token endpoint answers `HTTP 200` with an `{"error": "..."}`
/// body (a bad/expired code), so a missing token is never a success with an empty token. A JSON
/// array (the `/user/orgs` shape) is never a token response, so its text can never reach the form
/// branch.
///
/// A `token_type` other than `bearer` (ASCII case-insensitive) is a token this plugin does not
/// understand and so never presents (RFC 6749 §7.1): `None`. An absent `token_type` keeps GitHub's
/// bearer meaning.
pub fn parse_access_token(body: &str) -> Option<Cred> {
    /// Only `access_token` (captured as the parser meets it) and `token_type` are read.
    #[derive(Deserialize)]
    struct TokenReply {
        access_token: Option<Cred>,
        token_type: Option<String>,
    }
    let trimmed = body.trim();
    if trimmed.starts_with('[') {
        return None;
    }
    if trimmed.starts_with('{') {
        let reply = json_reply::<TokenReply>(trimmed.as_bytes()).ok()?;
        if reply
            .token_type
            .is_some_and(|t| !t.eq_ignore_ascii_case("bearer"))
        {
            return None;
        }
        return reply.access_token.filter(|t| !t.is_empty());
    }
    let mut token = None;
    for pair in trimmed.split('&') {
        match pair.split_once('=') {
            Some(("access_token", val)) if token.is_none() => {
                let val = form_decode(val);
                if !val.is_empty() {
                    token = Some(Cred::captured(val));
                }
            }
            Some(("token_type", val)) if !form_decode(val).eq_ignore_ascii_case(b"bearer") => {
                return None;
            }
            _ => {}
        }
    }
    token
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

/// The most bytes a GitHub login (a user's or an org's) may hold here; GitHub's own limit is 39 (an
/// Enterprise Managed User's login adds a `_<shortcode>` suffix to it).
pub const MAX_LOGIN_BYTES: usize = 64;
/// The most characters of a profile `name` kept; a longer one is cut.
pub const MAX_NAME_CHARS: usize = 256;

/// Whether `login` is one a GitHub reply can carry: non-empty, at most [`MAX_LOGIN_BYTES`], and
/// only GitHub's login characters: ASCII letters, digits, `-` and `_` (the `_` of an Enterprise
/// Managed User's `<handle>_<shortcode>`). Hyphen placement is not judged: accounts that predate
/// GitHub's single-hyphen rule still sign in. Anything else (a control, a format or bidi
/// character, a separator, `/`, `:`, `@`, non-ASCII) is no login GitHub issues, so the reply
/// carrying it is foreign (the caller's outage), never an identity or a group.
fn plain_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= MAX_LOGIN_BYTES
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Parse a GitHub `/user` response body into a [`GhUser`]. Fail-CLOSED: a missing, empty or
/// foreign `login` (any character but GitHub's, over [`MAX_LOGIN_BYTES`]), a missing numeric `id`,
/// or non-JSON yields `None` (the caller's outage). A `name` holding a control, a Unicode format
/// character (`General_Category=Cf`, so also the invisible ZWNJ/ZWJ joiners: the name is display
/// text an admin compares by eye) or a line/paragraph separator is not taken (the login is shown
/// instead); a longer one than [`MAX_NAME_CHARS`] is cut.
pub fn parse_user(body: &str) -> Option<GhUser> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let login = v
        .get("login")
        .and_then(Value::as_str)
        .filter(|s| plain_login(s))?
        .to_string();

    let id = v.get("id").and_then(Value::as_u64).filter(|id| *id != 0)?;
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

/// The bytes an identity adds around its domain at most: `github-v2:` and `:user:` (16) plus a
/// `u64` id's 20 digits. A domain whose identity could not be measured in a `u32` is refused.
const MAX_IDENTITY_FRAME: usize = "github-v2:".len() + ":user:".len() + 20;

/// The provider namespace used by immutable account and organization identities.
/// API base includes the GHES deployment path; client IDs and mutable names are not domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDomain(String);

impl IdentityDomain {
    /// Parse a configured API base into its canonical, path-safe identity namespace.
    /// Credentials, query strings, fragments and control bytes are not identity domains.
    pub fn from_api_base(base: &str) -> Option<Self> {
        use base64::Engine;
        if base.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return None;
        }
        let url = url::Url::parse(base).ok()?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let canonical = url.as_str().trim_end_matches('/');
        let length =
            base64::encoded_len(canonical.len(), false)?.checked_add(MAX_IDENTITY_FRAME)?;
        u32::try_from(length).ok()?;
        Some(Self(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical),
        ))
    }

    /// The immutable account subject, also emitted as its explicit user grant identity.
    pub fn user(&self, id: u64) -> String {
        format!("github-v2:{}:user:{id}", self.0)
    }

    /// The immutable organization grant identity.
    pub fn org(&self, id: u64) -> String {
        format!("github-v2:{}:org:{id}", self.0)
    }
}

/// Parse one bounded organization page into immutable positive numeric IDs.
/// The login is checked as profile metadata but never emitted as an authorization role.
/// Any malformed entry refuses the whole page; a valid empty page has no org grants.
pub fn parse_org_groups(body: &str) -> Option<Vec<u64>> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let orgs = v.as_array().filter(|orgs| orgs.len() <= ORGS_PER_PAGE)?;
    let mut groups = Vec::with_capacity(orgs.len());
    for org in orgs {
        org.get("login")
            .and_then(Value::as_str)
            .filter(|s| plain_login(s))?;
        groups.push(
            org.get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id != 0)?,
        );
    }
    Some(groups)
}

/// Assemble immutable, provider-qualified identity and grant IDs. User and organization
/// logins are display metadata only: no historical handle/slug identity fallback is emitted.
/// Existing persistent state requires the host's cold principal transition and explicit
/// organization-binding reconciliation before this format is activated.
pub fn build_principal(domain: &IdentityDomain, user: &GhUser, org_ids: Vec<u64>) -> Principal {
    let mut p = Principal::from_id(domain.user(user.id));
    p.name = Some(user.name.clone().unwrap_or_else(|| user.login.clone()));
    p.roles = Vec::with_capacity(org_ids.len() + 1);
    p.roles.push(p.id.clone());
    p.roles.extend(org_ids.into_iter().map(|id| domain.org(id)));
    p
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod diagnostics;
