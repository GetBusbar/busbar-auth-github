// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GitHub-login logic tests: the pure helpers (URLs, hop descriptions, body parsers), hermetic. The
//! step machine and its hops are driven over a scripted exchange in `login_tests.rs`.

use super::*;
use busbar_contract::abi::sdk::test_support::chip;

/// Whether `token` holds exactly `want` (the chip's constant-time equality; it has no getter).
fn holds(token: Option<Cred>, want: &str) -> bool {
    token.is_some_and(|t| t == chip::cred(want))
}

/// The principal the production decoders ([`parse_user`], [`parse_org_groups`]) and
/// [`build_principal`] assemble from a `/user` body and an optional org page; `None` when a decoder
/// refuses its body. What the step machine answers for each is driven in `login_tests.rs`.
fn principal(user_body: &str, orgs_body: Option<&str>) -> Option<Principal> {
    let user = parse_user(user_body)?;
    let groups = match orgs_body {
        Some(body) => parse_org_groups(body)?,
        None => Vec::new(),
    };
    Some(build_principal(&user, groups))
}

fn cfg() -> GitHubConfig {
    GitHubConfig {
        client_id: "Iv1.client".to_string(),
        scopes: default_scopes(),
        api_base: default_api_base(),
        authorize_base: default_authorize_base(),
        token_base: default_token_base(),
        fetch_orgs: true,
        ca_cert_pem: None,
    }
}

// ── authorize URL ───────────────────────────────────────────────────────────────────────────────

#[test]
fn build_github_authorize_url_has_state_scope_no_secret() {
    let url = build_github_authorize_url(
        &cfg(),
        "https://busbar.example/auth/token",
        "state-xyz",
        "challenge-abc",
        &[],
    );
    assert!(
        url.starts_with("https://github.com/login/oauth/authorize?"),
        "{url}"
    );
    assert!(url.contains("client_id=Iv1.client"), "{url}");
    assert!(url.contains("state=state-xyz"), "{url}");
    assert!(url.contains("code_challenge=challenge-abc"), "{url}");
    assert!(url.contains("code_challenge_method=S256"), "{url}");
    // scope: default read:org + read:user, space-encoded (%20).
    assert!(url.contains("scope=read%3Aorg%20read%3Auser"), "{url}");
    // redirect_uri present and percent-encoded.
    assert!(
        url.contains("redirect_uri=https%3A%2F%2Fbusbar.example%2Fauth%2Ftoken"),
        "{url}"
    );
    // Structurally NO client secret on the begin path.
    assert!(
        !url.contains("client_secret") && !url.contains("secret"),
        "{url}"
    );
}

// ── hop descriptions (the pure halves of the legacy module's step tests) ─────────────────────────

/// The token-exchange hop: POST to the token endpoint, the `client_secret` an EMPTY placeholder
/// keyed by `secret_form_field` (the renderer fills it from the held secret).
#[test]
fn the_token_exchange_hop_names_the_secret_field_and_leaves_it_empty() {
    let hop = build_token_exchange(
        &cfg(),
        "authcode",
        "https://busbar.example/auth/token",
        "verifier",
    );
    assert_eq!(hop.method, "POST");
    assert_eq!(hop.url, "https://github.com/login/oauth/access_token");
    assert_eq!(hop.secret_form_field.as_deref(), Some("client_secret"));
    let form: std::collections::HashMap<_, _> = hop.form.iter().cloned().collect();
    assert_eq!(
        form.get("client_id").map(String::as_str),
        Some("Iv1.client")
    );
    assert_eq!(form.get("code").map(String::as_str), Some("authcode"));
    assert_eq!(
        form.get("redirect_uri").map(String::as_str),
        Some("https://busbar.example/auth/token")
    );
    assert_eq!(
        form.get("code_verifier").map(String::as_str),
        Some("verifier")
    );
    assert_eq!(form.get("client_secret").map(String::as_str), Some(""));
}

/// The `/user` hop carries the public User-Agent + Accept headers, no form, no secret field: the
/// bearer is the chip's, sealed in when the hop is rendered (`login_tests`).
#[test]
fn the_userinfo_hop_carries_the_public_headers_and_no_bearer() {
    let hop = build_userinfo_get(&cfg());
    assert_eq!(hop.method, "GET");
    assert_eq!(hop.url, "https://api.github.com/user");
    assert_eq!(hop.secret_form_field, None);
    assert!(hop.form.is_empty());
    assert!(!hop
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
    assert!(hop
        .headers
        .iter()
        .any(|(k, v)| k == "User-Agent" && v == "busbar"));
    assert_eq!(hop.headers, userinfo_headers());
}

/// Both token-response shapes parse; GitHub's 200-with-`error` body and an empty token do not.
#[test]
fn parse_access_token_reads_both_shapes_and_refuses_an_empty_or_missing_token() {
    assert!(holds(
        parse_access_token("access_token=gho_form&x=1"),
        "gho_form"
    ));
    assert!(holds(
        parse_access_token(r#"{"access_token":"gho_json"}"#),
        "gho_json"
    ));
    assert!(parse_access_token(r#"{"error":"bad_verification_code"}"#).is_none());
    assert!(parse_access_token(r#"{"access_token":""}"#).is_none());
    assert!(parse_access_token("access_token=&scope=read:org").is_none());
    assert_eq!(parse_user(r#"{"id":42,"name":"No Login"}"#), None);
}

// ── identity (after /user, after /user/orgs) ───────────────────────────────────────────────────────

#[test]
fn complete_login_after_userinfo_identifies() {
    // The decoders: good /user JSON → github:<login>; + orgs JSON → github:org groups.
    let user = r#"{"login":"octocat","id":583231,"name":"The Octocat"}"#;
    let orgs = r#"[{"login":"github"},{"login":"octo-org"}]"#;

    let p = principal(user, Some(orgs)).expect("identifies");
    assert_eq!(p.id, "github:octocat");
    assert_eq!(p.name.as_deref(), Some("The Octocat"));
    // `github:id/<numeric>` leads: the stable, non-transferable identifier, emitted alongside the
    // login-based id so operators have something to bind to that a released handle cannot inherit.
    assert_eq!(
        p.roles,
        vec![
            "github:id/583231".to_string(),
            "github:org/github".to_string(),
            "github:org/octo-org".to_string()
        ]
    );
}

// ── fail-closed ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn reject_on_malformed_user_json() {
    assert_eq!(parse_user("{ not json"), None);
    assert_eq!(principal("{ not json", None), None);
}

// ── GHES base URL overrides ────────────────────────────────────────────────────────────────────────

#[test]
fn ghes_base_urls_config() {
    let c = GitHubConfig {
        client_id: "ent-client".to_string(),
        scopes: default_scopes(),
        api_base: "https://ghe.corp.example/api/v3".to_string(),
        authorize_base: "https://ghe.corp.example".to_string(),
        token_base: "https://ghe.corp.example".to_string(),
        fetch_orgs: true,
        // A set `ca_cert_pem` is refused at open (door_tests.rs); the URLs do not depend on it.
        ca_cert_pem: None,
    };
    // authorize URL → GHES host
    let url = build_github_authorize_url(&c, "https://busbar/auth/token", "s", "ch", &[]);
    assert!(
        url.starts_with("https://ghe.corp.example/login/oauth/authorize?"),
        "{url}"
    );
    // token endpoint → GHES host
    let hop = build_token_exchange(&c, "code", "https://busbar/auth/token", "v");
    assert_eq!(hop.url, "https://ghe.corp.example/login/oauth/access_token");
    // REST endpoints → GHES /api/v3 (the bearer is sealed in at render, `login_tests`).
    let user_hop = build_userinfo_get(&c);
    assert_eq!(user_hop.url, "https://ghe.corp.example/api/v3/user");
    assert_eq!(user_hop.headers, userinfo_headers());
    let orgs_hop = build_orgs_get(&c);
    assert_eq!(
        orgs_hop.url,
        "https://ghe.corp.example/api/v3/user/orgs?per_page=100"
    );
    assert_eq!(orgs_hop.headers, userinfo_headers());
}

// ── parsing helpers ──────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_org_groups_maps_and_skips_bad_entries() {
    let groups = parse_org_groups(r#"[{"login":"a"},{"id":1},{"login":""},{"login":"b"}]"#);
    assert_eq!(
        groups,
        Some(vec!["github:org/a".to_string(), "github:org/b".to_string()])
    );
    // A legitimately-empty array → Some(empty): login succeeds with zero org groups.
    assert_eq!(parse_org_groups("[]"), Some(Vec::new()));
    // Fail-closed: a non-array body or malformed JSON is NOT a silent empty — it is None so the
    // caller Rejects (a truncated orgs response must not drop the user's org groups).
    assert!(parse_org_groups(r#"{"message":"Not Found"}"#).is_none());
    assert!(parse_org_groups("[{bad").is_none());
    assert!(parse_org_groups("not json at all").is_none());
}

// ── malformed /user/orgs fails closed; a valid empty array is fine ──────────────────────────────────

#[test]
fn identity_malformed_orgs_rejects_but_empty_array_identifies() {
    let user = r#"{"login":"octocat","id":1}"#;
    // Malformed (starts with '[' but truncated) → refused, not a silent zero-group login.
    assert_eq!(principal(user, Some("[{bad")), None);
    // A valid empty array → identified with no org roles.
    let p = principal(user, Some("[]")).expect("identifies");
    assert_eq!(p.id, "github:octocat");
    assert_eq!(p.roles, vec!["github:id/1".to_string()]);
    // A valid array → groups parsed.
    let p = principal(user, Some(r#"[{"login":"acme"}]"#)).expect("identifies");
    assert_eq!(
        p.roles,
        vec!["github:id/1".to_string(), "github:org/acme".to_string()]
    );
}

/// The `/user` body must carry a numeric `id`. That shape check is the only thing standing between
/// this module and a foreign JSON object that happens to have a `login` field, and only the
/// opposite direction (an `id` with no `login`) was tested.
#[test]
fn a_user_body_without_a_numeric_id_is_refused() {
    assert!(
        parse_user(r#"{"login":"alice"}"#).is_none(),
        "a /user body with no id must not parse into an identity"
    );
    assert!(
        parse_user(r#"{"login":"alice","id":"not-a-number"}"#).is_none(),
        "a non-numeric id must not parse into an identity"
    );
    assert!(
        parse_user(r#"{"login":"alice","id":42}"#).is_some(),
        "the well-formed shape must still parse"
    );
}

// ── the /user/orgs hop is paginated (per_page=100) ──────────────────────────────────────────────────

#[test]
fn orgs_hop_url_requests_per_page_100() {
    let hop = build_orgs_get(&cfg());
    assert!(
        hop.url.contains("per_page=100"),
        "orgs hop must raise the page cap: {}",
        hop.url
    );
}

/// A released GitHub handle must not silently inherit the previous owner's bindings.
///
/// GitHub RELEASES a login when an account is renamed or deleted, and anyone may then register it.
/// The principal id is `github:<login>`, so a departed employee's handle taken by an outsider yields
/// the IDENTICAL principal id and inherits their role bindings, per-user group, pools and budgets.
/// Changing the id would break every existing operator binding at once, so the stable numeric account
/// id is emitted alongside as `github:id/<id>`: purely additive, and an operator who binds to it gets
/// an identifier that cannot be transferred with a handle.
#[test]
fn the_stable_numeric_id_distinguishes_two_accounts_sharing_one_handle() {
    let original = r#"{"login":"alice","id":1001,"name":"Alice"}"#;
    let impostor = r#"{"login":"alice","id":90210,"name":"Not Alice"}"#;

    let a = principal(original, None).expect("identifies");
    let b = principal(impostor, None).expect("identifies");

    // The login-based identity CANNOT tell them apart -- this is the hazard, stated as a test.
    assert_eq!(a.id, b.id, "the handle is the same, so the id is the same");

    // The numeric role can, and it is present on both so a binding to it is decidable.
    assert!(
        a.roles.contains(&"github:id/1001".to_string()),
        "{:?}",
        a.roles
    );
    assert!(
        b.roles.contains(&"github:id/90210".to_string()),
        "{:?}",
        b.roles
    );
    assert!(
        !b.roles.contains(&"github:id/1001".to_string()),
        "the impostor must not carry the original's stable id: {:?}",
        b.roles
    );
}

// ── a fed-back /user/orgs array is never a token response ───────────────────────────────────────────

#[test]
fn an_orgs_array_with_an_embedded_access_token_pair_is_not_a_token_response() {
    let poisoned = r#"[{"login":"acme","description":"x&access_token=gho_ATTACKER&y"}]"#;
    assert!(parse_access_token(poisoned).is_none());
    // Truncated/malformed array: still never a token.
    let truncated = r#"[{"login":"acme","description":"x&access_token=gho_ATTACKER&"#;
    assert!(parse_access_token(truncated).is_none());
}

/// Form-encoded token values are percent- and plus-decoded.
#[test]
fn parse_access_token_form_decodes_percent_and_plus() {
    assert!(holds(
        parse_access_token("access_token=gho%5Fab+c&scope=x"),
        "gho_ab c"
    ));
    assert!(holds(
        parse_access_token("scope=x&access_token=a%2Bb%3D"),
        "a+b="
    ));
}

#[test]
fn next_link_reads_the_next_relation_only() {
    let link = r#"<https://api.github.com/user/orgs?page=2>; rel="next", <https://api.github.com/user/orgs?page=5>; rel="last""#;
    assert_eq!(
        next_link(link),
        Some("https://api.github.com/user/orgs?page=2")
    );
    let last_first =
        r#"<https://a.example/p?page=1>; rel="prev", <https://a.example/p?page=3>; REL=next"#;
    assert_eq!(next_link(last_first), Some("https://a.example/p?page=3"));
    assert_eq!(
        next_link(r#"<https://a.example/x>; rel="next last""#),
        Some("https://a.example/x")
    );
    for none in [
        "",
        r#"<https://a.example/p?page=1>; rel="prev""#,
        r#"<https://a.example/p?page=1>; rel="nextish""#,
        "garbage",
        "<unterminated; rel=\"next\"",
    ] {
        assert_eq!(next_link(none), None, "{none}");
    }
}
