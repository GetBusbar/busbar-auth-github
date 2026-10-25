// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GitHub-login logic tests. Hermetic — no network: the CORE executes hops in production, so these
//! drive the pure helpers and the `LoginModule` step machine directly with fixture response bodies.

use super::*;
use busbar_contract::auth::{BeginLogin, CompleteLogin, LoginHttpResponse, LoginOutcome};

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

fn resp(status: u16, body: &str) -> LoginHttpResponse {
    LoginHttpResponse {
        status,
        body: body.to_string(),
    }
}

fn expect_exchange(outcome: LoginOutcome) -> LoginHop {
    match outcome {
        LoginOutcome::Exchange(hop) => hop,
        other => panic!("expected Exchange, got {other:?}"),
    }
}

fn expect_identify(outcome: LoginOutcome) -> Principal {
    match outcome {
        LoginOutcome::Identify(p) => p,
        other => panic!("expected Identify, got {other:?}"),
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

#[test]
fn begin_login_folds_in_request_time_extra_scopes_deduped() {
    let module = GithubModule::new(cfg());
    let begin = BeginLogin {
        redirect_uri: "https://busbar.example/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: None,
        scopes: vec!["read:user".to_string(), "repo".to_string()],
    };
    let url = match module.begin_login(&begin) {
        LoginOutcome::Authorize(u) => u,
        other => panic!("expected Authorize, got {other:?}"),
    };
    // read:user is not duplicated; repo is appended.
    assert!(
        url.contains("scope=read%3Aorg%20read%3Auser%20repo"),
        "{url}"
    );
}

// ── token-exchange hop ────────────────────────────────────────────────────────────────────────────

#[test]
fn complete_login_first_returns_token_exchange_hop() {
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code: Some("authcode".to_string()),
        redirect_uri: Some("https://busbar.example/auth/token".to_string()),
        code_verifier: Some("verifier".to_string()),
        ..Default::default()
    };
    let hop = expect_exchange(module.complete_login(&req));
    assert_eq!(hop.method, "POST");
    assert_eq!(hop.url, "https://github.com/login/oauth/access_token");
    // The CORE injects the secret into this exact field; the module never writes the value.
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
    // client_secret is present as an EMPTY placeholder — the value is the CORE's to fill.
    assert_eq!(form.get("client_secret").map(String::as_str), Some(""));
}

#[test]
fn complete_login_first_without_full_triple_rejects() {
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code: Some("authcode".to_string()),
        // missing redirect_uri + code_verifier
        ..Default::default()
    };
    assert_eq!(module.complete_login(&req), LoginOutcome::Reject);
}

// ── /user GET hop (after token) ────────────────────────────────────────────────────────────────────

#[test]
fn complete_login_after_token_returns_userinfo_get_hop() {
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code_verifier: Some("verifier".to_string()),
        token_response: Some(resp(
            200,
            r#"{"access_token":"gho_opaque","token_type":"bearer","scope":"read:org,read:user"}"#,
        )),
        ..Default::default()
    };
    let hop = expect_exchange(module.complete_login(&req));
    assert_eq!(hop.method, "GET");
    assert_eq!(hop.url, "https://api.github.com/user");
    // A userinfo hop carries no secret.
    assert_eq!(hop.secret_form_field, None);
    assert!(hop.form.is_empty());

    // The `/user` hop itself must carry the Authorization: Bearer + User-Agent headers (ABI v2
    // `headers` field), not just what `userinfo_headers` computes in isolation.
    assert!(hop
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v == "Bearer gho_opaque"));
    assert!(hop
        .headers
        .iter()
        .any(|(k, v)| k == "User-Agent" && v == "busbar"));
    assert_eq!(hop.headers, userinfo_headers("gho_opaque"));
}

#[test]
fn token_response_form_encoded_also_yields_userinfo_hop() {
    // GitHub returns x-www-form-urlencoded without an Accept: application/json header — handle it.
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code_verifier: Some("v".to_string()),
        token_response: Some(resp(
            200,
            "access_token=gho_form&scope=read%3Aorg&token_type=bearer",
        )),
        ..Default::default()
    };
    let hop = expect_exchange(module.complete_login(&req));
    assert_eq!(hop.url, "https://api.github.com/user");
    assert_eq!(
        parse_access_token("access_token=gho_form&x=1").as_deref(),
        Some("gho_form")
    );
}

// ── identity (after /user, after /user/orgs) ───────────────────────────────────────────────────────

#[test]
fn complete_login_after_userinfo_identifies() {
    // Direct-helper form: good /user JSON → Identify github:<login>; + orgs JSON → github:org groups.
    let user = r#"{"login":"octocat","id":583231,"name":"The Octocat"}"#;
    let orgs = r#"[{"login":"github"},{"login":"octo-org"}]"#;

    let p = expect_identify(identity_from_user_and_orgs(user, Some(orgs)));
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

#[test]
fn full_hop_chain_through_the_module_identifies_with_org_groups() {
    // Drive the whole chain through complete_login the way the CORE would, feeding each hop's response
    // back. The correlator (code_verifier) threads the opaque token + /user identity across hops.
    let module = GithubModule::new(cfg());
    let cv = Some("the-verifier".to_string());

    // 1) code → token exchange POST
    let r1 = module.complete_login(&CompleteLogin {
        code: Some("c".into()),
        redirect_uri: Some("https://busbar.example/auth/token".into()),
        code_verifier: cv.clone(),
        ..Default::default()
    });
    assert!(matches!(r1, LoginOutcome::Exchange(h) if h.method == "POST"));

    // 2) token response → /user GET
    let r2 = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    assert!(matches!(r2, LoginOutcome::Exchange(ref h) if h.url.ends_with("/user")));

    // 3) /user response → /user/orgs GET, bearer-authenticated with the SAME token stashed at step 2.
    let r3 = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"login":"octocat","id":1}"#)),
        ..Default::default()
    });
    match &r3 {
        LoginOutcome::Exchange(h) => {
            assert!(h.url.contains("/user/orgs"));
            assert!(h
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer gho_x"));
        }
        other => panic!("expected Exchange, got {other:?}"),
    }

    // 4) /user/orgs response → Identify with org groups
    let r4 = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"[{"login":"acme"}]"#)),
        ..Default::default()
    });
    let p = expect_identify(r4);
    assert_eq!(p.id, "github:octocat");
    assert_eq!(
        p.roles,
        vec!["github:id/1".to_string(), "github:org/acme".to_string()]
    );
}

#[test]
fn fetch_orgs_false_identifies_after_user_without_org_hop() {
    let mut c = cfg();
    c.fetch_orgs = false;
    let module = GithubModule::new(c);
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"login":"solo","id":9}"#)),
        ..Default::default()
    });
    let p = expect_identify(out);
    assert_eq!(p.id, "github:solo");
    // No orgs were fetched, but the stable id role is still emitted -- it comes from /user, not
    // /user/orgs, so it does not depend on `fetch_orgs`.
    assert_eq!(p.roles, vec!["github:id/9".to_string()]);
}

// ── fail-closed ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn reject_on_non_2xx() {
    let module = GithubModule::new(cfg());
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(401, r#"{"access_token":"should-be-ignored"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
}

#[test]
fn reject_on_missing_access_token() {
    // GitHub answers HTTP 200 with an {"error":...} body on a bad code — no access_token, and the
    // body is an object without `login`, so it fails closed at the userinfo-parse branch.
    let module = GithubModule::new(cfg());
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"error":"bad_verification_code"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(
        parse_access_token(r#"{"error":"bad_verification_code"}"#),
        None
    );
}

#[test]
fn reject_on_missing_login() {
    // A /user response lacking `login` (or malformed) is a hard failure.
    let module = GithubModule::new(cfg());
    // Prime the token step so the next response is treated as /user.
    module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"id":42,"name":"No Login"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(parse_user(r#"{"id":42}"#), None);
}

#[test]
fn reject_on_malformed_user_json() {
    assert_eq!(parse_user("{ not json"), None);
    assert_eq!(
        identity_from_user_and_orgs("{ not json", None),
        LoginOutcome::Reject
    );
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
        ca_cert_pem: Some("-----BEGIN CERTIFICATE-----\n...".to_string()),
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
    // REST endpoints → GHES /api/v3, both bearer-authenticated with the access token.
    let user_hop = build_userinfo_get(&c, "gho_ent");
    assert_eq!(user_hop.url, "https://ghe.corp.example/api/v3/user");
    assert!(user_hop
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v == "Bearer gho_ent"));
    let orgs_hop = build_orgs_get(&c, "gho_ent");
    assert_eq!(
        orgs_hop.url,
        "https://ghe.corp.example/api/v3/user/orgs?per_page=100"
    );
    assert!(orgs_hop
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v == "Bearer gho_ent"));
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
    // Malformed (starts with '[' but truncated) → Reject, not a silent zero-group login.
    assert_eq!(
        identity_from_user_and_orgs(user, Some("[{bad")),
        LoginOutcome::Reject
    );
    // A valid empty array → Identify with no roles.
    let p = expect_identify(identity_from_user_and_orgs(user, Some("[]")));
    assert_eq!(p.id, "github:octocat");
    assert_eq!(p.roles, vec!["github:id/1".to_string()]);
    // A valid array → groups parsed.
    let p = expect_identify(identity_from_user_and_orgs(
        user,
        Some(r#"[{"login":"acme"}]"#),
    ));
    assert_eq!(
        p.roles,
        vec!["github:id/1".to_string(), "github:org/acme".to_string()]
    );
}

#[test]
fn full_chain_malformed_orgs_rejects() {
    let module = GithubModule::new(cfg());
    let cv = Some("cv".to_string());
    module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"login":"octocat","id":1}"#)),
        ..Default::default()
    });
    // Truncated /user/orgs array → fail closed.
    let out = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, "[{bad")),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
}

// ── an uncorrelatable feedback call fails closed (no shared "" slot) ────────────────────────────────

#[test]
fn feedback_without_any_correlator_rejects() {
    assert_eq!(correlation_key(&CompleteLogin::default()), None);
    let module = GithubModule::new(cfg());
    // A token response fed back with NO code_verifier/code/redirect_uri cannot be threaded → Reject,
    // and must not stash anything under a shared "" slot.
    let out = module.complete_login(&CompleteLogin {
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(module.pending.lock().unwrap().len(), 0);
}

// ── the pending map never leaks — empty after both failed and completed flows ───────────────────────

/// The pending map must be BOUNDED. Every removal path in this module runs only when the core calls
/// back into it, and the core abandons a hop chain without re-entering the module whenever a hop
/// itself fails to execute. So an anonymous caller who starts flows and lets the second hop fail
/// grew the map without limit, each entry retaining a live GitHub access token for the process
/// lifetime. There was no cap, no TTL and no eviction, and no test that inserted N entries and
/// asserted anything about N.
#[test]
fn the_pending_map_refuses_to_grow_without_bound() {
    let module = GithubModule::new(cfg());
    // Drive PENDING_MAX successful token steps, each with its own correlator and none of them ever
    // completed: exactly the abandoned-flow shape.
    for i in 0..PENDING_MAX {
        let out = module.complete_login(&CompleteLogin {
            code_verifier: Some(format!("cv-{i}")),
            token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
            ..Default::default()
        });
        assert!(
            matches!(out, LoginOutcome::Exchange(_)),
            "flow {i} should have stashed and emitted the /user hop"
        );
    }
    // One more must be refused rather than admitted, since nothing is sweepable yet.
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("cv-overflow".to_string()),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    assert!(
        matches!(out, LoginOutcome::Reject),
        "past the ceiling a new flow must be refused, not admitted: the map holds live bearers"
    );
}

/// An EMPTY access token must not be stashed and must not produce a `Bearer ` header with nothing
/// after it. The filters that reject it had no test: the existing missing-token test feeds a body
/// with no `access_token` key at all, which is a different branch.
#[test]
fn an_empty_access_token_is_refused() {
    let module = GithubModule::new(cfg());
    for body in [
        r#"{"access_token":""}"#,
        "access_token=&scope=read:org&token_type=bearer",
    ] {
        let out = module.complete_login(&CompleteLogin {
            code_verifier: Some("cv-empty".to_string()),
            token_response: Some(resp(200, body)),
            ..Default::default()
        });
        assert!(
            matches!(out, LoginOutcome::Reject),
            "an empty access_token must be refused, not stashed: body {body}"
        );
    }
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

#[test]
fn pending_map_empty_after_failed_and_completed_flows() {
    let module = GithubModule::new(cfg());

    // Failed flow: stash at token step, then a malformed /user body fails closed.
    let cv1 = Some("cv-fail".to_string());
    module.complete_login(&CompleteLogin {
        code_verifier: cv1.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_fail"}"#)),
        ..Default::default()
    });
    assert_eq!(
        module.pending.lock().unwrap().len(),
        1,
        "stashed after token"
    );
    let out = module.complete_login(&CompleteLogin {
        code_verifier: cv1.clone(),
        token_response: Some(resp(200, "{ not a user")),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(
        module.pending.lock().unwrap().len(),
        0,
        "removed on fail-closed Reject"
    );

    // Completed flow: full chain to Identify leaves the map empty.
    let cv2 = Some("cv-ok".to_string());
    module.complete_login(&CompleteLogin {
        code_verifier: cv2.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_ok"}"#)),
        ..Default::default()
    });
    module.complete_login(&CompleteLogin {
        code_verifier: cv2.clone(),
        token_response: Some(resp(200, r#"{"login":"octocat","id":1}"#)),
        ..Default::default()
    });
    let out = module.complete_login(&CompleteLogin {
        code_verifier: cv2.clone(),
        token_response: Some(resp(200, r#"[{"login":"acme"}]"#)),
        ..Default::default()
    });
    assert!(matches!(out, LoginOutcome::Identify(_)));
    assert_eq!(
        module.pending.lock().unwrap().len(),
        0,
        "removed on final Identify"
    );
}

// ── the /user/orgs hop is paginated (per_page=100) ──────────────────────────────────────────────────

#[test]
fn orgs_hop_url_requests_per_page_100() {
    let hop = build_orgs_get(&cfg(), "gho_x");
    assert!(
        hop.url.contains("per_page=100"),
        "orgs hop must raise the page cap: {}",
        hop.url
    );
}

// ── redirect_uri is a deployment-wide constant, NOT a per-flow correlator ───────────────────────────

#[test]
fn feedback_with_only_redirect_uri_rejects_no_shared_slot() {
    // redirect_uri is a deployment-wide CONSTANT, so it is not per-flow-unique. Two concurrent flows
    // carrying only redirect_uri (no code_verifier/code) must NOT collapse onto one shared pending
    // slot and overwrite each other's stashed token/identity — they fail closed instead.
    let ru = Some("https://busbar.example/auth/token".to_string());
    // The correlator must not fall back to redirect_uri.
    assert_eq!(
        correlation_key(&CompleteLogin {
            redirect_uri: ru.clone(),
            ..Default::default()
        }),
        None
    );
    let module = GithubModule::new(cfg());
    let a = module.complete_login(&CompleteLogin {
        redirect_uri: ru.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_a"}"#)),
        ..Default::default()
    });
    let b = module.complete_login(&CompleteLogin {
        redirect_uri: ru.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_b"}"#)),
        ..Default::default()
    });
    assert_eq!(a, LoginOutcome::Reject);
    assert_eq!(b, LoginOutcome::Reject);
    assert_eq!(module.pending.lock().unwrap().len(), 0);
}

// ── an orgs array with no prior /user stash (missing stashed user) fails closed ─────────────────────

#[test]
fn orgs_array_as_first_feedback_without_stashed_user_rejects() {
    let module = GithubModule::new(cfg());
    // An orgs array arriving for a fresh key with no prior /user stash → missing stashed user →
    // Reject, and the pending map is left empty.
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("cv".into()),
        token_response: Some(resp(200, r#"[{"login":"acme"}]"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(module.pending.lock().unwrap().len(), 0);
}

// ── a non-2xx AFTER a stash removes the stashed entry (observable remove) ───────────────────────────

#[test]
fn non_2xx_after_stash_removes_pending_entry() {
    let module = GithubModule::new(cfg());
    let cv = Some("cv".to_string());
    // Stash at the token step.
    module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    assert_eq!(
        module.pending.lock().unwrap().len(),
        1,
        "stashed after token"
    );
    // Non-2xx on the NEXT hop (/user) → Reject AND the stashed entry is removed (not a no-op).
    let out = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(500, r#"{"message":"server error"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(
        module.pending.lock().unwrap().len(),
        0,
        "removed on non-2xx after stash"
    );
}

// ── a /user body with no prior token stash fails closed (no fabricated empty token) ─────────────────

#[test]
fn userinfo_as_first_feedback_without_stashed_token_rejects() {
    let module = GithubModule::new(cfg());
    // A /user object arriving for a fresh key with no prior token stash must fail closed, NOT
    // fabricate an empty-token PendingLogin and emit a /user/orgs hop with an empty Bearer.
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("cv".into()),
        token_response: Some(resp(200, r#"{"login":"octocat","id":1}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(module.pending.lock().unwrap().len(), 0);
}

#[test]
fn authenticate_passes_opaque_bearer() {
    let module = GithubModule::new(cfg());
    assert_eq!(module.authenticate(Some("gho_whatever")), AuthVerdict::Pass);
    assert_eq!(module.authenticate(None), AuthVerdict::Pass);
    assert_eq!(module.name(), "github");
    assert!(!module.cacheable());
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

    let a = expect_identify(identity_from_user_and_orgs(original, None));
    let b = expect_identify(identity_from_user_and_orgs(impostor, None));

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

/// The TTL sweep had no test: an entry older than `PENDING_TTL_SECS` must be dropped by the next
/// token step, while a fresh one survives.
#[test]
fn the_ttl_sweep_drops_stale_pending_entries_on_the_next_token_step() {
    let module = GithubModule::new(cfg());
    let stale = Instant::now()
        .checked_sub(std::time::Duration::from_secs(PENDING_TTL_SECS + 1))
        .expect("monotonic clock has run long enough");
    {
        let mut pending = module.pending.lock().unwrap();
        for k in ["stale-flow", "fresh-flow"] {
            pending.insert(
                k.to_string(),
                PendingLogin {
                    access_token: Held::new("gho_old".to_string()),
                    user: None,
                    inserted_at: if k == "stale-flow" {
                        stale
                    } else {
                        Instant::now()
                    },
                },
            );
        }
    }
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("cv-new".to_string()),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    assert!(matches!(out, LoginOutcome::Exchange(_)));
    let pending = module.pending.lock().unwrap();
    assert!(
        !pending.contains_key("stale-flow"),
        "stale entry must be swept"
    );
    assert!(
        pending.contains_key("fresh-flow"),
        "fresh entry must survive"
    );
    assert!(pending.contains_key("cv-new"));
}

/// Form-encoded token values are percent- and plus-decoded.
#[test]
fn parse_access_token_form_decodes_percent_and_plus() {
    assert_eq!(
        parse_access_token("access_token=gho%5Fab+c&scope=x").as_deref(),
        Some("gho_ab c")
    );
    assert_eq!(
        parse_access_token("scope=x&access_token=a%2Bb%3D").as_deref(),
        Some("a+b=")
    );
}
