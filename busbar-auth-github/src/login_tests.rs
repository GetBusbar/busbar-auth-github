// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-owned login, driven over a scripted exchange. Hermetic: no network. Each arm states
//! the 1.5.5 answer it keeps (the core hop loop in busbar v1.5.5 `auth/token.rs` over the v1.0.3
//! step machine).

use super::*;
use std::collections::HashMap;

const SECRET: &str = "s3cr3t-client-value";
const TOKEN: &str = "gho_live_bearer";
const NONCE: &str = "kernel-minted-nonce";

/// The operator writes every base out (as a 1.5.5 GitHub method had to, for its hops to pass).
const SETTINGS: &str = r#"{
    "client_id": "Iv1.client",
    "api_base": "https://api.github.com",
    "authorize_base": "https://github.com",
    "token_base": "https://github.com"
}"#;

const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const ORGS_URL: &str = "https://api.github.com/user/orgs?per_page=100";

/// A scripted one-shot exchange: per target, the answer; optionally PENDING once per request first
/// (the re-issue gets the stored answer). Records every issue.
#[derive(Default)]
struct Script {
    answers: HashMap<String, Fetched>,
    pend_first: bool,
    pended: Vec<HopRequest>,
    issued: Vec<HopRequest>,
}

impl Script {
    fn new() -> Self {
        Self::default()
    }
    fn answer(mut self, target: &str, status: u16, body: &str) -> Self {
        self.answers.insert(
            target.to_string(),
            Fetched::Ready(HopResponse {
                status,
                body: body.as_bytes().to_vec().into(),
            }),
        );
        self
    }
    fn unreachable(mut self, target: &str) -> Self {
        self.answers
            .insert(target.to_string(), Fetched::Unreachable);
        self
    }
    fn happy() -> Self {
        Self::new()
            .answer(
                TOKEN_URL,
                200,
                &format!(r#"{{"access_token":"{TOKEN}","token_type":"bearer"}}"#),
            )
            .answer(USER_URL, 200, r#"{"login":"octocat","id":1,"name":"Octo"}"#)
            .answer(ORGS_URL, 200, r#"[{"login":"acme"},{"login":"widgets"}]"#)
    }
    fn targets(&self) -> Vec<&str> {
        self.issued.iter().map(|r| r.target.as_str()).collect()
    }
}

/// A request's header fields as plain pairs, for comparison.
fn plain(fields: &[(String, zeroize::Zeroizing<String>)]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|(n, v)| (n.clone(), v.as_str().to_string()))
        .collect()
}

impl Exchange for Script {
    fn exchange(&mut self, request: &HopRequest) -> Fetched {
        self.issued.push(request.clone());
        if self.pend_first && !self.pended.contains(request) {
            self.pended.push(request.clone());
            return Fetched::Pending;
        }
        self.answers
            .get(&request.target)
            .cloned()
            .unwrap_or(Fetched::Unreachable)
    }
}

fn login() -> GithubLogin {
    GithubLogin::open(SETTINGS, Some(SECRET)).expect("opens")
}

fn flow(l: &GithubLogin) -> LoginFlow {
    l.start(
        Some("the-code"),
        Some("https://node.example/auth/token"),
        Some("the-verifier"),
        Some(NONCE),
    )
}

fn run(l: &GithubLogin, script: &mut Script) -> LoginStep {
    let mut f = flow(l);
    l.drive(&mut f, script)
}

fn identity(step: LoginStep) -> Principal {
    match step {
        LoginStep::Identity(p) => p,
        other => panic!("expected an identity, got {other:?}"),
    }
}

#[test]
fn a_member_signs_in_with_org_groups() {
    let l = login();
    let mut s = Script::happy();
    let p = identity(run(&l, &mut s));
    assert_eq!(p.id, "github:octocat");
    assert_eq!(p.name.as_deref(), Some("Octo"));
    assert_eq!(
        p.roles,
        vec![
            "github:id/1".to_string(),
            "github:org/acme".to_string(),
            "github:org/widgets".to_string()
        ]
    );
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL]);
}

/// The token exchange as 1.5.5's core sent it: the form in the module's order with the secret
/// injected into its slot, serde_urlencoded bytes, `content-type` then the default `accept`.
#[test]
fn the_token_exchange_carries_the_plugins_own_secret_in_1_5_5_bytes() {
    let l = login();
    let mut s = Script::happy();
    run(&l, &mut s);
    let token = &s.issued[0];
    assert_eq!(token.method, "POST");
    assert_eq!(token.target, TOKEN_URL);
    assert_eq!(token.timeout_ms, 10_000);
    assert_eq!(
        String::from_utf8(token.body.to_vec()).unwrap(),
        "client_id=Iv1.client&code=the-code\
         &redirect_uri=https%3A%2F%2Fnode.example%2Fauth%2Ftoken\
         &code_verifier=the-verifier&client_secret=s3cr3t-client-value"
    );
    assert_eq!(
        plain(&token.fields),
        vec![
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            ),
            ("accept".to_string(), "*/*".to_string()),
        ]
    );
}

/// The authenticated GETs: an empty form (so `content-type` and an empty body, as reqwest's
/// `.form(&[])` sent), then the module's headers, lowercase, in order.
#[test]
fn the_rest_gets_carry_the_bearer_and_user_agent() {
    let l = login();
    let mut s = Script::happy();
    run(&l, &mut s);
    for get in &s.issued[1..] {
        assert_eq!(get.method, "GET");
        assert!(get.body.is_empty());
        assert_eq!(
            plain(&get.fields),
            vec![
                (
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string()
                ),
                ("authorization".to_string(), format!("Bearer {TOKEN}")),
                ("user-agent".to_string(), "busbar".to_string()),
                (
                    "accept".to_string(),
                    "application/vnd.github+json".to_string()
                ),
            ]
        );
    }
}

/// RED ARM (non-member): a user outside the org signs in, as in 1.5.5, WITHOUT that org's group, so
/// an `auth.role_bindings.github: "github:org/acme"` binding never admits them. Membership is the
/// org list GitHub answers; the plugin invents none.
#[test]
fn red_a_non_member_carries_no_group_for_the_org() {
    let l = login();
    let mut s = Script::happy().answer(ORGS_URL, 200, r#"[{"login":"elsewhere"}]"#);
    let p = identity(run(&l, &mut s));
    assert!(
        !p.roles.contains(&"github:org/acme".to_string()),
        "{:?}",
        p.roles
    );
    assert_eq!(
        p.roles,
        vec![
            "github:id/1".to_string(),
            "github:org/elsewhere".to_string()
        ]
    );

    // A member of nothing: identified, zero groups (a VALID empty list).
    let mut s = Script::happy().answer(ORGS_URL, 200, "[]");
    assert_eq!(
        identity(run(&l, &mut s)).roles,
        vec!["github:id/1".to_string()]
    );
}

/// RED (ruling 2026-10-27): an identity provider that answers 5xx or 429 on any hop is an outage
/// (the host answers 503, retryable), never a declined credential, and the flow goes no further.
#[test]
fn an_idp_5xx_or_429_is_an_outage_not_a_decline() {
    let l = login();
    for status in [500, 502, 503, 429] {
        let mut s = Script::happy().answer(TOKEN_URL, status, r#"{"error":"busy"}"#);
        assert_eq!(run(&l, &mut s), LoginStep::Outage, "token {status}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
        let mut s = Script::happy().answer(USER_URL, status, "{}");
        assert_eq!(run(&l, &mut s), LoginStep::Outage, "user {status}");
        assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
    }
}

/// RED ARM (revoked token): GitHub answers `/user` 401 for a revoked or expired bearer. 1.5.5 fed
/// the 401 back and the module declined ("Sign-in was declined"): a bad credential, never an
/// outage, and the org hop is never made with a dead token.
#[test]
fn red_a_revoked_token_is_declined_and_goes_no_further() {
    let l = login();
    let mut s = Script::happy().answer(
        USER_URL,
        401,
        r#"{"message":"Bad credentials","status":"401"}"#,
    );
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);

    // Revoked between /user and /user/orgs: declined as well.
    let mut s = Script::happy().answer(ORGS_URL, 401, r#"{"message":"Bad credentials"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
}

#[test]
fn a_bad_code_answered_200_with_an_error_body_is_declined() {
    // GitHub answers a bad/expired code with HTTP 200 and `{"error": ...}`: no token, declined.
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 200, r#"{"error":"bad_verification_code"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
}

#[test]
fn a_form_encoded_token_response_is_accepted() {
    let l = login();
    let mut s = Script::happy().answer(
        TOKEN_URL,
        200,
        &format!("access_token={TOKEN}&scope=read%3Aorg&token_type=bearer"),
    );
    assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
}

#[test]
fn an_unreachable_idp_is_an_outage() {
    let l = login();
    let mut s = Script::happy().unreachable(USER_URL);
    assert_eq!(run(&l, &mut s), LoginStep::Outage);
}

#[test]
fn a_malformed_org_list_is_declined_not_a_zero_group_login() {
    let l = login();
    let mut s = Script::happy().answer(ORGS_URL, 200, "[{truncated");
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
}

#[test]
fn fetch_orgs_false_identifies_after_user_with_two_hops() {
    let settings = SETTINGS.replace("\"client_id\"", "\"fetch_orgs\": false, \"client_id\"");
    let l = GithubLogin::open(&settings, Some(SECRET)).unwrap();
    let mut s = Script::happy();
    let p = identity(run(&l, &mut s));
    assert_eq!(p.roles, vec!["github:id/1".to_string()]);
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
}

#[test]
fn a_callback_missing_the_verifier_is_declined_with_no_exchange() {
    let l = login();
    let mut s = Script::happy();
    let mut f = l.start(
        Some("c"),
        Some("https://node.example/cb"),
        None,
        Some(NONCE),
    );
    assert_eq!(l.drive(&mut f, &mut s), LoginStep::BadCredential);
    assert!(s.issued.is_empty());
}

/// Slow I/O pends: each hop answers PENDING once, the flow parks on it, and the next drive re-issues
/// the SAME request (a one-shot exchange serves its stored result) and carries on.
#[test]
fn a_pending_exchange_parks_and_resumes_on_the_same_request() {
    let l = login();
    let mut s = Script::happy();
    s.pend_first = true;
    let mut f = flow(&l);
    let mut pendings = 0;
    let step = loop {
        match l.drive(&mut f, &mut s) {
            LoginStep::Pending => pendings += 1,
            done => break done,
        }
        assert!(pendings <= 3, "one pend per hop");
    };
    assert_eq!(pendings, 3);
    assert_eq!(identity(step).id, "github:octocat");
    // Every hop was issued twice, identically: once pending, once answered.
    assert_eq!(s.issued.len(), 6);
    for pair in s.issued.chunks(2) {
        assert_eq!(pair[0], pair[1]);
    }
}

/// The answer is kept: a re-call (the host's short-buffer re-issue) is served from it and never
/// redeems the code again.
#[test]
fn a_finished_flow_answers_again_without_new_exchanges() {
    let l = login();
    let mut s = Script::happy();
    let mut f = flow(&l);
    let first = l.drive(&mut f, &mut s);
    let issued = s.issued.len();
    assert_eq!(l.drive(&mut f, &mut s), first);
    assert_eq!(s.issued.len(), issued);
}

/// 1.5.5's allowlist is the hosts the OPERATOR wrote: with the bases left at their defaults, 1.5.5
/// refused the first hop before sending anything ("Couldn't reach your provider"). OWNER RULING
/// (sibling/auth): such settings can never log in, so they are now refused at open, explained,
/// instead of loading and failing every login; nothing is ever sent.
#[test]
fn defaulted_bases_are_refused_at_open_explained() {
    assert_eq!(
        GithubLogin::open(r#"{"client_id":"Iv1.client"}"#, Some(SECRET)).unwrap_err(),
        "settings: `token_base` must be written out: the hop allowlist is built only from URLs in the settings"
    );
}

#[test]
fn a_plaintext_public_token_base_is_refused_before_the_secret_leaves() {
    let settings = SETTINGS.replace(
        "\"token_base\": \"https://github.com\"",
        "\"token_base\": \"http://github.com\"",
    );
    let l = GithubLogin::open(&settings, Some(SECRET)).unwrap();
    let mut s = Script::happy();
    assert_eq!(run(&l, &mut s), LoginStep::Outage);
    assert!(s.issued.is_empty());
}

#[test]
fn a_bearer_with_a_line_break_fails_the_hop_closed() {
    // A token that would split the request: 1.5.5's header sanitiser failed the hop (an outage).
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 200, r#"{"access_token":"gho_x\r\nX-Evil: 1"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::Outage);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
}

/// An unsigned JWT-shaped token whose payload is `claims` (base64url, no padding).
fn id_token(claims: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let b = claims.as_bytes();
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &x| (a << 8) | x as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    format!("eyJhbGciOiJub25lIn0.{out}.sig")
}

/// 1.5.5's core nonce binding, now the plugin's (WIRE-AUTH: `CompleteLoginIn.nonce`): an id_token
/// whose nonce is not the one minted at begin is refused before any identity is trusted.
#[test]
fn an_id_token_with_a_foreign_nonce_is_refused() {
    let l = login();
    for body in [
        format!(
            r#"{{"access_token":"gho_x","id_token":"{}"}}"#,
            id_token(r#"{"nonce":"someone-else"}"#)
        ),
        format!(
            r#"{{"access_token":"gho_x","id_token":"{}"}}"#,
            id_token(r#"{"sub":"no-nonce"}"#)
        ),
        r#"{"access_token":"gho_x","id_token":"a.!!!.c"}"#.to_string(),
        r#"{"access_token":"gho_x","id_token":"no-dots"}"#.to_string(),
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(run(&l, &mut s), LoginStep::SecurityCheckFailed, "{body}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
    // No nonce minted: any id_token is refused (1.5.5 always minted one).
    let body = format!(
        r#"{{"access_token":"gho_x","id_token":"{}"}}"#,
        id_token(&format!(r#"{{"nonce":"{NONCE}"}}"#))
    );
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    let mut f = l.start(Some("c"), Some("https://node.example/cb"), Some("v"), None);
    assert_eq!(l.drive(&mut f, &mut s), LoginStep::SecurityCheckFailed);
}

#[test]
fn an_id_token_bound_to_the_minted_nonce_passes_the_check() {
    let l = login();
    for claims in [
        format!(r#"{{"nonce":"{NONCE}"}}"#),
        format!(r#"{{"nonce":"{NONCE}","sub":"x1"}}"#),
        format!(r#"{{"nonce":"{NONCE}","s":"xy"}}"#),
    ] {
        let body = format!(
            r#"{{"access_token":"{TOKEN}","id_token":"{}"}}"#,
            id_token(&claims)
        );
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(identity(run(&l, &mut s)).id, "github:octocat", "{claims}");
    }
}

#[test]
fn b64url_decode_is_strict_url_safe_no_pad() {
    assert_eq!(b64url_decode("").as_deref(), Some(&b""[..]));
    assert_eq!(b64url_decode("Zg").as_deref(), Some(&b"f"[..]));
    assert_eq!(b64url_decode("Zm8").as_deref(), Some(&b"fo"[..]));
    assert_eq!(b64url_decode("Zm9v").as_deref(), Some(&b"foo"[..]));
    assert_eq!(b64url_decode("-_8").as_deref(), Some(&[0xfb, 0xff][..]));
    for bad in ["Zg==", "Z", "Zh", "Zm9", "+/8", "Zm9v!"] {
        assert_eq!(b64url_decode(bad), None, "{bad}");
    }
}

/// The hop loop is bounded as 1.5.5's was: a far end that keeps answering token-shaped bodies never
/// identifies, and the flow ends after six turns.
#[test]
fn the_hop_loop_is_bounded() {
    let l = login();
    let tok = r#"{"access_token":"gho_again"}"#;
    let mut s = Script::happy().answer(USER_URL, 200, tok);
    assert_eq!(run(&l, &mut s), LoginStep::Outage);
    assert_eq!(s.issued.len(), MAX_HOPS);
}

/// The answers the 1.5.5 module, driven by the 1.5.5 core, reached for these bodies (pinned while
/// the legacy `GithubModule` lived beside the flow, and checked against it): the flow reaches the
/// same answer over the same hops.
#[test]
fn the_flow_answers_as_the_1_5_5_module_driven_by_the_1_5_5_core() {
    let id = |roles: &[&str]| {
        let mut p = Principal::from_id("github:octocat");
        p.name = Some("Octo".to_string());
        p.roles = roles.iter().map(|r| r.to_string()).collect();
        LoginStep::Identity(p)
    };
    let cases: Vec<(Script, LoginStep, Vec<&str>)> = vec![
        (
            Script::happy(),
            id(&["github:id/1", "github:org/acme", "github:org/widgets"]),
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
        (
            Script::happy().answer(ORGS_URL, 200, r#"[{"login":"elsewhere"}]"#),
            id(&["github:id/1", "github:org/elsewhere"]),
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
        (
            Script::happy().answer(USER_URL, 401, "{}"),
            LoginStep::BadCredential,
            vec![TOKEN_URL, USER_URL],
        ),
        (
            Script::happy().answer(TOKEN_URL, 200, r#"{"error":"bad_verification_code"}"#),
            LoginStep::BadCredential,
            vec![TOKEN_URL],
        ),
        (
            Script::happy().answer(ORGS_URL, 200, "[{bad"),
            LoginStep::BadCredential,
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
        (
            Script::happy().answer(USER_URL, 200, r#"{"login":"no-id"}"#),
            LoginStep::BadCredential,
            vec![TOKEN_URL, USER_URL],
        ),
    ];
    for (mut script, legacy, urls) in cases {
        assert_eq!(run(&login(), &mut script), legacy);
        assert_eq!(script.targets(), urls);
    }
}

// ── the legacy module's step tests, on the live flow ────────────────────────────────────────────

/// Request-time scopes are folded in, de-duplicated (was the legacy `begin_login` test).
#[test]
fn begin_login_folds_in_request_time_extra_scopes_deduped() {
    let url = login().begin_login(
        "https://busbar.example/auth/token",
        "st",
        "ch",
        &["read:user".to_string(), "repo".to_string()],
    );
    assert!(
        url.contains("scope=read%3Aorg%20read%3Auser%20repo"),
        "{url}"
    );
}

/// A callback without the full code + redirect_uri + verifier triple, or with no correlator at
/// all, is declined before anything is sent.
#[test]
fn a_callback_without_the_full_triple_is_declined_with_no_exchange() {
    let l = login();
    for (code, redirect_uri, verifier) in [
        (Some("authcode"), None, None),
        (None, Some("https://busbar.example/auth/token"), None),
        (None, None, None),
    ] {
        let mut s = Script::happy();
        let mut f = l.start(code, redirect_uri, verifier, Some(NONCE));
        assert_eq!(l.drive(&mut f, &mut s), LoginStep::BadCredential);
        assert!(s.issued.is_empty());
    }
}

/// The token endpoint's non-2xx is declined even when its body carries a token.
#[test]
fn a_non_2xx_token_answer_is_declined_even_with_a_token_in_it() {
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 401, r#"{"access_token":"should-be-ignored"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
}

/// An empty access token (either shape) is declined: never a `Bearer ` with nothing after it.
#[test]
fn an_empty_access_token_is_refused() {
    let l = login();
    for body in [
        r#"{"access_token":""}"#,
        "access_token=&scope=read:org&token_type=bearer",
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, body);
        assert_eq!(run(&l, &mut s), LoginStep::BadCredential, "{body}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
}

/// A `/user` without a `login` is declined.
#[test]
fn a_user_without_a_login_is_declined() {
    let l = login();
    let mut s = Script::happy().answer(USER_URL, 200, r#"{"id":42,"name":"No Login"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
}

/// Out-of-order bodies fail closed: an org list or a `/user` where the token response belongs
/// (no user held, no token held) never identifies and never sends an empty bearer.
#[test]
fn out_of_order_bodies_fail_closed() {
    let l = login();
    for body in [r#"[{"login":"acme"}]"#, r#"{"login":"octocat","id":1}"#] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, body);
        assert_eq!(run(&l, &mut s), LoginStep::BadCredential, "{body}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
}

/// The `/user/orgs` hop is authenticated with the SAME token the token step answered.
#[test]
fn the_orgs_hop_carries_the_token_from_the_token_step() {
    let l = login();
    let mut s = Script::happy();
    run(&l, &mut s);
    assert_eq!(s.issued[2].target, ORGS_URL);
    assert!(plain(&s.issued[2].fields)
        .iter()
        .any(|(k, v)| k == "authorization" && *v == format!("Bearer {TOKEN}")));
}

/// Each flow owns its state (the legacy module's shared pending map, its correlation key, cap and
/// TTL sweep have no live counterpart): two flows never see each other's bearer, and a finished
/// flow, declined or identified, holds no token and no token response.
#[test]
fn each_flow_owns_its_state_and_a_finished_one_holds_nothing() {
    let l = login();
    let token = |t: &str| format!(r#"{{"access_token":"{t}"}}"#);
    let mut a = Script::happy().answer(TOKEN_URL, 200, &token("gho_a"));
    let mut b = Script::happy().answer(TOKEN_URL, 200, &token("gho_b"));
    a.pend_first = true;
    b.pend_first = true;
    let (mut fa, mut fb) = (flow(&l), flow(&l));
    // Interleaved: each parks on its token exchange, then on /user.
    for _ in 0..2 {
        assert_eq!(l.drive(&mut fa, &mut a), LoginStep::Pending);
        assert_eq!(l.drive(&mut fb, &mut b), LoginStep::Pending);
    }
    let bearer = |s: &Script, t: &str| {
        s.issued
            .iter()
            .any(|r| r.fields.iter().any(|(_, v)| v.contains(t)))
    };
    assert!(bearer(&a, "gho_a") && !bearer(&a, "gho_b"));
    assert!(bearer(&b, "gho_b") && !bearer(&b, "gho_a"));

    for mut s in [Script::happy(), Script::happy().answer(USER_URL, 500, "{}")] {
        let mut f = flow(&l);
        l.drive(&mut f, &mut s);
        assert!(f.done.is_some());
        assert!(f.state.access_token.is_none() && f.state.user.is_none());
        assert!(
            f.req.token_response.is_none(),
            "the token response is cleared"
        );
    }
}

#[test]
fn open_keeps_the_1_5_5_refusal_texts() {
    let err = |s: &str, secret: Option<&str>| GithubLogin::open(s, secret).unwrap_err();
    assert_eq!(
        err("  ", Some(SECRET)),
        "github plugin requires config (client_id); none provided"
    );
    assert!(err("{ not json", Some(SECRET)).starts_with("invalid github plugin config: "));
    assert!(err(r#"{"client_id":"x","bogus":1}"#, Some(SECRET))
        .starts_with("invalid github plugin config: unknown field `bogus`"));
    // The secret is never a settings key: it comes from browser_login.client_secret.
    assert!(
        err(r#"{"client_id":"x","client_secret":"leak"}"#, Some(SECRET))
            .starts_with("invalid github plugin config: unknown field `client_secret`")
    );
}

/// The exact v1.5.5 GitHub provider (busbar-auth-github v1.0.3 `tests/e2e.rs:301-306`):
///
/// ```yaml
/// identity-providers:
///   github:
///     module: github
///     settings: { token_base: <ghe>, api_base: <ghe>, authorize_base: <ghe> }
///     browser_login: { client_id: "Iv1.e2eclient", client_secret: { env: BUSBAR_GH_CLIENT_SECRET } }
/// ```
///
/// reaches the plugin as 1.5.5's core composed it: the settings, plus `browser_login.client_id`
/// merged in (v1.5.5 `auth/token.rs:218-229`), the secret NOT among them (the kernel resolves it
/// and the loader moves it into `OpenIn.secrets`). It loads, and the secret it logs in with is the
/// one handed in beside the settings.
#[test]
fn the_v1_5_5_example_provider_loads_and_logs_in_with_the_secret_beside_the_settings() {
    let delivered = r#"{
        "token_base": "https://ghe.example",
        "api_base": "https://ghe.example",
        "authorize_base": "https://ghe.example",
        "client_id": "Iv1.e2eclient"
    }"#;
    let l = GithubLogin::open(delivered, Some(SECRET)).expect("the 1.5.5 provider loads");
    let mut s = Script::new()
        .answer(
            "https://ghe.example/login/oauth/access_token",
            200,
            &format!(r#"{{"access_token":"{TOKEN}"}}"#),
        )
        .answer(
            "https://ghe.example/user",
            200,
            r#"{"login":"octocat","id":1}"#,
        )
        .answer(
            "https://ghe.example/user/orgs?per_page=100",
            200,
            r#"[{"login":"testorg"}]"#,
        );
    let p = identity(run(&l, &mut s));
    // The principal, byte for byte (owner Q109 signed: the stable numeric id role leads).
    let mut expected = Principal::from_id("github:octocat");
    expected.name = Some("octocat".to_string());
    expected.roles = vec!["github:id/1".to_string(), "github:org/testorg".to_string()];
    assert_eq!(p, expected);
    let body = String::from_utf8(s.issued[0].body.to_vec()).unwrap();
    assert!(body.starts_with("client_id=Iv1.e2eclient&"), "{body}");
    assert!(
        body.ends_with(&format!("&client_secret={SECRET}")),
        "{body}"
    );

    // RED: a secret left in the settings (not moved into OpenIn.secrets) is refused, as 1.5.5's
    // plugin refused a `client_secret` key in its config; the plugin never takes one from there.
    let leaked = delivered.replace("\"client_id\"", "\"client_secret\": \"s\", \"client_id\"");
    assert!(GithubLogin::open(&leaked, Some(SECRET))
        .unwrap_err()
        .starts_with("invalid github plugin config: unknown field `client_secret`"));
}

/// A headless-only provider (no `browser_login`, so no secret) loaded in 1.5.5 and still does; a
/// hop then carries no `client_secret` field at all (1.5.5 dropped the placeholder), and an empty
/// secret (the loader's answer for a missing one) is the same as none.
#[test]
fn no_secret_loads_and_drops_the_secret_field_as_1_5_5_did() {
    for secret in [None, Some("")] {
        let l = GithubLogin::open(SETTINGS, secret).expect("loads without a secret");
        let mut s = Script::happy();
        assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
        let body = String::from_utf8(s.issued[0].body.to_vec()).unwrap();
        assert!(!body.contains("client_secret"), "{body}");
        assert!(body.ends_with("&code_verifier=the-verifier"), "{body}");
    }
}

#[test]
fn nothing_formats_a_secret_the_code_or_the_bearer() {
    let l = login();
    let mut s = Script::happy();
    s.pend_first = true;
    let mut f = flow(&l);
    l.drive(&mut f, &mut s); // pending on the token exchange
    l.drive(&mut f, &mut s); // pending on /user, the bearer held
    let text = format!("{l:?} {f:?} {:?}", s.issued);
    for secret in [SECRET, TOKEN, "the-code", "the-verifier"] {
        assert!(!text.contains(secret), "{secret} leaked into {text}");
    }
}

#[test]
fn begin_login_is_the_1_5_5_authorize_url() {
    let l = login();
    let url = l.begin_login(
        "https://node.example/auth/token",
        "st",
        "ch",
        &["user:email".to_string()],
    );
    assert_eq!(
        url,
        build_github_authorize_url(
            l.config(),
            "https://node.example/auth/token",
            "st",
            "ch",
            &["user:email".to_string()]
        )
    );
    assert!(!url.contains(SECRET));
}

#[test]
fn form_encode_is_serde_urlencoded() {
    let pairs = [("a b", "x*y-z._~!"), ("k", "é/=&")];
    assert_eq!(
        form_encode(&pairs).as_str(),
        "a+b=x*y-z._%7E%21&k=%C3%A9%2F%3D%26"
    );
    assert_eq!(form_encode(&[]).as_str(), "");
    // Sized exactly up front: no growth leaves a partial copy behind.
    let encoded = form_encode(&pairs);
    assert_eq!(encoded.capacity(), encoded.len());
}

/// A GitHub Enterprise base delivered as a plain URL logs in. HISTORY: v1.5.5 built the hop
/// allowlist from the RAW settings (auth/token.rs:283), so `api_base: {env: GHE_API}` contributed no
/// host and every hop was refused (502); OWNER Q123 (2026-09-30) then had the kernel resolve such a
/// reference in place. Q123 is OVERTURNED (OWNER RULING, CHIP-REVIEW-v4 change 2): this plugin's
/// Statement declares only `client_secret`, so the kernel REFUSES a reference at `api_base`,
/// `token_base` or `authorize_base` at boot and at `--validate`, and the operator writes each base
/// as its URL. The plugin side is unchanged: what it is delivered is the plain URLs below.
#[test]
fn decision_a_reference_written_base_resolved_by_the_kernel_logs_in() {
    // As the kernel delivers `settings: { api_base: "https://ghe.corp.example/api/v3", token_base:
    // "https://ghe.corp.example", authorize_base: "https://ghe.corp.example", client_id:
    // "Iv1.client" }`, each base written as its URL.
    let delivered = r#"{
        "client_id": "Iv1.client",
        "api_base": "https://ghe.corp.example/api/v3",
        "token_base": "https://ghe.corp.example",
        "authorize_base": "https://ghe.corp.example"
    }"#;
    let l = GithubLogin::open(delivered, Some(SECRET)).unwrap();
    let mut s = Script::new()
        .answer(
            "https://ghe.corp.example/login/oauth/access_token",
            200,
            &format!(r#"{{"access_token":"{TOKEN}"}}"#),
        )
        .answer(
            "https://ghe.corp.example/api/v3/user",
            200,
            r#"{"login":"octocat","id":1}"#,
        )
        .answer(
            "https://ghe.corp.example/api/v3/user/orgs?per_page=100",
            200,
            "[]",
        );
    assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
}

#[test]
fn a_poisoned_orgs_array_cannot_swap_the_token_mid_flow() {
    let l = login();
    let mut s = Script::happy().answer(
        ORGS_URL,
        200,
        r#"[{"login":"acme","description":"x&access_token=gho_ATTACKER&y"}]"#,
    );
    let p = identity(run(&l, &mut s));
    assert_eq!(p.id, "github:octocat");
    assert!(p.roles.contains(&"github:org/acme".to_string()));
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL]);
    assert!(s
        .issued
        .iter()
        .all(|r| !r.fields.iter().any(|(_, v)| v.contains("gho_ATTACKER"))));
}

mod logging {
    use super::*;
    use busbar_contract::testkit::WarnCapture;

    /// Settings that omit `token_base`: its default host is not operator-written, so not allowed.
    const NO_TOKEN_BASE: &str =
        r#"{"client_id": "Iv1.client", "api_base": "https://api.github.com"}"#;

    /// OWNER RULING (sibling/auth): settings that leave `token_base` at its default are refused at
    /// open, explained, instead of loading and having the guard refuse every hop. The guard's own
    /// log for a hop it refuses is kept below.
    #[test]
    fn a_hop_the_guard_refuses_is_explained_without_a_secret() {
        let err = GithubLogin::open(NO_TOKEN_BASE, Some(SECRET)).unwrap_err();
        assert!(
            err.contains("token_base") && err.contains("allowlist"),
            "{err}"
        );
        assert!(!err.contains(SECRET), "{err}");

        let l = login();
        let cap = WarnCapture::default();
        let hop = LoginHop {
            method: "GET".to_string(),
            url: "https://elsewhere.example/user".to_string(),
            form: Vec::new(),
            secret_form_field: None,
            headers: Vec::new(),
        };
        let refused = tracing::subscriber::with_default(cap.clone(), || l.render(&hop));
        assert_eq!(refused, Err(Refused));
        assert!(cap.contains("elsewhere.example"), "{:?}", cap.messages());
        assert!(cap.contains("allow"), "{:?}", cap.messages());
        assert!(cap.contains("module=github"), "{:?}", cap.messages());
        for secret in [SECRET, "the-code", "the-verifier"] {
            assert!(!cap.contains(secret), "{:?}", cap.messages());
        }
    }

    #[test]
    fn a_declined_code_logs_the_idp_error_and_no_secret() {
        let l = login();
        let mut s = Script::new().answer(TOKEN_URL, 200, r#"{"error":"bad_verification_code"}"#);
        let cap = WarnCapture::capturing_debug();
        let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
        assert_eq!(step, LoginStep::BadCredential);
        assert!(
            cap.contains("bad_verification_code"),
            "{:?}",
            cap.messages()
        );
        for secret in [SECRET, "the-code", "the-verifier"] {
            assert!(!cap.contains(secret), "{:?}", cap.messages());
        }
    }

    #[test]
    fn a_misconfigured_client_is_a_warn() {
        let l = login();
        let mut s = Script::new().answer(TOKEN_URL, 200, "error=incorrect_client_credentials");
        let cap = WarnCapture::default();
        let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
        assert_eq!(step, LoginStep::BadCredential);
        assert!(
            cap.contains("incorrect_client_credentials"),
            "{:?}",
            cap.messages()
        );
    }
}

/// RED: a hop answer's body is the token response (the access token): Debug shows its status and
/// length, never its bytes.
#[test]
fn a_hop_response_debug_shows_no_body() {
    let r = HopResponse {
        status: 200,
        body: b"access_token=SECRETX".to_vec().into(),
    };
    let text = format!("{r:?} {:?}", Fetched::Ready(r.clone()));
    assert!(!text.contains("SECRETX"), "{text}");
    // Nor as the bytes' numbers (`S` `E` `C` is 83, 69, 67).
    assert!(!text.contains("83, 69, 67"), "{text}");
    assert_eq!(
        format!("{r:?}"),
        "HopResponse { status: 200, body_len: 20 }"
    );
}

/// RED: a hop reply past 1 MiB is not parsed: the login ends as an outage, nothing more is sent.
#[test]
fn a_hop_reply_over_the_cap_is_an_outage() {
    let l = login();
    let mut body = format!(r#"{{"access_token":"{TOKEN}"}}"#);
    body.push_str(&" ".repeat(1024 * 1024 + 1 - body.len()));
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    assert_eq!(run(&l, &mut s), LoginStep::Outage);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
    // At the cap exactly it is read.
    body.pop();
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
}

mod module_field {
    use super::*;
    use busbar_contract::testkit::WarnCapture;

    /// RED: every record carries `module = "github"`, as the sibling auth plugins' do.
    #[test]
    fn a_decline_is_logged_with_the_module_field() {
        let l = login();
        let mut s = Script::happy().answer(USER_URL, 401, "{}");
        let cap = WarnCapture::capturing_debug();
        let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
        assert_eq!(step, LoginStep::BadCredential);
        let messages = cap.messages();
        assert!(!messages.is_empty());
        for m in &messages {
            assert!(m.contains("module=github"), "{messages:?}");
        }
    }
}

/// RED (type level): the hop bodies (the token form carries the client secret, the code and the
/// verifier; the token response the access token) are wiped on drop.
#[test]
fn the_hop_bodies_are_wiped_on_drop() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let l = login();
    let mut s = Script::happy();
    run(&l, &mut s);
    let request = &s.issued[0];
    wipes(&request.body);
    for (_, value) in &request.fields {
        wipes(value);
    }
    let response = HopResponse {
        status: 200,
        body: b"access_token=x".to_vec().into(),
    };
    wipes(&response.body);
}
