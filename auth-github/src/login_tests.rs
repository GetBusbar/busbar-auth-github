// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-owned login, driven over a scripted exchange. Hermetic: no network. Each arm states

#[path = "audit_tests.rs"]
mod audit;

#[path = "remaining_audit_tests.rs"]
mod remaining_audit;

#[path = "reported_audit_tests.rs"]
mod reported_audit;

use super::*;
use busbar_contract::abi::sdk::test_support::chip;
use std::collections::HashMap;

const SECRET: &str = "s3cr3t-client-value";
const TOKEN: &str = "gho_live_bearer";
const NONCE: &str = "kernel-minted-nonce";
/// An outage with no retry hint.
const OUTAGE: LoginStep = LoginStep::Outage { retry_after: None };

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
                fields: ReplyFields::default(),
                body: body.as_bytes().to_vec().into(),
            }),
        );
        self
    }
    fn answer_with(mut self, target: &str, status: u16, fields: ReplyFields, body: &str) -> Self {
        self.answers.insert(
            target.to_string(),
            Fetched::Ready(HopResponse {
                status,
                fields,
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
            .answer(
                ORGS_URL,
                200,
                r#"[{"login":"acme","id":1},{"login":"widgets","id":2}]"#,
            )
    }
    fn targets(&self) -> Vec<&str> {
        self.issued.iter().map(|r| r.target.as_str()).collect()
    }
}

/// A request's header fields as the SDK frames them (the chip's sealed bearer included), read
fn plain(r: &HopRequest) -> Vec<(String, String)> {
    let wire = r.wire(MAX_HOP_REPLY_BYTES).expect("the hop frames");
    let head = chip::framed_head(&wire);
    let block_at = r.method.len() + split(&r.target).expect("the target splits").1.len();
    String::from_utf8(head[block_at..].to_vec())
        .expect("a UTF-8 head")
        .split_terminator("\r\n")
        .map(|line| {
            let (n, v) = line.split_once(": ").expect("a field line");
            (n.to_string(), v.to_string())
        })
        .collect()
}

/// A request's body as the SDK encodes it on the wire.
fn body_text(r: &HopRequest) -> String {
    let mut sealed = r.body.encoded().expect("the form encodes");
    let mut out = Vec::new();
    let done = chip::drive_sealed::<()>(&mut sealed, |b| {
        out.extend_from_slice(b);
        std::task::Poll::Ready(Ok(b.len()))
    });
    assert!(done.is_ready());
    String::from_utf8(out).expect("a UTF-8 body")
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
            .unwrap_or_else(|| panic!("unscripted GitHub target: {}", request.target))
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
    assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
    assert_eq!(p.name.as_deref(), Some("Octo"));
    assert_eq!(
        p.roles,
        vec![
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1".to_string(),
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1".to_string(),
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2".to_string()
        ]
    );
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL]);
}

/// The token exchange as 1.5.5's core sent it: the form in the module's order with the secret
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
        body_text(token),
        "client_id=Iv1.client&code=the-code\
         &redirect_uri=https%3A%2F%2Fnode.example%2Fauth%2Ftoken\
         &code_verifier=the-verifier&client_secret=s3cr3t-client-value"
    );
    assert_eq!(
        plain(token),
        vec![
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            ),
            ("accept".to_string(), "application/json".to_string()),
        ]
    );
}

#[test]
fn the_rest_gets_carry_the_bearer_and_user_agent() {
    let l = login();
    let mut s = Script::happy();
    run(&l, &mut s);
    for get in &s.issued[1..] {
        assert_eq!(get.method, "GET");
        assert!(body_text(get).is_empty());
        assert_eq!(
            plain(get),
            vec![
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

#[test]
fn red_a_non_member_carries_no_group_for_the_org() {
    let l = login();
    let mut s = Script::happy().answer(ORGS_URL, 200, r#"[{"login":"elsewhere","id":11}]"#);
    let p = identity(run(&l, &mut s));
    assert!(
        !p.roles
            .contains(&"github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1".to_string()),
        "{:?}",
        p.roles
    );
    assert_eq!(
        p.roles,
        vec![
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1".to_string(),
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:11".to_string()
        ]
    );

    let mut s = Script::happy().answer(ORGS_URL, 200, "[]");
    assert_eq!(
        identity(run(&l, &mut s)).roles,
        vec!["github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1".to_string()]
    );
}

#[test]
fn an_idp_5xx_or_429_is_an_outage_not_a_decline() {
    let l = login();
    for status in [500, 502, 503, 429] {
        let mut s = Script::happy().answer(TOKEN_URL, status, r#"{"error":"busy"}"#);
        assert_eq!(run(&l, &mut s), OUTAGE, "token {status}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
        let mut s = Script::happy().answer(USER_URL, status, "{}");
        assert_eq!(run(&l, &mut s), OUTAGE, "user {status}");
        assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
    }
}

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

    let mut s = Script::happy().answer(ORGS_URL, 401, r#"{"message":"Bad credentials"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
}

#[test]
fn a_bad_code_answered_200_with_an_error_body_is_declined() {
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 200, r#"{"error":"bad_verification_code"}"#);
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
}

#[test]
fn red_g2_a_200_token_error_is_declined_only_for_the_users_own_code() {
    let l = login();
    for code in ["bad_verification_code", "invalid_grant", "expired_token"] {
        for body in [format!(r#"{{"error":"{code}"}}"#), format!("error={code}")] {
            let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
            assert_eq!(run(&l, &mut s), LoginStep::BadCredential, "{body}");
            assert_eq!(s.targets(), vec![TOKEN_URL]);
        }
    }
    for code in [
        "incorrect_client_credentials",
        "redirect_uri_mismatch",
        "application_suspended",
        "unverified_user_email",
        "something_new",
    ] {
        for body in [
            format!(r#"{{"error":"{code}","error_description":"x"}}"#),
            format!("error={code}&error_description=x"),
        ] {
            let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
            assert_eq!(run(&l, &mut s), OUTAGE, "{body}");
            assert_eq!(s.targets(), vec![TOKEN_URL]);
        }
    }
    for body in [
        "",
        "<html>sign in</html>",
        "{not json",
        r#"{"token_type":"bearer"}"#,
        "scope=read%3Aorg",
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{body:?}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
}

#[test]
fn a_form_encoded_token_response_is_accepted() {
    let l = login();
    let mut s = Script::happy().answer(
        TOKEN_URL,
        200,
        &format!("access_token={TOKEN}&scope=read%3Aorg&token_type=bearer"),
    );
    assert_eq!(
        identity(run(&l, &mut s)).id,
        "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
    );
}

#[test]
fn an_unreachable_idp_is_an_outage() {
    let l = login();
    let mut s = Script::happy().unreachable(USER_URL);
    assert_eq!(run(&l, &mut s), OUTAGE);
}

/// A truncated org list is never a zero-group login; it is no sign-in answer either (G3,
#[test]
fn a_malformed_org_list_is_an_outage_not_a_zero_group_login() {
    let l = login();
    let mut s = Script::happy().answer(ORGS_URL, 200, "[{truncated");
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
}

#[test]
fn red_g3_a_malformed_rest_answer_is_an_outage() {
    let l = login();
    for body in [
        "",
        "<html>maintenance</html>",
        "{not json",
        r#"{"id":1}"#,
        r#"{"login":"octocat"}"#,
        r#"{"login":"octocat","id":"1"}"#,
        r#"{"login":"","id":1}"#,
    ] {
        let mut s = Script::happy().answer(USER_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "/user {body:?}");
        assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
    }
    for body in ["", "[{bad", r#"{"message":"x"}"#, "<html></html>"] {
        let mut s = Script::happy().answer(ORGS_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "/user/orgs {body:?}");
        assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL]);
    }
}

/// The URL of org page `n`.
fn orgs_page(n: usize) -> String {
    format!("https://api.github.com/user/orgs?per_page=100&page={n}")
}

/// An org page's reply fields: a `link` to page `next` (and the last), or none.
fn link_to(next: Option<&str>) -> ReplyFields {
    ReplyFields {
        link: next.map(|n| {
            format!(r#"<{n}>; rel="next", <https://api.github.com/user/orgs?per_page=100&page=99>; rel="last""#)
        }),
        ..ReplyFields::default()
    }
}

#[test]
fn red_g4_the_org_list_is_followed_past_page_one() {
    let l = login();
    let mut s = Script::happy()
        .answer_with(
            ORGS_URL,
            200,
            link_to(Some(&orgs_page(2))),
            r#"[{"login":"acme","id":1}]"#,
        )
        .answer_with(
            &orgs_page(2),
            200,
            link_to(Some(&orgs_page(3))),
            r#"[{"login":"widgets","id":2}]"#,
        )
        .answer_with(
            &orgs_page(3),
            200,
            link_to(None),
            r#"[{"login":"gadgets","id":12}]"#,
        );
    let p = identity(run(&l, &mut s));
    assert_eq!(
        p.roles,
        vec![
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1".to_string(),
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1".to_string(),
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2".to_string(),
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:12".to_string(),
        ]
    );
    let (p2, p3) = (orgs_page(2), orgs_page(3));
    assert_eq!(
        s.targets(),
        vec![TOKEN_URL, USER_URL, ORGS_URL, p2.as_str(), p3.as_str()]
    );

    for page in &s.issued[2..] {
        assert!(plain(page)
            .iter()
            .any(|(k, v)| k == "authorization" && *v == format!("Bearer {TOKEN}")));
    }
}

#[test]
fn red_g4_the_org_list_stops_at_ten_pages_with_a_warn() {
    use crate::diagnostics::GithubDiagnostics;
    let l = login();
    let mut s = Script::happy().answer_with(
        ORGS_URL,
        200,
        link_to(Some(&orgs_page(2))),
        r#"[{"login":"o1","id":1}]"#,
    );
    for n in 2..=12 {
        s = s.answer_with(
            &orgs_page(n),
            200,
            link_to(Some(&orgs_page(n + 1))),
            &format!(r#"[{{"login":"o{n}","id":{n}}}]"#),
        );
    }
    let cap = GithubDiagnostics::default();
    let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
    let p = identity(step);
    assert_eq!(p.roles.len(), 1 + 10, "{:?}", p.roles);
    assert_eq!(
        p.roles.last().map(String::as_str),
        Some("github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:10")
    );
    assert_eq!(s.issued.len(), 2 + 10);
    assert!(cap.contains("truncated"), "{:?}", cap.messages());
}

#[test]
fn red_g4_a_next_link_off_the_api_origin_is_never_followed() {
    let l = login();
    for next in [
        "https://evil.example/user/orgs?page=2",
        "http://api.github.com/user/orgs?page=2",
        "https://github.com/user/orgs?page=2",
    ] {
        let mut s = Script::happy()
            .answer_with(
                ORGS_URL,
                200,
                link_to(Some(next)),
                r#"[{"login":"acme","id":1}]"#,
            )
            .answer(next, 200, r#"[{"login":"injected","id":13}]"#);
        assert_eq!(run(&l, &mut s), OUTAGE, "{next}");
        assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL], "{next}");
    }
}

#[test]
fn red_l11_far_end_strings_enter_the_principal_filtered() {
    let l = login();
    let user = |login: &str, name: &str| {
        serde_json::json!({"login": login, "id": 1, "name": name}).to_string()
    };
    for bad in ["octo\ncat", "octo\u{1b}[31m", "octo\u{7f}", &"a".repeat(65)] {
        let mut s = Script::happy().answer(USER_URL, 200, &user(bad, "Octo"));
        assert_eq!(run(&l, &mut s), OUTAGE, "login {bad:?}");
        let orgs =
            serde_json::json!([{"login": "acme", "id": 1}, {"login": bad, "id": 2}]).to_string();
        let mut s = Script::happy().answer(ORGS_URL, 200, &orgs);
        assert_eq!(run(&l, &mut s), OUTAGE, "org {bad:?}");
    }
    let long = "a".repeat(64);
    let mut s = Script::happy()
        .answer(USER_URL, 200, &user(&long, "Octo"))
        .answer(
            ORGS_URL,
            200,
            &serde_json::json!([{"login": long, "id": 2}]).to_string(),
        );
    let p = identity(run(&l, &mut s));
    assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
    assert!(p
        .roles
        .contains(&"github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2".to_string()));

    let mut s = Script::happy().answer(USER_URL, 200, &user("octocat", "Evil\r\nAdmin"));
    assert_eq!(identity(run(&l, &mut s)).name.as_deref(), Some("octocat"));
    let mut s = Script::happy().answer(USER_URL, 200, &user("octocat", &"é".repeat(300)));
    assert_eq!(
        identity(run(&l, &mut s)).name.map(|n| n.chars().count()),
        Some(256)
    );
}

#[test]
fn fetch_orgs_false_identifies_after_user_with_two_hops() {
    let settings = SETTINGS.replace("\"client_id\"", "\"fetch_orgs\": false, \"client_id\"");
    let l = GithubLogin::open(&settings, Some(SECRET)).unwrap();
    let mut s = Script::happy();
    let p = identity(run(&l, &mut s));
    assert_eq!(
        p.roles,
        vec!["github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1".to_string()]
    );
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

#[test]
fn red_l7_an_empty_callback_value_is_declined_before_the_exchange() {
    let l = login();
    for (code, redirect_uri, verifier) in [
        ("", "https://node.example/cb", "v"),
        ("c", "https://node.example/cb", ""),
        ("c", "", "v"),
        ("", "", ""),
    ] {
        let mut s = Script::happy();
        let mut f = l.start(Some(code), Some(redirect_uri), Some(verifier), Some(NONCE));
        assert_eq!(
            l.drive(&mut f, &mut s),
            LoginStep::BadCredential,
            "{code:?} {redirect_uri:?} {verifier:?}"
        );
        assert!(
            s.issued.is_empty(),
            "{code:?} {redirect_uri:?} {verifier:?}"
        );
    }
}

/// Slow I/O pends: each hop answers PENDING once, the flow parks on it, and the next drive re-issues
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
    assert_eq!(
        identity(step).id,
        "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
    );

    assert_eq!(s.issued.len(), 6);
    for pair in s.issued.chunks(2) {
        assert_eq!(pair[0], pair[1]);
    }
}

/// The answer is kept: a re-call (the host's short-buffer re-issue) is served from it and never
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
#[test]
fn defaulted_bases_are_refused_at_open_explained() {
    assert_eq!(
        GithubLogin::open(r#"{"client_id":"Iv1.client"}"#, Some(SECRET)).unwrap_err(),
        "settings.token_base: must be written out: the hop allowlist is built only from URLs in the settings"
    );
}

/// A hop base on plain http to a public host could never sign anyone in (the hop guard refuses
/// every hop to it), so it is refused at `open`, named, before any secret can leave; a loopback or
/// private host may take plain http, and `authorize_base` (a browser redirect) is not judged.
#[test]
fn a_plaintext_public_hop_base_is_refused_at_open_by_name() {
    for (key, from, public) in [
        ("token_base", "https://github.com", "http://github.com"),
        (
            "api_base",
            "https://api.github.com",
            "http://api.github.com",
        ),
        (
            "api_base",
            "https://api.github.com",
            "http://ghe.corp.internal/api/v3",
        ),
        ("token_base", "https://github.com", "HTTP://github.com"),
    ] {
        let settings = SETTINGS.replace(
            &format!("\"{key}\": \"{from}\""),
            &format!("\"{key}\": \"{public}\""),
        );
        let refused = GithubLogin::open(&settings, Some(SECRET)).unwrap_err();
        assert!(
            refused == format!("settings.{key}: plain http to a host that is not loopback or private: use https")
                || refused == format!("settings.{key}: not an http(s) URL with a host"),
            "{public}: {refused}"
        );
        assert!(!refused.contains(SECRET), "{refused}");
    }
    let settings = SETTINGS.replace(
        "\"token_base\": \"https://github.com\"",
        "\"token_base\": \"http://github.com\"",
    );
    assert_eq!(
        GithubLogin::open(&settings, Some(SECRET)).unwrap_err(),
        "settings.token_base: plain http to a host that is not loopback or private: use https"
    );
    for private in [
        "http://127.0.0.1:8080",
        "http://10.0.0.7",
        "http://ghe.localhost",
    ] {
        let settings = format!(
            r#"{{"client_id":"Iv1.client","token_base":"{private}","api_base":"{private}","authorize_base":"http://github.com"}}"#
        );
        assert!(
            GithubLogin::open(&settings, Some(SECRET)).is_ok(),
            "{private}"
        );
    }
}

#[test]
fn the_secret_and_the_bearer_go_out_only_secured_under_https_bases() {
    let l = login();
    let mut s = Script::happy();
    identity(run(&l, &mut s));
    let token = &s.issued[0];
    assert!(
        token
            .body
            .encoded()
            .expect("the form encodes")
            .secure_required(),
        "the client secret is pinned to a secured connection"
    );
    assert!(token.bearer.is_none());
    for get in &s.issued[1..] {
        let bearer = get.bearer.as_ref().expect("an authenticated hop");
        assert!(bearer.secure_required(), "{}", get.target);
        assert!(bearer.bearer().secure_required(), "{}", get.target);
        assert!(!get.body.encoded().expect("an empty form").secure_required());
    }

    let mixed = |token_base: &str, api_base: &str| {
        let settings = format!(
            r#"{{"client_id":"Iv1.client","token_base":"{token_base}","api_base":"{api_base}"}}"#
        );
        let l = GithubLogin::open(&settings, Some(SECRET)).expect("opens");
        let mut s = Script::new()
            .answer(
                &format!("{token_base}/login/oauth/access_token"),
                200,
                &format!(r#"{{"access_token":"{TOKEN}"}}"#),
            )
            .answer(
                &format!("{api_base}/user"),
                200,
                r#"{"login":"octocat","id":1}"#,
            )
            .answer(&format!("{api_base}/user/orgs?per_page=100"), 200, "[]");
        identity(run(&l, &mut s));
        let secret = s.issued[0]
            .body
            .encoded()
            .expect("encodes")
            .secure_required();
        let bearer = s.issued[1]
            .bearer
            .as_ref()
            .expect("a bearer")
            .secure_required();
        (secret, bearer)
    };
    assert_eq!(
        mixed("https://github.com", "http://10.0.0.7"),
        (true, false)
    );
    assert_eq!(
        mixed("http://10.0.0.7", "https://api.github.com"),
        (false, true)
    );

    assert_eq!(mixed("http://10.0.0.7", "http://10.0.0.8"), (false, false));
}

#[test]
fn a_bearer_with_a_line_break_fails_the_hop_closed() {
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 200, r#"{"access_token":"gho_x\r\nX-Evil: 1"}"#);
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
}

#[test]
fn red_r1_prod0_7_a_hop_with_an_invalid_method_is_refused_not_sent_as_post() {
    let l = login();
    let mut hop = busbar_auth_github_plugin_hop();
    for bad in ["", "GET ", "G3T", "GE\r\nT"] {
        hop.method = bad.to_string();
        assert!(
            l.render(&hop, None).is_err(),
            "method {bad:?} must be refused"
        );
    }
    hop.method = "GET".to_string();
    assert_eq!(l.render(&hop, None).expect("valid").method, "GET");
}

fn busbar_auth_github_plugin_hop() -> busbar_contract::auth::LoginHop {
    busbar_contract::auth::LoginHop {
        method: "GET".to_string(),
        url: format!("{}/user", "https://api.github.com"),
        form: Vec::new(),
        secret_form_field: None,
        headers: Vec::new(),
    }
}

/// The hop loop is bounded at [`MAX_HOPS`] exchanges per callback: a flow that has spent them sends
/// nothing more and ends as an outage, at warn; one with a single hop left sends that one only.
/// (The step machine itself stops at the tenth org page, so a full chain spends exactly the
/// bound: `red_g4_the_org_list_stops_at_ten_pages_with_a_warn`.)
#[test]
fn the_hop_loop_is_bounded() {
    let l = login();
    let mut s = Script::happy();
    let mut f = flow(&l);
    f.turns = MAX_HOPS;
    let cap = crate::diagnostics::GithubDiagnostics::default();
    let step = tracing::subscriber::with_default(cap.subscriber(), || l.drive(&mut f, &mut s));
    assert_eq!(step, OUTAGE);
    assert!(s.issued.is_empty(), "no hop past the bound");
    assert!(cap.contains("hop limit"), "{:?}", cap.messages());

    let mut s = Script::happy();
    let mut f = flow(&l);
    f.turns = MAX_HOPS - 1;
    assert_eq!(l.drive(&mut f, &mut s), OUTAGE);
    assert_eq!(
        s.targets(),
        vec![TOKEN_URL],
        "the last hop allowed, then none"
    );
}

#[test]
fn red_l1_an_answer_is_read_as_the_answer_of_the_hop_sent() {
    let login_only = GithubLogin::open(
        &SETTINGS.replace("\"client_id\"", "\"fetch_orgs\": false, \"client_id\""),
        Some(SECRET),
    )
    .expect("opens");
    let mut s = Script::happy().answer(TOKEN_URL, 200, r#"{"login":"octocat","id":1}"#);
    assert_eq!(
        run(&login_only, &mut s),
        OUTAGE,
        "a user where the token belongs"
    );
    assert_eq!(s.targets(), vec![TOKEN_URL]);

    let l = login();
    let cases: [(&str, &str, Vec<&str>); 4] = [
        (
            USER_URL,
            r#"{"access_token":"gho_swapped"}"#,
            vec![TOKEN_URL, USER_URL],
        ),
        (
            USER_URL,
            r#"[{"login":"acme","id":1}]"#,
            vec![TOKEN_URL, USER_URL],
        ),
        (
            ORGS_URL,
            r#"{"login":"someone-else","id":2}"#,
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
        (
            ORGS_URL,
            r#"{"access_token":"gho_swapped"}"#,
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
    ];
    for (url, body, targets) in cases {
        let mut s = Script::happy().answer(url, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{url} {body}");
        assert_eq!(s.targets(), targets, "{url} {body}");
        assert!(
            s.issued
                .iter()
                .all(|r| plain(r).iter().all(|(_, v)| !v.contains("gho_swapped"))),
            "{url} {body}"
        );
    }
}

/// Current identity/failure answers for these bodies; immutable subjects replace historical handles.
#[test]
fn the_flow_preserves_current_identity_and_failure_contract() {
    let id = |roles: &[&str]| {
        let mut p = Principal::from_id("github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
        p.name = Some("Octo".to_string());
        p.roles = roles.iter().map(|r| r.to_string()).collect();
        LoginStep::Identity(p)
    };
    let cases: Vec<(Script, LoginStep, Vec<&str>)> = vec![
        (
            Script::happy(),
            id(&[
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1",
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1",
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2",
            ]),
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
        (
            Script::happy().answer(ORGS_URL, 200, r#"[{"login":"elsewhere","id":11}]"#),
            id(&[
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1",
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:11",
            ]),
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
            OUTAGE,
            vec![TOKEN_URL, USER_URL, ORGS_URL],
        ),
        (
            Script::happy().answer(USER_URL, 200, r#"{"login":"no-id"}"#),
            OUTAGE,
            vec![TOKEN_URL, USER_URL],
        ),
    ];
    for (mut script, expected, urls) in cases {
        assert_eq!(run(&login(), &mut script), expected);
        assert_eq!(script.targets(), urls);
    }
}

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

/// The token endpoint's non-2xx is never a token, even when its body carries one: a 401 with an
#[test]
fn a_non_2xx_token_answer_is_never_a_token_even_with_one_in_it() {
    let l = login();
    let mut s = Script::happy().answer(
        TOKEN_URL,
        401,
        r#"{"error":"invalid_grant","access_token":"should-be-ignored"}"#,
    );
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
    let mut s = Script::happy().answer(TOKEN_URL, 401, r#"{"access_token":"should-be-ignored"}"#);
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
}

#[test]
fn red_g1_the_token_endpoint_declines_only_a_5_2_error() {
    let l = login();
    for (status, body) in [
        (400, r#"{"error":"invalid_grant"}"#),
        (401, r#"{"error":"invalid_client","error_description":"x"}"#),
        (400, "error=invalid_grant&error_description=gone"),
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, status, body);
        assert_eq!(run(&l, &mut s), LoginStep::BadCredential, "{status} {body}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
    for (status, body) in [
        (302, ""),
        (301, "<html>moved</html>"),
        (403, r#"{"message":"forbidden"}"#),
        (404, "Not Found"),
        (408, ""),
        (400, "<html>bad request</html>"),
        (401, r#"{"message":"Bad credentials"}"#),
        (418, r#"{"error":"invalid_grant"}"#),
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, status, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{status} {body}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
}

#[test]
fn red_g1_the_rest_hops_decline_only_a_401() {
    let l = login();
    for (url, before) in [
        (USER_URL, vec![TOKEN_URL, USER_URL]),
        (ORGS_URL, vec![TOKEN_URL, USER_URL, ORGS_URL]),
    ] {
        let mut s = Script::happy().answer(url, 401, r#"{"message":"Bad credentials"}"#);
        assert_eq!(run(&l, &mut s), LoginStep::BadCredential, "{url} 401");
        for status in [301, 302, 304, 403, 404, 408, 410, 422] {
            let mut s = Script::happy().answer(url, status, r#"{"message":"x"}"#);
            assert_eq!(run(&l, &mut s), OUTAGE, "{url} {status}");
            assert_eq!(s.targets(), before, "{url} {status}");
        }
    }
}

/// The retry hint against a fixed clock: delta seconds first, then an HTTP-date (its three
/// RFC 9110 forms) as the seconds to it, then a spent rate limit's reset.
#[test]
fn the_retry_hint_reads_seconds_dates_and_resets_against_the_clock() {
    let http_date = |value| {
        busbar_contract::abi::auth::http_date_unix(value, 1_793_793_600)
            .and_then(|at| u64::try_from(at).ok())
    };
    // 1994-11-06T08:49:37Z, and the same date in each HTTP-date form.
    const AT: u64 = 784_111_777;
    let after = |v: &str| ReplyFields {
        retry_after: Some(v.to_string()),
        ..ReplyFields::default()
    };
    for date in [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
    ] {
        assert_eq!(http_date(date), Some(AT), "{date}");
        assert_eq!(retry_hint(&after(date), AT - 90), Some(90), "{date}");
        assert_eq!(retry_hint(&after(date), AT + 5), Some(0), "{date}: past");
    }
    assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    assert_eq!(
        http_date("Wed, 04 Nov 2026 12:00:00 GMT"),
        Some(1_793_793_600)
    );
    assert_eq!(
        http_date("Tue, 29 Feb 2028 00:00:01 GMT"),
        Some(1_835_395_201)
    );
    for bad in [
        "",
        "soon",
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Sun 06 Nov 1994 08:49:37 GMT",
        "Sun, 06 Foo 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 32 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1969 08:49:37 GMT",
        "Sun, 06 Nov 1994 08:49 GMT",
        "Sunday, 06-Nov-1994 08:49:37 GMT",
    ] {
        assert_eq!(http_date(bad), None, "{bad:?}");
    }
    assert_eq!(retry_hint(&after("120"), AT), Some(120), "seconds first");
    let spent = ReplyFields {
        ratelimit_remaining: Some("0".to_string()),
        ratelimit_reset: Some((AT + 100).to_string()),
        ..ReplyFields::default()
    };
    assert_eq!(retry_hint(&spent, AT), Some(100));
    assert_eq!(retry_hint(&spent, AT + 200), Some(0));
    let unreadable = ReplyFields {
        retry_after: Some("soon".to_string()),
        ..spent.clone()
    };
    assert_eq!(
        retry_hint(&unreadable, AT),
        Some(100),
        "falls back to the reset"
    );
    assert_eq!(retry_hint(&ReplyFields::default(), AT), None);
}

/// Without a usable wall clock only a delta `retry-after` is meaningful: an absolute reset (or
/// date) is dropped, said at warn, never read as a delay from epoch zero.
#[test]
fn unavailable_wall_clock_warns_and_preserves_only_delta_seconds() {
    let before_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
    let cap = crate::diagnostics::GithubDiagnostics::default();
    let mut fields = ReplyFields {
        ratelimit_remaining: Some("0".into()),
        ratelimit_reset: Some(u64::MAX.to_string()),
        ..ReplyFields::default()
    };
    assert_eq!(
        tracing::subscriber::with_default(cap.subscriber(), || retry_hint_at(
            &fields,
            before_epoch
        )),
        None
    );
    assert!(cap.contains("wall clock unavailable"));
    fields.retry_after = Some("Sun, 06 Nov 1994 08:49:37 GMT".into());
    assert_eq!(retry_hint_at(&fields, before_epoch), None);
    fields.retry_after = Some(u64::MAX.to_string());
    assert_eq!(retry_hint_at(&fields, before_epoch), Some(u64::MAX));
}

#[test]
fn red_g1_a_rate_limit_is_an_outage_with_the_idps_retry_hint() {
    let l = login();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let after = |secs: &str| ReplyFields {
        retry_after: Some(secs.to_string()),
        ..ReplyFields::default()
    };
    let spent = ReplyFields {
        ratelimit_remaining: Some("0".to_string()),
        ratelimit_reset: Some((now + 100).to_string()),
        ..ReplyFields::default()
    };
    for url in [USER_URL, ORGS_URL] {
        for status in [403, 429] {
            let mut s = Script::happy().answer_with(url, status, after("60"), "{}");
            assert_eq!(
                run(&l, &mut s),
                LoginStep::Outage {
                    retry_after: Some(60)
                },
                "{url} {status}"
            );
            // The exact seconds are pinned against a fixed clock above; through the flow the
            // hint is the reset less the flow's own (later) clock, so never more than 100.
            let mut s = Script::happy().answer_with(url, status, spent.clone(), "{}");
            match run(&l, &mut s) {
                LoginStep::Outage {
                    retry_after: Some(secs),
                } => assert!(secs <= 100, "{url} {status}: {secs}"),
                other => panic!("{url} {status}: {other:?}"),
            }
        }
    }
    for url in [TOKEN_URL, USER_URL, ORGS_URL] {
        for status in [429, 500, 503] {
            let mut s = Script::happy().answer_with(url, status, after("120"), "{}");
            assert_eq!(
                run(&l, &mut s),
                LoginStep::Outage {
                    retry_after: Some(120)
                },
                "{url} {status}"
            );
        }
    }

    let mut s = Script::happy().answer_with(USER_URL, 503, after("soon"), "{}");
    assert_eq!(run(&l, &mut s), OUTAGE);
}

/// An empty access token (either shape) is no token: never a `Bearer ` with nothing after it. A
#[test]
fn an_empty_access_token_is_refused() {
    let l = login();
    for body in [
        r#"{"access_token":""}"#,
        "access_token=&scope=read:org&token_type=bearer",
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{body}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
    }
}

/// A `/user` without a `login` is no sign-in answer: an outage (G3).
#[test]
fn a_user_without_a_login_is_an_outage() {
    let l = login();
    let mut s = Script::happy().answer(USER_URL, 200, r#"{"id":42,"name":"No Login"}"#);
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
}

/// Out-of-order bodies fail closed: an org list or a `/user` where the token response belongs
#[test]
fn out_of_order_bodies_fail_closed() {
    let l = login();
    for body in [
        r#"[{"login":"acme","id":1}]"#,
        r#"{"login":"octocat","id":1}"#,
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{body}");
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
    assert!(plain(&s.issued[2])
        .iter()
        .any(|(k, v)| k == "authorization" && *v == format!("Bearer {TOKEN}")));
}

/// Each flow owns its state (the legacy module's shared pending map, its correlation key, cap and
#[test]
fn each_flow_owns_its_state_and_a_finished_one_holds_nothing() {
    let l = login();
    let token = |t: &str| format!(r#"{{"access_token":"{t}"}}"#);
    let mut a = Script::happy().answer(TOKEN_URL, 200, &token("gho_a"));
    let mut b = Script::happy().answer(TOKEN_URL, 200, &token("gho_b"));
    a.pend_first = true;
    b.pend_first = true;
    let (mut fa, mut fb) = (flow(&l), flow(&l));

    for _ in 0..2 {
        assert_eq!(l.drive(&mut fa, &mut a), LoginStep::Pending);
        assert_eq!(l.drive(&mut fb, &mut b), LoginStep::Pending);
    }
    let bearer = |s: &Script, t: &str| {
        s.issued
            .iter()
            .any(|r| plain(r).iter().any(|(_, v)| v.contains(t)))
    };
    assert!(bearer(&a, "gho_a") && !bearer(&a, "gho_b"));
    assert!(bearer(&b, "gho_b") && !bearer(&b, "gho_a"));

    for mut s in [Script::happy(), Script::happy().answer(USER_URL, 500, "{}")] {
        let mut f = flow(&l);
        l.drive(&mut f, &mut s);
        assert!(f.done.is_some());
        assert!(f.state.access_token.is_none() && f.state.user.is_none());
        assert!(f.req.answer.is_none(), "the token response is cleared");
        assert!(
            f.req.code.is_none() && f.req.code_verifier.is_none(),
            "the code and the verifier are wiped"
        );
    }
}

#[test]
fn open_refuses_in_the_contracts_settings_lines() {
    let err = |s: &str, secret: Option<&str>| GithubLogin::open(s, secret).unwrap_err();
    assert_eq!(
        err("  ", Some(SECRET)),
        "settings: empty: the github plugin requires client_id"
    );
    assert!(err("{ not json", Some(SECRET)).starts_with("settings: not a JSON document"));
    assert!(err(r#"{"client_id":"x","bogus":1}"#, Some(SECRET))
        .starts_with("settings: unknown field `bogus`"));

    let leaked = err(r#"{"client_id":"x","client_secret":"leak"}"#, Some(SECRET));
    assert!(
        leaked.starts_with("settings: unknown field `client_secret`"),
        "{leaked}"
    );
    assert!(!leaked.contains("leak\""), "{leaked}");
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
            r#"[{"login":"testorg","id":7}]"#,
        );
    let p = identity(run(&l, &mut s));

    let mut expected = Principal::from_id("github-v2:aHR0cHM6Ly9naGUuZXhhbXBsZQ:user:1");
    expected.name = Some("octocat".to_string());
    expected.roles = vec![
        "github-v2:aHR0cHM6Ly9naGUuZXhhbXBsZQ:user:1".to_string(),
        "github-v2:aHR0cHM6Ly9naGUuZXhhbXBsZQ:org:7".to_string(),
    ];
    assert_eq!(p, expected);
    let body = body_text(&s.issued[0]);
    assert!(body.starts_with("client_id=Iv1.e2eclient&"), "{body}");
    assert!(
        body.ends_with(&format!("&client_secret={SECRET}")),
        "{body}"
    );

    let leaked = delivered.replace("\"client_id\"", "\"client_secret\": \"s\", \"client_id\"");
    assert!(GithubLogin::open(&leaked, Some(SECRET))
        .unwrap_err()
        .starts_with("settings: unknown field `client_secret`"));
}

/// A headless-only provider (no `browser_login`, so no secret) loaded in 1.5.5 and still does; a
#[test]
fn no_secret_loads_and_drops_the_secret_field_as_1_5_5_did() {
    for secret in [None, Some("")] {
        let l = GithubLogin::open(SETTINGS, secret).expect("loads without a secret");
        let mut s = Script::happy();
        assert_eq!(
            identity(run(&l, &mut s)).id,
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
        );
        let body = body_text(&s.issued[0]);
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
    l.drive(&mut f, &mut s);
    l.drive(&mut f, &mut s);
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
            &l.cfg,
            "https://node.example/auth/token",
            "st",
            "ch",
            &["user:email".to_string()]
        )
    );
    assert!(!url.contains(SECRET));
}

#[test]
fn the_form_is_serde_urlencoded() {
    let body = FormBody::new()
        .public("a b", "x*y-z._~!")
        .public("k", "é/=&");
    let r = |body: FormBody| HopRequest {
        method: "POST".to_string(),
        target: TOKEN_URL.to_string(),
        fields: Vec::new(),
        bearer: None,
        body,
        timeout_ms: 0,
    };
    assert_eq!(body_text(&r(body)), "a+b=x*y-z._%7E%21&k=%C3%A9%2F%3D%26");
    assert_eq!(body_text(&r(FormBody::new())), "");
}

#[test]
fn decision_a_reference_written_base_resolved_by_the_kernel_logs_in() {
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
    assert_eq!(
        identity(run(&l, &mut s)).id,
        "github-v2:aHR0cHM6Ly9naGUuY29ycC5leGFtcGxlL2FwaS92Mw:user:1"
    );
}

#[test]
fn a_poisoned_orgs_array_cannot_swap_the_token_mid_flow() {
    let l = login();
    let mut s = Script::happy().answer(
        ORGS_URL,
        200,
        r#"[{"login":"acme","id":1,"description":"x&access_token=gho_ATTACKER&y"}]"#,
    );
    let p = identity(run(&l, &mut s));
    assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
    assert!(p
        .roles
        .contains(&"github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1".to_string()));
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL]);

    for r in &s.issued[1..] {
        let authorization: Vec<String> = plain(r)
            .into_iter()
            .filter(|(k, _)| k == "authorization")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(
            authorization,
            vec![format!("Bearer {TOKEN}")],
            "{}",
            r.target
        );
    }
    assert!(s
        .issued
        .iter()
        .all(|r| plain(r).iter().all(|(_, v)| !v.contains("gho_ATTACKER"))));
}

mod logging {
    use super::*;
    use crate::diagnostics::GithubDiagnostics;

    /// Settings that omit `token_base`: its default host is not operator-written, so not allowed.
    const NO_TOKEN_BASE: &str =
        r#"{"client_id": "Iv1.client", "api_base": "https://api.github.com"}"#;

    #[test]
    fn a_hop_the_guard_refuses_is_explained_without_a_secret() {
        let err = GithubLogin::open(NO_TOKEN_BASE, Some(SECRET)).unwrap_err();
        assert!(
            err.contains("token_base") && err.contains("allowlist"),
            "{err}"
        );
        assert!(!err.contains(SECRET), "{err}");

        let l = login();
        let cap = GithubDiagnostics::default();
        let hop = LoginHop {
            method: "GET".to_string(),
            url: "https://elsewhere.example/user".to_string(),
            form: Vec::new(),
            secret_form_field: None,
            headers: Vec::new(),
        };
        let refused = tracing::subscriber::with_default(cap.subscriber(), || l.render(&hop, None));
        assert_eq!(refused, Err(Refused));
        assert!(cap.contains("elsewhere.example"), "{:?}", cap.messages());
        assert!(cap.contains("allow"), "{:?}", cap.messages());
        assert!(cap.contains("module=\"github\""), "{:?}", cap.messages());
        for secret in [SECRET, "the-code", "the-verifier"] {
            assert!(!cap.contains(secret), "{:?}", cap.messages());
        }
    }

    #[test]
    fn a_declined_code_logs_the_idp_error_and_no_secret() {
        let l = login();
        let mut s = Script::new().answer(TOKEN_URL, 200, r#"{"error":"bad_verification_code"}"#);
        let cap = GithubDiagnostics::capturing_debug();
        let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
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

    /// The token endpoint declining the client itself (invalid_client / unauthorized_client) is the
    /// operator's misconfiguration: it warns, naming client_secret. A user's bad code (invalid_grant)
    /// stays at info.
    #[test]
    fn a_token_endpoint_refusing_the_client_warns_the_operator() {
        let l = login();
        for (body, expected) in [
            (
                r#"{"error":"invalid_client","error_description":"x"}"#,
                LoginStep::BadCredential,
            ),
            (
                r#"{"error":"unauthorized_client"}"#,
                LoginStep::BadCredential,
            ),
            (r#"{"error":"incorrect_client_credentials"}"#, OUTAGE),
            (r#"{"error":"redirect_uri_mismatch"}"#, OUTAGE),
            (r#"{"error":"application_suspended"}"#, OUTAGE),
        ] {
            let mut s = Script::happy().answer(TOKEN_URL, 401, body);
            let cap = GithubDiagnostics::default();
            let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
            assert_eq!(step, expected, "{body}");
            assert!(
                cap.contains("client_secret"),
                "{body}: {:?}",
                cap.messages()
            );
            assert_eq!(
                cap.messages().len(),
                1,
                "one operator WARN: {:?}",
                cap.messages()
            );
            for secret in [SECRET, "the-code", "the-verifier"] {
                assert!(!cap.contains(secret), "{:?}", cap.messages());
            }
        }
        let mut s = Script::happy().answer(TOKEN_URL, 400, r#"{"error":"invalid_grant"}"#);
        let cap = GithubDiagnostics::default();
        let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
        assert_eq!(step, LoginStep::BadCredential);
        assert!(!cap.contains("client_secret"), "{:?}", cap.messages());
    }

    /// RED L8: a hop that could not be made (refused, connect, TLS, timeout, a request that could
    /// not be framed) ends the login as an outage with one WARN naming the hop, never silently.
    #[test]
    fn red_l8_an_unreachable_hop_is_a_warn_naming_the_hop() {
        let l = login();
        for (url, path) in [
            (TOKEN_URL, "/login/oauth/access_token"),
            (USER_URL, "/user"),
            (ORGS_URL, "/user/orgs"),
        ] {
            let mut s = Script::happy().unreachable(url);
            let cap = GithubDiagnostics::default();
            let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
            assert_eq!(step, OUTAGE, "{url}");
            assert!(
                cap.contains("could not be made"),
                "{url}: {:?}",
                cap.messages()
            );
            assert!(cap.contains(path), "{url}: {:?}", cap.messages());
            assert!(
                cap.contains("module=\"github\""),
                "{url}: {:?}",
                cap.messages()
            );
        }
    }

    #[test]
    fn red_g1_a_403_on_the_org_list_warns_of_the_scope() {
        let l = login();
        let mut s = Script::happy().answer(ORGS_URL, 403, r#"{"message":"forbidden"}"#);
        let cap = GithubDiagnostics::default();
        let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
        assert_eq!(step, OUTAGE);
        assert!(cap.contains("read:org"), "{:?}", cap.messages());
        assert!(cap.contains("module=\"github\""), "{:?}", cap.messages());
    }

    #[test]
    fn a_misconfigured_client_is_a_warn() {
        let l = login();
        let mut s = Script::new().answer(TOKEN_URL, 200, "error=incorrect_client_credentials");
        let cap = GithubDiagnostics::default();
        let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
        assert_eq!(
            step, OUTAGE,
            "the operator's misconfiguration is no declined sign-in"
        );
        assert!(
            cap.contains("incorrect_client_credentials"),
            "{:?}",
            cap.messages()
        );
    }

    #[test]
    fn red_g2_a_foreign_error_string_is_never_logged() {
        let l = login();
        for body in [
            r#"{"error":"EVIL\u001b[31m forged line"}"#.to_string(),
            format!("error=EVIL{}", "x".repeat(80)),
        ] {
            let mut s = Script::new().answer(TOKEN_URL, 200, &body);
            let cap = GithubDiagnostics::capturing_debug();
            let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
            assert_eq!(step, OUTAGE, "{body}");
            assert!(!cap.contains("EVIL"), "{:?}", cap.messages());
            assert!(cap.contains("<unrecognised>"), "{:?}", cap.messages());
        }
    }
}

#[test]
fn a_hop_response_debug_shows_no_body() {
    let r = HopResponse {
        status: 200,
        fields: ReplyFields::default(),
        body: b"access_token=SECRETX".to_vec().into(),
    };
    let text = format!("{r:?} {:?}", Fetched::Ready(r.clone()));
    assert!(!text.contains("SECRETX"), "{text}");

    assert!(!text.contains("83, 69, 67"), "{text}");
    assert_eq!(
        format!("{r:?}"),
        "HopResponse { status: 200, body_len: 20 }"
    );
}

#[test]
fn a_hop_reply_over_the_cap_is_an_outage() {
    assert_eq!(MAX_HOP_REPLY_BYTES, 256 * 1024);
    let l = login();
    let mut body = format!(r#"{{"access_token":"{TOKEN}"}}"#);
    body.push_str(&" ".repeat(256 * 1024 + 1 - body.len()));
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), vec![TOKEN_URL]);

    body.pop();
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    assert_eq!(
        identity(run(&l, &mut s)).id,
        "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
    );
}

mod module_field {
    use super::*;
    use crate::diagnostics::GithubDiagnostics;

    #[test]
    fn a_decline_is_logged_with_the_module_field() {
        let l = login();
        let mut s = Script::happy().answer(USER_URL, 401, "{}");
        let cap = GithubDiagnostics::capturing_debug();
        let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
        assert_eq!(step, LoginStep::BadCredential);
        let messages = cap.messages();
        assert!(!messages.is_empty());
        for m in &messages {
            assert!(m.contains("module=\"github\""), "{messages:?}");
        }
    }
}

/// What the flow wipes, observed: a described hop's plain form values (the code, the verifier)
/// once it is rendered, and every credential the flow held once it finishes. The hop bodies the
/// SDK and the exchange hold are wiped on drop (their types say so).
#[test]
fn the_hop_bodies_are_wiped_on_drop() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let mut hop = build_token_exchange(
        &login().cfg,
        "code-canary",
        "https://node.example/auth/token",
        "verifier-canary",
    );
    assert!(hop.form.iter().any(|(_, v)| v == "code-canary"));
    wipe_hop(&mut hop);
    assert!(hop.form.iter().all(|(_, v)| v.is_empty()), "{:?}", hop.form);

    let l = login();
    let mut s = Script::happy();
    let mut f = flow(&l);
    identity(l.drive(&mut f, &mut s));
    assert!(f.req.code.is_none() && f.req.code_verifier.is_none());
    assert!(f.req.answer.is_none() && f.inflight.is_none());
    assert!(f.state.access_token.is_none() && f.state.user.is_none());
    wipes(&s.issued[0].body);
    let response = HopResponse {
        status: 200,
        fields: ReplyFields::default(),
        body: b"access_token=x".to_vec().into(),
    };
    wipes(&response.body);
}

/// GHO2, REFRESH MID-FLOW: the door swaps the login whole on `refresh`, but a parked flow is
/// driven by the login it began under to its end (L2, `Parked::login`). Even a flow driven by
/// another login re-issues the hop parked on a pending exchange exactly as it was sent (its stored
/// answer is read, the code is never redeemed twice), and that login's client secret is never sent,
/// as no token exchange is made again.
#[test]
fn a_refresh_mid_flow_resumes_the_parked_hop_unchanged() {
    let before = login();
    let after = GithubLogin::open(SETTINGS, Some("rotated-secret")).expect("opens");
    let mut s = Script::happy();
    s.pend_first = true;
    let mut f = flow(&before);
    assert_eq!(before.drive(&mut f, &mut s), LoginStep::Pending);
    let mut step = after.drive(&mut f, &mut s);
    while step == LoginStep::Pending {
        step = after.drive(&mut f, &mut s);
    }
    assert_eq!(
        identity(step).id,
        "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
    );
    let tokens: Vec<&HopRequest> = s.issued.iter().filter(|r| r.target == TOKEN_URL).collect();
    assert_eq!(tokens.len(), 2, "pended once, re-issued once");
    assert!(
        tokens[0] == tokens[1],
        "the parked hop is re-issued unchanged"
    );
    assert!(body_text(tokens[1]).ends_with(&format!("&client_secret={SECRET}")));
    assert!(s
        .issued
        .iter()
        .all(|r| !body_text(r).contains("rotated-secret")));
}

#[test]
fn repeated_link_lines_are_one_list() {
    let fields = ReplyFields::kept([
        (
            &b"Link"[..],
            &b"<https://api.github.com/user/orgs?page=1>; rel=\"prev\""[..],
        ),
        (
            &b"link"[..],
            &b"<https://api.github.com/user/orgs?page=3>; rel=\"next\""[..],
        ),
        (&b"Retry-After"[..], &b"5"[..]),
        (&b"retry-after"[..], &b"9"[..]),
    ]);
    let link = fields.link.as_deref().expect("a link");
    assert_eq!(
        crate::read_link(link).flatten(),
        Some("https://api.github.com/user/orgs?page=3")
    );
    assert_eq!(fields.retry_after.as_deref(), Some("5"));
}

/// A non-UTF-8 `Link` line is kept as unreadable, never dropped as if absent.
#[test]
fn a_non_utf8_link_line_reads_as_unreadable() {
    let fields = ReplyFields::kept([(
        &b"Link"[..],
        &b"<https://api.github.com/\xff>; rel=\"next\""[..],
    )]);
    assert_eq!(fields.link.as_deref(), Some("\u{fffd}"));
    assert_eq!(crate::read_link(fields.link.as_deref().unwrap()), None);
}

/// Logins (the user's and each org's) are GitHub's own characters only: ASCII letters, digits,
/// `-` and `_` (an Enterprise Managed User's `_<shortcode>`). A reply carrying any other login,
/// an invisible, bidi or separator character among them, is foreign: an outage, never an
/// identity or a group.
#[test]
fn a_login_outside_githubs_character_set_is_an_outage() {
    let l = login();
    let user = |login: &str| serde_json::json!({"login": login, "id": 1}).to_string();
    for bad in [
        "admin\u{200b}",
        "acme\u{202e}gnp",
        "octo\u{2028}cat",
        "octo\u{feff}",
        "octo cat",
        "octo/cat",
        "octo:cat",
        "octo@cat",
        "octo.cat",
        "\u{fffd}",
        "ｏｃｔｏ",
    ] {
        let mut s = Script::happy().answer(USER_URL, 200, &user(bad));
        assert_eq!(run(&l, &mut s), OUTAGE, "login {bad:?}");
        assert_eq!(s.targets(), [TOKEN_URL, USER_URL], "login {bad:?}");
        let orgs =
            serde_json::json!([{"login": "acme", "id": 1}, {"login": bad, "id": 2}]).to_string();
        let mut s = Script::happy().answer(ORGS_URL, 200, &orgs);
        assert_eq!(run(&l, &mut s), OUTAGE, "org {bad:?}");
    }
    for good in [
        "octocat",
        "Octo-Cat",
        "octo--cat",
        "octocat-",
        "octo_acme",
        "x1",
    ] {
        let orgs = serde_json::json!([{ "login": good, "id": 2 }]).to_string();
        let mut s = Script::happy()
            .answer(USER_URL, 200, &user(good))
            .answer(ORGS_URL, 200, &orgs);
        let p = identity(run(&l, &mut s));
        assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
        assert!(
            p.roles
                .contains(&"github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2".to_string()),
            "{good}"
        );
    }
}

/// A token reply whose `token_type` is not `bearer` (any case) is a token this plugin does not
/// understand: never presented, an outage. An absent `token_type` keeps GitHub's bearer meaning.
#[test]
fn a_token_of_another_type_is_never_presented() {
    let l = login();
    for body in [
        format!(r#"{{"access_token":"{TOKEN}","token_type":"mac"}}"#),
        format!(r#"{{"access_token":"{TOKEN}","token_type":""}}"#),
        format!(r#"{{"access_token":"{TOKEN}","token_type":7}}"#),
        format!("access_token={TOKEN}&token_type=mac"),
        format!("token_type=pop&access_token={TOKEN}"),
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{body}");
        assert_eq!(s.targets(), [TOKEN_URL], "{body}");
    }
    for body in [
        format!(r#"{{"access_token":"{TOKEN}","token_type":"Bearer"}}"#),
        format!(r#"{{"access_token":"{TOKEN}","token_type":null}}"#),
        format!(r#"{{"access_token":"{TOKEN}"}}"#),
        format!("access_token={TOKEN}&token_type=BEARER"),
        format!("access_token={TOKEN}"),
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(
            identity(run(&l, &mut s)).id,
            "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1",
            "{body}"
        );
    }
}

/// The ten-page cap is judged only after the next link's origin: a foreign next link on the
/// tenth page is the same outage it is on any other page, never a truncated sign-in.
#[test]
fn a_foreign_next_link_on_the_last_page_is_still_an_outage() {
    let l = login();
    let mut s = Script::happy().answer_with(
        ORGS_URL,
        200,
        link_to(Some(&orgs_page(2))),
        r#"[{"login":"o1","id":1}]"#,
    );
    for n in 2..=10 {
        let next = if n == 10 {
            "https://evil.example/user/orgs?page=11".to_string()
        } else {
            orgs_page(n + 1)
        };
        s = s.answer_with(
            &orgs_page(n),
            200,
            link_to(Some(&next)),
            &format!(r#"[{{"login":"o{n}","id":{n}}}]"#),
        );
    }
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.issued.len(), 2 + 10, "the foreign link is never followed");
}

/// A `Link` field that cannot be read is an outage (fail-closed: the login cannot finish with a
/// non-deterministic group set); it is never silently taken as the last page.
#[test]
fn an_unreadable_link_field_is_an_outage() {
    let l = login();
    for link in [
        "<https://api.github.com/user/orgs?page=2; rel=\"next\"",
        "garbage",
        "\u{fffd}",
    ] {
        let fields = ReplyFields {
            link: Some(link.to_string()),
            ..ReplyFields::default()
        };
        let mut s =
            Script::happy().answer_with(ORGS_URL, 200, fields, r#"[{"login":"acme","id":1}]"#);
        let cap = crate::diagnostics::GithubDiagnostics::default();
        let step = tracing::subscriber::with_default(cap.subscriber(), || run(&l, &mut s));
        assert_eq!(step, OUTAGE, "{link:?}");
        assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL], "{link:?}");
        assert!(
            cap.contains("cannot be read"),
            "{link:?}: {:?}",
            cap.messages()
        );
    }
}

/// An org page answers at most the 100 entries it was asked for; one carrying more is no answer
/// GitHub gives (an outage), which bounds what one login can assert.
#[test]
fn an_org_page_past_its_requested_size_is_an_outage() {
    let l = login();
    let page = |n: usize| {
        serde_json::Value::Array(
            (0..n)
                .map(|i| serde_json::json!({ "login": format!("o{i}"), "id": i + 1 }))
                .collect(),
        )
        .to_string()
    };
    let mut s = Script::happy().answer(ORGS_URL, 200, &page(crate::ORGS_PER_PAGE));
    assert_eq!(
        identity(run(&l, &mut s)).roles.len(),
        1 + crate::ORGS_PER_PAGE
    );
    let mut s = Script::happy().answer(ORGS_URL, 200, &page(crate::ORGS_PER_PAGE + 1));
    assert_eq!(run(&l, &mut s), OUTAGE);
}

/// The token endpoint's `error` is read alone, whatever members sit beside it (a repeated access
/// token included); a repeated or non-string `error` is no code.
#[test]
fn the_token_error_is_read_alone() {
    assert_eq!(
        github_error(
            r#"{"access_token":"gho_x","access_token":"gho_x","error":"bad_verification_code"}"#
        )
        .as_deref(),
        Some("bad_verification_code")
    );
    assert_eq!(github_error(r#"{"error":"a","error":"b"}"#), None);
    assert_eq!(github_error(r#"{"error":5}"#), None);
    assert_eq!(github_error(r#"{"access_token":"gho_x"}"#), None);
    assert_eq!(
        github_error("error=invalid_grant&x=1").as_deref(),
        Some("invalid_grant")
    );
}

#[test]
fn immutable_identity_is_used_by_the_complete_login_hop_chain() {
    let run_actor = |name: &str, user_id: u64, org_name: &str, org_id: u64| {
        let mut s = Script::happy()
            .answer(
                USER_URL,
                200,
                &serde_json::json!({"login":name,"id":user_id}).to_string(),
            )
            .answer(
                ORGS_URL,
                200,
                &serde_json::json!([{"login":org_name,"id":org_id}]).to_string(),
            );
        identity(run(&login(), &mut s))
    };
    let original = run_actor("alice", 1001, "acme", 700);
    let renamed = run_actor("alice-new", 1001, "acme-new", 700);
    let reused = run_actor("alice", 90210, "acme", 701);
    assert_eq!(original.id, renamed.id);
    assert_eq!(original.roles, renamed.roles);
    assert_ne!(original.id, reused.id);
    assert!(original
        .roles
        .iter()
        .all(|role| !reused.roles.contains(role)));
    for body in [r#"[{"login":"acme"}]"#, r#"[{"login":"acme","id":0}]"#] {
        let mut s = Script::happy().answer(ORGS_URL, 200, body);
        assert_eq!(run(&login(), &mut s), OUTAGE);
    }
}

#[test]
fn github_unused_id_token_members_do_not_change_authenticated_identity() {
    for member in [r#""not-a-jwt""#, "null", "42", r#"{"nonce":"foreign"}"#] {
        let mut s = Script::happy()
            .answer(
                TOKEN_URL,
                200,
                &format!(r#"{{"access_token":"{TOKEN}","id_token":{member}}}"#),
            )
            .answer(
                USER_URL,
                200,
                &format!(r#"{{"login":"octocat","id":1,"id_token":{member}}}"#),
            )
            .answer(
                ORGS_URL,
                200,
                &format!(r#"[{{"login":"acme","id":7,"id_token":{member}}}]"#),
            );
        let l = login();
        let mut f = l.start(
            Some("code"),
            Some("https://node.example/auth/token"),
            Some("verifier"),
            None,
        );
        let p = identity(l.drive(&mut f, &mut s));
        assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
        assert_eq!(
            p.roles,
            [
                p.id.clone(),
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:7".into()
            ]
        );
        assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
    }
    let mut s = Script::happy().answer(
        TOKEN_URL,
        200,
        &format!("access_token={TOKEN}&id_token=not-a-jwt"),
    );
    assert_eq!(
        identity(run(&login(), &mut s)).id,
        "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
    );
}

#[test]
fn github_unused_id_token_cannot_supply_credentials_or_override_failure_status() {
    let l = login();
    for body in [
        r#"{"id_token":"header.payload.signature"}"#,
        "id_token=header.payload.signature",
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE);
        assert_eq!(s.targets(), [TOKEN_URL]);
    }
    let mut s = Script::happy().answer(USER_URL, 200, r#"{"id_token":"header.payload.signature"}"#);
    assert_eq!(run(&l, &mut s), OUTAGE);
    for target in [TOKEN_URL, USER_URL, ORGS_URL] {
        let mut s = Script::happy().answer_with(
            target,
            503,
            ReplyFields {
                retry_after: Some("17".into()),
                ..ReplyFields::default()
            },
            r#"{"id_token":null}"#,
        );
        assert_eq!(
            run(&l, &mut s),
            LoginStep::Outage {
                retry_after: Some(17)
            }
        );
    }
    let mut s = Script::happy().answer(
        TOKEN_URL,
        200,
        r#"{"error":"bad_verification_code","id_token":null}"#,
    );
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
}

/// RFC 850 uses a rolling fifty-year window, and invalid calendar dates are refused.
#[test]
fn retry_dates_use_the_shared_calendar_and_rolling_century() {
    let http_date = |value| {
        busbar_contract::abi::auth::http_date_unix(value, 1_793_793_600)
            .and_then(|at| u64::try_from(at).ok())
    };
    assert_eq!(
        http_date("Wednesday, 04-Nov-26 12:00:00 GMT"),
        Some(1_793_793_600)
    );
    assert_eq!(
        http_date("Thursday, 01-Jan-70 00:00:00 GMT"),
        http_date("Wed, 01 Jan 2070 00:00:00 GMT")
    );
    assert_eq!(
        http_date("Wed, 04 Nov 2026 12:00:60 GMT"),
        Some(1_793_793_660)
    );
    for bad in [
        "Sun, 00 Nov 1994 08:49:37 GMT",
        "Wed, 31 Apr 2026 00:00:00 GMT",
        "Sun, 29 Feb 2026 00:00:00 GMT",
        "Sun, 06 Nov 1994 08:60:37 GMT",
        "Sun, 06 Nov 1994 08:49:61 GMT",
    ] {
        assert_eq!(http_date(bad), None, "{bad:?}");
    }
}

#[test]
fn retry_hint_calendar_failure_preserves_reset_fallback_and_overflow_policy() {
    let now = 1_793_793_600;
    let mut fields = ReplyFields {
        retry_after: Some("Wed, 31 Apr 2026 00:00:00 GMT".into()),
        ratelimit_remaining: Some("0".into()),
        ratelimit_reset: Some((now + 17).to_string()),
        ..ReplyFields::default()
    };
    assert_eq!(retry_hint(&fields, now), Some(17));
    fields.retry_after = Some("18446744073709551616".into());
    assert_eq!(retry_hint(&fields, now), Some(17));
    fields.retry_after = Some("Thursday, 01-Jan-70 00:00:00 GMT".into());
    assert_eq!(
        retry_hint(&fields, now),
        busbar_contract::abi::auth::retry_after_secs(b"Wed, 01 Jan 2070 00:00:00 GMT", now)
    );
}
