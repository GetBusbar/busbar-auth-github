// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-owned login, driven over a scripted exchange. Hermetic: no network. Each arm states
//! the 1.5.5 answer it keeps (the core hop loop in busbar v1.5.5 `auth/token.rs` over the v1.0.3
//! step machine).

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
            .answer(ORGS_URL, 200, r#"[{"login":"acme"},{"login":"widgets"}]"#)
    }
    fn targets(&self) -> Vec<&str> {
        self.issued.iter().map(|r| r.target.as_str()).collect()
    }
}

/// A request's header fields as the SDK frames them (the chip's sealed bearer included), read
/// back off the head it would send.
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
/// injected into its slot, serde_urlencoded bytes, `content-type`; then (RED L3) `accept:
/// application/json`, so GitHub answers JSON rather than its form-encoded default.
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

/// The authenticated GETs: no body and (RED L4) no `content-type` (only a hop with a form body
/// carries one), the bearer, then the module's headers, lowercase, in order.
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
        assert_eq!(run(&l, &mut s), OUTAGE, "token {status}");
        assert_eq!(s.targets(), vec![TOKEN_URL]);
        let mut s = Script::happy().answer(USER_URL, status, "{}");
        assert_eq!(run(&l, &mut s), OUTAGE, "user {status}");
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

/// RED G2 (owner-signed 2026-10-30): GitHub answers a token exchange it refuses with HTTP 200 and an
/// `error`. Only the user's own codes (a bad or expired code, an invalid grant) are a declined
/// sign-in; the operator's (wrong client credentials, a redirect_uri mismatch, a suspended app),
/// any other code, and a 2xx with neither a token nor an error are an outage. Both reply shapes.
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
    assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
}

#[test]
fn an_unreachable_idp_is_an_outage() {
    let l = login();
    let mut s = Script::happy().unreachable(USER_URL);
    assert_eq!(run(&l, &mut s), OUTAGE);
}

/// A truncated org list is never a zero-group login; it is no sign-in answer either (G3,
/// owner-signed 2026-10-30): an outage.
#[test]
fn a_malformed_org_list_is_an_outage_not_a_zero_group_login() {
    let l = login();
    let mut s = Script::happy().answer(ORGS_URL, 200, "[{truncated");
    assert_eq!(run(&l, &mut s), OUTAGE);
}

/// RED G3 (owner-signed 2026-10-30): a malformed or foreign 2xx from `/user` or `/user/orgs` is
/// the far end answering something that is no sign-in answer: an outage, never a declined
/// sign-in, and nothing more is sent.
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

/// RED G4: a user in more orgs than one page holds keeps every org: `/user/orgs` is followed by
/// its `Link: rel="next"` to the end.
#[test]
fn red_g4_the_org_list_is_followed_past_page_one() {
    let l = login();
    let mut s = Script::happy()
        .answer_with(
            ORGS_URL,
            200,
            link_to(Some(&orgs_page(2))),
            r#"[{"login":"acme"}]"#,
        )
        .answer_with(
            &orgs_page(2),
            200,
            link_to(Some(&orgs_page(3))),
            r#"[{"login":"widgets"}]"#,
        )
        .answer_with(
            &orgs_page(3),
            200,
            link_to(None),
            r#"[{"login":"gadgets"}]"#,
        );
    let p = identity(run(&l, &mut s));
    assert_eq!(
        p.roles,
        vec![
            "github:id/1".to_string(),
            "github:org/acme".to_string(),
            "github:org/widgets".to_string(),
            "github:org/gadgets".to_string(),
        ]
    );
    let (p2, p3) = (orgs_page(2), orgs_page(3));
    assert_eq!(
        s.targets(),
        vec![TOKEN_URL, USER_URL, ORGS_URL, p2.as_str(), p3.as_str()]
    );
    // Every page is authenticated with the same token.
    for page in &s.issued[2..] {
        assert!(plain(page)
            .iter()
            .any(|(k, v)| k == "authorization" && *v == format!("Bearer {TOKEN}")));
    }
}

/// RED G4: the org list is read for at most 10 pages (1000 orgs); a next link left after the
/// tenth is a WARN that the org groups are truncated, and the login identifies with what it read
/// (fail-safe: fewer roles, never more).
#[test]
fn red_g4_the_org_list_stops_at_ten_pages_with_a_warn() {
    use busbar_test_kit::warn_capture::WarnCapture;
    let l = login();
    let mut s = Script::happy().answer_with(
        ORGS_URL,
        200,
        link_to(Some(&orgs_page(2))),
        r#"[{"login":"o1"}]"#,
    );
    for n in 2..=12 {
        s = s.answer_with(
            &orgs_page(n),
            200,
            link_to(Some(&orgs_page(n + 1))),
            &format!(r#"[{{"login":"o{n}"}}]"#),
        );
    }
    let cap = WarnCapture::default();
    let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
    let p = identity(step);
    assert_eq!(p.roles.len(), 1 + 10, "{:?}", p.roles);
    assert_eq!(p.roles.last().map(String::as_str), Some("github:org/o10"));
    assert_eq!(s.issued.len(), 2 + 10);
    assert!(cap.contains("truncated"), "{:?}", cap.messages());
}

/// RED G4: a next link is followed only on the API's own origin (and through the hop guard): one
/// to another host, or to plain http, is an outage and is never sent.
#[test]
fn red_g4_a_next_link_off_the_api_origin_is_never_followed() {
    let l = login();
    for next in [
        "https://evil.example/user/orgs?page=2",
        "http://api.github.com/user/orgs?page=2",
        "https://github.com/user/orgs?page=2",
    ] {
        let mut s = Script::happy()
            .answer_with(ORGS_URL, 200, link_to(Some(next)), r#"[{"login":"acme"}]"#)
            .answer(next, 200, r#"[{"login":"injected"}]"#);
        assert_eq!(run(&l, &mut s), OUTAGE, "{next}");
        assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL, ORGS_URL], "{next}");
    }
}

/// RED L11: the far end's strings enter the Principal filtered. A login or an org login holding a
/// control character, or longer than 64 bytes (GitHub's own limit is 39), is no GitHub reply: an
/// outage. A display name holding a control character is not taken (the login stands in), and one
/// longer than 256 characters is cut to 256.
#[test]
fn red_l11_far_end_strings_enter_the_principal_filtered() {
    let l = login();
    let user = |login: &str, name: &str| {
        serde_json::json!({"login": login, "id": 1, "name": name}).to_string()
    };
    for bad in ["octo\ncat", "octo\u{1b}[31m", "octo\u{7f}", &"a".repeat(65)] {
        let mut s = Script::happy().answer(USER_URL, 200, &user(bad, "Octo"));
        assert_eq!(run(&l, &mut s), OUTAGE, "login {bad:?}");
        let orgs = serde_json::json!([{"login": "acme"}, {"login": bad}]).to_string();
        let mut s = Script::happy().answer(ORGS_URL, 200, &orgs);
        assert_eq!(run(&l, &mut s), OUTAGE, "org {bad:?}");
    }
    let long = "a".repeat(64);
    let mut s = Script::happy()
        .answer(USER_URL, 200, &user(&long, "Octo"))
        .answer(
            ORGS_URL,
            200,
            &serde_json::json!([{"login": long}]).to_string(),
        );
    let p = identity(run(&l, &mut s));
    assert_eq!(p.id, format!("github:{long}"));
    assert!(p.roles.contains(&format!("github:org/{long}")));

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

/// RED L7: an empty code, redirect_uri or code_verifier is refused before the exchange: the code
/// is never spent on a callback that cannot complete.
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
        "settings.token_base: must be written out: the hop allowlist is built only from URLs in the settings"
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
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert!(s.issued.is_empty());
}

/// G5: the client secret and the bearer are each required to go out on a secured connection when
/// the operator's base for their hop is `https` (`Cred::secure_for`): the SDK's exchange then
/// refuses to write either toward a target that is not secured (`cred::NOT_SECURE`), so a
/// plain-http target never receives them. The flags are read off the hops as they are sent.
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

    // Each is pinned by its own base: an https token_base pins the secret even when the API is a
    // private plain-http host, and an https api_base pins the bearer even when the token endpoint
    // is.
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
    // An operator who writes both bases as plain http to a private host is not overruled.
    assert_eq!(mixed("http://10.0.0.7", "http://10.0.0.8"), (false, false));
}

#[test]
fn a_bearer_with_a_line_break_fails_the_hop_closed() {
    // A token that would split the request: 1.5.5's header sanitiser failed the hop (an outage).
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 200, r#"{"access_token":"gho_x\r\nX-Evil: 1"}"#);
    assert_eq!(run(&l, &mut s), OUTAGE);
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
    let b64url_decode = |s: &str| URL_SAFE_NO_PAD.decode(s).ok();
    assert_eq!(b64url_decode("").as_deref(), Some(&b""[..]));
    assert_eq!(b64url_decode("Zg").as_deref(), Some(&b"f"[..]));
    assert_eq!(b64url_decode("Zm8").as_deref(), Some(&b"fo"[..]));
    assert_eq!(b64url_decode("Zm9v").as_deref(), Some(&b"foo"[..]));
    assert_eq!(b64url_decode("-_8").as_deref(), Some(&[0xfb, 0xff][..]));
    for bad in ["Zg==", "Z", "Zh", "Zm9", "+/8", "Zm9v!"] {
        assert_eq!(b64url_decode(bad), None, "{bad}");
    }
}

/// The hop loop is bounded: a far end that keeps answering token-shaped bodies from `/user` never
/// identifies and is never asked again (L1: a hop's answer is read as that hop's answer). The send
/// bound itself (the org pages) is `red_g4_the_org_list_stops_at_ten_pages_with_a_warn`.
#[test]
fn the_hop_loop_is_bounded() {
    let l = login();
    let tok = r#"{"access_token":"gho_again"}"#;
    let mut s = Script::happy().answer(USER_URL, 200, tok);
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), vec![TOKEN_URL, USER_URL]);
}

/// RED L1: the step machine reads each answer as the answer of the hop it sent, never by its
/// shape: a user-shaped token reply is no token (and never an identity with no token held), a
/// token-shaped `/user` reply never swaps the bearer, an org list from `/user` or a user from
/// `/user/orgs` is no answer. Each is an outage, and nothing more is sent.
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
        (USER_URL, r#"[{"login":"acme"}]"#, vec![TOKEN_URL, USER_URL]),
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
        // G3 (owner-signed 2026-10-30): a malformed REST answer is an outage, where 1.5.5 declined.
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

/// The token endpoint's non-2xx is never a token, even when its body carries one: a 401 with an
/// RFC 6749 §5.2 `error` is declined, a 401 without one is an outage (owner-signed 2026-10-30).
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

/// RED G1 (owner-signed 2026-10-30: only RFC 6749 §5.2 credential errors are a declined sign-in):
/// at the token endpoint a 400/401 carrying a §5.2 `error` (JSON or form) is declined; every other
/// non-2xx (a redirect, 403, 404, 408, a 400/401 with no `error`) is an outage, and nothing more is
/// sent.
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

/// RED G1: on `/user` and `/user/orgs` only a 401 (the token is not accepted) is a declined
/// sign-in; a redirect, a 404, a 408 or a 403 that is no rate limit is an outage.
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

/// RED G1: a rate limit on any REST hop (a 403 or 429 with `retry-after` or
/// `x-ratelimit-remaining: 0`), and a 5xx or 429 anywhere, is an outage carrying the IdP's retry
/// hint: its `retry-after` seconds, else the seconds to its `x-ratelimit-reset`.
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
            let mut s = Script::happy().answer_with(url, status, spent.clone(), "{}");
            match run(&l, &mut s) {
                LoginStep::Outage {
                    retry_after: Some(secs),
                } => assert!((90..=100).contains(&secs), "{url} {status}: {secs}"),
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
    // A hint that is no number of seconds is none.
    let mut s = Script::happy().answer_with(USER_URL, 503, after("soon"), "{}");
    assert_eq!(run(&l, &mut s), OUTAGE);
}

/// An empty access token (either shape) is no token: never a `Bearer ` with nothing after it. A
/// 2xx with no token and no error is an outage (G2, owner-signed 2026-10-30).
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
/// (no user held, no token held) never identifies and never sends an empty bearer: no token and no
/// error is an outage (G2, L1).
#[test]
fn out_of_order_bodies_fail_closed() {
    let l = login();
    for body in [r#"[{"login":"acme"}]"#, r#"{"login":"octocat","id":1}"#] {
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
    // The secret is never a settings key: it comes from browser_login.client_secret.
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
            r#"[{"login":"testorg"}]"#,
        );
    let p = identity(run(&l, &mut s));
    // The principal, byte for byte (owner Q109 signed: the stable numeric id role leads).
    let mut expected = Principal::from_id("github:octocat");
    expected.name = Some("octocat".to_string());
    expected.roles = vec!["github:id/1".to_string(), "github:org/testorg".to_string()];
    assert_eq!(p, expected);
    let body = body_text(&s.issued[0]);
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
        .starts_with("settings: unknown field `client_secret`"));
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
    use busbar_test_kit::warn_capture::WarnCapture;

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
        let refused = tracing::subscriber::with_default(cap.clone(), || l.render(&hop, None));
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
            let cap = WarnCapture::default();
            let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
            assert_eq!(step, OUTAGE, "{url}");
            assert!(
                cap.contains("could not be made"),
                "{url}: {:?}",
                cap.messages()
            );
            assert!(cap.contains(path), "{url}: {:?}", cap.messages());
            assert!(cap.contains("module=github"), "{url}: {:?}", cap.messages());
        }
    }

    /// RED G1: a 403 on `/user/orgs` that is no rate limit is the operator's (the token lacks the
    /// `read:org` scope): an outage, and a WARN naming the scope.
    #[test]
    fn red_g1_a_403_on_the_org_list_warns_of_the_scope() {
        let l = login();
        let mut s = Script::happy().answer(ORGS_URL, 403, r#"{"message":"forbidden"}"#);
        let cap = WarnCapture::default();
        let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
        assert_eq!(step, OUTAGE);
        assert!(cap.contains("read:org"), "{:?}", cap.messages());
        assert!(cap.contains("module=github"), "{:?}", cap.messages());
    }

    #[test]
    fn a_misconfigured_client_is_a_warn() {
        let l = login();
        let mut s = Script::new().answer(TOKEN_URL, 200, "error=incorrect_client_credentials");
        let cap = WarnCapture::default();
        let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
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

    /// RED G2: an error code is logged only when it is `[a-z0-9_]{1,64}`; any other far-end string
    /// is `<unrecognised>`, never echoed.
    #[test]
    fn red_g2_a_foreign_error_string_is_never_logged() {
        let l = login();
        for body in [
            r#"{"error":"EVIL\u001b[31m forged line"}"#.to_string(),
            format!("error=EVIL{}", "x".repeat(80)),
        ] {
            let mut s = Script::new().answer(TOKEN_URL, 200, &body);
            let cap = WarnCapture::capturing_debug();
            let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
            assert_eq!(step, OUTAGE, "{body}");
            assert!(!cap.contains("EVIL"), "{:?}", cap.messages());
            assert!(cap.contains("<unrecognised>"), "{:?}", cap.messages());
        }
    }
}

/// RED: a hop answer's body is the token response (the access token): Debug shows its status and
/// length, never its bytes.
#[test]
fn a_hop_response_debug_shows_no_body() {
    let r = HopResponse {
        status: 200,
        fields: ReplyFields::default(),
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

/// RED: a hop reply past 256 KiB (the kind standard's bound on a token or userinfo endpoint) is not
/// parsed: the login ends as an outage, nothing more is sent.
#[test]
fn a_hop_reply_over_the_cap_is_an_outage() {
    assert_eq!(MAX_HOP_REPLY_BYTES, 256 * 1024);
    let l = login();
    let mut body = format!(r#"{{"access_token":"{TOKEN}"}}"#);
    body.push_str(&" ".repeat(256 * 1024 + 1 - body.len()));
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    assert_eq!(run(&l, &mut s), OUTAGE);
    assert_eq!(s.targets(), vec![TOKEN_URL]);
    // At the cap exactly it is read.
    body.pop();
    let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
    assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
}

mod module_field {
    use super::*;
    use busbar_test_kit::warn_capture::WarnCapture;

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
    let response = HopResponse {
        status: 200,
        fields: ReplyFields::default(),
        body: b"access_token=x".to_vec().into(),
    };
    wipes(&response.body);
}

/// GHO2, REFRESH MID-FLOW: the door swaps the login whole on `refresh`, but a parked flow is
/// driven by the login it began under to its end (L2, `door::driving`). Even a flow driven by
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
    assert_eq!(identity(step).id, "github:octocat");
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
