// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-owned login, driven over a scripted exchange. Hermetic: no network. Each arm states
//! the 1.5.5 answer it keeps (the core hop loop in busbar v1.5.5 `auth/token.rs` over the v1.0.3
//! step machine).

use super::*;
use crate::GithubModule;
use busbar_contract::auth::LoginModule;
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
                body: body.as_bytes().to_vec(),
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
        String::from_utf8(token.body.clone()).unwrap(),
        "client_id=Iv1.client&code=the-code\
         &redirect_uri=https%3A%2F%2Fnode.example%2Fauth%2Ftoken\
         &code_verifier=the-verifier&client_secret=s3cr3t-client-value"
    );
    assert_eq!(
        token.fields,
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
            get.fields,
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
fn an_idp_5xx_is_fed_back_and_declined_as_1_5_5_did() {
    // 1.5.5's core fed EVERY HTTP status back; the module rejected non-2xx.
    let l = login();
    let mut s = Script::happy().answer(TOKEN_URL, 503, "unavailable");
    assert_eq!(run(&l, &mut s), LoginStep::BadCredential);
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
/// refused the first hop before sending anything ("Couldn't reach your provider"), and so does this.
#[test]
fn defaulted_bases_are_not_allow_listed_as_in_1_5_5() {
    let l = GithubLogin::open(r#"{"client_id":"Iv1.client"}"#, Some(SECRET)).unwrap();
    let mut s = Script::happy();
    assert_eq!(run(&l, &mut s), LoginStep::Outage);
    assert!(s.issued.is_empty(), "the secret never left the plugin");
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

/// The same bodies through the 1.5.5 step machine (the cold module, driven as 1.5.5's core drove it)
/// and through the flow reach the same answer and describe the same hops.
#[test]
fn the_flow_answers_as_the_1_5_5_module_driven_by_the_1_5_5_core() {
    let cfg: GitHubConfig = serde_json::from_str(SETTINGS).unwrap();
    let cases: Vec<Script> = vec![
        Script::happy(),
        Script::happy().answer(ORGS_URL, 200, r#"[{"login":"elsewhere"}]"#),
        Script::happy().answer(USER_URL, 401, "{}"),
        Script::happy().answer(TOKEN_URL, 200, r#"{"error":"bad_verification_code"}"#),
        Script::happy().answer(ORGS_URL, 200, "[{bad"),
        Script::happy().answer(USER_URL, 200, r#"{"login":"no-id"}"#),
    ];
    for mut script in cases {
        let answers = script.answers.clone();
        let flow_step = run(&login(), &mut script);

        // 1.5.5: the core's loop over the module.
        let module = GithubModule::new(cfg.clone());
        let mut cl = CompleteLogin {
            code: Some("the-code".into()),
            redirect_uri: Some("https://node.example/auth/token".into()),
            code_verifier: Some("the-verifier".into()),
            ..Default::default()
        };
        let mut urls = Vec::new();
        let mut legacy = LoginStep::Outage;
        for _ in 0..MAX_HOPS {
            match module.complete_login(&cl) {
                LoginOutcome::Identify(p) => {
                    legacy = LoginStep::Identity(p);
                    break;
                }
                LoginOutcome::Reject => {
                    legacy = LoginStep::BadCredential;
                    break;
                }
                LoginOutcome::Exchange(hop) => {
                    urls.push(hop.url.clone());
                    let Some(Fetched::Ready(r)) = answers.get(&hop.url) else {
                        break;
                    };
                    cl.token_response = Some(LoginHttpResponse {
                        status: r.status,
                        body: String::from_utf8_lossy(&r.body).into_owned(),
                    });
                }
                _ => break,
            }
        }
        assert_eq!(flow_step, legacy);
        assert_eq!(script.targets(), urls);
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
    let body = String::from_utf8(s.issued[0].body.clone()).unwrap();
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
        let body = String::from_utf8(s.issued[0].body.clone()).unwrap();
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
    let pairs = vec![
        ("a b".to_string(), "x*y-z._~!".to_string()),
        ("k".to_string(), "é/=&".to_string()),
    ];
    assert_eq!(form_encode(&pairs), "a+b=x*y-z._%7E%21&k=%C3%A9%2F%3D%26");
    assert_eq!(form_encode(&[]), "");
}

/// OWNER Q123 ACCEPTED (2026-09-30: "a GitHub base URL written as a secret reference now logs
/// in"): v1.5.5 built the hop allowlist from the RAW settings (auth/token.rs:283), so
/// `api_base: {env: GHE_API}` contributed no host and every hop was refused (502). On 1.6.0 the
/// kernel resolves the reference in place and the plugin sees only the resolved string, so the
/// same provider logs in. The owner accepted that; this cell pins it.
#[test]
fn decision_a_reference_written_base_resolved_by_the_kernel_logs_in() {
    // As the kernel delivers `settings: { api_base: {env: GHE_API}, token_base: {env: GHE_WEB},
    // authorize_base: {env: GHE_WEB}, client_id: "Iv1.client" }` after resolving in place.
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

mod logging {
    use super::*;
    use busbar_contract::testkit::WarnCapture;

    /// Settings that omit `token_base`: its default host is not operator-written, so not allowed.
    const NO_TOKEN_BASE: &str =
        r#"{"client_id": "Iv1.client", "api_base": "https://api.github.com"}"#;

    #[test]
    fn a_hop_the_guard_refuses_is_explained_without_a_secret() {
        let l = GithubLogin::open(NO_TOKEN_BASE, Some(SECRET)).expect("opens");
        let cap = WarnCapture::default();
        let step = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut Script::happy()));
        assert_eq!(step, LoginStep::Outage);
        assert!(cap.contains("github.com"), "{:?}", cap.messages());
        assert!(cap.contains("allow"), "{:?}", cap.messages());
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
