// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises GitHub login flows over the scripted exchange API.

use super::*;

#[test]
fn token_400_and_401_decline_only_the_documented_oauth_error_set() {
    let l = login();
    for status in [400, 401] {
        for code in [
            "invalid_request",
            "invalid_client",
            "invalid_grant",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
        ] {
            for body in [format!(r#"{{"error":"{code}"}}"#), format!("error={code}")] {
                let mut s = Script::happy().answer(TOKEN_URL, status, &body);
                assert_eq!(
                    run(&l, &mut s),
                    LoginStep::BadCredential,
                    "{status}: {body}"
                );
                assert_eq!(s.targets(), [TOKEN_URL]);
            }
        }
        for body in [
            r#"{"error":"server_error"}"#,
            r#"{"error":"temporarily_unavailable"}"#,
            r#"{"error":""}"#,
            r#"{"error":"unknown"}"#,
            r#"{"error":42}"#,
            r#"{"error":null}"#,
            r#"{"error":[]}"#,
            "error=server_error",
            "error=",
        ] {
            let mut s = Script::happy().answer(TOKEN_URL, status, body);
            assert_eq!(run(&l, &mut s), OUTAGE, "{status}: {body}");
            assert_eq!(s.targets(), [TOKEN_URL]);
        }
    }
}

#[test]
fn a_token_hop_403_preserves_the_rate_limit_hint() {
    let l = login();
    for (fields, expected) in [
        (
            ReplyFields {
                retry_after: Some("60".into()),
                ..ReplyFields::default()
            },
            Some(60),
        ),
        (
            ReplyFields {
                ratelimit_remaining: Some("0".into()),
                ratelimit_reset: Some("1".into()),
                ..ReplyFields::default()
            },
            Some(0),
        ),
        (
            ReplyFields {
                ratelimit_remaining: Some("0".into()),
                ..ReplyFields::default()
            },
            None,
        ),
    ] {
        let mut s = Script::happy().answer_with(TOKEN_URL, 403, fields, r#"{"message":"limited"}"#);
        assert_eq!(
            run(&l, &mut s),
            LoginStep::Outage {
                retry_after: expected
            }
        );
        assert_eq!(s.targets(), [TOKEN_URL]);
    }
}

#[test]
fn separate_link_field_lines_preserve_the_next_org_page() {
    let fields = ReplyFields::kept([
        (
            &b"Link"[..],
            &b"<https://api.github.com/user/orgs?page=5>; rel=\"last\""[..],
        ),
        (
            &b"link"[..],
            &b"<https://api.github.com/user/orgs?page=2>; rel=\"next\""[..],
        ),
    ]);
    let page2 = "https://api.github.com/user/orgs?page=2";
    let mut s = Script::happy()
        .answer_with(ORGS_URL, 200, fields, r#"[{"login":"first"}]"#)
        .answer(page2, 200, r#"[{"login":"second"}]"#);
    let p = identity(run(&login(), &mut s));
    assert!(p.roles.contains(&"github:org/first".to_string()));
    assert!(p.roles.contains(&"github:org/second".to_string()));
    assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL, page2]);
}

#[test]
fn a_json_array_cannot_supply_an_access_token() {
    assert!(parse_access_token(r#"["gho_array_token"]"#).is_none());
    assert!(parse_access_token(r#"["gho_array_token",null]"#).is_none());
}

#[test]
fn positional_json_arrays_are_neither_access_tokens_nor_id_token_envelopes() {
    let l = login();
    for target in [TOKEN_URL, USER_URL, ORGS_URL] {
        for status in [200, 503] {
            let mut s = Script::happy().answer(target, status, r#"["acme"]"#);
            assert_eq!(run(&l, &mut s), OUTAGE, "{target} {status}");
            let last = [TOKEN_URL, USER_URL, ORGS_URL]
                .iter()
                .position(|v| *v == target)
                .unwrap();
            assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL][..=last]);
        }
    }
}

#[test]
fn a_present_id_token_must_be_readable_and_nonce_bound_in_json_or_form() {
    let l = login();
    for shape in ["null", "false", "42", "{}", "[]"] {
        let body = format!(r#"{{"access_token":"{TOKEN}","id_token":{shape}}}"#);
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(run(&l, &mut s), LoginStep::SecurityCheckFailed, "{shape}");
        assert_eq!(s.targets(), [TOKEN_URL]);
    }
    let wrong = id_token(r#"{"nonce":"another-login"}"#);
    let right = id_token(&serde_json::json!({"nonce": NONCE}).to_string());
    for encoded in [
        format!("id_token={wrong}"),
        format!("id%5Ftoken={wrong}"),
        "id_token=".into(),
        "id_token=%FF".into(),
        "id_token".into(),
        format!("id_token={right}&id_token={wrong}"),
    ] {
        let body = format!("access_token={TOKEN}&{encoded}");
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(run(&l, &mut s), LoginStep::SecurityCheckFailed, "{encoded}");
        assert_eq!(s.targets(), [TOKEN_URL]);
    }
    let duplicate =
        format!(r#"{{"access_token":"{TOKEN}","id_token":"{right}","id_token":"{wrong}"}}"#);
    let mut s = Script::happy().answer(TOKEN_URL, 200, &duplicate);
    assert_eq!(run(&l, &mut s), LoginStep::SecurityCheckFailed);
    for body in [
        format!("access_token={TOKEN}&id_token={right}"),
        format!("access_token={TOKEN}&id%5ftoken={right}"),
        format!(r#"{{"access_token":"{TOKEN}","id_token":"{right}"}}"#),
    ] {
        let mut s = Script::happy().answer(TOKEN_URL, 200, &body);
        assert_eq!(identity(run(&l, &mut s)).id, "github:octocat");
        assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
    }
}

fn enterprise_login() -> GithubLogin {
    let mut settings: Value = serde_json::from_str(SETTINGS).unwrap();
    settings["api_base"] = Value::String("https://ghe.corp/api/v3".into());
    GithubLogin::open(&settings.to_string(), Some(SECRET)).unwrap()
}

const ENTERPRISE_USER: &str = "https://ghe.corp/api/v3/user";
const ENTERPRISE_ORGS: &str = "https://ghe.corp/api/v3/user/orgs?per_page=100";

fn enterprise_script(next: &str) -> Script {
    Script::new()
        .answer(TOKEN_URL, 200, &format!(r#"{{"access_token":"{TOKEN}"}}"#))
        .answer(ENTERPRISE_USER, 200, r#"{"login":"octocat","id":1}"#)
        .answer_with(
            ENTERPRISE_ORGS,
            200,
            ReplyFields {
                link: Some(format!("<{next}>; rel=\"next\"")),
                ..ReplyFields::default()
            },
            r#"[{"login":"first"}]"#,
        )
}

#[test]
fn org_next_links_normalize_default_ports_and_resolve_against_each_current_page() {
    let l = enterprise_login();
    let page2 = "https://ghe.corp/api/v3/user/pages/two?page=2";
    let page3 = "https://ghe.corp/api/v3/user/pages/two?page=3";
    for next in [
        "https://ghe.corp:443/api/v3/user/pages/two?page=2",
        "/api/v3/user/pages/two?page=2",
        "pages/two?page=2",
        "//ghe.corp:443/api/v3/user/pages/two?page=2",
    ] {
        let mut s = enterprise_script(next)
            .answer_with(
                page2,
                200,
                ReplyFields {
                    link: Some("<?page=3>; rel=\"next\"".into()),
                    ..ReplyFields::default()
                },
                r#"[{"login":"second"}]"#,
            )
            .answer(page3, 200, r#"[{"login":"third"}]"#);
        let p = identity(run(&l, &mut s));
        for org in ["first", "second", "third"] {
            assert!(
                p.roles.contains(&format!("github:org/{org}")),
                "{next}: {org}"
            );
        }
        assert_eq!(
            s.targets(),
            [TOKEN_URL, ENTERPRISE_USER, ENTERPRISE_ORGS, page2, page3]
        );
    }
    for next in [
        "//other.corp/orgs",
        "https://ghe.corp:444/orgs",
        "http://ghe.corp/orgs",
        "https://user@ghe.corp/orgs",
        "https://user:password@ghe.corp/orgs",
    ] {
        let mut s = enterprise_script(next);
        assert_eq!(run(&l, &mut s), OUTAGE, "{next}");
        assert_eq!(s.targets(), [TOKEN_URL, ENTERPRISE_USER, ENTERPRISE_ORGS]);
    }
}

#[test]
fn consumed_token_response_is_gone_while_the_next_hop_is_pending() {
    let l = login();
    let mut s = Script::happy();
    s.pend_first = true;
    let mut f = flow(&l);
    assert_eq!(l.drive(&mut f, &mut s), LoginStep::Pending, "token hop");
    assert_eq!(l.drive(&mut f, &mut s), LoginStep::Pending, "user hop");
    assert_eq!(s.targets().last(), Some(&USER_URL));
    assert!(
        f.req.answer.is_none(),
        "the consumed plaintext token response must be wiped before parking /user"
    );
    assert!(plain(s.issued.last().unwrap())
        .iter()
        .any(|(n, v)| n == "authorization" && v == &format!("Bearer {TOKEN}")));
    assert_eq!(l.drive(&mut f, &mut s), LoginStep::Pending, "org hop");
    assert!(
        f.req.answer.is_none(),
        "the consumed profile is not retained either"
    );
    assert_eq!(identity(l.drive(&mut f, &mut s)).id, "github:octocat");
}

#[test]
fn malformed_org_entries_refuse_the_whole_reply_at_the_org_hop() {
    let l = login();
    for body in [
        "[1,2]",
        "[null]",
        r#"[{"message":"foreign"}]"#,
        r#"[{"login":""}]"#,
        r#"[{"login":42}]"#,
        r#"[{"login":"valid"},{"message":"foreign"}]"#,
    ] {
        let mut s = Script::happy().answer(ORGS_URL, 200, body);
        assert_eq!(run(&l, &mut s), OUTAGE, "{body}");
        assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
    }
    let mut s = Script::happy().answer(ORGS_URL, 200, "[]");
    assert_eq!(identity(run(&l, &mut s)).roles, ["github:id/1"]);
    assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
}
