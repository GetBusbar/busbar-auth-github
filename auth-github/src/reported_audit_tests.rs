// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Remaining reported input boundaries, driven through the existing login API.

use super::*;

#[test]
fn display_controls_fall_back_to_login_without_changing_identity_or_roles() {
    for control in [
        '\u{00ad}',
        '\u{0600}',
        '\u{0605}',
        '\u{06dd}',
        '\u{070f}',
        '\u{0890}',
        '\u{0891}',
        '\u{08e2}',
        '\u{180e}',
        '\u{fff9}',
        '\u{fffb}',
        '\u{110bd}',
        '\u{110cd}',
        '\u{13430}',
        '\u{1343f}',
        '\u{1bca0}',
        '\u{1bca3}',
        '\u{1d173}',
        '\u{1d17a}',
        '\u{e0001}',
        '\u{e0020}',
        '\u{e007f}',
        '\u{061c}',
        '\u{200b}',
        '\u{200c}',
        '\u{200d}',
        '\u{200e}',
        '\u{200f}',
        '\u{2028}',
        '\u{2029}',
        '\u{202a}',
        '\u{202b}',
        '\u{202c}',
        '\u{202d}',
        '\u{202e}',
        '\u{2060}',
        '\u{2066}',
        '\u{2067}',
        '\u{2068}',
        '\u{2069}',
        '\u{feff}',
    ] {
        let body = serde_json::json!({
            "login": "octocat", "id": 1, "name": format!("Octo{control}Admin")
        })
        .to_string();
        let mut script = Script::happy().answer(USER_URL, 200, &body);
        let p = identity(run(&login(), &mut script));
        assert_eq!(p.name.as_deref(), Some("octocat"), "{control:?}");
        assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
        assert_eq!(
            p.roles,
            [
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1",
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1",
                "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2"
            ]
        );
        assert_eq!(script.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
    }
    for name in ["Zoë 李娜", "O'Connor", "علي", "שָׁלוֹם", "e\u{301}"] {
        let body = serde_json::json!({"login":"octocat", "id":1, "name":name}).to_string();
        let mut script = Script::happy().answer(USER_URL, 200, &body);
        assert_eq!(
            identity(run(&login(), &mut script)).name.as_deref(),
            Some(name)
        );
        assert_eq!(script.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
    }
}

#[test]
fn actual_rate_limit_uses_the_first_valid_trimmed_case_insensitive_header() {
    let fields = ReplyFields::kept([
        (&b"ReTrY-AfTeR"[..], &b"\xff"[..]),
        (&b"Retry-After"[..], &b" 120 \t"[..]),
        (&b"retry-after"[..], &b"999"[..]),
    ]);
    let mut script = Script::happy().answer_with(TOKEN_URL, 429, fields, "{}");
    assert_eq!(
        run(&login(), &mut script),
        LoginStep::Outage {
            retry_after: Some(120)
        }
    );
    assert_eq!(script.targets(), [TOKEN_URL]);
}

#[test]
fn non_utf8_replies_fail_closed_without_panicking_or_exposing_the_body() {
    for target in [TOKEN_URL, USER_URL, ORGS_URL] {
        let mut script = Script::happy();
        script.answers.insert(
            target.into(),
            Fetched::Ready(HopResponse {
                status: 200,
                fields: ReplyFields::default(),
                body: b"credential-canary-\xff".to_vec().into(),
            }),
        );
        let cap = crate::diagnostics::GithubDiagnostics::default();
        let result =
            tracing::subscriber::with_default(cap.subscriber(), || run(&login(), &mut script));
        assert_eq!(result, OUTAGE, "{target}");
        assert_eq!(script.targets().last().copied(), Some(target));
        assert!(!cap.contains("credential-canary"), "{:?}", cap.messages());
    }
}

#[test]
fn foreign_json_arrays_cannot_smuggle_a_form_credential_error() {
    for status in [400, 401] {
        let mut script = Script::happy().answer(
            TOKEN_URL,
            status,
            r#"[{"description":"x&error=invalid_grant&unused=x"}]"#,
        );
        assert_eq!(run(&login(), &mut script), OUTAGE);
        assert_eq!(script.targets(), [TOKEN_URL]);
    }
}

#[test]
fn malformed_percent_escapes_in_form_tokens_are_preserved_on_the_actual_bearer() {
    for suffix in ["%", "%4", "%GG", "%FF", "%00"] {
        let encoded = format!("access_token=token{suffix}");
        let mut script = Script::happy().answer(TOKEN_URL, 200, &encoded);
        if suffix == "%00" {
            assert_eq!(run(&login(), &mut script), OUTAGE);
            assert_eq!(script.targets(), [TOKEN_URL]);
        } else {
            let p = identity(run(&login(), &mut script));
            assert_eq!(p.id, "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1");
            let expected = if suffix == "%FF" {
                b"authorization: Bearer token\xff\r\n".to_vec()
            } else {
                format!("authorization: Bearer token{suffix}\r\n").into_bytes()
            };
            let wire = script.issued[1].wire(MAX_HOP_REPLY_BYTES).expect("frames");
            assert!(chip::framed_head(&wire)
                .windows(expected.len())
                .any(|window| window == expected));
        }
    }
}

#[test]
fn trailing_operator_slashes_do_not_change_any_login_endpoint() {
    let settings = SETTINGS
        .replace("https://api.github.com\"", "https://api.github.com///\"")
        .replace("https://github.com\"", "https://github.com///\"");
    let login = GithubLogin::open(&settings, Some(SECRET)).expect("opens");
    assert!(login
        .begin_login("https://node.example/auth/token", "state", "challenge", &[])
        .starts_with("https://github.com/login/oauth/authorize?"));
    let mut script = Script::happy();
    assert_eq!(
        identity(run(&login, &mut script)).id,
        "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:user:1"
    );
    assert_eq!(script.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
}

#[test]
fn uppercase_same_origin_pagination_keeps_the_bearer_and_all_roles() {
    let next = "https://api.github.com/user/orgs?page=2";
    let mut script = Script::happy()
        .answer_with(
            ORGS_URL,
            200,
            ReplyFields {
                link: Some("<HTTPS://API.GITHUB.COM:443/user/orgs?page=2>; rel=\"next\"".into()),
                ..ReplyFields::default()
            },
            r#"[{"login":"acme","id":1}]"#,
        )
        .answer(next, 200, r#"[{"login":"widgets","id":2}]"#);
    let p = identity(run(&login(), &mut script));
    assert!(p
        .roles
        .contains(&"github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:1".into()));
    assert!(p
        .roles
        .contains(&"github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:2".into()));
    assert_eq!(script.targets(), [TOKEN_URL, USER_URL, ORGS_URL, next]);
    assert!(plain(&script.issued[3]).contains(&("authorization".into(), format!("Bearer {TOKEN}"))));
}

#[test]
fn a_rendered_secret_only_form_has_its_content_type_and_sealed_value() {
    let hop = LoginHop {
        method: "POST".into(),
        url: TOKEN_URL.into(),
        form: Vec::new(),
        secret_form_field: Some("client_secret".into()),
        headers: Vec::new(),
    };
    let request = login().render(&hop, None).expect("renders");
    assert_eq!(body_text(&request), format!("client_secret={SECRET}"));
    assert!(plain(&request).contains(&(
        "content-type".into(),
        "application/x-www-form-urlencoded".into()
    )));
    assert!(plain(&request).contains(&("accept".into(), "*/*".into())));
}

#[test]
fn malformed_hop_methods_are_explained_refusals_without_rendering_secrets() {
    for method in ["", "GE T", "GET\r\nX: injected"] {
        let hop = LoginHop {
            method: method.into(),
            url: TOKEN_URL.into(),
            form: Vec::new(),
            secret_form_field: Some("client_secret".into()),
            headers: Vec::new(),
        };
        let cap = crate::diagnostics::GithubDiagnostics::default();
        let result =
            tracing::subscriber::with_default(cap.subscriber(), || login().render(&hop, None));
        assert_eq!(result, Err(Refused));
        assert!(cap.contains("method"), "{:?}", cap.messages());
        assert!(!cap.contains(SECRET) && !cap.contains("injected"));
    }
}
