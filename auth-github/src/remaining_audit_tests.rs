// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn reset_hints_handle_past_missing_and_full_width_values() {
    let fields = |reset: Option<&str>| ReplyFields {
        ratelimit_remaining: Some("0".into()),
        ratelimit_reset: reset.map(str::to_string),
        ..ReplyFields::default()
    };
    assert_eq!(retry_hint(&fields(Some("99")), 100), Some(0));
    assert_eq!(retry_hint(&fields(Some("100")), 100), Some(0));
    assert_eq!(retry_hint(&fields(None), 100), None);
    assert_eq!(
        retry_hint(&fields(Some(&u64::MAX.to_string())), 100),
        Some(u64::MAX - 100)
    );
    let l = login();
    for (field, expected) in [(fields(Some("1")), Some(0)), (fields(None), None)] {
        let mut s = Script::happy().answer_with(USER_URL, 403, field, "{}");
        assert_eq!(
            run(&l, &mut s),
            LoginStep::Outage {
                retry_after: expected
            }
        );
        assert_eq!(s.targets(), [TOKEN_URL, USER_URL]);
    }
    let mut s = Script::happy().answer_with(
        TOKEN_URL,
        429,
        ReplyFields {
            retry_after: Some(u64::MAX.to_string()),
            ..ReplyFields::default()
        },
        "{}",
    );
    assert_eq!(
        run(&l, &mut s),
        LoginStep::Outage {
            retry_after: Some(u64::MAX)
        }
    );
    assert_eq!(s.targets(), [TOKEN_URL]);
}

#[test]
fn an_oauth_invalid_client_decline_warns_without_exposing_credentials() {
    let l = login();
    for status in [400, 401] {
        for error in ["invalid_client", "unauthorized_client"] {
            let mut s =
                Script::happy().answer(TOKEN_URL, status, &format!(r#"{{"error":"{error}"}}"#));
            let cap = busbar_test_kit::warn_capture::WarnCapture::default();
            let result = tracing::subscriber::with_default(cap.clone(), || run(&l, &mut s));
            assert_eq!(result, LoginStep::BadCredential);
            assert_eq!(s.targets(), [TOKEN_URL]);
            assert!(cap.contains(error) && cap.contains("check client_id and client_secret"));
            for secret in [SECRET, TOKEN, "the-code", "the-verifier"] {
                assert!(!cap.contains(secret));
            }
        }
    }
}

#[test]
fn a_real_null_profile_name_falls_back_to_the_login() {
    let mut s = Script::happy().answer(USER_URL, 200, r#"{"login":"octocat","id":1,"name":null}"#);
    let p = identity(run(&login(), &mut s));
    assert_eq!(p.name.as_deref(), Some("octocat"));
    assert_eq!(p.id, "github:octocat");
    assert_eq!(s.targets(), [TOKEN_URL, USER_URL, ORGS_URL]);
}
