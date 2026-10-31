// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn security_check_failed_is_its_own_verdict() {
    assert_eq!(
        verdict(&LoginStep::SecurityCheckFailed),
        LOGIN_SECURITY_CHECK_FAILED
    );
}

#[test]
fn other_steps_keep_their_verdicts() {
    assert_eq!(verdict(&LoginStep::BadCredential), LOGIN_BAD_CREDENTIAL);
    assert_eq!(
        verdict(&LoginStep::Outage { retry_after: None }),
        LOGIN_OUTAGE
    );
}

fn who(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        name: None,
        roles: Vec::new(),
        ttl_secs: None,
    }
}

fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: n,
        generation: 1,
    }
}

#[test]
fn a_full_answered_map_evicts_only_the_oldest() {
    let t0 = Instant::now();
    let at = |n: u32| t0 + std::time::Duration::from_millis(u64::from(n));
    let mut map = Answered::new();
    for n in 1..=3 {
        keep(&mut map, 3, at(n), ticket(n), who(&format!("u{n}")));
    }
    keep(&mut map, 3, at(4), ticket(4), who("u4"));
    assert_eq!(map.len(), 3);
    assert!(!map.contains_key(&ticket(1)), "the oldest is evicted");
    for n in 2..=4 {
        assert!(map.contains_key(&ticket(n)), "ticket {n} is kept");
    }
}

#[test]
fn a_ticket_kept_again_does_not_evict() {
    let t0 = Instant::now();
    let mut map = Answered::new();
    keep(&mut map, 2, t0, ticket(1), who("a"));
    keep(&mut map, 2, t0, ticket(2), who("b"));
    keep(&mut map, 2, t0, ticket(2), who("b2"));
    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&ticket(1)));
}

/// Every base written out, as a usable config must be.
const WRITTEN: &str = r#"{
    "client_id": "Iv1.client",
    "api_base": "https://api.github.com",
    "authorize_base": "https://github.com",
    "token_base": "https://github.com"
}"#;

fn refusal(settings: &str) -> Refusal {
    <Github as Life>::validate(settings.as_bytes()).expect_err("validate refuses")
}

#[test]
fn the_written_out_settings_validate() {
    assert!(<Github as Life>::validate(WRITTEN.as_bytes()).is_ok());
}

const PEM: &str = "-----BEGIN CERTIFICATE-----\\nY29uZm9ybWFuY2U=\\n-----END CERTIFICATE-----\\n";

/// RED: a `ca_cert_pem` (a GHES behind an internal CA) anchors every hop: the login goes out on the
/// need that trusts it (`trust_from` = `settings.ca_cert_pem`), beside the public roots. Without
/// one (absent or null) it goes out on the public-roots need.
#[test]
fn a_set_ca_cert_pem_anchors_the_hops() {
    let anchored = WRITTEN.replace(
        "\"client_id\"",
        &format!("\"ca_cert_pem\": \"{PEM}\", \"client_id\""),
    );
    assert!(<Github as Life>::validate(anchored.as_bytes()).is_ok());
    let login = GithubLogin::open(&anchored, None).expect("opens");
    assert_eq!(need_of(&login), NEED_ANCHORED);
    assert!(!NEEDS[NEED_ANCHORED as usize].trust_from.is_absent());
    assert!(NEEDS[NEED_PUBLIC as usize].trust_from.is_absent());
    for public in [
        WRITTEN.to_string(),
        WRITTEN.replace("\"client_id\"", "\"ca_cert_pem\": null, \"client_id\""),
    ] {
        let login = GithubLogin::open(&public, None).expect("opens");
        assert_eq!(need_of(&login), NEED_PUBLIC, "{public}");
    }
}

/// RED L5: a `ca_cert_pem` written but blank names no certificate: refused at validate and open,
/// by name, never accepted and ignored (the operator meant to anchor the hops).
#[test]
fn red_l5_a_blank_ca_cert_pem_is_refused_by_name() {
    for blank in ["", "   ", "\\n\\t "] {
        let settings = WRITTEN.replace(
            "\"client_id\"",
            &format!("\"ca_cert_pem\": \"{blank}\", \"client_id\""),
        );
        let r = refusal(&settings);
        assert_eq!(r.outcome(), Outcome::Failed, "{blank:?}");
        assert_eq!(
            r.text(),
            Some("settings.ca_cert_pem: blank: omit it, or give a PEM certificate"),
            "{blank:?}"
        );
        assert!(GithubLogin::open(&settings, None).is_err(), "{blank:?}");
    }
}

/// RED: a `ca_cert_pem` that is not a PEM certificate is refused, named, at validate (as `open`
/// refuses it), never handed to the host to fail at the first login.
#[test]
fn a_ca_cert_pem_that_is_not_a_certificate_is_refused_by_name() {
    let settings = WRITTEN.replace(
        "\"client_id\"",
        "\"ca_cert_pem\": \"not a certificate\", \"client_id\"",
    );
    let r = refusal(&settings);
    assert_eq!(r.outcome(), Outcome::Failed);
    assert_eq!(
        r.text(),
        Some("settings.ca_cert_pem: not a PEM certificate (no -----BEGIN CERTIFICATE----- line)")
    );
}

/// RED: a base left at its default is not on the hop allowlist (built only from URLs written in
/// the settings), so every hop to it would be refused: validate refuses it, explained.
#[test]
fn a_hop_base_left_at_its_default_is_refused_explained() {
    for key in ["token_base", "api_base"] {
        let settings: serde_json::Value = serde_json::from_str(WRITTEN).unwrap();
        let mut settings = settings.as_object().unwrap().clone();
        settings.remove(key);
        let r = refusal(&serde_json::Value::Object(settings).to_string());
        assert_eq!(r.outcome(), Outcome::Failed);
        assert_eq!(
            r.text().map(str::to_string),
            Some(format!(
                "settings.{key}: must be written out: the hop allowlist is built only from URLs in the settings"
            ))
        );
    }
    // authorize_base is a browser redirect, not a hop: it may stay at its default.
    let settings = WRITTEN.replace("\"authorize_base\": \"https://github.com\",", "");
    assert!(<Github as Life>::validate(settings.as_bytes()).is_ok());
}

/// RED: a mistyped value is never echoed into the refusal (it may be a secret pasted into the
/// wrong key); every line is the contract's instance-relative `settings.<path>: <reason>`.
#[test]
fn a_mistyped_value_is_not_echoed_in_the_refusal() {
    let settings = WRITTEN.replace("\"Iv1.client\"", "12345678");
    let r = refusal(&settings);
    let text = r.text().unwrap_or_default();
    assert!(!text.contains("12345678"), "{text}");
    assert_eq!(
        text,
        "settings.client_id: invalid type: integer `***`, expected a string"
    );
    // Malformed JSON: no fragment of the input either.
    let r = refusal(r#"{"client_id": "x", "api_base": SECRETVALUE}"#);
    let text = r.text().unwrap_or_default();
    assert!(!text.contains("SECRETVALUE"), "{text}");
    assert!(
        text.starts_with("settings: not a JSON document (line 1"),
        "{text}"
    );
    // A missing or unknown key keeps the decoder's text: it names the key, never a value.
    assert!(
        refusal(r#"{"api_base":"https://a.example","token_base":"https://a.example"}"#)
            .text()
            .unwrap_or_default()
            .starts_with("settings: missing field `client_id`")
    );
    assert!(
        refusal(&WRITTEN.replace("\"client_id\"", "\"bogus\": 1, \"client_id\""))
            .text()
            .unwrap_or_default()
            .starts_with("settings: unknown field `bogus`")
    );
}

/// RED: a client secret that is not UTF-8 is refused in the kind's secrets line, by name.
#[test]
fn a_non_utf8_client_secret_is_refused_by_name() {
    let r = login_from(WRITTEN.as_bytes(), &[&[0xff, 0xfe]]).expect_err("refused");
    assert_eq!(r.outcome(), Outcome::Failed);
    assert_eq!(r.text(), Some("secrets: `client_secret` is not UTF-8"));
    // Settings bytes that are not UTF-8: named, no byte quoted.
    let r = login_from(&[b'{', 0xff, b'}'], &[]).expect_err("refused");
    assert_eq!(r.text(), Some("settings: not UTF-8"));
}

/// RED: an empty required string (the client id, a base URL) is refused at validate, named, as
/// `open` refuses it: an empty client id cannot sign in, and an empty or host-less base would
/// fail every hop.
#[test]
fn an_empty_client_id_or_base_is_refused_by_name() {
    for (key, value, line) in [
        ("client_id", "", "settings.client_id: empty"),
        (
            "token_base",
            "",
            "settings.token_base: not an http(s) URL with a host",
        ),
        (
            "api_base",
            "",
            "settings.api_base: not an http(s) URL with a host",
        ),
        (
            "authorize_base",
            "",
            "settings.authorize_base: not an http(s) URL with a host",
        ),
        (
            "api_base",
            "api.github.com",
            "settings.api_base: not an http(s) URL with a host",
        ),
        (
            "token_base",
            "ftp://github.com",
            "settings.token_base: not an http(s) URL with a host",
        ),
    ] {
        let mut settings: serde_json::Value = serde_json::from_str(WRITTEN).unwrap();
        settings[key] = serde_json::Value::String(value.to_string());
        let r = refusal(&settings.to_string());
        assert_eq!(r.outcome(), Outcome::Failed);
        assert_eq!(r.text(), Some(line), "{key}={value:?}");
    }
}

/// RED L2: a flow parked before `refresh()` resumes under the login it began with, to its end (its
/// client secret, its bases, its allowlist), never under the refreshed one.
#[test]
fn red_l2_a_parked_flow_resumes_under_the_login_it_began_with() {
    let g = <Github as Life>::open(WRITTEN.as_bytes(), &[b"secret-before"], 1).expect("opens");
    let begun = g.login();
    let parked = Parked {
        flow: begun.start(
            Some("the-code"),
            Some("https://node.example/auth/token"),
            Some("the-verifier"),
            None,
        ),
        login: begun.clone(),
        wire: None,
        base: 0,
    };
    let rotated = WRITTEN.replace("https://api.github.com", "https://ghe.example/api/v3");
    <Github as Life>::refresh(&g, rotated.as_bytes(), &[b"secret-after"], 2).expect("refreshes");
    assert_eq!(g.login().config().api_base, "https://ghe.example/api/v3");
    let resumed = driving(&g, &parked);
    assert!(
        Arc::ptr_eq(&resumed, &begun),
        "the flow keeps its own login"
    );
    assert_eq!(resumed.config().api_base, "https://api.github.com");
    // A flow begun after the refresh is the refreshed login's.
    let after = Parked {
        flow: g.login().start(None, None, None, None),
        login: g.login(),
        wire: None,
        base: 0,
    };
    assert!(Arc::ptr_eq(&driving(&g, &after), &g.login()));
}
