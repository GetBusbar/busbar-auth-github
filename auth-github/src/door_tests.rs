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
    assert_eq!(verdict(&LoginStep::Outage), LOGIN_OUTAGE);
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

/// RED: a `ca_cert_pem` has no delivery channel (the one outbound need carries no CA), so a set
/// one is refused, named, rather than accepted and silently ignored.
#[test]
fn a_set_ca_cert_pem_is_refused_by_name() {
    let settings = WRITTEN.replace(
        "\"client_id\"",
        "\"ca_cert_pem\": \"-----BEGIN CERTIFICATE-----\", \"client_id\"",
    );
    let r = refusal(&settings);
    assert_eq!(r.outcome(), Outcome::Failed);
    assert_eq!(
        r.text(),
        Some("github ca_cert_pem is not yet supported; omit it or use a system-trusted cert")
    );
    // Written as null it is not set.
    let null = WRITTEN.replace("\"client_id\"", "\"ca_cert_pem\": null, \"client_id\"");
    assert!(<Github as Life>::validate(null.as_bytes()).is_ok());
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
                "settings: `{key}` must be written out: the hop allowlist is built only from URLs in the settings"
            ))
        );
    }
    // authorize_base is a browser redirect, not a hop: it may stay at its default.
    let settings = WRITTEN.replace("\"authorize_base\": \"https://github.com\",", "");
    assert!(<Github as Life>::validate(settings.as_bytes()).is_ok());
}

/// RED: a mistyped value is never echoed into the refusal (it may be a secret pasted into the
/// wrong key); a refusal naming a KEY keeps serde's text.
#[test]
fn a_mistyped_value_is_not_echoed_in_the_refusal() {
    let settings = WRITTEN.replace("\"Iv1.client\"", "12345678");
    let r = refusal(&settings);
    let text = r.text().unwrap_or_default();
    assert!(!text.contains("12345678"), "{text}");
    assert!(text.starts_with("invalid github plugin config: "), "{text}");
    assert!(text.contains("line "), "{text}");
    // Malformed JSON: no fragment of the input either.
    let r = refusal(r#"{"client_id": "x", "api_base": SECRETVALUE}"#);
    assert!(!r.text().unwrap_or_default().contains("SECRETVALUE"));
    // A missing or unknown key keeps the decoder's text: it names the key, never a value.
    assert!(
        refusal(r#"{"api_base":"https://a.example","token_base":"https://a.example"}"#)
            .text()
            .unwrap_or_default()
            .starts_with("invalid github plugin config: missing field `client_id`")
    );
    assert!(
        refusal(&WRITTEN.replace("\"client_id\"", "\"bogus\": 1, \"client_id\""))
            .text()
            .unwrap_or_default()
            .starts_with("invalid github plugin config: unknown field `bogus`")
    );
}
