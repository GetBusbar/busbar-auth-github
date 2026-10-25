// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hop guard keeps 1.5.5's answers (vectors from busbar v1.5.5's own guard tests).

use super::*;
use serde_json::json;

fn allowed(hosts: &[&str]) -> HashSet<String> {
    hosts.iter().map(|h| h.to_string()).collect()
}

#[test]
fn the_allowlist_is_every_operator_url_host_lowercased() {
    let settings = json!({
        "client_id": "https://not-a-base.example/looks-like-a-url",
        "api_base": "https://GHE.corp.example/api/v3",
        "token_base": "https://ghe.corp.example:8443",
        "scopes": ["read:org", "http://scoped.example"],
        "fetch_orgs": true,
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----",
    });
    let hosts = collect_allowed_hosts(&settings);
    assert_eq!(
        hosts,
        allowed(&["not-a-base.example", "ghe.corp.example", "scoped.example"])
    );
    assert!(collect_allowed_hosts(&json!({"client_id": "x"})).is_empty());
}

#[test]
fn an_allow_listed_https_host_passes() {
    let a = allowed(&["api.github.com"]);
    assert!(vet_hop_url("https://api.github.com/user", &a).is_ok());
    assert!(vet_hop_url("HTTPS://API.GitHub.com/user", &a).is_ok());
}

#[test]
fn a_host_the_operator_did_not_write_is_refused() {
    let a = allowed(&["api.github.com"]);
    assert!(vet_hop_url("https://evil.example/user", &a).is_err());
    // userinfo does not smuggle a host past the list
    assert!(vet_hop_url("https://api.github.com@evil.example/", &a).is_err());
    // a backslash ends the authority, as the http stack reads it
    assert!(vet_hop_url("https://evil.example\\@api.github.com/", &a).is_err());
    assert!(vet_hop_url("not a url", &a).is_err());
}

#[test]
fn plaintext_is_only_for_private_or_loopback_hosts() {
    assert!(vet_hop_url("http://github.com/x", &allowed(&["github.com"])).is_err());
    assert!(vet_hop_url("http://10.1.2.3/x", &allowed(&["10.1.2.3"])).is_ok());
    assert!(vet_hop_url("http://localhost:8080/x", &allowed(&["localhost"])).is_ok());
    assert!(vet_hop_url("ftp://10.1.2.3/x", &allowed(&["10.1.2.3"])).is_err());
}

#[test]
fn a_metadata_host_is_refused_even_when_allow_listed() {
    for (url, host) in [
        ("http://169.254.169.254/latest", "169.254.169.254"),
        (
            "https://metadata.google.internal/",
            "metadata.google.internal",
        ),
        ("http://2852039166/", "2852039166"),
        ("http://169%2E254%2E169%2E254/", "169.254.169.254"),
        ("https://[fd00:ec2::254]/", "fd00:ec2::254"),
        ("https://168.63.129.16/", "168.63.129.16"),
    ] {
        assert!(metadata_host(url), "{url}");
        assert!(vet_hop_url(url, &allowed(&[host])).is_err(), "{url}");
    }
    assert!(!metadata_host("https://api.github.com/"));
    assert!(!metadata_host("http://10.0.0.1/"));
}

#[test]
fn host_normalisation_matches_1_5_5() {
    let h = |u: &str| extract_normalized_host(u);
    assert_eq!(
        h("https://Api.GitHub.com./user").as_deref(),
        Some("Api.GitHub.com")
    );
    assert_eq!(
        h("https://u:p@host.example:443/x").as_deref(),
        Some("host.example")
    );
    assert_eq!(h("https://[::1]:8443/").as_deref(), Some("::1"));
    assert_eq!(
        h("https://169.254.169\t.254/").as_deref(),
        Some("169.254.169.254")
    );
    assert_eq!(h("https:///path"), None);
    assert_eq!(h("gopher://x"), None);
}

#[test]
fn headers_are_sanitised_as_1_5_5_did() {
    assert_eq!(
        sanitize_hop_header("User-Agent", "busbar"),
        Ok((
            "user-agent".to_string(),
            zeroize::Zeroizing::new("busbar".to_string())
        ))
    );
    for (n, v) in [
        ("Authorization", "Bearer a\r\nX: y"),
        ("X\nY", "v"),
        ("Host", "evil"),
        ("content-length", "0"),
        ("Transfer-Encoding", "chunked"),
        ("bad name", "v"),
        ("", "v"),
        ("X", "del\u{7f}"),
    ] {
        assert!(sanitize_hop_header(n, v).is_err(), "{n:?}: {v:?}");
    }
    // A tab and non-ASCII bytes are values the http stack accepted.
    assert!(sanitize_hop_header("X", "a\tb é").is_ok());
}

#[test]
fn private_or_loopback_matches_1_5_5() {
    for h in [
        "localhost",
        "a.localhost",
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "127.1",
    ] {
        assert!(host_is_private_or_loopback(h), "{h}");
    }
    for h in ["github.com", "8.8.8.8", "2001:4860::1"] {
        assert!(!host_is_private_or_loopback(h), "{h}");
    }
}

#[test]
fn private_or_loopback_covers_ipv4_mapped_and_link_local_v6() {
    for h in ["::ffff:10.0.0.1", "::ffff:127.0.0.1", "fe80::1"] {
        assert!(host_is_private_or_loopback(h), "{h}");
    }
    assert!(!host_is_private_or_loopback("::ffff:8.8.8.8"));
}

#[test]
fn metadata_host_covers_every_provider_constant_and_name() {
    for url in [
        "http://100.100.100.200/",
        "http://192.0.0.192/",
        "http://168.63.129.16/",
        "http://metadata.internal/",
        "http://metadata.tencentyun.com/",
        "http://metadata.platformequinix.com/",
        "http://instance-data/",
        "http://instance-data.ec2.internal/",
        "http://INSTANCE-DATA.EC2.INTERNAL/",
    ] {
        assert!(metadata_host(url), "{url}");
    }
    assert!(!metadata_host("http://metadata.example.com/"));
    assert!(!metadata_host("http://100.100.100.201/"));
}

mod logging {
    use super::*;
    use busbar_contract::testkit::WarnCapture;

    #[test]
    fn a_refused_header_logs_its_name_never_its_value() {
        let cap = WarnCapture::default();
        tracing::subscriber::with_default(cap.clone(), || {
            assert_eq!(
                sanitize_hop_header("x-api-key", "Bearer gho_bearer_value\nInjected: 1"),
                Err(Refused)
            );
        });
        assert!(cap.contains("x-api-key"), "{:?}", cap.messages());
        assert!(!cap.contains("gho_bearer_value"), "{:?}", cap.messages());
    }

    #[test]
    fn a_host_outside_the_allowlist_logs_the_rule_and_the_host_only() {
        let cap = WarnCapture::default();
        tracing::subscriber::with_default(cap.clone(), || {
            let url = "https://user:hunter2@evil.example/path?code=abc";
            assert_eq!(vet_hop_url(url, &allowed(&["github.com"])), Err(Refused));
        });
        assert!(cap.contains("evil.example"), "{:?}", cap.messages());
        assert!(cap.contains("allow"), "{:?}", cap.messages());
        assert!(!cap.contains("hunter2"), "{:?}", cap.messages());
        assert!(!cap.contains("code=abc"), "{:?}", cap.messages());
    }
}
