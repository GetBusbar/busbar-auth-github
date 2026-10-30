// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hop guard applied to every login hop, enforced by the plugin itself in addition to the
//! need's egress class.
//!
//! The host readers and the private/metadata judgements are `busbar_contract::net`, the one
//! definition. The operator's `security.{allow,blocked}_metadata_hosts` / `allow_all_metadata` do not
//! reach the hop vetting, so only the hardcoded denylist is here.

use busbar_contract::net::{
    extract_normalized_host, host_is_cloud_metadata, host_is_private_or_loopback, scheme_is,
};
use serde_json::Value;
use std::collections::HashSet;

/// A hop the guard refuses: no request is built, and nothing (the secret least of all) is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// The header names a hop may never set.
const FORBIDDEN_HOP_HEADERS: [&str; 3] = ["host", "content-length", "transfer-encoding"];

/// The hop host-allowlist, derived from the OPERATOR's settings only: the host of every absolute http(s) URL string
/// anywhere in the settings tree, lowercased. Never derived from anything an IdP answered.
///
/// A key the operator left at its default is not in the settings, so its host is not allowed: a GitHub
/// method whose `token_base`/`api_base` were not written out would have every hop refused.
/// [`crate::login::GithubLogin::open`] therefore refuses such settings up front, explained.
pub fn collect_allowed_hosts(settings: &Value) -> HashSet<String> {
    fn walk(v: &Value, hosts: &mut HashSet<String>) {
        match v {
            Value::String(s) => {
                if s.starts_with("http://") || s.starts_with("https://") {
                    if let Some(h) = extract_normalized_host(s) {
                        hosts.insert(h.to_ascii_lowercase());
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, hosts)),
            Value::Object(o) => o.values().for_each(|x| walk(x, hosts)),
            _ => {}
        }
    }
    let mut hosts = HashSet::new();
    if let Value::Object(o) = settings {
        // The settings' `issuer` is a string value of the same tree, so the walk covers it.
        o.values().for_each(|v| walk(v, &mut hosts));
    }
    hosts
}

/// Vet a hop URL: the host must be allow-listed; https for a public host (http only for a
/// loopback/private one); never a cloud-metadata host.
pub fn vet_hop_url(url: &str, allowed: &HashSet<String>) -> Result<(), Refused> {
    let Some(host) = extract_normalized_host(url) else {
        // The URL is not named: it may carry userinfo.
        tracing::warn!(
            module = "github",
            "github login: hop refused, its host could not be read from the URL"
        );
        return Err(Refused);
    };
    if !allowed.contains(&host.to_ascii_lowercase()) {
        tracing::warn!(
            module = "github",
            host = ?host,
            "github login: hop refused, host not in the allowlist built from the URLs written in the plugin settings"
        );
        return Err(Refused);
    }
    let host_private = host_is_private_or_loopback(&host);
    if !(scheme_is(url, "https") || (host_private && scheme_is(url, "http"))) {
        tracing::warn!(module = "github", host = ?host, "github login: hop refused, plaintext http to a public host");
        return Err(Refused);
    }
    if host_is_cloud_metadata(&host) {
        tracing::warn!(module = "github", host = ?host, "github login: hop refused, cloud-metadata host");
        return Err(Refused);
    }
    Ok(())
}

/// Sanitize a hop header, answering the header as the http stack would write it: the name
/// lowercased (`HeaderName::from_bytes`), the value unchanged (`HeaderValue::from_str`). A hop's
/// headers are public: the bearer is the chip's ([`crate::login::HopRequest::bearer`]).
pub fn sanitize_hop_header(name: &str, value: &str) -> Result<(String, String), Refused> {
    // Only the header NAME is ever logged (as `?`, so CR/LF cannot forge a line): never the value.
    let refuse = |why: &str| {
        tracing::warn!(module = "github", header = ?name, "github login: hop refused, {why}");
        Err(Refused)
    };
    let bad = |s: &str| s.contains('\r') || s.contains('\n') || s.contains('\0');
    if bad(name) || bad(value) {
        return refuse("a header carries CR, LF or NUL");
    }
    if FORBIDDEN_HOP_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        return refuse("a header the hop may not set");
    }
    if name.is_empty() || !name.bytes().all(is_tchar) {
        return refuse("a header name is not a valid token");
    }
    if !value.bytes().all(|b| (b >= 32 && b != 127) || b == b'\t') {
        return refuse("a header value has a control byte");
    }
    Ok((name.to_ascii_lowercase(), value.to_string()))
}

/// An RFC 7230 `tchar` (what `http::HeaderName` accepts).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
