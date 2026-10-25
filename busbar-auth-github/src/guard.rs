// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOP GUARD 1.5.5's CORE APPLIED TO EVERY LOGIN HOP, now enforced by the plugin itself
//! (ARCHITECT ruling R8, 2026-09-30: a 1.5.5 guard the core applied to a plugin's hops becomes plugin
//! logic, IN ADDITION to the need's egress class, never weaker than 1.5.5).
//!
//! Ported byte-for-byte in behaviour from busbar v1.5.5: `auth/token.rs` (`collect_allowed_hosts`,
//! `vet_hop_url`, `sanitize_hop_header`, `FORBIDDEN_HOP_HEADERS`), `config_validate/mod.rs`
//! (`scheme_is`, `extract_normalized_host`, `percent_decode_host`, `host_is_private_or_loopback`, the
//! hardcoded half of `ssrf_blocked_host`, `expand_alternate_ipv4`) and `net_guard.rs`. The operator's
//! `security.{allow,blocked}_metadata_hosts` / `allow_all_metadata` never reached the hop vetting in
//! 1.5.5 (it passed `&[]`, `false`, `&[]`), so only the hardcoded denylist is here.

use serde_json::Value;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zeroize::Zeroizing;

/// A hop the guard refuses: no request is built, and nothing (the secret least of all) is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// The header names a hop may never set (1.5.5 `FORBIDDEN_HOP_HEADERS`).
const FORBIDDEN_HOP_HEADERS: [&str; 3] = ["host", "content-length", "transfer-encoding"];

/// The hop host-allowlist, derived from the OPERATOR's settings only (1.5.5
/// `collect_allowed_hosts(&mc.settings, issuer)`): the host of every absolute http(s) URL string
/// anywhere in the settings tree, lowercased. Never derived from anything an IdP answered.
///
/// A key the operator left at its default is not in the settings, so its host is not allowed: in
/// 1.5.5 a GitHub method whose `token_base`/`api_base` were not written out had every hop refused.
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
        // 1.5.5 also added the settings' `issuer`; it is a string value of the same tree, so the
        // walk already covers it.
        o.values().for_each(|v| walk(v, &mut hosts));
    }
    hosts
}

/// 1.5.5 `vet_hop_url`: the host must be allow-listed; https for a public host (http only for a
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
    if metadata_host(url) {
        tracing::warn!(module = "github", host = ?host, "github login: hop refused, cloud-metadata host");
        return Err(Refused);
    }
    Ok(())
}

/// 1.5.5 `sanitize_hop_header`, answering the header as the http stack would write it: the name
/// lowercased (`HeaderName::from_bytes`), the value unchanged (`HeaderValue::from_str`) and wiped
/// on drop (an `authorization` value is the bearer).
pub fn sanitize_hop_header(
    name: &str,
    value: &str,
) -> Result<(String, Zeroizing<String>), Refused> {
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
    Ok((name.to_ascii_lowercase(), Zeroizing::new(value.to_string())))
}

/// An RFC 7230 `tchar` (what `http::HeaderName` accepts).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// 1.5.5 `scheme_is`.
pub fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

fn strip_scheme(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")).then_some(rest)
}

/// 1.5.5 `percent_decode_host`.
fn percent_decode_host(host: &str) -> String {
    let bytes = host.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| host.to_string())
}

/// 1.5.5 `extract_normalized_host`: tab/LF/CR stripped, scheme stripped, `\` folded to `/`,
/// authority isolated, userinfo and port dropped (IPv6 brackets handled), percent-decoded, one
/// trailing dot removed. Case preserved.
pub fn extract_normalized_host(url: &str) -> Option<String> {
    let url = url.replace(['\t', '\n', '\r'], "");
    let rest = strip_scheme(&url)?;
    let rest = rest.replace('\\', "/");
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest.as_str());
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host: &str = if let Some(after_bracket) = host_port.strip_prefix('[') {
        match after_bracket.split_once(']') {
            Some((inner, _)) => inner,
            None => after_bracket,
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((left, _)) if !left.contains(':') => left,
            _ => host_port,
        }
    };
    if host.is_empty() {
        return None;
    }
    let decoded = percent_decode_host(host);
    let host = decoded.strip_suffix('.').unwrap_or(decoded.as_str());
    Some(host.to_string())
}

fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// 1.5.5 `net_guard::is_alternate_ipv4_encoding`.
fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        if parts.len() < 4 {
            return true;
        }
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }
    host.bytes().all(|b| b.is_ascii_digit())
}

/// 1.5.5 `host_is_private_or_loopback`: the hosts plaintext http is tolerated for.
pub fn host_is_private_or_loopback(host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost"
        || host_lc
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld == "localhost")
    {
        return true;
    }
    if is_alternate_ipv4_encoding(host) {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || is_cgnat_shared_v4(&v4)
        }
        Ok(IpAddr::V6(v6)) => {
            let embedded = v6.to_ipv4();
            v6.is_loopback()
                || v6.is_unspecified()
                || is_unique_local_v6(&v6)
                || is_link_local_v6(&v6)
                || embedded.is_some_and(|m| {
                    m.is_loopback()
                        || m.is_private()
                        || m.is_link_local()
                        || m.is_unspecified()
                        || is_cgnat_shared_v4(&m)
                })
        }
        Err(_) => false,
    }
}

/// 1.5.5 `expand_alternate_ipv4`.
fn expand_alternate_ipv4(host: &str) -> Option<Ipv4Addr> {
    fn parse_component(p: &str) -> Option<u64> {
        if p.is_empty() {
            return None;
        }
        if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if p.len() > 1 && p.starts_with('0') {
            if !p.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return None;
            }
            u64::from_str_radix(p, 8).ok()
        } else {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()
        }
    }
    if host.is_empty() {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    let vals: Vec<u64> = parts
        .iter()
        .map(|p| parse_component(p))
        .collect::<Option<Vec<u64>>>()?;
    let is_alternate_octet = |p: &&str, v: &u64| {
        *v > 255
            || p.starts_with("0x")
            || p.starts_with("0X")
            || (p.len() > 1 && p.starts_with('0'))
    };
    let is_canonical_quad = parts.len() == 4
        && !parts
            .iter()
            .zip(&vals)
            .any(|(p, v)| is_alternate_octet(p, v));
    if is_canonical_quad {
        return None;
    }
    let addr: u32 = match vals.as_slice() {
        [a] => u32::try_from(*a).ok()?,
        [a, b] => {
            if *a > 0xff || *b > 0x00ff_ffff {
                return None;
            }
            ((*a as u32) << 24) | (*b as u32)
        }
        [a, b, c] => {
            if *a > 0xff || *b > 0xff || *c > 0x0000_ffff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | (*c as u32)
        }
        [a, b, c, d] => {
            if *a > 0xff || *b > 0xff || *c > 0xff || *d > 0xff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | ((*c as u32) << 8) | (*d as u32)
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(addr))
}

/// The hardcoded half of 1.5.5 `ssrf_blocked_host(url, &[], false, &[])`: a cloud-metadata target.
pub fn metadata_host(url: &str) -> bool {
    const METADATA_HOSTS: &[&str] = &[
        "metadata.google.internal",
        "metadata.internal",
        "metadata.tencentyun.com",
        "metadata.platformequinix.com",
        "instance-data",
        "instance-data.ec2.internal",
    ];
    let Some(host) = extract_normalized_host(url) else {
        return false;
    };
    if METADATA_HOSTS.contains(&host.to_ascii_lowercase().as_str()) {
        return true;
    }
    let imds_v6 = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);
    let alibaba_v4 = Ipv4Addr::new(100, 100, 100, 200);
    let azure_v4 = Ipv4Addr::new(168, 63, 129, 16);
    let oci_v4 = Ipv4Addr::new(192, 0, 0, 192);
    let is_metadata_v4 =
        |v4: &Ipv4Addr| v4.is_link_local() || *v4 == alibaba_v4 || *v4 == azure_v4 || *v4 == oci_v4;
    if let Some(expanded) = expand_alternate_ipv4(&host) {
        if is_metadata_v4(&expanded) {
            return true;
        }
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_metadata_v4(&v4),
        Ok(IpAddr::V6(v6)) => v6 == imds_v6 || v6.to_ipv4().is_some_and(|m| is_metadata_v4(&m)),
        Err(_) => false,
    }
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
