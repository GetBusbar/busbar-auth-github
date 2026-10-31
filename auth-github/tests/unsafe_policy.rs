// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S UNSAFE POLICY, read off this crate's own source (BUSBAR-1.6.0.md THE DESIGN §2:
//! "Plane, hook, auth (inbound and outbound) and secret plugins are `#![forbid(unsafe_code)]`").
//! The crate states `forbid` at its root, and no source file under `src/` lifts it, holds an
//! `unsafe` block or asserts `Send`/`Sync` by hand: every door slot is a `SafeSlot` over the
//! SDK's safe surface.

use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("src is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `line` up to its `//` comment, a `//` inside a string literal (`"https://x"`) being code.
fn code_of(line: &str) -> &str {
    let bytes = line.as_bytes();
    let (mut in_string, mut i) = (false, 0);
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

#[test]
fn the_scan_reads_past_a_url_and_stops_at_a_comment() {
    assert_eq!(
        code_of(r#"let u = "http://x"; unsafe{ x() }"#),
        r#"let u = "http://x"; unsafe{ x() }"#
    );
    assert_eq!(
        code_of(r#"let s = "a\"//b"; // unsafe { }"#),
        r#"let s = "a\"//b"; "#
    );
    assert_eq!(code_of("// unsafe { }"), "");
}

#[test]
fn the_crate_root_forbids_unsafe_code() {
    let root = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs");
    assert!(
        root.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
        "an auth plugin's crate root states #![forbid(unsafe_code)] (THE DESIGN §2)"
    );
}

#[test]
fn no_source_file_lifts_the_policy_or_holds_unsafe() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(
        !files.is_empty(),
        "positive control: src holds Rust sources"
    );
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file");
        for (n, line) in text.lines().enumerate() {
            let code: String = code_of(line)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if code.contains("allow(unsafe_code)")
                || [
                    "unsafe {",
                    "unsafe{",
                    "unsafe impl",
                    "unsafe fn",
                    "unsafe extern",
                    "unsafe trait",
                ]
                .iter()
                .any(|form| code.contains(form))
            {
                found.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "unsafe code in an auth plugin: {found:#?}"
    );
}
