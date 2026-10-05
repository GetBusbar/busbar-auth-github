// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE GITHUB LOGIN, BOTH DOORS, ONE TABLE**: the GitHub login plugin's linked + dropped-in
//! conformance on the auth kind's memory ABI (v3), run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, as a compiled-in
//! row through the loader's `load_linked`) and DROPPED IN (this crate's built cdylib, its door's
//! Statement rendered and signed into the manifest's `statement` as the pack tool does, packed into
//! a temp `plugins/` directory, admitted by the loader's scan, and bound from the verified bytes
//! against that signed rendering through `load_dropped_bytes`). Each is driven over the same script
//! through the auth table: `validate` over 1.5.5's config refusals, `open` with the kernel-resolved
//! client secret, `verify` (not served), `begin_login` (the authorize URL, leased, then released),
//! a ticket-less `complete_login` (REFUSED: the token exchange waits on I/O, so it runs on a
//! ticket), `refresh` accepted and refused, `tick` and `close`. The two transcripts must be equal.
//!
//! THE RED ARMS, each its own test: the dropped-in door opened over ANOTHER config answers a different
//! transcript (so the equality is not vacuous); the door asked for as another kind is refused,
//! linked and dropped in. A missing cdylib PANICS: this test IS the dropped-in door's proof, and
//! never skips.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{
    self, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, IdentityOut,
    RequestFacts, VerifyIn, BEGIN_AUTHORIZE,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Span, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_dropped_bytes, load_linked, out_head, rendering_of_library, Bind,
    Called, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

/// The plugin's registry name and alias (what an operator's `auth.chain` names).
const NAME: &str = busbar_auth_github::door::NAME;
const ALIAS: &str = busbar_auth_github::door::ALIAS;

/// The operator config both arms are opened with.
const CFG: &str = r#"{"client_id":"Iv1.conformance","fetch_orgs":true}"#;

/// The client secret the kernel resolved; no transcript line may carry it.
const SECRET: &str = "conformance-client-secret";

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_github_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-auth-github-plugin cdylib ({file}) is not built"))
}

/// The process's dispatcher, as the composition root builds one.
fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }))
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("github-conformance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// THE LINKED DOOR: the logic crate's door as a compiled-in row.
fn row() -> LinkedRow {
    LinkedRow::of(busbar_auth_github::door::door).expect("the door states its row")
}

fn linked(d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(), bind(d)).expect("the linked door loads")
}

/// The door's Statement rendering, as the pack tool reads it off the built library.
fn rendering() -> Vec<u8> {
    rendering_of_library(&cdylib())
        .expect("the cdylib opens")
        .expect("the cdylib exports a door")
}

/// THE DROPPED-IN DOOR: the cdylib signed first-party with its Statement in the manifest, packed
/// into a fresh `plugins/` directory, scanned under a policy holding the release key, and bound
/// from the verified bytes against the signed rendering.
fn dropped(d: &Dispatcher) -> Plugin<Auth> {
    let lib = std::fs::read(cdylib()).expect("read the cdylib");
    let hex: String = rendering().iter().map(|b| format!("{b:02x}")).collect();
    let manifest = Manifest {
        name: NAME.into(),
        alias: ALIAS.into(),
        kind: "auth".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: *busbar_plugin_loader::supported_abi("auth")
            .iter()
            .max()
            .expect("a payload schema for auth"),
        statement: Some(hex),
        ..Manifest::default()
    };
    // One directory per call: the tests of this target run in parallel and each packs its own.
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("auth-github-conf-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, &lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libauth.so", &lib).unwrap();
    std::fs::write(dir.join("auth.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed plugin scans");
    let _ = std::fs::remove_dir_all(&dir);
    let p = registry.resolve(ALIAS).expect("the alias resolves");
    assert_eq!(p.manifest.name, NAME);
    let stated = p
        .manifest
        .stated_rendering()
        .expect("the signed statement is hex")
        .expect("the manifest states the Statement");
    load_dropped_bytes::<Auth>(&p.lib_bytes, &p.file, &stated, bind(d))
        .expect("the dropped-in door loads")
}

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn secret_blob(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: busbar_contract::abi::mechanism::call::BLOB_SECRET,
    }
}

fn s(text: &'static str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

const NO_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// A call's answer as the transcript spells it: outcome, error text, and whether a lease came back.
fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn validate(p: &Plugin<Auth>, settings: &str) -> String {
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings.as_bytes()),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    spelled(&p.call(lc::VALIDATE, &mut f))
}

fn open(p: &Plugin<Auth>, settings: &str, secret: Option<&str>) -> String {
    let secrets: Vec<Blob> = secret
        .map(|t| secret_blob(t.as_bytes()))
        .into_iter()
        .collect();
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: json(settings.as_bytes()),
            secrets: secrets.as_ptr(),
            secrets_len: secrets.len(),
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    spelled(&p.call(lc::OPEN, &mut f))
}

fn refresh(p: &Plugin<Auth>, settings: &str) -> String {
    let secrets = [secret_blob(SECRET.as_bytes())];
    let mut f = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: json(settings.as_bytes()),
            secrets: secrets.as_ptr(),
            secrets_len: secrets.len(),
        },
        out_head(),
    );
    spelled(&p.call(lc::REFRESH, &mut f))
}

fn release_lease(p: &Plugin<Auth>, lease: u64) -> String {
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    spelled(&p.call(lc::RELEASE, &mut f))
}

fn tick(p: &Plugin<Auth>) -> String {
    let mut f = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = p.call(lc::TICK, &mut f);
    format!("{} next={}", spelled(&c), f.out.next_tick_ns)
}

fn close(p: &Plugin<Auth>) -> String {
    let mut f = Frame::new(in_head(), out_head());
    spelled(&p.call(lc::CLOSE, &mut f))
}

const ABSENT: Span = Span {
    offset: auth::SPAN_ABSENT,
    len: 0,
};

/// An all-zero `T`: every `in`/`out` here is plain C data, all-zero a valid value of each (the
/// fields a test does not name stay zero, so a field the ABI appends needs no edit here).
fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is a valid value of each type this file zeroes.
    unsafe { std::mem::zeroed() }
}

fn identify_out() -> IdentifyOut {
    let mut o: IdentifyOut = z();
    o.head = out_head();
    let i: &mut IdentityOut = &mut o.identity;
    for span in [
        &mut i.subject,
        &mut i.key_id,
        &mut i.key_name,
        &mut i.user,
        &mut i.provider,
        &mut i.name,
        &mut i.claims,
    ] {
        *span = ABSENT;
    }
    o
}

/// The host's identity buffer over `bytes` and `groups`.
fn identity_buf(bytes: &mut [u8], groups: &mut [Span]) -> IdentityBuf {
    IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    }
}

fn verify(p: &Plugin<Auth>) -> String {
    let (mut bytes, mut groups) = (vec![0u8; 256], vec![ABSENT; 4]);
    let credential = b"gho_opaque";
    let mut i: VerifyIn = z();
    i.head = in_head();
    i.credential = secret_blob(credential);
    i.request = RequestFacts {
        method: s("GET"),
        authority: s("node.example"),
        canonical_path: s("/v1/models"),
        query: NO_STR,
        ..z()
    };
    i.out_buf = identity_buf(&mut bytes, &mut groups);
    let mut f = Frame::new(i, identify_out());
    spelled(&p.call(auth::slot::VERIFY, &mut f))
}

/// `begin_login`: the answer, the authorize URL it leased, and the release of that lease (READY
/// once, REFUSED the second time).
fn begin_login(p: &Plugin<Auth>) -> Vec<String> {
    let mut f = Frame::new(
        BeginLoginIn {
            head: in_head(),
            redirect_uri: s("https://node.example/auth/token"),
            state: s("conformance-state"),
            nonce: NO_STR,
            code_challenge: s("conformance-challenge"),
            scopes: std::ptr::null(),
            scopes_len: 0,
        },
        BeginLoginOut {
            head: out_head(),
            shape: 0,
            _reserved: 0,
            authorize_url: NO_STR,
            form: std::ptr::null(),
            form_len: 0,
        },
    );
    let c = p.call(auth::slot::BEGIN_LOGIN, &mut f);
    let url = &f.out.authorize_url;
    // SAFETY: a READY `begin_login` names its URL in plugin memory held under the answer's lease,
    // valid until that lease is released (below, after this copy).
    let url = if url.ptr.is_null() {
        String::new()
    } else {
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(url.ptr, url.len) })
            .into_owned()
    };
    vec![
        format!(
            "begin_login {} authorize={} {url}",
            spelled(&c),
            f.out.shape == BEGIN_AUTHORIZE
        ),
        format!("release {}", release_lease(p, c.lease)),
        format!("release again {}", release_lease(p, c.lease)),
    ]
}

fn complete_login(p: &Plugin<Auth>) -> String {
    let (mut bytes, mut groups) = (vec![0u8; 256], vec![ABSENT; 4]);
    let (code, verifier) = (b"the-code", b"conformance-verifier");
    let mut i: CompleteLoginIn = z();
    i.head = in_head();
    i.code = secret_blob(code);
    i.state = s("conformance-state");
    i.redirect_uri = s("https://node.example/auth/token");
    i.code_verifier = secret_blob(verifier);
    i.out_buf = identity_buf(&mut bytes, &mut groups);
    let mut f = Frame::new(i, identify_out());
    let c = p.call(auth::slot::COMPLETE_LOGIN, &mut f);
    format!("complete_login {} verdict={}", spelled(&c), f.out.verdict)
}

/// What one door does with the plugin opened under `cfg`, as one comparable transcript.
fn transcript(p: &Plugin<Auth>, cfg: &str) -> Vec<String> {
    let mut t = vec![
        format!("kind={:?} name={}", p.kind(), p.name()),
        // 1.5.5's open-time refusals, as `validate` answers them.
        format!("validate empty: {}", validate(p, "")),
        format!("validate malformed: {}", validate(p, "{ not json")),
        format!(
            "validate no client_id: {}",
            validate(p, r#"{"scopes":["read:user"]}"#)
        ),
        format!(
            "validate unknown field: {}",
            validate(p, r#"{"client_id":"x","bogus":true}"#)
        ),
        format!(
            "validate secret in settings: {}",
            validate(p, r#"{"client_id":"x","client_secret":"leak"}"#)
        ),
        format!("validate: {}", validate(p, cfg)),
        format!("open: {}", open(p, cfg, Some(SECRET))),
        format!("verify: {}", verify(p)),
    ];
    t.extend(begin_login(p));
    t.push(complete_login(p));
    t.push(format!(
        "refresh: {}",
        refresh(p, r#"{"client_id":"Iv1.refreshed"}"#)
    ));
    t.push(format!("refresh refused: {}", refresh(p, "{ not json")));
    t.push(format!("tick: {}", tick(p)));
    t.push(format!("close: {}", close(p)));
    t
}

/// The GitHub login plugin answers as ONE plugin through either door (the RED arms below show the
/// comparison is not vacuous).
#[test]
fn the_linked_and_the_dropped_in_github_login_are_one_plugin() {
    let d = dispatcher();
    let linked = transcript(&linked(&d), CFG);
    let dropped_in = transcript(&dropped(&d), CFG);
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    // Not a vacuous pass: the script did what the plugin is for.
    let text = linked.join("\n");
    assert!(
        !text.contains(SECRET),
        "a transcript carries the secret: {text}"
    );
    for refused in [
        "validate empty: Failed lease=false github plugin requires config (client_id)",
        "validate malformed: Failed lease=false invalid github plugin config",
        "validate no client_id: Failed lease=false invalid github plugin config",
        "validate unknown field: Failed lease=false invalid github plugin config",
        "validate secret in settings: Failed lease=false invalid github plugin config: unknown field `client_secret`",
    ] {
        assert!(text.contains(refused), "missing {refused:?} in:\n{text}");
    }
    for line in [
        "validate: Ready",
        "open: Ready",
        "verify: Refused",
        "begin_login Ready lease=true  authorize=true https://github.com/login/oauth/authorize?",
        "state=conformance-state&code_challenge=conformance-challenge",
        "client_id=Iv1.conformance",
        "release Ready",
        "release again Refused",
        "complete_login Refused lease=false  verdict=0",
        "refresh: Ready",
        "refresh refused: Failed lease=false invalid github plugin config",
        "close: Ready",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
}

/// RED ARM 1: the dropped-in door under a different operator config is a different transcript, so
/// the equality in the both-ways test is not vacuous.
#[test]
fn a_different_operator_config_is_a_different_transcript() {
    let d = dispatcher();
    let linked = transcript(&linked(&d), CFG);
    let other = transcript(
        &dropped(&d),
        r#"{"client_id":"Iv1.someone-else","fetch_orgs":false}"#,
    );
    assert_ne!(
        other, linked,
        "a different config must not read as the same plugin"
    );
}

/// RED ARM 2: the door asked for as another kind is refused, linked and dropped in.
#[test]
fn an_auth_door_loaded_as_another_kind_is_refused() {
    let d = dispatcher();
    assert!(
        load_linked::<Secret>(&row(), bind(&d)).is_err(),
        "an auth door must not load as secret"
    );
    assert!(
        load_dropped::<Secret>(&cdylib(), &rendering(), bind(&d)).is_err(),
        "an auth library must not load as secret"
    );
}
