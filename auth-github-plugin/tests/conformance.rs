// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE GITHUB LOGIN, BOTH DOORS, ONE TABLE**: the GitHub login plugin's linked + dropped-in

#[path = "support/github_image.rs"]
mod github_image;
use github_image::cdylib;

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
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_dropped_bytes, load_linked, out_head, rendering_of_library, Bind,
    Called, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

/// The plugin's registry name and alias (what an operator's `auth.chain` names).
const NAME: &str = busbar_auth_github::door::NAME;
const ALIAS: &str = busbar_auth_github::door::ALIAS;

/// The operator config both arms are opened with (the hop bases written out, as `open` requires).
const CFG: &str = r#"{"client_id":"Iv1.conformance","fetch_orgs":true,"token_base":"https://github.com","api_base":"https://api.github.com"}"#;

/// The client secret the kernel resolved; no transcript line may carry it.
const SECRET: &str = "conformance-client-secret";

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
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

        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    }
}

/// THE LINKED DOOR: the logic crate's door as a compiled-in row.
fn row() -> LinkedRow {
    LinkedRow::of_macro(busbar_auth_github::door::MACRO_DOOR).expect("the door states its row")
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
        first_party_keys: Vec::new(),
        revoked: Default::default(),
        release_keys_floor: 0,
        release_clock: None,
        release_enforce_expiry: false,
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
    // SAFETY: the caller keeps `bytes` alive across the call that reads the blob.
    #[allow(unused_unsafe)]
    unsafe {
        Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), BLOB_JSON, 0)
    }
}

fn secret_blob(bytes: &[u8]) -> Blob {
    // SAFETY: the caller keeps `bytes` alive across the call that reads the blob.
    #[allow(unused_unsafe)]
    unsafe {
        Blob::from_raw_parts(
            bytes.as_ptr(),
            bytes.len(),
            BLOB_OCTETS,
            busbar_contract::abi::mechanism::call::BLOB_SECRET,
        )
    }
}

fn s(text: &'static str) -> AbiStr {
    AbiStr::of(text)
}

const NO_STR: AbiStr = AbiStr::ABSENT;

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
    let url = if url.is_absent() {
        String::new()
    } else {
        #[allow(unused_unsafe)]
        String::from_utf8_lossy(unsafe { url.bytes() }).into_owned()
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

/// One `begin_login` with the caller's own fields: the call's outcome (as the transcript spells
/// it), the authorize URL it named (if any), and the lease it returned (released here).
fn begin_with(
    p: &Plugin<Auth>,
    redirect_uri: AbiStr,
    state: AbiStr,
    code_challenge: AbiStr,
    scopes: &[AbiStr],
) -> (String, Option<String>) {
    let mut f = Frame::new(
        BeginLoginIn {
            head: in_head(),
            redirect_uri,
            state,
            nonce: NO_STR,
            code_challenge,
            scopes: scopes.as_ptr(),
            scopes_len: scopes.len(),
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
    let url = if url.is_absent() {
        None
    } else {
        #[allow(unused_unsafe)]
        Some(String::from_utf8_lossy(unsafe { url.bytes() }).into_owned())
    };
    let spoken = spelled(&c);
    if c.lease != 0 {
        release_lease(p, c.lease);
    }
    (spoken, url)
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
        // The open-time refusals, as `validate` answers them (the contract's `settings` lines).
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
        refresh(
            p,
            r#"{"client_id":"Iv1.refreshed","token_base":"https://github.com","api_base":"https://api.github.com"}"#,
        )
    ));
    t.push(format!("refresh refused: {}", refresh(p, "{ not json")));
    t.push(format!("tick: {}", tick(p)));
    t.push(format!("close: {}", close(p)));
    t
}

#[test]
fn the_linked_and_the_dropped_in_github_login_are_one_plugin() {
    let d = dispatcher();
    let linked = transcript(&linked(&d), CFG);
    let dropped_in = transcript(&dropped(&d), CFG);
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    let text = linked.join("\n");
    assert!(
        !text.contains(SECRET),
        "a transcript carries the secret: {text}"
    );
    for refused in [
        "validate empty: Failed lease=false settings: empty: the github plugin requires client_id",
        "validate malformed: Failed lease=false settings: not a JSON document",
        "validate no client_id: Failed lease=false settings: missing field `client_id`",
        "validate unknown field: Failed lease=false settings: unknown field `bogus`",
        "validate secret in settings: Failed lease=false settings: unknown field `client_secret`",
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
        "refresh refused: Failed lease=false settings: not a JSON document",
        "close: Ready",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
}

/// `begin_login` fails closed: a redirect_uri, state or code_challenge that is absent or not
/// UTF-8 is refused with no authorize URL, never defaulted to an empty string (which would drop
/// CSRF and PKCE silently). Both doors.
#[test]
fn begin_login_refuses_a_missing_or_non_utf8_field_through_both_doors() {
    const BAD: AbiStr = AbiStr::of_bytes(b"\xff\xfe");
    let d = dispatcher();
    for (door, p) in [("linked", linked(&d)), ("dropped-in", dropped(&d))] {
        assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
        let (ok, url) = begin_with(
            &p,
            s("https://node.example/auth/token"),
            s("st"),
            s("ch"),
            &[],
        );
        assert!(
            ok.starts_with("Ready"),
            "{door}: control must succeed: {ok}"
        );
        assert!(url.is_some(), "{door}: control names a URL");
        for bad in [NO_STR, BAD] {
            for which in 0..3 {
                let mut f = [s("https://node.example/auth/token"), s("st"), s("ch")];
                f[which] = bad;
                let (spoken, url) = begin_with(&p, f[0], f[1], f[2], &[]);
                assert!(
                    !spoken.starts_with("Ready"),
                    "{door}: field {which} bad must be refused, got {spoken}"
                );
                assert!(url.is_none(), "{door}: field {which} leaked a URL: {url:?}");
            }
        }
    }
}

/// The scopes a host requests in `BeginLoginIn.scopes` reach the authorize URL (merged with the
/// configured ones, de-duplicated); a scope that is not UTF-8 is refused, not skipped. Both doors.
#[test]
fn begin_login_carries_the_requested_scopes_through_both_doors() {
    const BAD: AbiStr = AbiStr::of_bytes(b"\xff\xfe");
    let d = dispatcher();
    for (door, p) in [("linked", linked(&d)), ("dropped-in", dropped(&d))] {
        assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
        let call = |scopes: &[AbiStr]| {
            begin_with(
                &p,
                s("https://node.example/auth/token"),
                s("st"),
                s("ch"),
                scopes,
            )
        };
        let (spoken, url) = call(&[s("gist"), s("read:user")]);
        let url = url.unwrap_or_default();
        assert!(spoken.starts_with("Ready"), "{door}: {spoken}");
        let scope = url
            .split('&')
            .find_map(|kv| kv.strip_prefix("scope="))
            .unwrap_or_default()
            .replace("%3A", ":")
            .replace("%20", " ")
            .replace('+', " ");
        let scopes: Vec<&str> = scope.split(' ').collect();
        assert!(
            scopes.contains(&"gist"),
            "{door}: requested scope missing: {url}"
        );
        assert_eq!(
            scopes.iter().filter(|x| **x == "read:user").count(),
            1,
            "{door}: scope not de-duplicated: {url}"
        );
        let (spoken, url) = call(&[s("gist"), BAD]);
        assert!(
            !spoken.starts_with("Ready"),
            "{door}: bad scope accepted: {spoken}"
        );
        assert!(url.is_none(), "{door}: bad scope leaked a URL: {url:?}");
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
        r#"{"client_id":"Iv1.someone-else","fetch_orgs":false,"token_base":"https://github.com","api_base":"https://api.github.com"}"#,
    );
    assert_ne!(
        other, linked,
        "a different config must not read as the same plugin"
    );
}

#[test]
fn an_auth_door_loaded_as_another_kind_is_refused() {
    let d = dispatcher();
    assert!(
        load_linked::<busbar_plugin_loader::dispatch::kinds::secret::Secret>(&row(), bind(&d))
            .is_err()
    );
    assert!(
        load_dropped::<busbar_plugin_loader::dispatch::kinds::secret::Secret>(
            &cdylib(),
            &rendering(),
            bind(&d)
        )
        .is_err()
    );
    assert!(
        load_linked::<busbar_plugin_loader::dispatch::kinds::store::Store>(&row(), bind(&d))
            .is_err()
    );
    assert!(
        load_dropped::<busbar_plugin_loader::dispatch::kinds::store::Store>(
            &cdylib(),
            &rendering(),
            bind(&d)
        )
        .is_err()
    );
    assert!(
        load_linked::<busbar_plugin_loader::dispatch::kinds::hook::Hook>(&row(), bind(&d)).is_err()
    );
    assert!(
        load_dropped::<busbar_plugin_loader::dispatch::kinds::hook::Hook>(
            &cdylib(),
            &rendering(),
            bind(&d)
        )
        .is_err()
    );
    assert!(
        load_linked::<busbar_plugin_loader::dispatch::kinds::export::Export>(&row(), bind(&d))
            .is_err()
    );
    assert!(
        load_dropped::<busbar_plugin_loader::dispatch::kinds::export::Export>(
            &cdylib(),
            &rendering(),
            bind(&d)
        )
        .is_err()
    );
    assert!(
        load_linked::<busbar_plugin_loader::dispatch::kinds::plane::Plane>(&row(), bind(&d))
            .is_err()
    );
    assert!(
        load_dropped::<busbar_plugin_loader::dispatch::kinds::plane::Plane>(
            &cdylib(),
            &rendering(),
            bind(&d)
        )
        .is_err()
    );
    assert!(
        load_linked::<busbar_plugin_loader::dispatch::kinds::transport::Transport>(
            &row(),
            bind(&d)
        )
        .is_err()
    );
    assert!(
        load_dropped::<busbar_plugin_loader::dispatch::kinds::transport::Transport>(
            &cdylib(),
            &rendering(),
            bind(&d)
        )
        .is_err()
    );
}

/// The envelope's log records as the host receives them: `(severity, text)`.
#[derive(Default)]
struct Logs(
    std::sync::Mutex<Vec<(u8, String)>>,
    std::sync::Mutex<Vec<Vec<u8>>>,
    std::sync::atomic::AtomicBool,
);

#[test]
fn begin_login_requires_each_utf8_binding_field_through_both_doors() {
    let d = dispatcher();
    for dropped in [false, true] {
        let p = if dropped {
            load_dropped::<Auth>(&cdylib(), &rendering(), bind(&d)).expect("dropped door loads")
        } else {
            load_linked::<Auth>(&row(), bind(&d)).expect("linked door loads")
        };
        assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
        let invalid = AbiStr {
            ptr: b"\xff".as_ptr(),
            len: 1,
        };
        for field in 0..3 {
            for value in [NO_STR, invalid] {
                let mut input = BeginLoginIn {
                    head: in_head(),
                    redirect_uri: s("https://node.example/auth/token"),
                    state: s("state"),
                    nonce: NO_STR,
                    code_challenge: s("challenge"),
                    scopes: std::ptr::null(),
                    scopes_len: 0,
                };
                match field {
                    0 => input.redirect_uri = value,
                    1 => input.state = value,
                    _ => input.code_challenge = value,
                }
                let mut output: BeginLoginOut = z();
                output.head = out_head();
                output.authorize_url = NO_STR;
                let mut frame = Frame::new(input, output);
                let called = p.call(auth::slot::BEGIN_LOGIN, &mut frame);
                assert!(spelled(&called).starts_with("Failed"));
                assert!(frame.out.authorize_url.is_absent());
                assert_eq!(frame.out.shape, 0);
            }
        }
        assert_eq!(close(&p), "Ready lease=false ");
    }
}

#[test]
fn unsupported_verify_is_explained_through_both_doors_without_echoing_credentials() {
    let d = dispatcher();
    for dropped in [false, true] {
        let logs = Arc::new(Logs::default());
        let binding = Bind {
            sink: logs.clone(),
            ..bind(&d)
        };
        let p = if dropped {
            load_dropped::<Auth>(&cdylib(), &rendering(), binding).expect("dropped door loads")
        } else {
            load_linked::<Auth>(&row(), binding).expect("linked door loads")
        };
        assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
        assert_eq!(verify(&p), "Refused lease=false ");
        let logs = logs.0.lock().expect("records");
        assert!(
            logs.iter().any(|(severity, text)| *severity == 0
                && text.contains("reason=\"unsupported-operation\"")
                && text.contains("login operations only")),
            "{logs:?}"
        );
        for (_, text) in logs.iter() {
            assert!(!text.contains("gho_opaque") && !text.contains(SECRET));
        }
        drop(logs);
        assert_eq!(close(&p), "Ready lease=false ");
    }
}

impl busbar_plugin_loader::dispatch::EnvelopeSink for Logs {
    fn metric(&self, m: busbar_plugin_loader::dispatch::Metric<'_>) {
        self.1
            .lock()
            .unwrap()
            .extend(m.labels.iter().map(|label| label.to_vec()));
    }
    fn diag(&self, d: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
        self.1
            .lock()
            .unwrap()
            .extend([d.name.to_vec(), d.text.to_vec()]);
        if let Ok(mut logs) = self.0.lock() {
            logs.push((d.severity, String::from_utf8_lossy(d.text).into_owned()));
        }
    }
    fn dropped(&self, _: busbar_plugin_loader::dispatch::Dropped) {
        self.2.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn red_l9_a_ticketless_complete_login_is_refused_at_info_with_a_reason() {
    let d = dispatcher();
    let logs = Arc::new(Logs::default());
    let p = load_linked::<Auth>(
        &row(),
        Bind {
            sink: logs.clone(),
            ..bind(&d)
        },
    )
    .expect("the linked door loads");
    assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
    assert!(complete_login(&p).starts_with("complete_login Refused"));
    let logs = logs.0.lock().expect("the records").clone();
    assert!(
        logs.iter().any(|(sev, text)| *sev == 0
            && text.contains("reason=\"no-ticket\"")
            && text.contains("module=\"github\"")),
        "{logs:?}"
    );
}

#[path = "support/remaining.rs"]
mod remaining;

// A malformed ABI header and failing READY cannot be produced by the conforming GitHub image.
// These inputs retain its actual Statement and operations, replacing only the tested field.
#[test]
fn malformed_github_headers_and_a_failing_ready_are_refused() {
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    static BAD: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    static READY_CALLS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn malformed() -> *const Door {
        BAD.load(Ordering::SeqCst)
    }
    extern "C" fn failing_ready(
        _: *mut std::ffi::c_void,
        _: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        READY_CALLS.fetch_add(1, Ordering::SeqCst);
        let failed = RawOutcome::of(Outcome::Failed);
        // SAFETY: READY receives the host's writable OutHead.
        unsafe {
            let head = &mut *out.cast::<OutHead>();
            head.outcome = failed;
            head.error = AbiStr::of("github test: discovery refused");
        }
        failed
    }
    let d = dispatcher();
    let honest = row();
    // SAFETY: the shipped macro door owns a complete static Door.
    let real = unsafe { Door::read_parts((honest.door)()) };
    for abi in [real.kind_abi.wrapping_sub(1), real.kind_abi + 1] {
        // SAFETY: only the ABI version changes; every pointer still refers to the real product.
        BAD.store(
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    kind_abi: abi,
                    ..real
                })
            })),
            Ordering::SeqCst,
        );
        let bad = LinkedRow {
            statement: honest.statement.clone(),
            door: malformed,
        };
        assert!(matches!(
            load_linked::<Auth>(&bad, bind(&d)),
            Err(busbar_plugin_loader::dispatch::LoadError::KindAbi { .. })
        ));
        assert!(
            LinkedRow::of_raw(malformed).is_err(),
            "the packer must refuse the malformed ABI"
        );
        let mut stated = rendering();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        stated[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert!(matches!(
            load_dropped::<Auth>(&cdylib(), &stated, bind(&d)),
            Err(busbar_plugin_loader::dispatch::LoadError::ManifestKindAbi { .. })
        ));
    }
    for layout in [0, real.layout ^ 1] {
        // SAFETY: the layout fingerprint alone is malformed; the real pointers are unchanged.
        BAD.store(
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts { layout, ..real })
            })),
            Ordering::SeqCst,
        );
        let bad = LinkedRow {
            statement: honest.statement.clone(),
            door: malformed,
        };
        assert!(matches!(
            load_linked::<Auth>(&bad, bind(&d)),
            Err(busbar_plugin_loader::dispatch::LoadError::KindLayout { .. })
        ));
        assert!(LinkedRow::of_raw(malformed).is_err());
    }
    // SAFETY: copy the complete real static Statement, changing only its version.
    let changed = unsafe { real.statement.read_unaligned() };
    let changed = Box::leak(Box::new(busbar_contract::abi::mechanism::door::Statement {
        version: AbiStr::of("9.6.0"),
        ..changed
    }));
    // SAFETY: the only replacement points at the complete leaked Statement above.
    BAD.store(
        Box::into_raw(Box::new(unsafe {
            Door::__from_parts(DoorParts {
                statement: changed,
                ..real
            })
        })),
        Ordering::SeqCst,
    );
    assert_eq!(
        load_linked::<Auth>(
            &LinkedRow {
                statement: honest.statement.clone(),
                door: malformed
            },
            bind(&d)
        )
        .err(),
        Some(busbar_plugin_loader::dispatch::LoadError::StatementMismatch)
    );
    // SAFETY: the sole replacement callback obeys the READY ABI and writes only OutHead.
    BAD.store(
        Box::into_raw(Box::new(unsafe {
            Door::__from_parts(DoorParts {
                size: std::mem::size_of::<Door>() as u32,
                ready: Some(failing_ready),
                ..real
            })
        })),
        Ordering::SeqCst,
    );
    let p = load_linked::<Auth>(
        &LinkedRow {
            statement: honest.statement,
            door: malformed,
        },
        bind(&d),
    )
    .unwrap();
    assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
    let before_ready = p.inner.crossings.load(Ordering::Relaxed);
    assert_eq!(
        p.ready(&d, Duration::from_secs(5)).unwrap_err(),
        format!("plugin '{NAME}' ready failed: github test: discovery refused")
    );
    assert_eq!(READY_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(p.inner.crossings.load(Ordering::Relaxed) - before_ready, 1);
    assert_eq!(close(&p), "Ready lease=false ");
}

#[test]
fn a_mismatched_statement_is_refused_through_both_doors() {
    let d = dispatcher();
    let mut bad = row();
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let at = bad
        .statement
        .windows(version.len())
        .position(|w| w == version)
        .expect("Statement contains package version");
    bad.statement[at] = b'9';
    busbar_contract::abi::mechanism::rendering::read(&bad.statement)
        .expect("a valid but different Statement");
    assert_eq!(
        load_linked::<Auth>(&bad, bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&cdylib(), &bad.statement, bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::StatementMismatch)
    );
}

#[test]
fn github_needs_match_its_declares_file_and_release_profile() {
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../auth-github/declares.json")).unwrap();
    let rendered = row().statement;
    let statement = busbar_contract::abi::mechanism::rendering::read(&rendered).unwrap();
    let mut schemes: Vec<_> = statement
        .needs
        .iter()
        .map(|n| n.transport.as_str())
        .collect();
    schemes.sort_unstable();
    schemes.dedup();
    assert_eq!(
        schemes,
        declared["needs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let debug_build = std::hint::black_box(cfg!(debug_assertions));
    if std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some() {
        assert!(
            !debug_build,
            "BUSBAR_EXPECT_RELEASE requires a release build"
        );
    }
}

#[test]
fn github_serving_requires_its_connection_table_through_both_doors() {
    use busbar_plugin_loader::dispatch::{ConnTable, LoadError};
    let d = dispatcher();
    let expected = LoadError::NoConnectionTable {
        plugin: NAME.to_owned(),
        needs: 2,
    };
    assert!(expected.to_string().contains(&format!("plugin '{NAME}'")));
    assert_eq!(
        load_linked::<Auth>(
            &row(),
            Bind {
                conns: ConnTable::NoNeeds,
                ..bind(&d)
            }
        )
        .err(),
        Some(expected.clone())
    );
    assert_eq!(
        load_dropped::<Auth>(
            &cdylib(),
            &rendering(),
            Bind {
                conns: ConnTable::NoNeeds,
                ..bind(&d)
            }
        )
        .err(),
        Some(expected)
    );
    assert!(
        load_linked::<Auth>(&row(), bind(&d)).is_ok(),
        "probe load remains allowed"
    );
}

#[test]
fn github_lifecycle_crosses_once_and_undeclared_outbound_slots_refuse() {
    use busbar_contract::abi::auth::{
        FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    };
    use std::sync::atomic::Ordering;
    let d = dispatcher();
    for is_dropped in [false, true] {
        let p = if is_dropped { dropped(&d) } else { linked(&d) };
        let count =
            || p.inner.crossings.load(Ordering::Relaxed) - p.inner.resumes.load(Ordering::Relaxed);
        assert_eq!(count(), 0);
        assert_eq!(p.max_inflight(), 64);
        assert_eq!(p.name(), NAME);
        for (bad, error_prefix) in [
            ("{}", "Failed lease=false settings:"),
            (
                r#"{"client_id":5}"#,
                "Failed lease=false settings.client_id:",
            ),
        ] {
            let before = count();
            assert!(validate(&p, bad).starts_with("Failed"));
            assert_eq!(count() - before, 1);
            let before = count();
            let answer = open(&p, bad, Some(SECRET));
            assert!(answer.starts_with(error_prefix), "bad OPEN {bad}: {answer}");
            if bad == r#"{"client_id":5}"# {
                assert!(
                    answer.contains("invalid type: integer `***`, expected a string"),
                    "bad OPEN masks the field value and names its type: {answer}"
                );
            }
            assert_eq!(count() - before, 1);
        }
        let before = count();
        assert_eq!(validate(&p, CFG), "Ready lease=false ");
        assert_eq!(count() - before, 1);
        let before = count();
        assert_eq!(open(&p, CFG, Some(SECRET)), "Ready lease=false ");
        assert_eq!(count() - before, 1);
        let before = count();
        p.ready(&d, Duration::from_secs(5)).unwrap();
        assert_eq!(count() - before, u64::from(p.has_ready()));
        let before = count();
        assert!(verify(&p).starts_with("Refused"));
        assert_eq!(count() - before, 1);
        // begin_login includes release and double-release: three independent crossings.
        let before = count();
        begin_login(&p);
        assert_eq!(count() - before, 3);
        let mut i: OpenOutboundIn = z();
        i.head = in_head();
        let mut o: OpenOutboundOut = z();
        o.head = out_head();
        let before = count();
        assert_eq!(
            p.call(auth::slot::OPEN_OUTBOUND, &mut Frame::new(i, o))
                .outcome,
            busbar_contract::abi::mechanism::call::Outcome::Refused
        );
        assert_eq!(count() - before, 1);
        let mut i: OutboundReadyIn = z();
        i.head = in_head();
        let mut o: OutboundReadyOut = z();
        o.head = out_head();
        let before = count();
        assert_eq!(
            p.call(auth::slot::OUTBOUND_READY, &mut Frame::new(i, o))
                .outcome,
            busbar_contract::abi::mechanism::call::Outcome::Refused
        );
        assert_eq!(count() - before, 1);
        let mut i: FieldsIn = z();
        i.head = in_head();
        let mut o: FieldsOut = z();
        o.head = out_head();
        let before = count();
        assert_eq!(
            p.call(auth::slot::FIELDS, &mut Frame::new(i, o)).outcome,
            busbar_contract::abi::mechanism::call::Outcome::Refused
        );
        assert_eq!(count() - before, 1);
        let before = count();
        tick(&p);
        assert_eq!(count() - before, 1);
        let before = count();
        assert_eq!(refresh(&p, CFG), "Ready lease=false ");
        assert_eq!(count() - before, 1);
        let before = count();
        assert_eq!(close(&p), "Ready lease=false ");
        assert_eq!(count() - before, 1);
    }
}

#[test]
fn github_linked_and_dropped_are_distinct_images_with_the_same_statement() {
    use busbar_contract::abi::mechanism::door::Door;
    let row = row();
    assert_eq!(row.statement, rendering());
    let linked = (row.door)();
    // SAFETY: this is the actual macro's static Door and its full auth Statement tail.
    let real = unsafe { Door::read_parts(linked) };
    let tail = unsafe {
        (*real.statement)
            .kind_tail
            .cast::<auth::AuthTail>()
            .read_unaligned()
    };
    assert_eq!(tail.caps, auth::CAP_LOGIN);
    assert_eq!(tail.login_kind, auth::LOGIN_KIND_REDIRECT);
    assert_eq!(tail.facts, 0);
    let (dropped, ops) = busbar_plugin_loader::dispatch::load::door_addresses_of_library(&cdylib())
        .unwrap()
        .expect("actual exported door");
    assert_ne!(dropped, linked as usize);
    assert_ne!(ops, real.ops as usize);
}
