// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::{now_ns, ConnTable};
use std::collections::HashMap;
use std::sync::Mutex;

const LOCAL: &str = r#"{"client_id":"Iv1.conformance","token_base":"http://127.0.0.1:8080","api_base":"http://127.0.0.1:8080"}"#;
struct RateLimited {
    stream: bool,
    streams: busbar_contract::conn::ConnSlab<()>,
    hint: Option<u64>,
    success: bool,
    reads: Mutex<HashMap<u64, u8>>,
    sent: Mutex<Vec<String>>,
}
impl Conns for RateLimited {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        if need.0 >= 2 {
            return Err(ConnError::UndeclaredNeed);
        }
        if need.0 == 0 {
            return Err(ConnError::Refused);
        }
        let mut sent = self.sent.lock().unwrap();
        sent.push(String::from_utf8_lossy(desc.head_target).into_owned());
        let id = if self.stream {
            self.streams.insert(caller, need, ())?
        } else {
            ConnId(sent.len() as u64)
        };
        self.reads.lock().unwrap().insert(id.0, 0);
        Ok(id)
    }
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        if self.stream {
            self.streams.get(caller, conn)?;
            Ok(bytes.len())
        } else {
            Err(ConnError::Closed)
        }
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        if self.stream {
            self.streams.get(caller, conn)?;
        }
        let successful_body = self.success.then(|| {
            let sent = self.sent.lock().unwrap();
            match sent[(conn.0 - 1) as usize].as_str() {
                "/login/oauth/access_token" => r#"{"access_token":"gho_conformance_token"}"#,
                "/user" => r#"{"login":"identity-canary","id":42}"#,
                "/user/orgs?per_page=100" => "[]",
                "/user/orgs?page=2" => r#"[{"login":"second-page-canary","id":7}]"#,
                other => panic!("unexpected target {other}"),
            }
        });
        let mut reads = self.reads.lock().unwrap();
        let step = reads.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        let (kind, data, status) = match *step {
            0 => (
                PieceKind::Fields,
                if successful_body == Some("[]") {
                    b"LiNk: </user/orgs?page=2>; rel=\"next\"\r\n".to_vec()
                } else {
                    self.hint
                        .map(|n| format!("ReTrY-AfTeR: {n}\r\n"))
                        .unwrap_or_default()
                        .into_bytes()
                },
                Some(if self.success { 200 } else { 429 }),
            ),
            1 => (
                PieceKind::Body,
                successful_body.unwrap_or("{}").as_bytes().to_vec(),
                None,
            ),
            _ => (PieceKind::Completion, Vec::new(), None),
        };
        *step += 1;
        buf[..data.len()].copy_from_slice(&data);
        Ok(Piece {
            kind,
            stream: StreamId(0),
            len: data.len(),
            end: true,
            status: None,
            status_code: status,
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        if self.stream {
            self.streams.remove(caller, conn)?;
        }
        self.reads.lock().unwrap().remove(&conn.0);
        Ok(())
    }
}
impl DeclaredConns for RateLimited {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        _dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        // This immediate in-memory I/O answer supports a separate dial deadline without waiting.
        // Preserve the default security refusal: this value double never claims to provide TLS.
        self.open_with_security(caller, need, desc, require_secure)
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        if !spec.trust_from.is_empty() && trust.is_none() {
            Err(ConnError::Refused)
        } else {
            if self.stream {
                self.streams.declare(owner, need);
            }
            Ok(())
        }
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        Some(if need.0 == 0 {
            Err(ConnError::Refused)
        } else if need.0 == 1 {
            if self.stream {
                self.streams.check_need(owner, need)
            } else {
                Ok(())
            }
        } else {
            Err(ConnError::UndeclaredNeed)
        })
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        !self.stream
    }
}
fn load(dropped: bool, binding: Bind) -> Plugin<Auth> {
    if dropped {
        load_dropped::<Auth>(&cdylib(), &rendering(), binding).unwrap()
    } else {
        load_linked::<Auth>(&row(), binding).unwrap()
    }
}

#[test]
fn retry_hint_reaches_host_owned_extensions_through_both_doors() {
    let d = dispatcher();
    for dropped in [false, true] {
        for hint in [None, Some(0), Some(120), Some(u64::MAX)] {
            let conns = Arc::new(RateLimited {
                stream: false,
                streams: Default::default(),
                hint,
                success: false,
                reads: Mutex::new(HashMap::new()),
                sent: Mutex::new(Vec::new()),
            });
            let p = load(
                dropped,
                Bind {
                    conns: ConnTable::Host(conns.clone()),
                    ..bind(&d)
                },
            );
            assert_eq!(open(&p, LOCAL, Some(SECRET)), "Ready lease=false ");
            let (mut bytes, mut groups) = (vec![0u8; 1024], vec![ABSENT; 4]);
            let mut i: CompleteLoginIn = z();
            i.head = in_head();
            i.code = secret_blob(b"code");
            i.code_verifier = secret_blob(b"verifier");
            i.state = s("state");
            i.redirect_uri = s("https://node.example/auth/token");
            i.out_buf = identity_buf(&mut bytes, &mut groups);
            let ticket = d.mint(0).unwrap();
            let done = d
                .submit(
                    &p,
                    ticket,
                    auth::slot::COMPLETE_LOGIN,
                    Frame::new(i, identify_out()),
                    DeadlineClass::Call,
                    now_ns() + 20_000_000_000,
                )
                .wait(Duration::from_secs(30))
                .expect("login completed");
            assert_eq!(done.outcome, Outcome::Ready);
            let frame = done
                .frame
                .as_ref()
                .expect("Ready returns the completed frame");
            assert_eq!(frame.out.verdict, auth::LOGIN_OUTAGE);
            let ext = frame.out.head.extensions;
            match hint {
                None => assert_eq!(ext.len, 0),
                Some(hint) => {
                    let offset = (ext.ptr as usize)
                        .checked_sub(bytes.as_ptr() as usize)
                        .expect("extension belongs to host buffer");
                    let end = offset.checked_add(ext.len).unwrap();
                    let encoded = bytes
                        .get(offset..end)
                        .expect("extension stays in host buffer");
                    assert_eq!(
                        busbar_contract::abi::mechanism::extensions::get(encoded, "retry_after"),
                        Some(hint.to_string().as_bytes())
                    );
                }
            }
            d.recycle(ticket);
            assert_eq!(*conns.sent.lock().unwrap(), ["/login/oauth/access_token"]);
            assert!(conns.reads.lock().unwrap().is_empty());
            assert_eq!(close(&p), "Ready lease=false ");
        }
    }
}

#[test]
fn open_warns_once_for_absent_or_empty_optional_secret_but_validation_does_not() {
    let d = dispatcher();
    for dropped in [false, true] {
        for secret in [None, Some(""), Some(SECRET)] {
            let logs = Arc::new(Logs::default());
            let p = load(
                dropped,
                Bind {
                    sink: logs.clone(),
                    ..bind(&d)
                },
            );
            assert_eq!(validate(&p, CFG), "Ready lease=false ");
            assert!(!logs
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|(_, text)| text.contains("opened without a client_secret")));
            assert_eq!(open(&p, CFG, secret), "Ready lease=false ");
            let records = logs.0.lock().unwrap();
            let warnings: Vec<_> = records
                .iter()
                .filter(|(_, text)| text.contains("opened without a client_secret"))
                .collect();
            assert_eq!(
                warnings.len(),
                usize::from(secret.is_none_or(str::is_empty))
            );
            assert!(warnings.iter().all(|(severity, _)| *severity == 1));
            assert!(records.iter().all(|(_, text)| !text.contains(SECRET)));
            drop(records);
            assert_eq!(close(&p), "Ready lease=false ");
        }
    }
}

#[test]
fn short_answer_capacity_eviction_warns_without_exposing_the_identity() {
    let d = dispatcher();
    for dropped in [false, true] {
        let conns = Arc::new(RateLimited {
            stream: false,
            streams: Default::default(),
            hint: None,
            success: true,
            reads: Mutex::new(HashMap::new()),
            sent: Mutex::new(Vec::new()),
        });
        let logs = Arc::new(Logs::default());
        let p = load(
            dropped,
            Bind {
                conns: ConnTable::Host(conns.clone()),
                sink: logs.clone(),
                ..bind(&d)
            },
        );
        assert_eq!(open(&p, LOCAL, Some(SECRET)), "Ready lease=false ");
        for _ in 0..1025 {
            let mut bytes = [];
            let mut groups = [];
            let mut input: CompleteLoginIn = z();
            input.head = in_head();
            input.code = secret_blob(b"code-canary");
            input.code_verifier = secret_blob(b"verifier-canary");
            input.redirect_uri = s("https://node.example/auth/token");
            input.out_buf = identity_buf(&mut bytes, &mut groups);
            let ticket = d.mint(0).expect("ticket");
            let done = d
                .submit(
                    &p,
                    ticket,
                    auth::slot::COMPLETE_LOGIN,
                    Frame::new(input, identify_out()),
                    DeadlineClass::Call,
                    now_ns() + 20_000_000_000,
                )
                .wait(Duration::from_secs(30))
                .expect("short answer completed");
            assert_eq!(done.outcome, Outcome::Failed);
            d.recycle(ticket);
        }
        let records = logs.0.lock().unwrap();
        let evictions: Vec<_> = records
            .iter()
            .filter(|(_, text)| text.contains("evicted"))
            .collect();
        assert_eq!(evictions.len(), 1, "{records:?}");
        assert_eq!(evictions[0].0, 1);
        for (_, text) in records.iter() {
            for secret in [
                "identity-canary",
                "gho_conformance_token",
                "code-canary",
                "verifier-canary",
                SECRET,
            ] {
                assert!(!text.contains(secret), "{records:?}");
            }
        }
        drop(records);
        assert!(conns.reads.lock().unwrap().is_empty());
        let sent = conns.sent.lock().unwrap();
        assert_eq!(sent.len(), 1025 * 4);
        for targets in sent.as_chunks::<4>().0 {
            assert_eq!(
                targets.as_slice(),
                [
                    "/login/oauth/access_token",
                    "/user",
                    "/user/orgs?per_page=100",
                    "/user/orgs?page=2"
                ]
            );
        }
        drop(sent);
        assert_eq!(close(&p), "Ready lease=false ");
    }
}

/// The short-buffer rule through both doors: an identity that does not fit the host's buffer is
/// the short FAILED, and the one re-submit on the same ticket, with room, is served the identity
/// reached, with no hop sent again (the authorization code redeems once).
#[test]
fn a_short_answer_is_served_to_its_retry_on_the_same_ticket_through_both_doors() {
    let d = dispatcher();
    for dropped in [false, true] {
        let conns = Arc::new(RateLimited {
            stream: false,
            streams: Default::default(),
            hint: None,
            success: true,
            reads: Mutex::new(HashMap::new()),
            sent: Mutex::new(Vec::new()),
        });
        let p = load(
            dropped,
            Bind {
                conns: ConnTable::Host(conns.clone()),
                ..bind(&d)
            },
        );
        assert_eq!(open(&p, LOCAL, Some(SECRET)), "Ready lease=false ");
        let ticket = d.mint(0).expect("ticket");
        let (mut bytes, mut groups) = (vec![0u8; 4096], vec![ABSENT; 16]);
        let mut verdicts = Vec::new();
        for room in [false, true] {
            let mut input: CompleteLoginIn = z();
            input.head = in_head();
            input.code = secret_blob(b"conformance-code");
            input.code_verifier = secret_blob(b"conformance-verifier");
            input.state = s("conformance-state");
            input.redirect_uri = s("https://node.example/auth/token");
            input.out_buf = if room {
                identity_buf(&mut bytes, &mut groups)
            } else {
                identity_buf(&mut [], &mut [])
            };
            let done = d
                .submit(
                    &p,
                    ticket,
                    auth::slot::COMPLETE_LOGIN,
                    Frame::new(input, identify_out()),
                    DeadlineClass::Call,
                    now_ns() + 20_000_000_000,
                )
                .wait(Duration::from_secs(30))
                .expect("login completes");
            verdicts.push(done.outcome);
            if room {
                let output = &done.frame.as_ref().expect("Ready returns the frame").out;
                assert_eq!(output.verdict, auth::LOGIN_IDENTITY);
                let span = output.identity.subject;
                assert_eq!(
                    std::str::from_utf8(
                        &bytes[span.offset as usize..(span.offset + span.len) as usize]
                    )
                    .unwrap(),
                    "github-v2:aHR0cDovLzEyNy4wLjAuMTo4MDgw:user:42"
                );
            }
        }
        assert_eq!(
            verdicts,
            [Outcome::Failed, Outcome::Ready],
            "dropped={dropped}"
        );
        assert_eq!(
            *conns.sent.lock().unwrap(),
            [
                "/login/oauth/access_token",
                "/user",
                "/user/orgs?per_page=100",
                "/user/orgs?page=2"
            ],
            "the retry sends no hop"
        );
        d.recycle(ticket);
        assert_eq!(close(&p), "Ready lease=false ");
    }
}

#[test]
fn a_successful_login_and_an_empty_code_are_compared_through_both_doors() {
    let d = dispatcher();
    let mut answers = Vec::new();
    for dropped in [false, true] {
        let conns = Arc::new(RateLimited {
            stream: false,
            streams: Default::default(),
            hint: None,
            success: true,
            reads: Mutex::new(HashMap::new()),
            sent: Mutex::new(Vec::new()),
        });
        let logs = Arc::new(Logs::default());
        let p = load(
            dropped,
            Bind {
                conns: ConnTable::Host(conns.clone()),
                sink: logs.clone(),
                ..bind(&d)
            },
        );
        for bad in ["{}", r#"{"client_id":5}"#] {
            assert!(validate(&p, bad).starts_with("Failed"));
        }
        assert_eq!(open(&p, LOCAL, Some(SECRET)), "Ready lease=false ");
        let mut leg = Vec::new();
        for code in [b"conformance-code".as_slice(), b""] {
            let (mut bytes, mut groups) = (vec![0u8; 4096], vec![ABSENT; 16]);
            let mut input: CompleteLoginIn = z();
            input.head = in_head();
            input.code = secret_blob(code);
            input.code_verifier = secret_blob(b"conformance-verifier");
            input.state = s("conformance-state");
            input.redirect_uri = s("https://node.example/auth/token");
            input.out_buf = identity_buf(&mut bytes, &mut groups);
            let before = conns.sent.lock().unwrap().len();
            let crossings = p.test_invocations().0 - p.test_invocations().1;
            let ticket = d.mint(0).unwrap();
            let done = d
                .submit(
                    &p,
                    ticket,
                    auth::slot::COMPLETE_LOGIN,
                    Frame::new(input, identify_out()),
                    DeadlineClass::Call,
                    now_ns() + 20_000_000_000,
                )
                .wait(Duration::from_secs(30))
                .expect("login completes");
            assert_eq!(done.outcome, Outcome::Ready);
            assert_eq!(done.lease, 0);
            assert_eq!(
                p.test_invocations().0 - p.test_invocations().1 - crossings,
                1
            );
            leg.push(format!(
                "{:?} lease={} {}",
                done.outcome,
                done.lease != 0,
                String::from_utf8_lossy(done.error.as_deref().unwrap_or_default())
            ));
            let output = &done.frame.as_ref().unwrap().out;
            if code.is_empty() {
                assert_eq!(output.verdict, auth::LOGIN_BAD_CREDENTIAL);
                assert_eq!(
                    conns.sent.lock().unwrap().len(),
                    before,
                    "empty code opens no hop"
                );
                leg.push("reject".to_owned());
            } else {
                assert_eq!(output.verdict, auth::LOGIN_IDENTITY);
                let span = output.identity.subject;
                let subject = std::str::from_utf8(
                    &bytes[span.offset as usize..(span.offset + span.len) as usize],
                )
                .unwrap();
                assert_eq!(subject, "github-v2:aHR0cDovLzEyNy4wLjAuMTo4MDgw:user:42");
                let spans = &groups[..output.identity.groups_len as usize];
                let roles: Vec<_> = spans
                    .iter()
                    .map(|span| {
                        std::str::from_utf8(
                            &bytes[span.offset as usize..(span.offset + span.len) as usize],
                        )
                        .unwrap()
                        .to_owned()
                    })
                    .collect();
                assert_eq!(
                    roles,
                    [
                        "github-v2:aHR0cDovLzEyNy4wLjAuMTo4MDgw:user:42",
                        "github-v2:aHR0cDovLzEyNy4wLjAuMTo4MDgw:org:7"
                    ]
                );
                leg.push(format!("{subject} {roles:?}"));
                assert_eq!(
                    &conns.sent.lock().unwrap()[before..],
                    [
                        "/login/oauth/access_token",
                        "/user",
                        "/user/orgs?per_page=100",
                        "/user/orgs?page=2"
                    ]
                );
            }
            d.recycle(ticket);
            assert!(conns.reads.lock().unwrap().is_empty());
        }
        let text = format!("{:?}", logs.0.lock().unwrap());
        for secret in [
            SECRET,
            "gho_conformance_token",
            "conformance-code",
            "conformance-verifier",
        ] {
            assert!(!text.contains(secret), "{secret}");
        }
        assert_eq!(close(&p), "Ready lease=false ");
        let lifecycle = load(
            dropped,
            Bind {
                sink: logs.clone(),
                ..bind(&d)
            },
        );
        let mut emitted = transcript(&lifecycle, CFG);
        emitted.extend(leg.iter().cloned());
        assert_github_credentials_stay_private(&logs, &emitted);
        answers.push(leg);
    }
    assert_eq!(answers[0], answers[1]);
}

mod custody {
    use super::*;
    use busbar_contract::abi::host::conn::connector::{service, EstablishIn, IoIn, StreamIn};
    use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
    use busbar_contract::abi::mechanism::call::RawOutcome;
    use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
    use busbar_plugin_loader::dispatch::conn_services::CONN_SLOTS;
    use std::os::raw::c_void;
    fn head(op: u32, size: usize) -> ServiceHead {
        ServiceHead {
            size: u32::try_from(size).unwrap_or(u32::MAX),
            op,
            handle: CompletionHandle {
                ticket: Ticket::NONE,
                seq: 0,
                _reserved: 0,
            },
        }
    }

    fn out() -> ServiceOut {
        // SAFETY: a plain repr(C) value of integers and a NULL/0 string: all-zero is valid.
        let mut out: ServiceOut = unsafe { std::mem::zeroed() };
        out.size = std::mem::size_of::<ServiceOut>() as u32;
        out
    }

    fn answered(raw: RawOutcome, o: &ServiceOut) -> (Outcome, u64, String) {
        let text = if o.error.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: the host's text, `'static` (interned) or held for the call.
            String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
                .into_owned()
        };
        (raw.outcome(), o.value, text)
    }

    fn establish(p: &Plugin<Auth>, need: u32, target: &str) -> (Outcome, u64, String) {
        let none = AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        };
        let i = EstablishIn {
            head: head(service::ESTABLISH, std::mem::size_of::<EstablishIn>()),
            need,
            timeout_ms: 5_000,
            target: AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            },
            within: none,
            member: none,
        };
        let mut o = out();
        let f = CONN_SLOTS.establish.expect("the host offers ESTABLISH");
        // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
        let raw = unsafe {
            f(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        answered(raw, &o)
    }

    fn io(p: &Plugin<Auth>, stream: u64, write: bool) -> (Outcome, u64, String) {
        let mut buf = *b"x";
        let (op, f) = if write {
            (service::WRITE, CONN_SLOTS.write)
        } else {
            (service::READ, CONN_SLOTS.read)
        };
        let i = IoIn {
            head: head(op, std::mem::size_of::<IoIn>()),
            stream,
            buf: buf.as_mut_ptr(),
            len: buf.len(),
        };
        let mut o = out();
        // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
        let raw = unsafe {
            f.expect("the host offers READ and WRITE")(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        answered(raw, &o)
    }

    fn close_stream(p: &Plugin<Auth>, stream: u64) -> (Outcome, u64, String) {
        let i = StreamIn {
            head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
            stream,
        };
        let mut o = out();
        // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
        let raw = unsafe {
            CONN_SLOTS.close.expect("the host offers CLOSE")(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        answered(raw, &o)
    }

    #[test]
    fn github_connections_refuse_undeclared_needs_and_other_instances() {
        let d = dispatcher();
        let table = Arc::new(RateLimited {
            stream: true,
            streams: Default::default(),
            hint: None,
            success: false,
            reads: Mutex::new(HashMap::new()),
            sent: Mutex::new(Vec::new()),
        });
        for dropped in [false, true] {
            let owner = load(
                dropped,
                Bind {
                    instance: Arc::from("github-custody-owner"),
                    conns: ConnTable::Host(table.clone()),
                    ..bind(&d)
                },
            );
            let other = load(
                dropped,
                Bind {
                    instance: Arc::from("github-custody-other"),
                    conns: ConnTable::Host(table.clone()),
                    ..bind(&d)
                },
            );
            assert_ne!(owner.instance(), other.instance());
            assert_eq!(open(&owner, LOCAL, Some(SECRET)), "Ready lease=false ");
            assert_eq!(open(&other, LOCAL, Some(SECRET)), "Ready lease=false ");
            let (outcome, stream, text) = establish(&owner, 1, "127.0.0.1:8080");
            assert_eq!(outcome, Outcome::Ready, "{text}");
            assert_eq!(io(&owner, stream, true).0, Outcome::Ready);
            for need in [2, u32::MAX] {
                let (outcome, _, text) = establish(&owner, need, "127.0.0.1:8080");
                assert_eq!(
                    (outcome, text.as_str()),
                    (Outcome::Refused, ConnError::UndeclaredNeed.text())
                );
            }
            for answer in [
                io(&other, stream, true),
                io(&other, stream, false),
                close_stream(&other, stream),
            ] {
                assert_eq!(
                    (answer.0, answer.2.as_str()),
                    (Outcome::Refused, ConnError::NotOwner.text())
                );
            }
            assert_eq!(io(&owner, stream, true).0, Outcome::Ready);
            assert_eq!(close_stream(&owner, stream).0, Outcome::Ready);
            assert_eq!(close(&other), "Ready lease=false ");
            assert_eq!(close(&owner), "Ready lease=false ");
        }
    }
}

// The GitHub credential test scans raw envelope fields and every spelling the old suite checked.
fn assert_github_credentials_stay_private(logs: &Logs, answers: &[String]) {
    use base64::Engine as _;
    assert!(
        !logs.2.load(std::sync::atomic::Ordering::Relaxed),
        "credential capture lost an envelope"
    );
    let inputs: serde_json::Value =
        serde_json::from_str(include_str!("../conformance.json")).unwrap();
    let mut secrets: Vec<_> = inputs["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    secrets.extend([SECRET, "conformance-code", "conformance-verifier"]);
    let mut emitted = logs.1.lock().unwrap().clone();
    emitted.extend(answers.iter().map(|answer| answer.as_bytes().to_vec()));
    for secret in secrets {
        let mut upper = String::new();
        let mut lower = String::new();
        for byte in secret.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                upper.push(byte as char);
                lower.push(byte as char);
            } else {
                upper.push_str(&format!("%{byte:02X}"));
                lower.push_str(&format!("%{byte:02x}"));
            }
        }
        let spellings = [
            secret.to_owned(),
            upper,
            lower,
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .trim_end_matches('=')
                .to_owned(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
            secret.bytes().map(|b| format!("{b:02x}")).collect(),
            secret.bytes().map(|b| format!("{b:02X}")).collect(),
        ];
        for bytes in &emitted {
            for spelling in &spellings {
                assert!(!spelling.is_empty());
                assert!(
                    !bytes
                        .windows(spelling.len())
                        .any(|window| window == spelling.as_bytes()),
                    "GitHub credential escaped into answer/envelope"
                );
            }
        }
    }
}
