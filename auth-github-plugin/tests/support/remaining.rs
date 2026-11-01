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

// The existing safe Door runs the real exchange against its host connection table.
// HTTP loopback is an explicit operator setting; no TLS fact or public-HTTP exception is invented.
const LOCAL: &str = r#"{"client_id":"Iv1.conformance","token_base":"http://127.0.0.1:8080","api_base":"http://127.0.0.1:8080"}"#;
struct RateLimited {
    hint: Option<u64>,
    success: bool,
    reads: Mutex<HashMap<u64, u8>>,
    sent: Mutex<Vec<String>>,
}
impl Conns for RateLimited {
    fn open(&self, _: InstanceId, _: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        let mut sent = self.sent.lock().unwrap();
        sent.push(String::from_utf8_lossy(desc.head_target).into_owned());
        let id = sent.len() as u64;
        self.reads.lock().unwrap().insert(id, 0);
        Ok(ConnId(id))
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(
        &self,
        _: InstanceId,
        conn: ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let successful_body = self.success.then(|| {
            let sent = self.sent.lock().unwrap();
            match sent[(conn.0 - 1) as usize].as_str() {
                "/login/oauth/access_token" => r#"{"access_token":"fixture-token"}"#,
                "/user" => r#"{"login":"identity-canary","id":42}"#,
                "/user/orgs?per_page=100" => "[]",
                "/user/orgs?page=2" => r#"[{"login":"second-page-canary"}]"#,
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
    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.reads.lock().unwrap().remove(&conn.0);
        Ok(())
    }
}
impl DeclaredConns for RateLimited {
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        spec: &ReadNeed,
        _: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        if !spec.trust_from.is_empty() && trust.is_none() {
            Err(ConnError::Refused)
        } else {
            Ok(())
        }
    }
    fn declared(&self, _: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        Some(if need.0 == 0 {
            Err(ConnError::Refused)
        } else {
            Ok(())
        })
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
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
    // Old API only: the extension key is read through the existing generic extension parser.
    // Thus the old plugin fails behaviorally (missing metadata), not on a new SDK test API.
    let d = dispatcher();
    for dropped in [false, true] {
        for hint in [None, Some(0), Some(120), Some(u64::MAX)] {
            let conns = Arc::new(RateLimited {
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
            assert_eq!(done.frame.out.verdict, auth::LOGIN_OUTAGE);
            let ext = done.frame.out.head.extensions;
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
                "fixture-token",
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
        for targets in sent.chunks_exact(4) {
            assert_eq!(
                targets,
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
