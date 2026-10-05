// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the GitHub login on the auth kind's table (`busbar_contract::abi::auth`, v3), every
//! slot a [`SafeSlot`] over the SDK's safe surface, so this crate holds no `unsafe`. The verify-only
//! `auth_verify_door!` refuses the login ops, so the door is this crate's own `plugin_door!`.
//!
//! * The lifecycle is the SDK's ([`Life`]): `validate`/`open`/`refresh` parse the settings with
//!   1.5.5's texts ([`GithubLogin::open`]); the client secret is the Statement's one secret
//!   reference, resolved by the kernel into `OpenIn.secrets[0]`, never a settings value.
//! * `begin_login` answers the GitHub authorize URL under a lease.
//! * `complete_login` runs the hop chain itself ([`GithubLogin::drive`]) over the Statement's one
//!   outbound need, each hop one framed `exchange()`; PENDING parks the flow on the ticket. A
//!   ticket-less call cannot wait on I/O and answers REFUSED. An identity that does not fit the
//!   host's buffer is the short answer, and the retry is served from the identity reached (an
//!   authorization code redeems once).
//! * `verify` and the outbound ops are not served (the tail states only `CAP_LOGIN`): REFUSED.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf,
    BEGIN_AUTHORIZE, CANCEL_ABANDONED, CAP_LOGIN, IDENTITY_HAS_TTL, LOGIN_BAD_CREDENTIAL,
    LOGIN_IDENTITY, LOGIN_KIND_REDIRECT, LOGIN_OUTAGE, SPAN_ABSENT,
};
use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_DEFAULT};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::conn::Connector;
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange as Wire, Request};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, SafeSlot};
use busbar_contract::auth::Principal;

use crate::login::{Exchange, Fetched, GithubLogin, HopRequest, HopResponse, LoginFlow, LoginStep};

/// The plugin's name (the manifest name).
pub const NAME: &str = "busbar-auth-github";
/// The name config gives it (`auth.chain`, `identity-providers.<name>.module`).
pub const ALIAS: &str = "github";
/// The settings key whose value is the client secret's reference; the kernel resolves it into
/// `OpenIn.secrets[0]`.
pub const CLIENT_SECRET_KEY: &str = "client_secret";

const ABSENT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};
const SECRET_REFS: &[AbiStr] = &[abi_str(CLIENT_SECRET_KEY)];
const REWRITES: &[Rewrite] = &[Rewrite {
    class: REWRITE_ALIAS,
    _reserved: 0,
    from: abi_str(ALIAS),
    to: ABSENT,
}];
/// The index of the one need in [`NEEDS`].
const NEED: u32 = 0;
/// The one need: outbound to the IdP over the `http` transport (the scheme the http framer
/// claims; an `https` target is secured by the connector), its target named per hop (token,
/// `/user`, `/user/orgs`), bounded by 1.5.5's per-hop timeout.
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_DEFAULT,
    transport: abi_str("http"),
    auth: ABSENT,
    target_from: ABSENT,
    trust_from: ABSENT,
    details: Blob::ABSENT,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: crate::login::HOP_TIMEOUT_MS,
}];
/// A redirect login, nothing else.
const TAIL: AuthTail = AuthTail {
    head: KindTailHead {
        size: std::mem::size_of::<AuthTail>() as u32,
        _reserved: 0,
    },
    caps: CAP_LOGIN,
    facts: 0,
    login_kind: LOGIN_KIND_REDIRECT,
    _reserved: 0,
    styles: std::ptr::null(),
    styles_len: 0,
};

/// This plugin's Statement.
pub const STATEMENT: Statement = Statement {
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..with_tail(statement(NAME, env!("CARGO_PKG_VERSION"), 64), &TAIL)
};

/// The most short answers kept for their retry at once.
const ANSWERED_MAX: usize = 1024;

/// One instance: the login (swapped whole on `refresh`) and the identities a short answer reached,
/// kept for the retry on the same ticket.
pub struct Github {
    login: RwLock<Arc<GithubLogin>>,
    answered: Mutex<HashMap<Ticket, Principal>>,
}

impl std::fmt::Debug for Github {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Github").finish_non_exhaustive()
    }
}

impl Github {
    fn login(&self) -> Arc<GithubLogin> {
        self.login
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn answered(&self) -> std::sync::MutexGuard<'_, HashMap<Ticket, Principal>> {
        self.answered.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The login from settings bytes and the resolved secrets (the client secret first, if any).
fn login_from(settings: &[u8], secrets: &[&[u8]]) -> Result<GithubLogin, Refusal> {
    let settings = std::str::from_utf8(settings)
        .map_err(|e| Refusal::failed(format!("invalid github plugin config: {e}")))?;
    let secret = match secrets.first() {
        None => None,
        Some(s) => Some(std::str::from_utf8(s).map_err(|_| {
            Refusal::failed("invalid github plugin config: the client secret is not UTF-8")
        })?),
    };
    GithubLogin::open(settings, secret).map_err(Refusal::failed)
}

impl Life for Github {
    const CANCEL: u32 = CANCEL_ABANDONED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        login_from(settings, &[]).map(|_| ())
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _generation: u64) -> Result<Self, Refusal> {
        Ok(Self {
            login: RwLock::new(Arc::new(login_from(settings, secrets)?)),
            answered: Mutex::new(HashMap::new()),
        })
    }

    fn refresh(
        &self,
        settings: &[u8],
        secrets: &[&[u8]],
        _generation: u64,
    ) -> Result<Refreshed, Refusal> {
        let login = login_from(settings, secrets)?;
        *self.login.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(login);
        Ok(Refreshed::default())
    }
}

/// A lent string, `None` when absent or not UTF-8.
fn text(s: Lent<'_, AbiStr>) -> Option<&str> {
    if s.ptr.is_null() {
        return None;
    }
    s.as_str().ok()
}

/// A lent blob as UTF-8, `None` when absent or not UTF-8.
fn blob_text(b: Lent<'_, Blob>) -> Option<&str> {
    if b.fmt == BLOB_ABSENT || b.ptr.is_null() {
        return None;
    }
    std::str::from_utf8(b.bytes()).ok()
}

/// `begin_login`: the GitHub authorize URL, leased. The requested scopes are not read (the safe
/// SDK lends no accessor for `BeginLoginIn.scopes`); the configured scopes are asked for.
#[derive(Debug)]
pub struct Begin;

impl SafeSlot for Begin {
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    type State = Held<Github>;
    fn call(
        instance: Instance<'_, Held<Github>>,
        input: Lent<'_, BeginLoginIn>,
        mut out: Out<'_, BeginLoginOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        let (Some(redirect_uri), Some(state), Some(challenge)) = (
            text(input.field(|i| &i.redirect_uri)),
            text(input.field(|i| &i.state)),
            text(input.field(|i| &i.code_challenge)),
        ) else {
            return out.fail(Refusal::failed(
                "begin_login: redirect_uri, state and code_challenge are required UTF-8",
            ));
        };
        let url = h
            .life()
            .login()
            .begin_login(redirect_uri, state, challenge, &[]);
        out.set(|o| &o.shape, BEGIN_AUTHORIZE);
        out.lease_str(|o| &o.authorize_url, h.leases(), url);
        Outcome::Ready
    }
}

/// What a pending `complete_login` parks on its ticket: the flow, the exchange in flight, and how
/// many connector services the finished hops made (the next hop's handles count on from there).
struct Parked {
    flow: LoginFlow,
    wire: Option<Wire>,
    base: u32,
}

/// The hop exchange over the instance's connector: one framed `exchange()` per hop on the one need.
struct Over<'c, 'h> {
    c: &'c mut Connector<'h>,
    wire: &'c mut Option<Wire>,
    base: &'c mut u32,
}

/// `url` as the need's target (scheme and authority) and the request target (path and query).
fn split(url: &str) -> Option<(&str, String)> {
    let host_at = url.find("://")? + 3;
    let path_at = url[host_at..]
        .find(['/', '?'])
        .map_or(url.len(), |i| host_at + i);
    let (origin, path) = url.split_at(path_at);
    let path = match path.as_bytes().first() {
        None => "/".to_string(),
        Some(b'?') => format!("/{path}"),
        Some(_) => path.to_string(),
    };
    Some((origin, path))
}

impl Exchange for Over<'_, '_> {
    fn exchange(&mut self, request: &HopRequest) -> Fetched {
        let Some((origin, target)) = split(&request.target) else {
            return Fetched::Unreachable;
        };
        if self.wire.is_none() {
            let sent = Wire::request(Request {
                method: request.method.clone().into_bytes(),
                target: target.into_bytes(),
                fields: request
                    .fields
                    .iter()
                    .map(|(n, v)| (n.clone().into_bytes(), v.clone().into_bytes()))
                    .collect(),
                body: request.body.clone(),
                timeout_ms: request.timeout_ms,
            });
            match sent {
                Ok(w) => *self.wire = Some(w),
                Err(_) => return Fetched::Unreachable,
            }
        }
        let Some(wire) = self.wire.as_mut() else {
            return Fetched::Unreachable;
        };
        match exchange(&mut *self.c, wire, NEED, Some(origin)) {
            Poll::Pending => Fetched::Pending,
            Poll::Ready(answer) => {
                *self.wire = None;
                *self.base = self.c.issued();
                match answer {
                    Ok(reply) => Fetched::Ready(HopResponse {
                        status: reply.status,
                        body: reply.body,
                    }),
                    Err(_) => Fetched::Unreachable,
                }
            }
        }
    }
}

/// No connector was lent (the instance's need was not carried): every hop is unreachable.
struct Unarmed;

impl Exchange for Unarmed {
    fn exchange(&mut self, _: &HopRequest) -> Fetched {
        Fetched::Unreachable
    }
}

const NO_SPAN: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

/// Write `p` into the host's identity buffer and answer READY, or answer the short FAILED (every
/// `needed_*` at its full size), keeping `p` for the retry on `ticket`.
fn identify(
    g: &Github,
    ticket: Ticket,
    p: Principal,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    let mut bytes: HostBuf<'_, u8> = buf.buf();
    let mut groups: HostBuf<'_, Span> = buf.groups();
    let need_bytes = p.id.len()
        + p.name.as_ref().map_or(0, String::len)
        + p.roles.iter().map(String::len).sum::<usize>();
    if need_bytes > bytes.cap() || p.roles.len() > groups.cap() {
        out.set(|o| &o.needed_bytes, need_bytes as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(p.roles.len()).unwrap_or(u32::MAX),
        );
        let mut answered = g.answered();
        if answered.len() >= ANSWERED_MAX {
            answered.clear();
        }
        answered.insert(ticket, p);
        return Outcome::Failed;
    }
    let mut span = |s: &str| -> Span {
        let at = bytes.extend(s.as_bytes());
        Span {
            offset: u32::try_from(at).unwrap_or(u32::MAX),
            len: u32::try_from(s.len()).unwrap_or(u32::MAX),
        }
    };
    let subject = span(&p.id);
    let name = p.name.as_deref().map_or(NO_SPAN, &mut span);
    for role in &p.roles {
        let s = span(role);
        groups.push(s);
    }
    out.set(|o| &o.identity.subject, subject);
    out.set(|o| &o.identity.key_id, NO_SPAN);
    out.set(|o| &o.identity.key_name, NO_SPAN);
    out.set(|o| &o.identity.user, NO_SPAN);
    out.set(|o| &o.identity.provider, NO_SPAN);
    out.set(|o| &o.identity.name, name);
    out.set(|o| &o.identity.claims, NO_SPAN);
    out.set(|o| &o.identity.claims_fmt, BLOB_ABSENT);
    let (flags, ttl) = p.ttl_secs.map_or((0, 0), |t| (IDENTITY_HAS_TTL, t));
    out.set(|o| &o.identity.flags, flags);
    out.set(|o| &o.identity.ttl_secs, ttl);
    out.set(
        |o| &o.identity.groups_len,
        u32::try_from(groups.written()).unwrap_or(u32::MAX),
    );
    out.set(|o| &o.verdict, LOGIN_IDENTITY);
    Outcome::Ready
}

/// `complete_login`: the hop chain, run by the plugin over its need.
#[derive(Debug)]
pub struct Complete;

impl SafeSlot for Complete {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Github>;
    fn call(
        instance: Instance<'_, Held<Github>>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        let ticket = instance.ticket();
        if ticket.is_none() {
            // The exchange waits on I/O: the host submits the op on a ticket.
            return Outcome::Refused;
        }
        let g = h.life();
        let buf = input.field(|i| &i.out_buf);
        let reached = g.answered().remove(&ticket);
        if let Some(p) = reached {
            return identify(g, ticket, p, buf, &mut out);
        }
        let login = g.login();
        let mut parked = match instance.resume::<Parked>() {
            Some(p) => *p,
            None => Parked {
                flow: login.start(
                    blob_text(input.field(|i| &i.code)),
                    text(input.field(|i| &i.redirect_uri)),
                    blob_text(input.field(|i| &i.code_verifier)),
                    None,
                ),
                wire: None,
                base: 0,
            },
        };
        let step = match h.host() {
            None => login.drive(&mut parked.flow, &mut Unarmed),
            Some(host) => {
                let mut c = host.connector_from(ticket, parked.base);
                let mut over = Over {
                    c: &mut c,
                    wire: &mut parked.wire,
                    base: &mut parked.base,
                };
                login.drive(&mut parked.flow, &mut over)
            }
        };
        match step {
            LoginStep::Pending => {
                instance.park(parked);
                Outcome::Pending
            }
            LoginStep::Identity(p) => identify(g, ticket, p, buf, &mut out),
            LoginStep::BadCredential | LoginStep::SecurityCheckFailed => {
                out.set(|o| &o.verdict, LOGIN_BAD_CREDENTIAL);
                Outcome::Ready
            }
            LoginStep::Outage => {
                out.set(|o| &o.verdict, LOGIN_OUTAGE);
                Outcome::Ready
            }
        }
    }
}

/// An auth op this plugin does not serve (`verify`, the outbound family): REFUSED, never called.
#[derive(Debug)]
pub struct NotServed<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotServed<I, O> {
    type In = I;
    type Out = O;
    type State = Held<Github>;
    fn call(_: Instance<'_, Held<Github>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

mod table {
    use super::{Begin, Complete, Github, NotServed};
    use busbar_contract::abi::auth::{
        FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
        OutboundReadyOut, VerifyIn,
    };
    use busbar_contract::abi::sdk::Safe;

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Github),
        kind_ops: {
            verify: Safe<NotServed<VerifyIn, IdentifyOut>>,
            begin_login: Safe<Begin>,
            complete_login: Safe<Complete>,
            open_outbound: Safe<NotServed<OpenOutboundIn, OpenOutboundOut>>,
            outbound_ready: Safe<NotServed<OutboundReadyIn, OutboundReadyOut>>,
            fields: Safe<NotServed<FieldsIn, FieldsOut>>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
