// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door: the GitHub login on the auth kind's table (`busbar_contract::abi::auth`, v3), every

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf,
    BEGIN_AUTHORIZE, CANCEL_ABANDONED, CAP_LOGIN, LOGIN_BAD_CREDENTIAL, LOGIN_KIND_REDIRECT,
    LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_DEFAULT, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::door::{Rewrite, Statement};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::auth_kit::{login_identity, login_outage};
use busbar_contract::abi::sdk::conn::Connector;
use busbar_contract::abi::sdk::door::{abi_str, alias, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange as Wire};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::auth::Principal;

use crate::login::{
    split, Exchange, Fetched, GithubLogin, HopRequest, HopResponse, LoginFlow, LoginStep,
    ReplyFields, MAX_HOP_REPLY_BYTES,
};
use zeroize::Zeroizing;

/// The plugin's name (the manifest name).
pub const NAME: &str = "busbar-auth-github";
/// The name config gives it (`auth.chain`, `identity-providers.<name>.module`).
pub const ALIAS: &str = "github";
/// The settings key whose value is the client secret's reference; the kernel resolves it into

pub const CLIENT_SECRET_KEY: &str = "client_secret";

const SECRET_REFS: &[AbiStr] = &[abi_str(CLIENT_SECRET_KEY)];
const REWRITES: &[Rewrite] = &[alias(ALIAS)];
/// The need a login whose settings name a `ca_cert_pem` goes out on (it trusts that root beside

const NEED_ANCHORED: u32 = 0;
/// The need every other login goes out on (the public roots only). The host refuses a need whose

const NEED_PUBLIC: u32 = 1;
/// The setting the anchored need's extra trusted root comes from (a config path the host reads).
const CA_CERT_PATH: &str = "settings.ca_cert_pem";

/// One outbound need to the IdP over the `http` transport (the scheme the http framer claims; an

const fn need(trust_from: AbiStr) -> Need {
    let mut n = Need::EMPTY;
    n.direction = DIRECTION_OUTBOUND;
    n.egress_class = EGRESS_DEFAULT;
    n.transport = abi_str("http");
    n.timeout_ms = crate::login::HOP_TIMEOUT_MS;
    n.keep_mode = KEEP_NAMED;
    n.trust_from = trust_from;
    n
}

/// The needs, in index order: [`NEED_ANCHORED`], [`NEED_PUBLIC`].
const NEEDS: &[Need] = &[need(abi_str(CA_CERT_PATH)), need(AbiStr::ABSENT)];

/// The need `login`'s hops go out on.
fn need_of(login: &GithubLogin) -> u32 {
    if login.anchored() {
        NEED_ANCHORED
    } else {
        NEED_PUBLIC
    }
}

/// A redirect login, nothing else.
const TAIL: AuthTail = {
    let mut t = AuthTail::EMPTY;
    t.caps = CAP_LOGIN;
    t.login_kind = LOGIN_KIND_REDIRECT;

    t.operator_principal = abi_str("");
    t
};

/// This plugin's Statement.
pub const STATEMENT: Statement = with_tail(
    statement(NAME, env!("CARGO_PKG_VERSION"), 64)
        .with_secret_refs(SECRET_REFS)
        .with_rewrites(REWRITES)
        .with_needs(NEEDS),
    &TAIL,
);

/// The most short answers kept for their retry at once.
const ANSWERED_MAX: usize = 1024;

/// The identities short answers reached, by the ticket whose retry they wait for, each stamped with

type Answered = HashMap<Ticket, (Instant, Principal)>;

/// How long a short answer waits for its retry: an entry older is dropped on the next access.
const ANSWERED_TTL: Duration = Duration::from_secs(10 * 60);

/// Drop every entry older than [`ANSWERED_TTL`] at `now`.
fn sweep(map: &mut Answered, now: Instant) -> usize {
    let before = map.len();
    map.retain(|_, (at, _)| now.saturating_duration_since(*at) <= ANSWERED_TTL);
    before - map.len()
}

/// The identity a short answer reached for `ticket`, taken for its retry, if it is not stale.
fn take(map: &mut Answered, now: Instant, ticket: Ticket) -> Option<Principal> {
    sweep(map, now);
    map.remove(&ticket).map(|(_, p)| p)
}

/// Keep `p` for `ticket`'s retry, at most `max` at once: entries past [`ANSWERED_TTL`] go first;

fn keep(map: &mut Answered, max: usize, at: Instant, ticket: Ticket, p: Principal) -> usize {
    let mut evicted = sweep(map, at);
    if map.len() >= max && !map.contains_key(&ticket) {
        let oldest = map.iter().min_by_key(|(_, (at, _))| *at).map(|(t, _)| *t);
        if let Some(oldest) = oldest {
            map.remove(&oldest);
            evicted += 1;
        }
    }
    map.insert(ticket, (at, p));
    evicted
}

/// One bounded record per cache access, after its mutex is released; no identity or ticket data.
fn warn_evicted(evicted: usize) {
    if evicted != 0 {
        tracing::warn!(
            module = "github",
            evicted,
            "github login: short-buffer identities expired or were evicted before their retry"
        );
    }
}

/// One instance: the login (swapped whole on `refresh`) and the identities a short answer reached,

pub struct Github {
    login: RwLock<Arc<GithubLogin>>,
    answered: Mutex<Answered>,
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

    fn answered(&self) -> std::sync::MutexGuard<'_, Answered> {
        self.answered.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The login from settings bytes and the resolved secrets (the client secret first, if any).
fn login_from(settings: &[u8], secrets: &[&[u8]]) -> Result<GithubLogin, Refusal> {
    let settings =
        std::str::from_utf8(settings).map_err(|_| Refusal::failed("settings: not UTF-8"))?;
    let secret = match secrets.first() {
        None => None,
        Some(s) => Some(std::str::from_utf8(s).map_err(|_| {
            Refusal::failed(format!("secrets: `{CLIENT_SECRET_KEY}` is not UTF-8"))
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
        let instance = Self {
            login: RwLock::new(Arc::new(login_from(settings, secrets)?)),
            answered: Mutex::new(HashMap::new()),
        };
        if secrets.first().is_none_or(|secret| secret.is_empty()) {
            tracing::warn!(module = "github", "github login: opened without a client_secret; token exchanges omit it (check the OAuth App and secret reference if sign-in fails)");
        }
        Ok(instance)
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

/// REFUSED, said once at info with its reason word.
fn refused(reason: &'static str, why: &'static str) -> Outcome {
    tracing::info!(module = "github", reason, "github login: refused: {why}");
    Outcome::Refused
}

/// A lent string, `None` when absent or not UTF-8.
fn text(s: Lent<'_, AbiStr>) -> Option<&str> {
    if s.is_absent() {
        return None;
    }
    s.as_str().ok()
}

/// A lent blob as UTF-8, `None` when absent or not UTF-8.
fn blob_text(b: Lent<'_, Blob>) -> Option<&str> {
    if b.is_absent() {
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
            return refused("no-instance", "the op arrived on no open instance");
        };
        let (Some(redirect_uri), Some(state), Some(challenge)) = (
            text(input.redirect_uri()),
            text(input.state()),
            text(input.code_challenge()),
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

/// What a pending `complete_login` parks on its ticket: the login the flow began under, the flow,

struct Parked {
    login: Arc<GithubLogin>,
    flow: LoginFlow,
    wire: Option<Wire>,
    base: u32,
}

/// The login a resumed flow is driven by: the one it began under, to its end. A `refresh` swaps

fn driving(parked: &Parked) -> Arc<GithubLogin> {
    parked.login.clone()
}

/// The hop exchange over the instance's connector: one framed `exchange()` per hop on its selected need.
struct Over<'c, 'h> {
    c: &'c mut Connector<'h>,
    need: u32,
    wire: &'c mut Option<Wire>,
    base: &'c mut u32,
}

impl Exchange for Over<'_, '_> {
    fn exchange(&mut self, request: &HopRequest) -> Fetched {
        let Some((origin, _)) = split(&request.target) else {
            tracing::warn!(
                module = "github",
                "github login: a hop URL has no scheme and authority to send it to"
            );
            return Fetched::Unreachable;
        };
        if self.wire.is_none() {
            match request.wire(MAX_HOP_REPLY_BYTES) {
                Some(w) => *self.wire = Some(w),
                None => return Fetched::Unreachable,
            }
        }
        let Some(wire) = self.wire.as_mut() else {
            return Fetched::Unreachable;
        };
        match exchange(&mut *self.c, wire, self.need, Some(origin)) {
            Poll::Pending => Fetched::Pending,
            Poll::Ready(answer) => {
                *self.wire = None;
                *self.base = self.c.issued();
                match answer {
                    Ok(reply) => {
                        let mut reply = Zeroizing::new(reply);
                        Fetched::Ready(HopResponse {
                            status: reply.status,
                            fields: ReplyFields::kept(
                                reply
                                    .fields
                                    .iter()
                                    .map(|(n, v)| (n.as_slice(), v.as_slice())),
                            ),
                            body: Zeroizing::new(std::mem::take(&mut reply.body)),
                        })
                    }

                    Err(e) => {
                        tracing::warn!(module = "github", error = ?e, "github login: the hop exchange failed");
                        Fetched::Unreachable
                    }
                }
            }
        }
    }
}

/// No connector was lent (the instance's need was not carried): every hop is unreachable.
struct Unarmed;

impl Exchange for Unarmed {
    fn exchange(&mut self, _: &HopRequest) -> Fetched {
        tracing::warn!(
            module = "github",
            "github login: no connector lent: the instance's outbound http need was not granted"
        );
        Fetched::Unreachable
    }
}

/// Write `p` into the host's identity buffer and answer READY, or answer the short FAILED (every

fn identify(
    g: &Github,
    ticket: Ticket,
    p: Principal,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    let outcome = login_identity(&p, buf, out);
    if outcome == Outcome::Failed {
        let evicted = {
            let mut answered = g.answered();
            keep(&mut answered, ANSWERED_MAX, Instant::now(), ticket, p)
        };
        warn_evicted(evicted);
    }
    outcome
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
            return refused("no-instance", "the op arrived on no open instance");
        };
        let ticket = instance.ticket();
        if ticket.is_none() {
            return refused(
                "no-ticket",
                "complete_login arrived without a ticket (it waits on I/O); the host resubmits it on one",
            );
        }
        let g = h.life();
        let buf = input.out_buf();
        let (reached, expired) = {
            let mut answered = g.answered();
            let before = answered.len();
            let reached = take(&mut answered, Instant::now(), ticket);
            let expired = before - answered.len() - usize::from(reached.is_some());
            (reached, expired)
        };
        warn_evicted(expired);
        if let Some(p) = reached {
            return identify(g, ticket, p, buf, &mut out);
        }
        let mut parked = match instance.resume::<Parked>() {
            Some(p) => *p,
            None => {
                let login = g.login();
                Parked {
                    flow: login.start(
                        blob_text(input.code()),
                        text(input.redirect_uri()),
                        blob_text(input.code_verifier()),
                        text(input.nonce()),
                    ),
                    login,
                    wire: None,
                    base: 0,
                }
            }
        };
        let login = driving(&parked);
        let step = match h.host() {
            None => login.drive(&mut parked.flow, &mut Unarmed),
            Some(host) => {
                let mut c = host.connector_from(ticket, parked.base);
                let mut over = Over {
                    c: &mut c,
                    need: need_of(&login),
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
            LoginStep::Outage { retry_after } => login_outage(retry_after, buf, &mut out),
            other @ (LoginStep::BadCredential | LoginStep::SecurityCheckFailed) => {
                out.set(|o| &o.verdict, verdict(&other));
                Outcome::Ready
            }
        }
    }
}

/// The verdict a step that reached no identity answers.
fn verdict(step: &LoginStep) -> u32 {
    match step {
        LoginStep::Outage { .. } => LOGIN_OUTAGE,
        LoginStep::SecurityCheckFailed => LOGIN_SECURITY_CHECK_FAILED,
        LoginStep::BadCredential | LoginStep::Pending | LoginStep::Identity(_) => {
            LOGIN_BAD_CREDENTIAL
        }
    }
}

/// An auth op this plugin does not serve (`verify`, the outbound family): explained REFUSED.
#[derive(Debug)]
pub struct NotServed<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotServed<I, O> {
    type In = I;
    type Out = O;
    type State = Held<Github>;
    fn call(_: Instance<'_, Held<Github>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        refused(
            "unsupported-operation",
            "this plugin serves GitHub login operations only; verify and outbound auth are not supported",
        )
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
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "door_tests.rs"]
mod tests;
