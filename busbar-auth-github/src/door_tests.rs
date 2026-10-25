// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn security_check_failed_is_its_own_verdict() {
    assert_eq!(
        verdict(&LoginStep::SecurityCheckFailed),
        LOGIN_SECURITY_CHECK_FAILED
    );
}

#[test]
fn other_steps_keep_their_verdicts() {
    assert_eq!(verdict(&LoginStep::BadCredential), LOGIN_BAD_CREDENTIAL);
    assert_eq!(verdict(&LoginStep::Outage), LOGIN_OUTAGE);
}

fn who(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        name: None,
        roles: Vec::new(),
        ttl_secs: None,
    }
}

fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: n,
        generation: 1,
    }
}

#[test]
fn a_full_answered_map_evicts_only_the_oldest() {
    let t0 = Instant::now();
    let at = |n: u32| t0 + std::time::Duration::from_millis(u64::from(n));
    let mut map = Answered::new();
    for n in 1..=3 {
        keep(&mut map, 3, at(n), ticket(n), who(&format!("u{n}")));
    }
    keep(&mut map, 3, at(4), ticket(4), who("u4"));
    assert_eq!(map.len(), 3);
    assert!(!map.contains_key(&ticket(1)), "the oldest is evicted");
    for n in 2..=4 {
        assert!(map.contains_key(&ticket(n)), "ticket {n} is kept");
    }
}

#[test]
fn a_ticket_kept_again_does_not_evict() {
    let t0 = Instant::now();
    let mut map = Answered::new();
    keep(&mut map, 2, t0, ticket(1), who("a"));
    keep(&mut map, 2, t0, ticket(2), who("b"));
    keep(&mut map, 2, t0, ticket(2), who("b2"));
    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&ticket(1)));
}
