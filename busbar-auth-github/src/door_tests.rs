// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::LOGIN_SECURITY_CHECK_FAILED;

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
