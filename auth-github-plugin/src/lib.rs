// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **GitHub-OAuth login module as a droppable busbar plugin**: the logic crate re-exported whole,
//! and its door (`busbar_auth_github::door::door`, the auth kind's table, login-capable) exported as
//! this image's ONE symbol, `busbar_plugin_door` (`export_door!`). Build it, drop the packed tarball
//! into the engine's plugins folder, add `github` to `auth.chain` with a `browser_login` block, and
//! configure the module `config`. The plugin holds its own client secret (the Statement's secret
//! reference) and runs the token exchange and the `/user` and `/user/orgs` reads over its own need.
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one reviewed
//! exemption (a `forbid` cannot be lifted for it). The logic crate is `#![forbid(unsafe_code)]` and
//! exports nothing, so a build that links it carries no door symbol.
#![deny(unsafe_code)]

pub use busbar_auth_github::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_github::door::door);
}
