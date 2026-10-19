// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Held`] — a credential THIS PLUGIN holds in its own memory: the GitHub access token it receives
//! from the token endpoint, and the OAuth `state` nonce / confidential-client secret it keeps for the
//! duration of a login flow.
//!
//! These are the plugin's own material, not a value the kernel resolved and lent it, so they are not
//! the contract's sealed `Secret<T>` (busbar #1021: that type's one raw accessor takes a kernel seal,
//! which a plugin neither holds nor can obtain). `Held` keeps exactly the hygiene the plugin relied on
//! when it wrapped them in the contract's former redaction wrapper:
//!
//! * **`Debug` / `Display` never reveal it.** Both print the literal `"[REDACTED]"`.
//! * **It does not serialize.** `Held` implements neither `Serialize` nor `Deserialize`.
//! * **It zeroizes its backing memory on drop.**
//! * **Equality is constant-time** (the contract's `constant_time_eq` over the byte form).
//!
//! The value is reached ONLY through [`Held::reveal`]: every call site is an audit point where the
//! plaintext escapes on purpose.

use core::fmt;

use zeroize::Zeroize;

/// A credential this plugin holds. `Debug`/`Display` print `"[REDACTED]"`; it never serializes; its
/// backing memory is zeroized on drop. See the module docs.
pub(crate) struct Held<T: Zeroize>(T);

impl<T: Zeroize> Held<T> {
    /// Hold `secret`.
    pub(crate) fn new(secret: T) -> Self {
        Self(secret)
    }

    /// Borrow the held value. AUDIT POINT: the plaintext escapes redaction here.
    pub(crate) fn reveal(&self) -> &T {
        &self.0
    }
}

/// `Debug` NEVER reveals the value.
impl<T: Zeroize> fmt::Debug for Held<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// `Display` NEVER reveals the value either.
impl<T: Zeroize> fmt::Display for Held<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Drop for Held<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Held<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Equality on two held values is CONSTANT-TIME (the contract's `constant_time_eq`), never a
/// byte-by-byte compare with a data-dependent early exit.
impl<T: Zeroize + AsRef<[u8]>> PartialEq for Held<T> {
    fn eq(&self, other: &Self) -> bool {
        busbar_contract::constant_time_eq(&self.0, &other.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Held<T> {}

#[cfg(test)]
mod tests {
    use super::Held;

    #[test]
    fn debug_and_display_print_only_the_redaction_marker() {
        let h = Held::new(String::from("sk-live-plaintext"));
        assert_eq!(format!("{h:?}"), "[REDACTED]");
        assert_eq!(format!("{h}"), "[REDACTED]");
        assert_eq!(format!("{:?}", Some(&h)), "Some([REDACTED])");
        assert_eq!(h.reveal(), "sk-live-plaintext");
    }

    #[test]
    fn equality_compares_the_held_bytes() {
        let a = Held::new(String::from("same"));
        assert_eq!(a, a.clone());
        assert_ne!(a, Held::new(String::from("other")));
        assert_ne!(a, Held::new(String::from("sam")));
    }
}
