//! Shell brand — compile-time per-shell type isolation (spec §3.7).
//!
//! Cross-shell references fail the type checker long before `submit()` reaches
//! the kernel. The replay path adds a runtime `ctx.read` double-check (E7
//! dual-tier) against storage-layer `ActorProfile.shell_id`, closing the
//! brand-bypass gap that arises when admin tools reconstruct primitives from
//! raw ECS state.

use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

/// Shell identity — 16-byte handle assigned when a shell manifest is loaded.
///
/// Canonical wire bytes are the inner `[u8; 16]` (transparent serde). Distinct
/// shells on the same Runtime get non-colliding `ShellId`s via the world-seed
/// entropy path (spec §4.7); cross-runtime collision is scoped away by
/// `InstanceId` in the id-derivation function.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShellId(pub [u8; 16]);

/// Compile-time shell brand (invariant-lifetime pattern, Yanovski et al. 2021).
///
/// `PhantomData<fn(&'s ()) -> &'s ()>` forces lifetime invariance —
/// `ShellBrand<'a>` and `ShellBrand<'b>` cannot unify, so a primitive branded
/// under one shell cannot be passed to a function expecting another shell's
/// brand. Obtain a fresh brand via [`ShellBrand::run`].
pub struct ShellBrand<'s> {
    _brand: PhantomData<fn(&'s ()) -> &'s ()>,
}

impl<'s> Clone for ShellBrand<'s> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
impl<'s> Copy for ShellBrand<'s> {}

impl core::fmt::Debug for ShellBrand<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShellBrand<'_>")
    }
}

impl ShellBrand<'static> {
    /// Open a fresh shell-branded scope. The `for<'s>` higher-rank bound pins
    /// the brand's lifetime to the closure, so it cannot escape — two
    /// independent `run` invocations yield incompatible brands.
    ///
    /// ```
    /// use arkhe_forge_core::brand::ShellBrand;
    /// let out = ShellBrand::run(|_brand| 42);
    /// assert_eq!(out, 42);
    /// ```
    #[inline]
    pub fn run<R, F>(f: F) -> R
    where
        F: for<'s> FnOnce(ShellBrand<'s>) -> R,
    {
        f(ShellBrand {
            _brand: PhantomData,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn shell_id_is_copy_and_eq() {
        let a = ShellId([0x11; 16]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn shell_brand_scope_returns_closure_value() {
        assert_eq!(ShellBrand::run(|_| 7i32), 7);
    }

    #[test]
    fn shell_brand_is_zero_sized() {
        assert_eq!(core::mem::size_of::<ShellBrand<'static>>(), 0);
    }
}
