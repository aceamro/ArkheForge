//! # ArkheForge Runtime Testkit
//!
//! Property-based test helpers for ArkheForge Runtime (theorist M4) —
//! proptest `Arbitrary` strategies plus a scope-based shrinker.
//!
//! The shrinker specializes in "structural minimization" of Runtime
//! primitives: it narrows a failure case down to the smallest reproducible
//! counterexample. "Scope-based" means one shrink path per TypeCode region
//! (core / shell / debug), so a range-boundary violation is pinned to its
//! originating region immediately.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod arbitrary;
pub mod shrink;

/// Testkit semver.
pub const TESTKIT_SEMVER: (u16, u16, u16) = (0, 12, 0);
