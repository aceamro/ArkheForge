//! Internal sealed-trait machinery — **not part of the public API**.
//!
//! The trait below is exposed through the [`crate::__sealed`] module (note
//! the `__` prefix and `#[doc(hidden)]` attribute) so the
//! `arkhe-forge-macros` derives can emit `impl __Sealed for UserType {}`.
//! This is the same convention-seal used by `pin-project-lite`,
//! `thiserror`, and `tokio` — naming + visibility hide the trait from
//! downstream crates while keeping the derive-emitted path resolvable.
//!
//! ## Why this is a convention seal, not a compile-time hard seal
//!
//! The `#[derive(ArkheEvent/ArkheComponent/ArkheAction)]` macros live in the
//! separate `arkhe-forge-macros` crate and emit the `impl __Sealed for T {}`
//! line into the **downstream** crate that invokes the derive. For that
//! emitted impl to compile, [`__Sealed`] must be name-reachable from
//! downstream code via the `::arkhe_forge_core::__sealed` path. Rust's name
//! resolution cannot distinguish macro-emitted code from hand-written code:
//! any path the derive reaches, a hand-written downstream `impl __Sealed for
//! Evil {}` reaches identically. The usual "hard seal" idioms (a private
//! constructor token, a sealed method returning a crate-private type) do not
//! close this gap either — the token constructor must itself be `pub`-reachable
//! for the cross-crate derive to call it, so a downstream attacker can call it
//! too. The kernel reaches the same conclusion for its own `_sealed::Sealed`
//! (`arkhe_kernel::state::traits`).
//!
//! Net: a true compile-time seal is unattainable while the impl is emitted by
//! a derive macro in a sibling crate. The seal is therefore a documented
//! convention — `#[doc(hidden)]` + the `__` prefix keep it out of downstream
//! autocompletion and rustdoc, making an accidental external impl effectively
//! impossible and a deliberate one obvious in review. Never write
//! `impl __Sealed for X` by hand.

/// Sealed marker — derive-macro-only, convention-sealed via `__` naming.
///
/// Any `pub` item name-reachable from a downstream crate can be implemented
/// from that crate, and the impl here must come from a derive-macro expansion
/// in the sibling `arkhe-forge-macros` crate, so a true compile-time seal is
/// unattainable (see the module-level docs). `#[doc(hidden)]` plus the `__`
/// prefix keep the trait off downstream surfaces, making accidental external
/// implementations effectively impossible and deliberate ones review-visible.
#[doc(hidden)]
pub trait __Sealed {}
