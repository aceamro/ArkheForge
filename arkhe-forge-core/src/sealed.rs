//! Internal sealed-trait machinery — **not part of the public API**.
//!
//! The trait below is exposed through the [`crate::__sealed`] module (note
//! the `__` prefix and `#[doc(hidden)]` attribute) so the
//! `arkhe-forge-macros` derives can emit `impl __Sealed for UserType {}`.
//! This is the same soft-seal convention used by `pin-project-lite`,
//! `thiserror`, and `tokio` — naming + visibility hide the trait from
//! downstream crates while keeping the derive-emitted path resolvable.
//!
//! Manual downstream impls defeat the seal and are caught by the runtime
//! dylint CI gate (`arkhe-trait-default-check`); never write
//! `impl __Sealed for X` by hand.

/// Sealed marker — derive-macro-only, soft-sealed via `__` naming.
///
/// Any `pub` item accessible to a downstream crate can technically be
/// implemented from that crate, so a true compile-time seal is impossible
/// when the impl must come from a derive-macro expansion. The combination
/// of `#[doc(hidden)]`, the `__` prefix, and the dylint CI gate makes
/// accidental external implementations the only realistic failure mode,
/// and CI catches that.
#[doc(hidden)]
pub trait __Sealed {}
