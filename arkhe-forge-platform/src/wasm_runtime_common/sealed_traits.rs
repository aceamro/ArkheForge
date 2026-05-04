//! Sealed-trait pattern for `wasm_runtime_common`.
//!
//! Three parallel sealed traits sharing one private super-trait:
//! - [`HookCapTokenSealed`] / [`ObserverCapTokenSealed`] — capability-
//!   token enum markers (anchor: `CapTokenSealed` INV / E15.b
//!   chain-non-affecting clause).
//! - [`SealedHostImport`] — host-linker type marker (anchor:
//!   `HostImportSealed` INV / E14.L2-Allow rule 3 host-import 4-set).
//!
//! Pattern: single private `private_seal::Sealed` super-trait, only
//! same-crate types impl via [`sealed_impl`] re-export module. External
//! crates cannot name the private marker so cannot satisfy the bound,
//! preserving the cap-token universe + host-import 4-set closure at
//! compile time.
//!
//! **Single-private-marker pattern**: one `private_seal::Sealed` super-
//! trait with sub-trait bounds providing structural distinction at type
//! level (cap-tokens carry `Ord + Copy + Clone + Debug + Hash +
//! 'static`; host-linker types carry no extra bounds).

/// Sealed-trait pattern internals — `private_seal::Sealed` is private
/// to `wasm_runtime_common`, so external crates cannot implement
/// [`HookCapTokenSealed`], [`ObserverCapTokenSealed`], or [`SealedHostImport`]
/// (only types defined within `arkhe-forge-platform` can satisfy the
/// bound).
///
/// **Closure safeguard**: the compile-time invariant that the cap-token
/// universe (`HookCapTokenSealed` / `ObserverCapTokenSealed`) and the
/// host-linker universe (`SealedHostImport`) are both closed at the
/// host-defining crate boundary. Single private marker, sub-trait
/// bounds preserve structural distinction at type level.
mod private_seal {
    /// Private marker trait — sealed-trait pattern entry point. No
    /// public constructor, no public access; external crates cannot
    /// name this trait so cannot implement it.
    //
    // `dead_code` allowed: marker trait carries no methods. Rust's
    // dead-code lint flags marker traits since they aren't "called",
    // but the trait IS the safeguard mechanism (its presence as a
    // bound is what prevents external impls of `HookCapTokenSealed` /
    // `ObserverCapTokenSealed` / `SealedHostImport`). Compile-time
    // witness tests in mod.rs `tests::{hook,observer}_cap_token_satisfies_sealed_bound`
    // and `tests::{hook,observer}_capability_linker_satisfies_sealed_host_import`
    // verify the bound holds for the host concrete types.
    #[allow(dead_code)]
    pub trait Sealed {}
}

/// Sealed marker trait for **hook-host** capability-token enums.
///
/// Only types implementing [`private_seal::Sealed`] (a private sub-module
/// trait) satisfy the bound — and only the host-defining crate
/// (`arkhe-forge-platform`) can extend `Sealed`. External crates cannot
/// add new hook-cap-token types without forking, preserving the
/// **E14.L2-Allow rule 3** host-import allow-list integrity at
/// compile-time.
///
/// Bounds (`Ord + Copy + Clone + Debug + Hash + 'static`) reflect the
/// canonical use site `BTreeSet<Cap>` (deterministic iteration matters
/// for the call-time capability check audit log) + zero-cost copy
/// semantics for token comparisons.
//
// `dead_code` allowed: marker trait pattern. Used as a bound in
// `tests::assert_hook_cap_token_sealed::<C>()` compile-time witness;
// future generic refactors (StoreData<Cap, Extra>) will use it as a
// where-bound. Rust dead-code lint doesn't account for sealed-marker
// patterns where the safeguard is structural, not operational.
#[allow(dead_code)]
pub trait HookCapTokenSealed:
    private_seal::Sealed + Ord + Copy + Clone + std::fmt::Debug + std::hash::Hash + 'static
{
}

/// Sealed marker trait for **observer-host** capability-token enums.
///
/// Mirrors [`HookCapTokenSealed`] but distinct trait — type-system enforces
/// hook ↔ observer cap-token separation. An observer host cannot
/// receive a hook cap-token at compile time (and vice versa),
/// preserving the **E15.b** chain-non-affecting clause: observer
/// side-effects route exclusively through observer-declared
/// `ObserverCapability` impls, and never through hook-side capability
/// surfaces.
///
/// Bounds match [`HookCapTokenSealed`] for the symmetric `BTreeSet<Cap>` use
/// site rationale.
//
// `dead_code` allowed: same rationale as `HookCapTokenSealed` —
// marker trait pattern, used as a bound in compile-time witness tests
// + future generic refactor surface.
#[allow(dead_code)]
pub trait ObserverCapTokenSealed:
    private_seal::Sealed + Ord + Copy + Clone + std::fmt::Debug + std::hash::Hash + 'static
{
}

/// Sealed marker trait for **host-linker** types.
///
/// Hook `CapabilityLinker` + Observer `ObserverCapabilityLinker` impl
/// this marker. The bound requires the private
/// [`private_seal::Sealed`] marker which only types defined in
/// `arkhe-forge-platform` can impl — preserving the **HostImports
/// compile-time invariant**: the wasmtime host-fn import surface (4-set:
/// state.read / state.write / emit.extra_bytes / fuel.consumed for hook;
/// 0 for chain-non-affecting observer) universe is closed at the
/// host-defining crate boundary.
///
/// External crates cannot fork the `WasmtimeHookHost` /
/// `WasmtimeObserverHost` host-linker structure with their own linker
/// type, preventing runtime-level invariant violations via type-system
/// enforcement.
//
// `dead_code` allowed: marker trait pattern. Used as a bound in
// `tests::assert_sealed_host_import::<L>()` compile-time witness;
// future generic refactors (`WasmtimeHostBase<L: SealedHostImport>`)
// will use it as a where-bound. Rust dead-code lint doesn't account
// for sealed-marker patterns where the safeguard is structural.
#[allow(dead_code)]
pub trait SealedHostImport: private_seal::Sealed {}

/// Sealed-trait re-export module — provides controlled access to
/// [`private_seal::Sealed`] for **same-crate** impls. Hook + observer
/// concrete types (capability-token enums + host-linker structs) impl
/// `Sealed` via this re-export; external crates cannot name the trait
/// so cannot impl it (sealed-trait pattern enforced at module privacy
/// boundary).
///
/// **Single re-export**: same-crate types impl `sealed_impl::Sealed`
/// for both cap-tokens and host-linkers. Sub-trait bound differences
/// provide structural separation at the type level.
pub(crate) mod sealed_impl {
    pub(crate) use super::private_seal::Sealed;
}
