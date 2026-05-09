//! Observer host — capability-bounded WASM sandbox for L2 projection
//! observers (E15 — Observer Capability Confinement).
//!
//! ## Spec anchor
//!
//! - **E15 Observer Capability Confinement** — Runtime axiom:
//!   - **E15.a** observer panic is contained at the sandbox boundary; the
//!     host catches the trap and emits an `ObserverQuarantine` event. No
//!     native unwind reaches the L0 chain (L0 A22 strengthening).
//!   - **E15.b** observer side-effects route exclusively through host-
//!     declared capability tokens; direct syscalls and `wasi-{fs, sockets,
//!     clocks, random}` are rejected at module-load.
//! - Observer path — L2 projection observers operate *post-commit*
//!   on already-chained data; they cannot mutate chain state.
//!
//! ## Chain-non-affecting invariant (cryptographer-anchored firm contract)
//!
//! Observer execution is *chain-non-affecting* by construction. Four
//! clauses establish the invariant; together they ensure observer panic /
//! capability-deny / module compromise cannot affect L0 chain integrity:
//!
//! 1. **No chain-mutation host-fn**: every binding under `arkhe:observer/*`
//!    is a side-effect to a non-chain destination (PG projection, metric
//!    sink, KMS rotation receipt). No binding calls `Op::EmitEvent`,
//!    `Op::SpawnEntity`, or any chain-head-write primitive.
//! 2. **Effect signature is chain-orthogonal**: every host-side
//!    [`capability_linker::ObserverCapability`] impl carries its effect to
//!    a layer *outside* the chain (projection / metric / vault). Enforced
//!    by the trait signature shape — the impl receives no chain reference.
//! 3. **Quarantine emission is host-supervised**: when an observer wasm
//!    traps, the *host* generates the `ObserverQuarantine` event. The
//!    observer *triggers* the emission via its trap, but does not
//!    *generate* it — the cryptographic chain anchor is host-owned.
//! 4. **Panic isolation preserves chain progression**: the wasmtime trap
//!    is caught at the host's invoke boundary; chain progression
//!    continues independently. The chain hash of the next tick is
//!    unaffected by observer existence or panic-state.
//!
//! ## L0↔Runtime boundary surface
//!
//! `observer_host/` is a *Runtime-layer* concept. It uses no L0 source —
//! the L0 [`KernelObserver`](arkhe_kernel::KernelObserver) trait is
//! referenced only as a conceptual anchor (`observer_host` exposes the
//! same `KernelEvent` observation pattern but inside a capability-bounded
//! WASM sandbox).
//!
//! ## Surface
//!
//! - [`ObserverHost`] trait + [`NoopObserverHost`] (default when sandbox-
//!   backed observer is not feature-gated).
//! - [`ObserverContext`] / [`ObserverError`] / [`ObserverTrapClass`].
//! - [`ObserverCapToken`] enum (`#[non_exhaustive]`) — currently a single
//!   variant `PgWrite`; additional capabilities can be added without
//!   breaking external matchers.
//! - `WasmtimeObserverHost` (feature `tier-2-observer-host-v2`) —
//!   wasmtime preview-2 sandbox with fuel-metered execution + capability-
//!   bounded `arkhe:observer/*` host-fn dispatch.

#[cfg(feature = "tier-2-observer-host-v2")]
pub mod capability_linker;
#[cfg(feature = "tier-2-observer-host-v2")]
pub mod wasmtime_observer;

/// Capability tokens an enabled observer may request from the host.
///
/// `#[non_exhaustive]` — additive expansion is non-breaking. Currently
/// a single variant (`PgWrite`); additional capabilities (KMS / metric /
/// etc.) can be added without breaking external matchers.
///
/// `Ord` / `PartialOrd` are required so `ObserverCapToken` can live in a
/// deterministic [`std::collections::BTreeSet`] (the host's per-observer
/// capability set — deterministic iteration matters for the call-time
/// capability check audit log).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObserverCapToken {
    /// `arkhe:observer/pg.write` — append a row to the operator's
    /// projection PostgreSQL table. Side-effect routes outside the chain.
    PgWrite,
}

// SealedCapToken safeguard. The observer `ObserverCapToken` enum
// implements both the private `Sealed` marker (only reachable from
// `arkhe-forge-platform`) and the public
// `wasm_runtime_common::ObserverCapTokenSealed` trait. External crates
// cannot satisfy the `Sealed` bound, so the observer-cap-token universe
// is closed at the host-defining crate boundary — preserving the E15.b
// chain-non-affecting clause at compile-time (observer side-effects
// route exclusively through observer-declared capabilities, never
// through hook surfaces or unknown external types).
//
// Compiled only when at least one wasmtime feature is enabled (matches
// `wasm_runtime_common`'s feature gate).
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
impl crate::wasm_runtime_common::sealed_impl::Sealed for ObserverCapToken {}
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
impl crate::wasm_runtime_common::ObserverCapTokenSealed for ObserverCapToken {}

/// Observer execution context — opaque to observers themselves; managed
/// by the host. Carries only the capability set; observers are read-only
/// sinks and do not mutate the submission pipeline (cf. hook host's
/// `ExtraBytesBuilder` thread).
///
/// **Chain-non-affecting clause 2 enforcement** (cryptographer-anchored):
/// this struct intentionally does NOT carry a reference to chain state,
/// chain head, or any Op-emit primitive. The borrow-checker enforces
/// that observer code can never construct a chain mutation through
/// `ctx`. Future field additions must preserve this invariant.
#[derive(Debug)]
pub struct ObserverContext<'b> {
    /// Capability tokens granted by the manifest for this observer
    /// invocation.
    pub capabilities: &'b [ObserverCapToken],
}

// `ObserverTrapClass` is re-exported from `arkhe-forge-core::event` —
// single source of truth lives in core because the value enters the L0
// chain via the `ObserverQuarantine` event. Re-export keeps the
// platform-side API surface stable for callers that imported from
// `arkhe_forge_platform::observer_host::ObserverTrapClass`.
pub use arkhe_forge_core::event::ObserverTrapClass;

/// Observer execution outcome.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ObserverError {
    /// Observer invocation exceeded the fuel budget. Surfaces only from
    /// sandbox-backed hosts; the no-op pass-through never returns this.
    #[error("observer budget exhausted")]
    BudgetExceeded,
    /// Observer tried to import a host-fn not in its capability set.
    /// Rejected at module-load (linker pre-scan) or at the call site
    /// (host-fn capability check).
    #[error("observer capability denied: {0:?}")]
    CapabilityDenied(ObserverCapToken),
    /// Observer invocation trapped at the sandbox boundary — the host
    /// catches and quarantines without propagating the unwind (E15.a
    /// strengthening of L0 A22).
    #[error("observer trap: {0}")]
    Trapped(&'static str),
    /// Observer was placed under quarantine. After repeated panic events
    /// (host policy threshold), the observer is removed from the active
    /// rotation and its module-digest blacklisted — terminal state
    /// distinct from per-invocation [`Self::Trapped`].
    #[error("observer quarantined")]
    Quarantined,
}

/// Capability-bounded observer host — runs a registered observer module
/// against a `KernelEvent` stream with side-effects gated by the
/// configured capability set.
///
/// # Backends
///
/// The runtime selects between two backends:
/// - [`NoopObserverHost`] (always available) — pass-through that
///   returns `Ok(())` without invoking any wasm.
/// - `WasmtimeObserverHost` (feature `tier-2-observer-host-v2`) —
///   wasmtime preview-2 sandbox with fuel-metered execution +
///   capability-bounded `arkhe:observer/*` host-fn dispatch.
pub trait ObserverHost {
    /// Invoke the observer bound to this host against the supplied
    /// context. Implementations may inspect `ctx.capabilities`; they
    /// may NOT — by construction — mutate any chain state. The return
    /// is informational only; chain progression is unaffected.
    fn invoke(&self, ctx: &mut ObserverContext<'_>) -> Result<(), ObserverError>;
}

/// Pass-through host — returns `Ok(())` without invoking any observer
/// logic. Default when sandbox-backed observer is not feature-gated.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserverHost;

impl NoopObserverHost {
    /// Construct a new no-op observer host.
    pub fn new() -> Self {
        Self
    }
}

impl ObserverHost for NoopObserverHost {
    fn invoke(&self, _ctx: &mut ObserverContext<'_>) -> Result<(), ObserverError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn noop_host_passes_through_ok() {
        let host = NoopObserverHost::new();
        let caps = [ObserverCapToken::PgWrite];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        assert!(host.invoke(&mut ctx).is_ok());
    }

    #[test]
    fn observer_cap_token_set_is_ordered_for_btreeset() {
        // PgWrite is currently the only variant; deterministic ordering
        // matters once additional variants are added. Round-trip into
        // a BTreeSet exercises the Ord / PartialOrd derives.
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(ObserverCapToken::PgWrite);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&ObserverCapToken::PgWrite));
    }

    #[test]
    fn observer_error_display_does_not_panic() {
        let errors = [
            ObserverError::BudgetExceeded,
            ObserverError::CapabilityDenied(ObserverCapToken::PgWrite),
            ObserverError::Trapped("test trap"),
            ObserverError::Quarantined,
        ];
        for e in errors {
            assert!(!format!("{e}").is_empty());
        }
    }

    #[test]
    fn observer_trap_class_variants_round_trip() {
        let classes = [
            ObserverTrapClass::Panic,
            ObserverTrapClass::BudgetExceeded,
            ObserverTrapClass::CapabilityDenied,
            ObserverTrapClass::Other,
        ];
        for c in classes {
            // Trivial round-trip — discriminator stays printable; copy
            // semantics work; equality is reflexive.
            assert_eq!(c, c);
            assert!(!format!("{c:?}").is_empty());
        }
    }

    /// Chain-non-affecting clause 2 (cryptographer-anchored): the
    /// `ObserverContext` carries only the capability set — no chain
    /// reference is reachable. The structural invariant ("no chain-
    /// mutation surface") is enforced by the type shape + review at
    /// PR time; this test is the runtime sanity check on the
    /// `capabilities` slice round-trip. Future field additions must
    /// not introduce a chain-mutation reference (PR review catch).
    #[test]
    fn observer_context_carries_only_capabilities() {
        let caps = [ObserverCapToken::PgWrite];
        let ctx = ObserverContext {
            capabilities: &caps,
        };
        assert_eq!(ctx.capabilities.len(), 1);
        assert_eq!(ctx.capabilities[0], ObserverCapToken::PgWrite);
    }
}
