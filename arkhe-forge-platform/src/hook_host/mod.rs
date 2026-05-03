//! Hook host v2 — pre-submit capability-bounded extension point (spec
//! §5.3 / §14.5, v0.12 sealing cycle Track B).
//!
//! ## Hook contract (spec §5.3)
//!
//! Submit-side execution order:
//!
//! ```text
//! Auth & Quota → Hook (extra_bytes only) → Policy re-validation → Build → Submit
//! ```
//!
//! A hook can mutate **only** the [`ExtraBytesBuilder`] — every other
//! field of the in-flight submission (`actor`, `verb`, `target`,
//! `shell_id`, `principal`) is opaque to the hook. Post-hook policy
//! re-validation re-checks the same predicates as pre-hook — a hook that
//! edits extra bytes in a way that changes policy outcome is rejected
//! at the re-validation step (C8 / S1 confused-deputy defense).
//!
//! ## v1 alpha = pass-through no-op
//!
//! Per §14.5 v1 alpha, every concrete hook is OFF — the hook host runs
//! [`NoopHookHost`] which always returns `Ok(())` without mutating extra
//! bytes. This is the v0.12 first-cut scaffold. v2 (this module's
//! eventual full form) wires:
//!
//! - WASI preview-2 sandbox embedding (wasmtime `Engine` + `Linker`).
//! - 10 ms wall-clock budget enforced via wasmtime fuel.
//! - Resource limits (memory cap + table size cap).
//! - Capability-token whitelist (`arkhe:hook/{state, emit, fuel, ...}`)
//!   — the L2 paired enforcement of E14.L2-Allow-v0_12 (cryptographer
//!   detail anchors at §X.Y).
//! - Post-hook policy re-validation via the existing policy gate.
//!
//! ## Spec anchor
//!
//! - **E14 Compute Determinism Closure** (v0.12 도입, MC) — paired
//!   E14.L1-Deny (build-time AST deny-list) + E14.L2-Allow (runtime
//!   host-import allow-list, this module).
//! - **Track B (DIP-N1)** — Hook host v2 + 3-tier hook bytes ingestion.

use bytes::Bytes;

#[cfg(feature = "tier-2-hook-host-v2")]
pub mod capability_linker;
#[cfg(feature = "tier-2-hook-host-v2")]
pub mod wasmtime_host;

/// Mutable extra-bytes accumulator threaded through hook invocations.
/// Hooks may append; they cannot read prior policy-invariant fields.
/// Wraps the existing `bytes::BytesMut` shape so the L1 builder can
/// adopt it without re-allocating after the hook returns.
#[derive(Debug, Default)]
pub struct ExtraBytesBuilder {
    inner: bytes::BytesMut,
}

impl ExtraBytesBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a byte slice to the builder.
    pub fn append(&mut self, bytes: &[u8]) {
        self.inner.extend_from_slice(bytes);
    }

    /// Current accumulated length.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Empty check.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Freeze into an immutable [`Bytes`] for downstream submission build.
    pub fn freeze(self) -> Bytes {
        self.inner.freeze()
    }
}

/// Capability tokens an enabled hook may request from the host. The
/// v0.12 cut declares the shape; concrete imports land in Track B's
/// wasmtime integration sub-step. Each token grants permission to call
/// a single host-side function — non-whitelisted imports are rejected
/// at module-load (E14.L2-Allow enforcement).
///
/// `#[non_exhaustive]` — additive expansion is non-breaking
/// (impl-plan §6 / spec §3.2 forward-compat). `Ord`/`PartialOrd` are
/// required so `CapToken` can live in a deterministic
/// [`std::collections::BTreeSet`] (the `HookStoreData::capabilities`
/// container — deterministic iteration matters for the call-time
/// capability check audit log).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapToken {
    /// `arkhe:hook/state.read` — read the hook-scoped key/value scratchpad.
    StateRead,
    /// `arkhe:hook/state.write` — write the hook-scoped scratchpad.
    StateWrite,
    /// `arkhe:hook/emit.extra_bytes` — append into [`ExtraBytesBuilder`].
    EmitExtraBytes,
    /// `arkhe:hook/fuel.consumed` — query remaining fuel budget.
    FuelConsumed,
}

// M2.4 cycle (DIP-N6 Phase 2): SealedCapToken safeguard. The hook
// `CapToken` enum implements both the private `Sealed` marker (only
// reachable from `arkhe-forge-platform`) and the public
// `wasm_runtime_common::HookCapToken` trait. External crates cannot
// satisfy the `Sealed` bound, so the hook-cap-token universe is closed
// at the host-defining crate boundary — preserving the E14.L2-Allow
// rule 3 host-import allow-list integrity at compile-time.
//
// Compiled only when at least one wasmtime feature is enabled (matches
// `wasm_runtime_common`'s feature gate).
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
impl crate::wasm_runtime_common::sealed_impl::Sealed for CapToken {}
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
impl crate::wasm_runtime_common::HookCapTokenSealed for CapToken {}

/// Hook execution context — opaque to hooks themselves; managed by the
/// host. v0.12 cut carries only the capability set + the extra-bytes
/// builder; the wasmtime `Store` / `Caller<'_, _>` plumbing lands in
/// Track B's wasmtime integration sub-step.
#[derive(Debug)]
pub struct HookContext<'b> {
    /// Capability tokens granted by the manifest for this hook
    /// invocation.
    pub capabilities: &'b [CapToken],
    /// Extra-bytes builder threaded through Hook → Policy re-validation
    /// → L1 build.
    pub extra: &'b mut ExtraBytesBuilder,
}

/// Hook execution outcome.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// Hook invocation exceeded the 10 ms / fuel budget. v2-only — the
    /// v1 alpha pass-through never returns this.
    #[error("hook budget exhausted")]
    BudgetExceeded,
    /// Hook tried to import a host function not in its capability set.
    /// Rejected at module-load (v2) or call-site (v2 fallback).
    #[error("capability denied: {0:?}")]
    CapabilityDenied(CapToken),
    /// Hook invocation trapped — host catches and quarantines without
    /// propagating the unwind (analog of L0 A22).
    #[error("hook trap: {0}")]
    Trapped(&'static str),
    /// Post-hook policy re-validation rejected the mutated extra bytes
    /// (C8 confused-deputy defense — hook attempted to flip policy
    /// outcome).
    #[error("post-hook policy re-validation failed")]
    PolicyReValidationFailed,
}

/// Pre-submit hook host — the L2 service that runs registered hooks
/// against an in-flight submission's `extra_bytes` buffer.
///
/// # v1 alpha behaviour
///
/// Per §14.5 the v1 alpha host is [`NoopHookHost`] — every call returns
/// `Ok(())` without mutation. A future Track B sub-step replaces this
/// with `WasmtimeHookHost` (not yet shipped) that embeds wasmtime
/// preview-2 + WASI + fuel + capability-whitelisted host functions.
pub trait HookHost {
    /// Invoke the hook bound to the given submission. Implementations
    /// may mutate `ctx.extra`; they may read `ctx.capabilities`. v1
    /// alpha skips invocation entirely.
    fn invoke(&self, ctx: &mut HookContext<'_>) -> Result<(), HookError>;
}

/// v1 alpha pass-through host — returns `Ok(())` without mutating extra
/// bytes. The §5.3 diagram's "Hook host" box runs this implementation
/// in v0.12. v2 replaces this with a wasmtime-backed sandbox.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopHookHost;

impl NoopHookHost {
    /// New no-op host.
    pub fn new() -> Self {
        Self
    }
}

impl HookHost for NoopHookHost {
    fn invoke(&self, _ctx: &mut HookContext<'_>) -> Result<(), HookError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extra_bytes_builder_append_and_freeze() {
        let mut b = ExtraBytesBuilder::new();
        assert!(b.is_empty());
        b.append(b"hello ");
        b.append(b"world");
        assert_eq!(b.len(), 11);
        let frozen = b.freeze();
        assert_eq!(&frozen[..], b"hello world");
    }

    #[test]
    fn noop_host_passes_through_without_mutation() {
        let host = NoopHookHost::new();
        let mut extra = ExtraBytesBuilder::new();
        extra.append(b"prefix");
        let caps = [CapToken::EmitExtraBytes];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        assert!(host.invoke(&mut ctx).is_ok());
        // Pass-through must not have mutated extra bytes.
        assert_eq!(extra.len(), 6);
    }

    #[test]
    fn cap_token_v0_12_set_round_trips() {
        // Each currently-shipped `CapToken` variant is reachable + has
        // a stable `Debug` discriminator. External crates must wildcard
        // because the enum is `#[non_exhaustive]` (additive expansion is
        // non-breaking — see impl-plan §6).
        let tokens = [
            CapToken::StateRead,
            CapToken::StateWrite,
            CapToken::EmitExtraBytes,
            CapToken::FuelConsumed,
        ];
        for t in tokens {
            // Trivial round-trip — discriminator stays printable; copy
            // semantics work; equality is reflexive.
            assert_eq!(t, t);
            assert!(!format!("{t:?}").is_empty());
        }
    }

    #[test]
    fn hook_error_display_does_not_panic() {
        let errors = [
            HookError::BudgetExceeded,
            HookError::CapabilityDenied(CapToken::StateRead),
            HookError::Trapped("unexpected"),
            HookError::PolicyReValidationFailed,
        ];
        for e in errors {
            assert!(!format!("{e}").is_empty());
        }
    }
}
