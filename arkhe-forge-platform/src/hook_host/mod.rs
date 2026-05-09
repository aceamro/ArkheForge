//! Hook host — pre-submit capability-bounded extension point.
//!
//! ## Hook contract
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
//! at the re-validation step (confused-deputy defense).
//!
//! ## Two implementations
//!
//! - **[`NoopHookHost`]** (always compiled): pass-through that returns
//!   `Ok(())` without mutating extra bytes. Selected when the runtime
//!   does not opt in to a sandbox-backed hook.
//! - **`WasmtimeHookHost`** (feature `tier-2-hook-host-v2`): wasmtime
//!   preview-2 sandbox with fuel-metered execution, capability-token
//!   whitelist (`arkhe:hook/{state, emit, fuel}`), and 4-set host-fn
//!   surface enforcing E14.L2-Allow at runtime. See
//!   [`wasmtime_host`] (feature-gated) for the concrete sandbox host.
//!
//! Both implement the [`HookHost`] trait, so submit-side callers stay
//! agnostic of the active backend.
//!
//! ## Spec anchor
//!
//! - **E14 Compute Determinism Closure** — paired E14.L1-Deny
//!   (build-time AST deny-list) + E14.L2-Allow (runtime host-import
//!   allow-list, this module).
//! - **Hook-host 3-tier ingestion** — BLAKE3 digest pin (sigstore +
//!   cargo-vet attestation tiers route through
//!   [`wasmtime_host::HookAttestationVerifier`]).

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

/// Capability tokens an enabled hook may request from the host. Each
/// token grants permission to call a single host-side function — non-
/// whitelisted imports are rejected at module-load (E14.L2-Allow
/// enforcement).
///
/// `#[non_exhaustive]` — additive expansion is non-breaking (TypeCode
/// forward-compat). `Ord`/`PartialOrd` are required so `CapToken` can
/// live in a deterministic [`std::collections::BTreeSet`] (the
/// `HookStoreData::capabilities` container — deterministic iteration
/// matters for the call-time capability check audit log).
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

// SealedCapToken safeguard. The hook `CapToken` enum implements both
// the private `Sealed` marker (only reachable from
// `arkhe-forge-platform`) and the public
// `wasm_runtime_common::HookCapTokenSealed` trait. External crates
// cannot satisfy the `Sealed` bound, so the hook-cap-token universe is
// closed at the host-defining crate boundary — preserving the
// E14.L2-Allow rule 3 host-import allow-list integrity at compile-time.
//
// Compiled only when at least one wasmtime feature is enabled (matches
// `wasm_runtime_common`'s feature gate).
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
impl crate::wasm_runtime_common::sealed_impl::Sealed for CapToken {}
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
impl crate::wasm_runtime_common::HookCapTokenSealed for CapToken {}

/// Hook execution context — opaque to hooks themselves; managed by the
/// host. Carries the capability set + the extra-bytes builder; sandbox-
/// backed hosts (`WasmtimeHookHost`) thread these into a per-invocation
/// wasmtime `Store` / `Caller<'_, _>` internally.
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
    /// Hook invocation exceeded the 10 ms / fuel budget. Surfaces only
    /// from sandbox-backed hosts; the no-op pass-through never returns
    /// this.
    #[error("hook budget exhausted")]
    BudgetExceeded,
    /// Hook tried to import a host function not in its capability set.
    /// Rejected at module-load (sandbox-backed host) or as a call-site
    /// fallback.
    #[error("capability denied: {0:?}")]
    CapabilityDenied(CapToken),
    /// Hook invocation trapped — host catches and quarantines without
    /// propagating the unwind (analog of L0 A22).
    #[error("hook trap: {0}")]
    Trapped(&'static str),
    /// Post-hook policy re-validation rejected the mutated extra bytes
    /// (confused-deputy defense — hook attempted to flip policy
    /// outcome).
    #[error("post-hook policy re-validation failed")]
    PolicyReValidationFailed,
}

/// Pre-submit hook host — the L2 service that runs registered hooks
/// against an in-flight submission's `extra_bytes` buffer.
///
/// # Backends
///
/// The runtime selects between two backends:
/// - [`NoopHookHost`] (always available) — pass-through that returns
///   `Ok(())` without mutation.
/// - `WasmtimeHookHost` (feature `tier-2-hook-host-v2`) — wasmtime
///   preview-2 sandbox with fuel-metered execution + capability-
///   whitelisted host-fns.
pub trait HookHost {
    /// Invoke the hook bound to the given submission. Implementations
    /// may mutate `ctx.extra`; they may read `ctx.capabilities`. The
    /// no-op pass-through skips invocation entirely.
    fn invoke(&self, ctx: &mut HookContext<'_>) -> Result<(), HookError>;
}

/// Pass-through host — returns `Ok(())` without mutating extra bytes.
/// The Hook host box in the contract diagram runs this implementation when
/// the runtime is not configured for sandbox-backed hooks.
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
    fn cap_token_set_round_trips() {
        // Each currently-shipped `CapToken` variant is reachable + has
        // a stable `Debug` discriminator. External crates must wildcard
        // because the enum is `#[non_exhaustive]` (additive expansion
        // is non-breaking — see TypeCode reservation policy).
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
