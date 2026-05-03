//! Module registration shared across hook + observer hosts (M2.2 cycle,
//! DIP-N6 Phase 2). Single source of truth for the 3-tier ingestion
//! path Tier 1 — BLAKE3 digest pin + WASI deny + arkhe-prefix
//! allow-list.
//!
//! **M2.7 + M2.8 strengthening**: digest comparison uses
//! [`blake3::Hash::eq`] PartialEq — constant-time via `constant_time_eq_32`,
//! eliminating the timing-leak risk of raw byte-array `==` short-circuit
//! comparison without introducing a new dependency.

use bytes::Bytes;
use wasmtime::{Engine, Module};

use super::import_scan::{scan_module_imports, ScanImportsError};

/// Result variants from [`register_module_common`]. Each host wraps
/// these into its own error enum (`HookHostError` / `ObserverHostError`)
/// via `From<RegistrationError>` so callers see typed surface specific
/// to their context (M2.2 register_module DRY, DIP-N6 Phase 2).
///
/// The variants are flat (digest mismatch + scan failure cases) rather
/// than nested (`ScanFailed(ScanImportsError)`) so the host error enums
/// can map 1:1 without a nested-match ladder. Source-of-truth for the
/// 3-tier ingestion path Tier 1 (BLAKE3 digest pin + import allow-list
/// pre-scan) error surface.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum RegistrationError {
    /// BLAKE3 digest mismatch — bytes hash to a different value than
    /// the operator-pinned `expected_digest`. Operator-recoverable:
    /// re-deploy with matching module bytes, or correct the manifest's
    /// `digest_b3` field.
    #[error("module digest mismatch — expected {expected:?}, actual {actual:?}")]
    DigestMismatch {
        /// The BLAKE3 digest the operator expected (manifest-anchored).
        /// M2.8 cycle (DIP-N6 Phase 2): typed as `blake3::Hash` (was
        /// `[u8; 32]`) to propagate type-strengthening from the
        /// canonical hash function. M2.7 cycle benefits automatically:
        /// `blake3::Hash::eq` PartialEq is constant-time via
        /// `constant_time_eq_32`, eliminating the timing-leak risk of
        /// raw byte-array `==` short-circuit comparison.
        expected: blake3::Hash,
        /// The BLAKE3 digest the host computed from the supplied bytes.
        actual: blake3::Hash,
    },
    /// Wasmtime [`Module::from_binary`] rejected the bytes as non-wasm
    /// (corrupt / truncated / non-wasm format).
    #[error("module parse failed: {reason}")]
    ParseFailed {
        /// Underlying error stringified.
        reason: String,
    },
    /// Module imports landed outside the allow-list or inside the
    /// deny-list. Operator-recoverable: rebuild without the offending
    /// import.
    #[error("module import rejected: {name} — {reason}")]
    ImportRejected {
        /// Fully-qualified `module::name` import path.
        name: String,
        /// Pre-scan rejection reason (deny-list match or allow-list miss).
        reason: String,
    },
}

/// Register a wasm module against the operator-pinned digest + import
/// allow-list. Single source of truth for the 3-tier ingestion path
/// Tier 1 (BLAKE3 digest pin + WASI deny + arkhe-prefix allow-list)
/// shared across hook + observer hosts (M2.2 register_module DRY,
/// DIP-N6 Phase 2).
///
/// # Steps (in order)
///
/// 1. Compute `blake3::hash(bytes)` — host-side, per cryptographer
///    Q-M2.2-A (Tier 1 ingestion model = host trust root).
/// 2. Reject with [`RegistrationError::DigestMismatch`] if the computed
///    digest does not equal `expected_digest`.
/// 3. Delegate to [`scan_module_imports`] for the parse + allow/deny
///    pre-scan; convert [`ScanImportsError`] variants to
///    [`RegistrationError::ParseFailed`] / [`RegistrationError::ImportRejected`].
/// 4. Return the parsed [`Module`] for caller storage.
///
/// **M2.7 + M2.8 strengthening (DIP-N6 Phase 2)**: digest comparison
/// uses `blake3::Hash::eq` PartialEq — constant-time via
/// `constant_time_eq_32`. Eliminates the timing-leak risk of raw
/// byte-array `==` short-circuit comparison without introducing a new
/// dependency (`subtle` crate avoidable — blake3 1.5+ ships its own
/// constant-time PartialEq impl). M2.8 propagates the `blake3::Hash`
/// type through the host-host signature boundary; M2.7 benefits
/// automatically from the type's PartialEq semantics.
pub(crate) fn register_module_common(
    engine: &Engine,
    bytes: &Bytes,
    expected_digest: blake3::Hash,
    allow_prefixes: &[&str],
    deny_prefixes: &[&str],
    audit_allow_message: &str,
) -> Result<Module, RegistrationError> {
    let actual = blake3::hash(bytes.as_ref());
    if actual != expected_digest {
        return Err(RegistrationError::DigestMismatch {
            expected: expected_digest,
            actual,
        });
    }
    scan_module_imports(
        engine,
        bytes,
        allow_prefixes,
        deny_prefixes,
        audit_allow_message,
    )
    .map_err(|e| match e {
        ScanImportsError::ParseFailed { reason } => RegistrationError::ParseFailed { reason },
        ScanImportsError::ImportRejected { name, reason } => {
            RegistrationError::ImportRejected { name, reason }
        }
    })
}
