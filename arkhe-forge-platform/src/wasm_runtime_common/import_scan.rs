//! Module import pre-scan with allow-list + WIT-boundary deny-list
//! shared across hook + observer hosts (M2.3 cycle DRY consolidation,
//! DIP-N6 Phase 2).
//!
//! Anchor: **E14.L2-Allow rule 3** (host-import allow-list) + **E15.b**
//! (observer capability confinement). The single 7-prefix WASI deny set
//! [`WASI_DENY_PREFIXES`] is shared between hook + observer hosts.

use bytes::Bytes;
use wasmtime::{Engine, Module};

/// Pre-scan a module's imports against an allow-list + WIT-boundary
/// deny-list. Returns the parsed [`Module`] on success (callers reuse
/// it for instantiation rather than re-parsing).
///
/// **WIT-boundary match** (cryptographer C1 v0.12, DIP-N1 B.3.a):
/// deny prefixes must terminate at a real namespace boundary —
/// `/` (sub-namespace), `@` (version qualifier) or end-of-string.
/// This stops a hypothetical `wasi:randomly-pure` from being
/// mis-attributed to the `wasi:random` deny-list; it falls through
/// to the allow-list catch-all (still rejected, but with the correct
/// "not in allow-list" reason).
///
/// `audit_allow_message` is the human-readable allow-list summary
/// used in the catch-all rejection reason (e.g.,
/// `"only `arkhe:hook/*` permitted"`); host-specific so audit logs
/// cleanly distinguish hook vs observer rejections.
pub(crate) fn scan_module_imports(
    engine: &Engine,
    bytes: &Bytes,
    allow_prefixes: &[&str],
    deny_prefixes: &[&str],
    audit_allow_message: &str,
) -> Result<Module, ScanImportsError> {
    let module =
        Module::from_binary(engine, bytes.as_ref()).map_err(|e| ScanImportsError::ParseFailed {
            reason: format!("{e}"),
        })?;
    for imp in module.imports() {
        let module_field = imp.module();
        // (1) explicit deny-list — WIT-boundary match.
        for denied in deny_prefixes {
            if let Some(trailing) = module_field.strip_prefix(denied) {
                let at_boundary =
                    trailing.is_empty() || trailing.starts_with('/') || trailing.starts_with('@');
                if at_boundary {
                    return Err(ScanImportsError::ImportRejected {
                        name: format!("{}::{}", module_field, imp.name()),
                        reason: format!("denied namespace `{denied}`"),
                    });
                }
            }
        }
        // (2) allow-list catch-all.
        let allowed = allow_prefixes.iter().any(|p| module_field.starts_with(p));
        if !allowed {
            return Err(ScanImportsError::ImportRejected {
                name: format!("{}::{}", module_field, imp.name()),
                reason: format!("not in allow-list ({audit_allow_message})"),
            });
        }
    }
    Ok(module)
}

/// Result variants from [`scan_module_imports`]. Each host wraps these
/// into its own error enum (`HookHostError` / `ObserverHostError`) so
/// callers see typed surface specific to their context.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum ScanImportsError {
    /// Wasmtime [`Module::from_binary`] rejected the bytes.
    #[error("module parse failed: {reason}")]
    ParseFailed {
        /// Underlying error stringified.
        reason: String,
    },
    /// An import landed in the deny-list or outside the allow-list.
    #[error("import rejected: {name} — {reason}")]
    ImportRejected {
        /// Fully-qualified `module::name` import path.
        name: String,
        /// Pre-scan rejection reason (deny-list match or allow-list miss).
        reason: String,
    },
}

/// Single source of truth for the WASI module-namespace deny-list
/// shared across hook + observer hosts (M2.3 cycle DRY consolidation,
/// DIP-N6 Phase 2). The 7-prefix deny set is **identical** for hook and
/// observer — both hosts re-export this constant via
/// `pub use crate::wasm_runtime_common::WASI_DENY_PREFIXES as
/// DENIED_IMPORT_MODULE_PREFIXES;`.
///
/// **E14.L2-Allow rule 3** (host-import allow-list) + **E15.b**
/// (observer capability confinement): WASI module imports are rejected
/// at module-load. Pure defense-in-depth — the host-specific allow-list
/// (`arkhe:hook/*` or `arkhe:observer/*`) already excludes every WASI
/// prefix; the deny-list adds a *specific* `denied namespace` error so
/// the audit log distinguishes intentional WASI-import attempts from
/// generic allow-list misses.
///
/// Covered prefixes (verbatim 7-element set):
///
/// - `wasi:random` / `wasi:clocks` — determinism-critical surfaces
///   (E14.L2-Allow direct violations).
/// - `wasi:filesystem` / `wasi:sockets` / `wasi:io` / `wasi:cli` /
///   `wasi:http` — host I/O surfaces that bypass the cap-token audit
///   log; no sandbox-side wasm should reach them.
///
/// **theorist 6th condition (M2.3 verify gate)**:
/// - (a) compile-time const, runtime mutation 불가
/// - (b) hook + observer 양쪽 호출이 동일 const reference
/// - (c) cfg(feature) gate 으로 일부 prefix 제외 0 — 모든 build profile
///   에서 7 prefix 전부 enabled 보장
/// - (d) PR verify gate: `grep -c 'WASI_DENY_PREFIXES' arkhe-forge-platform/src/**/*.rs`
///   → 1 정의 + 2 use (re-export) site = 3 hits 정확
///
/// Cryptographer C7 v0.12. Maintenance: review on every wasmtime
/// version bump (fail-closed even when out of sync via allow-list
/// catch-all, but specific-error classification is preferred).
pub const WASI_DENY_PREFIXES: &[&str] = &[
    "wasi:random",
    "wasi:clocks",
    "wasi:filesystem",
    "wasi:sockets",
    "wasi:io",
    "wasi:cli",
    "wasi:http",
];
