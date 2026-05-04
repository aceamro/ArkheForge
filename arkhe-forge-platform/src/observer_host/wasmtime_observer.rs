//! Wasmtime-backed observer host (E15 capability-bounded sandbox).
//!
//! Feature-gated behind `tier-2-observer-host-v2`. Operators that do
//! not enable the feature ship the [`super::NoopObserverHost`] pass-
//! through; enabling the feature opts the runtime into this wasmtime-
//! backed sandbox for E15.a (panic close) and E15.b (capability-token
//! interface) realisation.
//!
//! ## Surface
//!
//! - [`WasmtimeObserverEngineConfig`] — declarative `Config` shape
//!   pinning the panic-close + fuel-metering axes. Determinism axes
//!   (NaN canonicalisation / SIMD opt-out) are NOT pinned for observer:
//!   E15 is *chain-non-affecting* (clause 4 — observer execution does
//!   not contribute to the L0 chain hash), so observer execution need
//!   not be replay-deterministic. Operators may still override.
//! - [`WasmtimeObserverHost`] — opaque host owning a wasmtime [`Engine`]
//!   plus a cached [`ObserverCapabilityLinker`] template.
//!   [`WasmtimeObserverHost::register_module`] runs the 3-tier-aware
//!   ingestion (Tier 1 BLAKE3 digest pin, observer-side pre-scan, and
//!   parsed module store). `ObserverHost::invoke` builds a per-
//!   invocation `Store<ObserverStoreData>` seeded with the caller's
//!   capability set and fuel budget, instantiates via the cached
//!   linker, looks up the conventional `"observer"` export and calls
//!   it.
//! - Concrete [`super::capability_linker::PgWriteCapability`] and
//!   [`super::capability_linker::MockPgWriteCapability`] (test helper).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use wasmtime::{Config, Engine, Module, Store};

use super::capability_linker::{ObserverCapability, ObserverCapabilityLinker};
use super::{ObserverCapToken, ObserverContext, ObserverError, ObserverHost};

/// Default per-invocation fuel budget for observer execution.
/// `100_000_000` (≈ 100 ms wall-clock target) is more generous than the
/// hook host's 10⁷ because:
///
/// - **Hook** is *chain-affecting* (E14.L2) → must run on the submission
///   hot path → tight 10 ms budget.
/// - **Observer** is *chain-non-affecting* (E15) → runs post-commit on
///   already-chained data → tolerates higher latency (projection write
///   may include round-trip to PG).
///
/// **Fail-direction**: same as hook — fail-secure (under-budget kills
/// observer early; over-budget creates DoS surface for the projection
/// pipeline). Operator overrides via [`WasmtimeObserverEngineConfig::with_fuel_budget`].
pub const DEFAULT_OBSERVER_FUEL_BUDGET_V0_12: u64 = 100_000_000;

/// Declarative wasmtime [`Config`] for observer execution. Pins the
/// panic-close + fuel-metering axes; determinism axes (NaN / SIMD) are
/// deliberately UNPINNED — observer is chain-non-affecting (E15 clause
/// 4) and need not be replay-deterministic.
///
/// **Field consumption matrix:**
///
/// | Field            | Consumed at         | Effect                                   |
/// |------------------|---------------------|------------------------------------------|
/// | `fuel_metering`  | `Engine::new`       | Engine-level `consume_fuel(...)` flag    |
/// | `fuel_budget`    | per-invocation      | `Store::set_fuel(fuel_budget)`           |
#[derive(Debug, Clone)]
pub struct WasmtimeObserverEngineConfig {
    /// `consume_fuel` — fuel metering caps observer execution time.
    /// Default: always `true` (panic-close requirement — wasmtime
    /// needs fuel instrumentation to deliver fine-grained traps).
    pub fuel_metering: bool,
    /// Per-invocation fuel budget. Defaults to
    /// [`DEFAULT_OBSERVER_FUEL_BUDGET_V0_12`] (~100 ms target on the
    /// reference platform).
    pub fuel_budget: u64,
}

impl WasmtimeObserverEngineConfig {
    /// Default profile — fuel metering on, default budget.
    pub fn deterministic_replay() -> Self {
        Self {
            fuel_metering: true,
            fuel_budget: DEFAULT_OBSERVER_FUEL_BUDGET_V0_12,
        }
    }

    /// Override the per-invocation fuel budget. Use to re-calibrate for
    /// non-reference hardware or for projection pipelines with longer
    /// PG round-trip targets.
    pub fn with_fuel_budget(mut self, fuel_budget: u64) -> Self {
        self.fuel_budget = fuel_budget;
        self
    }

    /// Materialise the wasmtime [`Config`] from the declarative shape.
    /// Routes through the shared
    /// `wasm_runtime_common::config_for_profile` factory for the
    /// `EngineProfile::ChainNonAffecting` pinning — single source of
    /// truth shared with hook host's engine construction.
    /// [`Self::fuel_budget`] is **not** consumed here — it's a per-
    /// invocation policy applied via `Store::set_fuel(...)` at
    /// observer-execution time.
    pub fn to_config(&self) -> Config {
        crate::wasm_runtime_common::config_for_profile(
            &crate::wasm_runtime_common::EngineProfile::ChainNonAffecting {
                fuel_budget: self.fuel_budget,
            },
        )
    }
}

impl Default for WasmtimeObserverEngineConfig {
    fn default() -> Self {
        Self::deterministic_replay()
    }
}

/// Wasmtime-backed observer host (E15 capability-bounded sandbox).
///
/// Owns a single [`Engine`] (build cost is significant — Cranelift JIT
/// cache initialisation — so we amortise across observer invocations)
/// plus a single [`ObserverCapabilityLinker`] template (host-fn
/// dispatch shape shared across invocations; per-invocation `Store`
/// brings the capability set).
///
/// Empty-host invocations (no module registered) pass through `Ok(())`
/// to match [`super::NoopObserverHost`]. Once a module is registered
/// via [`Self::register_module`] — which runs the BLAKE3 digest pin
/// (Tier 1) + module pre-scan (allow-list + WASI deny-list) and
/// rejects invalid or denied imports at registration time —
/// `ObserverHost::invoke` runs the module under a per-invocation
/// `Store<ObserverStoreData>` and translates wasmtime traps to
/// [`ObserverError`].
#[derive(Debug)]
pub struct WasmtimeObserverHost {
    engine: Engine,
    /// Cached capability-bounded [`Linker`](wasmtime::Linker) template.
    /// Built once at construction and reused across every invocation;
    /// tied to [`Self::engine`] for wasmtime's identity check.
    linker: ObserverCapabilityLinker,
    /// Optional pre-scanned + parsed [`Module`] representing the
    /// registered observer. `None` = empty-host pass-through.
    /// Populated via [`Self::register_module`].
    registered_module: Option<Module>,
    /// Per-invocation fuel budget snapshot — `invoke` seeds
    /// `Store::set_fuel(...)` with this before instantiation.
    fuel_budget: u64,
    /// Per-host trap counter — increments on every `invoke()` that
    /// returns any [`ObserverError`]. Operator telemetry surface
    /// routed downstream into chain-anchored `ObserverQuarantine`
    /// events. `AtomicU64` for lock-free concurrent updates from
    /// invocations on different threads.
    trap_count: AtomicU64,
}

impl WasmtimeObserverHost {
    /// Construct a host with the default config and **no**
    /// capabilities registered. Calls to `arkhe:observer/*` host-fns
    /// will trap "no impl registered" — useful for test fixtures
    /// that exercise the link-time / pre-scan layers without wiring
    /// concrete capabilities.
    pub fn with_deterministic_replay_config() -> Result<Self, ObserverHostError> {
        Self::with_config(&WasmtimeObserverEngineConfig::deterministic_replay(), &[])
    }

    /// Construct a host with an explicit [`WasmtimeObserverEngineConfig`]
    /// and the supplied capability set. The capabilities are passed
    /// to [`ObserverCapabilityLinker::deny_by_default`] which builds
    /// the dispatch registry; each cap-token maps to its
    /// [`ObserverCapability`] impl for the host-fn dispatch shim.
    /// Routes through the shared `wasm_runtime_common::build_engine`
    /// factory — single source of truth for the
    /// `ChainNonAffecting` profile pinning (E15 chain-non-affecting;
    /// fuel metering only).
    pub fn with_config(
        config: &WasmtimeObserverEngineConfig,
        capabilities: &[Arc<dyn ObserverCapability>],
    ) -> Result<Self, ObserverHostError> {
        let (engine, fuel_budget) = crate::wasm_runtime_common::build_engine(
            &crate::wasm_runtime_common::EngineProfile::ChainNonAffecting {
                fuel_budget: config.fuel_budget,
            },
        )
        .map_err(|e| ObserverHostError::EngineInitFailed {
            reason: format!("{e}"),
        })?;
        let linker = ObserverCapabilityLinker::deny_by_default(&engine, capabilities)?;
        Ok(Self {
            engine,
            linker,
            registered_module: None,
            fuel_budget,
            trap_count: AtomicU64::new(0),
        })
    }

    /// Register a wasm observer module with an operator-pinned BLAKE3
    /// digest. Mirrors the hook host's
    /// `WasmtimeHookHost::register_module` 3-tier-aware ingestion:
    ///
    /// 1. Compute `blake3::hash(bytes)`.
    /// 2. Reject with [`ObserverHostError::DigestMismatch`] if it does
    ///    not match `expected_digest`.
    /// 3. Run the allow-list / WASI deny-list pre-scan via
    ///    [`super::capability_linker::scan_imports`].
    /// 4. Store the parsed [`Module`] for invoke-time instantiation.
    ///
    /// `expected_digest` is sourced from the operator's manifest TOML
    /// (anchored chain-side via the `ObserverModuleRegister`-class
    /// event for symmetry with the hook host's `HookModuleRegister`).
    ///
    /// # Errors
    ///
    /// - [`ObserverHostError::DigestMismatch`] — `blake3(bytes)` did
    ///   not match `expected_digest`. Operator config typo or
    ///   accidental file substitution.
    /// - [`ObserverHostError::ModuleParseFailed`] — bytes are not a
    ///   valid wasm module (after digest verification passed).
    /// - [`ObserverHostError::ImportRejected`] — module imports a
    ///   denied namespace (specific WASI prefixes) or any namespace
    ///   outside the `arkhe:observer/*` allow-list.
    pub fn register_module(
        &mut self,
        bytes: Bytes,
        expected_digest: blake3::Hash,
    ) -> Result<(), ObserverHostError> {
        // Route through the shared
        // `wasm_runtime_common::register_module_common` factory for
        // the 3-tier ingestion path Tier 1 (BLAKE3 digest pin + import
        // allow/deny pre-scan). Single source of truth shared with
        // hook host. `From<RegistrationError>` impl below maps the
        // factory's flat error variants 1:1 to `ObserverHostError`.
        //
        // `expected_digest` is typed as `blake3::Hash` so the caller
        // gets type-safe digest construction (no raw `[u8;32]` →
        // wrong-direction conversion possible at compile time);
        // timing-safe comparison is automatic via `blake3::Hash::eq`
        // PartialEq (constant-time).
        use super::capability_linker::{
            ALLOWED_IMPORT_MODULE_PREFIXES, DENIED_IMPORT_MODULE_PREFIXES,
        };
        let module = crate::wasm_runtime_common::register_module_common(
            &self.engine,
            &bytes,
            expected_digest,
            ALLOWED_IMPORT_MODULE_PREFIXES,
            DENIED_IMPORT_MODULE_PREFIXES,
            "only `arkhe:observer/*` permitted",
        )?;
        self.registered_module = Some(module);
        Ok(())
    }

    /// Borrow the underlying wasmtime [`Engine`].
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Borrow the cached [`ObserverCapabilityLinker`]. Exposed for the
    /// invoke-time instantiation path; reused across every invocation.
    pub fn capability_linker(&self) -> &ObserverCapabilityLinker {
        &self.linker
    }

    /// Whether the host has a registered observer module (vs empty-
    /// host pass-through).
    pub fn has_registered_module(&self) -> bool {
        self.registered_module.is_some()
    }

    /// Per-invocation fuel budget snapshot from construction-time
    /// [`WasmtimeObserverEngineConfig::fuel_budget`]. `invoke` wires
    /// this into `Store::set_fuel` immediately before instantiation.
    pub fn fuel_budget(&self) -> u64 {
        self.fuel_budget
    }

    /// Current trap count — number of times [`ObserverHost::invoke`] has
    /// returned any [`ObserverError`] across the lifetime of this host.
    /// Counts actual wasm-execution traps (`BudgetExceeded` /
    /// `Trapped` / `CapabilityDenied`); pass-through invocations
    /// against an unregistered module never increment. Operator
    /// telemetry surface routed downstream into chain-anchored
    /// `ObserverQuarantine` events.
    pub fn trap_count(&self) -> u64 {
        self.trap_count.load(Ordering::Relaxed)
    }
}

impl ObserverHost for WasmtimeObserverHost {
    fn invoke(&self, ctx: &mut ObserverContext<'_>) -> Result<(), ObserverError> {
        let result = match self.registered_module.as_ref() {
            None => Ok(()),
            Some(module) => self.run_wasm_invoke(module, ctx),
        };
        if result.is_err() {
            self.trap_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

/// Compile-time chain-non-affecting clause 2 sentinel: assert
/// [`ObserverContext`]'s in-memory shape is exactly a
/// `&[ObserverCapToken]` slice. Future field additions trip this
/// build-time check; PR reviewers re-verify chain-orthogonality before
/// unblocking the build. Stronger than a runtime `debug_assert` —
/// release builds inherit the guarantee for free.
const _OBSERVER_CONTEXT_SHAPE_CHECK: () = {
    if core::mem::size_of::<ObserverContext<'static>>()
        != core::mem::size_of::<&[ObserverCapToken]>()
    {
        panic!(
            "ObserverContext gained a field — review chain-non-affecting \
             clause 2 invariant before continuing"
        );
    }
};

impl WasmtimeObserverHost {
    /// Real wasm execution wiring. Builds a per-invocation
    /// `Store<ObserverStoreData>` seeded with the caller's capability
    /// set + fuel budget, instantiates the registered module via the
    /// cached [`ObserverCapabilityLinker`], looks up the conventional
    /// `"observer"` export (entry point), and calls it.
    ///
    /// Wasmtime errors are translated coarsely:
    /// - Fuel-exhaustion trap → [`ObserverError::BudgetExceeded`]
    /// - Capability-deny → [`ObserverError::CapabilityDenied`] (with
    ///   the offending [`ObserverCapToken`] when recoverable from the
    ///   trap message)
    /// - Anything else → [`ObserverError::Trapped`] with a static
    ///   reason tag (operator stderr + downstream
    ///   `ObserverQuarantine` event carry the rich detail).
    ///
    /// **Chain-non-affecting clause 4 enforcement**: this function
    /// does not — and cannot — mutate any L0 chain state. The only
    /// host-fn dispatch surface is `arkhe:observer/pg.write`, which
    /// routes through the chain-orthogonal
    /// [`ObserverCapability::execute`] trait method. Any wasm trap
    /// is caught at the `entry.call(...)` boundary; chain progression
    /// continues independently (cryptographer-anchored firm
    /// contract).
    fn run_wasm_invoke(
        &self,
        module: &Module,
        ctx: &mut ObserverContext<'_>,
    ) -> Result<(), ObserverError> {
        let store_data = super::capability_linker::ObserverStoreData::with_capabilities(
            ctx.capabilities.iter().copied(),
        )
        .with_initial_fuel(self.fuel_budget);
        let mut store = Store::new(&self.engine, store_data);

        // Seed fuel — engine has consume_fuel(true), so without
        // set_fuel any wasm op traps "all fuel consumed" immediately.
        store
            .set_fuel(self.fuel_budget)
            .map_err(|_| ObserverError::Trapped("fuel seed failed at invoke entry"))?;

        // Instantiate via the cached linker.
        let inst = self
            .linker
            .linker()
            .instantiate(&mut store, module)
            .map_err(|_| ObserverError::Trapped("observer module instantiation failed"))?;

        // Convention: observer modules export a single zero-arg, zero-
        // return entry point named "observer". Mirrors the hook host's
        // "hook" convention.
        let entry = inst
            .get_typed_func::<(), ()>(&mut store, "observer")
            .map_err(|_| {
                ObserverError::Trapped(
                    "observer module missing `observer` export (signature `() -> ()`)",
                )
            })?;

        // Call the entry; classify the wasmtime error → ObserverError.
        // Imperfect string-matching; the typed-trap alternative would
        // require deeper wasmtime integration.
        match entry.call(&mut store, ()) {
            Ok(()) => Ok(()),
            Err(e) => {
                let s = format!("{e:?}");
                if s.contains("all fuel consumed") || s.contains("OutOfFuel") {
                    Err(ObserverError::BudgetExceeded)
                } else if s.contains("called without PgWrite capability") {
                    // Specifically the cap-token deny trap from the
                    // host-fn body. Distinct from "no PgWrite
                    // capability impl registered" (operator config
                    // error → falls into the Trapped catch-all).
                    Err(ObserverError::CapabilityDenied(ObserverCapToken::PgWrite))
                } else {
                    Err(ObserverError::Trapped(
                        "observer trapped during wasm execution",
                    ))
                }
            }
        }
    }
}

/// Host construction-time + module-registration error — distinct
/// from per-invocation [`ObserverError`]. Engine / linker
/// initialisation can fail for capability / allocator reasons; module
/// registration can fail for digest / parse / import-policy reasons.
/// Mirrors `hook_host::wasmtime_host::HookHostError` for symmetry
/// (shared sandbox surface invariants).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ObserverHostError {
    /// Wasmtime [`Engine::new`] failed during construction.
    #[error("wasmtime engine initialisation failed: {reason}")]
    EngineInitFailed {
        /// Underlying error stringified.
        reason: String,
    },
    /// Wasmtime linker setup rejected a host-fn registration during
    /// [`super::capability_linker::ObserverCapabilityLinker::deny_by_default`].
    /// Surfaces when the dispatch binding for `arkhe:observer/pg.write`
    /// fails to register on the linker (programming error rather than
    /// operator-recoverable state).
    #[error("wasmtime linker setup failed: {reason}")]
    LinkerSetupFailed {
        /// Underlying error stringified, prefixed with the offending
        /// host-fn name.
        reason: String,
    },
    /// Wasmtime [`Module::from_binary`] rejected the module bytes
    /// during [`super::capability_linker::scan_imports`]. The bytes
    /// do not parse as a valid wasm module.
    #[error("observer module parse failed: {reason}")]
    ModuleParseFailed {
        /// Underlying error stringified.
        reason: String,
    },
    /// Module pre-scan rejected an import outside the
    /// [`super::capability_linker::ALLOWED_IMPORT_MODULE_PREFIXES`]
    /// allow-list, or in the
    /// [`super::capability_linker::DENIED_IMPORT_MODULE_PREFIXES`]
    /// explicit deny-list. Operator-recoverable: the observer author
    /// must rebuild without the offending import.
    #[error("observer module import rejected: {name} — {reason}")]
    ImportRejected {
        /// The fully-qualified import name in `module::field` form.
        name: String,
        /// The pre-scan rejection reason (e.g.,
        /// `denied namespace 'wasi:random'` or
        /// `not in allow-list (only 'arkhe:observer/*' permitted)`).
        reason: String,
    },
    /// BLAKE3 digest pin mismatch during
    /// [`WasmtimeObserverHost::register_module`]. The bytes hash to a
    /// different value than the operator-pinned `expected_digest`
    /// (typically sourced from the manifest TOML). Operator-
    /// recoverable: re-deploy with the matching observer bytes, or
    /// correct the manifest's `digest_b3` field.
    #[error("observer module digest mismatch — expected {expected:?}, actual {actual:?}")]
    DigestMismatch {
        /// The BLAKE3 digest the operator expected (manifest-anchored).
        /// Typed as `blake3::Hash` so the type-strengthened digest
        /// carries through to the error surface; timing-safe comparison
        /// is automatic via `blake3::Hash::eq` PartialEq (constant-
        /// time).
        expected: blake3::Hash,
        /// The BLAKE3 digest the host computed from the supplied bytes.
        actual: blake3::Hash,
    },
}

/// Map the shared registration-error surface to the observer-specific
/// error enum. 1:1 variant mapping — DigestMismatch preserves operator-
/// pinned digest, ParseFailed → ModuleParseFailed, ImportRejected →
/// ImportRejected.
impl From<crate::wasm_runtime_common::RegistrationError> for ObserverHostError {
    fn from(e: crate::wasm_runtime_common::RegistrationError) -> Self {
        match e {
            crate::wasm_runtime_common::RegistrationError::DigestMismatch { expected, actual } => {
                ObserverHostError::DigestMismatch { expected, actual }
            }
            crate::wasm_runtime_common::RegistrationError::ParseFailed { reason } => {
                ObserverHostError::ModuleParseFailed { reason }
            }
            crate::wasm_runtime_common::RegistrationError::ImportRejected { name, reason } => {
                ObserverHostError::ImportRejected { name, reason }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::observer_host::ObserverCapToken;

    #[test]
    fn deterministic_replay_config_pins_fuel_metering_and_budget() {
        let cfg = WasmtimeObserverEngineConfig::deterministic_replay();
        assert!(cfg.fuel_metering);
        assert_eq!(cfg.fuel_budget, DEFAULT_OBSERVER_FUEL_BUDGET_V0_12);
    }

    /// Sanity-check the const has a plausible wall-clock value:
    /// between 1 M (1 ms floor) and 1 G (1 s ceiling — anything beyond
    /// is operator-opt-in via `with_fuel_budget`). Pinned at compile-
    /// time via `const _ = assert!` so future edits to the constant
    /// trip the build, not just the test runner.
    const _ASSERT_FUEL_BUDGET_LOWER: () = assert!(DEFAULT_OBSERVER_FUEL_BUDGET_V0_12 >= 1_000_000);
    const _ASSERT_FUEL_BUDGET_UPPER: () =
        assert!(DEFAULT_OBSERVER_FUEL_BUDGET_V0_12 <= 1_000_000_000);

    #[test]
    fn with_fuel_budget_override_works() {
        let cfg = WasmtimeObserverEngineConfig::deterministic_replay().with_fuel_budget(50_000_000);
        assert_eq!(cfg.fuel_budget, 50_000_000);
        // Other axis unchanged.
        assert!(cfg.fuel_metering);
    }

    #[test]
    fn host_records_fuel_budget_at_construction() {
        let host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        assert_eq!(host.fuel_budget(), DEFAULT_OBSERVER_FUEL_BUDGET_V0_12);
        let host2 = WasmtimeObserverHost::with_config(
            &WasmtimeObserverEngineConfig::deterministic_replay().with_fuel_budget(7_777),
            &[],
        )
        .unwrap();
        assert_eq!(host2.fuel_budget(), 7_777);
    }

    #[test]
    fn engine_builds_with_deterministic_replay_config() {
        let host = WasmtimeObserverHost::with_deterministic_replay_config()
            .expect("engine init must succeed under default config");
        // Sanity: the engine handle is borrowable.
        let _engine = host.engine();
    }

    #[test]
    fn empty_host_pass_through_ok() {
        let host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let caps = [ObserverCapToken::PgWrite];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        // No registered module → pass-through Ok regardless of caps.
        assert!(host.invoke(&mut ctx).is_ok());
    }

    #[test]
    fn trap_count_starts_at_zero() {
        let host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        assert_eq!(host.trap_count(), 0);
    }

    #[test]
    fn trap_count_does_not_increment_on_pass_through_invoke() {
        // Empty host (no module registered) never errors → counter stays zero.
        let host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let caps: [ObserverCapToken; 0] = [];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        for _ in 0..3 {
            assert!(host.invoke(&mut ctx).is_ok());
        }
        assert_eq!(host.trap_count(), 0);
    }

    #[test]
    fn observer_host_error_display_does_not_panic() {
        let e = ObserverHostError::EngineInitFailed {
            reason: "test reason".into(),
        };
        assert!(format!("{e}").contains("test reason"));
    }

    /// Compute the BLAKE3 digest the host expects for a given byte
    /// slice. Returns `blake3::Hash` to match the `register_module`
    /// signature.
    fn digest(bytes: &[u8]) -> blake3::Hash {
        blake3::hash(bytes)
    }

    fn wat_to_bytes(wat: &str) -> Bytes {
        Bytes::from(wat::parse_str(wat).expect("valid wat"))
    }

    #[test]
    fn register_module_accepts_zero_import_preamble() {
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let preamble = Bytes::from_static(&[
            0x00, 0x61, 0x73, 0x6d, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]);
        let d = digest(preamble.as_ref());
        host.register_module(preamble, d)
            .expect("zero-import preamble passes digest + pre-scan");
        assert!(host.has_registered_module());
    }

    #[test]
    fn register_module_accepts_arkhe_observer_pg_write_import() {
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:observer/pg" "write"
                    (func (param i32 i32))))"#,
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d)
            .expect("allowed observer import passes registration");
        assert!(host.has_registered_module());
    }

    #[test]
    fn register_module_rejects_digest_mismatch() {
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let preamble = Bytes::from_static(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        let wrong_digest: blake3::Hash = [0xFFu8; 32].into();
        let err = host
            .register_module(preamble.clone(), wrong_digest)
            .expect_err("wrong digest must reject");
        match err {
            ObserverHostError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, wrong_digest);
                assert_eq!(actual, digest(preamble.as_ref()));
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        assert!(!host.has_registered_module());
    }

    #[test]
    fn register_module_rejects_wasi_random() {
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:random/random" "get-random-u64"
                    (func (result i64))))"#,
        );
        let d = digest(bytes.as_ref());
        let err = host
            .register_module(bytes, d)
            .expect_err("wasi:random must reject at registration");
        assert!(matches!(err, ObserverHostError::ImportRejected { .. }));
        assert!(!host.has_registered_module());
    }

    #[test]
    fn register_module_rejects_arkhe_hook_in_observer_context() {
        // Cross-host isolation: hook imports must reject in observer
        // context (not in observer allow-list, not in WASI deny-list,
        // → catch-all rejection).
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func (param i32 i32) (result i32))))"#,
        );
        let d = digest(bytes.as_ref());
        let err = host
            .register_module(bytes, d)
            .expect_err("arkhe:hook/* must reject in observer context");
        assert!(matches!(err, ObserverHostError::ImportRejected { .. }));
        assert!(!host.has_registered_module());
    }

    #[test]
    fn register_module_rejects_invalid_bytes() {
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let bytes = Bytes::from_static(&[0x00, 0x61, 0x73, 0x6d]); // truncated
        let d = digest(bytes.as_ref());
        let err = host
            .register_module(bytes, d)
            .expect_err("invalid bytes must reject");
        assert!(matches!(err, ObserverHostError::ModuleParseFailed { .. }));
    }

    #[test]
    fn register_module_digest_check_runs_before_pre_scan() {
        // wasi:random module — pre-scan would also reject, but digest
        // check fires first (cheaper, no engine work).
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:random/random" "get-random-u64"
                    (func (result i64))))"#,
        );
        let wrong_digest: blake3::Hash = [0xAAu8; 32].into();
        let err = host
            .register_module(bytes, wrong_digest)
            .expect_err("must reject");
        // Digest check fires first → DigestMismatch (NOT ImportRejected).
        assert!(matches!(err, ObserverHostError::DigestMismatch { .. }));
    }

    #[test]
    fn capability_linker_accessor_returns_template() {
        let host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let linker = host.capability_linker();
        // Smoke test — the accessor returns a reference to the cached
        // linker; Debug on the linker exposes the allow-list / deny-list
        // for operator audit.
        let dbg = format!("{linker:?}");
        assert!(dbg.contains("arkhe:observer/"));
    }

    // ============== Integration tests ==============

    use crate::observer_host::capability_linker::{MockPgWriteCapability, PgWriteCapability};

    /// Chain-non-affecting integration test: an observer module
    /// imports `arkhe:observer/pg.write`, calls it with a payload,
    /// and the host's [`MockPgWriteCapability`] records the bytes.
    /// The chain is unaffected — no chain-mutation primitive is
    /// reachable from the observer's wasm.
    #[test]
    fn integration_observer_pg_write_records_bytes_chain_unaffected() {
        let mock = Arc::new(MockPgWriteCapability::new());
        let mock_handle: Arc<MockPgWriteCapability> = Arc::clone(&mock);
        let cap: Arc<dyn ObserverCapability> = mock;
        let mut host = WasmtimeObserverHost::with_config(
            &WasmtimeObserverEngineConfig::deterministic_replay(),
            &[cap],
        )
        .expect("host with PgWrite capability");
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:observer/pg" "write"
                    (func $w (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "ROW-PAYLOAD")
                (func (export "observer")
                    i32.const 0
                    i32.const 11
                    call $w))"#,
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d).expect("register module");
        let caps = [ObserverCapToken::PgWrite];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        host.invoke(&mut ctx).expect("observer invocation");
        let recorded = mock_handle.recorded();
        assert_eq!(recorded.len(), 1, "exactly one pg.write invocation");
        assert_eq!(recorded[0], b"ROW-PAYLOAD");
        assert_eq!(host.trap_count(), 0, "no traps on success");
    }

    /// Capability-deny: observer wasm calls `arkhe:observer/pg.write`
    /// without `PgWrite` in the cap-token set → trap → ObserverError
    /// → trap counter increments. Mock records nothing.
    #[test]
    fn integration_observer_pg_write_traps_without_capability() {
        let mock = Arc::new(MockPgWriteCapability::new());
        let mock_handle: Arc<MockPgWriteCapability> = Arc::clone(&mock);
        let cap: Arc<dyn ObserverCapability> = mock;
        let mut host = WasmtimeObserverHost::with_config(
            &WasmtimeObserverEngineConfig::deterministic_replay(),
            &[cap],
        )
        .unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:observer/pg" "write"
                    (func $w (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "BLOCKED")
                (func (export "observer")
                    i32.const 0
                    i32.const 7
                    call $w))"#,
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d).unwrap();
        // Cap-token set is EMPTY — observer calls pg.write but lacks
        // the PgWrite token → host-fn body traps `CapabilityDenied`.
        let caps: [ObserverCapToken; 0] = [];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        match host.invoke(&mut ctx) {
            Err(ObserverError::CapabilityDenied(ObserverCapToken::PgWrite)) => {}
            other => panic!("expected CapabilityDenied(PgWrite), got {other:?}"),
        }
        assert_eq!(mock_handle.invocation_count(), 0, "mock untouched on deny");
        assert_eq!(host.trap_count(), 1, "trap counter incremented");
    }

    /// No-impl-registered: observer module calls `arkhe:observer/pg.write`,
    /// the cap-token IS in the set, but no `PgWriteCapability` impl
    /// is registered on the host → trap. This is operator
    /// configuration error — declared the cap-token but no concrete
    /// impl wired.
    #[test]
    fn integration_observer_pg_write_traps_when_no_impl_registered() {
        // No capabilities registered.
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:observer/pg" "write"
                    (func $w (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "ORPHAN")
                (func (export "observer")
                    i32.const 0
                    i32.const 6
                    call $w))"#,
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d).unwrap();
        let caps = [ObserverCapToken::PgWrite];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        // Cap-token present but no impl → trap with the
        // "no PgWrite capability impl registered" message.
        match host.invoke(&mut ctx) {
            Err(ObserverError::Trapped(_)) => {}
            other => panic!("expected Trapped (no impl registered), got {other:?}"),
        }
        assert_eq!(host.trap_count(), 1);
    }

    /// Observer fuel-exhaustion: an infinite-loop observer traps with
    /// BudgetExceeded; the trap counter increments on real wasm
    /// execution.
    #[test]
    fn integration_observer_infinite_loop_returns_budget_exceeded() {
        // Tight fuel budget so the loop trips fast.
        let mut host = WasmtimeObserverHost::with_config(
            &WasmtimeObserverEngineConfig::deterministic_replay().with_fuel_budget(1_000),
            &[],
        )
        .unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (func (export "observer")
                    (loop $forever (br $forever))))"#,
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d).unwrap();
        let caps: [ObserverCapToken; 0] = [];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        match host.invoke(&mut ctx) {
            Err(ObserverError::BudgetExceeded) => {}
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        assert_eq!(host.trap_count(), 1);
    }

    /// Observer module without `observer` export traps with the
    /// missing-export message at invoke. Symmetric with hook host's
    /// missing-`hook`-export trap.
    #[test]
    fn integration_observer_module_without_observer_export_traps() {
        let mut host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        // Smallest valid wasm — magic + version, no exports.
        let preamble = Bytes::from_static(&[
            0x00, 0x61, 0x73, 0x6d, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]);
        let d = digest(preamble.as_ref());
        host.register_module(preamble, d).unwrap();
        let caps: [ObserverCapToken; 0] = [];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        match host.invoke(&mut ctx) {
            Err(ObserverError::Trapped(msg)) => {
                assert!(
                    msg.contains("missing `observer` export"),
                    "unexpected trap: {msg}"
                );
            }
            other => panic!("expected Trapped(missing observer), got {other:?}"),
        }
    }

    /// Empty-host pass-through: no registered module → invoke returns
    /// Ok(()) without any wasm execution. Trap counter stays zero.
    #[test]
    fn integration_empty_host_pass_through() {
        let host = WasmtimeObserverHost::with_deterministic_replay_config().unwrap();
        let caps = [ObserverCapToken::PgWrite];
        let mut ctx = ObserverContext {
            capabilities: &caps,
        };
        assert!(host.invoke(&mut ctx).is_ok());
        assert_eq!(host.trap_count(), 0);
    }

    /// Compile-time chain-non-affecting clause 2 sentinel verification —
    /// if this test compiles, the
    /// `_OBSERVER_CONTEXT_SHAPE_CHECK` const in wasmtime_observer.rs
    /// passed its `assert!`. Future field additions to ObserverContext
    /// would trip the const_assert at build time.
    #[test]
    fn observer_context_shape_check_holds_at_compile_time() {
        // The const is evaluated at compile time; this test exists
        // so the build/test pipeline surfaces the structural invariant
        // pinning to operators reading the test list.
        let _: () = _OBSERVER_CONTEXT_SHAPE_CHECK;
    }

    /// Verify PgWriteCapability impl is observable via the
    /// constructor + execute path. Used by integration test fixtures.
    #[test]
    fn integration_pg_write_capability_can_be_default_registered() {
        let cap: Arc<dyn ObserverCapability> = Arc::new(PgWriteCapability::new());
        let host = WasmtimeObserverHost::with_config(
            &WasmtimeObserverEngineConfig::deterministic_replay(),
            &[cap],
        )
        .expect("default PgWriteCapability registers");
        assert_eq!(host.capability_linker().registered_capability_count(), 1);
    }
}
