//! Capability-bounded wasmtime [`Linker`] template for the observer
//! host (E15.b realisation, Track A.2.2).
//!
//! Three-layer defense for E15 chain-non-affecting confinement —
//! mirrors the hook host's three-layer pattern:
//!
//! 1. **Pre-scan** ([`scan_imports`]) — eager-rejects modules whose
//!    imports do not match the [`ALLOWED_IMPORT_MODULE_PREFIXES`]
//!    allow-list, with explicit specific-error paths for the WASI
//!    [`DENIED_IMPORT_MODULE_PREFIXES`] namespaces.
//! 2. **Link-time deny-by-default** — [`ObserverCapabilityLinker::v0_12_first_cut`]
//!    only `func_wrap`s the dispatch shim that routes
//!    `arkhe:observer/*` calls through registered
//!    [`ObserverCapability`] impls. Modules importing any other name
//!    fail at instantiation. (Track A.2.2 ships the linker scaffold
//!    and dispatch shape; concrete capability impls — including the
//!    v0.12 single `PgWriteCapability` — land in Track A.2.3.)
//! 3. **Call-time capability check** — every dispatch path inspects
//!    `Caller::data().capabilities` (the per-invocation
//!    [`ObserverStoreData::capabilities`]) and traps
//!    `CapabilityDenied` if the matching [`super::ObserverCapToken`]
//!    is absent. Even a linked function refuses to execute without
//!    the per-invocation grant.
//!
//! ## Chain-non-affecting clause 1 + 2 enforcement (cryptographer-anchored)
//!
//! - **Clause 1**: every binding under `arkhe:observer/*` routes to
//!   [`ObserverCapability::execute`], which receives only a `&[u8]`
//!   payload — no chain-mutation primitive. Concrete impls land in
//!   A.2.3 with shape pre-committed at the trait signature.
//! - **Clause 2**: [`ObserverCapability`] is `Send + Sync + Debug`
//!   only — no `KernelObserver` / `Op` reference. The trait
//!   signature itself enforces chain-orthogonality at type-level.
//!
//! ## v0.12 first-cut allow set
//!
//! - `arkhe:observer/pg.write` — Track A.2.3 binds the dispatch.
//!   v0.12 ships a single concrete impl (`PgWriteCapability`)
//!   alongside the `MockPgWriteCapability` test helper. KMS / metric
//!   etc. capabilities are deferred to v0.13+ ecosystem-driven
//!   addition (Track A.2 deferral per `docs/runtime-sealing-plan.md`).
//!
//! ## Why both pre-scan + link-time + call-time
//!
//! The three layers are not redundant — each catches a different
//! attack shape (DIP-N1 cryptographer Q1 / spec §5.5 confused-deputy
//! observer-side mirror):
//!
//! | Layer       | Catches                                            |
//! |-------------|----------------------------------------------------|
//! | Pre-scan    | Forbidden namespaces (clearer audit error)         |
//! | Link-time   | Typos / unknown names within an allowed namespace  |
//! | Call-time   | Linked dispatch invoked without per-invocation cap |

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use wasmtime::{Caller, Engine, Linker, Module};

use super::wasmtime_observer::ObserverHostError;
use super::ObserverCapToken;
use crate::wasm_runtime_common::{read_caller_memory, scan_module_imports, ScanImportsError};

/// Allow-list of module prefixes an observer may import from. The
/// pre-scan rejects any import whose `module` field does not start
/// with one of these. v0.12 first cut admits only the
/// `arkhe:observer/*` namespace — everything else (including all
/// WASI namespaces) is out of scope.
///
/// **Stability:** additive expansion is non-breaking; removal is a
/// breaking change for observer authors. Each entry pairs with at
/// least one [`ObserverCapToken`] in the call-time check.
pub const ALLOWED_IMPORT_MODULE_PREFIXES: &[&str] = &["arkhe:observer/"];

/// Explicit deny-list of WASI module prefixes — re-exported from the
/// shared `wasm_runtime_common::WASI_DENY_PREFIXES` constant (M2.3 cycle
/// DRY consolidation, DIP-N6 Phase 2). Observer + hook share the
/// **identical 7-prefix set** so the deny-list lives in one place.
///
/// E15 is chain-non-affecting, but WASI surfaces still introduce
/// undocumented capabilities outside the host's audit log — rejected
/// on principle. Observer side-effects must route through host-
/// declared [`ObserverCapability`] impls (E15.b).
///
/// Maintenance: kept in sync with the WASI Preview 2 namespace
/// inventory at the shared site (one update point, both hosts inherit).
pub use crate::wasm_runtime_common::WASI_DENY_PREFIXES as DENIED_IMPORT_MODULE_PREFIXES;

/// Per-invocation [`wasmtime::Store`] data threaded through linked
/// observer host functions. The host clones the per-shell capability
/// set into a fresh `ObserverStoreData` at each `invoke()`; dispatch
/// bodies inspect `caller.data().capabilities` to enforce the call-
/// time check.
///
/// Distinct from [`crate::hook_host::capability_linker::HookStoreData`]
/// — observers are read-only sinks (no `extra` builder, no `scratchpad`
/// at v0.12). Observer-specific fields land additively as v0.13+
/// ecosystem evidence drives them.
///
/// **Chain-non-affecting clause 2 enforcement**: this struct
/// intentionally does NOT carry chain references. Future field
/// additions must preserve this invariant (caught at PR review).
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ObserverStoreData {
    /// Capability tokens granted to the observer for this invocation.
    /// Set by the host before [`wasmtime::Linker::instantiate`];
    /// dispatch bodies trap `CapabilityDenied` if the matching token
    /// is absent.
    pub capabilities: BTreeSet<ObserverCapToken>,
    /// Fuel granted at the start of this invocation. The host calls
    /// `Store::set_fuel(initial_fuel)` immediately after constructing
    /// the `Store<ObserverStoreData>`. Future Track A.2 sub-steps may
    /// expose a `fuel.consumed` host-fn analogous to the hook host's;
    /// v0.12 first cut keeps the field for symmetry with hook_host
    /// without yet exposing a host-fn.
    pub initial_fuel: u64,
}

impl ObserverStoreData {
    /// Construct an `ObserverStoreData` from an iterable of capability
    /// tokens. `initial_fuel` defaults to 0 — set via
    /// [`Self::with_initial_fuel`] after the host calls
    /// `Store::set_fuel(...)`.
    pub fn with_capabilities<I: IntoIterator<Item = ObserverCapToken>>(caps: I) -> Self {
        Self {
            capabilities: caps.into_iter().collect(),
            initial_fuel: 0,
        }
    }

    /// Set the initial fuel value for this invocation.
    pub fn with_initial_fuel(mut self, initial_fuel: u64) -> Self {
        self.initial_fuel = initial_fuel;
        self
    }
}

/// Host-side abstraction for an observer's chain-orthogonal effect
/// (E15.b interface). Concrete impls (e.g. `PgWriteCapability` at
/// Track A.2.3) carry the actual side-effect machinery — projection
/// writes, KMS calls, metric emits.
///
/// **Chain-non-affecting clause 2 enforcement** (cryptographer-anchored
/// firm contract): the trait signature itself constrains every impl to
/// chain-orthogonality:
///
/// - [`Self::token`] returns only the capability identifier — no
///   chain context.
/// - [`Self::execute`] receives only a `&[u8]` payload extracted via
///   the shared bounds-checked `read_caller_memory` helper (crate-
///   private, in `wasm_runtime_common`) — no chain-state reference.
/// - Failure surface is [`CapabilityExecutionError`] — a structured
///   error the host records via the trap counter (Track A.2.4 routes
///   this into the chain-anchored `ObserverQuarantine` event).
///
/// The trait is `Send + Sync + Debug` so observer hosts can be
/// shared across threads.
pub trait ObserverCapability: std::fmt::Debug + Send + Sync {
    /// The token this capability provides. The observer host checks
    /// the caller's [`ObserverStoreData::capabilities`] set for this
    /// token before invoking [`Self::execute`].
    fn token(&self) -> ObserverCapToken;

    /// Execute the side-effect with the supplied bytes payload.
    /// `bytes` was extracted from observer wasm memory through the
    /// shared `read_caller_memory` helper (B.5 bounds-check pinned).
    ///
    /// Returns `Ok(())` on success; `Err(_)` on side-effect failure
    /// (PG connection broken, KMS unreachable, etc.). Failure does
    /// NOT trap the observer at the wasm boundary — it surfaces as a
    /// structured error the host records via the trap counter.
    /// Track A.2.4 routes this into the chain-anchored
    /// `ObserverQuarantine` event.
    fn execute(&self, bytes: &[u8]) -> Result<(), CapabilityExecutionError>;
}

/// Failure surface for [`ObserverCapability::execute`]. Distinct from
/// [`super::ObserverError`] — the cap-execution error is recoverable
/// (retry / fallback) while observer trap is terminal.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CapabilityExecutionError {
    /// Side-effect destination unreachable / failed.
    #[error("capability execution failed: {reason}")]
    ExecutionFailed {
        /// Underlying error stringified.
        reason: String,
    },
}

/// Type alias for the host-side capability registry — maps each
/// [`ObserverCapToken`] to its [`ObserverCapability`] impl. The
/// registry is built once at host construction and shared with the
/// linker dispatch closures via `Arc`.
pub(crate) type CapabilityRegistry = BTreeMap<ObserverCapToken, Arc<dyn ObserverCapability>>;

/// Cached wasmtime [`Linker`] template for observers. Constructed
/// once per [`super::wasmtime_observer::WasmtimeObserverHost`] and
/// reused across every invocation. Per-invocation
/// `Store<ObserverStoreData>` instances bring the capability set;
/// the linker holds the host-fn dispatch bindings + the capability
/// registry that the `arkhe:observer/*` host-fns route through.
///
/// **Concurrency:** [`Linker<T>`] is `Send + Sync` for `T: Send + Sync`
/// — a single instance can serve concurrent invocations on different
/// threads (each with its own `Store`).
///
/// ## v0.12 first-cut scope (Track A.2.3)
///
/// The linker binds the `arkhe:observer/pg.write` dispatch shim. The
/// shim performs the 3-layer defense layer 3 (call-time capability
/// check) + bounds-checked `(ptr, len)` extraction via
/// `read_caller_memory<ObserverStoreData>` + lookup in the registry +
/// `ObserverCapability::execute(bytes)` route. Operational failures
/// from `execute` (PG unreachable etc.) are swallowed at the wasm
/// boundary (cryptographer A.2.4 anchor: chain-non-affecting →
/// trigger NOT chain-anchored Quarantine; future v0.13+ DIP routes
/// these to a typed metric / runtime_doctor_journal entry).
pub struct ObserverCapabilityLinker {
    inner: Linker<ObserverStoreData>,
    /// Number of capabilities registered in the dispatch registry.
    /// Exposed via [`Self::registered_capability_count`] for operator
    /// audit; the actual registry lives inside the linker's host-fn
    /// closures via `Arc<CapabilityRegistry>`.
    registered_count: usize,
}

// M2.5 cycle (DIP-N6 Phase 2): SealedHostImport safeguard. The
// observer `ObserverCapabilityLinker` impls both the private `Sealed`
// marker (only reachable from `arkhe-forge-platform`) and the public
// `wasm_runtime_common::SealedHostImport` trait. External crates
// cannot fork the host-linker structure with their own linker type,
// preserving the **E15.b chain-non-affecting compile-time invariant**:
// the observer-side host-fn import surface (0 wasmtime host-fns —
// dispatch routes through cap-token surface) is structurally bounded
// at the host-defining crate boundary.
impl crate::wasm_runtime_common::sealed_impl::Sealed for ObserverCapabilityLinker {}
impl crate::wasm_runtime_common::SealedHostImport for ObserverCapabilityLinker {}

impl std::fmt::Debug for ObserverCapabilityLinker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObserverCapabilityLinker")
            .field("allowed_prefixes", &ALLOWED_IMPORT_MODULE_PREFIXES)
            .field("denied_prefixes", &DENIED_IMPORT_MODULE_PREFIXES)
            .field("registered_capability_count", &self.registered_count)
            .finish_non_exhaustive()
    }
}

impl ObserverCapabilityLinker {
    /// Build the v0.12 first-cut observer linker with the supplied
    /// capability set.
    ///
    /// The linker binds the `arkhe:observer/pg.write` dispatch shim
    /// closure that routes to the [`PgWriteCapability`]-tagged impl
    /// in `capabilities`. Calls without the matching
    /// [`ObserverCapToken`] in [`ObserverStoreData::capabilities`]
    /// trap at the host boundary (3-layer defense layer 3 — call-
    /// time check). Calls with the cap-token but no registered impl
    /// in `capabilities` also trap (configuration error — operator
    /// must register a [`ObserverCapability`] impl matching the
    /// declared cap-token set).
    ///
    /// **Empty `capabilities`**: linker still binds the dispatch
    /// shim, but every call falls through to the "no impl
    /// registered" trap. This is the v0.12 first-cut "minimum-viable
    /// observer host" deployment for operators who declare cap-
    /// tokens but haven't yet wired the concrete impl. The host's
    /// pre-scan + link-time layers still reject malformed modules.
    pub fn v0_12_first_cut(
        engine: &Engine,
        capabilities: &[Arc<dyn ObserverCapability>],
    ) -> Result<Self, ObserverHostError> {
        // Build the dispatch registry: each capability is keyed by
        // its declared token. If two capabilities declare the same
        // token, the later one overwrites the earlier — operator
        // configuration error caught structurally at registration.
        let registry: Arc<CapabilityRegistry> = Arc::new(
            capabilities
                .iter()
                .map(|c| (c.token(), Arc::clone(c)))
                .collect(),
        );
        let registered_count = registry.len();

        let mut linker = Linker::<ObserverStoreData>::new(engine);

        // arkhe:observer/pg.write — append a row to the operator's
        // projection PostgreSQL table. v0.12 first-cut wasm signature
        // `(ptr: i32, len: i32) -> ()`. Returns void: observer is
        // fire-and-forget from the wasm's perspective; operational
        // failures (PG unreachable, write conflict, etc.) are
        // swallowed silently at the wasm boundary per cryptographer
        // A.2.4 anchor (CapabilityExecutionError → metric/log alert,
        // NOT chain-anchored Quarantine — v0.13+ DIP wires the
        // typed metric).
        //
        // Trap conditions (chain-anchored via Quarantine — A.2.4):
        // - PgWrite cap-token absent from caller capabilities
        //   (3-layer defense layer 3 call-time check).
        // - No PgWriteCapability impl registered (configuration
        //   error — operator declared the cap but no concrete impl).
        // - Bounds-check failure on (ptr, len) memory access (B.5
        //   firm contract — read_caller_memory).
        let pg_registry = Arc::clone(&registry);
        linker
            .func_wrap(
                "arkhe:observer/pg",
                "write",
                move |mut caller: Caller<'_, ObserverStoreData>,
                      ptr: i32,
                      len: i32|
                      -> Result<(), wasmtime::Error> {
                    if !caller
                        .data()
                        .capabilities
                        .contains(&ObserverCapToken::PgWrite)
                    {
                        return Err(wasmtime::Error::msg(
                            "arkhe:observer/pg.write called without PgWrite capability",
                        ));
                    }
                    let bytes = read_caller_memory(&mut caller, ptr, len)?;
                    let cap = pg_registry.get(&ObserverCapToken::PgWrite).ok_or_else(|| {
                        wasmtime::Error::msg(
                            "arkhe:observer/pg.write: no PgWrite capability impl registered \
                             on host (operator must wire a concrete `ObserverCapability` \
                             before declaring `PgWrite` in the cap-token set)",
                        )
                    })?;
                    // CapabilityExecutionError is operational, not
                    // sandbox-boundary — swallow at wasm boundary so
                    // observer execution proceeds (fire-and-forget).
                    // Future v0.13+ DIP: wire to typed metric +
                    // runtime_doctor_journal entry per cryptographer
                    // A.2.4 anchor (NOT chain-anchored Quarantine).
                    let _ = cap.execute(&bytes);
                    Ok(())
                },
            )
            .map_err(|e| ObserverHostError::LinkerSetupFailed {
                reason: format!("arkhe:observer/pg.write: {e}"),
            })?;

        Ok(Self {
            inner: linker,
            registered_count,
        })
    }

    /// Borrow the underlying [`Linker`] for invoke-time
    /// instantiation. Used by `WasmtimeObserverHost::invoke` (the
    /// trait impl from [`super::ObserverHost`]).
    pub fn linker(&self) -> &Linker<ObserverStoreData> {
        &self.inner
    }

    /// Number of [`ObserverCapability`] impls registered in the
    /// dispatch registry. Operator audit surface; used by tests +
    /// runbook diagnostics.
    pub fn registered_capability_count(&self) -> usize {
        self.registered_count
    }
}

/// Concrete [`ObserverCapability`] impl for `arkhe:observer/pg.write`.
///
/// **v0.12 first-cut scope** (Track A.2.3): this impl is the surface
/// declaration only — actual PostgreSQL connection wiring is shell-
/// territory (deferred to v0.13+ ecosystem-driven DIP per
/// `docs/runtime-sealing-plan.md` Track A.2 deferral). v0.12 ships
/// the trait + a [`MockPgWriteCapability`] in-memory test helper so
/// the chain-non-affecting integration test can run without a real
/// PG dependency.
///
/// **Chain-non-affecting clause 2 enforcement** (cryptographer Q3 PR
/// review point): the impl's `self` field is chain-orthogonal. v0.12
/// `PgWriteCapability` carries no field at all (unit struct) —
/// future shell-territory wiring may add a connection pool / SQL
/// template, both of which are PG-side concerns and never reach the
/// L0 chain.
#[derive(Debug, Default, Clone, Copy)]
pub struct PgWriteCapability;

impl PgWriteCapability {
    /// Construct a v0.12 PgWriteCapability instance. Real PG wiring
    /// is deferred to v0.13+ — this constructor exists so operator
    /// code can declare the cap-token + register the impl without a
    /// PG dependency at compile time.
    pub fn new() -> Self {
        Self
    }
}

impl ObserverCapability for PgWriteCapability {
    fn token(&self) -> ObserverCapToken {
        ObserverCapToken::PgWrite
    }

    fn execute(&self, _bytes: &[u8]) -> Result<(), CapabilityExecutionError> {
        // v0.12: no PG wiring — this impl ALWAYS returns Ok(()) so
        // operators can declare the cap-token before the v0.13+
        // shell-territory PG integration lands. Real impl will:
        //   1. Acquire a PG connection from the pool.
        //   2. Run the configured INSERT against the projection table.
        //   3. Map PG errors → CapabilityExecutionError::ExecutionFailed.
        //
        // For chain-non-affecting integration testing, prefer
        // `MockPgWriteCapability` which records the bytes for test
        // assertion.
        Ok(())
    }
}

/// In-memory test helper: records every `execute` call's bytes for
/// downstream assertion. Used by Track A.2.3 chain-non-affecting
/// integration tests + future test-fixture builders.
///
/// **Why a separate type from `PgWriteCapability`**: cryptographer
/// Q3 PR review point — `MockPgWriteCapability` carries an
/// `Arc<Mutex<Vec<Vec<u8>>>>` field, which is *test-only* state. The
/// production [`PgWriteCapability`] stays a unit struct (zero state
/// = chain-orthogonal proof). Mixing the two via flag-toggled
/// internal state would muddy the structural-invariant review.
#[derive(Debug, Default, Clone)]
pub struct MockPgWriteCapability {
    /// Records every `execute` invocation's bytes. Wrapped in
    /// `Arc<Mutex<_>>` so test code can clone the handle, register
    /// the impl, and inspect the recorded bytes after the wasm runs.
    recorded: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl MockPgWriteCapability {
    /// Construct a fresh mock. Each instance has its own recording.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded bytes. Returns a clone so the caller
    /// can inspect without holding the mutex.
    #[allow(clippy::expect_used)]
    pub fn recorded(&self) -> Vec<Vec<u8>> {
        self.recorded
            .lock()
            .expect("MockPgWriteCapability mutex poisoned")
            .clone()
    }

    /// Number of recorded invocations.
    pub fn invocation_count(&self) -> usize {
        self.recorded.lock().map(|v| v.len()).unwrap_or(0)
    }
}

impl ObserverCapability for MockPgWriteCapability {
    fn token(&self) -> ObserverCapToken {
        ObserverCapToken::PgWrite
    }

    #[allow(clippy::expect_used)]
    fn execute(&self, bytes: &[u8]) -> Result<(), CapabilityExecutionError> {
        self.recorded
            .lock()
            .expect("MockPgWriteCapability mutex poisoned")
            .push(bytes.to_vec());
        Ok(())
    }
}

/// Pre-scan an observer module's imports against the allow-list +
/// specific-error WASI deny-list. Returns the parsed [`Module`] on
/// success (callers reuse it for instantiation rather than re-
/// parsing).
///
/// Delegates to the shared `scan_module_imports` helper (crate-
/// private, in `wasm_runtime_common`) with the observer-specific
/// allow-list and audit message.
///
/// # Errors
///
/// - [`ObserverHostError::ModuleParseFailed`] — wasmtime rejected the
///   bytes as a non-wasm module.
/// - [`ObserverHostError::ImportRejected`] with `reason: "denied
///   namespace <prefix>"` — the module imports from a
///   [`DENIED_IMPORT_MODULE_PREFIXES`] namespace.
/// - [`ObserverHostError::ImportRejected`] with `reason: "not in
///   allow-list ..."` — the module imports from a namespace outside
///   [`ALLOWED_IMPORT_MODULE_PREFIXES`] but not in the explicit deny
///   list.
pub fn scan_imports(engine: &Engine, bytes: &Bytes) -> Result<Module, ObserverHostError> {
    scan_module_imports(
        engine,
        bytes,
        ALLOWED_IMPORT_MODULE_PREFIXES,
        DENIED_IMPORT_MODULE_PREFIXES,
        "only `arkhe:observer/*` permitted",
    )
    .map_err(|e| match e {
        ScanImportsError::ParseFailed { reason } => ObserverHostError::ModuleParseFailed { reason },
        ScanImportsError::ImportRejected { name, reason } => {
            ObserverHostError::ImportRejected { name, reason }
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::observer_host::wasmtime_observer::WasmtimeObserverEngineConfig;

    fn engine() -> Engine {
        let cfg = WasmtimeObserverEngineConfig::v0_12_first_cut();
        Engine::new(&cfg.to_config()).expect("v0.12 observer engine builds")
    }

    fn wat_to_bytes(wat: &str) -> Bytes {
        Bytes::from(wat::parse_str(wat).expect("valid wat"))
    }

    #[test]
    fn linker_v0_12_first_cut_constructs_with_no_capabilities() {
        let linker = ObserverCapabilityLinker::v0_12_first_cut(&engine(), &[])
            .expect("empty capability set yields a valid linker");
        assert_eq!(linker.registered_capability_count(), 0);
    }

    #[test]
    fn linker_v0_12_first_cut_constructs_with_pg_write_capability() {
        let cap: Arc<dyn ObserverCapability> = Arc::new(PgWriteCapability::new());
        let linker = ObserverCapabilityLinker::v0_12_first_cut(&engine(), &[cap])
            .expect("PgWriteCapability registers cleanly");
        assert_eq!(linker.registered_capability_count(), 1);
    }

    #[test]
    fn observer_store_data_with_capabilities_collects() {
        let data = ObserverStoreData::with_capabilities([ObserverCapToken::PgWrite])
            .with_initial_fuel(100_000);
        assert!(data.capabilities.contains(&ObserverCapToken::PgWrite));
        assert_eq!(data.initial_fuel, 100_000);
    }

    #[test]
    fn pg_write_capability_token_matches() {
        let cap = PgWriteCapability::new();
        assert_eq!(cap.token(), ObserverCapToken::PgWrite);
    }

    #[test]
    fn pg_write_capability_execute_v0_12_returns_ok() {
        // v0.12 first-cut PgWriteCapability has no PG wiring — always Ok.
        let cap = PgWriteCapability::new();
        assert!(cap.execute(b"any payload").is_ok());
    }

    #[test]
    fn mock_pg_write_records_invocations() {
        let mock = MockPgWriteCapability::new();
        assert_eq!(mock.invocation_count(), 0);
        assert!(mock.execute(b"first").is_ok());
        assert!(mock.execute(b"second").is_ok());
        assert!(mock.execute(b"").is_ok()); // empty payload
        assert_eq!(mock.invocation_count(), 3);
        let recorded = mock.recorded();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0], b"first");
        assert_eq!(recorded[1], b"second");
        assert_eq!(recorded[2], b"");
    }

    #[test]
    fn mock_pg_write_token_matches() {
        let mock = MockPgWriteCapability::new();
        assert_eq!(mock.token(), ObserverCapToken::PgWrite);
    }

    /// Cryptographer Q3 PR review point — PgWriteCapability `self`
    /// fields are chain-orthogonal. v0.12 first-cut: zero fields
    /// (unit struct). The compile-time size check catches future
    /// field additions; PR reviewer must re-verify chain-orthogonality.
    #[test]
    fn pg_write_capability_is_zero_sized_at_v0_12() {
        // Unit struct = zero-sized. Future v0.13+ shell-territory PG
        // wiring may add a connection-pool handle, but that's PG-side
        // (outside the chain) and never reaches L0.
        assert_eq!(std::mem::size_of::<PgWriteCapability>(), 0);
    }

    #[test]
    fn scan_accepts_module_with_arkhe_observer_pg_write() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:observer/pg" "write"
                    (func (param i32 i32))))"#,
        );
        let _module = scan_imports(&engine(), &bytes).expect("allowed import passes scan");
    }

    #[test]
    fn scan_accepts_module_with_no_imports() {
        let bytes = wat_to_bytes(r#"(module (func (export "noop")))"#);
        let _ = scan_imports(&engine(), &bytes).expect("zero-import module passes");
    }

    #[test]
    fn scan_rejects_wasi_random() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:random/random" "get-random-u64"
                    (func (result i64))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:random must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("denied namespace `wasi:random`"),
            "expected specific deny message, got: {msg}"
        );
    }

    #[test]
    fn scan_rejects_wasi_io_streams() {
        // Confirms the deny-list covers all WASI capability surfaces
        // (not just the determinism-critical ones).
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:io/streams" "write"
                    (func (param i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:io must reject");
        let msg = format!("{err}");
        assert!(msg.contains("denied namespace `wasi:io`"), "got: {msg}");
    }

    #[test]
    fn scan_rejects_arkhe_hook_imports_in_observer_context() {
        // Cross-host isolation: an `arkhe:hook/*` import in an observer
        // module is in neither observer allow-list nor WASI deny-list,
        // so it falls through to the catch-all rejection.
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func (param i32 i32) (result i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes)
            .expect_err("arkhe:hook/* must reject in observer context");
        let msg = format!("{err}");
        assert!(
            msg.contains("not in allow-list (only `arkhe:observer/*` permitted)"),
            "got: {msg}"
        );
    }

    #[test]
    fn scan_rejects_unknown_namespace() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "ext:legacy/random" "u64"
                    (func (result i64))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("unknown namespace must reject");
        let msg = format!("{err}");
        assert!(msg.contains("not in allow-list"), "got: {msg}");
    }

    #[test]
    fn scan_rejects_invalid_bytes() {
        let bytes = Bytes::from_static(&[0x00, 0x61, 0x73, 0x6d]);
        let err = scan_imports(&engine(), &bytes).expect_err("invalid bytes must reject");
        assert!(matches!(err, ObserverHostError::ModuleParseFailed { .. }));
    }

    #[test]
    fn scan_rejection_does_not_match_substring_of_allowed_prefix() {
        // `wasi:random-pure` (hypothetical) would be confused-deputy
        // mis-attributed if the deny-list used substring match. The
        // WIT-boundary match in scan_module_imports prevents that —
        // it falls through to the allow-list catch-all.
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:randomly-pure" "ok"
                    (func)))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("non-deny-boundary must reject");
        let msg = format!("{err}");
        // Should be the catch-all rejection, NOT the specific deny.
        assert!(msg.contains("not in allow-list"), "got: {msg}");
        assert!(
            !msg.contains("denied namespace"),
            "must not be deny-list match: {msg}"
        );
    }

    /// `ObserverCapability` trait — verify Debug + Send + Sync at
    /// type-level. The trait signature itself is the cryptographer-
    /// anchored chain-orthogonality enforcement (clause 2).
    #[test]
    fn observer_capability_is_send_sync_debug() {
        fn assert_send_sync_debug<T: Send + Sync + std::fmt::Debug + ?Sized>() {}
        assert_send_sync_debug::<dyn ObserverCapability>();
    }

    #[test]
    fn capability_execution_error_display_does_not_panic() {
        let e = CapabilityExecutionError::ExecutionFailed {
            reason: "test reason".into(),
        };
        assert!(format!("{e}").contains("test reason"));
    }
}
