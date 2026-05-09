//! Capability-bounded wasmtime [`Linker`] template.
//!
//! Three-layer defense for E14.L2-Allow runtime enforcement:
//!
//! 1. **Pre-scan** ([`scan_imports`]) — eager-rejects modules whose imports
//!    do not match the [`ALLOWED_IMPORT_MODULE_PREFIXES`] allow-list, with
//!    explicit specific-error paths for [`DENIED_IMPORT_MODULE_PREFIXES`]
//!    namespaces. Runs before the wasmtime engine sees the module — the
//!    operator audit log gets `denied namespace `wasi:random`` rather than
//!    a generic `unknown import`.
//! 2. **Link-time deny-by-default** — [`CapabilityLinker::deny_by_default`]
//!    only [`Linker::func_wrap`]s the supported `arkhe:hook/*` host
//!    functions. Modules importing any other name fail at instantiation.
//! 3. **Call-time capability check** — every host-fn body inspects
//!    [`HookStoreData::capabilities`] (set per-invocation) and traps
//!    `CapabilityDenied` if the matching [`CapToken`] is absent. Even
//!    a linked function refuses to execute without the per-invocation
//!    grant.
//!
//! ## Allow set
//!
//! - `arkhe:hook/state.read` — read scratchpad value by key bytes.
//! - `arkhe:hook/state.write` — store key→value mapping in scratchpad.
//! - `arkhe:hook/emit.extra_bytes` — append bytes into the in-flight
//!   submission's extra-bytes builder.
//! - `arkhe:hook/fuel.consumed` — return live consumed fuel as i64
//!   (`initial_fuel - Caller::get_fuel()`).
//!
//! ## Why both pre-scan + link-time + call-time
//!
//! The three layers are not redundant — each catches a different attack
//! shape:
//!
//! | Layer       | Catches                                            |
//! |-------------|----------------------------------------------------|
//! | Pre-scan    | Forbidden namespaces (clearer audit error)         |
//! | Link-time   | Typos / unknown names within an allowed namespace  |
//! | Call-time   | Linked host-fn called without per-invocation grant |
//!
//! Belt-and-braces is appropriate for the supply-chain trust boundary
//! (confused-deputy mitigation).

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use wasmtime::{Caller, Engine, Linker, Module};

use super::wasmtime_host::HookHostError;
use super::CapToken;
use crate::wasm_runtime_common::{
    read_caller_memory, scan_module_imports, write_caller_memory, ScanImportsError,
};

/// Allow-list of module prefixes a hook may import from. The pre-scan
/// rejects any import whose `module` field does not start with one of
/// these. Admits only the `arkhe:hook/*` namespace — everything else
/// (including all WASI namespaces) is out of scope.
///
/// **Stability:** additive expansion is non-breaking; removal is a
/// breaking change for hook authors. Each entry should be paired with
/// at least one [`CapToken`] in the call-time check (otherwise the
/// allow-list admits names the host has no way to enforce).
pub const ALLOWED_IMPORT_MODULE_PREFIXES: &[&str] = &["arkhe:hook/"];

/// Explicit deny-list of WASI module prefixes — re-exported from the
/// shared `wasm_runtime_common::WASI_DENY_PREFIXES` constant (DRY
/// consolidation). Hook + observer share the **identical 7-prefix set**
/// so the deny-list lives in one place.
///
/// Pure defense-in-depth — the allow-list above already excludes every
/// WASI prefix; the deny-list adds a *specific* `denied namespace`
/// error so the audit log distinguishes intentional WASI-import attempts
/// from generic allow-list misses.
///
/// Maintenance: kept in sync with the WASI Preview 2 namespace
/// inventory at the shared site (one update point, both hosts inherit).
pub use crate::wasm_runtime_common::WASI_DENY_PREFIXES as DENIED_IMPORT_MODULE_PREFIXES;

/// Per-invocation [`wasmtime::Store`] data threaded through linked host
/// functions. The host clones the per-shell capability set into a fresh
/// `HookStoreData` at each `invoke()`; host-fn bodies inspect
/// `caller.data().capabilities` to enforce the call-time check.
///
/// The shape is `#[non_exhaustive]` so additive growth (extra fields
/// for future host-fn surfaces) does not break out-of-tree consumers.
///
/// Fields:
/// - `capabilities`: per-invocation capability set.
/// - `initial_fuel`: feeds the `fuel.consumed` host-fn computation.
/// - `scratchpad`: backs `state.read` / `state.write` key→value
///   storage.
/// - `extra`: holds the [`super::ExtraBytesBuilder`] threaded through
///   `emit.extra_bytes`.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct HookStoreData {
    /// Capability tokens granted to the hook for this invocation. Set
    /// by the host before [`wasmtime::Linker::instantiate`]; host-fn
    /// bodies trap `CapabilityDenied` if the matching token is absent.
    pub capabilities: BTreeSet<CapToken>,
    /// Fuel granted at the start of this invocation. The host calls
    /// `Store::set_fuel(initial_fuel)` immediately after constructing
    /// the `Store<HookStoreData>`. The `arkhe:hook/fuel.consumed`
    /// host-fn reads this value + `Caller::get_fuel()` to compute
    /// consumption (`initial - remaining`).
    pub initial_fuel: u64,
    /// Hook-scoped key/value scratchpad. Backed by `BTreeMap<Vec<u8>,
    /// Vec<u8>>` for deterministic iteration order (matches
    /// `BTreeSet<CapToken>` discipline elsewhere in this struct).
    /// Populated/queried by the `arkhe:hook/state.{read, write}`
    /// host-fns. Lives for the duration of one `invoke()` call —
    /// fresh map per invocation, contents discarded at end. The host's
    /// threat model assumes per-invocation statelessness for the hook
    /// author's view.
    pub scratchpad: BTreeMap<Vec<u8>, Vec<u8>>,
    /// In-flight submission's extra-bytes builder, moved into
    /// `HookStoreData` for the duration of one `invoke()` so the
    /// `arkhe:hook/emit.extra_bytes` host-fn body can mutate it.
    /// Caller (host) takes the builder back out via
    /// [`Self::take_extra`] after the wasm execution returns.
    pub extra: Option<super::ExtraBytesBuilder>,
}

impl HookStoreData {
    /// Construct a `HookStoreData` from an iterable of capability tokens.
    /// `initial_fuel` defaults to 0 — set via [`Self::with_initial_fuel`]
    /// after the host calls `Store::set_fuel(...)`. `scratchpad`
    /// defaults empty; `extra` defaults `None`.
    pub fn with_capabilities<I: IntoIterator<Item = CapToken>>(caps: I) -> Self {
        Self {
            capabilities: caps.into_iter().collect(),
            initial_fuel: 0,
            scratchpad: BTreeMap::new(),
            extra: None,
        }
    }

    /// Set the initial fuel value for this invocation. Builder method
    /// — call immediately after the host runs
    /// `Store::set_fuel(initial_fuel)` so the value matches what the
    /// store actually holds. The `arkhe:hook/fuel.consumed` host-fn
    /// returns `initial_fuel - Caller::get_fuel()` (i.e. fuel consumed
    /// so far).
    pub fn with_initial_fuel(mut self, initial_fuel: u64) -> Self {
        self.initial_fuel = initial_fuel;
        self
    }

    /// Seed the scratchpad with initial key/value entries. Used by
    /// tests (e.g. to verify `state.read` returns the seeded value).
    /// Production callers always pass an empty iterator (per-
    /// invocation statelessness).
    pub fn with_scratchpad<I, K, V>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<Vec<u8>>,
        V: Into<Vec<u8>>,
    {
        self.scratchpad = entries
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    /// Move an [`super::ExtraBytesBuilder`] into the store data so the
    /// `arkhe:hook/emit.extra_bytes` host-fn body can append to it.
    /// Paired with [`Self::take_extra`] after wasm execution returns.
    pub fn with_extra(mut self, extra: super::ExtraBytesBuilder) -> Self {
        self.extra = Some(extra);
        self
    }

    /// Take ownership of the `extra` builder back from the store data.
    /// Called by the host immediately after wasm execution returns,
    /// so the post-hook policy re-validation step (and ultimately
    /// the L1 build step) can consume the mutated builder.
    pub fn take_extra(&mut self) -> Option<super::ExtraBytesBuilder> {
        self.extra.take()
    }
}

/// Cached wasmtime [`Linker`] template. Constructed once per
/// [`super::wasmtime_host::WasmtimeHookHost`] (per-shell in operator
/// deployments) and reused across every invocation. Per-invocation
/// `Store<HookStoreData>` instances bring the capability set; the
/// linker holds only the host-fn bindings.
///
/// **Concurrency:** [`Linker<T>`] is `Send + Sync` for `T: Send + Sync`
/// — a single instance can serve concurrent invocations on different
/// threads (each with its own `Store`).
pub struct CapabilityLinker {
    inner: Linker<HookStoreData>,
}

// SealedHostImport safeguard. The hook `CapabilityLinker` impls both
// the private `Sealed` marker (only reachable from
// `arkhe-forge-platform`) and the public
// `wasm_runtime_common::SealedHostImport` trait. External crates
// cannot fork the host-linker structure with their own linker type,
// preserving the **HostImports compile-time invariant**: the wasmtime
// host-fn import surface (4-set hook host-fns) is structurally bounded
// at the host-defining crate boundary.
impl crate::wasm_runtime_common::sealed_impl::Sealed for CapabilityLinker {}
impl crate::wasm_runtime_common::SealedHostImport for CapabilityLinker {}

impl std::fmt::Debug for CapabilityLinker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityLinker")
            .field("allowed_prefixes", &ALLOWED_IMPORT_MODULE_PREFIXES)
            .field("denied_prefixes", &DENIED_IMPORT_MODULE_PREFIXES)
            .finish_non_exhaustive()
    }
}

impl CapabilityLinker {
    /// Build the deny-by-default linker. Binds four host-fns:
    ///
    /// | Import path                  | CapToken          | Sig                       | Behaviour                                                |
    /// |------------------------------|-------------------|---------------------------|----------------------------------------------------------|
    /// | `arkhe:hook/state.read`      | `StateRead`       | `(i32, i32, i32, i32) -> i32` | scratchpad lookup; returns bytes copied / -1 / -2     |
    /// | `arkhe:hook/state.write`     | `StateWrite`      | `(i32, i32, i32, i32)`    | scratchpad insert (key bytes → value bytes)              |
    /// | `arkhe:hook/emit.extra_bytes`| `EmitExtraBytes`  | `(i32, i32)`              | append bytes to seeded `ExtraBytesBuilder`               |
    /// | `arkhe:hook/fuel.consumed`   | `FuelConsumed`    | `() -> i64`               | returns `initial_fuel - Caller::get_fuel()`              |
    ///
    /// Each body inspects the per-invocation
    /// [`HookStoreData::capabilities`] set — if the matching
    /// [`CapToken`] is absent, trap with `CapabilityDenied`. The
    /// `state.{read, write}` and `emit.extra_bytes` bodies route input
    /// and output bytes through the cryptographer-pinned bounds-check
    /// helpers in `wasm_runtime_common`. `fuel.consumed` is metric-only
    /// (no scratchpad or linear-memory access) and returns the live
    /// consumed fuel value.
    pub fn deny_by_default(engine: &Engine) -> Result<Self, HookHostError> {
        let mut linker = Linker::<HookStoreData>::new(engine);
        // arkhe:hook/state.read — read scratchpad value by key bytes
        // into a wasm-side output buffer.
        //
        // Sig: (key_ptr, key_len, val_ptr_out, val_buf_len) -> i32.
        //   Returns:
        //     >=0 → number of bytes copied into val_ptr_out
        //     -1  → key not found in scratchpad
        //     -2  → val_buf_len too small to hold the value
        //
        // Bounds-check on (key_ptr, key_len) input read + (val_ptr_out,
        // value.len()) output write — both ranges go through the
        // cryptographer-pinned helpers.
        linker
            .func_wrap(
                "arkhe:hook/state",
                "read",
                |mut caller: Caller<'_, HookStoreData>,
                 key_ptr: i32,
                 key_len: i32,
                 val_ptr_out: i32,
                 val_buf_len: i32|
                 -> Result<i32, wasmtime::Error> {
                    if !caller.data().capabilities.contains(&CapToken::StateRead) {
                        return Err(wasmtime::Error::msg(
                            "arkhe:hook/state.read called without StateRead capability",
                        ));
                    }
                    if val_buf_len < 0 {
                        return Err(wasmtime::Error::msg(format!(
                            "OOB: negative val_buf_len ({val_buf_len})"
                        )));
                    }
                    let key = read_caller_memory(&mut caller, key_ptr, key_len)?;
                    // Clone the value out so the immutable borrow on
                    // `caller.data()` is released before the mutable
                    // borrow needed by `write_caller_memory`.
                    let value: Option<Vec<u8>> = caller.data().scratchpad.get(&key).cloned();
                    match value {
                        None => Ok(-1),
                        Some(v) => {
                            if v.len() as u64 > val_buf_len as u64 {
                                return Ok(-2);
                            }
                            write_caller_memory(&mut caller, val_ptr_out, &v)?;
                            Ok(v.len() as i32)
                        }
                    }
                },
            )
            .map_err(|e| HookHostError::LinkerSetupFailed {
                reason: format!("arkhe:hook/state.read: {e}"),
            })?;
        // arkhe:hook/state.write — store key→value mapping in scratchpad.
        // Bounds-check both (key) + (val) ranges; insert/replace
        // existing entry. No return value (void).
        linker
            .func_wrap(
                "arkhe:hook/state",
                "write",
                |mut caller: Caller<'_, HookStoreData>,
                 key_ptr: i32,
                 key_len: i32,
                 val_ptr: i32,
                 val_len: i32|
                 -> Result<(), wasmtime::Error> {
                    if !caller.data().capabilities.contains(&CapToken::StateWrite) {
                        return Err(wasmtime::Error::msg(
                            "arkhe:hook/state.write called without StateWrite capability",
                        ));
                    }
                    let key = read_caller_memory(&mut caller, key_ptr, key_len)?;
                    let val = read_caller_memory(&mut caller, val_ptr, val_len)?;
                    caller.data_mut().scratchpad.insert(key, val);
                    Ok(())
                },
            )
            .map_err(|e| HookHostError::LinkerSetupFailed {
                reason: format!("arkhe:hook/state.write: {e}"),
            })?;
        // arkhe:hook/emit.extra_bytes — append bytes into the in-flight
        // submission's extra-bytes builder. Bounds-check (ptr, len),
        // read bytes, append to the `HookStoreData::extra` builder
        // (must be Some — caller's responsibility to seed via
        // `with_extra`). If `extra` is `None` a host-fn programmer
        // error is reported as a trap rather than silent drop; prevents
        // accidentally-discarded extra bytes.
        linker
            .func_wrap(
                "arkhe:hook/emit",
                "extra_bytes",
                |mut caller: Caller<'_, HookStoreData>,
                 ptr: i32,
                 len: i32|
                 -> Result<(), wasmtime::Error> {
                    if !caller
                        .data()
                        .capabilities
                        .contains(&CapToken::EmitExtraBytes)
                    {
                        return Err(wasmtime::Error::msg(
                            "arkhe:hook/emit.extra_bytes called without EmitExtraBytes capability",
                        ));
                    }
                    let bytes = read_caller_memory(&mut caller, ptr, len)?;
                    let extra = caller.data_mut().extra.as_mut().ok_or_else(|| {
                        wasmtime::Error::msg(
                            "arkhe:hook/emit.extra_bytes called without an `extra` builder seeded in HookStoreData",
                        )
                    })?;
                    extra.append(&bytes);
                    Ok(())
                },
            )
            .map_err(|e| HookHostError::LinkerSetupFailed {
                reason: format!("arkhe:hook/emit.extra_bytes: {e}"),
            })?;
        // arkhe:hook/fuel.consumed — return live consumed fuel as i64.
        // No scratchpad / linear-memory access needed, just a wasmtime
        // fuel API call. Returns `i64` (wasm has no unsigned types in
        // core wasm; the value is non-negative semantically).
        linker
            .func_wrap(
                "arkhe:hook/fuel",
                "consumed",
                |caller: Caller<'_, HookStoreData>| -> Result<i64, wasmtime::Error> {
                    if !caller.data().capabilities.contains(&CapToken::FuelConsumed) {
                        return Err(wasmtime::Error::msg(
                            "arkhe:hook/fuel.consumed called without FuelConsumed capability",
                        ));
                    }
                    let initial = caller.data().initial_fuel;
                    let remaining = caller.get_fuel().unwrap_or(0);
                    let consumed = initial.saturating_sub(remaining);
                    // u64 → i64 — saturate at i64::MAX so wasm always
                    // sees a non-negative value even in pathological
                    // overflow scenarios. Real fuel budgets are far
                    // below i64::MAX (~10^8 typical at 10 ms target).
                    Ok(i64::try_from(consumed).unwrap_or(i64::MAX))
                },
            )
            .map_err(|e| HookHostError::LinkerSetupFailed {
                reason: format!("arkhe:hook/fuel.consumed: {e}"),
            })?;
        Ok(Self { inner: linker })
    }

    /// Borrow the underlying [`Linker`] for invoke-time instantiation.
    /// `WasmtimeHookHost::invoke` uses this accessor to call
    /// `linker.instantiate(&mut store, &module)` per invocation.
    pub fn linker(&self) -> &Linker<HookStoreData> {
        &self.inner
    }
}

/// Pre-scan a module's imports against the allow-list +
/// specific-error deny-list. Returns the parsed [`Module`] on success
/// (callers reuse it for instantiation rather than re-parsing).
///
/// # Errors
///
/// - [`HookHostError::ModuleParseFailed`] — wasmtime rejected the bytes
///   as a non-wasm module.
/// - [`HookHostError::ImportRejected`] with `reason: "denied namespace
///   <prefix>"` — the module imports from a [`DENIED_IMPORT_MODULE_PREFIXES`]
///   namespace.
/// - [`HookHostError::ImportRejected`] with `reason: "not in allow-list"`
///   — the module imports from a namespace outside
///   [`ALLOWED_IMPORT_MODULE_PREFIXES`] but not in the explicit deny list.
pub fn scan_imports(engine: &Engine, bytes: &Bytes) -> Result<Module, HookHostError> {
    scan_module_imports(
        engine,
        bytes,
        ALLOWED_IMPORT_MODULE_PREFIXES,
        DENIED_IMPORT_MODULE_PREFIXES,
        "only `arkhe:hook/*` permitted",
    )
    .map_err(|e| match e {
        ScanImportsError::ParseFailed { reason } => HookHostError::ModuleParseFailed { reason },
        ScanImportsError::ImportRejected { name, reason } => {
            HookHostError::ImportRejected { name, reason }
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hook_host::wasmtime_host::WasmtimeEngineConfig;
    use wasmtime::Store;

    fn engine() -> Engine {
        let cfg = WasmtimeEngineConfig::deterministic_replay();
        Engine::new(&cfg.to_config()).expect("default engine builds")
    }

    fn wat_to_bytes(wat: &str) -> Bytes {
        Bytes::from(wat::parse_str(wat).expect("valid wat"))
    }

    #[test]
    fn linker_deny_by_default_constructs() {
        let _ = CapabilityLinker::deny_by_default(&engine()).expect("default linker constructs");
    }

    #[test]
    fn scan_accepts_module_with_only_arkhe_hook_state_read() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func (param i32 i32) (result i32))))"#,
        );
        let _module = scan_imports(&engine(), &bytes).expect("allowed import passes scan");
    }

    #[test]
    fn scan_accepts_module_with_no_imports() {
        // Pure compute hook — emits nothing, imports nothing.
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
        assert!(msg.contains("wasi:random"), "msg = {msg}");
        assert!(msg.contains("denied namespace"), "msg = {msg}");
    }

    #[test]
    fn scan_rejects_wasi_clocks() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:clocks/wall-clock" "now"
                    (func (result i64))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:clocks must reject");
        assert!(format!("{err}").contains("wasi:clocks"));
    }

    #[test]
    fn scan_rejects_wasi_filesystem() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:filesystem/types" "open-at"
                    (func (param i32 i32 i32) (result i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:filesystem must reject");
        assert!(format!("{err}").contains("wasi:filesystem"));
    }

    #[test]
    fn scan_rejects_wasi_sockets() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:sockets/tcp" "connect"
                    (func (param i32) (result i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:sockets must reject");
        assert!(format!("{err}").contains("wasi:sockets"));
    }

    #[test]
    fn scan_rejects_wasi_io() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:io/streams" "write"
                    (func (param i32 i32 i32) (result i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:io must reject");
        assert!(format!("{err}").contains("wasi:io"));
    }

    #[test]
    fn scan_rejects_wasi_cli() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:cli/environment" "get-environment"
                    (func (result i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:cli must reject");
        assert!(format!("{err}").contains("wasi:cli"));
    }

    #[test]
    fn scan_rejects_wasi_http() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:http/outgoing-handler" "handle"
                    (func (param i32) (result i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("wasi:http must reject");
        assert!(format!("{err}").contains("wasi:http"));
    }

    #[test]
    fn scan_rejects_unknown_namespace_with_allow_list_message() {
        // Outside `arkhe:hook/*` and not in explicit deny list — falls
        // through to the catch-all allow-list rejection.
        let bytes = wat_to_bytes(
            r#"(module
                (import "evil:network/exfil" "send"
                    (func (param i32 i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("unknown ns must reject");
        let msg = format!("{err}");
        assert!(msg.contains("not in allow-list"), "msg = {msg}");
        assert!(msg.contains("evil:network"), "msg = {msg}");
    }

    /// Cross-host isolation reciprocal:
    /// `arkhe:observer/*` imports in hook context must reject. Not in
    /// the hook allow-list (`arkhe:hook/*`) and not in the WASI deny
    /// set, so falls through to the catch-all allow-list rejection.
    /// Pairs with the observer-side
    /// `scan_rejects_arkhe_hook_imports_in_observer_context` test —
    /// together they verify bidirectional namespace isolation.
    #[test]
    fn scan_rejects_arkhe_observer_imports_in_hook_context() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:observer/pg" "write"
                    (func (param i32 i32))))"#,
        );
        let err = scan_imports(&engine(), &bytes)
            .expect_err("arkhe:observer/* must reject in hook context");
        let msg = format!("{err}");
        assert!(
            msg.contains("not in allow-list (only `arkhe:hook/*` permitted)"),
            "expected catch-all rejection, got: {msg}"
        );
    }

    #[test]
    fn scan_rejects_invalid_wasm_bytes() {
        // 4-byte truncated magic — not a valid module.
        let bytes = Bytes::from_static(&[0x00, 0x61, 0x73, 0x6d]);
        let err = scan_imports(&engine(), &bytes).expect_err("invalid bytes must reject");
        assert!(matches!(err, HookHostError::ModuleParseFailed { .. }));
    }

    /// Fuel budget for tests — enough to reach the host-fn call without
    /// the wasm code itself running out. The production budget is
    /// calibrated against the 10 ms wall-clock target; tests just need
    /// "plenty".
    const TEST_FUEL: u64 = 1_000_000;

    /// state.read cap-deny: missing `StateRead` capability → trap fires
    /// before any scratchpad lookup or memory access. Uses the 4-arg
    /// signature with all-zero literals so the host-fn fails at the
    /// cap check before reaching bounds-check or scratchpad code.
    #[test]
    fn state_read_traps_with_capability_denied_when_missing() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func $r (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "go") (result i32)
                    i32.const 0
                    i32.const 0
                    i32.const 0
                    i32.const 0
                    call $r))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        // Empty capability set — `StateRead` not granted.
        let mut store = Store::new(&engine, HookStoreData::default());
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i32>(&mut store, "go")
            .expect("go export");
        let err = go.call(&mut store, ()).expect_err("trap expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("StateRead capability"), "msg = {msg}");
    }

    /// state.read returns -1 when the queried key is not present in
    /// the per-invocation scratchpad.
    #[test]
    fn state_read_returns_minus_one_when_key_not_found() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // Module writes "k" (1 byte) at memory address 0, then calls
        // state.read with (key_ptr=0, key_len=1, val_ptr_out=8, val_buf_len=64).
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func $r (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "k")
                (func (export "go") (result i32)
                    i32.const 0
                    i32.const 1
                    i32.const 8
                    i32.const 64
                    call $r))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        // Empty scratchpad → key "k" not present.
        let store_data = HookStoreData::with_capabilities([CapToken::StateRead]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i32>(&mut store, "go")
            .expect("go export");
        let result = go.call(&mut store, ()).expect("call should succeed");
        assert_eq!(result, -1, "expected -1 for not-found, got {result}");
    }

    /// state.read returns the value byte length when the key is
    /// found in the seeded scratchpad. Verifies the round-trip from
    /// `HookStoreData::with_scratchpad` seed → wasm-side read.
    #[test]
    fn state_read_returns_seeded_value_length_when_key_found() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func $r (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "k")
                (func (export "go") (result i32)
                    i32.const 0
                    i32.const 1
                    i32.const 8
                    i32.const 64
                    call $r))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data = HookStoreData::with_capabilities([CapToken::StateRead])
            .with_scratchpad([(b"k" as &[u8], b"value-bytes-here" as &[u8])]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i32>(&mut store, "go")
            .expect("go export");
        let bytes_copied = go.call(&mut store, ()).expect("call should succeed");
        assert_eq!(bytes_copied, b"value-bytes-here".len() as i32);
    }

    /// state.read returns -2 when the supplied output buffer is
    /// smaller than the value length.
    #[test]
    fn state_read_returns_minus_two_when_buffer_too_small() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // val_buf_len=2 but value is 16 bytes → -2.
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func $r (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "k")
                (func (export "go") (result i32)
                    i32.const 0
                    i32.const 1
                    i32.const 8
                    i32.const 2
                    call $r))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data = HookStoreData::with_capabilities([CapToken::StateRead])
            .with_scratchpad([(b"k" as &[u8], b"value-bytes-here" as &[u8])]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i32>(&mut store, "go")
            .expect("go export");
        let result = go.call(&mut store, ()).expect("call should succeed");
        assert_eq!(result, -2, "expected -2 for buffer-too-small, got {result}");
    }

    #[test]
    fn link_time_deny_by_default_rejects_unknown_arkhe_hook_name() {
        // `arkhe:hook/state` namespace is allowed, but `unknown` name
        // is not bound — instantiation fails at the wasmtime Linker
        // (the second defense layer, after pre-scan accepts the
        // allowed namespace).
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "unknown_fn"
                    (func)))"#,
        );
        let module = scan_imports(&engine, &bytes).expect("scan accepts allowed namespace");
        let mut store = Store::new(&engine, HookStoreData::default());
        let err = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .expect_err("unknown name must fail at link-time");
        // wasmtime's "unknown import" / "no item named" error.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unknown") || msg.contains("import") || msg.contains("not"),
            "expected link-time rejection, got: {msg}"
        );
    }

    #[test]
    fn debug_format_lists_prefixes() {
        let cl = CapabilityLinker::deny_by_default(&engine()).unwrap();
        let s = format!("{cl:?}");
        assert!(s.contains("arkhe:hook/"));
        assert!(s.contains("wasi:random"));
    }

    #[test]
    fn hook_store_data_default_has_no_capabilities() {
        let d = HookStoreData::default();
        assert!(d.capabilities.is_empty());
    }

    #[test]
    fn hook_store_data_with_capabilities_round_trips() {
        let d = HookStoreData::with_capabilities([CapToken::StateRead, CapToken::FuelConsumed]);
        assert!(d.capabilities.contains(&CapToken::StateRead));
        assert!(d.capabilities.contains(&CapToken::FuelConsumed));
        assert_eq!(d.capabilities.len(), 2);
    }

    // ---- WIT-boundary check tests + state.write + emit.extra_bytes ----

    /// WIT-boundary: `wasi:randomly-pure` shares the `wasi:random`
    /// byte prefix but is NOT a `wasi:random/...` namespace import. The
    /// boundary check (next char must be `/`, `@`, or end-of-string)
    /// stops it being mis-attributed to the deny-list. It still rejects,
    /// but via the allow-list catch-all with the correct
    /// `not in allow-list` reason.
    #[test]
    fn wit_boundary_check_routes_lookalike_to_allow_list_message() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:randomly-pure" "noop"
                    (func)))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("lookalike must reject");
        let msg = format!("{err}");
        // Routed via the allow-list catch-all, NOT the deny-list.
        assert!(msg.contains("not in allow-list"), "msg = {msg}");
        assert!(!msg.contains("denied namespace"), "msg = {msg}");
        assert!(msg.contains("wasi:randomly-pure"), "msg = {msg}");
    }

    /// WIT-boundary: bare `wasi:random` (no `/` or `@`) at the namespace position
    /// hits the boundary check via `trailing.is_empty()` — denied.
    #[test]
    fn wit_boundary_check_admits_exact_prefix_match() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:random" "f"
                    (func)))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("exact prefix must reject");
        let msg = format!("{err}");
        assert!(msg.contains("denied namespace"), "msg = {msg}");
        assert!(msg.contains("wasi:random"), "msg = {msg}");
    }

    /// WIT-boundary: `package@version/interface` form (`@` boundary) stays in
    /// the deny-list — denied with the specific-error reason.
    #[test]
    fn wit_boundary_check_admits_at_version_suffix() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:clocks@0.2.0/wall-clock" "now"
                    (func (result i64))))"#,
        );
        let err = scan_imports(&engine(), &bytes).expect_err("@-suffix must reject");
        let msg = format!("{err}");
        assert!(msg.contains("denied namespace"), "msg = {msg}");
        assert!(msg.contains("wasi:clocks"), "msg = {msg}");
    }

    /// state.write call-time check: capability missing → `CapabilityDenied` trap.
    #[test]
    fn state_write_traps_with_capability_denied_when_missing() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "write"
                    (func $w (param i32 i32 i32 i32)))
                (func (export "go")
                    i32.const 0
                    i32.const 0
                    i32.const 0
                    i32.const 0
                    call $w))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let mut store = Store::new(&engine, HookStoreData::default());
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go export");
        let err = go.call(&mut store, ()).expect_err("trap expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("StateWrite capability"), "msg = {msg}");
    }

    /// state.write end-to-end: wasm writes a key/value pair into the
    /// scratchpad; host inspects `Store::data().scratchpad` post-call.
    #[test]
    fn state_write_inserts_into_scratchpad() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // Module: write key="kk" (2 bytes at offset 0) → value="vvvv"
        // (4 bytes at offset 2). state.write(0, 2, 2, 4).
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "write"
                    (func $w (param i32 i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "kkvvvv")
                (func (export "go")
                    i32.const 0
                    i32.const 2
                    i32.const 2
                    i32.const 4
                    call $w))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data = HookStoreData::with_capabilities([CapToken::StateWrite]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go export");
        go.call(&mut store, ()).expect("call should succeed");
        // Verify the scratchpad now has the entry.
        let value = store.data().scratchpad.get(b"kk" as &[u8]).cloned();
        assert_eq!(value, Some(b"vvvv".to_vec()));
    }

    /// state round-trip: write `(k, v)` then read `k` and verify the
    /// value bytes appear at the wasm-side output buffer. Exercises
    /// the full input + output bounds-check + scratchpad mutation +
    /// memory-write path end-to-end.
    #[test]
    fn state_round_trip_write_then_read() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // Module: write key="k" at offset 0, value="hello" at offset 1
        // (5 bytes), then read key=offset 0, len 1 into output buffer
        // at offset 16, len 32. Returns bytes copied (= 5).
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/state" "write"
                    (func $w (param i32 i32 i32 i32)))
                (import "arkhe:hook/state" "read"
                    (func $r (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "khello")
                (func (export "go") (result i32)
                    i32.const 0
                    i32.const 1
                    i32.const 1
                    i32.const 5
                    call $w
                    i32.const 0
                    i32.const 1
                    i32.const 16
                    i32.const 32
                    call $r))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data =
            HookStoreData::with_capabilities([CapToken::StateRead, CapToken::StateWrite]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i32>(&mut store, "go")
            .expect("go export");
        let bytes_copied = go.call(&mut store, ()).expect("call should succeed");
        assert_eq!(bytes_copied, 5, "state.read should report 5 bytes copied");
        // Inspect wasm memory at offset 16..21 — should contain "hello".
        let memory = inst.get_memory(&mut store, "memory").expect("memory");
        let mut out = [0u8; 5];
        memory
            .read(&store, 16, &mut out)
            .expect("read output buffer");
        assert_eq!(&out, b"hello");
    }

    /// emit.extra_bytes call-time check: capability missing → trap.
    #[test]
    fn emit_extra_bytes_traps_with_capability_denied_when_missing() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/emit" "extra_bytes"
                    (func $e (param i32 i32)))
                (func (export "go")
                    i32.const 0
                    i32.const 0
                    call $e))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let mut store = Store::new(&engine, HookStoreData::default());
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go export");
        let err = go.call(&mut store, ()).expect_err("trap expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("EmitExtraBytes capability"), "msg = {msg}");
    }

    /// emit.extra_bytes appends bytes to the seeded
    /// [`super::ExtraBytesBuilder`] in `HookStoreData::extra`. After
    /// the wasm call returns, `take_extra` recovers the mutated builder
    /// for downstream consumption — end-to-end.
    #[test]
    fn emit_extra_bytes_appends_to_seeded_builder() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // Module: write 4 bytes "ABCD" to memory at offset 0, then
        // call extra_bytes(0, 4).
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/emit" "extra_bytes"
                    (func $e (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "ABCD")
                (func (export "go")
                    i32.const 0
                    i32.const 4
                    call $e))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data = HookStoreData::with_capabilities([CapToken::EmitExtraBytes])
            .with_extra(super::super::ExtraBytesBuilder::new());
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go export");
        go.call(&mut store, ()).expect("call should succeed");
        let extra = store.data_mut().take_extra().expect("extra was seeded");
        let frozen = extra.freeze();
        assert_eq!(&frozen[..], b"ABCD");
    }

    /// emit.extra_bytes traps if `HookStoreData::extra` is `None` (the
    /// host did not seed a builder). Programmer-error guard prevents
    /// silently-discarded extra bytes.
    #[test]
    fn emit_extra_bytes_traps_when_extra_not_seeded() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/emit" "extra_bytes"
                    (func $e (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "AB")
                (func (export "go")
                    i32.const 0
                    i32.const 2
                    call $e))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        // Capability granted but `extra` field is None.
        let store_data = HookStoreData::with_capabilities([CapToken::EmitExtraBytes]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go export");
        let err = go.call(&mut store, ()).expect_err("trap expected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("without an `extra` builder seeded"),
            "msg = {msg}"
        );
    }

    // ---- fuel.consumed bind + initial_fuel + DENIED list sync ----

    /// fuel.consumed call-time check: capability missing → `CapabilityDenied` trap.
    #[test]
    fn fuel_consumed_traps_with_capability_denied_when_missing() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/fuel" "consumed"
                    (func $f (result i64)))
                (func (export "go") (result i64) call $f))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let mut store = Store::new(&engine, HookStoreData::default());
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i64>(&mut store, "go")
            .expect("go export");
        let err = go.call(&mut store, ()).expect_err("trap expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("FuelConsumed capability"), "msg = {msg}");
    }

    /// fuel.consumed: capability present, no work done yet → returns 0.
    #[test]
    fn fuel_consumed_returns_zero_at_invocation_start() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/fuel" "consumed"
                    (func $f (result i64)))
                (func (export "go") (result i64) call $f))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data =
            HookStoreData::with_capabilities([CapToken::FuelConsumed]).with_initial_fuel(TEST_FUEL);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i64>(&mut store, "go")
            .expect("go export");
        // The wasm `call` itself burns a small amount of fuel; the
        // host-fn call burns more (`func_wrap` overhead). So we expect
        // a small non-negative value, not exactly 0.
        let consumed = go.call(&mut store, ()).expect("call should succeed");
        assert!(consumed >= 0, "consumed = {consumed}");
        // Must be far less than the budget — minimal work performed.
        assert!(
            (consumed as u64) < TEST_FUEL / 100,
            "expected minimal consumption, got {consumed} of {TEST_FUEL}"
        );
    }

    /// fuel.consumed: after a noticeable wasm workload, returns a
    /// strictly positive value reflecting fuel consumption.
    #[test]
    fn fuel_consumed_grows_with_wasm_work() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // Module with a small loop that does measurable work before
        // calling fuel.consumed.
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/fuel" "consumed"
                    (func $f (result i64)))
                (func (export "go") (result i64)
                    (local $i i32)
                    (local.set $i (i32.const 1000))
                    (loop $continue
                        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
                        (br_if $continue (i32.gt_s (local.get $i) (i32.const 0))))
                    call $f))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data =
            HookStoreData::with_capabilities([CapToken::FuelConsumed]).with_initial_fuel(TEST_FUEL);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i64>(&mut store, "go")
            .expect("go export");
        let consumed = go.call(&mut store, ()).expect("call should succeed");
        // 1000-iteration loop must consume more than the no-op baseline.
        assert!(
            consumed > 100,
            "expected loop-driven consumption, got {consumed}"
        );
    }

    /// fuel.consumed reports correct value even when initial_fuel is 0
    /// (degenerate but defensively-handled — value clamps to 0).
    #[test]
    fn fuel_consumed_handles_zero_initial_gracefully() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let bytes = wat_to_bytes(
            r#"(module
                (import "arkhe:hook/fuel" "consumed"
                    (func $f (result i64)))
                (func (export "go") (result i64) call $f))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        // initial_fuel = 0, but TEST_FUEL set on Store → saturating_sub
        // bottoms out at 0.
        let store_data = HookStoreData::with_capabilities([CapToken::FuelConsumed]);
        // initial_fuel default = 0
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), i64>(&mut store, "go")
            .expect("go export");
        let consumed = go.call(&mut store, ()).expect("call should succeed");
        // initial=0, remaining=positive → saturating_sub = 0
        assert_eq!(consumed, 0, "consumed = {consumed} should saturate to 0");
    }

    /// HookStoreData::with_initial_fuel builder round-trip.
    #[test]
    fn hook_store_data_with_initial_fuel_round_trips() {
        let d =
            HookStoreData::with_capabilities([CapToken::FuelConsumed]).with_initial_fuel(42_000);
        assert_eq!(d.initial_fuel, 42_000);
        assert!(d.capabilities.contains(&CapToken::FuelConsumed));
    }

    /// Engine fuel-metering: when a Store starts with low fuel, wasm
    /// loops trap with "all fuel consumed" before the host-fn is reached.
    /// Verifies the default Engine config's fuel-metering is actually
    /// wired through `Engine::new` → `Config::consume_fuel(true)`.
    #[test]
    fn wasm_traps_when_fuel_exhausted() {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        // A very tight infinite loop — guaranteed to exhaust any finite fuel.
        let bytes = wat_to_bytes(
            r#"(module
                (func (export "go")
                    (loop $forever (br $forever))))"#,
        );
        let module = scan_imports(&engine, &bytes).unwrap();
        let mut store = Store::new(&engine, HookStoreData::default());
        // Tiny fuel — exhausted within a few iterations.
        store.set_fuel(1_000).expect("seed fuel");
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go export");
        let err = go.call(&mut store, ()).expect_err("fuel must exhaust");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("fuel") || msg.contains("Fuel"),
            "expected fuel-exhaustion trap, got: {msg}"
        );
    }

    // ---- memory bounds-check OOB tests ----

    /// Build a wasm module that calls state.read with literal
    /// (key_ptr, key_len) + zero-length output buffer at ptr 0 + 1-page
    /// memory export. Used by tests that exercise the input-side
    /// bounds-check path (OOB on key range). The output side is a
    /// zero-length buffer so the helper short-circuits without
    /// engaging memory writes.
    fn wat_state_read_with_memory(key_ptr: i32, key_len: i32) -> Bytes {
        wat_state_read_full(key_ptr, key_len, 0, 0)
    }

    /// Build a wasm module that calls state.read with all four
    /// arguments literal.
    fn wat_state_read_full(
        key_ptr: i32,
        key_len: i32,
        val_ptr_out: i32,
        val_buf_len: i32,
    ) -> Bytes {
        let wat = format!(
            r#"(module
                (import "arkhe:hook/state" "read"
                    (func $r (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "go") (result i32)
                    i32.const {key_ptr}
                    i32.const {key_len}
                    i32.const {val_ptr_out}
                    i32.const {val_buf_len}
                    call $r))"#
        );
        Bytes::from(wat::parse_str(&wat).expect("valid wat"))
    }

    fn wat_state_write_with_memory(
        key_ptr: i32,
        key_len: i32,
        val_ptr: i32,
        val_len: i32,
    ) -> Bytes {
        let wat = format!(
            r#"(module
                (import "arkhe:hook/state" "write"
                    (func $w (param i32 i32 i32 i32)))
                (memory (export "memory") 1)
                (func (export "go")
                    i32.const {key_ptr}
                    i32.const {key_len}
                    i32.const {val_ptr}
                    i32.const {val_len}
                    call $w))"#
        );
        Bytes::from(wat::parse_str(&wat).expect("valid wat"))
    }

    fn wat_emit_with_memory(ptr: i32, len: i32) -> Bytes {
        let wat = format!(
            r#"(module
                (import "arkhe:hook/emit" "extra_bytes"
                    (func $e (param i32 i32)))
                (memory (export "memory") 1)
                (func (export "go")
                    i32.const {ptr}
                    i32.const {len}
                    call $e))"#
        );
        Bytes::from(wat::parse_str(&wat).expect("valid wat"))
    }

    fn run_export<R: wasmtime::WasmResults>(
        bytes: Bytes,
        cap: CapToken,
    ) -> Result<R, wasmtime::Error> {
        let engine = engine();
        let cap_linker = CapabilityLinker::deny_by_default(&engine).unwrap();
        let module = scan_imports(&engine, &bytes).unwrap();
        let store_data = HookStoreData::with_capabilities([cap]);
        let mut store = Store::new(&engine, store_data);
        store.set_fuel(TEST_FUEL).unwrap();
        let inst = cap_linker
            .linker()
            .instantiate(&mut store, &module)
            .unwrap();
        let go = inst
            .get_typed_func::<(), R>(&mut store, "go")
            .expect("go export");
        go.call(&mut store, ())
    }

    #[test]
    fn state_read_traps_on_oob_ptr_plus_len() {
        // 1-page memory = 65536 bytes. ptr=65000, len=1000 → end=66000 > 65536.
        let bytes = wat_state_read_with_memory(65_000, 1_000);
        let err = run_export::<i32>(bytes, CapToken::StateRead).expect_err("OOB expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("OOB"), "msg = {msg}");
        assert!(msg.contains("exceeds memory size"), "msg = {msg}");
    }

    #[test]
    fn state_read_traps_on_negative_len() {
        let bytes = wat_state_read_with_memory(0, -1);
        let err = run_export::<i32>(bytes, CapToken::StateRead).expect_err("negative len trap");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("OOB") && msg.contains("negative length"),
            "msg = {msg}"
        );
    }

    #[test]
    fn state_read_traps_on_negative_ptr() {
        let bytes = wat_state_read_with_memory(-1, 1);
        let err = run_export::<i32>(bytes, CapToken::StateRead).expect_err("negative ptr trap");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("OOB") && msg.contains("negative pointer"),
            "msg = {msg}"
        );
    }

    #[test]
    fn state_read_traps_on_huge_ptr() {
        // ptr near i32::MAX + non-zero len → must reject; with i32 reinterp
        // both ≤ 2^31-1 so u64 sum cannot overflow u64, but it WILL exceed
        // the 64 KiB memory size → "exceeds memory size" path.
        let bytes = wat_state_read_with_memory(i32::MAX, 1);
        let err = run_export::<i32>(bytes, CapToken::StateRead).expect_err("huge ptr trap");
        let msg = format!("{err:?}");
        assert!(msg.contains("OOB"), "msg = {msg}");
    }

    /// state.read with zero-length key (key_len=0) hits the
    /// `read_caller_memory` len==0 early-return — empty key bytes pass
    /// through without OOB. Looking up the empty-byte key in an empty
    /// scratchpad returns -1 (not found).
    #[test]
    fn state_read_zero_key_returns_minus_one_in_empty_scratchpad() {
        let bytes = wat_state_read_with_memory(0, 0);
        let result = run_export::<i32>(bytes, CapToken::StateRead)
            .expect("zero-len key looks up empty scratchpad");
        assert_eq!(result, -1, "expected -1 (not-found), got {result}");
    }

    #[test]
    fn state_write_traps_on_key_oob() {
        let bytes = wat_state_write_with_memory(65_000, 1_000, 0, 0);
        let err = run_export::<()>(bytes, CapToken::StateWrite).expect_err("key OOB expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("OOB"), "msg = {msg}");
    }

    #[test]
    fn state_write_traps_on_val_oob() {
        // key valid (0,0), val OOB.
        let bytes = wat_state_write_with_memory(0, 0, 65_000, 1_000);
        let err = run_export::<()>(bytes, CapToken::StateWrite).expect_err("val OOB expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("OOB"), "msg = {msg}");
    }

    #[test]
    fn emit_extra_bytes_traps_on_oob() {
        let bytes = wat_emit_with_memory(65_000, 1_000);
        let err = run_export::<()>(bytes, CapToken::EmitExtraBytes).expect_err("OOB expected");
        let msg = format!("{err:?}");
        assert!(msg.contains("OOB"), "msg = {msg}");
    }

    /// Module without a `memory` export — non-zero key_len read traps
    /// at `read_caller_memory` (the helper requires a `memory` export
    /// for any non-empty range). Updated to use the 4-arg state.read
    /// signature.
    #[test]
    fn read_caller_memory_traps_when_module_has_no_memory_export() {
        let bytes = Bytes::from(
            wat::parse_str(
                r#"(module
                    (import "arkhe:hook/state" "read"
                        (func $r (param i32 i32 i32 i32) (result i32)))
                    (func (export "go") (result i32)
                        i32.const 0
                        i32.const 4
                        i32.const 0
                        i32.const 0
                        call $r))"#,
            )
            .expect("valid wat"),
        );
        let err = run_export::<i32>(bytes, CapToken::StateRead)
            .expect_err("no-memory module must trap on len>0");
        let msg = format!("{err:?}");
        assert!(msg.contains("does not export"), "msg = {msg}");
    }
}
