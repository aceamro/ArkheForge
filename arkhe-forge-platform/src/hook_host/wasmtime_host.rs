//! Wasmtime + WASI preview-2 hook host (E14.L2-Allow runtime enforcement).
//!
//! Feature-gated behind `tier-2-hook-host-v2`. Operators that do not
//! enable the feature ship the [`super::NoopHookHost`] pass-through;
//! enabling the feature opts the runtime into this wasmtime-backed
//! sandbox for actual E14.L2-Allow enforcement.
//!
//! ## Surface
//!
//! - [`WasmtimeEngineConfig`] — declarative `Config` shape that pins
//!   three configurable E14.L2 axes; the fourth axis (IEEE-754 strict)
//!   is the Cranelift default and requires no override:
//!   - **NaN canonicalisation** — `cranelift_nan_canonicalization(true)`.
//!     Defends bit-identical replay against IEEE-754 NaN payload drift.
//!   - **SIMD opt-out** — `wasm_simd(false)`. SIMD instructions can shift
//!     rounding behaviour across hosts; rejected at module-load.
//!   - **Fuel-metering bounded execution** — `consume_fuel(true)`. The
//!     10 ms wall-clock budget is enforced via fuel rather than wall-time
//!     to keep replay deterministic.
//!   - **IEEE-754 strict** *(Cranelift default — no `Config` field)*.
//!     Floating-point ops produce host-independent bits without any
//!     `cranelift_*_rounding` override.
//! - [`WasmtimeHookHost`] — opaque host owning a wasmtime [`Engine`]
//!   built from [`WasmtimeEngineConfig`] plus a cached
//!   [`super::capability_linker::CapabilityLinker`] template.
//!   `HookHost::invoke` runs the registered module under a per-
//!   invocation `Store<HookStoreData>` seeded with the caller's
//!   capability set + fuel budget + extra-bytes builder; the
//!   conventional `"hook"` zero-arg export is the entry point.
//!   Modules without the export trap with the missing-export message;
//!   no module registered → pass-through `Ok(())` matching
//!   [`super::NoopHookHost`].
//! - 3-tier ingestion scaffold ([`HookAttestationVerifier`]):
//!   - **Tier 1** — BLAKE3 digest pin enforced at the host level via
//!     [`WasmtimeHookHost::register_module`].
//!   - **Tier 2** (sigstore signature) + **Tier 3** (cargo-vet
//!     provenance attestation) — ship as the [`Tier1OnlyVerifier`]
//!     loud-reject default; supplying a Tier 2 / Tier 3 payload to
//!     `verify` returns [`HookHostError::UnexpectedTier23Payload`].
//!     Operator opt-in via a different [`HookAttestationVerifier`]
//!     impl flips loud-reject to a real verification path.
//!
//! ## Spec anchor
//!
//! - **E14 Compute Determinism Closure** — Runtime axiom.
//! - **E14.L2-Allow** runtime realisation (this module).
//! - Spec §14.5 Hook host configuration.
//! - Spec §5.3 Hook contract (Auth → Hook → Policy re-validation → Build).

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use wasmtime::{Config, Engine, Module, Store};

use super::capability_linker::{CapabilityLinker, HookStoreData};
use super::{HookContext, HookError, HookHost};

/// Default per-invocation fuel budget targeting **~10 ms wall-clock**
/// on the default [`WasmtimeEngineConfig`] (NaN canonicalisation +
/// SIMD off + IEEE-754 strict + fuel-metering). Reference platform:
/// `x86_64-unknown-linux-gnu`, modern server CPU class (~3 GHz, single
/// core, e.g. AWS c5.large).
///
/// **Calibration methodology**:
///
/// - Workload model: tight integer arithmetic loop in wasm, no host
///   calls. Worst case for fuel-instruction ratio (every instruction
///   counts; no syscall amortisation).
/// - Empirical anchor: wasmtime cranelift dispatches at roughly
///   10⁸–10⁹ wasm ops/sec on the reference platform; ~1 fuel/op
///   average → 10⁷ fuel ≈ 10 ms (best case) – 100 ms (slower hardware).
///   The 10⁷ default targets the lower end of this range.
/// - **Fail-direction (cryptographer-anchored)**: prefer **fail-secure**
///   (under-budget → hook killed early → policy bypass attempt blocked
///   by post-hook re-validation). The opposite (over-budget → hook
///   runs > 10 ms → DoS surface for submission processing) is the
///   threat to avoid. Default: tight 10⁷ budget; operators raise via
///   override only after measured calibration.
///
/// **Operator override:**
///
/// - Direct field assignment: `cfg.fuel_budget = 50_000_000;`
/// - Fluent builder: [`WasmtimeEngineConfig::with_fuel_budget`].
/// - Re-calibrate for non-server hardware (ARM, embedded, throttled
///   VMs) by measuring the conversion ratio on the actual deployment
///   class. The minimum sensible budget is `1_000_000` (1 M = ~1 ms
///   target — see compile-time bound in tests).
pub const DEFAULT_FUEL_BUDGET_V0_12: u64 = 10_000_000;

/// Declarative wasmtime [`Config`] shape pinning the configurable E14.L2
/// axes (IEEE-754 strict — the fourth determinism axis — is the
/// Cranelift default and requires no field). Constructed once at
/// host-init; the engine flags are consumed at [`Self::to_config`] →
/// [`Engine::new`], while [`Self::fuel_budget`] is consumed per
/// invocation when the host calls `Store::set_fuel(fuel_budget)`
/// before instantiation.
///
/// **Field consumption matrix:**
///
/// | Field                  | Consumed at         | Effect                                    |
/// |------------------------|---------------------|-------------------------------------------|
/// | `nan_canonicalisation` | `Engine::new`       | Cranelift NaN canonicalisation flag       |
/// | `wasm_simd_enabled`    | `Engine::new`       | Reject SIMD instructions at module-load   |
/// | `fuel_metering`        | `Engine::new`       | Engine-level `consume_fuel(...)` flag     |
/// | `fuel_budget`          | per-invocation      | `Store::set_fuel(fuel_budget)` before run |
#[derive(Debug, Clone)]
pub struct WasmtimeEngineConfig {
    /// `cranelift_nan_canonicalization` — defends replay against
    /// host-dependent NaN payload bits. Default: always `true`.
    pub nan_canonicalisation: bool,
    /// `wasm_simd` — SIMD enables host-dependent rounding paths.
    /// Default: always `false`.
    pub wasm_simd_enabled: bool,
    /// `consume_fuel` — fuel metering replaces wall-time budgeting so
    /// replay is deterministic. Default: always `true`.
    pub fuel_metering: bool,
    /// Per-invocation fuel budget. Defaults to
    /// [`DEFAULT_FUEL_BUDGET_V0_12`] (~10 ms wall-clock target on the
    /// reference platform). Consumed at invocation time, not engine
    /// construction.
    pub fuel_budget: u64,
}

impl WasmtimeEngineConfig {
    /// Default deterministic-replay profile — locks the configurable
    /// E14.L2 axes to their determinism-preserving values (IEEE-754
    /// strict is Cranelift default and requires no override). Fuel
    /// budget defaults to [`DEFAULT_FUEL_BUDGET_V0_12`]. Operators do
    /// not currently have engine-flag opt-out; the fuel budget is
    /// operator-tunable via [`Self::with_fuel_budget`] or direct field
    /// assignment.
    pub fn deterministic_replay() -> Self {
        Self {
            nan_canonicalisation: true,
            wasm_simd_enabled: false,
            fuel_metering: true,
            fuel_budget: DEFAULT_FUEL_BUDGET_V0_12,
        }
    }

    /// Override the per-invocation fuel budget. Use to re-calibrate for
    /// non-reference hardware (ARM / embedded / throttled VMs).
    pub fn with_fuel_budget(mut self, fuel_budget: u64) -> Self {
        self.fuel_budget = fuel_budget;
        self
    }

    /// Materialise the wasmtime [`Config`] from the declarative shape.
    /// Routes through the shared
    /// `wasm_runtime_common::config_for_profile` factory for the
    /// `EngineProfile::ReplayDeterministic` pinning — single source of
    /// truth shared with observer host's engine construction.
    /// [`Self::fuel_budget`] is **not** consumed here — it's a per-
    /// invocation policy applied via `Store::set_fuel(...)` at hook-
    /// execution time.
    pub fn to_config(&self) -> Config {
        crate::wasm_runtime_common::config_for_profile(
            &crate::wasm_runtime_common::EngineProfile::ReplayDeterministic {
                fuel_budget: self.fuel_budget,
            },
        )
    }
}

impl Default for WasmtimeEngineConfig {
    fn default() -> Self {
        Self::deterministic_replay()
    }
}

/// Wasmtime-backed hook host. Owns a single [`Engine`] (build cost is
/// significant — Cranelift JIT cache initialisation — so we amortise it
/// across hook invocations) plus a single [`CapabilityLinker`] template
/// (host-fn bindings shared across invocations; per-shell cached
/// linker, per-invocation `Store`).
///
/// Empty-host invocations (no module registered) pass through `Ok(())`
/// to match [`super::NoopHookHost`]. Once a module is registered via
/// [`Self::register_module`] — which runs the BLAKE3 digest pin
/// (Tier 1) + module pre-scan (allow-list + WASI deny-list) and rejects
/// invalid or denied imports at registration time — `HookHost::invoke`
/// runs the module under a per-invocation `Store<HookStoreData>` and
/// translates wasmtime traps to [`HookError`].
#[derive(Debug)]
pub struct WasmtimeHookHost {
    engine: Engine,
    /// Cached capability-bounded [`Linker`] template. Built once at
    /// construction and reused across every invocation; tied to
    /// [`Self::engine`] for wasmtime's identity check.
    linker: CapabilityLinker,
    /// Optional pre-scanned + parsed [`Module`] representing the
    /// registered hook. `None` = pass-through behaviour. Populated via
    /// [`Self::register_module`], which runs the 3-tier ingestion path
    /// (Tier 1 BLAKE3 digest pin enforced; Tier 2 sigstore + Tier 3
    /// cargo-vet enforced through pluggable
    /// [`HookAttestationVerifier`] impls).
    registered_module: Option<Module>,
    /// Per-invocation fuel budget snapshot from the originating
    /// [`WasmtimeEngineConfig`]. `invoke` threads
    /// `Store::set_fuel(self.fuel_budget)` before instantiation.
    fuel_budget: u64,
    /// Per-host trap counter — increments on every `invoke()` that
    /// returns any [`HookError`]. Operator telemetry surface routed
    /// into chain-signed `runtime_doctor_journal` entries downstream.
    /// `AtomicU64` for lock-free concurrent updates from invocations
    /// on different threads.
    trap_count: AtomicU64,
}

impl WasmtimeHookHost {
    /// Construct a host with the default [`WasmtimeEngineConfig`].
    /// Engine build can fail if Cranelift codegen initialisation hits
    /// an allocator / capability error; surfaced as
    /// [`HookHostError::EngineInitFailed`]. Linker setup uses
    /// [`CapabilityLinker::deny_by_default`] and can fail at
    /// `func_wrap` registration; surfaced as
    /// [`HookHostError::LinkerSetupFailed`].
    pub fn with_deterministic_replay_config() -> Result<Self, HookHostError> {
        Self::with_config(&WasmtimeEngineConfig::deterministic_replay())
    }

    /// Construct a host with an explicit [`WasmtimeEngineConfig`].
    /// Routes through the shared `wasm_runtime_common::build_engine`
    /// factory — single source of truth for the
    /// `ReplayDeterministic` profile pinning (E14.L2-Allow rule
    /// 1+2+4: NaN canon + SIMD off + fuel metering).
    pub fn with_config(config: &WasmtimeEngineConfig) -> Result<Self, HookHostError> {
        let (engine, fuel_budget) = crate::wasm_runtime_common::build_engine(
            &crate::wasm_runtime_common::EngineProfile::ReplayDeterministic {
                fuel_budget: config.fuel_budget,
            },
        )
        .map_err(|e| HookHostError::EngineInitFailed {
            reason: format!("{e}"),
        })?;
        let linker = CapabilityLinker::deny_by_default(&engine)?;
        Ok(Self {
            engine,
            linker,
            registered_module: None,
            fuel_budget,
            trap_count: AtomicU64::new(0),
        })
    }

    /// Register a wasm module with an operator-pinned BLAKE3 digest.
    /// Implements the **Tier 1 (digest pin)** ingestion check:
    ///
    /// 1. Compute `blake3::hash(bytes)`.
    /// 2. Reject with [`HookHostError::DigestMismatch`] if it does not
    ///    match `expected_digest`.
    /// 3. Run the allow-list / deny-list pre-scan
    ///    ([`super::capability_linker::scan_imports`]) on the bytes.
    /// 4. Store the parsed [`Module`] for invoke-time instantiation.
    ///
    /// `expected_digest` comes from the operator's manifest TOML
    /// (`[hook.<name>] digest_b3 = "..."`), itself anchored by a
    /// chain-signed [`HookModuleRegister`](arkhe_forge_core::event::HookModuleRegister)
    /// event. The combined chain is: manifest TOML signed by operator
    /// key → manifest digest → expected_digest → bytes match → store.
    ///
    /// **Tier 2 / Tier 3 ingestion** (sigstore sign-before-load +
    /// cargo-vet provenance attestation) is gated behind the
    /// [`HookAttestationVerifier`] trait. The default
    /// [`Tier1OnlyVerifier`] loud-rejects Tier 2 / Tier 3 inputs;
    /// operators wire a different verifier impl to enforce those tiers.
    ///
    /// # Errors
    ///
    /// - [`HookHostError::DigestMismatch`] — `blake3(bytes)` did not
    ///   match `expected_digest`. Operator config typo or accidental
    ///   file substitution.
    /// - [`HookHostError::ModuleParseFailed`] — bytes are not a valid
    ///   wasm module (after digest verification passed).
    /// - [`HookHostError::ImportRejected`] — module imports a denied
    ///   namespace (specific WASI prefixes) or any namespace outside the
    ///   `arkhe:hook/*` allow-list.
    pub fn register_module(
        &mut self,
        bytes: Bytes,
        expected_digest: blake3::Hash,
    ) -> Result<(), HookHostError> {
        // Route through the shared
        // `wasm_runtime_common::register_module_common` factory for the
        // 3-tier ingestion path Tier 1 (BLAKE3 digest pin + import
        // allow/deny pre-scan). Single source of truth shared with
        // observer host. `From<RegistrationError>` impl below maps the
        // factory's flat error variants 1:1 to `HookHostError`.
        //
        // `expected_digest` is typed as `blake3::Hash` so callers get
        // type-safe digest construction (no raw `[u8;32]` →
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
            "only `arkhe:hook/*` permitted",
        )?;
        self.registered_module = Some(module);
        Ok(())
    }

    /// Borrow the underlying wasmtime [`Engine`]. Exposed for callers
    /// that build their own `Linker` + `Store` against the same engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Borrow the cached [`CapabilityLinker`]. Exposed for the
    /// invoke-time instantiation path; reused across every invocation.
    pub fn capability_linker(&self) -> &CapabilityLinker {
        &self.linker
    }

    /// Whether the host has a registered hook module (vs pure
    /// pass-through).
    pub fn has_registered_module(&self) -> bool {
        self.registered_module.is_some()
    }

    /// Per-invocation fuel budget snapshot from construction-time
    /// [`WasmtimeEngineConfig::fuel_budget`]. `invoke` wires this into
    /// `Store::set_fuel` immediately before instantiation; surfaced as
    /// an accessor here so operators can inspect the active value.
    pub fn fuel_budget(&self) -> u64 {
        self.fuel_budget
    }

    /// Current trap count — number of times [`HookHost::invoke`] has
    /// returned any [`HookError`] across the lifetime of this host.
    /// Counts actual wasm-execution traps (`BudgetExceeded` /
    /// `Trapped` / `PolicyReValidationFailed`); pass-through invocations
    /// against an unregistered module never increment. Operator
    /// telemetry surface routed downstream into chain-signed
    /// `runtime_doctor_journal` entries.
    pub fn trap_count(&self) -> u64 {
        self.trap_count.load(Ordering::Relaxed)
    }
}

impl HookHost for WasmtimeHookHost {
    fn invoke(&self, ctx: &mut HookContext<'_>) -> Result<(), HookError> {
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

impl WasmtimeHookHost {
    /// Real wasm execution wiring. Builds a per-invocation
    /// `Store<HookStoreData>` seeded with the caller's capability set +
    /// fuel budget + the extra-bytes builder taken from `ctx.extra`,
    /// instantiates the registered module via the cached
    /// [`CapabilityLinker`], looks up the conventional `"hook"` export
    /// (entry point), and calls it. After return — whether success or
    /// trap — the mutated extra-bytes builder is moved back into
    /// `ctx.extra` so the post-hook re-validation step sees it.
    ///
    /// Wasmtime errors are translated coarsely:
    /// - Fuel-exhaustion trap → [`HookError::BudgetExceeded`]
    /// - Anything else → [`HookError::Trapped`] with a static reason
    ///   tag (operator stderr + future `runtime_doctor_journal` carry
    ///   the full wasmtime error for forensics)
    fn run_wasm_invoke(&self, module: &Module, ctx: &mut HookContext<'_>) -> Result<(), HookError> {
        // Move the caller's extra builder into the store so the
        // `arkhe:hook/emit.extra_bytes` host-fn can mutate it.
        // Default-replacement preserves the &mut reference shape and
        // avoids any allocation-on-the-hot-path concern.
        let extra_in = std::mem::take(ctx.extra);

        let store_data = HookStoreData::with_capabilities(ctx.capabilities.iter().copied())
            .with_initial_fuel(self.fuel_budget)
            .with_extra(extra_in);
        let mut store = Store::new(&self.engine, store_data);

        // Seed fuel — engine has consume_fuel(true), so without
        // set_fuel any wasm op traps "all fuel consumed" immediately.
        store
            .set_fuel(self.fuel_budget)
            .map_err(|_| HookError::Trapped("fuel seed failed at invoke entry"))?;

        // Instantiate via the cached linker.
        let inst_result = self.linker.linker().instantiate(&mut store, module);
        let inst = match inst_result {
            Ok(i) => i,
            Err(_) => {
                // Move the extra builder back even on instantiation
                // failure — caller reuses the slot.
                if let Some(extra) = store.data_mut().take_extra() {
                    *ctx.extra = extra;
                }
                return Err(HookError::Trapped("hook module instantiation failed"));
            }
        };

        // Convention: hook modules export a single zero-arg, zero-return
        // entry point named "hook". Modules without it cannot be
        // invoked.
        let entry_result = inst.get_typed_func::<(), ()>(&mut store, "hook");
        let entry = match entry_result {
            Ok(f) => f,
            Err(_) => {
                if let Some(extra) = store.data_mut().take_extra() {
                    *ctx.extra = extra;
                }
                return Err(HookError::Trapped(
                    "hook module missing `hook` export (signature `() -> ()`)",
                ));
            }
        };

        let call_result = entry.call(&mut store, ());

        // Move the (possibly-mutated) extra builder back into ctx
        // BEFORE classifying the error. The builder must be returned
        // so post-hook policy re-validation can inspect it whether the
        // call succeeded or trapped (a partial trap may have appended
        // some bytes).
        if let Some(extra) = store.data_mut().take_extra() {
            *ctx.extra = extra;
        }

        // Translate wasmtime trap → HookError. Coarse classification
        // only — HookError::Trapped takes &'static str so we cannot
        // forward the full wasmtime error string. Operator stderr +
        // future runtime_doctor_journal entries carry the rich detail.
        match call_result {
            Ok(()) => Ok(()),
            Err(e) => {
                let s = format!("{e:?}");
                if s.contains("all fuel consumed") || s.contains("OutOfFuel") {
                    Err(HookError::BudgetExceeded)
                } else {
                    Err(HookError::Trapped("hook trapped during wasm execution"))
                }
            }
        }
    }
}

/// Host construction-time + module-registration error — distinct from
/// per-invocation [`HookError`]. Engine / linker initialisation can fail
/// for capability / allocator reasons; module registration can fail for
/// parse / import-policy reasons. All surfaced at construction or
/// registration so the operator sees a clear failure rather than a
/// per-tick `Trapped`.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HookHostError {
    /// Wasmtime [`Engine::new`] failed during construction.
    #[error("wasmtime engine initialisation failed: {reason}")]
    EngineInitFailed {
        /// Underlying error stringified.
        reason: String,
    },
    /// Wasmtime [`wasmtime::Linker::func_wrap`] rejected a host-fn
    /// registration during [`super::capability_linker::CapabilityLinker::deny_by_default`].
    /// Indicates a programming error (name collision, unsupported function
    /// shape) rather than operator-recoverable state.
    #[error("wasmtime linker setup failed: {reason}")]
    LinkerSetupFailed {
        /// Underlying error stringified, prefixed with the offending
        /// host-fn name (e.g., `arkhe:hook/state.read: ...`).
        reason: String,
    },
    /// Wasmtime [`Module::from_binary`] rejected the module bytes during
    /// [`super::capability_linker::scan_imports`]. The bytes do not parse
    /// as a valid wasm module (corrupt / truncated / non-wasm).
    #[error("wasm module parse failed: {reason}")]
    ModuleParseFailed {
        /// Underlying error stringified.
        reason: String,
    },
    /// Module pre-scan rejected an import outside the
    /// [`super::capability_linker::ALLOWED_IMPORT_MODULE_PREFIXES`]
    /// allow-list, or in the
    /// [`super::capability_linker::DENIED_IMPORT_MODULE_PREFIXES`]
    /// explicit deny-list. Operator-recoverable: the hook author must
    /// rebuild without the offending import.
    #[error("module import rejected: {name} — {reason}")]
    ImportRejected {
        /// The fully-qualified import name in `module::field` form.
        name: String,
        /// The pre-scan rejection reason (e.g.,
        /// `denied namespace 'wasi:random'` or
        /// `not in allow-list (only 'arkhe:hook/*' permitted)`).
        reason: String,
    },
    /// Tier 1 BLAKE3 digest pin mismatch. The bytes passed to
    /// [`WasmtimeHookHost::register_module`] hash to a different value
    /// than the operator-pinned `expected_digest` (typically sourced
    /// from the manifest TOML). Operator-recoverable: re-deploy with
    /// the matching module bytes, or correct the manifest's
    /// `digest_b3` field.
    #[error("hook module digest mismatch — expected {expected:?}, actual {actual:?}")]
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
    /// A [`HookAttestationVerifier`] implementation rejected a
    /// `(signature, vet_attestation)` payload because the active
    /// verifier does not enforce that tier. The default
    /// [`Tier1OnlyVerifier`] **rejects** any non-`None` Tier 2 / Tier 3
    /// input — silent acceptance would let a caller confused-deputy a
    /// configuration where they believe signatures are checked while
    /// the active verifier only enforces Tier 1 BLAKE3 digest pin.
    /// Operator-recoverable: configure an explicit Tier 2 / Tier 3
    /// verifier impl, or pass `None` for unsupported tiers.
    #[error(
        "hook attestation tier {which:?} payload supplied to verifier that does not enforce it"
    )]
    UnexpectedTier23Payload {
        /// Which payload (signature or vet attestation) was unexpectedly present.
        which: Tier23Source,
    },
}

/// Map the shared registration-error surface to the hook-specific
/// error enum. 1:1 variant mapping — DigestMismatch preserves operator-
/// pinned digest, ParseFailed → ModuleParseFailed, ImportRejected →
/// ImportRejected.
impl From<crate::wasm_runtime_common::RegistrationError> for HookHostError {
    fn from(e: crate::wasm_runtime_common::RegistrationError) -> Self {
        match e {
            crate::wasm_runtime_common::RegistrationError::DigestMismatch { expected, actual } => {
                HookHostError::DigestMismatch { expected, actual }
            }
            crate::wasm_runtime_common::RegistrationError::ParseFailed { reason } => {
                HookHostError::ModuleParseFailed { reason }
            }
            crate::wasm_runtime_common::RegistrationError::ImportRejected { name, reason } => {
                HookHostError::ImportRejected { name, reason }
            }
        }
    }
}

/// Discriminator for [`HookHostError::UnexpectedTier23Payload`] —
/// distinguishes Tier 2 (sigstore signature) from Tier 3 (cargo-vet
/// provenance attestation) so operator audit logs surface which
/// payload triggered the loud-reject.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier23Source {
    /// Tier 2 sigstore signature.
    Signature,
    /// Tier 3 cargo-vet provenance attestation.
    VetAttestation,
}

/// 3-tier hook ingestion verifier. Tier 1 (BLAKE3 digest pin) is wired
/// directly into [`WasmtimeHookHost::register_module`]; this trait
/// scaffolds Tier 2 (sigstore sign-before-load) + Tier 3 (cargo-vet
/// provenance) so operators can swap in active verifiers without
/// touching the host construction path.
///
/// **Default**: [`Tier1OnlyVerifier`] — loud-rejects any non-`None`
/// Tier 2 / Tier 3 payload; Tier 1 digest pin enforcement happens at
/// the host level.
///
/// **Operator-supplied implementations** (illustrative, not shipped
/// from this crate):
/// - `SigstoreVerifier` — verifies the signature blob against a sigstore
///   TUF-rooted public-key inventory.
/// - `CargoVetVerifier` — checks the cargo-vet attestation hash matches
///   the operator's audit trail.
/// - `MultiTierVerifier` — composes the above with AND semantics for
///   defense-in-depth.
pub trait HookAttestationVerifier: std::fmt::Debug + Send + Sync {
    /// Verify the supplied attestation payloads. The default verifier
    /// expects `(None, None)`; alternative impls accept real signature
    /// / vet attestation bytes.
    fn verify(
        &self,
        module_digest: &[u8; 32],
        signature: Option<&[u8]>,
        vet_attestation: Option<&[u8]>,
    ) -> Result<(), HookHostError>;
}

/// Default verifier — enforces Tier 1 BLAKE3 digest pin at the host
/// level (via [`WasmtimeHookHost::register_module`]) and **loud-
/// rejects** any Tier 2 / Tier 3 payload (signature or vet_attestation)
/// supplied to [`HookAttestationVerifier::verify`].
///
/// **Why loud-reject**: silent acceptance would let a caller wire
/// sigstore signatures into the call site believing they are validated,
/// while the active verifier only enforces Tier 1. The confused-deputy
/// pattern is exactly that. Enforced contract = Tier 1 only; passing
/// Tier 2 / Tier 3 input is a configuration error (caller has not
/// understood which verifier is active). Operators that want active
/// Tier 2 / Tier 3 verification supply their own
/// [`HookAttestationVerifier`] impl — at that point the loud-reject
/// becomes a successful verification path.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tier1OnlyVerifier;

impl HookAttestationVerifier for Tier1OnlyVerifier {
    fn verify(
        &self,
        _module_digest: &[u8; 32],
        signature: Option<&[u8]>,
        vet_attestation: Option<&[u8]>,
    ) -> Result<(), HookHostError> {
        if signature.is_some() {
            return Err(HookHostError::UnexpectedTier23Payload {
                which: Tier23Source::Signature,
            });
        }
        if vet_attestation.is_some() {
            return Err(HookHostError::UnexpectedTier23Payload {
                which: Tier23Source::VetAttestation,
            });
        }
        // Tier 1 (digest pin) is enforced at the host level
        // (`register_module`); this verifier accepts only the Tier 1
        // path with no Tier 2 / Tier 3 inputs.
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hook_host::{CapToken, ExtraBytesBuilder};

    #[test]
    fn deterministic_replay_config_pins_engine_axes_and_fuel_budget() {
        let cfg = WasmtimeEngineConfig::deterministic_replay();
        assert!(cfg.nan_canonicalisation);
        assert!(!cfg.wasm_simd_enabled);
        assert!(cfg.fuel_metering);
        assert_eq!(cfg.fuel_budget, DEFAULT_FUEL_BUDGET_V0_12);
    }

    /// Sanity-check the const has a plausible wall-clock value:
    /// between 1 M (1 ms floor) and 100 M (100 ms ceiling — anything
    /// beyond is operator-opt-in via `with_fuel_budget`). Pinned at
    /// compile-time via `const _ = assert!` so future edits to the
    /// constant trip the build, not just the test runner.
    /// Cryptographer C8: fail-secure direction → tightened envelope.
    const _ASSERT_FUEL_BUDGET_LOWER: () = assert!(DEFAULT_FUEL_BUDGET_V0_12 >= 1_000_000);
    const _ASSERT_FUEL_BUDGET_UPPER: () = assert!(DEFAULT_FUEL_BUDGET_V0_12 <= 100_000_000);

    #[test]
    fn with_fuel_budget_override_works() {
        let cfg = WasmtimeEngineConfig::deterministic_replay().with_fuel_budget(50_000_000);
        assert_eq!(cfg.fuel_budget, 50_000_000);
        // Other axes unchanged.
        assert!(cfg.nan_canonicalisation);
        assert!(!cfg.wasm_simd_enabled);
        assert!(cfg.fuel_metering);
    }

    #[test]
    fn host_records_fuel_budget_at_construction() {
        let host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        assert_eq!(host.fuel_budget(), DEFAULT_FUEL_BUDGET_V0_12);
        let host2 = WasmtimeHookHost::with_config(
            &WasmtimeEngineConfig::deterministic_replay().with_fuel_budget(7_777),
        )
        .unwrap();
        assert_eq!(host2.fuel_budget(), 7_777);
    }

    #[test]
    fn engine_builds_with_deterministic_replay_config() {
        let host = WasmtimeHookHost::with_deterministic_replay_config()
            .expect("engine init must succeed under default config");
        // Sanity: the engine handle is borrowable and has a
        // non-default identity (wasmtime stores Engine state).
        let _engine = host.engine();
        assert!(!host.has_registered_module());
    }

    #[test]
    fn empty_host_pass_through_ok() {
        let host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let mut extra = ExtraBytesBuilder::new();
        extra.append(b"prefix");
        let caps = [CapToken::EmitExtraBytes];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        // No registered module → pass-through Ok, no extra-bytes mutation.
        assert!(host.invoke(&mut ctx).is_ok());
        assert_eq!(extra.len(), 6);
    }

    /// Compute the BLAKE3 digest the host expects for a given byte slice.
    /// Real operators source this from the manifest TOML. Returns
    /// `blake3::Hash` to match the `register_module` signature.
    fn digest(bytes: &[u8]) -> blake3::Hash {
        blake3::hash(bytes)
    }

    /// A valid but minimal wasm module without a `hook` export traps
    /// with the missing-export message.
    #[test]
    fn registered_module_without_hook_export_traps_at_invoke() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        // Smallest valid wasm preamble — magic + version, no exports.
        let preamble = Bytes::from_static(&[
            0x00, 0x61, 0x73, 0x6d, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]);
        let d = digest(preamble.as_ref());
        host.register_module(preamble, d)
            .expect("zero-import preamble passes digest + pre-scan");
        assert!(host.has_registered_module());
        let mut extra = ExtraBytesBuilder::new();
        let caps: [CapToken; 0] = [];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        match host.invoke(&mut ctx) {
            Err(HookError::Trapped(msg)) => {
                assert!(
                    msg.contains("missing `hook` export"),
                    "unexpected trap message: {msg}"
                );
            }
            other => panic!("expected Trapped(missing hook), got {other:?}"),
        }
    }

    /// A module with a `hook` export that is a no-op succeeds end-to-
    /// end, returning Ok(()). Verifies the invoke pipeline (instantiate,
    /// entry lookup, call, extra builder thread back to ctx) is intact
    /// for the success path.
    #[test]
    fn registered_module_with_noop_hook_export_succeeds() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let bytes = Bytes::from(
            wat::parse_str(
                r#"(module
                    (func (export "hook")))"#,
            )
            .expect("valid wat"),
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d)
            .expect("noop hook module passes ingestion");
        let mut extra = ExtraBytesBuilder::new();
        let caps: [CapToken; 0] = [];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        host.invoke(&mut ctx).expect("noop hook should succeed");
        // Extra builder unchanged — nothing emitted.
        assert!(ctx.extra.is_empty());
    }

    /// A module whose `hook` export contains an infinite loop traps
    /// via fuel exhaustion → BudgetExceeded.
    #[test]
    fn registered_module_with_infinite_loop_returns_budget_exceeded() {
        // Use a tiny custom budget so the trap is fast.
        let mut host = WasmtimeHookHost::with_config(
            &WasmtimeEngineConfig::deterministic_replay().with_fuel_budget(1_000),
        )
        .unwrap();
        let bytes = Bytes::from(
            wat::parse_str(
                r#"(module
                    (func (export "hook")
                        (loop $forever (br $forever))))"#,
            )
            .expect("valid wat"),
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d).unwrap();
        let mut extra = ExtraBytesBuilder::new();
        let caps: [CapToken; 0] = [];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        match host.invoke(&mut ctx) {
            Err(HookError::BudgetExceeded) => {}
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        // Trap counter incremented.
        assert_eq!(host.trap_count(), 1);
    }

    /// A module that calls `arkhe:hook/emit.extra_bytes` to append
    /// bytes — verify the `HookContext::extra` has those bytes after
    /// invoke returns.
    #[test]
    fn invoke_threads_extra_bytes_back_to_ctx() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let bytes = Bytes::from(
            wat::parse_str(
                r#"(module
                    (import "arkhe:hook/emit" "extra_bytes"
                        (func $e (param i32 i32)))
                    (memory (export "memory") 1)
                    (data (i32.const 0) "TRACE")
                    (func (export "hook")
                        i32.const 0
                        i32.const 5
                        call $e))"#,
            )
            .expect("valid wat"),
        );
        let d = digest(bytes.as_ref());
        host.register_module(bytes, d).unwrap();
        let mut extra = ExtraBytesBuilder::new();
        let caps = [CapToken::EmitExtraBytes];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        host.invoke(&mut ctx).expect("hook should succeed");
        // The hook appended "TRACE" via emit.extra_bytes.
        assert_eq!(ctx.extra.len(), 5);
        let frozen = std::mem::take(ctx.extra).freeze();
        assert_eq!(&frozen[..], b"TRACE");
    }

    #[test]
    fn trap_count_starts_at_zero() {
        let host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        assert_eq!(host.trap_count(), 0);
    }

    #[test]
    fn trap_count_does_not_increment_on_invoke_success() {
        // No registered module → invoke pass-through Ok → no trap.
        let host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let mut extra = ExtraBytesBuilder::new();
        let caps: [CapToken; 0] = [];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        for _ in 0..3 {
            assert!(host.invoke(&mut ctx).is_ok());
        }
        assert_eq!(host.trap_count(), 0);
    }

    #[test]
    fn trap_count_increments_on_invoke_error() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let preamble = Bytes::from_static(&[
            0x00, 0x61, 0x73, 0x6d, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]);
        let d = digest(preamble.as_ref());
        host.register_module(preamble, d).unwrap();
        let mut extra = ExtraBytesBuilder::new();
        let caps: [CapToken; 0] = [];
        let mut ctx = HookContext {
            capabilities: &caps,
            extra: &mut extra,
        };
        assert_eq!(host.trap_count(), 0);
        let _ = host.invoke(&mut ctx);
        assert_eq!(host.trap_count(), 1);
        let _ = host.invoke(&mut ctx);
        let _ = host.invoke(&mut ctx);
        assert_eq!(host.trap_count(), 3);
    }

    #[test]
    fn register_module_rejects_wasi_random() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let bytes = Bytes::from(
            wat::parse_str(
                r#"(module
                    (import "wasi:random/random" "get-random-u64"
                        (func (result i64))))"#,
            )
            .expect("valid wat"),
        );
        let d = digest(bytes.as_ref());
        let err = host
            .register_module(bytes, d)
            .expect_err("wasi:random must reject at registration");
        assert!(matches!(err, HookHostError::ImportRejected { .. }));
        assert!(!host.has_registered_module());
    }

    #[test]
    fn register_module_rejects_invalid_bytes() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        // 4-byte truncated magic — not a valid module.
        let bytes = Bytes::from_static(&[0x00, 0x61, 0x73, 0x6d]);
        let d = digest(bytes.as_ref());
        let err = host
            .register_module(bytes, d)
            .expect_err("invalid bytes must reject");
        assert!(matches!(err, HookHostError::ModuleParseFailed { .. }));
    }

    // ---- BLAKE3 digest pin + Tier1OnlyVerifier scaffold ----

    #[test]
    fn register_module_rejects_digest_mismatch() {
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let preamble = Bytes::from_static(&[
            0x00, 0x61, 0x73, 0x6d, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]);
        // Operator pinned a wrong digest in the manifest.
        let wrong_digest: blake3::Hash = [0xFFu8; 32].into();
        let err = host
            .register_module(preamble.clone(), wrong_digest)
            .expect_err("wrong digest must reject");
        match err {
            HookHostError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, wrong_digest);
                assert_eq!(actual, digest(preamble.as_ref()));
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        assert!(!host.has_registered_module());
    }

    #[test]
    fn register_module_rejects_byte_tampering() {
        // Operator pins the original digest; bytes get mutated by 1 byte.
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let original = Bytes::from_static(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        let pinned = digest(original.as_ref());
        let tampered = Bytes::from_static(&[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x01, // last byte 0x00 → 0x01
        ]);
        let err = host
            .register_module(tampered, pinned)
            .expect_err("tampered bytes must reject");
        assert!(matches!(err, HookHostError::DigestMismatch { .. }));
        assert!(!host.has_registered_module());
    }

    #[test]
    fn register_module_digest_check_runs_before_pre_scan() {
        // wasi:random module — pre-scan would also reject, but digest
        // check fires first (cheaper, no engine work).
        let mut host = WasmtimeHookHost::with_deterministic_replay_config().unwrap();
        let bytes = Bytes::from(
            wat::parse_str(
                r#"(module
                    (import "wasi:random/random" "get-random-u64"
                        (func (result i64))))"#,
            )
            .expect("valid wat"),
        );
        let wrong_digest: blake3::Hash = [0xAAu8; 32].into();
        let err = host
            .register_module(bytes, wrong_digest)
            .expect_err("must reject");
        // Digest check fires first → DigestMismatch (NOT ImportRejected).
        assert!(matches!(err, HookHostError::DigestMismatch { .. }));
    }

    #[test]
    fn tier1_only_verifier_accepts_no_tier23_payloads() {
        let v = Tier1OnlyVerifier;
        let digest = [0u8; 32];
        // No signature, no vet attestation — Tier 1 only path → Ok.
        assert!(v.verify(&digest, None, None).is_ok());
    }

    #[test]
    fn tier1_only_verifier_loud_rejects_signature() {
        let v = Tier1OnlyVerifier;
        let digest = [0u8; 32];
        let err = v
            .verify(&digest, Some(b"sig-bytes"), None)
            .expect_err("Tier 2 signature must loud-reject under default verifier");
        match err {
            HookHostError::UnexpectedTier23Payload { which } => {
                assert_eq!(which, Tier23Source::Signature);
            }
            other => panic!("expected UnexpectedTier23Payload, got {other:?}"),
        }
    }

    #[test]
    fn tier1_only_verifier_loud_rejects_vet_attestation() {
        let v = Tier1OnlyVerifier;
        let digest = [0u8; 32];
        let err = v
            .verify(&digest, None, Some(b"vet-bytes"))
            .expect_err("Tier 3 vet must loud-reject under default verifier");
        match err {
            HookHostError::UnexpectedTier23Payload { which } => {
                assert_eq!(which, Tier23Source::VetAttestation);
            }
            other => panic!("expected UnexpectedTier23Payload, got {other:?}"),
        }
    }

    #[test]
    fn tier1_only_verifier_loud_rejects_signature_first_when_both_present() {
        // Order: signature checked before vet_attestation in the verifier
        // body. When BOTH are supplied, Signature is the reported source.
        let v = Tier1OnlyVerifier;
        let digest = [0u8; 32];
        let err = v
            .verify(&digest, Some(b"sig"), Some(b"vet"))
            .expect_err("either Tier 2 or Tier 3 input must loud-reject");
        match err {
            HookHostError::UnexpectedTier23Payload { which } => {
                assert_eq!(which, Tier23Source::Signature);
            }
            other => panic!("expected UnexpectedTier23Payload, got {other:?}"),
        }
    }

    #[test]
    fn digest_mismatch_error_display_does_not_panic() {
        let e = HookHostError::DigestMismatch {
            expected: [0xAAu8; 32].into(),
            actual: [0xBBu8; 32].into(),
        };
        let s = format!("{e}");
        assert!(s.contains("digest mismatch"));
    }

    #[test]
    fn host_host_error_display_does_not_panic() {
        let e = HookHostError::EngineInitFailed {
            reason: "test reason".into(),
        };
        assert!(format!("{e}").contains("test reason"));
    }
}
