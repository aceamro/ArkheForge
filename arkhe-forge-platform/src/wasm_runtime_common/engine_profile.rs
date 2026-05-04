//! Wasmtime engine profile + factory shared across hook + observer
//! hosts. Single source of truth for the **E14.L2-Allow rule 1+2+4
//! anchor** (chain-effect-aware determinism axis pinning).

use wasmtime::Engine;

/// Wasmtime engine profile — selects the determinism axis pinning based
/// on the host's chain-effect class. Centralised at `wasm_runtime_common`
/// so hook + observer hosts share a single source of truth for the
/// **E14.L2-Allow rule 1+2+4 anchor**.
///
/// **E14.L2-Allow rules**:
///
/// - **rule 1** — `cranelift_nan_canonicalization(true)` — defends bit-
///   identical replay against IEEE-754 NaN payload drift.
/// - **rule 2** — `wasm_simd(false)` (+ `wasm_relaxed_simd(false)`) —
///   SIMD instructions can shift rounding behaviour across hosts;
///   rejected at module-load.
/// - **rule 3** — host-import allow-list — orthogonal axis
///   (`scan_module_imports` + `WASI_DENY_PREFIXES`).
/// - **rule 4** — `consume_fuel(true)` — fuel-metered execution is
///   replay-deterministic; per-invocation budget enforced via
///   `Store::set_fuel(...)`.
/// - IEEE-754 strict (the fourth determinism axis) is the Cranelift
///   default and requires no `Config` field.
///
/// **Chain-non-affecting hosts** (Observer, E15) only pin fuel metering
/// (rule 4) — chain hash is unaffected by observer execution (E15
/// clause 4), so NaN/SIMD pinning is unnecessary. Operators may still
/// override fuel budget via the host's config builder.
//
// `dead_code` allowed: under hook-only or observer-only feature, only
// one variant is constructed. The other variant compiles + type-checks
// so the unified factory contract is preserved across both feature
// matrices (mirrors `read_caller_memory<T>` / `write_caller_memory<T>`
// rationale).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum EngineProfile {
    /// Hook host — replay-deterministic execution. Pins all three
    /// configurable E14.L2-Allow rules (NaN canon + SIMD off + fuel).
    ReplayDeterministic {
        /// Per-invocation fuel budget. Caller threads via
        /// `Store::set_fuel(fuel_budget)` before instantiation.
        fuel_budget: u64,
    },
    /// Observer host — chain-non-affecting execution (E15). Pins fuel
    /// metering only.
    ChainNonAffecting {
        /// Per-invocation fuel budget. Higher than Hook by default
        /// (observer is post-commit, tolerates higher latency).
        fuel_budget: u64,
    },
}

impl EngineProfile {
    /// The fuel budget this profile carries. Caller consumes at
    /// `Store::set_fuel(...)` time.
    pub(crate) fn fuel_budget(&self) -> u64 {
        match self {
            Self::ReplayDeterministic { fuel_budget } | Self::ChainNonAffecting { fuel_budget } => {
                *fuel_budget
            }
        }
    }
}

/// Materialise a wasmtime [`Config`] from an [`EngineProfile`]. Single
/// source of truth for chain-effect-aware determinism axis pinning;
/// callers that build the [`Engine`] themselves (legacy
/// `WasmtimeEngineConfig::to_config()` paths + tests) route through this
/// helper. Callers that want the engine + fuel budget directly use
/// [`build_engine`] instead.
///
/// # Pinned axes (verbatim, by profile)
///
/// **`ReplayDeterministic`** (Hook host, chain-affecting):
/// - `cranelift_nan_canonicalization(true)` (rule 1)
/// - `wasm_simd(false)` + `wasm_relaxed_simd(false)` (rule 2)
/// - `consume_fuel(true)` (rule 4)
///
/// **`ChainNonAffecting`** (Observer host, chain-non-affecting):
/// - `consume_fuel(true)` (rule 4)
pub(crate) fn config_for_profile(profile: &EngineProfile) -> wasmtime::Config {
    let mut c = wasmtime::Config::new();
    match profile {
        EngineProfile::ReplayDeterministic { .. } => {
            c.cranelift_nan_canonicalization(true);
            c.wasm_simd(false);
            // wasmtime rejects "relaxed-simd enabled while simd disabled"
            // at Engine::new — the two flags travel together.
            c.wasm_relaxed_simd(false);
            c.consume_fuel(true);
        }
        EngineProfile::ChainNonAffecting { .. } => {
            c.consume_fuel(true);
        }
    }
    c
}

/// Build a wasmtime [`Engine`] from an [`EngineProfile`] + return the
/// per-invocation fuel budget for caller use at `Store::set_fuel(...)`
/// time. Canonical entrypoint for chain-effect-aware engine
/// construction.
///
/// Routes through [`config_for_profile`] for the underlying [`Config`]
/// shape — single source of truth shared with legacy
/// `WasmtimeEngineConfig::to_config()` paths.
///
/// # Errors
///
/// Returns the underlying `wasmtime::Error` if `Engine::new` fails
/// (Cranelift codegen initialisation issue — typically allocator or
/// capability error). Callers wrap into their host-specific error type.
pub(crate) fn build_engine(profile: &EngineProfile) -> Result<(Engine, u64), wasmtime::Error> {
    let engine = Engine::new(&config_for_profile(profile))?;
    Ok((engine, profile.fuel_budget()))
}
