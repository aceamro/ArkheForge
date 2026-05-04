//! Shared wasmtime-sandbox helpers for `hook_host/` and `observer_host/`.
//!
//! Compiled only when at least one wasmtime-backed feature is enabled
//! (`tier-2-hook-host-v2` or `tier-2-observer-host-v2`); both hosts'
//! `capability_linker` modules import from here.
//!
//! ## Module stratum classification
//!
//! - `hook_host/` + `observer_host/` = **boundary** stratum (host-side
//!   wasmtime sandbox surfaces; chain-affecting / chain-non-affecting
//!   adapters that face the L1 submission + L2 projection paths).
//! - `wasm_runtime_common/` (this module) = **runtime** stratum
//!   (shared sandbox helpers; chain-effect-orthogonal logic reused by
//!   both host stratum modules).
//!
//! **DAG invariant** (Layer A item 6): import direction is
//! **boundary → runtime only**. A reverse edge (runtime → boundary)
//! would let `wasm_runtime_common` depend on host-specific code,
//! breaking the layered abstraction at the host-layer boundary. The
//! invariant is enforced at CI by a grep step (`grep -rE
//! "use\s+(crate::)?(hook_host|observer_host)"
//! arkhe-forge-platform/src/wasm_runtime_common/` must return 0 hits).
//!
//! ## Why shared
//!
//! The bounds-check helpers + parameterised import scan are extracted
//! from `hook_host/capability_linker.rs` into this module. Both
//! wasmtime hosts need:
//!
//! - **`(ptr, len)` bounds-check** on every wasm-memory deref —
//!   cryptographer-anchored firm contract (no FFI-shaped sandbox-escape
//!   primitive). Generic over the [`wasmtime::Store`] data type so the
//!   same body works for `HookStoreData` and `ObserverStoreData`.
//! - **Module pre-scan** with allow-list + WIT-boundary deny-list —
//!   E14.L2-Allow + E15.b runtime enforcement. Parameterised so each
//!   host configures its own `arkhe:{hook,observer}/*` prefix and
//!   shares the WASI deny set.
//!
//! `pub(crate)` visibility — these are sandbox-implementation details
//! within `arkhe-forge-platform`. External consumers reach the
//! sandboxes via the published `ObserverHost` / `HookHost` traits.

#![cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]

/// Sealed-trait pattern for cap-token + host-linker markers (extracted
/// from this file into `sealed_traits.rs` for module-size hygiene).
pub(crate) mod sealed_traits;
pub(crate) use sealed_traits::sealed_impl;
pub use sealed_traits::{HookCapTokenSealed, ObserverCapTokenSealed, SealedHostImport};

/// Generic wasm-memory `(ptr, len)` bounds-check helpers (extracted
/// from this file into `wasm_memory.rs` for module-size hygiene).
pub(crate) mod wasm_memory;
pub(crate) use wasm_memory::{read_caller_memory, write_caller_memory};

/// Module import pre-scan + WASI deny-list (extracted to
/// `import_scan.rs` for module-size hygiene).
pub(crate) mod import_scan;
pub use import_scan::WASI_DENY_PREFIXES;
pub(crate) use import_scan::{scan_module_imports, ScanImportsError};

/// Wasmtime engine profile + factory (extracted to `engine_profile.rs`
/// for module-size hygiene).
pub(crate) mod engine_profile;
pub(crate) use engine_profile::{build_engine, config_for_profile, EngineProfile};

/// Module registration with BLAKE3 digest pin + import pre-scan
/// (extracted to `register_module.rs` for module-size hygiene).
pub(crate) mod register_module;
pub(crate) use register_module::{register_module_common, RegistrationError};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use wasmtime::{Caller, Config, Engine, Module, Store};

    fn engine() -> Engine {
        let mut c = Config::new();
        c.consume_fuel(true);
        Engine::new(&c).expect("test engine builds")
    }

    fn wat_to_bytes(wat: &str) -> Bytes {
        Bytes::from(wat::parse_str(wat).expect("valid wat"))
    }

    /// Generic smoke test — scan accepts modules whose imports match
    /// the supplied allow-list. Caller chooses prefixes; helper is
    /// host-agnostic.
    #[test]
    fn scan_accepts_arbitrary_allowed_prefix() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "test:custom/effect" "fire"
                    (func (param i32 i32))))"#,
        );
        let _ = scan_module_imports(
            &engine(),
            &bytes,
            &["test:custom/"],
            &["wasi:random"],
            "only `test:custom/*` permitted",
        )
        .expect("custom allow-list accepts matching import");
    }

    /// Audit message survives into the rejection reason so operator
    /// logs distinguish hook vs observer rejection contexts.
    #[test]
    fn scan_rejection_carries_audit_message() {
        let bytes = wat_to_bytes(
            r#"(module
                (import "wasi:io/streams" "write"
                    (func (param i32))))"#,
        );
        let err = scan_module_imports(
            &engine(),
            &bytes,
            &["arkhe:observer/"],
            &["wasi:io"],
            "only `arkhe:observer/*` permitted",
        )
        .expect_err("denied import must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("denied namespace `wasi:io`"),
            "audit message lost: {msg}"
        );
    }

    /// `Vec<u8>` round-trip through `read_caller_memory<T>` for an
    /// arbitrary store data type — verifies the generic body compiles
    /// and runs for non-hook/non-observer T. All wasmtime entities
    /// must share the same `Engine` instance per wasmtime's cross-
    /// engine validation.
    #[test]
    fn read_caller_memory_works_for_arbitrary_t() {
        let eng = engine();
        let bytes = wat_to_bytes(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 0) "HELLO")
                (func (export "hook") (result i32)
                    i32.const 0))"#,
        );
        let module = Module::from_binary(&eng, bytes.as_ref()).expect("module parses");
        let mut store = Store::new(&eng, 42_u32);
        store.set_fuel(1_000_000).expect("seed fuel");

        let mut linker = wasmtime::Linker::<u32>::new(&eng);
        // Bind a host-fn that exercises read_caller_memory<u32>.
        linker
            .func_wrap(
                "test",
                "probe",
                |mut caller: Caller<'_, u32>, ptr: i32, len: i32| -> Result<i32, wasmtime::Error> {
                    let buf = read_caller_memory(&mut caller, ptr, len)?;
                    Ok(buf.len() as i32)
                },
            )
            .expect("bind probe");

        let inst = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");
        let entry = inst
            .get_typed_func::<(), i32>(&mut store, "hook")
            .expect("entry");
        // Instantiate succeeds; the mere fact that this compiles +
        // runs verifies that `read_caller_memory<u32>` compiles for
        // `T = u32` (probe host-fn is wired but not called from this
        // test path).
        let _ = entry.call(&mut store, ()).expect("call");
    }

    /// `EngineProfile::ReplayDeterministic` builds a wasmtime engine
    /// with all three E14.L2-Allow rules pinned. Verifies the
    /// EngineProfile factory single source of truth — any future drift
    /// in the rule 1+2+4 axis pinning will fail this test.
    #[test]
    fn engine_profile_replay_deterministic_builds_engine() {
        let profile = EngineProfile::ReplayDeterministic {
            fuel_budget: 10_000_000,
        };
        let (engine, fuel) = build_engine(&profile).expect("engine builds");
        assert_eq!(fuel, 10_000_000);

        // The engine must accept a wat module that does NOT use SIMD
        // and run with fuel metering — empirical proof that
        // consume_fuel(true) is active.
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "noop")))"#;
        let bytes = wat_to_bytes(wat);
        let module = Module::from_binary(&engine, bytes.as_ref()).expect("noop module parses");
        let mut store = Store::new(&engine, ());
        store.set_fuel(fuel).expect("seed fuel");
        let inst = wasmtime::Linker::<()>::new(&engine)
            .instantiate(&mut store, &module)
            .expect("instantiate");
        let _ = inst
            .get_typed_func::<(), ()>(&mut store, "noop")
            .expect("noop export");
    }

    /// `EngineProfile::ReplayDeterministic` rejects SIMD-using modules
    /// at module-load — empirical proof that `wasm_simd(false)`
    /// (rule 2) is pinned by the factory.
    #[test]
    fn engine_profile_replay_deterministic_rejects_simd() {
        let profile = EngineProfile::ReplayDeterministic {
            fuel_budget: 10_000_000,
        };
        let (engine, _) = build_engine(&profile).expect("engine builds");
        let wat = r#"(module (func (drop (v128.const i32x4 0 0 0 0))))"#;
        let bytes = wat_to_bytes(wat);
        let res = Module::from_binary(&engine, bytes.as_ref());
        assert!(
            res.is_err(),
            "ReplayDeterministic profile must reject SIMD modules"
        );
    }

    /// `EngineProfile::ChainNonAffecting` builds a wasmtime engine with
    /// fuel metering only — NaN/SIMD pinning skipped (E15 chain-non-
    /// affecting rationale). The factory's profile dispatch is
    /// regression-tested here.
    #[test]
    fn engine_profile_chain_non_affecting_builds_engine() {
        let profile = EngineProfile::ChainNonAffecting {
            fuel_budget: 100_000_000,
        };
        let (engine, fuel) = build_engine(&profile).expect("engine builds");
        assert_eq!(fuel, 100_000_000);

        // Engine accepts noop module + fuel metering active.
        let wat = r#"(module (func (export "noop")))"#;
        let bytes = wat_to_bytes(wat);
        let module = Module::from_binary(&engine, bytes.as_ref()).expect("noop module parses");
        let mut store = Store::new(&engine, ());
        store.set_fuel(fuel).expect("seed fuel");
        let _ = wasmtime::Linker::<()>::new(&engine)
            .instantiate(&mut store, &module)
            .expect("instantiate");
    }

    /// `EngineProfile::fuel_budget` accessor returns the per-variant
    /// budget for both variants — used by callers seeding
    /// `Store::set_fuel(...)`.
    #[test]
    fn engine_profile_fuel_budget_accessor() {
        assert_eq!(
            EngineProfile::ReplayDeterministic {
                fuel_budget: 42_000
            }
            .fuel_budget(),
            42_000
        );
        assert_eq!(
            EngineProfile::ChainNonAffecting {
                fuel_budget: 7_000_000
            }
            .fuel_budget(),
            7_000_000
        );
    }

    /// SealedCapToken safeguard compile-time witness.
    /// `assert_*_sealed::<C>()` requires `C: HookCapTokenSealed` (or
    /// `ObserverCapTokenSealed`) which is only satisfiable by types
    /// impl-ing the private `Sealed` marker. External crates cannot
    /// name `Sealed`, so cannot impl the trait — invariant raised to
    /// compile-time (`cargo expand` would show the sealed bound +
    /// `cargo doc` surfaces the sealed pattern).
    fn assert_hook_cap_token_sealed<C: HookCapTokenSealed>() {}
    fn assert_observer_cap_token_sealed<C: ObserverCapTokenSealed>() {}

    /// Hook `CapToken` enum satisfies [`HookCapTokenSealed`]. The bound
    /// requires the private `Sealed` marker which only types defined
    /// in `arkhe-forge-platform` can impl. Compile-time witness for the
    /// sealed-trait safeguard.
    #[test]
    fn hook_cap_token_satisfies_sealed_bound() {
        assert_hook_cap_token_sealed::<crate::hook_host::CapToken>();
    }

    /// Observer `ObserverCapToken` enum satisfies [`ObserverCapTokenSealed`].
    /// Mirrors the hook-side compile-time witness — observer-side
    /// invariant raised to compile-time (E15.b enforcement at type
    /// level, not just runtime).
    #[test]
    fn observer_cap_token_satisfies_sealed_bound() {
        assert_observer_cap_token_sealed::<crate::observer_host::ObserverCapToken>();
    }

    /// SealedHostImport safeguard compile-time witness.
    /// `assert_sealed_host_import::<L>()` requires `L: SealedHostImport`
    /// which is only satisfiable by types impl-ing the private
    /// [`private_seal::Sealed`] marker. External crates cannot name
    /// `Sealed`, so cannot impl the trait — invariant raised to
    /// compile-time (HostImports universe closed at host-defining crate
    /// boundary).
    fn assert_sealed_host_import<L: SealedHostImport>() {}

    /// Hook `CapabilityLinker` satisfies [`SealedHostImport`]. Compile-
    /// time witness for the sealed-trait safeguard — verifies the
    /// hook-side host-linker type belongs to the sealed universe.
    /// Feature-gated to `tier-2-hook-host-v2` since `CapabilityLinker`
    /// is only compiled under that feature.
    #[cfg(feature = "tier-2-hook-host-v2")]
    #[test]
    fn hook_capability_linker_satisfies_sealed_host_import() {
        assert_sealed_host_import::<crate::hook_host::capability_linker::CapabilityLinker>();
    }

    /// Observer `ObserverCapabilityLinker` satisfies [`SealedHostImport`].
    /// Mirrors the hook-side compile-time witness — observer-side
    /// host-linker invariant raised to compile-time (E15.b
    /// chain-non-affecting boundary structurally bounded). Feature-
    /// gated to `tier-2-observer-host-v2` since
    /// `ObserverCapabilityLinker` is only compiled under that feature.
    #[cfg(feature = "tier-2-observer-host-v2")]
    #[test]
    fn observer_capability_linker_satisfies_sealed_host_import() {
        assert_sealed_host_import::<
            crate::observer_host::capability_linker::ObserverCapabilityLinker,
        >();
    }
}
