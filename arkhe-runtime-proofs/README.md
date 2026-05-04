# `arkhe-runtime-proofs/` — ArkheForge Runtime Kani harness crate

Implementation-level Kani harness for the L1 Action submit / dispatch /
replay path. Ships a 5-property harness suite covering authorization
(E6/E7), dispatch determinism (E14), bit-identical replay (A1), wasm
memory bounds-check, and the PQC Hybrid AND-mode dispatch.

## Workspace exclusion

This crate is **NOT a member of the root ArkheForge workspace**:

- `cargo build --workspace` from the workspace root does not compile
  this crate.
- `cargo test --workspace` from the workspace root does not run this
  crate's tests.
- The workspace test baselines stay independent of the proofs harness.

`cargo kani` is invoked from inside this directory only.

## Toolchain pin

`rust-toolchain.toml` pins **nightly-2025-11-21** (Kani 0.67.0
requirement). Production crates retain workspace MSRV 1.80; this
crate's nightly toolchain is isolated to the proofs directory and does
not propagate to the workspace.

## Kani version

**Kani 0.67.0**. Install:

```bash
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup
```

`cargo kani setup` downloads Kani's bundled binaries (CBMC + Kani's
Rust front-end) into `~/.kani/`.

## Run

```bash
cd arkhe-runtime-proofs
cargo kani
```

CI runs the `kani-verify` job (`.github/workflows/ci.yml`) on every
push and PR. 35-min job timeout (per-harness 30-min target, buffered
for setup overhead).

## Harness suite

| Harness | Anchor | Bounded MC scope |
|---|---|---|
| `kani_authorize_property` | E6/E7 typestate | N=4 shell brands × M=2 typestate variants = 8 cases |
| `kani_dispatch_property` | E14 deterministic execution | u32 input, twice-dispatch determinism |
| `kani_replay_property` | A1 bit-identical replay | k=3 reorder window |
| `kani_memory_bounds_check_property` | wasm memory firm contract | `read_caller_memory` / `write_caller_memory` symbolic OOB |
| `kani_hybrid_and_mode_property` | PQC Hybrid AND-mode dispatch | 3 policy variants × 2 ed25519 × 2 mldsa65 = 12 cases |

Each harness uses `#[kani::unwind(8)]` to bound SMT loop depth and
`kani::assume(...)` for input-domain restriction.

## Layer A non-touch invariant

- L0 (`arkhe-kernel/src/**`) untouched
- macros (`arkhe-macros/src/**`) untouched
- root `Cargo.toml` `[workspace] members` untouched
- inline rustdoc spec citations across the workspace untouched
- `verify-l0-baseline.sh` 31-files SHA-256 baseline preserved
