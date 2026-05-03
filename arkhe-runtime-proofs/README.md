# `arkhe-runtime-proofs/` — ArkheKernel Runtime Kani harness crate

DIP-N5 cycle plan Track E sub-step E.2 (scaffold). v0.12 sealing
cycle implementation-level proof anchor.

## Workspace exclusion

This crate is **NOT a member of the root ArkheKernel workspace**. Per
cycle plan v0.4 D-USER-3 (c) Q4(a) absorption (Linus single-path):

- `cargo build --workspace` from workspace root does not compile this
  crate
- `cargo test --workspace` from workspace root does not run this crate's
  tests
- 7-config cargo test matrix (default 540 / federation-archive 543 /
  audit-receipt 544 / both 548 / tier-2-hook 611 / tier-2-observer 585 /
  all-features 695) baseline preserved

`cargo kani` is invoked from inside this directory only.

## Toolchain pin

`rust-toolchain.toml` pins **nightly-2025-11-21** (Kani 0.67.0
requirement). Production crates retain workspace MSRV 1.80; this
crate's nightly toolchain is isolated to the proofs directory and does
not propagate to the workspace.

## Kani version

**Kani 0.67.0** (released January 2026). Install:

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
push + PR. 35-min job timeout (per-harness 30-min target, buffered for
install overhead — cycle plan v0.4 theorist Q4(b) absorption).

## DIP-N5 sub-step trace

| Sub-step | Deliverable |
|---|---|
| E.2 (this commit) | Crate scaffold (`Cargo.toml` + `rust-toolchain.toml` + `src/lib.rs` smoke harness + this `README.md`) + ci `kani-verify` job |
| E.8 | 4-property suite — `kani_authorize_property` (E6/E7 typestate, N=4×M=4=16 cases) / `kani_dispatch_property` (E14 deterministic, 2x dispatch determinism) / `kani_replay_property` (A1 bit-identical, k=3 reorder window) / `kani_memory_bounds_check_property` (DIP-N1 B.5 firm contract anchor — `read_caller_memory` / `write_caller_memory` symbolic OOB) |

Each harness uses `#[kani::unwind(8)]` to bound SMT loop depth and
`kani::assume(...)` for input-domain restriction (cycle plan v0.4
theorist (d) input-domain bounding absorption).

## Layer A 침범 0 anchor

- L0 (`arkhe-kernel/src/**`) untouched
- macros (`arkhe-macros/src/**`) untouched
- root `Cargo.toml` `[workspace] members` untouched (auditor C1
  workspace-root parallel placement HARD CONCUR)
- spec body (`runtime-book/src/**` / `book/src/**`) untouched until
  E.9 evidence cite addition
- `verify-l0-baseline.sh` 31-files SHA-256 baseline preserved

E.9 cycle close 3-agent verify (cryptographer + auditor + theorist)
commits verbatim Layer A 8건 침범 0 declaration.

## E.8 cryptographer + theorist primary verify

**cryptographer** primary verify per cycle plan v0.4 lead scope:
DIP-N1 B.5 firm contract anchor (`kani_memory_bounds_check_property`)
+ replay determinism (`kani_replay_property`) sealed-completeness
chain mapping.

**theorist** primary verify: Kani harness correctness +
`kani::any` input-domain bounding strategy + `#[kani::unwind]` SMT
loop depth selection.
