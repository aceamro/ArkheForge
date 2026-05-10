# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — v0.13 is a single fixed pre-public version.
Subsequent corrections land on the same v0.13 line. Version 1.0 is
intentionally never reached (parity with ArkheKernel's versioning
policy).

## [0.13.0] — Initial release

ArkheForge L1+L2 runtime substrate — action dispatch, multi-tier KMS
crypto, WASM-sandboxed extension hosts, observer pipeline, audit
receipts, and end-to-end provably-fair example crates — built on top
of the ArkheKernel L0 deterministic microkernel.

### Workspace

Eleven crates total — 10 workspace members + 1 standalone Kani
harness:

- `arkhe-forge` — umbrella re-export for shell authors.
- `arkhe-forge-core` — L1 primitives (`ActionContext`, sealed
  `ArkheAction` / `ArkheEvent` traits, `process_action` pipeline,
  observer pipeline scaffold).
- `arkhe-forge-platform` — L2 services (`RuntimeService` dispatcher,
  hook host v2, observer host v2, KMS / AEAD tiers, `wal_export`
  reader+writer, manifest loader, dedup, projection observer,
  process-protection shim).
- `arkhe-forge-macros` — forge-side derive helper.
- `arkhe-rand` — L3 BLAKE3-keyed PRNG (no_std, `RngSource::from_seed`
  + Lemire-unbiased `gen_range_inclusive` + Fisher-Yates `shuffle`).
- `arkhe-runtime-testkit` — proptest harness for runtime crates.
- `arkhe-trait-default-check` — sealed-trait safeguard lint.
- `arkhe-subset-rust-check` — `Action::compute()` determinism subset
  lint.
- `examples/card_primitives` — provably-fair Texas Hold'em
  end-to-end (Hold'em primitives + Forge L1 + L2 + WAL round-trip).
- `examples/dice` — provably-fair 3D6 with server-commit + user-seed
  combined PRF + WAL persistence + multi-run history.
- `arkhe-runtime-proofs` — standalone Kani 5-property harness
  (excluded from workspace via own `[workspace]` table).

### Layer architecture

Single-direction layer DAG enforced by an `ImportDirectionMonotone`
invariant + a CI grep gate (no reverse edges):

- **L0 (inherit)** — `ArkheKernel` provides the deterministic state
  machine, WAL chain, signing class, and 25 formally-verified
  invariants.
- **L1 forge core** — Action / Event sealed traits, compute pipeline,
  context, event records.
- **L2 forge platform** — dispatcher, hook host v2 (wasmtime), observer
  host v2 (wasmtime), KMS / AEAD multi-tier, manifest, audit receipts,
  WAL export reader+writer.
- **L3 utility** — `arkhe-rand` BLAKE3-keyed PRNG (consumer-side use
  only — kernel + forge runtime forbid runtime RNG to preserve
  deterministic replay).
- **L4 examples** — `card_primitives`, `dice`.

### Cryptography

- **Tier-0 (default)** — BLAKE3 commit-reveal + Ed25519 Forge L2
  attestations + ChaCha20 (transitive). Crate-level zero-feature
  baseline.
- **Tier-1 KMS** (`tier-1-kms` feature) — XChaCha20-Poly1305 AEAD +
  Argon2 KDF for the free-tier KMS path.
- **Tier-2 multi-KMS** (`tier-2-multi-kms` feature) — adds AES-GCM +
  AES-GCM-SIV for production deployments and threshold-HSM coordination.
- **Tier-2 AWS KMS** (`tier-2-aws-kms` feature) — AWS KMS backend via
  AWS SDK, routed through the modern `rustls 0.23` /
  `rustls-aws-lc` chain (the legacy `rustls 0.21` chain affected by
  RUSTSEC-2026-0098 + RUSTSEC-2026-0099 is excluded by feature
  selection).
- **Tier-2 hook host v2** (`tier-2-hook-host-v2`) — wasmtime + WASI
  sandbox for hosted hook modules; capability gating + fuel budgets +
  Kani-verified host-fn boundary.
- **Tier-2 observer host v2** (`tier-2-observer-host-v2`) — wasmtime
  sandbox for projection observer modules.
- **PQC inheritance** — Hybrid Ed25519 + ML-DSA 65 (NIST FIPS 204,
  CNSA 2.0 transition) signing of the WAL chain is provided by the
  kernel; ArkheForge does not directly depend on `ml-dsa` while the
  upstream crate is at `0.1.0-rc.9` (unstable). Forge L2 attestation
  surfaces (KMS journal, audit receipts) emit Ed25519 today and will
  switch to Hybrid in lockstep with the kernel once `ml-dsa`
  stabilises.

### Formal verification

- **Kani 5-property harness** in `arkhe-runtime-proofs/` —
  `authorize`, `dispatch`, `replay`, `memory_bounds_check`,
  `hybrid_and_mode`. Standalone crate so the harness can be invoked
  independently of the workspace's normal `cargo test` path.
- **TLA+ refinement** — `formal/tla-plus/runtime_core.tla` +
  `formal/tla-plus/r4_implementation_refinement.tla` enforce the
  layer-DAG single-direction property and the L1+L2 dispatch
  refinement of the kernel state machine. Apalache typecheck CI gate
  runs on every push.
- **Axiom-cite registry** — `formal/axiom-test-cite.toml` +
  `scripts/verify-axiom-cite.sh` catch inventory drift; the four
  formal anchors are MD5-pinned in every cycle's verify checklist.

### Examples

- **`card-primitives`** — 9-stage end-to-end demo (`cargo run -p
  card-primitives`): dealer commits to a 32-byte seed, deals a
  2-player Texas Hold'em hand, reveals the seed, the audience-side
  pure functions reconstruct the shuffle, the same showdown then
  flows through the L1 event pipeline, the L2 `RuntimeService`
  dispatch loop, the framed `BufferedWalSink` byte stream, and a
  `StreamingWalReader` round-trip that asserts every record decodes
  byte-identical to the original.
- **`dice`** — provably-fair 3D6 (`cargo run -p dice`): server
  commits via `BLAKE3(domain || server_seed)`, user contributes a
  UTF-8 string via interactive stdin, the combined seed is
  `BLAKE3(domain || server_seed || user_input || nonce)`, and three
  Lemire-unbiased rolls land via `arkhe-rand::RngSource`. Every roll
  rewrites a single canonical `dice.wal` (chronological history,
  newest-first display capped at 5) with per-stage wall-clock
  timings + an aggregate TPS estimate. `--reset` deletes the WAL;
  `--verify` re-dispatches the file and asserts byte-equality with
  the on-disk stream.

### Engineering discipline

- `#![forbid(unsafe_code)]` across every crate that owns its own
  `lib.rs` / `main.rs`.
- Workflow-3 9-step pre-commit gate — `cargo build --workspace`,
  `cargo test`, `cargo clippy --workspace --all-targets`,
  `cargo doc --no-deps`, `cargo deny check`, `cargo fmt --check`,
  PCRE self-grep, companion-file sync, formal-anchor MD5 verify.
- 4-axis cross-review per substantive change (architect / cryptographer
  / theorist / auditor) with a cap-5 plan-iteration boundary.
- Workspace-level lints (`unwrap_used`, `expect_used`, `panic`, `todo`,
  `unimplemented`, `dbg_macro` all denied).
- Single-version pin v0.13 across every workspace crate.

### Documentation

- Root [`README.md`](README.md) — workspace overview + crate table.
- Per-crate `README.md` for the example crates
  ([`examples/card_primitives/`](examples/card_primitives/),
  [`examples/dice/`](examples/dice/)) and `arkhe-rand`.
- API reference — published per-crate on crates.io.

### Sibling repository

[ArkheKernel](https://github.com/aceamro/ArkheKernel) ships the L0
deterministic microkernel that this substrate consumes (action /
component / event derive macros, sealed WAL writer, Hybrid PQC
signing, formal axiom inventory).

### Licensing

Dual-licensed under MIT OR Apache-2.0.
