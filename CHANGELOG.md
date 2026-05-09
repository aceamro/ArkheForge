# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.13.0] — Initial release

First public release of **ArkheForge**, the L1+L2 runtime substrate for
[ArkheKernel](https://github.com/aceamro/ArkheKernel).

### Added

- Eight workspace crates: umbrella `arkhe-forge`, L1 core, L2 platform,
  forge derive macros, proptest testkit, two custom-lint crates
  (sealed-trait safeguard + `Action::compute` determinism subset), and a
  standalone Kani harness.
- L2 dispatcher (`RuntimeService::dispatch` + `export_wal` +
  `wal_to_sink`) driving the kernel WAL append + replay path.
- WASM-sandboxed hook host v2 + observer host v2 — capability gating,
  fuel budgets, Kani-verified host-fn boundary.
- Three-tier KMS / AEAD compliance stack with crypto-erasure
  coordination (Tier-0 software-KEK / Tier-1 free-tier / Tier-2
  multi-KMS + threshold HSM).
- Inherits the Hybrid Ed25519 + ML-DSA 65 WAL chain signing pipeline
  (NIST FIPS 204) from ArkheKernel. Forge L2 attestation surfaces
  (KMS journal, audit receipts) emit Ed25519 by default; the
  `pqc-hybrid` feature flag ships as preview scaffolding.
- Reference example `card-primitives` — provably-fair Texas Hold'em
  with BLAKE3 commit-reveal, end-to-end Forge L1 + L2 integration, and
  audit-grade WAL round-trip.
- Formal verification: 5-property Kani harness, TLA+ refinement
  (`runtime_core` + `r4_implementation_refinement`), and an axiom-cite
  CI gate.

### Compatibility

- `arkhe-kernel = "0.13"` (crates.io)
- `arkhe-macros = "0.13"` (crates.io)
- Rust MSRV: per workspace `rust-version`

### License

Dual-licensed under Apache-2.0 OR MIT.
