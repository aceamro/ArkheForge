# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — v0.13 is a single fixed pre-public version.
Subsequent corrections land on the same v0.13 line. Version 1.0 is
intentionally never reached.

## [0.13.0] — Initial release

ArkheForge L1+L2 runtime substrate for the [ArkheKernel](https://github.com/aceamro/ArkheKernel)
deterministic microkernel.

### Workspace

Seven crates plus a standalone Kani harness:

- `arkhe-forge` — umbrella re-export for shell authors
- `arkhe-forge-core` — runtime traits, dispatch, observer pipeline
- `arkhe-forge-platform` — hook host v2, observer host v2, KMS, AEAD
- `arkhe-forge-macros` — derive macros for forge components
- `arkhe-runtime-testkit` — proptest harness for runtime crates
- `arkhe-trait-default-check` — sealed-trait safeguard lint
- `arkhe-subset-rust-check` — `Action::compute()` determinism subset lint
- `arkhe-runtime-proofs` — Kani 5-property harness (standalone)

### Determinism

- A1 D1-Total bit-identical replay carries through from sealed L0
  ArkheKernel to the runtime boundary.
- 3-band determinism — Core (L0 bit-identical) / Projection (eventually
  consistent observer pipeline) / Protocol-Correctness (shell-level
  compatibility contracts).

### Sandbox + sealed seam

- Hook host v2 + observer host v2 — WASM preview-2 sandbox with
  capability gating, fuel budgets, and Kani-verified host-fn boundary.
- Sealed-trait pattern (`private_seal::Sealed` bound) cross-cutting
  across capability_linker, hook_host_v2, observer_host_v2, cap_token,
  and SealedHostImport — sibling of kernel A24 lineage.

### Cryptography

- Inherits Hybrid Ed25519 + ML-DSA 65 (NIST FIPS 204) signing pipeline
  from ArkheKernel.
- Forge-specific AEAD stack: `argon2` + `chacha20poly1305` (Tier-1) +
  `aes-gcm` + `aes-gcm-siv` (Tier-2).
- 3-tier compliance — Tier-0 software-KEK / Tier-1 KMS free-tier /
  Tier-2 Multi-KMS + threshold HSM.
- Crypto-erasure design — HSM-generated DEK + envelope encryption +
  tombstone semantics + multi-region 2PC atomic shred (GDPR-aligned).

### Formal verification

- E1–E15 catalog — 15 distinct E-axioms across 17 enforcement slots
  (12 machine-checked + 5 non-MC; `E7` and `E14` are dual-tier).
- TLA+ refinement — `runtime_core` + `r4_implementation_refinement`
  in this repository, complementing `cr1`–`cr4` in sibling ArkheKernel.
- Kani 5-property harness suite (`arkhe-runtime-proofs/`):
  `kani_authorize_property`, `kani_dispatch_property`,
  `kani_replay_property`, `kani_memory_bounds_check_property`,
  `kani_hybrid_and_mode_property`.
- Machine-readable axiom inventory (`formal/axiom-test-cite.toml`) with
  cross-repo path resolution to sibling kernel TLA+ modules.

### Cross-repo dependency

`arkhe-kernel` and `arkhe-macros` referenced via path during
development; transition to `crates.io` after v0.13 publish.

### Planned (post-v0.13)

- Apalache typecheck CI extension covering `runtime_core` +
  `r4_implementation_refinement` (Apalache currently runs against
  `cr1`–`cr4` in sibling kernel CI).
- R4-X stratum boundary CI grep gate (`boundary → runtime` single
  direction enforcement of `ImportDirectionMonotone`).
- HF2 Auto Promote Trust Model — multi-channel health-checks +
  threshold HSM quorum for promoting standby key material under
  operator policy.

### Licensing

Dual-licensed under Apache-2.0 OR MIT.
