# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — the version tracks the ArkheKernel epoch. A new
minor epoch is cut on a substantive trigger (here: `ml-dsa` 0.1.0
stabilisation → kernel v0.14). Version 1.0 is intentionally never
reached (parity with ArkheKernel).

## [0.14.1] — wire-neutral dependency maintenance

Patch release on the same ArkheKernel v0.14 epoch, tracking ArkheKernel
0.14.1. Mirroring the kernel, the persisted wire format, signature
domains, and the code-level `SEMVER` epoch constants are frozen at the
0.14 epoch — every 0.14 audit chain and L2 receipt replays and verifies
bit-identically. Only the crate versions and the `ml-dsa` pin move; no
runtime behaviour changes.

### Changed
- `ml-dsa` pin `=0.1.0` → `=0.1.1` (`arkhe-forge-platform`, gated
  `tier-2-pqc-receipts`). The sole upstream change is a
  `module-lattice/alloc` feature-propagation fix (#1365); ML-DSA-65
  signature and key bytes are unchanged, so both the L0 WAL Hybrid path
  and the L2 audit-receipt verifier stay byte-compatible across the bump.
- Consumes `arkhe-kernel` / `arkhe-macros` 0.14.1. The `0.14` epoch pin is
  unchanged; the lockfile resolves the patch.

### Fixed
- `arkhe_runtime_testkit::TESTKIT_SEMVER` epoch marker corrected
  `(0, 12, 0)` → `(0, 14, 0)`; the constant had lagged two epochs.
  Introspection-only — not serialised into any wire or hashed surface.

### Licensing
Dual-licensed under MIT OR Apache-2.0.

## [0.14.0] — ml-dsa epoch: PQC receipts, plugin removal, hardening

Tracks the ArkheKernel v0.14 epoch (`ml-dsa` 0.1.0 / NIST FIPS 204 final).
Consumes `arkhe-kernel` / `arkhe-macros` 0.14; `ml-dsa` pinned at the
stable `=0.1.0`.

### Added
- L2 post-quantum audit-receipt verification + signing
  (`arkhe_forge_platform::verifier`). `verify_attestation` dispatches on
  the policy-pinned class — None / Ed25519 (`verify_strict`) / ML-DSA-65
  / Hybrid (AND-mode) — over a forge-receipt domain-separated message;
  `verify_receipt_envelope` enforces algorithm↔slot coherence;
  `ReceiptSigner` (ML-DSA-65, gated `tier-2-pqc-receipts`). Tier-2
  crypto-erasure receipts are signed for real.
- `AuditReceiptKeyPolicy` additive `attestation_pqc` slot (schema 2),
  byte-identical to schema 1 for Ed25519/None receipts (forward-only).
- Anchored journal verification (`InMemoryJournal::verify_chain_anchored`)
  against a pinned out-of-band key + expected tip/length.

### Removed
- The wasm hook host v2 + observer host v2 plugin subsystem — the
  `tier-2-hook-host-v2` / `tier-2-observer-host-v2` features, the
  `wasmtime` / `wasmtime-wasi` dependencies (~98 transitive crates), and
  the `HookModuleRegister` / `ObserverQuarantine` events. Dormant and
  off-by-default; removed to shrink the security surface and dependency
  weight. A permanent TypeCode gap is left at `0x0003_0F0B` / `0x0003_0F0C`.

### Fixed
- GDPR `ErasurePending` (C3) admission gate is enforced and live. The GDPR
  lifecycle pointer is its own `UserGdprState` component
  (`arkhe_forge_core::user`), so `GdprEraseUser` transitions it with a blind
  write valid on the viewless dispatch path; the `RuntimeService` L2 admission
  gate and the in-compute gate reject any actor-originated action whose backing
  user is `ErasurePending` or the terminal `Erased`, before the action reaches
  the WAL.
- DEK AES-256-GCM nonce reuse across reconstruction: long-lived
  (KMS-unwrapped) DEKs now require nonce-misuse-resistant AES-256-GCM-SIV;
  plain AES-256-GCM is rejected for them (`PiiError::NonceReuseRisk`).
- Crypto-erasure attestations no longer label a BLAKE3 transparency
  digest as an Ed25519 signature (now `RuntimeSignatureClass::None`).
- `arkhe-rand` full-range `gen_range_inclusive` overflow (`u8`/`u16`
  `MIN..=MAX`).
- Manifest `audit.signature_class` is validated (unknown values rejected).

### Changed
- **Breaking — acting-actor injection.** `RuntimeService::dispatch` takes a
  new trailing argument `authenticated_actor: Option<ActorId>`: the acting
  identity is injected through the kernel actor channel (the single source of
  truth the integrator's auth layer resolves), never carried on the wire.
  Forge actions dropped their wire actor/creator field accordingly —
  `SubmitActivity` takes `ActivityDraft` (was `ActivityRecord`) and
  `CreateSpace` takes `SpaceConfigDraft` (was `SpaceConfig`); compute stamps
  the injected actor into the stored record. This makes the GDPR-gate
  actor-substitution vector structurally impossible rather than merely
  checked. Removed: the `GdprGuard` trait, `gdpr_actor()`, and
  `DispatchError::ActorMismatch`.
- `arkhe-rand` KDF domain tag is now version-agnostic (`"arkhe-rand
  stream"`, previously carried a `v0.13` suffix). PRNG streams therefore
  differ from 0.13.0 for the same seed — a deliberate one-time change at
  this epoch boundary; the golden vector is regenerated.

### Licensing

Dual-licensed under MIT OR Apache-2.0.

## [0.13.0] — Initial release

ArkheForge L1+L2 runtime substrate built on the ArkheKernel L0 sealed
deterministic microkernel. Layered architecture: kernel inherit + L1
primitives (sealed `ArkheAction` / `ArkheEvent` traits, compute
pipeline) + L2 services (`RuntimeService` dispatcher, multi-tier KMS
AEAD, wasmtime-sandboxed hook host v2 and observer host v2, WAL
export reader+writer) + L3 utility (`arkhe-rand` BLAKE3-keyed PRNG) +
examples. Cryptographic primitives include BLAKE3 (hashing + KDF),
Ed25519 (Forge L2 attestations), multi-tier KMS AEAD (ChaCha20-Poly1305
/ AES-GCM / AES-GCM-SIV) with Argon2 KDF, and post-quantum signing
inherited transitively from the kernel (Hybrid Ed25519 + ML-DSA 65,
NIST FIPS 204). Provably-fair commit-reveal patterns demonstrated in
`examples/dice` (3D6 with WAL multi-run history) and
`examples/card_primitives` (Hold'em with end-to-end framework
integration). Engineering discipline: workflow-3 9-step gate + 4-axis
cross-review + workspace single-version pin. See [`README.md`](README.md)
for the crate enumeration and `Cargo.toml` for dependency pins.

### Licensing

Dual-licensed under MIT OR Apache-2.0.
