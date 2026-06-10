# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — the version tracks the ArkheKernel epoch. A new
minor epoch is cut on a substantive trigger (here: the kernel's
Canonical Input Log restructure → kernel v0.15). Version 1.0 is
intentionally never reached (parity with ArkheKernel).

## [0.15.0] — Canonical Input Log epoch sync (wire-format-breaking)

Epoch release tracking ArkheKernel v0.15.0, whose WAL is restructured
into a Canonical Input Log: one `Submit` record per externally admitted
action and one `Step` record (verdict + post-state digest) per pop, with
every deterministic effect re-derived on replay by re-executing
`compute()`. A 0.14-epoch WAL does not replay under 0.15 and 0.14-signed
L2 receipts verify only under 0.14 binaries (forward-only, pre-public).
The forge epoch surfaces advance in lockstep: `RUNTIME_SEMVER` /
`PLATFORM_SEMVER` / `SEMVER` / `TESTKIT_SEMVER` `(0, 15, 0)` and
`FORGE_RECEIPT_SIG_DOMAIN` `arkhe-forge v0.15 …`.

### Changed
- Consumes `arkhe-kernel` / `arkhe-macros` 0.15 (epoch pin `0.14` →
  `0.15`). One `RuntimeService::dispatch` now appends a Submit + Step
  record pair; `Kernel::submit` is called with the dispatch `caps` as
  the per-submission capability ceiling (recorded on the Submit record)
  and `Kernel::step` with the same `caps` as the operator session
  ceiling. Under the kernel's unified capability model
  (`effective_caps(default_caps, principal, ceiling)` ∩ session
  ceiling, no `Principal::System` bypass) the L2 gate posture is
  unchanged: capability denial still surfaces via
  `StepReport::effects_denied`.
- `WalRecordSink::append_record` takes the record's kind-agnostic
  monotonic `seq` as an explicit argument; `wal_to_sink` reads it
  through the typed `WalRecord::seq()` accessor. The sink no longer
  parses kernel record bytes (the v0.14 design decoded the leading
  postcard field, which the kind-discriminated v0.15 layout turns into
  the content tag) — the L0 schema coupling is now compiler-checked at
  the producer call site and the framing layer is fully
  payload-agnostic. The `ARKHEXP1` stream format itself is unchanged:
  magic, `u64` BE length prefix, and record-section bit-exactness all
  hold byte-for-byte.
- `examples/dice` history loading filters `Submit` records (Step
  records carry no action bytes), so roll/nonce derivation is stable
  over the two-record dispatch shape; a pre-0.15 `dice.wal` is a
  different wire epoch (`--reset` clears it).

### Added
- `RegisterActor` (`arkhe-forge-core`, type code `0x0001_0101`) — the
  production actor-registration action: spawns the actor entity and
  attaches `ActorProfile` + `UserBinding` with the spawn-then-set
  discipline, enforcing the E-actor-3 handle-collision gate. This is
  the binding path that makes the E-user-3 C3 GDPR admission gate live
  in production: `ensure_actor_eligible` resolves actor → user through
  the `UserBinding` this action writes, and the end-to-end liveness
  test now drives only production actions (`RegisterUser` →
  `RegisterActor` → `GdprEraseUser` → rejection before `submit`). The
  gate also fails closed on a resolved binding whose user has no
  `UserGdprState` (`ActionError::UserLifecycleUnresolved`, surfaced as
  `DispatchError::UnboundUserLifecycle`): an actor bound to a
  never-registered user — whose erasure request would no-op — is
  rejected at admission instead of becoming permanently ungateable.
- `ensure_schema_version` (`arkhe-forge-core::context`) — every
  production `compute()` body validates each wire-supplied
  `schema_version` field against the type's canonical constant as its
  first check and rejects mismatches with
  `ActionError::SchemaMismatch` (previously a dead variant; wire
  values were persisted verbatim).

### Fixed
- `ProjectionRouter` event dedup keyed on the per-compute
  `EventRecord.sequence`, which restarts at 0 for every action — the
  second of two successive actions' events was silently dropped as a
  duplicate. The router now tracks a composite `(tick, sequence)`
  stream cursor (tick-major): redelivery of the same position is a
  no-op only when the event identity (type code + payload) matches — a
  DIFFERENT event at the cursor position (same-tick compute collision)
  rejects loudly with the new `PositionConflict` variant; distinct
  computes' events all apply; `SequenceBackward`/`SequenceGap` carry
  full `ProjectionCursor` positions; and a failed fan-out — first or
  mid-stream — pins the unapplied event's position AND identity, so a
  skip-ahead cannot silently advance past the lost event and a
  different event at the failed position cannot be absorbed as its
  retry.
- `ObserverState::Draining` is terminal as documented: the single
  transition gate now rejects `Draining → Passive → Active`
  resurrection.
- `wal_to_sink` streams within the sink capacity: on `BufferOverflow`
  it flushes mid-stream and retries, so a WAL of any size exports
  through a bounded-memory sink (previously any WAL above the sink
  capacity hard-failed with nothing written, and re-running tripped
  `AppendOnlyViolation`). `BufferedWalSink::DEFAULT_CAPACITY` reserves
  the 16-byte framing overhead so a maximum-size legal record fits a
  fresh sink, and `flush` emits the stream header even for a
  record-less export — an empty WAL round-trips as a valid header-only
  stream instead of a 0-byte file the reader rejects.
- The `#[arkhe_pure]` purity gate closes four bypass routes: imported
  associated paths (`use std::time::Instant; Instant::now()`) via
  segment-aligned suffix matching, leading-colon paths
  (`::std::fs::…`) via normalisation, denied paths inside macro
  arguments (`vec!`/`format!` recursion + a denied-I/O-macro list for
  `println!`-family/`dbg!`), and `unsafe fn` signatures (edition-2021
  implicit unsafe bodies).
- The `ActionCompute` purity-coverage scanner recurses through fn-body
  items via a `syn` visitor (nested impls were invisible), with an
  exact-form `#[cfg(test)]`-module exemption; both workspace scanners
  now fail loudly on unreadable/unparseable files instead of silently
  skipping.
- `arkhe-rand` usize sampling is pointer-width independent: it routes
  through the u64 Lemire path unconditionally, so the same seed yields
  one `shuffle` permutation on 64-bit and 32-bit (wasm32) targets
  (previously values and stream consumption diverged). A golden
  52-element permutation and a usize/u64 identity test pin the
  contract; the crate's determinism docs now cite exactly the
  enforcement that exists (host golden vector, CI native-endian
  self-grep) rather than an aspirational cross-compile matrix.
- `combine_shares` validates the threshold config up front, returning
  `InvalidConfig` instead of panicking on an empty share set with
  `t = 0`.
- The L2 GDPR admission-gate integration test seeds its actor/user
  entities with explicit spawns: the kernel ledger now no-ops a
  `SetComponent` against a never-spawned entity (a v0.14 phantom-write
  hole), and the production `RegisterUser` → `GdprEraseUser` path
  already satisfies the existence precondition by spawning the user
  entity at registration.

### Security
- Secret-scrubbing hardening (the same in-memory-copy class the kernel
  0.15 release fixed): `ReceiptSigner::mldsa65_from_seed` zeroizes the
  transient `B32` seed conversion; `CryptoCoordinator` wraps decrypted
  and pre-encryption PII plaintext buffers in `Zeroizing` (including
  every per-element plaintext during `rotate_dek`); the AWS KMS
  backend wipes its stack DEK copies after `Dek` construction.
- Linux `disable_ptrace` fails closed when `/proc/self/status` is
  unreadable (hidepid/sandbox procfs): an unknown tracer state is now
  an error instead of a silent pass, preserving the documented
  "Ok ⇒ no debugger attached" guarantee.

### Performance
- `RngSource` serves draws from a 64-byte XOF block cache instead of
  recomputing a BLAKE3 output block per 4/8-byte draw — measured 5.7×
  on `gen_range`, 5.8× on a 52-card shuffle; the emitted byte stream
  is bit-identical (golden vectors unchanged).
- `StreamingWalReader` buffers its source internally (`BufReader`), so
  file-backed reads no longer pay three raw `read` syscalls per record
  (measured 43× on a 1k-record file stream).
- `wal_to_sink` reuses one encode scratch across records
  (`postcard::to_extend`) instead of allocating a fresh `Vec` per
  record — measured 3.3× on the export loop, byte-identical output.

### Licensing
Dual-licensed under MIT OR Apache-2.0.

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
