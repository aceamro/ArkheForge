# Security policy

ArkheForge is the L1+L2 runtime substrate built on top of the
`ArkheKernel` deterministic L0 microkernel. Cryptographic surfaces
exposed by this repository include the L2 `RuntimeService` dispatch
loop (kernel-bound `submit` → `step` → WAL append), the multi-tier
KMS / AEAD stack (Tier-1 ChaCha20-Poly1305 + Argon2, Tier-2 AES-GCM /
AES-GCM-SIV + cloud-KMS backends), the wasmtime-sandboxed hook host v2
+ observer host v2, the BLAKE3 commit-reveal patterns used by example
crates, and the audit-receipt + projection observer pipeline. Forge L2
attestation surfaces emit Ed25519; the WAL chain itself inherits the
kernel's Hybrid Ed25519 + ML-DSA 65 signing path. Vulnerabilities
affecting any of these surfaces — or the engineering invariants
(layer-DAG single-direction, sealed-trait surface, append-only WAL,
capability gating) that depend on them — are treated as security
issues.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to:

- **Email**: aceamro@gmail.com

Encrypt sensitive payloads if you have a public key for the maintainer;
an unencrypted initial contact requesting a key is also acceptable.

Please include:

1. The affected version (commit hash or crates.io version) and target
   triple.
2. A minimal reproduction (test, snippet, or repro project).
3. The observed vs. expected behaviour, and the security impact you
   believe applies (e.g., sandbox escape, capability bypass, KMS-tier
   AEAD downgrade, WAL chain-integrity break, sealed-trait escape,
   replay-determinism break, signature forgery, denial-of-service
   vector).
4. Optional: a suggested remediation or patch.

Please **do not** open a public GitHub issue, pull request, or
discussion thread for an unfixed vulnerability. Public reports that
name a concrete bypass or chain-integrity defect will be triaged the
same as private reports, but the disclosure window below no longer
applies.

## Response expectations

- **Acknowledgement**: within 5 business days.
- **Triage**: within 14 days the report is either confirmed, declined,
  or marked needing-more-info.
- **Fix window**: depends on severity and surface. Security-critical
  defects in a forge-sealed surface (wasmtime hook-host capability
  bypass; KMS-tier AEAD downgrade; WAL chain-integrity break;
  sealed-trait escape on `ArkheAction` / `ArkheEvent`; replay
  non-determinism; signature forgery on Forge L2 attestations; or
  any RUSTSEC advisory hitting the supply chain) are prioritised over
  functional bugs. Coordinated public disclosure is agreed with the
  reporter once a fix is ready.

## Scope

In-scope:

- `arkhe-forge` (umbrella facade re-exporting the L1 + L2 surface).
- `arkhe-forge-core` (L1 primitives — `ActionContext`,
  `ArkheAction` / `ArkheEvent` sealed traits, `process_action`
  pipeline).
- `arkhe-forge-platform` (L2 services — `RuntimeService` dispatcher,
  hook host v2, observer host v2, KMS / AEAD tiers, `wal_export`
  reader+writer, manifest loader, projection observer, dedup,
  process-protection shim).
- `arkhe-forge-macros` (forge derive helper crate).
- `arkhe-rand` (L3 BLAKE3-keyed PRNG library, `RngSource::from_seed`
  + Lemire-unbiased `gen_range_inclusive` + Fisher-Yates `shuffle`).
- `arkhe-runtime-testkit` (proptest harness for runtime crates).
- `arkhe-runtime-proofs` (standalone Kani 5-property harness).
- `arkhe-trait-default-check` / `arkhe-subset-rust-check` (CI lint
  helpers).
- The `examples/` workspace members (`card-primitives`, `dice`).
- The CI gates that protect the seals (workflow-3 9-step,
  workspace-level `cargo deny`, `cargo clippy` workspace lints,
  `cargo fmt`).

Out of scope (please report to the relevant repository):

- ArkheKernel L0 surface — sibling repository, owns its own
  `SECURITY.md`.
- Domain shells (BBS, casino front-ends, etc.) consuming ArkheForge —
  those repositories carry their own security policies.

## Versioning

ArkheForge ships under a single fixed version (currently v0.13).
Security fixes land on the published version; downstream consumers
pinning the exact version should re-pull after a security release. The
version is intentionally not bumped for routine fixes — see
`CHANGELOG.md` for the release narrative. Version 1.0 is intentionally
never reached (versioning policy parity with ArkheKernel).

## Cryptographic acknowledgements

Cryptographic primitives used by the runtime substrate:

- **BLAKE3** (`blake3`) — commit-reveal hashes and per-record
  chain-hash anchors in the example crates; KDF mode for
  `arkhe-rand::RngSource` (context string `"arkhe-rand stream v0.13"`,
  version-pinned for stream determinism).
- **Ed25519** (`ed25519-dalek`) — Forge L2 attestation surfaces (KMS
  journal, audit receipts).
- **ChaCha20-Poly1305** (`chacha20poly1305`) — Tier-1 KMS AEAD.
- **AES-GCM** (`aes-gcm`) and **AES-GCM-SIV** (`aes-gcm-siv`) —
  Tier-2 multi-KMS AEAD.
- **Argon2** (`argon2`) — Tier-1 KMS KDF.
- **getrandom** (`getrandom`) — OS CSPRNG entry point used by
  `RngSource::from_os_entropy` and the `dice` example's per-run server
  seed.
- **rustls 0.23** (modern HTTPS chain via the AWS SDK
  `default-https-client` feature; the legacy rustls 0.21 + webpki
  0.101 chain affected by RUSTSEC-2026-0098 and RUSTSEC-2026-0099 is
  explicitly excluded — see `arkhe-forge-platform/Cargo.toml`).
- **Hybrid Ed25519 + ML-DSA 65** — inherited transitively via
  `arkhe-kernel = "0.13"`; the kernel performs the dual-sign
  verification on the WAL chain. ArkheForge L2 itself does not
  directly depend on `ml-dsa` (the ML-DSA crate is at `0.1.0-rc.9`
  and unstable; forge will adopt direct dependence once it
  stabilises, in lockstep with the kernel — see
  `developteamset.md` for the ml-dsa stabilisation carry).

Reports about these crates' upstream defects belong with the upstream
maintainers; reports about how ArkheForge uses them belong here.
