# ArkheForge

**L1+L2 runtime substrate for [ArkheKernel](https://github.com/aceamro/ArkheKernel) — KMS-tier crypto, observer pipeline.**

[Changelog](CHANGELOG.md) · [License](#license)


A1 D1-Total bit-identical replay carries through from sealed L0 ArkheKernel
to the runtime boundary. 3-band determinism (Core / Projection / Protocol-
Correctness) layers on top, and the L0 kernel's Hybrid Ed25519 + ML-DSA 65
WAL chain signing is inherited unchanged, making ArkheForge a production
runtime stack for shell authors (BBS, game, social platform) building on a
sealed deterministic substrate. Forge L2 attestation surfaces (KMS journal,
audit receipts, manifest declaration) emit Ed25519.

## Quick start

ArkheForge composes on top of ArkheKernel — the kernel surface is your
primary API, and forge L2 features (KMS backends) layer on
top via Cargo feature flags:

```rust
use arkhe_kernel::abi::{CapabilityMask, Tick};
use arkhe_kernel::{Kernel, SignatureClass};

// Boot the sealed L0 kernel with Hybrid PQC signing.
let mut kernel = Kernel::new_with_wal_signed(
    world_id,
    manifest_digest,
    SignatureClass::Hybrid { /* Ed25519 + ML-DSA 65 secrets */ },
);

// Register your domain types and observers through the kernel surface.
kernel.register_action::<MyAction>();
kernel.register_observer(Box::new(MyAuditObserver));

// Submit + step — the WAL chain extends with a Hybrid PQC-signed record
// and your observer fires post-fsync.
kernel.submit(/* ... */).unwrap();
let report = kernel.step(Tick(0), CapabilityMask::SYSTEM);
```

Production deployments add the forge L2 KMS stack via Cargo feature flags:

| Feature                    | Adds                                                  |
| :---                       | :---                                                  |
| `tier-1-kms`               | `argon2` + `chacha20poly1305` (Tier-1 AEAD)           |
| `tier-2-multi-kms`         | `aes-gcm` + `aes-gcm-siv` (Tier-2 AEAD)               |
| `tier-2-aws-kms`           | `aws-sdk-kms` + `aws-config` (AWS KMS backend)        |

A provably-fair Texas Hold'em demo lives in
[`examples/card_primitives/`](examples/card_primitives/);
`cargo run -p card-primitives` plays a single 2-player hand through nine
stages — BLAKE3 commit broadcast, Fisher-Yates shuffle (Lemire-debiased),
best-5-of-7 evaluation, chain-hash receipt, dual-path audience
verification, a `RecordHandShowdown` `ArkheAction` emitted through the
L1 `pipeline::process_action` event pipeline, the same Action dispatched
end-to-end through the L2 `RuntimeService` (`Kernel::submit` +
`Kernel::step`), the kernel's WAL exported and streamed into a
`BufferedWalSink<Vec<u8>>` for durable framing, and a
`StreamingWalReader` round-trip that recovers each record byte-identical
to the kernel's original — the consumer-side proof that "yes, the
showdown is written to a WAL file" with audit-grade integrity.

## Why ArkheForge

- **3-band determinism.** *Core* (L0 bit-identical replay, inherited from
  ArkheKernel), *Projection* (eventually consistent read models, observer
  pipeline) and *Protocol-Correctness* (shell-level compatibility
  contracts) are explicit bands with separate guarantees and separate
  verification surfaces.
- **Crypto-erasure with cryptographic shred guarantees.** HSM-generated
  DEK + envelope encryption + tombstone semantics + multi-region 2PC
  atomic shred. GDPR-aligned erasure in a deterministic-replay world.
- **Formal verification anchored.** A 4-property Kani harness suite
  lives here (`arkhe-runtime-proofs/`), six TLA+ refinement modules
  span the platform (four in sibling ArkheKernel + two here), and the
  sibling kernel CI runs Apalache typecheck on `cr1`–`cr4` every push.
- **Provably-fair RNG, casino-grade by construction.** The
  `card-primitives` example (`examples/card_primitives/`) ships a
  BLAKE3 keyed-PRF stream RNG, a Fisher-Yates shuffle that draws
  bounded integers via Lemire's debiased multiply-shift (zero
  modulo bias by construction), and a 14-test NIST SP 800-22-derived
  statistical suite that pins the GLI-19 §3.2.5 1e-9 bias bound in
  CI on every push.

## Architecture

```text
+----------------------------------------+
|  L2 platform   capability linker,      |  capability linker, KMS
|                KMS abstractions,       |  abstractions, AEAD tiers,
|                AEAD tiers              |  AWS / multi-KMS backends
+------------------^---------------------+
                   |
+------------------+---------------------+
|  L1 core       Action / Component /    |  ECS dispatch, observer
|                Event runtime traits,   |  pipeline, runtime
|                KmsBackend trait        |  signature class
+------------------^---------------------+
                   |
+------------------+---------------------+
|  L0 (sibling)  ArkheKernel deterministic|  bit-identical replay,
|                microkernel              |  Hybrid PQC chain,
|                (separate repo)          |  Layer A 7 invariants
+----------------------------------------+
```

Single-direction DAG enforced by the `ImportDirectionMonotone` invariant
+ a CI grep gate (`boundary → runtime`, no reverse edges).

### Workspace

Eleven crates total — 10 workspace members + 1 standalone Kani harness:

| Crate                          | Layer       | Role                                       |
| :---                           | :---        | :---                                       |
| `arkhe-forge`                  | L1+L2       | Umbrella re-export for shell authors       |
| `arkhe-forge-core`             | L1          | Runtime traits, dispatch, observer pipeline|
| `arkhe-forge-platform`         | L2          | Capability linker, KMS, AEAD               |
| `arkhe-forge-macros`           | L1          | Derive macros for forge components         |
| `arkhe-rand`                   | L3          | BLAKE3-keyed PRNG (no_std), shell-side use |
| `arkhe-runtime-testkit`        | dev         | proptest harness for runtime crates        |
| `arkhe-trait-default-check`    | CI          | Sealed-trait safeguard lint                |
| `arkhe-subset-rust-check`      | CI          | `Action::compute()` determinism subset lint|
| `card-primitives`              | examples/   | Provably-fair Hold'em 9-stage demo (card / deck / hand_eval / shuffle_proof / forge_integration / main + Forge L2 `RuntimeService` dispatch + WAL export + streaming round-trip) + GLI-19 §3.2.5 RNG bias compliance (Lemire via `arkhe-rand`) + NIST SP 800-22 14-test + Forge L1 `ArkheAction`/`ArkheEvent` + Forge L2 `Kernel::submit`/`step` end-to-end reference integration |
| `dice`                         | examples/   | Provably-fair 3D6 dice demo — server commit + interactive user-seed combined PRF + arkhe-rand `RngSource` + Forge L1+L2 dispatch + `BufferedWalSink` persistence with chronological multi-run history (`dice.wal` rewritten each launch, top-5 display) + `--reset`/`--verify` CLI |
| `arkhe-runtime-proofs`         | proof       | Kani 4-property harness (standalone)       |

## Determinism guarantees

- **E14 Compute Determinism Closure** — `Action::compute()` is pure in
  its declared inputs (build-time deny-list enforcement on the
  clock / RNG / I/O / FFI surface).
- **E13 PQC Hybrid AND-mode dispatch** — both Ed25519 and ML-DSA 65
  signatures must verify for any record signed under the Hybrid
  policy.

Full E1–E14 catalog (14 distinct E-axioms across 16 enforcement slots:
11 machine-checked + 5 non-MC; `E7` is dual-tier) lives in
the source rustdoc — see
[`arkhe-runtime-proofs`](arkhe-runtime-proofs/) for the per-axiom Kani
proofs and the `E*` cites under
[`arkhe-forge-core`](arkhe-forge-core/).

## Crypto stack

Inherited from ArkheKernel (4 supply-chain-reviewed crates:
`ed25519-dalek`, `ml-dsa`, `blake3`, `postcard` — see
[ArkheKernel README](https://github.com/aceamro/ArkheKernel#crypto-stack-supply-chain-reviewed)).

Forge-specific (KMS / envelope / hash-key derivation, supply-chain
reviewed):

| Crate              | Role                                                  |
| :---               | :---                                                  |
| `argon2`           | Password hashing for KMS user salt derivation         |
| `chacha20poly1305` | XChaCha20-Poly1305 envelope (Tier-0 default AEAD)     |
| `aes-gcm`          | AES-GCM AEAD (Tier-1+)                                |
| `aes-gcm-siv`      | AES-GCM-SIV nonce-misuse-resistant (Tier-2)           |

## Compliance tiers

| Tier   | KMS                          | Use case                                  |
| :---   | :---                         | :---                                      |
| Tier-0 | software-KEK                 | Dev / single-host (default features)      |
| Tier-1 | KMS free-tier                | Managed cloud KMS, single region          |
| Tier-2 | Multi-KMS + threshold HSM    | Multi-region, auto-promote                |

Cloud backends are independent of AEAD tiering — a deployment can mix
`tier-1-kms` AEAD with `tier-2-aws-kms` key storage. The Auto Promote
Trust Model design (multi-channel health-checks + threshold HSM
quorum for promoting standby key material under operator policy) is
sketched in `arkhe-forge-platform::hf2_kms`.

## Formal verification

- **4-tier enforcement** — 11 machine-checked (TLA+ + Kani) + 3
  type-proven + 1 type-adjacent + 1 runtime-asserted = 16 enforcement
  slots for 14 distinct E-axioms (`E7` is dual-tier). See
  the source rustdoc in
  [`arkhe-runtime-proofs`](arkhe-runtime-proofs/) for the per-axiom
  Kani breakdown. Kernel
  L0 axioms (A1–A24 + S1) are tagged across a parallel 5-tier scheme
  (25 slots); combined with forge they form 41 total enforcement
  slots.
- **TLA+ refinement (six modules across the platform)** — `cr1` chain
  hash invariant, `cr2` state-machine refinement, `cr3` replay
  determinism, and `cr4` observer capability confinement live in the
  sibling [`ArkheKernel`](https://github.com/aceamro/ArkheKernel)
  repository; `runtime_core` and `r4_implementation_refinement` live
  in [`formal/tla-plus/`](formal/tla-plus/) here.
- **Kani harness suite (4 properties)** — implementation-level proofs
  in [`arkhe-runtime-proofs/`](arkhe-runtime-proofs/):
  - `kani_authorize_property` → E6 / E7 typestate
  - `kani_dispatch_property` → E14 Compute Determinism
  - `kani_replay_property` → A1 bit-identical replay
  - `kani_hybrid_and_mode_property` → E13 Hybrid AND-mode
- **Apalache typecheck CI gate** — `cr1`–`cr4` are typechecked on
  every push by the sibling ArkheKernel CI.
- **Stratum boundary invariant** — `boundary → runtime` single
  direction (forge L1+L2 internal layering) is specified by the
  `ImportDirectionMonotone` invariant in
  `formal/tla-plus/r4_implementation_refinement.tla`.
- **Machine-readable axiom inventory** — every cited TLA+ identifier
  appears in its `tla_module` file; every cited impl test exists as
  `fn <name>` in some cited path. Catches inventory drift, not
  theorem soundness.

## Kernel dependency

ArkheForge depends on the published [`arkhe-kernel`](https://crates.io/crates/arkhe-kernel)
and [`arkhe-macros`](https://crates.io/crates/arkhe-macros) crates from
crates.io:

```toml
[workspace.dependencies]
arkhe-kernel = "0.14"
arkhe-macros = "0.14"
```

No sibling repository checkout is required to build forge — `cargo build`
fetches both kernel crates from crates.io directly.

## Stability

v0.14 tracks the ArkheKernel v0.14 epoch (`ml-dsa` 0.1.1 / NIST FIPS 204
final). A new minor epoch is cut only on a substantive trigger; there is
no churn between epochs. Version 1.0 is intentionally never reached
(parity with ArkheKernel).

## Documentation

- Kernel architecture book (sibling): [ArkheKernel/book/](https://github.com/aceamro/ArkheKernel/tree/main/book)

## License

Dual-licensed under either of:

- Apache License 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License, ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same dual-license
terms.

---
*ArkheForge — a deterministic runtime substrate for byte-identical worlds.*
