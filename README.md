# ArkheForge

**Sandboxed L1+L2 runtime substrate for [ArkheKernel](https://github.com/aceamro/ArkheKernel) — WASM hook host, KMS-tier crypto, sealed observer pipeline.**

[Changelog](CHANGELOG.md) · [License](#license)


A1 D1-Total bit-identical replay carries through from sealed L0 ArkheKernel
to the runtime boundary. 3-band determinism (Core / Projection / Protocol-
Correctness) layers on top, the Hybrid Ed25519 + ML-DSA 65 signing pipeline
is inherited from the kernel, and a WASM-sandboxed hook host with a Kani-
verified host-fn boundary makes ArkheForge a production runtime stack for
shell authors (BBS, game, social platform) building on a sealed
deterministic substrate.

## Quick start

ArkheForge composes on top of ArkheKernel — the kernel surface is your
primary API, and forge L2 features (WASM hosts, KMS backends) layer on
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

Production deployments add the forge L2 sandbox via Cargo feature flags:

| Feature                    | Adds                                                  |
| :---                       | :---                                                  |
| `tier-2-observer-host-v2`  | `WasmtimeObserverHost::with_v0_12_config()` (WASM)    |
| `tier-2-hook-host-v2`      | `WasmtimeHookHost` (WASM hook host)                   |
| `tier-1-kms`               | `argon2` + `chacha20poly1305` (Tier-1 AEAD)           |
| `tier-2-multi-kms`         | `aes-gcm` + `aes-gcm-siv` (Tier-2 AEAD)               |
| `tier-2-aws-kms`           | `aws-sdk-kms` + `aws-config` (AWS KMS backend)        |

Runnable end-to-end examples — including a 5-minute shell author tutorial
— live in [`runtime-book/`](runtime-book/) (`cd runtime-book && mdbook
serve` for local preview).

## Why ArkheForge

- **3-band determinism.** *Core* (L0 bit-identical replay, inherited from
  ArkheKernel), *Projection* (eventually consistent read models, observer
  pipeline) and *Protocol-Correctness* (shell-level compatibility
  contracts) are explicit bands with separate guarantees and separate
  verification surfaces.
- **Sandboxed hook + observer hosts.** Hook host v2 and observer host v2
  run hosted code under WASM preview-2 with capability gating, fuel
  budgets, and a Kani-verified host-fn boundary (`memory_bounds_check`
  property). External impls cannot cross the sealed seam.
- **Crypto-erasure with cryptographic shred guarantees.** HSM-generated
  DEK + envelope encryption + tombstone semantics + multi-region 2PC
  atomic shred. GDPR-aligned erasure in a deterministic-replay world.
- **Formal verification anchored.** A 5-property Kani harness suite
  lives here (`arkhe-runtime-proofs/`), six TLA+ refinement modules
  span the platform (four in sibling ArkheKernel + two here), and the
  sibling kernel CI runs Apalache typecheck on `cr1`–`cr4` every push
  (forge CI extension for `runtime_core` + `r4_implementation_refinement`
  planned post-v0.13).

## Architecture

```text
+----------------------------------------+
|  L2 platform   hook host v2 (WASM),    |  capability linker, KMS
|                observer host v2,       |  abstractions, AEAD tiers,
|                sandbox safeguards      |  AWS / multi-KMS backends
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
|                (separate repo)          |  Layer A 8 invariants
+----------------------------------------+
```

Single-direction DAG enforced by the `ImportDirectionMonotone` invariant
+ a CI grep gate (`boundary → runtime`, no reverse edges).

### Workspace

Eight crates total — 7 workspace members + 1 standalone Kani harness:

| Crate                          | Layer | Role                                       |
| :---                           | :---  | :---                                       |
| `arkhe-forge`                  | L1+L2 | Umbrella re-export for shell authors       |
| `arkhe-forge-core`             | L1    | Runtime traits, dispatch, observer pipeline|
| `arkhe-forge-platform`         | L2    | Hook host v2, observer host v2, KMS, AEAD  |
| `arkhe-forge-macros`           | L1    | Derive macros for forge components         |
| `arkhe-runtime-testkit`        | dev   | proptest harness for runtime crates        |
| `arkhe-trait-default-check`    | CI    | Sealed-trait safeguard lint                |
| `arkhe-subset-rust-check`      | CI    | `Action::compute()` determinism subset lint|
| `arkhe-runtime-proofs`         | proof | Kani 5-property harness (standalone)       |

## Determinism guarantees

- **E14 Compute Determinism Closure** — `Action::compute()` is pure in
  its declared inputs (build-time dylint + runtime sandbox dual-tier
  enforcement).
- **E13 PQC Hybrid AND-mode dispatch** — both Ed25519 and ML-DSA 65
  signatures must verify for any record signed under the Hybrid
  policy.
- **E15 Observer Capability Confinement** — observer code cannot
  affect the WAL chain hash. Sandbox traps panic before side-effects
  propagate (E15.a) and the cap-token universe is sealed via
  type-system anchors (E15.b: `HookCapTokenSealed`,
  `ObserverCapTokenSealed`).

Full E1–E15 catalog (15 distinct E-axioms across 17 enforcement slots:
12 machine-checked + 5 non-MC; `E7` and `E14` are dual-tier) →
[`runtime-book/`](runtime-book/).

## Sandbox & sealed seam

ArkheForge applies the sealed-trait pattern (`private_seal::Sealed`
bound — sibling of kernel A24 lineage) consistently across the
host-extension surface:

- `capability_linker` — bridges kernel cap mask to platform host imports
- `hook_host_v2` — sealed bound on the hosted-fn import set
- `observer_host_v2` — sealed bound on the observer cap-token universe
- `cap_token` — `HookCapTokenSealed` + `ObserverCapTokenSealed` (E15.b)
- `SealedHostImport` — host-fn wrapper that prevents external impls
  from widening the import allow-list at compile time

These five sealed seams together produce the host-import + cap-token
universe that the Kani `kani_authorize_property` and
`kani_memory_bounds_check_property` harnesses verify.

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
| Tier-2 | Multi-KMS + threshold HSM    | Multi-region, HF2 auto-promote            |

Cloud backends are independent of AEAD tiering — a deployment can mix
`tier-1-kms` AEAD with `tier-2-aws-kms` key storage. The HF2 Auto
Promote Trust Model (planned, multi-channel health-checks + threshold
HSM quorum for promoting standby key material under operator policy)
ships in a follow-up release.

## Formal verification

- **4-tier enforcement** — 12 machine-checked (TLA+ + Kani) + 3
  type-proven + 1 type-adjacent + 1 runtime-asserted = 17 enforcement
  slots for 15 distinct E-axioms (`E7` and `E14` are dual-tier). See
  [`runtime-book/`](runtime-book/) for the per-axiom breakdown. Kernel
  L0 axioms (A1–A24 + S1) are tagged across a parallel 5-tier scheme
  (25 slots); combined with forge they form 42 total enforcement
  slots.
- **TLA+ refinement (six modules across the platform)** — `cr1` chain
  hash invariant, `cr2` state-machine refinement, `cr3` replay
  determinism, and `cr4` observer capability confinement live in the
  sibling [`ArkheKernel`](https://github.com/aceamro/ArkheKernel)
  repository; `runtime_core` and `r4_implementation_refinement` live
  in [`formal/tla-plus/`](formal/tla-plus/) here.
- **Kani harness suite (5 properties)** — implementation-level proofs
  in [`arkhe-runtime-proofs/`](arkhe-runtime-proofs/):
  - `kani_authorize_property` → E6 / E7 typestate
  - `kani_dispatch_property` → E14 Compute Determinism
  - `kani_replay_property` → A1 bit-identical replay
  - `kani_memory_bounds_check_property` → E14.L2 host-fn boundary
  - `kani_hybrid_and_mode_property` → E13 Hybrid AND-mode
- **Apalache typecheck CI gate** — runs against `cr1`–`cr4` in the
  sibling ArkheKernel CI today; `runtime_core` and
  `r4_implementation_refinement` typecheck land in the forge CI
  extension planned for the post-v0.13 follow-up.
- **R4-X stratum boundary CI gate** — `boundary → runtime` single
  direction (sibling concept of kernel Layer A item 6 R4-X DAG, scoped
  to forge L1+L2 internal layering) is specified by the
  `ImportDirectionMonotone` invariant; a CI grep gate is planned for
  the same post-v0.13 follow-up.
- **Machine-readable axiom inventory** — every cited TLA+ identifier
  appears in its `tla_module` file; every cited impl test exists as
  `fn <name>` in some cited path. Catches inventory drift, not
  theorem soundness.

## Cross-repo dependency

ArkheForge depends on ArkheKernel as a sibling repository during
development:

```toml
[workspace.dependencies]
arkhe-kernel = { path = "../ArkheKernel/arkhe-kernel", version = "0.13" }
arkhe-macros = { path = "../ArkheKernel/arkhe-macros", version = "0.13" }
```

After the v0.13 publish, both kernel crates transition to `crates.io`
and the path dependency drops out of `Cargo.toml`.

## Stability

v0.13 — single fixed pre-public version, sibling-published with
ArkheKernel. No version churn before external publish; subsequent
corrections land on the same v0.13 line. Version 1.0 is intentionally
never reached.

## Documentation

- Runtime book: [`runtime-book/`](runtime-book/) (`cd runtime-book &&
  mdbook serve` for local preview)
- API reference: [docs.rs/arkhe-forge](https://docs.rs/arkhe-forge)
  (post-publish)
- Kernel architecture book (sibling): [ArkheKernel/book/](https://github.com/aceamro/ArkheKernel/tree/main/book)
- Test corpus (regression cases): [`test-corpus/`](test-corpus/)

## License

Dual-licensed under either of:

- Apache License 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License, ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same dual-license
terms.

---
*ArkheForge — a sandboxed runtime substrate for byte-identical worlds.*
