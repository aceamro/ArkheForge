# AGENTS.md — ArkheForge

> **What this is:** an orientation map for AI agents (and new humans) working in this repo.
> It is the entry point: read it before reading code, and **read §3 before editing anything**.

ArkheForge is the **L1 + L2 runtime** that sits **on top of the ArkheKernel L0 microkernel**
(a published crates.io dependency, `arkhe-kernel = "0.15"`). It turns the kernel's bare
deterministic state machine into an application substrate: five domain primitives, a purity
gate that keeps every action replay-deterministic, an envelope-encryption / KMS / GDPR
crypto-erasure stack, WAL streaming export, attestation verification, and read-model
projection. ~26,000 lines of Rust across 11 crates.

This file is **navigation metadata only** — it lives outside the source on purpose. It does
not change any behavior.

> ArkheForge does **not** contain the kernel. L0 lives in the separate **ArkheKernel** repo
> (with its own `AGENTS.md`). The Shell layer (BBS, end-user apps) is **yet another** repo.
> Layer independence is a hard directive — see §2.

---

## 0. How to use this file (agent prime directive)

> **In one line:** the kernel boundary is §2, the editing-hazard rules are §3, the commit gates are §6.

1. **Orient** — §1 (what it is) + §2 (the layer model and the kernel boundary you must not cross).
2. **Locate** — §4 (crate → role map) to find where a thing lives.
3. **Before editing** — §3 (DO NOT TOUCH). The determinism + crypto + wire-format surfaces here
   are gated; an innocent edit can break replay, a CI gate, or a security property.
4. **Understand the flow** — §5 traces one action from a `#[derive]` to a projected read-model,
   and shows how to write your own.
5. **Before committing** — run the §6 gates. CI runs the same ones.
6. **Stuck on a word?** — §7 is a glossary (~70 project terms).

**Two disciplines that define this codebase:**
- **Purity (E14.L1).** Every `ActionCompute::compute` body is marked `#[arkhe_pure]` and is
  checked at compile time to contain **no clock, no RNG, no I/O, no FFI, no `unsafe`**. This is
  what makes actions replay bit-identically. Breaking it breaks the whole guarantee.
- **`unsafe` is forbidden** in every crate (`#![forbid(unsafe_code)]`) **except
  `arkhe-forge-platform`**, which uses `unsafe` only inside `process_protection/` for OS
  syscalls (`mlockall`/`prctl`/`ptrace`/`setrlimit`/Win32). That is the one deliberate exception.

---

## 1. What ArkheForge is

> **In one line:** an application substrate on the kernel — 5 domain primitives, a purity gate, KMS/crypto-erasure, and WAL export/verify/projection.

- **L1 domain core** (`arkhe-forge-core`) — five primitives: **User, Actor, Space, Entry,
  Activity** — built from sealed traits, pure compute, and deterministic entity-id derivation.
- **L2 platform** (`arkhe-forge-platform`) — the service layer: dispatch onto the kernel,
  envelope encryption + KMS, GDPR crypto-erasure, WAL streaming export, attestation
  verification, read-model projection, idempotency dedup, process hardening.
- **Determinism inherited from L0.** The kernel's A1 bit-identical replay flows up unchanged.
  Forge adds the **E-axioms (E1–E14)**, the runtime-level invariants — most importantly **E14**
  (compute-determinism closure) and **E13** (Hybrid Ed25519 + ML-DSA 65 signature policy).
- **Provably-fair examples.** `examples/card_primitives` (Texas Hold'em commit-reveal shuffle)
  and `examples/dice` (3D6) demonstrate the full stack end-to-end.

---

## 2. Layer model & the kernel boundary

> **In one line:** L0←L1←L2←L3 one-way; forge sits *on* the kernel and must never re-implement WAL append, authorization, or the `Effect` typestate.

```text
L0  ArkheKernel        (separate repo, crates.io: arkhe-kernel 0.15)  ← sealed microkernel
        ▲
L1  arkhe-forge-core + arkhe-forge-macros        primitives, sealed traits, pure compute
        ▲
L2  arkhe-forge-platform                          KMS / AEAD / dispatch / projection / verify
        ▲
L3  arkhe-rand                                    BLAKE3-keyed PRNG — SHELL-SIDE ONLY
        ▲
L4-L6  Shell (BBS, apps)                           separate repo(s)
```

Dependencies flow **strictly downward**. The `ImportDirectionMonotone` TLA+ invariant + a CI
grep gate forbid reverse edges. `arkhe-forge-core` (L1) must **not** depend on
`arkhe-forge-platform` (L2). Shell crates depend on the **`arkhe-forge`** umbrella, never on
`*-core`/`*-platform` directly (version + feature coherence).

**The kernel boundary — what forge consumes and must never re-implement:**

- **Consumes from `arkhe-kernel`:** `Kernel`, `InstanceView`, `StepReport`, `Wal`/`WalRecord`,
  the kernel-side `Action`/`ActionDeriv`/`ActionCompute` traits, `Op`, and the ABI types
  (`CapabilityMask`, `Principal`, `Tick`, `TypeCode`, `InstanceId`, `EntityId`, `ArkheError`).
- **Never re-implement (L0-only):** WAL append, authorization dispatch, the `Effect<'i>`
  typestate. Forge bridges **over** them — `#[derive(ArkheAction)]` emits a kernel-side
  `ActionCompute` that calls `bridge::kernel_compute`, which rebuilds an L1 context, runs the
  forge `compute()`, and returns the drained `Vec<Op>` to the kernel. The kernel then
  re-authorizes each `Op` and appends to its WAL internally.
- **Kernel internals NOT exposed to forge:** `Instance::world_seed` (forge bridge hardcodes a
  `[0u8; 32]` placeholder today), the `Effect<'i, Authorized>` brand, and the kernel's
  `pub(crate)` PQC WAL signers (forge uses the `ml-dsa` crate directly for L2 audit receipts —
  a **separate** signature domain from the kernel's WAL signature).

---

## 3. ⛔ DO NOT TOUCH — editing hazards (READ BEFORE ANY EDIT)

> **In one line:** the determinism, wire-format, and crypto surfaces here are gated — an innocent edit breaks replay, a gate, or a security property.

### 3.1 The L0 boundary
Do **not** edit anything that belongs to the kernel. `arkhe-kernel`/`arkhe-macros` are
**published dependencies** pinned at `"0.15"` in `Cargo.toml`; their source is not in this repo.
Never vendor, patch, or shadow them. A breaking need = a new kernel epoch, not a local edit.
(`arkhe-runtime-proofs` spells this out as a "Layer A non-touch invariant.")

### 3.2 Purity / Subset-Rust gate (the discipline that makes replay work)
- **Why it exists:** a `compute` body runs again during replay; if it could read the clock,
  draw randomness, or touch I/O, a second run could diverge and break A1 bit-identical replay.
  So those are banned by construction.
- Every `ActionCompute::compute` body **must** carry `#[arkhe_pure]`
  (`arkhe-forge-macros/src/lib.rs:283-309`). A coverage test
  (`arkhe-trait-default-check/tests/action_compute_coverage.rs`) fails the build if any impl
  lacks it — you cannot silently neuter the gate.
- `#[arkhe_pure]` runs `arkhe-subset-rust-check` (`src/lib.rs:86-151`), an AST visitor that
  rejects **clock** (`std::time::*`, `chrono`, `minstant`, `quanta`, …), **RNG** (`rand::*`,
  `getrandom::*`, `rdrand`), **I/O** (`std::fs`/`net`/`process`/`env`, `tokio::*`,
  `async_std::*`, `mio`, `socket2`), **FFI** (`libc`), and **`unsafe` blocks**.
- Need a "time-like" value? Use the immutable `tick`/nonce fields from `ActionContext`. Need
  randomness? Derive it deterministically (seeded `ChaCha20Rng`/BLAKE3). Do **not** widen the
  deny-list without a spec amendment. Seeded RNGs (`rand_chacha::ChaCha20Rng::seed_from_u64`)
  and deterministic crypto (`blake3::hash`) are the only intentional exceptions.

### 3.3 Byte-identity / wire-stability surfaces
| Surface | Where | Why frozen |
| --- | --- | --- |
| **DO NOT TOUCH #7** — kernel `WalRecord` postcard layout (kind-discriminated `Submit`/`Step` content, frozen per-variant field order; seq read via `WalRecord::seq()`) | inherited from L0; bridged in `dispatcher.rs` (`wal_to_sink`), sentinel `wal_export/round_trip_tests.rs::walrecord_seq_contract_bridge` | `wal_to_sink` streams record bytes **unmodified**; any reorder breaks bit-exact export |
| WAL export framing | `wal_export/mod.rs` | magic `ARKHEXP1` (`STREAM_HEADER_MAGIC`), `u64` BE length prefix, `MAX_RECORD_BYTES = 1<<24` (16 MiB) |
| `wal_export` wire-stability tests | `wal_export/wire_stability.rs:59-200` | pin the record-section-bit-exact + golden header pattern |
| Derive canonical bytes (Layer A item 3) | `arkhe-forge-macros` emission; pinned by byte-identity fixture tests | a derive-emission change (field reorder, postcard config) can break A1 replay |
| `BoundedString<N>` capacity | `arkhe-forge-core/src/component.rs:37-133` | expanding `N` requires a `SCHEMA_VERSION` bump |
| TypeCode ranges | `arkhe-forge-core/src/typecode.rs` | Component `0x0003_0000..=0x0003_0EFF`, Action `0x0001_0000..=0x0001_FFFF`, Event `0x0003_0F00..=0x0003_FFFF`, CanonicalVerb `0x0002_0001..=0x0002_03FF`, ShellVerb `0x0002_0400..`, shell ext `0x0100_0000..=0xEFFF_FFFF` — enforced at derive time |
| Golden RNG vector | `arkhe-rand/tests/golden/proof_rng_canonical_seq_v1.bin` (4 KiB, seed `[0u8;32]`) | byte-compared on x86_64 / aarch64 / wasm32; the `KDF_CONTEXT = "arkhe-rand stream"` and little-endian pinning must not change |

### 3.4 Sealed traits & typestate
- `ArkheComponent` / `ArkheAction` / `ArkheEvent` are sealed via
  `arkhe-forge-core/src/sealed.rs` (`__Sealed`). Only `#[derive(...)]` may implement them —
  never hand-write an impl.
- `Actor<'s, S>` uses a sealed **typestate** (`Anonymous`/`Authenticated`/`Suspended`,
  `actor.rs:56-93`); transitions consume `self`.
- **`ShellBrand<'s>`** (`brand.rs:22-64`) is an invariant lifetime (`PhantomData<fn(&'s ()) ->
  &'s ()>`) that prevents cross-shell leakage at compile time. Don't relax it to make code
  compile.
- Sealed `PiiType` codes (`pii.rs`, `0x0001..=0x00FF`) are folded into the AEAD AAD — they are
  a security boundary, not labels.

### 3.5 Crypto correctness (security-critical — review-gated)
- **AEAD nonce discipline** (`crypto.rs`): a long-lived (KMS-unwrapped) DEK is admitted only
  under AES-256-GCM-**SIV** (its per-reconstruction counter reset would repeat plain-GCM
  nonces). The monotonic DEK counter guards reuse.
- **Crypto-erasure** (`crypto_erasure.rs`): GDPR right-to-erasure is *shred DEK → tombstone PII
  → emit attestation*, two-phase and idempotent. `dek_shred_message` layout
  (`verifier.rs`, `[16B dek_id ‖ 8B log_index BE]`) is frozen by a test.
- **Threshold** (`hf2_kms/threshold.rs`): Shamir t-of-n over GF(2^8); shares have **no**
  per-share integrity (caller detects tampering via the journal's `token_hash`).
- **Journal** (`hf2_kms/journal.rs`): Ed25519 chain-signed under its own domain
  (`arkhe-runtime-doctor-journal-chain`); canonical `ConsumedToken` bytes are a fixed 48-byte
  layout.
- **Attestation domain separation** (`verifier.rs`): `FORGE_RECEIPT_SIG_DOMAIN` is **distinct**
  from the kernel WAL signature domain; Hybrid verify is **AND-mode** (both must pass).
- **E13 policy pinning** (`manifest.rs`): `audit.signature_class` comes **only** from the
  manifest, never from the wire — this defeats signature-class downgrade.

### 3.6 Formal-proof harnesses (do not edit casually)
`arkhe-runtime-proofs/src/lib.rs` holds **4 Kani properties** —
`kani_authorize_property` (E6/E7), `kani_dispatch_property` (E14),
`kani_replay_property` (A1), `kani_hybrid_and_mode_property` (E13). Bodies, abstract models,
property statements, and `#[kani::unwind(8)]` bounds are review-gated (a theorist signs off).
The crate is **excluded from the workspace** and runs standalone via `cargo kani` on a pinned
nightly (`nightly-2025-11-21`, Kani 0.67.0). Likewise, don't weaken the deny-lists or coverage
tests in `arkhe-subset-rust-check` / `arkhe-trait-default-check`.

### 3.7 `unsafe`
`#![forbid(unsafe_code)]` holds in every crate **except `arkhe-forge-platform`**, where the
only `unsafe` lives in `process_protection/{linux,macos,windows}.rs` for OS hardening
syscalls. Do not introduce `unsafe` elsewhere.

---

## 4. Crate → role map (11 crates)

> **In one line:** find which crate/file owns a thing before you grep.

| Crate | Layer | Role |
| --- | --- | --- |
| `arkhe-forge-core` | L1 | domain primitives, sealed traits, pure compute, kernel bridge |
| `arkhe-forge-macros` | L1 | `#[derive(ArkheComponent/ArkheAction/ArkheEvent)]` + `#[arkhe_pure]` |
| `arkhe-subset-rust-check` | L1 support | the `#[arkhe_pure]` AST purity checker (E14.L1 deny-list) |
| `arkhe-forge-platform` | L2 | dispatch, KMS/AEAD, crypto-erasure, WAL export, verify, projection, process hardening |
| `arkhe-rand` | L3 | BLAKE3-keyed deterministic PRNG — **shell-side only** (`no_std`) |
| `arkhe-forge` | L1+L2 | umbrella facade; the single dependency shell authors should use |
| `arkhe-runtime-proofs` | proof | standalone Kani 4-property harness (excluded from workspace) |
| `arkhe-trait-default-check` | CI support | default-impl-body BLAKE3 fingerprint + `#[arkhe_pure]` coverage test |
| `arkhe-runtime-testkit` | dev | proptest `Arbitrary` strategies + scope-based shrinker |
| `examples/card_primitives` | example | provably-fair Texas Hold'em (9-stage commit-reveal) |
| `examples/dice` | example | provably-fair 3D6 dice (commit-reveal, WAL persist + replay) |

**Dependency rules:** shell/app authors depend on **only** `arkhe-forge` (the umbrella). The
`arkhe-subset-rust-check` / `arkhe-trait-default-check` / `arkhe-runtime-testkit` crates are
tooling and the `*-proofs` crate is a standalone proof harness — **never** production deps. The
examples depend on `-core`/`-platform` directly for teaching clarity only.

### `arkhe-forge-core/src/` (L1 domain — 16 files)
| File | Role |
| --- | --- |
| `lib.rs` | crate root + `derive_entity_id` (BLAKE3-keyed, deterministic per instance/type/tick/seq) |
| `sealed.rs` | `__Sealed` convention seal for the derive macros |
| `action.rs` | sealed `ArkheAction` + `ActionCompute` + `Band` (determinism class 1/2/3) |
| `component.rs` | sealed `ArkheComponent` + `BoundedString<N>` |
| `event.rs` | sealed `ArkheEvent` + core event catalog (`RuntimeBootstrap`, `UserErasure*`, `Attestation`, forward-looking define-only events) |
| `context.rs` | `ActionContext` — `next_id`, `emit_event`, `set_component`, `read`/`staged_read`, `ensure_actor_eligible` |
| `bridge.rs` | **L0↔forge bridge**: `kernel_compute` rebuilds context, runs compute, drains `Vec<Op>` |
| `pipeline.rs` | `process_action` — the L1 event-only compute surface |
| `brand.rs` | `ShellBrand<'s>` / `ShellId` — invariant-lifetime shell isolation |
| `typecode.rs` | TypeCode allocation ranges (core / shell / debug) |
| `user.rs` | `User` primitive + GDPR lifecycle (`UserGdprState`) + `AuthCredential` (KDF output, no raw password) |
| `actor.rs` | `Actor<'s, S>` typestate + `ActorProfile` + `UserBinding` |
| `space.rs` | `Space` container + parent-chain depth cache (cycle-free) |
| `entry.rs` | `Entry` content + relay/reply graph + body-hash |
| `activity.rs` | `Activity` (actor→target verb) + idempotency keying + self-loop rejection |
| `pii.rs` | PII wire format, AEAD AAD composition (19 bytes), `UserSalt` (zeroize), DEK message counter |

### `arkhe-forge-platform/src/` (L2 — selected)
| File | Role |
| --- | --- |
| `lib.rs` | crate root; `PLATFORM_SEMVER`; module exports |
| `dispatcher.rs` | `RuntimeService` — wraps `Kernel`, the C3 GDPR admission gate, `register_action`/`dispatch`/`export_wal` |
| `crypto.rs` | `CryptoCoordinator` + `Dek` lifecycle; AEAD (XChaCha20-Poly1305 / AES-GCM / AES-GCM-SIV) |
| `crypto_erasure.rs` | GDPR right-to-erasure cascade + DEK shredder + signed attestations |
| `hf2_kms/` | KMS abstraction: `kms_backend.rs` (trait + mock), `aws_kms.rs`, `threshold.rs` (Shamir), `journal.rs` (Ed25519 chain), `health.rs` (N-of-M quorum) |
| `verifier.rs` | `verify_attestation` — domain-separated receipt verification, Hybrid AND-mode |
| `projection.rs` | `ProjectionRouter` + `Projection` trait + active/passive/draining HA |
| `manifest.rs` | `ManifestLoader` — TOML policy anchor, canonical BLAKE3 digest, E13 pinning |
| `dedup.rs` | `IdempotencyIndex` (in-memory + PG-UNIQUE-INDEX production path) |
| `wal_export/` | `mod.rs` (contract), `buffered_sink.rs` (sole append-only write path), `reader.rs` (5 fail-secure reject paths), `wire_stability.rs`, `round_trip_tests.rs` |
| `process_protection/` | `mod.rs` trait + `linux.rs`/`macos.rs`/`windows.rs`/`fallback.rs` — **the only `unsafe` in the workspace** |

---

## 5. Action lifecycle (define → projected read-model)

> **In one line:** one action's path from a `#[derive]` to a projected read-model.

| # | Step | Where |
| --- | --- | --- |
| 1 | `#[derive(ArkheAction)]` emits forge-side **and** kernel-side `ActionCompute` (delegating to `bridge::kernel_compute`) | `arkhe-forge-macros/src/lib.rs:119-198` |
| 2 | `#[arkhe_pure]` scans the compute body for clock/RNG/I/O/FFI/`unsafe` → `compile_error!` on violation | `arkhe-forge-macros/src/lib.rs:283-309` |
| 3 | `RuntimeService::register_action::<A>()` registers the action with the kernel | `dispatcher.rs:117-119` |
| 4 | `RuntimeService::dispatch()` runs the **C3 GDPR `ErasurePending` admission gate** on the authenticated actor, postcard-encodes the action, calls `kernel.submit` (actor threaded through, `caps` as the submission ceiling), then `kernel.step` (`caps` as the session ceiling) | `dispatcher.rs` |
| 5 | the kernel appends a WAL `Submit` record at admission and a `Step` record (verdict + post-state digest) per pop — one dispatch = a Submit + Step pair; authority = `effective_caps(default_caps, principal, ceiling)` ∩ session ceiling, no `System` bypass | `arkhe-kernel 0.15` |
| 6 | the kernel-side compute calls `bridge::kernel_compute`, which rebuilds an L1 `ActionContext`, runs the user `compute()`, drains `Vec<Op>` back to the kernel | `arkhe-forge-core/src/bridge.rs:105-149` |
| 7 | `RuntimeService::export_wal` + `wal_to_sink` frame each **unmodified** `WalRecord` (`ARKHEXP1` magic + `u64` BE length prefix) | `dispatcher.rs:237-265`, `wal_export/mod.rs` |
| 8 | wire-stability tests assert the record section is bit-exact (DO NOT TOUCH #7) | `wal_export/wire_stability.rs:59-200` |
| 9 | `verify_attestation` checks audit receipts under the policy-pinned class (Hybrid = AND-mode) | `verifier.rs:89-147` |
| 10 | `ProjectionRouter` routes `EventRecord`s by TypeCode into denormalized read-models | `projection.rs` |

Run it end-to-end: `cargo run -p card_primitives` or `cargo run -p dice` (the dice example also
has `--reset` and `--verify` modes that prove WAL replay byte-equality).

### Adding your own Action

See `examples/dice/src/action.rs` for a complete, working version. The shape:

```rust
use arkhe_forge_core::{arkhe_pure, ArkheAction};
// also in scope: ActionCompute, ActionContext, ActionError (see the example for exact imports)
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0001, schema_version = 1, band = 1)]  // Action range; band=1 = bit-identical replay
struct Greet {
    pub schema_version: u16,   // MUST be the first field, type u16
    pub who: String,
}

impl ActionCompute for Greet {
    #[arkhe_pure]              // REQUIRED — the purity gate + a coverage test enforce it
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // pure only: no clock/RNG/I/O. Emit events/ops via ctx.
        Ok(())
    }
}

// L2 dispatch:
let mut svc = RuntimeService::new(world_id, manifest_digest);
svc.register_action::<Greet>();
svc.dispatch(
    instance, Principal::System, &Greet { schema_version: 1, who: "world".into() },
    Tick(0), CapabilityMask::SYSTEM, /* authenticated_actor */ None,
)?;
```

`type_code`/`band`/`schema_version` are byte-identity surfaces (§3.3): keep `type_code` in the
Action range, `band = 1` for anything that must replay identically, and `schema_version` as the
first field. Pick a fresh `type_code`; never change a published one.

---

## 6. ✅ Verify before you commit

> **In one line:** run the CI gates (and the Kani proofs) the same way CI does.

CI (`.github/workflows/ci.yml`) enforces:

```bash
# test job — workspace tests; the count must match the baseline (default=538 / all-features=597)
cargo test --workspace
#   (ci/test-baselines.txt; drift fails CI — adding tests is fine, but justify the delta)

# lint job
cargo fmt --check
cargo clippy --workspace --all-features --all-targets -- -D warnings   # denies unwrap/expect/panic/todo/unimplemented/dbg
cargo doc   --workspace --no-deps --all-features                        # rustdoc warnings denied
bash scripts/verify-axiom-cite.sh   # axiom inventory ↔ TLA+ INV ↔ impl test (1:1)
```

`verify-axiom-cite.sh` resolves cross-repo cites against a **sibling `../ArkheKernel`
checkout**; without it, sibling-only entries are skipped (exit 0) — CI checks out the sibling.

**Compliance-tier features** (these are *required build flags* per deployment tier, not optional
extras — the default build is dev-only Tier-0):

```bash
# enable on the arkhe-forge umbrella (it proxies the first three to the platform crate):
cargo build -p arkhe-forge --features tier-1-kms       # Argon2 + XChaCha20-Poly1305 (free-tier KMS)
cargo build -p arkhe-forge --features tier-2-multi-kms # + AES-GCM / AES-GCM-SIV (production AEAD)
cargo build -p arkhe-forge --features tier-2-aws-kms   # + AWS KMS backend (aws-sdk-kms + tokio)
# platform-crate-only (not re-exported by the umbrella):
cargo build -p arkhe-forge-platform --features tier-2-pqc-receipts  # ML-DSA-65 audit-receipt signing
```

The `all-features` test count (597) covers all tiers; `default` is 538.

**Formal proofs (separate, heavier).** The 4-property Kani harness is its own crate (excluded
from the workspace) on a pinned nightly:

```bash
rustup toolchain install nightly-2025-11-21
cargo install --locked kani-verifier            # one-time
cd arkhe-runtime-proofs && cargo kani           # ~35 min; optional locally, mandatory in CI
```

A failing property names the violated invariant (e.g. `kani_authorize_property` → E6/E7
typestate). Dependency policy is in `deny.toml` (crates.io only, no git deps, dual MIT/Apache,
CVE deny).

---

## 7. Glossary (~70 terms)

> **In one line:** one-line definitions for the project's terms — the #1 thing a newcomer gets stuck on.

**Layers & boundary**
- **L0 / L1 / L2 / L3** — Kernel (separate repo) / domain core / platform services / library (`arkhe-rand`). Shell is L4-L6 (separate repo).
- **Layer independence** — strict downward dependency; reverse edges fail the `ImportDirectionMonotone` invariant + CI grep gate.
- **Kernel boundary** — forge consumes the kernel; it never re-implements WAL append, authorization, or the `Effect<'i>` typestate.
- **Bridge** — `bridge::kernel_compute`: the kernel-side `ActionCompute` (emitted by derive) that rebuilds an L1 context and runs forge `compute()`.
- **Umbrella (`arkhe-forge`)** — the single facade crate shell authors depend on (version + feature coherence).
- **InstanceView** — the kernel's read-only borrowed view into entity/component state; forge uses it for the C3 eligibility probe before dispatch.

**Determinism & axioms**
- **E-axioms (E1–E14)** — runtime invariants layered on the kernel's A-axioms. Inventory in `formal/axiom-test-cite.toml`.
- **E14 Compute Determinism Closure** — two parts: **E14.L1** (build-time AST deny-list via `#[arkhe_pure]`) + **E14.L2** (runtime chain-hash determinism / canonical bytes).
- **E13** — `audit.signature_class` is policy-pinned (never wire-sourced); Hybrid is sticky.
- **E6 / E7** — typestate authorization (actor must be `Authenticated`) + shell-isolation (actor and target share a `ShellBrand`).
- **Determinism Band** — set at derive time via `#[arkhe(band=N)]`, immutable. **Band=1 (Core):** bit-identical replay, safe for the kernel path — use for any action that must replay identically (most user actions). **Band=2 (Projection):** eventually-consistent read-model updates (observer side). **Band=3 (Protocol):** shell-level semantic correctness, not used in L1+L2 today. Only Band=1 is currently safe to dispatch through the kernel.
- **A1 / D1-Total** — the kernel's bit-identical replay guarantee, inherited unchanged.
- **Subset-Rust / E14.L1-Deny** — the syntactic restriction (no clock/RNG/I/O/FFI/`unsafe`) enforced by `arkhe-subset-rust-check`.
- **`#[arkhe_pure]`** — the attribute that runs the purity check on a `compute` body.

**Domain primitives & lifecycle**
- **User / Actor / Space / Entry / Activity** — the five L1 primitives.
- **`ShellBrand<'s>`** — invariant-lifetime compile-time shell isolation (GhostCell pattern).
- **ActorState (typestate)** — `Actor<'s, S>` is parameterized by a sealed state `S ∈ {Anonymous, Authenticated, Suspended}`; transitions consume `self`. Anonymous has no `UserBinding`; Authenticated binds a user (subject to the C3 gate); Suspended rejects actions.
- **UserGdprState** — a user's erasure lifecycle: `Active` → `ErasurePending` (right-to-erasure requested; new actor actions blocked by C3) → `Erased` (tombstoned).
- **C3** — the GDPR `ErasurePending` admission gate at the L2 dispatch boundary (`dispatcher.rs:194-217`): before an action reaches the kernel/WAL, the authenticated actor's user is checked; if `ErasurePending`/`Erased`, dispatch is rejected (`DispatchError::ErasurePending`). (E-user-3 admission control.)
- **Acting Actor** — the authenticated identity threaded from L2 dispatch into `ActionContext` (single source of truth; never from the wire — the C3 actor-substitution defense).
- **Idempotency key** — optional `[u8;16]` dedup anchor; backed by a PG UNIQUE INDEX in production.
- **TargetKey / Kind code** — activity target identity including `target_shell_id` (defeats cross-shell idempotency bypass).
- **Staged read** — `staged_read` scans the op buffer in reverse to shadow staged mutations.
- **BoundedString\<N\>** — const-generic capacity-bounded string; growing `N` needs a schema bump.
- **TypeCode** — `u32` action/event/component id, range-validated at derive time.
- **Band/derive constants** — `TYPE_CODE`, `SCHEMA_VERSION` (first field, `u16`), `BAND`, `IDEMPOTENT`.

**Crypto & KMS**
- **DEK / KEK** — Data Encryption Key (32-byte, zeroize-on-drop, monotonic counter) / Key Encryption Key (HSM/KMS-held, wraps DEKs).
- **Envelope encryption** — plaintext DEK never leaves the HSM boundary; only wrapped ciphertext is stored.
- **AEAD** — XChaCha20-Poly1305 (192-bit random nonce), AES-256-GCM (deterministic counter nonce), AES-256-GCM-SIV (nonce-misuse resistant).
- **AAD** — the 19-byte authenticated header `dek_id(16) ‖ pii_code(2) ‖ aead_kind(1)`.
- **Crypto erasure** — GDPR right-to-erasure: shred DEK → tombstone PII rows → emit a destruction attestation (two-phase, idempotent).
- **`UserSalt`** — 16-byte per-user HSM-held entropy, `ZeroizeOnDrop`, not `Clone`.
- **PiiType** — sealed wire-tagged PII family code (`0x0001..=0x00FF` core), folded into the AAD.
- **HF2** — multi-region KMS auto-promotion gated by a health quorum.
- **Threshold** — Shamir t-of-n secret sharing over GF(2^8) (default 2-of-3) for the auto-promote token.
- **Journal** — Ed25519 chain-signed audit log of consumed Shamir tokens (BLAKE3-keyed chain).
- **Health** — N-of-M quorum liveness probe across DoH / alternate-region / static-IP channels.
- **Attestation** — a signed (or BLAKE3-digest) receipt; class is `None` / `Ed25519` / `MlDsa65` / `Hybrid`.
- **`FORGE_RECEIPT_SIG_DOMAIN`** — the receipt signature domain, distinct from the kernel WAL signature domain.
- **AND-mode** — Hybrid verification requires both Ed25519 and ML-DSA 65 to pass.
- **Compliance Tier 0/1/2** — software-KEK (dev) / single free-tier KMS / production multi-KMS + threshold HSM.

**WAL export & projection**
- **`RuntimeService`** — the L2 wrapper around `Kernel` exposing `dispatch`.
- **WAL export** — streaming the kernel's WAL out for durable backup.
- **`ARKHEXP1` / `STREAM_HEADER_MAGIC`** — the 8-byte export-stream magic (distinct from the kernel's `ARKHEWAL`).
- **`MAX_RECORD_BYTES`** — 16 MiB (`1<<24`) fail-secure ceiling on a record length prefix.
- **`BufferedWalSink`** — the **sole** append-only write path (no `Seek`; type-level A14 enforcement).
- **`StreamingWalReader`** — fail-secure stream reader (5 reject paths: bad magic / truncated header / over-max / zero-length / mid-record EOF).
- **DO NOT TOUCH #7** — the kernel's `WalRecord` postcard field order; export streams the bytes unmodified.
- **`ProjectionRouter` / `Projection` / `ObserverState`** — the read-model pipeline; `Passive`/`Active`/`Draining` for active-passive HA (Passive rejects writes — split-brain prevention).

**Process & tooling**
- **`ProcessProtection`** — Tier-0 memory hardening (`mlockall`/`prctl`/`ptrace` on Linux, `setrlimit`/`PT_DENY_ATTACH` on macOS, working-set pin on Windows) — the only `unsafe` in the workspace.
- **Kani** — bounded model checker; `arkhe-runtime-proofs` runs 4 properties (authorize/dispatch/replay/hybrid).
- **proptest arbitrary / shrink** — `arkhe-runtime-testkit` strategies that inject spec boundary values and shrink within TypeCode regions.
- **`arkhe-rand` / golden vector** — the shell-side PRNG and its 4 KiB cross-platform reproducibility fixture (kernel + runtime forbid RNG).
- **Provably-fair / commit-reveal** — both dealer and player bind to independent entropy before reveal; the audience verifies from the immutable WAL.

---

## 8. Where else to look

> **In one line:** deeper references — the project README, each crate README, formal/, docs/release-keys.md.

- `README.md` — project overview, the layer diagram, the E-axiom catalog, crypto stack.
- Per-crate `README.md` — each crate documents its own surface (esp. `arkhe-forge-core`, `arkhe-forge-platform`, `arkhe-subset-rust-check`, `arkhe-rand`).
- `formal/axiom-test-cite.toml` — the machine-readable E-axiom inventory (the source of truth for `verify-axiom-cite.sh`).
- `formal/tla-plus/` — the TLA+ refinement modules (`runtime_core.tla`, `r4_implementation_refinement.tla`, …).
- `docs/release-keys.md` — forward-pointer to the **external** `arkhe-release-keys` repo (no key material lives here).
- `SECURITY.md` — scope, crypto primitives, disclosure process.

> The **ArkheKernel** repo (L0, this runtime's dependency) has its own `AGENTS.md`. The Shell
> layer (BBS, apps) is a separate repo again.
