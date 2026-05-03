# ArkheForge Runtime Spec

> **Scope**: the canonical design document for the **L1 Primitives + L2 Services/Platform** of the Runtime sitting on ArkheKernel v0.11 (L0). On par with KERNEL_SPEC.md / INVARIANTS.md.
>
> **Runtime codename**: **ArkheForge Runtime** (§15). A forge metaphor — shells are manufactured by repeatedly hammering primitive raw materials.
>
> **What this document defines**: the Runtime primitive set, trait signatures, extension axes, determinism boundaries, inheritance of L0 axioms, multi-shell isolation, operational SLOs, upgrade paths, and backup/DR. Implementation chunk guidance, crate partitioning, and milestones are not here.

---

## §1. Identity — "Promise to minimize duplication, refuse generality"

**ArkheForge Runtime is a reuse substrate that absorbs only empirically demonstrated duplication across shells. Features that only one shell needs stay outside the Runtime, at the shell level. Speculative generalization is the path that failed Rails/Meteor.**

### §1.1 What the Runtime promises

1. **Core 5 primitives** — User, Actor, Space, Entry, Activity. Absorbed only when duplicated across 2+ shells.
2. **Four extension axes** — Component / TypeCode / Subtype / New-Primitive gate. Extension without modifying the Runtime core.
3. **Determinism inheritance** — Inherits L0 A1 (bit-identical replay), A2 (single-thread), A11 (pure compute), A13-A17 (crypto). Runtime axioms E1-E11 layer on top.
4. **Multi-shell isolation** — dual defense of User/Actor 2-tier + `ShellBrand<'s>` invariant variance + L1 compute `shell_id` (§11.2 E7 dual-tier). Compile-time at submit site + runtime MC on the replay/admin path.

### §1.2 What the Runtime does not promise (scope refusals)

| Refusal | Reason |
|---|---|
| "All social / media / game platforms in one Runtime" | The Rails/Meteor lesson. |
| Media byte storage / transport (blob storage) | Floats, huge bytes, non-determinism. Outside CDN/S3. |
| DRM key management / payments / AI recommendation algorithms | External KMS/billing/ML. Receipts/commitments only. |
| WebRTC SFU / real-time streaming substance | A separate system. Runtime only holds session metadata. |
| Federation content pull | v0.99+ later. |
| **Real-time tick-synchronized state** (position, health, movement) | MMORPG / FPS. Departs from L0 single-thread + tick-atomic commit. A separate DIP in §8.4 "game-kernel overlay". |
| State-machine game Runtime integration | Casino / boardgame shells implement Session/Turn/Round primitives (§8.3) themselves. |

### §1.3 Criterion for inclusion in Core

Restricted to **"empirically demonstrated duplication across 2 or more shells"**. Predictive/speculative grounds are rejected. Decision details in §4 (Core 5) / §8 (later candidates) / §7.4 (New-Primitive gate).

### §1.4 engine.md §E.12 self-review reflection

S2/S5/S8/S9/S10 all reflected (§7 extension axes, §9 3-band, §11 E10/E14.6 ArkheUri, §4 Core 5, §1.2 scope). S1/S3/S4/S6/S7 are carried to R5+.

### §1.5 Summary of R4 / R5 / R6 / R7 / R8 findings reflection

- **R4** (auditor/veteran/theorist + leader) — Critical 10 / Major 19 / Minor 11 all reflected in R4'. Source: `docs/Review/r4-findings-2026-04-24.md`.
- **R4'.1** (cryptographer R4 cold-read) — Critical 4 / Major 9 / Minor 4 all reflected. Source: `docs/Review/r4-cryptographer-findings-2026-04-24.md`.
- **R5** (4-person cold-read) — Critical 5 / Major 12 / Minor 15+ + Axis-3 Storage plurality PG-only tiered (unanimous among 4) + HSM fallback (team-lead directive 2026-04-24) all reflected in R5.1. Source: `docs/Review/r5-findings-2026-04-24.md`.
- **R6** (4-person full clean round) — Critical 1 (BBS compliance tier) / Major 11 (4 ops + 3 types + 4 security) / Minor 13 all reflected in R5.2. Team-lead option 2 confirmed (2026-04-24): R7 + R8 consecutive clean path. Source: `docs/Review/r6-findings-2026-04-24.md`.
- **R7** (4-person clean round) — Critical 0 / Major 3 (HF1 software-kek memory residual / HF2 auto_promote split-brain / M-R7-1 BBS telnet TLS wrap matrix) / Minor 15 of which **12 reflected, 3 deferred**. Team-lead option B confirmed (2026-04-24): R5.3 micro-revision ~60-100 LoC, no structural change. Source: `docs/Review/r7-findings-2026-04-24.md`.

**R7 deferrals (v0.12 implementation DIP / v0.13+)**:
- cryptographer R7-r1 — `EncryptedPii<T>::decrypt()` record-time manifest resolution (tick-anchored manifest lookup) → concretized in v0.12 implementation DIP.
- cryptographer R5-r5 — standard trait for shell verifier chain-attestation → already previewed in §9.3 / §15.4, promoted to v0.13 DIP proper.
- theorist R7-NR5/6/7 — Rust stable limits / over-engineering verdict: pass.
- veteran m-R7-1 — Grafana dashboard JSON template → §15.5 v0.13 nice-to-have row.
- auditor mR7-δ — `ComplianceTierChange` event → §15.5 v0.13 DIP candidate (TypeCode `0x0003_0F0A` reserved).

- **R8** (4-person verification round) — Critical 0 / Major 0 / 5 new Minor. **Achieved N=2 consecutive clean (R7 + R8)**. Team-lead decision (2026-04-24): skip R9 → close this R5.4 micro-patch → enter v0.12 implementation DIP. Of the 5 R8 Minors, 3 reflected in spec (theorist L0 version notation / veteran R8-m1 SLO 2 rows / veteran R8-m2 alpha→beta runbook) + 2 handed off to v0.12 implementation (cryptographer HF1 platform abstraction / HF4 manifest bypass audit). Source: R8 reviewer session records.

---

## §2. Layer system

### §2.1 L0 = Kernel as the baseline

```
┌──────────────────────────────────────────────────────────┐
│  L6  Shell Package                                        │
│      (Manifest + Hooks + Frontends + Migrations bundle)   │
│      e.g. ArkheNet BBS, ArkheCasino, GuildChat            │
├──────────────────────────────────────────────────────────┤
│  L5  Frontend                                             │
│      ANSI Telnet · Web · Mobile · CLI · Bot · IRC         │
├──────────────────────────────────────────────────────────┤
│  L4  Protocol Adapter                                     │
│      WebSocket · HTTP/gRPC · SSH · Telnet session         │
├──────────────────────────────────────────────────────────┤
│  L3  Library (shell-common utilities)                     │
│      Rate limiter · JWT verifier · S3 client · search    │
├──────────────────────────────────────────────────────────┤
│  L2  Runtime Services / Platform    ◄── this DIP scope    │
│      Policy · Quota · Projection · Manifest · Hook host  │
├──────────────────────────────────────────────────────────┤
│  L1  Runtime Primitives             ◄── this DIP scope    │
│      Core 5 traits · TypeCode registry · Action dispatch │
├──────────────────────────────────────────────────────────┤
│  L0  ArkheKernel v0.11                              │
│      WAL · deterministic state · authz · scheduler        │
└──────────────────────────────────────────────────────────┘
```

### §2.2 Per-layer responsibility

| Layer | Responsibility | This DIP |
|---|---|---|
| **L0 Kernel** | Bit-identical replay, single-thread state, `Effect<'i, S>`/`Op`, TypeCode registry, WAL, observer, scheduler. A1-A24 + S1. | Fixed (v0.11) |
| **L1 Runtime Primitives** | Core 5 primitive Rust types, TypeCode allocation, `ActionCompute` pure, dependency DAG, ShellBrand. | R1-R4' design |
| **L2 Runtime Services/Platform** | Policy, Manifest loader, Projection, Hook host (v2 WASI), Rate limit, Audit receipt, cascade scheduler, idempotency dedup. | R1-R4' design |
| L3 Library | shell-common utilities. | Out of scope |
| L4 Protocol Adapter | Session, encoding, idempotency key passthrough. | Out of scope |
| L5 Frontend | I/O rendering. | Out of scope |
| L6 Shell Package | Logical bundle of a single product. | Out of scope |

### §2.3 Dependency direction

- **Strictly downward DAG**: L_n → L_{n-1} or below only. L1 → L2 **forbidden** (cargo CI).
- **L6 Shell is a cross-cutting package** — physically distributed, logically grouped.
- **DO NOT TOUCH propagation**: propagate the L0 `#[arkhe_runtime_forbidden_modifier]` dylint CI gate to L1/L2. In particular, the `WalRecord` postcard field order (DO NOT TOUCH #8) must **never be modified** in the Runtime — §14.7 runtime information uses only the `RuntimeBootstrap` in-band event and the L0 `WalRecord.reserved` field path (sidecar metadata is retired, §14.7 / E12).

### §2.4 L1/L2 separation principle (details in §5)

- L1: semantic-level primitive. Knows nothing about PostgreSQL/HTTP/Manifest. Pure compute.
- L2: policy, projection, ingress. L0 observer, L4 request, manifest/quota validation → kernel submit.

---

## §3. ECS meta-structure conventions

Runtime primitives are defined on top of the 3 L0 sealed traits + `Op` + `Effect<'i, S>`.

### §3.1 Entity composition

Runtime entity = `(InstanceId, EntityId, TypeCode, [Component])`. L0-managed, NonZeroU64 ID, deterministic (tick, seq) generation (§4.7).

### §3.2 TypeCode allocation (M-verbrange / R5 NF5 core sub-split)

```
0x0000_0000 .. 0x0000_FFFF    L0 Kernel reserved
0x0001_0000 .. 0x0001_FFFF    ArkheForge core primitive Entity TypeCode
0x0002_0001 .. 0x0002_03FF    ArkheForge core Activity verb (canonical, 1023)
0x0002_0400 .. 0x0002_FFFF    Shell-extensible verb (shell_id BLAKE3 → 256-verb sub-range)
0x0003_0000 .. 0x0003_0EFF    ArkheForge core Component TypeCode
0x0003_0F00 .. 0x0003_FFFF    ArkheForge core Event TypeCode
0x0004_0000 .. 0x00FF_FFFF    ArkheForge reserved (post-R4' primitive)
0x0100_0000 .. 0xEFFF_FFFF    Shell-scoped Component/Action
0xF000_0000 .. 0xFFFF_FFFF    Debug / test
```

**R5 NF5 rationale**: in R4'.1 the single namespace `0x0003_0000..0xFFFF` caused the `UserProfile` Component and the `RuntimeBootstrap` Event to collide at the same `0x0003_0001`. L0 A15 pin is a TypeCode × schema_hash global registry → Component/Event share the same registry. Sub-range split permanently blocks the collision.

**Core Event TypeCode allocation (confirmed in R5.2)**:

| Event | TypeCode | Introduction rationale |
|---|---|---|
| `RuntimeBootstrap` | `0x0003_0F01` | §14.7 / E12 |
| `UserErasureScheduled` | `0x0003_0F02` | §14.9 GDPR cascade |
| `UserErasureCompleted` | `0x0003_0F03` | §14.9.1 crypto-shred receipt |
| `BackupErasurePropagated` | `0x0003_0F04` | §14.11.1 per-region propagation |
| `GdprPolicyViolation` | `0x0003_0F05` | §3.3 compute reject audit |
| `SignatureClassPolicy` | `0x0003_0F06` | §14.7 FG5 chain-anchored policy |
| `CrossShellActivity` | `0x0003_0F07` | §4.5 compute reject audit |
| `PerRegionErasureProgress` | `0x0003_0F08` | §14.9.1 GF4 multi-region 2PC shred (introduced R5.2) |
| `DekMigrationCompleted` | `0x0003_0F09` | §14.7 M-R6-4 Option 2 alpha→beta migration (v0.12 implementation) reserved |
| `ComplianceTierChange` | `0x0003_0F0A` | §14.9.1 §§12 Tier transition record (v0.13 DIP candidate, R7 auditor mR7-δ) reserved |
| `HookModuleRegister` | `0x0003_0F0B` | §14.5 Hook host v2 / E14.L2 chain-anchored module-registration receipt (Track B.6, v0.12 sealing cycle) |
| `ObserverQuarantine` | `0x0003_0F0C` | §14.5.2 Observer host v2 / E15 chain-anchored trap-quarantine receipt (Track A.2.4, v0.12 sealing cycle) |

**Core Event struct definitions (R5.2 mNF-B + GF4)**:

`RuntimeBootstrap` is defined in the body of §14.7. `SignatureClassPolicy` is also in §14.7. The remaining Event structs are defined here in one place — removing forward references from §14.9 / §4.5 / §3.3:

```rust
use arkhe_kernel::abi::{EntityId, Tick};
use crate::shell::ShellId;
use crate::user::UserId;
use crate::audit::RuntimeSignatureClass;   // defined in §14.7

/// The tick at which a GDPR erasure lease was scheduled.
/// Trigger for the §14.9 cascade observer.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F02, schema_version = 1)]
pub struct UserErasureScheduled {
    pub user: UserId,
    pub scheduled_tick: Tick,
}

/// Component-level removal + DEK shred completion. Chain-anchored receipt.
/// Target of the §14.9.1 FG3 transparency log.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F03, schema_version = 1)]
pub struct UserErasureCompleted {
    pub user: UserId,
    pub dek_shred_tick: Tick,
    pub attestation_class: RuntimeSignatureClass,   // R5.2 GF5 type tag
    pub attestation_bytes: bytes::Bytes,            // HSM attestation (64/128B)
    pub transparency_log_index: u64,                 // §14.11.3 log entry
}

/// Evidence that per-region offsite-backup tombstones have been applied.
/// Used in the §14.11.1 restore flow: refuse if any region's tombstone is absent.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F04, schema_version = 1)]
pub struct BackupErasurePropagated {
    pub user: UserId,
    pub region: BoundedString<32>,                   // e.g. "eu-west-1"
    pub applied_tick: Tick,
    pub receipt_class: RuntimeSignatureClass,
    pub receipt_bytes: bytes::Bytes,
}

/// Audit for an actor-originated modification attempt against a user in ErasurePending.
/// Emitted immediately after the §3.3 L1 compute MC gate rejects.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F05, schema_version = 1)]
pub struct GdprPolicyViolation {
    pub actor: ActorId,
    pub attempted_tick: Tick,
    pub action_type_code: TypeCode,
}

/// Emitted when a cross-shell Activity is detected on the replay/admin path.
/// §4.5 / §13.2 isolation-2 double-check.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F07, schema_version = 1)]
pub struct CrossShellActivity {
    pub actor: ActorId,
    pub target_shell_id: ShellId,
    pub record_shell_id: ShellId,
    pub detected_tick: Tick,
}

/// Per-scope progress for a multi-region or multi-KMS DEK shred.
/// §14.9.1 GF4 2PC — UserErasureCompleted must not be emitted until every scope has reported.
/// R5.3 mR7-γ — `scope` enum explicitly distinguishes region vs KMS identifier.
/// R5.3 R7-NR2 — `BoundedString<64>` provides room for custom region naming.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F08, schema_version = 1)]
pub struct PerRegionErasureProgress {
    pub user: UserId,
    pub scope: ProgressScope,
    pub shred_tick: Tick,
    pub attestation_class: RuntimeSignatureClass,
    pub attestation_bytes: bytes::Bytes,
}

/// R5.3 mR7-γ — distinguishes region coordinates vs KMS identifiers at the wire level.
/// Multi-region (§14.9.1 §§13 GF4) and Multi-KMS (§14.11.2 GF6) share the same event
/// struct but adversary / auditor can explicitly identify which dimension is progressing.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProgressScope {
    Region(BoundedString<64>) = 0,         // e.g. "eu-west-1", "ap-northeast-2"
    KmsIdentifier(BoundedString<64>) = 1,  // e.g. "aws-kms-prod", "gcp-kms-dr"
}
```

**Event schema_version bump convention**: each Event has an independent schema_version. Field addition uses `#[serde(default)]` + bump. Field removal / reordering is forbidden (inherited from §14.7 Enum WAL compat).

**Central registry** `runtime-typecode-allocations.toml` — distributed with the Runtime crate. When a new shell manifest loads, `blake3::derive_key("arkhe-forge-verb-alloc", shell_id_bytes)` → **first 2 bytes → sub-range index (0..=255)** — produces a deterministic 256-verb sub-range; the registry cross-checks.

**Collision detection (M7)**: the registry cross-checks derived ranges against existing allocations in advance. On collision → `ManifestError::VerbRangeCollision` reject. Remedy — permit a manifest `verb_range_nonce: u32` bump: `blake3::derive_key("arkhe-forge-verb-alloc", shell_id_bytes || nonce.to_be_bytes())` deterministic retry. After the nonce is fixed, pin it in the registry (A15 extension). Handles shell_id grinding birthday attacks.

A shell changing a verb's `extra_bytes` format obligates a new VerbCode allocation.

**Runtime BLAKE3 domain string list (m4 / §14.7 extension)**:
- `arkhe-forge-verb-alloc` — determines §3.2 verb sub-range
- `arkhe-forge-manifest-digest` — §5.6 canonical TOML digest
- `arkhe-forge-audit-receipt` — receipt MAC for `RuntimeSignatureClass`-based receipts (§5.2 / §14.7)
- `arkhe-forge-runtime-bootstrap` — §14.7 RuntimeBootstrap event MAC
- `arkhe-forge-signature-class-policy` — §14.7 SignatureClassPolicy event MAC
- `arkhe-forge-entity-id` — §4.7 deterministic id generation

CI exhaustively audits domain-string uses → any mismatch against this table fails.

### §3.3 ActionCompute & ActionContext — body fixed (NC2)

```rust
mod sealed {
    pub trait ActionComputeSealed {}
}

pub trait ActionCompute: sealed::ActionComputeSealed {
    /// L0 A19 invariant-lifetime brand `'i` threaded through the signature.
    fn compute<'i>(
        &self,
        ctx: &dyn ActionContext<'i>,
        eff: Effect<'i, Authorized>,
    ) -> Vec<Op<'i>>;
}

/// NC2 — body fixed for read/next_id/tick/actor-shell lookup.
/// `'i` is the brand (invariant), `'a` is the borrow scope — safe for chain reads.
pub trait ActionContext<'i> {
    /// Read current Component value for entity. None if component not attached.
    /// Tick-scoped cache (P2) is an implementation detail — within the same tick,
    /// identical (entity, TypeCode) reads share a single underlying lookup.
    fn read<'a, C: ArkheComponent>(&'a self, entity: EntityId) -> Option<&'a C>
    where Self: 'a;

    /// Deterministic ID generator. `K::TYPE_CODE` separates the ID namespace.
    fn next_id<K: EntityKind>(&self, tick: Tick, seq: u32) -> EntityId;

    /// Current tick.
    fn tick(&self) -> Tick;

    /// Convenience — the actor's shell_id. For the E7 compute dual-check.
    /// None if the actor entity is missing (invalid actor_id).
    fn authenticated_actor_shell<'a>(&'a self, actor: ActorId) -> Option<ShellId>
    where Self: 'a;

    /// R5.2 NR6-3 — Idempotency scan.
    /// None = miss (process as a new Action), Some = hit (return the existing entity_id → compute noop).
    /// L0 provides a tick-scoped auxiliary index (idempotency_key → (EntityId, Tick) over the last N ticks).
    /// Deterministic — identical WAL state → identical result. §14.8 WAL scan p99 < 5ms basis.
    fn idempotency_lookup(&self, key: &[u8; 16]) -> Option<(EntityId, Tick)>;
}

// Only #[derive(ArkheAction)] auto-impls sealed + ActionCompute.
// A shell crate's manual `impl ActionCompute` = compile rejection.
//
// R5.2 NR6-2 — `#[arkhe(idempotent)]` opt-in attribute.
//   When present, the derive's compile-time assert forces the struct to
//   carry an `idempotency_key: Option<[u8; 16]>` field — absent = compile rejection.
//   compute default path: `if let Some(k) = self.idempotency_key {
//                              if let Some((id, _)) = ctx.idempotency_lookup(&k) {
//                                  return noop_with_id(id);
//                              }
//                          }` synthesized automatically.
//   Default is opt-out — only an Action with an explicit declaration is idempotent.
//
// Example:
//   #[derive(ArkheAction, Serialize, Deserialize)]
//   #[arkhe(type_code = 0x0001_0401, schema_version = 1, band = 1, idempotent)]
//   pub struct SubmitActivity {
//       pub record: ActivityRecord,
//       pub idempotency_key: Option<[u8; 16]>,   // derive assertion target
//   }
```

**Pure convention** (inherited from L0 A11):
1. No I/O / rand / `std::time::now` / `HashMap::iter`.
2. Invariant checks use `ctx` reads inside compute.
3. Multi-Op atomic (L0 A20 StepStage).
4. `'i` brand threaded into the generated Op.
5. **GDPR gate (C3 / B3)**: every actor-originated compute verifies `ctx.read::<UserProfile>(actor.user_id)?.gdpr_status != ErasurePending`. On violation → empty `Vec<Op>` + `GdprPolicyViolation` event. See §14.9.

### §3.4 Component canonical bytes (M-component-sealed)

- `#[derive(ArkheComponent)]` + `#[arkhe(type_code = N, schema_version = M)]`.
- The `ArkheComponent` derive is **sealed** — a manual `Serialize + __CanonicalEncode` = compile rejection. Lockstep with L0 A15.
- postcard canonical (A17). `String`/`f32`/`f64`/foreign `Ord` keys are not allowed.
- `approx_size()` override: required for large `bytes::Bytes` fields.
- **Bounded string (m1 final, reflecting theorist analysis)**: `BoundedString<N>` is a **sealed wrapper** to freeze the external API (while leaving room to replace the internal `arrayvec::ArrayString<N>`). `Cargo.toml` dependency: `arrayvec = { version = "0.7", default-features = false, features = ["serde"] }` — minimal no_std + serde surface.

  ```rust
  // ArkheForge Runtime BoundedString<N> — sealed wrapper over arrayvec::ArrayString<N>.
  // Canonical wire = postcard serialize_str (varint byte-length + N-bounded UTF-8 bytes).
  // N is not exposed on the wire — a runtime length check runs on decode.
  // Enlarging N = schema_version bump (A15 pin rotate). Shrinking N = strictly forbidden.

  use arrayvec::ArrayString;
  use serde::{Serialize, Deserialize, Deserializer, de::Error as _};

  mod sealed { pub trait Sealed {} }

  #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
  pub struct BoundedString<const N: usize>(ArrayString<N>);

  impl<const N: usize> BoundedString<N> {
      pub fn new(s: &str) -> Result<Self, BoundedStringError> {
          ArrayString::from(s)
              .map(Self)
              .map_err(|_| BoundedStringError::Overflow { len: s.len(), cap: N })
      }
      pub fn as_str(&self) -> &str { self.0.as_str() }
      pub const CAP: usize = N;
  }

  impl<const N: usize> Serialize for BoundedString<N> {
      fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
          s.serialize_str(self.0.as_str())
      }
  }

  impl<'de, const N: usize> Deserialize<'de> for BoundedString<N> {
      fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
          let s = <&str>::deserialize(d)?;
          Self::new(s).map_err(|e| D::Error::custom(e))
      }
  }

  #[derive(Debug, thiserror::Error)]
  pub enum BoundedStringError {
      #[error("BoundedString overflow: len {len} > cap {cap}")]
      Overflow { len: usize, cap: usize },
  }
  ```

  **Rejected crate rationale** (see `docs/Review/bounded-string-analysis-2026-04-24.md`): `smol_str` / `smartstring` lack a const generic N + use heap growth — "bounded" does not hold. `heapless::String<N>` has the same wire format but ships `Vec<T, N>` / `LinearMap` / `spsc::Queue` alongside, unnecessarily expanding the Runtime surface. A self-implementation is ~200 LoC of burden + lacks external vetting. Aligned with the L0 kernel's minimal-crate principle and arrayvec.

  **Invariants** (added in §3.4):
  1. `BoundedString<N>` canonical wire = `postcard::serialize_str` output. **N is not exposed on the wire** — a runtime length check runs on decode (`ArrayString::from` Err).
  2. Adding a `BoundedString<N>` field obligates a schema_version bump on the containing Component (A15 pin rotate).
  3. Changing N of `BoundedString<N>`:
     - Enlarge (`N1 < N2`): new schema_version + existing WAL records replay fine (len ≤ N1 ≤ N2).
     - Shrink (`N1 > N2`): **strictly forbidden**. Replaying a record with `N2 < len ≤ N1` → `ReplayError::BoundedStringOverflow` — unrecoverable.

  **DO NOT TOUCH candidate**: the `BoundedString<N>` sealed wrapper **external API**. The internal `ArrayString<N>` may be freely replaced (e.g. with `smallstr` later), but the wire format, the 3 invariants, and the `BoundedStringError` variant order are fixed. Core to the A17 canonical-bytes inheritance path.

  **Forbidden**: padded `[u8; N]` is strictly forbidden — prevents emoji/CJK boundary truncation + zero-byte hash drift.

**Non-exhaustive enum default-reject policy (R5 NC5)**: every `#[non_exhaustive]` + `#[repr(u8)]` Runtime enum (AuthKind / GdprStatus / KdfKind / ActorKind / SpaceKind / Visibility / TargetKind / ActivityStatus / RelayKind / RuntimeSignatureClass / AeadKind etc.) is **default = reject** on the compute path. `match` uses `_ => { /* audit + reject */ }` to return an empty `Vec<Op>` + emit a Failure event of kind `GdprPolicyViolation`/`UnknownVariant`. Forward-compat is owned by schema_version bump + `unknown_variants` staging (§12.4) — a silent allow at compute would give an adversary who injects a future variant into the WAL a path around current-node rejection. Default-reject is aligned with Band 1 determinism.

### §3.5 Event emission

The `ArkheEvent` trait is **sealed** — impl only via `#[derive(ArkheEvent)]` (R5.3 R7-NR1). Canonical bytes = postcard serialize. Inherits A15 for TypeCode × schema_hash pin — same path as `ArkheComponent` / `ArkheAction`.

A domain event → `Op::EmitEvent { actor, event_type_code, event_bytes }`. postcard canonical.
L2 projection = L0 observer, `OBSERVER_REGISTER` cap, `DOMAIN_EVENT_EMITTED` + `ACTION_EXECUTED` mask + **mandatory shell_id filter** (S7, §5.5).

**`#[arkhe(canonical_sort)]` field attribute opt-in (R5.3 R7-NR3)**: when declared on a `Vec<T>` or `BTreeSet<T>` field, the derive injects a `sort_unstable()` right before serialize — securing canonical-bytes stability. Default preserves arrival order (default postcard behavior). Example:

```rust
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F01, schema_version = 1)]
pub struct RuntimeBootstrap {
    pub runtime_semver: SemVer,
    pub manifest_digest: [u8; 32],
    #[arkhe(canonical_sort)]         // R5.3 R7-NR3 — removes dependence on insertion order
    pub typecode_pins: Vec<TypeCode>,
    pub bootstrap_tick: Tick,
}
```

The derive sorts each `canonical_sort` field before the `Serialize` call. Copy-free in-place sort (Vec: mut borrow; BTreeSet: already sorted, no-op). Basis for E12 MC digest stability. The same attribute is supported on `ArkheComponent` / `ArkheAction` — field-level opt-in leaves overall wire format unchanged.

### §3.6 Authentication & authorization

- L0 `authorize(caps, effect) -> Effect<'i, Authorized>` must succeed.
- L2 resolves caps (manifest role-to-caps).
- `'i` preserves the L0 R5-T1 brand.

### §3.7 ShellBrand `'s` — compile-time shell isolation (entry-point defense)

```rust
/// Same technique as L0 InvariantLifetime<'i> (Yanovski et al. ICFP 2021).
pub struct ShellBrand<'s> {
    _brand: PhantomData<fn(&'s ()) -> &'s ()>,
}

pub struct Actor<'s, S: ActorState> {
    brand: ShellBrand<'s>,
    id: ActorId,
    _state: PhantomData<S>,
}

pub struct Entry<'s> {
    brand: ShellBrand<'s>,
    id: EntryId,
}

pub struct Activity<'s> {
    brand: ShellBrand<'s>,
    inner: ActivityRecord,    // Component, 'static
}
```

**Brand scope** (I1 ergonomics):

| Path | Brand handling | Defense |
|---|---|---|
| **Submit** (L2 → L1) | `'s` required at compile time. Cross-shell references = lifetime unification compile failure. | TYPE-PROVEN via ShellBrand |
| **Replay** (WAL → L1) | No brand. Inside compute, MC double-defense via `ctx.authenticated_actor_shell(actor)` vs target actor shell_id. | RUNTIME-ASSERTED (compute MC) |
| **Admin/Projection** | `BrandedAccess::enter<R>(shell_id, |brand| -> R)` scope closure. Provided by the `arkhe-runtime-admin` crate. Cross-shell admin tool re-constructs the brand on entry. | TYPE-PROVEN within closure |
| **Test** | `#[arkhe_runtime_test_brand]` attribute macro — auto-generates a brand scope inside the closure. | Test-only |

E7 dual-tier (§11.2) — Submit-site TP + Replay/storage RA. Bypass via cross-shell admin is blocked (S4).

---

## §4. Core 5 Primitives — Rust specification

Per primitive: (a) identity (b) evidence of 2+ shell duplication (c) Component (d) Action (e) invariants. TypeCode values are R4' proposals; the final values are registry-pinned.

### §4.1 User — Identity Subject (AuthCredential KDF redesign — C9 / S2)

**Identity**: the subject of authentication, payments, GDPR, and legal. Globally unique across a Runtime instance. Does not belong to any shell.

**2+ shell duplication evidence**: BBS/Twitter2/Blog/Casino/GuildChat all need "a single person". SSO/GDPR/billing cross shell boundaries.

```rust
pub mod user {
    use arkhe_kernel::abi::{EntityId, Tick};

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    pub struct UserId(EntityId);   // private field
    impl UserId {
        pub(crate) fn new(id: EntityId) -> Self { Self(id) }
        pub fn get(self) -> EntityId { self.0 }
    }

    #[non_exhaustive]
    #[repr(u8)]                     // C10 / S3 explicit index
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum AuthKind {
        Passkey = 0,
        Email = 1,
        Handle = 2,
        Address = 3,
        // Append only at the end. Reordering/removal forbidden.
    }

    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum GdprStatus {
        Active = 0,
        ErasurePending = 1,
        Erased = 2,
    }

    /// S2 — slow KDF obligation.
    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum KdfKind {
        Argon2id = 0,
        Scrypt = 1,
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct KdfParams {
        pub m_cost: u32,   // Argon2id: memory cost (KB)
        pub t_cost: u32,   // time cost (iterations)
        pub p_cost: u32,   // parallelism
    }

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0001, schema_version = 1)]
    pub struct UserProfile {
        pub created_tick: Tick,
        pub primary_auth_kind: AuthKind,
        pub gdpr_status: GdprStatus,
    }

    /// S2 / C9 — salt + KDF required. Direct SHA-256/BLAKE3 hashing forbidden.
    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0002, schema_version = 1)]
    pub struct AuthCredential {
        pub kind: AuthKind,
        pub kdf: KdfKind,
        pub salt: [u8; 16],            // per-credential random. included in canonical_bytes.
        pub credential_hash: [u8; 32], // KDF(password, salt, params)
        pub kdf_params: KdfParams,
        pub expires_tick: Option<Tick>, // S8 rotation policy
        pub bound_tick: Tick,
    }

    /// Runtime default — OWASP 2024 recommendation.
    impl AuthCredential {
        pub const DEFAULT_KDF: KdfKind = KdfKind::Argon2id;
        pub const MIN_ARGON2ID_M_COST: u32 = 19456;  // 19 MiB
        pub const MIN_ARGON2ID_T_COST: u32 = 2;
        pub const MIN_ARGON2ID_P_COST: u32 = 1;
        /// L1 compute validation — reject parameters below the minima.
        pub fn validate_kdf_params(kdf: KdfKind, p: &KdfParams) -> bool {
            match kdf {
                KdfKind::Argon2id =>
                    p.m_cost >= Self::MIN_ARGON2ID_M_COST
                    && p.t_cost >= Self::MIN_ARGON2ID_T_COST
                    && p.p_cost >= Self::MIN_ARGON2ID_P_COST,
                KdfKind::Scrypt => /* scrypt minima */ true,
            }
        }
    }

    #[derive(ArkheAction, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0001_0001, schema_version = 1)]
    pub struct RegisterUser { pub profile: UserProfile, pub credential: AuthCredential }
    // compute() — AuthCredential::validate_kdf_params(credential.kdf, &credential.kdf_params)
    //   false → reject.

    /// X1 / C3 — lease only. Cascade is done by the §14.9 L2 background.
    #[derive(ArkheAction, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0001_0003, schema_version = 1)]
    pub struct GdprEraseUser { pub user: UserId }
    // compute() -> vec![
    //   Op::SetComponent(UserProfile { gdpr_status: ErasurePending, ... }),
    //   Op::EmitEvent(UserErasureScheduled { user, tick })
    // ]
}
```

**Invariants**:
- E-user-1 (MC): exactly one `UserProfile`.
- E-user-2 (MC): at least one `AuthCredential`. `kdf` is `Argon2id` or `Scrypt` with ≥ minima. Principal::Unauthenticated binding forbidden (complements §11 E6 Authenticated typestate).
- E-user-3 (**RUNTIME-ASSERTED**): `GdprEraseUser` is a lease. Actual cascade §14.9 SLA (p95 < 24h). **L1 compute MC (C3)**: every actor-originated compute rejects when gdpr_status == ErasurePending → blocks modification attempts.
- E-user-4 (TYPE-PROVEN): UserId globally unique across the Runtime (via L0 A6 NonZeroU64).

### §4.2 Actor — Per-shell Activity Subject

**Identity**: the subject of activity within a specific shell. Shell-scoped handle/profile/karma. User N:1.

**2+ shell duplication evidence**: BBS handle, Twitter2 `@jane_d`, Casino SeatId, GuildChat guild handle — all "the subject of activity within a shell".

```rust
pub mod actor {
    use super::user::UserId;
    use crate::shell::{ShellBrand, ShellId};

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    pub struct ActorId(EntityId);
    impl ActorId {
        pub(crate) fn new(id: EntityId) -> Self { Self(id) }
        pub fn get(self) -> EntityId { self.0 }
    }

    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum ActorKind { Human = 0, Bot = 1, System = 2, Anonymous = 3 }

    mod state_seal { pub trait Sealed {} }
    pub trait ActorState: state_seal::Sealed {}

    pub enum Authenticated {}
    pub enum Anonymous {}
    impl state_seal::Sealed for Authenticated {}
    impl state_seal::Sealed for Anonymous {}
    impl ActorState for Authenticated {}
    impl ActorState for Anonymous {}

    pub struct Actor<'s, S: ActorState> {
        brand: ShellBrand<'s>,
        id: ActorId,
        _state: PhantomData<S>,
    }

    impl<'s> Actor<'s, Authenticated> {
        /// Total — not Option. E-actor-2 TYPE-PROVEN.
        pub fn user_binding(&self, ctx: &dyn ActionContext<'_>) -> UserId { /* ... */ }
    }
    // Actor<'s, Anonymous> has no user_binding.

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0101, schema_version = 1)]
    pub struct ActorProfile {
        pub shell_id: ShellId,                    // E5 immutable (MC)
        pub handle: BoundedString<32>,
        pub kind: ActorKind,
        pub created_tick: Tick,
    }

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0102, schema_version = 1)]
    pub struct UserBinding {
        pub user_id: UserId,                      // E5 immutable
    }
}
```

**Invariants**:
- E-actor-1 (MC): exactly one `ActorProfile`.
- E-actor-2 (TYPE-PROVEN — promoted at M4): `Actor<'s, Authenticated>` requires `UserBinding`. No `Actor<'s, Anonymous>` exists.
- E-actor-3 (MC): `(shell_id, handle)` unique.
- E-actor-4 (TYPE-PROVEN): an Actor belongs to one shell (`'s` brand).
- E-actor-5 (MC): `user_id` and `shell_id` immutable after creation. SetComponent mutation attempts are rejected.

### §4.3 Space — Container / Scope

**Identity**: Entry's publication target / classification axis / boundary.

**2+ shell duplication evidence**: 7-shell design verification — Flat/Tree/Graph/Hashtag/ActorFeed 5 kinds are sufficient.

```rust
pub mod space {
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    pub struct SpaceId(EntityId);

    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum SpaceKind {
        Flat = 0,
        Tree = 1,
        Graph = 2,
        Hashtag = 3,
        ActorFeed = 4,
        /// TypeCode registered via manifest + schema_hash pin.
        Extension { type_code: TypeCode } = 255,
    }

    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum Visibility {
        Public = 0,
        RestrictedByRole = 1,
        SubscribersOnly = 2,
        PrivateInvite = 3,
        Encrypted = 4,
    }

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0201, schema_version = 1)]
    pub struct SpaceConfig {
        pub shell_id: ShellId,
        pub slug: BoundedString<32>,
        pub kind: SpaceKind,
        pub visibility: Visibility,
        pub creator: ActorId,                  // E-space-5
        pub parent_space: Option<SpaceId>,     // Parent immutable after creation (P5)
        pub created_tick: Tick,
    }

    /// O(1) depth check — M-cycle.
    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0202, schema_version = 1)]
    pub struct ParentChainDepth { pub depth: u8 }   // 0..=64

    /// DM support (X3). PrivateInvite Space membership.
    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0203, schema_version = 1)]
    pub struct SpaceMembership {
        pub members: BTreeSet<ActorId>,
    }

    #[derive(ArkheAction, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0001_0201, schema_version = 1)]
    pub struct CreateSpace { pub config: SpaceConfig }
    // compute (N4 update logic):
    //   // GDPR gate (C3)
    //   if gdpr_status(creator.user_id) == ErasurePending { return reject; }
    //   // Shell isolation (E7 RA)
    //   if ctx.authenticated_actor_shell(config.creator)? != config.shell_id { return reject; }
    //   // Parent depth (E8)
    //   let parent_depth = match config.parent_space {
    //       Some(p) => {
    //           let p_cfg = ctx.read::<SpaceConfig>(p)?;
    //           if p_cfg.shell_id != config.shell_id { return reject; }  // E-space-2
    //           ctx.read::<ParentChainDepth>(p)?.depth
    //       }
    //       None => 0,
    //   };
    //   if parent_depth + 1 > 64 { return reject(DepthExceeded); }   // E-space-4
    //   let id = ctx.next_id::<SpaceMarker>(ctx.tick(), seq);
    //   vec![
    //       Op::SpawnEntity { id, owner: principal },
    //       Op::SetComponent(SpaceConfig ...),
    //       Op::SetComponent(ParentChainDepth { depth: parent_depth + 1 }),
    //   ]
    // Note: the UpdateSpace Action rejects parent_space changes (P5 / auditor N4).
}
```

**Invariants**:
- E-space-1 (MC): exactly one `SpaceConfig`.
- E-space-2 (MC): `parent_space` must be a Space in the same `shell_id`.
- E-space-3 (MC): cycle-free (E8).
- E-space-4 (MC): depth ≤ 64 (M-cycle). O(1) via cache.
- E-space-5 (MC): `creator.shell_id == self.shell_id` (auditor M6).
- E-space-6 (MC): `SpaceKind::Extension` requires preceding manifest load + A15 pin. Replay drift → `ReplayError::ExtensionTypeCodeDrift`.
- E-space-7 (MC / P5): `parent_space` immutable after creation. `UpdateSpace { parent_space: Some(_) }` reject.

### §4.4 Entry — Content Unit

**Identity**: the persistent content unit. BBS post, tweet, forum post, blog article, comment, reply, quote retweet.

**2+ shell duplication evidence**: the atomic unit across every content platform.

```rust
pub mod entry {
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    pub struct EntryId(EntityId);

    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum RelayKind { Plain = 0, Quote = 1 }

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0301, schema_version = 1)]
    pub struct EntryCore {
        pub shell_id: ShellId,
        pub space_id: SpaceId,
        pub author_id: ActorId,
        pub parent_entry: Option<EntryId>,    // P5 immutable after creation
        pub relay_of: Option<EntryId>,
        pub relay_kind: Option<RelayKind>,
        pub created_tick: Tick,
    }

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0302, schema_version = 1)]
    pub struct EntryBody {
        pub title: Option<BoundedString<256>>,
        pub body_hash: [u8; 32],
        pub body_cipher_meta: Option<BodyCipherMeta>,
        pub edit_seq: u32,
    }

    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0303, schema_version = 1)]
    pub struct EntryParentDepth { pub depth: u8 }    // M-cycle
}
```

**Invariants**:
- E-entry-1 (MC): exactly one `EntryCore`.
- E-entry-2 (MC): `author_id` / `space_id` must be in the same shell (E7).
- E-entry-3 (MC): `parent_entry` cycle-free, depth ≤ 64.
- E-entry-4 (MC): `relay_of` single level — B a relay of A a relay of C → B.relay_of = C.
- E-entry-5 (MC): `DeleteEntry` is soft — `EntryBody` removal, `EntryCore` retained.
- E-entry-6 (MC): `edit_seq` monotonic.
- E-entry-7 (MC / P5): `parent_entry` / `relay_of` immutable after creation.

### §4.5 Activity — Verb (C1+NC1 / C2 / N1 redesign)

**Identity**: actor → target one-way explicit action. Like/Follow/Report/Bookmark/Mute/Block/Pin/Flag.

**2+ shell duplication evidence**: ActivityPub industry standard. Reaction + Subscription + Moderation Report share identical storage / query / WAL patterns.

**R4' redesign essentials**:
- **C1/NC1** — `SubmitActivity` is a brand-less Action (postcard DeserializeOwned compatible). `Activity<'s>` is a branded wrapper for the user API only.
- **C2** — introduces `ActivityStatus`; on Retract, remove the BTreeMap entry, tombstone the ActivityRecord.
- **N1** — explicit `TargetKey` type for BTreeMap keys.

```rust
pub mod activity {
    use arkhe_kernel::abi::{EntityId, Tick, TypeCode};
    use crate::shell::{ShellBrand, ShellId};

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    pub struct ActivityId(EntityId);

    /// Compile-time enforcement of the canonical range.
    pub struct CanonicalVerb<const C: u32>(
        PhantomData<[(); (C >= 0x0002_0001 && C <= 0x0002_03FF) as usize]>,
    );
    pub struct ShellVerb<const C: u32>(
        PhantomData<[(); (C >= 0x0002_0400 && C <= 0x0002_FFFF) as usize]>,
    );

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug,
             serde::Serialize, serde::Deserialize)]
    pub struct VerbCode(TypeCode);   // private
    impl VerbCode {
        pub fn canonical<const C: u32>(_: CanonicalVerb<C>) -> Self { Self(TypeCode(C)) }
        pub fn shell<const C: u32>(_: ShellVerb<C>) -> Self { Self(TypeCode(C)) }
        pub fn code(self) -> TypeCode { self.0 }
    }

    pub mod canonical_verbs {
        use super::{CanonicalVerb, PhantomData};
        pub const LIKE_C:     CanonicalVerb<0x0002_0001> = CanonicalVerb(PhantomData);
        pub const FOLLOW_C:   CanonicalVerb<0x0002_0002> = CanonicalVerb(PhantomData);
        pub const BOOKMARK_C: CanonicalVerb<0x0002_0003> = CanonicalVerb(PhantomData);
        pub const REPORT_C:   CanonicalVerb<0x0002_0004> = CanonicalVerb(PhantomData);
        pub const MUTE_C:     CanonicalVerb<0x0002_0005> = CanonicalVerb(PhantomData);
        pub const BLOCK_C:    CanonicalVerb<0x0002_0006> = CanonicalVerb(PhantomData);
        pub const PIN_C:      CanonicalVerb<0x0002_0007> = CanonicalVerb(PhantomData);
        pub const FLAG_C:     CanonicalVerb<0x0002_0008> = CanonicalVerb(PhantomData);
    }

    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum TargetKind {
        Entry(EntryId) = 0,
        Actor(ActorId) = 1,
        Space(SpaceId) = 2,
        Activity(ActivityId) = 3,
        /// Shell-defined extension target.
        Extension { type_code: TypeCode, id: EntityId } = 4,
    }

    /// N1 — BTreeMap key. Deterministic conversion from TargetKind.
    /// C1 — includes `target_shell_id` so the idempotent key itself is shell-scoped,
    /// blocking Extension bypass.
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    pub struct TargetKey {
        kind_code: u8,              // Entry=1, Actor=2, Space=3, Activity=4, Extension=5
        type_code: TypeCode,        // TypeCode(0) unless Extension
        id: EntityId,
        target_shell_id: ShellId,   // C1 — shell-scoped idempotency
    }
    impl TargetKind {
        /// Requires ctx to resolve target entity's shell_id (Extension case).
        pub fn key(&self, ctx: &dyn ActionContext<'_>) -> Option<TargetKey> {
            let (kind_code, type_code, id, target_shell) = match self {
                Self::Entry(id)    => (1, TypeCode(0), id.0, ctx.read::<EntryCore>(id.0)?.shell_id),
                Self::Actor(id)    => (2, TypeCode(0), id.0, ctx.read::<ActorProfile>(id.0)?.shell_id),
                Self::Space(id)    => (3, TypeCode(0), id.0, ctx.read::<SpaceConfig>(id.0)?.shell_id),
                Self::Activity(id) => (4, TypeCode(0), id.0, ctx.read::<ActivityRecord>(id.0)?.shell_id),
                Self::Extension { type_code, id } => {
                    // C1 MC — resolve the Extension target's shell_id via the EntityShellId marker Component.
                    let shell = ctx.read::<EntityShellId>(*id)?.shell_id;
                    (5, *type_code, *id, shell)
                }
            };
            Some(TargetKey { kind_code, type_code, id, target_shell_id: target_shell })
        }
    }

    /// C1 — marker Component tracking the shell_id of an Extension entity.
    /// Must be SetComponent'd when spawning the Extension type_code.
    /// R5 R5-r1 — immutable after creation (E5-style). Reapplying SetComponent is rejected.
    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0402, schema_version = 1)]
    pub struct EntityShellId { pub shell_id: ShellId }

    /// C2 — status with retraction tombstone.
    #[non_exhaustive]
    #[repr(u8)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum ActivityStatus {
        Active = 0,
        Retracted { at: Tick } = 1,
    }

    /// Storage-safe Component. 'static. postcard DeserializeOwned.
    /// C1 — no brand.
    #[derive(ArkheComponent, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0003_0401, schema_version = 1)]
    pub struct ActivityRecord {
        pub shell_id: ShellId,
        pub actor: ActorId,
        pub verb: VerbCode,
        pub target: TargetKind,
        pub at_tick: Tick,
        pub status: ActivityStatus,     // C2
        pub extra_bytes: bytes::Bytes,  // M-schemaver-verb / P1 size cap (§5.6)
    }

    /// Runtime-only branded wrapper — user API only.
    /// C1 — the storage boundary uses inner only.
    /// R5 m-R5-2 — explicit Clone (user API ergonomics; brand is PhantomData so Copy is OK).
    #[derive(Clone)]
    pub struct Activity<'s> {
        brand: ShellBrand<'s>,
        inner: ActivityRecord,
    }
    impl<'s> Activity<'s> {
        pub(crate) fn new(brand: ShellBrand<'s>, inner: ActivityRecord) -> Self {
            Self { brand, inner }
        }
        pub fn inner(&self) -> &ActivityRecord { &self.inner }
    }

    /// Brand-less Action — postcard compatible.
    /// C1 — Activity<'s> is converted just before submit.
    #[derive(ArkheAction, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0001_0401, schema_version = 1, band = 1)]
    pub struct SubmitActivity {
        pub record: ActivityRecord,
    }
    impl SubmitActivity {
        /// Submit entry-point. Submit-site brand compile-time enforcement (E7 TP tier).
        pub fn from_branded<'s>(a: Activity<'s>) -> Self {
            Self { record: a.inner }
        }
    }
    // compute body (C3 GDPR + B1 shell dual-check + X4 cycle + C2 idempotent):
    //   let r = &self.record;
    //   // C3 GDPR gate
    //   let author_profile = ctx.read::<ActorProfile>(r.actor)?;
    //   let user_id = ctx.read::<UserBinding>(r.actor)?.user_id;
    //   if ctx.read::<UserProfile>(user_id)?.gdpr_status == ErasurePending {
    //       return reject(GdprPolicyViolation);
    //   }
    //   // B1 / S4 dual shell_id check (submit-site brand already passed / replay·admin double-defense)
    //   if author_profile.shell_id != r.shell_id { return reject(ShellMismatch); }
    //   let target_shell = match r.target {
    //       TargetKind::Actor(a) | TargetKind::Entry(a_or_e) /* ...*/ => {
    //           match r.target {
    //               TargetKind::Entry(e)    => ctx.read::<EntryCore>(e)?.shell_id,
    //               TargetKind::Actor(a)    => ctx.read::<ActorProfile>(a)?.shell_id,
    //               TargetKind::Space(s)    => ctx.read::<SpaceConfig>(s)?.shell_id,
    //               TargetKind::Activity(a) => ctx.read::<ActivityRecord>(a)?.shell_id,
    //               TargetKind::Extension { .. } => r.shell_id, // shell-defined
    //           }
    //       }
    //   };
    //   if target_shell != r.shell_id { return reject(CrossShellActivity); }
    //   // C1 Extension MC — blocks the type-erased id bypass path.
    //   if let TargetKind::Extension { id, .. } = r.target {
    //       let t_shell = ctx.read::<EntityShellId>(id)?.shell_id;
    //       if t_shell != r.shell_id { return reject(CrossShellExtensionTarget); }
    //   }
    //   // X4 self-loop + meta-verb depth ≤ manifest.appeal_max_depth (I3)
    //   let new_id = ctx.next_id::<ActivityMarker>(ctx.tick(), seq);
    //   if let TargetKind::Activity(tid) = r.target {
    //       if tid == new_id { return reject(SelfLoop); }
    //       // I3 parametric depth (manifest [moderation.appeal_max_depth], hard cap 8)
    //       let mut depth = 1;
    //       let mut cur = tid;
    //       while depth < manifest.appeal_max_depth {
    //           let t = ctx.read::<ActivityRecord>(cur)?;
    //           match t.target {
    //               TargetKind::Activity(next) => { cur = next; depth += 1; }
    //               _ => break,
    //           }
    //       }
    //       if matches!(ctx.read::<ActivityRecord>(cur)?.target, TargetKind::Activity(_)) {
    //           return reject(MetaVerbDepthExceeded);
    //       }
    //   }
    //   // C2 idempotent — only Active entries are kept in the BTreeMap.
    //   // The index is a BTreeMap<(ActorId, VerbCode, TargetKey), ActivityId> in L0 state (L1 primitive state).
    //   if let Some(existing) = index.get(&(r.actor, r.verb, r.target.key())) {
    //       return noop_with_id(existing);  // idempotent return
    //   }
    //   vec![ SpawnEntity, SetComponent(ActivityRecord { status: Active, ... }) ]

    /// C2 — on retract, remove the BTreeMap entry + change status.
    #[derive(ArkheAction, serde::Serialize, serde::Deserialize)]
    #[arkhe(type_code = 0x0001_0402, schema_version = 1, band = 1)]
    pub struct RetractActivity { pub activity: ActivityId }
    // compute:
    //   // GDPR gate
    //   let r = ctx.read::<ActivityRecord>(self.activity)?;
    //   // owner check (principal == actor)
    //   ...
    //   vec![
    //       Op::SetComponent(ActivityRecord { status: Retracted { at: ctx.tick() }, ..r.clone() }),
    //       // L1 primitive state: BTreeMap.remove((actor, verb, target.key()))
    //       //   — via StepStage index delta. Inherits L0 A20 atomic.
    //   ]
    // Re-submit gets a new ActivityId.
}
```

**Invariants**:
- E-act-1 (MC / C2 restatement): for the same `(actor, verb, target.key())`, **at most one Active ActivityRecord**. The BTreeMap index retains Active only. On Retract, the index is removed → re-submit gets a new ActivityId.
- E-act-2 (**TYPE-PROVEN at submit / RUNTIME-ASSERTED at replay** — B1 dual-tier): actor / target in the same shell. The submit path is ShellBrand compile-time. Replay/admin paths use compute MC double-check. **Extension target (C1)**: for `TargetKind::Extension { id, .. }`, `ctx.read::<EntityShellId>(id).shell_id == record.shell_id` double-defense MC — blocks the type-erased id path's brand bypass.
- E-act-3 (TYPE-ADJACENT): Runtime does not interpret `extra_bytes`. A format change obligates a new VerbCode.
- E-act-4 (MC / C2 restatement): Retract is a tombstone — `status = Retracted { at }` SetComponent + BTreeMap index removal. Re-submit gets a new ActivityId.
- E-act-5 (MC / X4): self-loop blocked + meta-verb depth ≤ `manifest.moderation.appeal_max_depth` (1..=8, default 2, I3 parametric). Runtime hard cap 8 (WAL replay bound).
- E-act-6 (MC): Mutex group (Like ↔ Dislike) — declared in the shell manifest, validated by L2 policy + rate limit `[activity.verb_cooldown_seconds]` (default 10s).
- E-act-7 (MC / R5-r1): `EntityShellId` Component is immutable after creation. SetComponent reapplication rejected — blocks shell-ownership tampering on Extension targets (complements C1).

**theorist M5 `Activity<const D: u8>` rejection verdict retained** — L1 compute runtime depth check is sufficient for MC.

### §4.6 Dependency DAG between primitives

```
                   User
                     │ (1:N)
                     ▼
                   Actor<'s, S>
                ┌────┴────┐
                │         │
          (author)    (actor)
                │         │
                ▼         ▼
         Entry<'s>  ◄── Activity<'s>  ──(inner: ActivityRecord storage)
            │   ▲               ▲
            │   │ (parent,      │ (target: Entry|Actor|Space|Activity|Extension,
            │   │  depth ≤ 64,  │  meta-depth ≤ manifest appeal_max_depth)
            │   │  P5 immutable)│
            └───┘               │
                                │
            Space<'s> ◄─────────┘
               │
               ▼ (parent DAG, depth ≤ 64, P5 immutable)
            Space<'s>
```

Topological: User → Actor → Space → Entry → Activity. Cycle-free + depth-bounded. No mutual cycles.

### §4.7 ID generation convention (M2 redesign — collision grinding defense)

Runtime L1 `ctx.next_id::<K: EntityKind>(tick, seq) -> EntityId` — **deterministic + collision-resistant**.

**Input extension** (M2):
- `world_seed`: **L0 config 256-bit entropy, non-exportable**. Public exposure forbidden (inherits the L0 A13 path).
- Include `instance_id` — blocks cross-instance collisions.
- Include `kind_code` (K::TYPE_CODE) — separates ID namespaces between primitives.
- Final decision function:
  ```rust
  fn next_id<K: EntityKind>(instance_id: InstanceId, tick: Tick, seq: u32) -> EntityId {
      let key = blake3::derive_key("arkhe-forge-entity-id", world_seed);
      let mut h = blake3::Hasher::new_keyed(&key);
      h.update(&instance_id.get().to_be_bytes());
      h.update(&K::TYPE_CODE.0.to_be_bytes());
      h.update(&tick.0.to_be_bytes());
      h.update(&seq.to_be_bytes());
      // truncate 8 bytes → NonZeroU64 (if zero, recompute with seq++)
      let out = h.finalize();
      let raw = u64::from_be_bytes(out.as_bytes()[..8].try_into().unwrap());
      EntityId::new(raw).unwrap_or_else(|| next_id::<K>(instance_id, tick, seq + 1))
  }
  ```
- On SpawnEntity, L0 performs `(instance_id, entity_id)` collision detection — when the entity already exists, auto-increment `seq` fallback + regenerate the Op. Deterministic path preserved.
- Birthday bound: per-instance-per-kind ~2^32 IDs → collision probability ~1/2^32 per spawn. `world_seed` secrecy + `instance_id` scoping neutralize cross-instance grinding.
- The same `(instance_id, kind_code, tick, seq)` → the same ID (inherits L0 A1).

**Collision fallback responsibility boundary (R5 NF6)**: the `seq` auto-increment recomputation is owned by the **tail recursion inside L1 `next_id`** (`unwrap_or_else(|| next_id::<K>(..., seq + 1))`). L0 `SpawnEntity` only reports the collision — no L0 modification (not the 8 DO NOT TOUCH items, including `Principal`/`KernelEvent`/`StepStage` derives and WalRecord field order) provides the fallback. Even with adversary grinding on tick·seq combinations, `world_seed` (L0 config 256-bit non-exportable) secrecy + `instance_id` scoping make cross-instance attacks ineffective. Expected L1 recursion depth is 1 empirically (< 2^-32 collision probability) — with a hard cap of 16 attempts → `ActionError::IdExhaustion` Failure event.

### §4.8 Primitive summary card (auditor m1 duplicate removal — canonical TypeCode table is separate, see §3.2)

| # | Name | Identity | Core Component | Key Action | Invariant essentials |
|---|---|---|---|---|---|
| 1 | User | Runtime-wide identity | UserProfile / AuthCredential (KDF+salt) | RegisterUser | GDPR lease + L1 MC gate (§14.9) |
| 2 | Actor | per-shell activity subject | ActorProfile | CreateActor | `(shell, handle)` unique, typestate Auth/Anon, user_id/shell_id immutable |
| 3 | Space | Entry publication target / boundary | SpaceConfig / ParentChainDepth | CreateSpace | parent DAG depth ≤ 64, immutable parent, creator in same shell |
| 4 | Entry | persistent content atom | EntryCore / EntryBody | SubmitEntry | soft delete, depth ≤ 64, immutable parent/relay |
| 5 | Activity | actor→target verb | ActivityRecord (+status) | SubmitActivity / RetractActivity | Active idempotent, retract tombstone, meta depth ≤ manifest |

---

## §5. L1 ↔ L2 boundary

### §5.1 Inside L1

L1 only: Core 5 primitive Rust types, L0 TypeCode registration, `ActionCompute::compute` pure, referential integrity between primitives, ID generation, ShellBrand distribution.

Strictly forbidden in L1: HTTP/WebSocket/gRPC, PostgreSQL/Redis/S3/CDN, manifest parsing, rate limiting, `std::time::now`, `async`, `tokio`, `unsafe`.

### §5.2 Inside L2

L2 only: manifest TOML load + validation (§5.6), Hook host (v2 WASI — v1 alpha OFF), L4 request → caps → L1 Action → `Kernel::submit`, L0 observer registration → projection (§12.4 SLO), rate limit / quota, audit receipt, cascade scheduler (E11), **idempotency dedup (§14.8)**, GDPR erasure-cascade service (§14.9), DR coordinator (§14.11).

**R4' operational model**: active-passive L2 only + client-supplied idempotency key. Multi-active is a separate DIP.

Forbidden in L2: direct mutation of Kernel state, name-based dispatch, kernel re-execution of hook-originated cascades (§9.1).

**Primary backing store (R5 Axis 3 — team-lead directive 2026-04-24, unanimous among 4)**: **PostgreSQL**. Redis is an optional cache/queue at production scale.

| Function | PG primary | Redis fallback condition |
|---|---|---|
| Idempotency dedup | **2-layer (R5.2 mNF-A)**: (1) L2 PG `UNIQUE INDEX (idempotency_key) + INSERT ON CONFLICT DO NOTHING + expires_at TIMESTAMPTZ` + background TTL cleanup (partition drop) — fast pre-filter. (2) L1 WAL scan via `ctx.idempotency_lookup` (§3.3 / §14.8 FG6) — crash-recovery backstop (PG Redis loss scenario after passive promote). *R5.3 R7-NR4 footnote: the L1 path activates the tick-scoped auxiliary index only under L0 v0.13+. During Runtime v0.12 the PG UNIQUE INDEX is the single dedup path — the crash-recovery gap is covered by `docs/runbook/crypto-erasure.md` and the operator runbook.* | `SETNX` alternative when < 5ms SLA required. |
| Rate limit counter | `UNLOGGED TABLE` (restart loss permitted) + atomic `UPDATE ... RETURNING`. | Under production 10k+ user PG lock contention → Redis `INCR`. |
| Observer fanout | `LISTEN / NOTIFY` (payload ≤ 8KB, scales to hundreds of connections). | For beta+ multi-region pub-sub → Redis Streams. |
| Queue worker | `SELECT ... FOR UPDATE SKIP LOCKED`. | Redis Lists optional in production. |

**L4 adapter TLS obligation (R5.2 GF3)**: L2 verifies transport-layer security when registering an L4 adapter. Plaintext protocols (raw Telnet, plaintext HTTP, MQTT without TLS, etc.) are rejected by default — `L4AdapterError::TlsRequired`. Fine control via shell manifest `[frontend.tls_required]` (default `true`). Permitted bypass = dev/alpha `runtime_max ≤ "0.15"` + `tls_required = false` + permanent admin-dashboard warning (production reject). The BBS reference shell requires **Telnet-over-TLS (RFC 2946)** or stunnel wrap — see example in §15.5 deployment guide.

**Tiered deployment (aligned with §14.10)**:
- alpha (< 1k users, < 100 req/s): **PG-only recommended**. UNLOGGED + LISTEN/NOTIFY + single-DB operator learning curve.
- beta (1–10k users, < 1k req/s): PG primary + optional Redis (dedicated to idempotency/rate-limit).
- production (10k+ users, > 1k req/s): PG + Redis (cache/queue required, bypasses the §10.4 single-thread ceiling).

Basis for the cryptographer R5 recommendation: Redis CVE-2022-0543 RCE, Sentinel master election race, RedLock Kleppmann 2016 critique, ACL misconfiguration — PG `INSERT ON CONFLICT` is single-primary ACID with no split-brain. Reduced alpha security surface.

#### §5.2.1 Rate limit model — 3-axis token bucket (R5 veteran m-R5-2)

The Runtime rate limit composes three-axis token buckets:

| Axis | Key | Purpose | Default capacity / refill |
|---|---|---|---|
| per-actor | `(shell_id, actor_id)` | per-actor abuse defense | 60 tok / 60s |
| per-shell | `shell_id` | shell-wide throttle (DoS response) | manifest `[quota.shell_rps]` |
| per-IP | `client_ip` (L4 adapter provided) | anonymous-scrape defense | 30 tok / 60s |

Before compute entry, L2 must allow on all 3 axes to submit. Any reject → `429 Too Many Requests` + `arkhe_runtime_rate_limit_reject_total{axis, shell_id}` counter.

**Leak semantics**: tokens are a leaky bucket — fixed refill per second. Burst capacity is derivable from the expiry tick (L0 ticks are integers → deterministically computable).

**Storage tier** (aligned with PG-only tiered):
- alpha: `UNLOGGED rate_limit_bucket(key BYTEA PRIMARY KEY, tokens INT, last_refill_tick BIGINT)` table + atomic `UPDATE ... RETURNING`. Capacity loss on restart permitted (alpha SLA).
- beta+: keep the same table, or switch to Redis `INCR` + `EXPIRE` (manifest `[quota.storage_backend = "pg" | "redis"]`).
- production: Redis required — PG row lock contention absorbs the §10.4 single-thread ceiling.

**Cross-axis composition** (NC3 style): all 3 axes allow → 1-submit; any reject → full reject. Per-stage reject reasons are recorded in the audit log (operator diagnosis).

### §5.3 Data flow — hook confused-deputy defense (C8/S1/I2)

```
[Frontend/Client]
      │  X-Arkhe-Idempotency-Key: <UUID v4> (C6)
      ▼
[L4 Protocol Adapter]  ─ decode ─▶ [L2 Service API DTO]
                                         │
                                         ▼
                        [L2 Idempotency dedup (PG UNIQUE INDEX primary §14.8)]
                                         │  duplicate → return prior response
                                         ▼
                        [L2 Auth & Quota check]  ◄── caps resolve
                                         │  fail → reject
                                         ▼
                [L2 Hook host (extra_bytes only, v2+, OFF in v1)]
                                         │  hook result: modifies only &mut ExtraBytesBuilder
                                         │  (policy-invariant fields cannot be modified)
                                         ▼
                [L2 Policy re-validation]   ◄── re-validates after hook execution (C8 confused-deputy defense)
                                         │  rechecks manifest rule / mutex / visibility
                                         │  fail → reject + audit log
                                         ▼
                [L1 Action body build (with hook-appended extra_bytes)]
                                         │
                                         ▼
                        Kernel::submit(inst, principal, caps, ...)
                                         │
                                         ▼
                   ┌──────────── L0 Kernel ────────────────┐
                   │ authorize → Action::compute → Ops     │
                   │ → StepStage commit → WAL chain        │
                   └──────────────────┬─────────────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
            [WAL fsync]     [Observer fanout (shell_id filter S7)]  [InstanceView read]
                 │                    │
                 │                    ▼
                 │   [L2 Projection writer  (Prometheus SLO)]
                 │       ─ auto-restart (exp backoff 3×)
                 │       ─ catch_unwind + pool regen
                 │                    │
                 │                    ▼
                 │           [PostgreSQL primary + Redis optional (§5.2)]
                 │                    │
                 │                    ▼
                 │           [L4 Frontend push]
                 │
                 └──► [L2 cascade scheduler — tick+1 re-submit (E11)]
                 └──► [L2 GDPR erasure-cascade (§14.9)]
                 └──► [L2 Audit receipt issuance]
                 └──► [L2 DR coordinator — WAL streaming replication (§14.11)]
```

**Hook contract** (C8 / S1):
1. Hook execution order: Auth & Quota → **Hook (extra_bytes only)** → **Policy re-validation (rerun)** → Build → Submit.
2. A hook **cannot modify** policy-invariant fields (actor / verb / target / shell_id / principal). Only `&mut ExtraBytesBuilder` is exposed.
3. The hook result is folded into canonical bytes and submitted to the kernel as a single Action. The kernel never re-runs hooks. Replay determinism preserved.
4. After hook execution, policy re-validation rechecks the same manifest rules. If a hook inflates extra_bytes without bound, the size cap rejects.
5. Hook failure = L2 submit rejection + audit log.
6. v1 alpha: **all OFF** (§14.5).

### §5.4 L1-L2 mutual prohibitions

| Prohibition | Reason |
|---|---|
| L1 → L2 import | Strictly downward DAG (E3). |
| L1 → std::fs / net / time | A11 pure. |
| L2 → kernel state (submit bypass) | Disables A18/A20. |
| L2 → Component private field | A17 bypass. |
| L1 compute → HTTP/DB | A11. |
| L2 → shell-specific hardcode | Manifest + hook only. |
| Hook → policy-invariant field mutation | §9.1 / C8 confused deputy. |
| Hook → multiple submit | 1-shot + fold-in only. |
| Observer → bypass shell_id filter | S7 cross-shell metadata leak. |

### §5.5 Observer path — X5 / M-slo / S7 / P2

- L2 Projection writer = L0 observer, `OBSERVER_REGISTER` cap, `DOMAIN_EVENT_EMITTED` + `ACTION_EXECUTED` mask.
- **Shell filter obligation (S7)**: observer registration must specify `shell_id_filter: BTreeSet<ShellId>`. Events of shells outside the interest set are not dispatched. A single observer may subscribe to multiple shells, but the filter mask is declared publicly.
- L0 A18: observer drain after WAL fsync.
- L0 A22: an observer panic causes immediate eviction.

**Operational contract** (X5 + M9 per-tick atomic):
1. SLO `NOW() - last_applied_at < 30s` p99.
2. Auto-restart with exp backoff (2s / 8s / 32s) × 3. Three failures → operator page + `observer_dead=true`.
3. UnwindSafe: PG/Redis connections are not UnwindSafe → after `catch_unwind`, replace the entire connection pool. Hold only `Arc<Mutex<Pool>>`.
4. Cascade tick (E11 MC): L2 post-event cascade uses `Op::ScheduleAction { at: Tick(t+1), ... }` bound to the original Action tick `t`. L0 scheduler imposes a deterministic order.
5. **Per-tick atomic PG transaction (M9 / R5 NF7 replay inheritance)**: `BEGIN` at tick start, `COMMIT` at tick end. On panic → PG rollback → idempotent restart. `kernel_projection_state.last_applied_tick` is updated only at committed ticks (single transaction together with C3 chain_tip signature). Extension TypeCode validation runs as a validator **before** the projection write — on failure log+skip, never panic. Blocks the adversary path where malformed Extension bytes induce a writer panic → partial-state oracle. **The replay path inherits the same contract**: the tick stream supplied by L0 `replay_into` is wrapped in tick-level BEGIN/COMMIT by the L2 projection. Failed-validator records are explicitly inserted into the `unknown_variants` staging table (§12.4) + audit log — silent skip forbidden. Both replay/live paths are per-tick atomic: no "half-applied tick" state is permitted.

**Tick-scoped Component read cache (P2)**:
```rust
// L1 wrapper over the L0 InstanceView — within the same tick, identical (entity, TypeCode) reads share a single underlying lookup.
// BTreeMap<(EntityId, TypeCode), Arc<Bytes>> per-tick.
// Invalidated at tick boundaries (step boundary).
// Metric: arkhe_runtime_component_read_cache_hit_ratio.
```

For N=10^7 entities, `BTreeMap::get` O(log n) ≈ 23 — amortized to 1 by the cache.

### §5.6 Manifest Schema v1 — extensions (C5 / I3 / P1 / C2)

**Purpose**: the official schema for shell manifest TOML. unknown-key reject + schema_version required + **canonical TOML digest** pinned in the WAL header.

```toml
schema_version = 1                               # only value=1
shell_id       = "bbs"                           # [a-z0-9][a-z0-9_-]{1,30}
display_name   = "ArkheNet BBS"
version        = "0.1.0"
runtime_min    = "0.12"
runtime_max    = "0.x"

[typecode_allocation]
entity_range    = { from = 0x0100_0000, to = 0x0100_FFFF }
component_range = { from = 0x0101_0000, to = 0x0101_FFFF }
verb_sub_range  = "auto"                         # BLAKE3(shell_id) deterministic 256-verb
verb_range_nonce = 0                             # R5 NF10 — bump on collision (§3.2)

[actor]
naming_regex   = "^[a-z0-9_]{3,20}$"
handle_change_cooldown_days = 30
allow_anonymous = false

[space]
kinds_enabled  = ["Flat"]
tree_max_depth = 0
creation_policy= "AdminApprove"                  # AdminApprove | UserFree | InviteOnly

[entry]
title         = "Required"                       # Required | Optional | Disabled
body_max      = 65536
edit_grace_seconds = 600
attachment_max = 4
tags_max      = 5

[activity]
verbs_enabled = ["Like", "Follow"]
extra_bytes_max_bytes = 4096                     # P1 required, hard cap 65536
verb_cooldown_seconds = 10                       # C2 default, prevents retract abuse

[[activity.mutex_group]]
verbs         = ["Like", "Dislike"]

[activity.visibility]
Like     = "Public"
Bookmark = "Private"

[activity.notify_policy]
Follow   = "Push"                                # Push | Digest | None

[moderation]
scope             = "SpaceScoped"                # Global | SpaceScoped
appeal_sla_days   = 7
appeal_max_depth  = 2                            # I3 parametric (1..=8, default 2)

[hook]
enabled = false                                  # §14.5 v1 alpha OFF

# R5.2 GF3 — L4 frontend security requirements
[frontend]
tls_required     = true                          # default true. false only allowed when runtime_max ≤ "0.15"
alpha_credential_rotation_required = true        # R5.3 HF4 — AuthCredentials created during alpha must be rotated + sessions invalidated on beta promote

# R5 C-R5-5 — audit / crypto-erasure backend composition
[audit]
signature_class  = "Ed25519"                     # "Ed25519" | "MlDsa65" | "Hybrid"
dek_backend      = "hsm"                         # "hsm" | "kms" | "software-kek"
dek_replication  = "global-hsm"                  # "global-hsm" | "per-region"
pii_cipher       = "xchacha20-poly1305"          # "xchacha20-poly1305" (default) | "aes256-gcm" | "aes256-gcm-siv"
kms_auto_promote = "manual"                      # "manual" (default) | "after_60min" (R5.2 m-R6-2)

# R5 Axis 3 — storage tier
[quota]
shell_rps        = 200                           # per-shell token bucket capacity
storage_backend  = "pg"                          # "pg" (default alpha/beta) | "redis" (beta+/production)

# M1 — L2 active writer same-tick ordering. Timing-critical shells use "commit_reveal".
[shell]
ordering_policy = "fifo"                         # "fifo" (default) | "commit_reveal"

# M3 — Tick-timing cross-shell covert channel defense.
[projection]
tick_visibility = "precise"                      # "precise" (default) | "coarse" | "none"
# coarse: 1000-tick bucket + internal order shuffle (exposed values only; WAL origin stays precise)
# none:   Band 3 sessions expose only in bulk after session close
# precise: existing scheme (default for public shells)

# optional shell deprecation marker (veteran N4 / §14.7 shell sunset)
# [deprecated]
# at_tick     = 123456789
# reason      = "superseded by bbs-v2"
```

**Validation**:
- `schema_version` required; only `1` currently valid.
- Unknown top-level / section key → reject (strict parser).
- Values outside the canonical enum → reject.
- Regex validity.
- Cross-reference: `[activity.mutex_group]` verbs ⊆ `verbs_enabled`.
- `extra_bytes_max_bytes` ≤ Runtime hard cap 65536 (P1).
- `appeal_max_depth` ∈ [1, 8] (I3).
- `ordering_policy` ∈ {"fifo", "commit_reveal"} (M1).
- `tick_visibility` ∈ {"precise", "coarse", "none"} (M3).
- **R5 PQC timeline enforcement (C-R5-5b)**: when `runtime_max ≥ "0.30"`, `[audit.signature_class] ∈ {MlDsa65, Hybrid}` is enforced. Ed25519-only → `ManifestError::PqcTimelineViolation` parse error. During the 2027–2029 transition (`0.16 ≤ runtime_max < 0.30`), Ed25519-only shells carry a **warning flag** + marketplace UI exposure. The `arkhe-runtime-doctor pqc-timeline-audit` command produces a PQC-readiness dashboard across all shells.
- **R5 software-kek constraint (C-R5-5a — team-lead directive 2026-04-24, strengthened by R5.2 GF1)**: `[audit.dek_backend = "software-kek"]` is valid only when **both** conditions hold:
  1. Shell manifest `runtime_max ≤ "0.15"` (alpha milestone).
  2. **Runtime binary `runtime_current` version ≤ "0.15"** (R5.2 GF1 blocks production leak).
  When a production runtime binary (`runtime_current ≥ "0.16"`) encounters a manifest declaring `dek_backend = "software-kek"` → LOAD stage `ManifestError::SoftwareKekProductionRefused` parse error. Even if an adversary selectively declares a shell manifest's `runtime_max = "0.15"`, the production runtime rejects. On successful declaration, publish a permanent warning tag `arkhe_runtime_software_kek_alpha_mode=true` metric to dashboards/audit logs. Not a ≤1k-user / GDPR Art.17 empirically-validated environment.
- **R5.2 GF2 AeadKind downgrade defense**: changes to shell manifest `[audit.pii_cipher]` **require a VerbCode-level schema_version bump**. Existing ciphertexts are kept under the old cipher (dispatched via wire `aead_kind` field); only new writes use the new cipher. `EncryptedPii<T>::decrypt()` verifies that the ciphertext's `aead_kind` matches the manifest `pii_cipher` at the time the record was created — mismatch → `PiiError::CipherDowngrade`. Same rule wired to §9.1 hook principle.
- **R5 verb_range_nonce (NF10)**: `[typecode_allocation.verb_range_nonce]` is `u32` (default `0`). `blake3::derive_key("arkhe-forge-verb-alloc", shell_id_bytes || nonce.to_be_bytes())` deterministic retry (§3.2). On collision detection, bump the nonce — the registry pin (A15) uses the confirmed nonce value.
- **shell_id homograph phishing defense (m1)**: when registering a new shell_id, Levenshtein distance ≥ 2 against already-registered shell_ids is a soft guideline (warning, not forced reject). `display_name` is a separate field — UI confusion is first defended by display_name uniqueness.

**Canonical TOML digest (C5)**:
- BLAKE3 over raw TOML bytes is **forbidden** (comment/whitespace drift).
- Approach: use the `toml_edit` crate or an in-house canonicalizer to parse → canonical serialize (sorted keys, normalized whitespace, comments removed) → BLAKE3 over canonical bytes.
- Result: pinned in WAL header as `manifest_digest: [u8; 32]` (A14 extension).
- Replay mismatch → `ReplayError::ManifestDigestMismatch`.
- `arkhe-runtime-doctor` provides a `manifest-digest-recompute` command (§14.7).

**Hot-reload not supported in v1** (veteran C1). Change = process restart + WAL resume. Lifecycle: `LOADING → VALIDATED → ACTIVE → DRAINING → UNLOADED`.

---

## §6. Activity generalization design

### §6.1 verb = TypeCode

A naive `enum Verb` is rejected (Open-Closed violation). Adopted: `VerbCode(TypeCode)` + const generic range partitioning. Type-erased `VerbCode` for storage.

### §6.2 verb range (M-verbrange final)

- Canonical: `0x0002_0001..=0x0002_03FF` (1023). 8 currently in use.
- Shell: `0x0002_0400..=0x0002_FFFF` (64,512). Deterministic BLAKE3-derived 256-verb sub-range per shell.
- Central registry `runtime-typecode-allocations.toml` (distributed with the Runtime crate).
- A change to the `extra_bytes` format obligates a new VerbCode allocation (M-schemaver-verb). Existing VerbCodes are schema_hash-pinned.

### §6.3 Reaction / Subscription / Follow / Report unification

| Original concept | Activity representation | Rationale |
|---|---|---|
| Reaction | verb=Like/... target=Entry | storage/query identical |
| Subscription | verb=Follow target=Actor/Space/Activity | WAL pattern identical |
| Follow | verb=Follow target=Actor | — |
| Report | verb=Report extra_bytes=reason_hash | workflow = verb + appeal chain |
| Bookmark | verb=Bookmark private | — |
| Mute/Block | verb=Mute/Block actor scope | — |
| Appeal | verb=Report target=Activity meta-verb | depth ≤ manifest (E9) |

### §6.4 Mapping to engine.md 13-primitives (X3 DM correction)

| engine.md primitive | R4' decision |
|---|---|
| Identity (User) | Core 5 #1 |
| Actor | Core 5 #2 |
| Space | Core 5 #3 |
| Entry | Core 5 #4 |
| Reaction / Subscription / Follow / Report | Activity verb |
| Relay | Entry variant (relay_of) |
| DirectMessage | `Space(kind=Flat, visibility=PrivateInvite, creator=sender) + SpaceMembership{members: {sender, recipient}} + Entry`. Primitive promotion only after 3-shell empirical evidence. |
| Room | **Separate primitive (follow-up DIP)** — §8.1 / §14.1 |
| Attachment/Media | Axis 1 Component — §8.2 |
| Playback | Activity verb(PlaybackCheckpoint) + scale issue deferred to R5 |
| Collection | Space.kind=Collection + Activity(Pin) |
| Moderation | Activity(Report) + meta-verb appeal + L2 ModerationAction |
| Gateway | Outside the Runtime — L4 proxy |
| AuditReceipt | L2 service (`RuntimeSignatureClass` §14.7) |

### §6.5 Mutex / visibility / notify / cooldown

Shell manifest `[activity.*]` (§5.6). L2 policy validation then kernel submit. The kernel sees only `SubmitActivity`.

---

## §7. Four extension axes

### §7.1 Axis 1 — Component

`#[derive(ArkheComponent)]` + shell-scoped TypeCode (manifest `[typecode_allocation.component_range]`). Inherits: A1, A11, A15, A17.

### §7.2 Axis 2 — TypeCode (verb / event / action)

`ArkheAction` / `ArkheEvent` derive over a shell-scoped range. A verb uses `ShellVerb<const C>` const assertion. A change to the extra_bytes format requires a new VerbCode. Inherits: A9, A11, A15, A17.

### §7.3 Axis 3 — Subtype

Variants of the `Extension { type_code: TypeCode, ... }` enum inside a primitive. Manifest load precedes use + A15 pin. Semantic validation is L2's responsibility. Runtime invariants default to safe.

### §7.4 Axis 4 — New-Primitive gate

One of 4 gates + evidence from 2+ shells:

| Gate | Question |
|---|---|
| (a) Lifecycle | Is the existing primitive lifecycle insufficient? |
| (b) Auth model | Is the existing Principal/Capability insufficient? |
| (c) Scale/query | Table explosion in the existing model? |
| (d) WAL policy | Fundamentally different recording policy? |

Procedure: RFC → Runtime semver bump → DIP R1-R4' → clean rounds → core addition.

**R4' currently adds none**. See §8 analysis.

### §7.5 Extension axis selection flowchart

```
 New feature request
       │
       ▼
 Existing primitive Component field? ──────── YES ─▶ Axis 1
       │ NO
       ▼
 Existing primitive extra_bytes + L2 hook? ── YES ─▶ Axis 2 (schema pin)
       │ NO
       ▼
 New verb/event/action type? ──────────────── YES ─▶ Axis 2
       │ NO
       ▼
 Extension variant of a primitive enum? ───── YES ─▶ Axis 3
       │ NO
       ▼
 4-gate + 2+ shell evidence? ──────────────── YES ─▶ Axis 4 RFC
       │ NO
       ▼
 Reject from Runtime core — shell-level
```

### §7.6 Anti-patterns

- "Might be useful in the future" — gate not met, rejected.
- "One shell wants it" — fails the 2+ shell rule, rejected.
- "Cannot attach a field to an existing primitive" — Axis 1 not considered, rejected.

---

## §8. Follow-up primitive candidates — Gate analysis

### §8.1 Room — real-time chat

Gates (a, c, d) — 3. Evidence from 2+ shells (BBS conversation rooms + TubeLike live + GuildChat). **R4' verdict**: **Separate primitive, follow-up DIP** (held since R3). The R1 draft "Entry(Ephemeral) + Activity(Say)" alternative is withdrawn (tuple idempotency collision). Runtime semver v0.12 → v0.13.

### §8.2 Attachment — Axis 1 Component

Gate (c) — 1. **Retained as Axis 1**. `EntryAttachments { refs }` + `entry_attachment_refs` extension table. sha256-based duplicate detection projection.

### §8.3 Session/Turn/Round — shell-scoped + Band 3

Gates (a, b, d) — 3. Insufficient 2+ shell evidence (Casino only). **Shell-scoped own implementation** permitted. A Band 3 `Band3Message` marker trait (§9.3) — no axiom promotion. Re-evaluate once a second game shell provides evidence.

### §8.4 MMORPG / real-time games — rejected

Gates (c, d). **Rejected from the Runtime core** (§1.2). Separate DIP: "game-kernel overlay" architecture. Consider ArkheForge + game-kernel side-car in v0.99+. Currently the Runtime makes no promise in this area.

### §8.5 SpaceMembership primitive gate — auditor N5

**Identity**: the set of actors participating in a Space. In R4' §4.3 it is retained as a Component accompanying SpaceConfig.

**Gate**:
- (a) Lifecycle — same persistence as Space. Fail.
- (b) Auth — existing cap is sufficient. Fail.
- (c) Scale — in a single space where member count reaches critical scale (e.g. 10k+ public groups), the BTreeSet may explode. Partial (depends on shell policy).
- (d) WAL — existing SetComponent suffices. Fail.

**Verdict**: Axis 1 Component retained. Not a follow-up primitive candidate. When the Room primitive follow-up DIP proceeds, re-evaluate whether to absorb membership into Room (Room is likely to include membership itself).

### §8.6 Summary of follow-up candidates

| Candidate | Gate | Evidence | R4' verdict |
|---|---|---|---|
| Room | a, c, d (3) | 3 shells | Separate primitive, follow-up DIP |
| Attachment | c (1) | 3 shells | Axis 1 retained |
| Session/Turn/Round | a, b, d (3) | 1 shell | shell-scoped + Band 3 marker |
| MMORPG tick-sync | c, d | — | Scope rejected, separate DIP overlay |
| SpaceMembership | — | 1 shell (R3 correction) | Axis 1 retained, re-evaluate together with Room |

---

## §9. Determinism boundaries — 3-band

### §9.1 Band 1 — Core Deterministic (direct L0 A1 lineage) + reinforced hook principles

**Guarantee**: the same config + postcard-canonical Action sequence + manifest → bit-identical WAL + snapshot.

**Scope**: all Core 5 Actions, all compute `Vec<Op<'i>>`, Component canonical_bytes, L0 Event emission.

**External input**: time/random/network must not enter Band 1 compute. L2 normalizes canonical bytes and folds them into the Action body before submit.

**Hook principles** (X2 / C8 / S1 reinforcement):
1. A hook is **1-shot pre-submit**. It may only modify `&mut ExtraBytesBuilder` (policy-invariant fields are immutable).
2. The result is folded into canonical bytes and submitted to the kernel as a single Action.
3. The kernel never re-executes the hook. Replay determinism preserved.
4. After hook execution, **policy re-validation** rechecks manifest rules (confused-deputy defense).
5. Hook failure = L2 submit rejection + audit log.
6. v1 alpha: all hooks OFF (§14.5).

**Cascade tick** (M-tick / E11 MC): L2 post-event cascade is an `Op::ScheduleAction { at: Tick(t+1), ... }` bound to the original Action's tick `t`. L0 scheduler imposes a deterministic order.

**Shell manifest change principle (R5.2 GF2 extension)**: changes to `[audit.pii_cipher]` / `[audit.signature_class]` / `[audit.dek_backend]` **require a VerbCode-level schema_version bump** — existing ciphertext/receipts remain under the old value (dispatched via wire tag); only new writes use the new value. Hot-swap is forbidden. The time of change is recorded with a chain-anchored event each (`SignatureClassPolicy` §14.7 E13 / consider introducing a similar PolicyEvent). Verifiers trust the chain-anchored policy, not the message tag.

### §9.2 Band 2 — L2 Projection (non-deterministic derivation)

Given the WAL, the L2 projection is reconstructed eventually consistent. Not bit-identical.

Scope: PostgreSQL, Redis, WebSocket fan-out, rate-limit counters. On projection corruption, re-derive from the WAL.

### §9.3 Band 3 — Protocol-Correctness Only (shell-level)

The kernel WAL is a valid protocol message sequence. State values cannot be bit-identically replayed.

Scope: Casino Mental Poker, E2E DM plaintext, threshold commit/reveal vote.

**Runtime core scope refusal (C4 team-lead option B 2026-04-24)**:

> **The Runtime core does not guarantee phase ordering / correctness / collusion resistance of Band 3 protocols. A Band 3 shell takes 100% responsibility for its own phase FSM, `arkhe-<shell>-verify` audit tool, and L2 active writer strict FIFO. The `Band3Message` marker trait (now replaced by the `#[arkhe(band = 3)]` attribute — NC3) is merely a type-level hint for routing.**

Rationale: enforcing phase ordering in a commit-reveal protocol (e.g. requiring Bob Commit to precede Alice Reveal) at L1 compute would require adding a "phase Component" + "action sequence guard" at the core primitive level. Insufficient 2+ shell evidence (Casino only) + conflict with §1 "refuse generality" principle. Therefore currently out of scope.

Officially registered as a **v0.13 DIP candidate** in §14 / §15.3 — once E2E DM, threshold vote, and Casino each have 3-shell evidence, a core promotion DIP for `BandThreePhase` Component + `Band3Action::required_phase()` compile-time enforcement will proceed.

**Band 3 shell audit checklist (C4 / §8.5 linkage)**: shell implementers own the defense against the following violation categories.

| Violation type | Description | Shell defense |
|---|---|---|
| commit-before-reveal | Reveal occurs before the counterpart's commit | Phase Component FSM — state transition guard |
| late reveal | Reveal after the deadline | Deadline tick cap + expiry Action |
| player collusion | Out-of-band collusion | Protocol design responsibility (outside engine scope) |
| phase skip / double-commit | Skipping FSM steps | Action guard: `if phase != Expected { reject }` |
| threshold cutoff manipulation | Threshold recomputation attack | Merkle-pinned threshold + commit-phase lock |

The Casino shell (`arkhe-casino`) provides its own `CasinoPhase` Component + `arkhe-casino-verify` audit tool — shell-scoped (§7.1 Axis 1).

**R5 R5-r5 — shell verifier chain-attestation requirement**: a Band 3 shell's audit tool (`arkhe-casino-verify` etc.) binary must itself ship as **chain-attestation**: (a) binary BLAKE3 digest + (b) Ed25519 / PQC operator signature + (c) transparency log (Sigstore/Rekor, or an in-house Merkle + periodic publish) entry. The Runtime manifest `[shell.verifier_attestation]` pins the digest + log index → only approved verifiers may produce trusted audit output. This blocks the path where an adversary ships a malicious verifier to forge a "pass" result. When §15.4 v0.13 DIP is promoted, the `Band3VerifierAdapter` trait interface will include an attestation verification API.

**Band attribute (NC3 adopted)**:
```rust
// A band attribute on Action derive — one Band per Action.
#[derive(ArkheAction)]
#[arkhe(type_code = ..., schema_version = 1, band = 1)]     // Band 1 (default)
pub struct SubmitActivity { ... }

#[derive(ArkheAction)]
#[arkhe(type_code = ..., schema_version = 1, band = 3)]     // Band 3
pub struct CasinoShuffleMessage { ... }
```

The ArkheAction derive reads the band attribute and auto-attaches the appropriate sealed marker trait. The standalone `Band3Message` trait is removed (NC3 integration).

### §9.4 Band-boundary red alerts

| Signal | Meaning |
|---|---|
| Core primitive Action uses rand/time | Band 1 violation of A11. |
| L2 projection bypasses WAL and writes | Band 2 → 1 contamination. |
| Shell Band 3 protocol injected into core primitive | Band boundary collapse. |
| Replay depends on PostgreSQL state | DAG inversion. |

### §9.5 Band summary (reflecting NC3 attribute)

| Band | Guarantee | Storage | Examples | Action attribute |
|---|---|---|---|---|
| 1 Core Deterministic | bit-identical replay | Kernel WAL | RegisterUser, SubmitActivity | `#[arkhe(band = 1)]` (default) |
| 2 L2 Projection | eventually consistent | PostgreSQL, Redis | reaction_count, timeline cache | (observer, not Action) |
| 3 Protocol-Correctness | protocol validity only | Kernel WAL (message bytes) | Mental Poker, E2E DM | `#[arkhe(band = 3)]` |

---

## §10. Rust type system limits

### §10.1 Compile-time invariants preserved

| L0 invariant | Runtime application |
|---|---|
| A2 `Kernel: !Sync` | Runtime dispatcher is `!Sync`. |
| A3/A19 `Effect<'i>` | L1 Action signatures thread `'i`. |
| A4 `#![forbid(unsafe_code)]` | Inherited by the Runtime crate. |
| A5 BTreeMap only | L1 `BTreeMap<TypeCode, ...>`. |
| A6 NonZeroU64 IDs | Every Id wraps it (private field). |
| A7 Principal exhaustive | L2 match is exhaustive. |
| A9 CapabilityMask | L2 manifest → caps. |
| A11 pure | `ActionCompute::compute` + `#[kernel_pure]`. |
| A15 TypeCode × schema_hash | WAL header `type_registry_pins` + `manifest_digest` + `runtime_semver`. |
| A17 postcard canonical | Runtime Component/Event/Action. |
| A20 StepStage | multi-Op atomic. |
| **Runtime new** | ShellBrand `'s` invariant-variance — multi-shell isolation (submit-site compile-time, replay/admin double-defense). |

### §10.2 Points where guarantees weaken

#### §10.2.1 Verb / shell-scoped dispatch

There is no verb-specific logic at L1. Policy lives in the L2 manifest + hooks. **L1 is fully static**.

#### §10.2.2 L2 Hook dispatch — M-hook-traitbound / C8

```rust
pub trait ShellHook: 'static {
    /// Extra-bytes only. Policy-invariant fields cannot be modified.
    /// 10ms CPU budget hard timeout. No blocking/async.
    /// Send + Sync removed — aligned with L0 A2 single-thread.
    fn pre_submit_activity(
        &self,
        req: &SubmitActivityReq,          // read-only view of policy-invariant fields
        builder: &mut ExtraBytesBuilder,  // only mutable surface
    ) -> Result<(), HookError>;

    fn pre_submit_entry(
        &self,
        req: &SubmitEntryReq,
        builder: &mut ExtraBytesBuilder,
    ) -> Result<(), HookError>;
}

/// The extra_bytes builder a hook appends to.
pub struct ExtraBytesBuilder {
    buffer: Vec<u8>,
    max_bytes: usize,                     // manifest extra_bytes_max_bytes
}
impl ExtraBytesBuilder {
    pub fn append_canonical<T: CanonicalEncode>(&mut self, value: &T) -> Result<(), HookError>;
}
```

**v1 alpha: all hooks OFF** (§14.5). v2 uses WASI.

#### §10.2.3 Shell Manifest runtime on/off

Core 5 are all registered with the kernel at compile time. on/off is L2 policy (reject at submit). L1 is always active. No dyn dispatch.

#### §10.2.4 Multi-shell brand operation (integrates I1 ergonomics)

`ShellBrand<'s>` provides submit-site compile-time isolation. Per-path handling is specified in §3.7.

**Multi-shell entry-point example** (representative boilerplate):
```rust
fn run_shell_bbs<F>(f: F) where F: for<'s> FnOnce(ShellBrand<'s>) {
    let brand = ShellBrand::<'_>::__new();
    f(brand);
}

// Usage:
run_shell_bbs(|brand_bbs| {
    let alice = Actor::<'_, Authenticated>::fetch(brand_bbs, alice_id);
    let entry = Entry::<'_>::fetch(brand_bbs, entry_id);
    let activity = Activity::new(brand_bbs, ActivityRecord { ... });
    submit(SubmitActivity::from_branded(activity));
});
```

Same pattern as L0 R5-T1 brand — boilerplate is absorbed by an HRTB closure wrapper. `arkhe-runtime-admin::BrandedAccess::enter` provides the standardized wrapper.

### §10.3 Summary of Rust type limits

| Point | Static? | Basis |
|---|---|---|
| L0 Kernel surface | ✓ | Unchanged |
| L1 `ActionCompute::compute` | ✓ | sealed + derive + `'i`/`'s` |
| L1 Component canonical_bytes | ✓ | ArkheComponent sealed + postcard |
| L1 Activity verb dispatch | ✓ | No verb-specific logic |
| L1 VerbCode range | ✓ | const generic `CanonicalVerb<C>` / `ShellVerb<C>` |
| L1 TypeCode registry | Partial | runtime BTreeMap, A15 structure determinism |
| L2 Shell Hook dispatch (v2+) | ✗ `dyn` | manifest runtime registration |
| L2 Projection writer | ✗ `dyn` | observer trait object + catch_unwind |
| L2 Manifest loader | ✓ | TOML strict + canonical digest |
| Submit-site Actor/Entry/Activity isolation | ✓ | ShellBrand compile-time |
| Replay/admin Actor/Entry/Activity isolation | Partial | compute MC double-check |

### §10.4 Throughput estimate — M-throughput / m2 context

- Upper bound for a single Runtime instance (L0 A2 single-thread): **p99 < 5ms/Action → ~200 Action/sec/instance**.
- Capacity: 1k active users × avg 0.2 Action/sec → ~1k users / instance.
- **The single-thread constraint is the cost of inheriting L0 A2 determinism**. Alternatives:
  - (a) Shard by shell_id — separate kernel instances (§14.10 Option A).
  - (b) Split stateless reads into L2 (§14.10 Option C).
  - Multi-thread primitive dispatch abandons determinism — out of Runtime scope.
- 10k+ concurrent users: see §14.10 Scaling Path.
- Prometheus `arkhe_runtime_action_duration_seconds` histogram (§12.4).

---

## §11. Axiom E-series — inheriting L0 A1-A24

### §11.1 Foundation

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E1** | Runtime core primitive set = {User, Actor, Space, Entry, Activity}. Additions require the §7.4 gate + a Runtime semver bump. | A15 | MACHINE-CHECKED |
| **E2** | Every Runtime Action `compute` inherits A11 pure. No I/O/rand/time. Hooks are pre-submit 1-shot + fold into canonical_bytes → the kernel never re-runs them + post-hook policy re-validation (§9.1). | A11 | MACHINE-CHECKED |
| **E3** | Runtime → L0 is strictly downward, one-way. L1 → L2 import is forbidden. | L0 R4-X | MACHINE-CHECKED |

### §11.2 Identity & multi-shell isolation (E7 dual-tier — B1)

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E4** | UserId is globally unique across the Runtime. ActorId is `(shell, handle)`, shell-unique. | A6 | TYPE-PROVEN |
| **E5** | Actor.user_id **and** Actor.shell_id are immutable after creation. SetComponent modifications are rejected. | A17 | MACHINE-CHECKED |
| **E6** | `Actor<_, Authenticated>` requires `UserBinding`. No `Actor<_, Anonymous>` exists. Typestate. | A11 | TYPE-PROVEN |
| **E7** | Shell isolation: an Activity `(actor, target)` / Entry `(author, space)` share the same shell. **Dual-tier**: (a) submit-site `ShellBrand<'s>` compile-time (TYPE-PROVEN). (b) Replay/admin compute `ctx.authenticated_actor_shell(actor) == target.shell_id` MC (RUNTIME-ASSERTED fallback). | A3, A19 | **TYPE-PROVEN (submit) + RUNTIME-ASSERTED (replay)** |

### §11.3 DAG integrity

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E8** | `Entry.parent_entry` / `Space.parent_space` are cycle-free **and depth ≤ 64**. O(1) via a depth Component cache. Parent is immutable after creation (P5). | A11 | MACHINE-CHECKED |
| **E9** | Activity self-loop is blocked + meta-verb depth ≤ `manifest.moderation.appeal_max_depth` (1..=8, default 2). Runtime hard cap 8. L1 compute MC. | A11 | MACHINE-CHECKED |

### §11.4 Federation-ready ID & cascade

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E10** | `ArkheUri<K: EntityKind>` is a 3-tuple `(instance, shell, local)` — only kind is phantom; the rest is runtime data. In a single instance, instance defaults. | A14 | TYPE-ADJACENT |
| **E11** | L2 post-event cascade re-submit uses `Op::ScheduleAction { at: Tick(t+1) }` bound to the original tick `t`. L0 scheduler imposes a deterministic order. | A23 | MACHINE-CHECKED |
| **E12** | The Runtime's `(runtime_semver, manifest_digest)` is chain-anchored via an in-band `RuntimeBootstrap` event in the WAL. On replay, a mismatch between the bootstrap event and the current load → `ReplayError::ManifestDrift` reject. The sidecar approach is retired — L0 chain-hash integrity is inherited to block backup-rewrite attacks (C2). | A1, A13 | MACHINE-CHECKED |
| **E13** | A shell's `[audit.signature_class]` is chain-anchored via an in-band `SignatureClassPolicy` event in the WAL. Audit receipts issued after the tick at which a given shell declared Hybrid must be Hybrid-signed — Ed25519-only receipts are rejected (blocks PQC Hybrid downgrade attacks, FG5). The verifier judges the message tag based on the shell-per-tick snapshot of `SignatureClassPolicy`. | A13, A14 | MACHINE-CHECKED |

**C3 vs C2 role separation (R5 NF9)**:
- **C2 (E12 WAL-level)** — **in-band events** such as `RuntimeBootstrap` / `SignatureClassPolicy` / `UserErasureCompleted` are included in the L0 chain hash (A13). Responsible for the integrity / anti-rewrite of the WAL itself. Tampering is detected by recomputing the chain during replay.
- **C3 (§12.4 projection-level)** — `kernel_projection_state.chain_tip_signature` signs **L2 projection rows** with Ed25519. Separate from the WAL, this detects tampering of the projection snapshot stored in PG. On restart/restore, MC compares the projection chain_tip against the L0 InstanceView chain tip.

The two paths are orthogonal: C2 is WAL bit-stream integrity, C3 is projection value integrity. Compromise scenarios separate — if only C2 breaks, chain hash mismatch is detected immediately; if only C3 breaks, recover by rebuilding the projection (the WAL is intact); if both break, restore from a backup snapshot.

### §11.5 Enforcement Tier distribution (recomputed at R5.1 / maintained through R5.2 / R5.3 / R5.4 — includes E13, includes E-act-7)

**Counting convention (R5 NF1)**: `E1-E13` are 13 distinct axiom IDs — `E7` (dual-tier) / `E-act-2` (dual-tier) are **counted as 1 axiom**, but the enforcement tier table records them as **a submit slot + a replay slot = 2 slots**. Therefore the total slot count in the tier table exceeds the axiom count.

**Runtime E-axioms (E1-E13, 13 items)**:

| Tier | Slots | Members |
|---|---:|---|
| MACHINE-CHECKED | **9** | E1, E2, E3, E5, E8, E9, E11, E12, E13 |
| TYPE-PROVEN | **3** | E4, E6, E7-submit |
| TYPE-ADJACENT | **1** | E10 |
| RUNTIME-ASSERTED | **1** | E7-replay (dual-tier fallback) |
| SOCIAL-CONTRACT | **0** | — |

Total slots 14 = 13 axioms + 1 extra dual-tier slot (E7).

**E7 change (R3 → R4')**: single MC → dual-tier (TP submit + RA replay). Removing the `SubmitActivity<'s>` lifetime lost the compile-time guarantee on the storage path; the compute MC double-defense compensates. Submit remains TP (ShellBrand). Extension targets gain compute MC (R4'.1 C1).

**E12 introduced (R4'.1 cryptographer C2)**: the sidecar-metadata approach is retired — on backup compromise, rewriting the sidecar could keep the chain hash while swapping `manifest_digest` → tampering with `SpaceKind::Extension` semantics. Instead, record `RuntimeBootstrap` as an in-band `Op::EmitEvent` → it is automatically included in the L0 chain hash. Respects DO NOT TOUCH #8 (WalRecord postcard field order) — integrity without modifying L0.

**E13 introduced (R5.1 cryptographer FG5)**: blocks `SignatureClass` downgrade attacks. An MC gate refuses Ed25519-only receipts after the tick at which a shell declared Hybrid — verifiers reconstruct a shell-per-tick snapshot from the `SignatureClassPolicy` events in the WAL and trust only the **chain-anchored policy**, not the message tag.

**Per-primitive invariants** (E-user-* 4 + E-actor-* 5 + E-space-* 7 + E-entry-* 7 + E-act-* 7 = **30 items**):

| Tier | Slots | Members |
|---|---:|---|
| MACHINE-CHECKED | **25** | E-user-1/2, E-actor-1/3/5, E-space-1~7, E-entry-1~7, E-act-1/4/5/6/7, E-act-2-Extension-submit (NF2 dual-tier submit slot) |
| TYPE-PROVEN | **3** | E-user-4 (A6 NonZeroU64), E-actor-2 (typestate), E-actor-4 (`'s` brand) |
| TYPE-ADJACENT | **1** | E-act-3 (extra_bytes opaque) |
| RUNTIME-ASSERTED | **2** | E-user-3 (GDPR cascade SLA §14.9), E-act-2-replay (dual-tier fallback) |
| SOCIAL-CONTRACT | 0 | — |

Total slots 31 = 30 invariants + 1 extra dual-tier slot (E-act-2 Extension submit MC + replay RA, per NF2 counting convention).

**Total 43 Runtime axioms/invariants** (E1-E13 + per-primitive 30). Progression R2 → R3 → R4' → R4'.1 → R5.1 → R5.2:
- R2→R3: E7 MC → dual-tier (honesty).
- R3→R4': E9 parametric (I3) / E-act-1 C2 re-statement / E-user-3 compute gate C3 / E-space/entry 7-7 extension P5.
- R4'→R4'.1: E12 introduced (in-band RuntimeBootstrap, sidecar retired) / E-act-2 Extension MC extended (C1, dual-tier retained) / E-user-3 crypto-erasure SLA extended (M5).
- R4'.1→R5.1: **E13 introduced** (SignatureClassPolicy chain-anchored, blocks PQC downgrade) / **E-act-7 introduced** (EntityShellId immutable, R5-r1) / `RuntimeSignatureClass` kept as a separate Runtime enum to protect L0 DO NOT TOUCH #3 (M-R5-1).
- **R5.1→R5.2**: **no change** to axiom / invariant counts. Existing tier slots retained. Additions are at the level of policy / runbook / type traits (sealed PiiType) / event structs (`PerRegionErasureProgress` 0x0003_0F08) / manifest validation — no axiom expansion. `E-user-3` RA's SLA scope is made concrete for multi-region 2PC (GF4) but the tier stays RA. `E13`'s MC enforcement scope extends to the `aead_kind` + `pii_cipher` manifest-anchored check (GF2) — tier stays MC.
- **R5.2→R5.3**: **no change** to axiom / invariant counts. 43 items / 45 slots unchanged. Reflects R7 Major 3 + Minor 12 at the level of policy (`alpha_credential_rotation_required` / auto_promote trust model) / trait sealed (`ArkheEvent` made explicit) / derive attribute opt-in (`#[arkhe(canonical_sort)]`) / metrics (`arkhe_runtime_event_total` / `kms_health_channels`) / event struct wire refinement (`PerRegionErasureProgress.scope: ProgressScope`, N=64) / runbook deliverables. Tier slots and axiom statements are unchanged. Minor 3 deferred (see §1.5 R7 section).
- **R5.3→R5.4**: **no change** to axiom / invariant counts. 43 items / 45 slots unchanged. After R8 verification (Critical 0 / Major 0 / 5 new Minor), a leader-housekeeping micro-patch — L0 version notation consistency (§14.8 `L0 v0.12+` → `L0 v0.13+`) / 2 SLO table rows (GdprPolicyViolation rate + kms_health_channels N-of-M) / alpha-to-beta-promote runbook deliverable registration / new v0.12 implementation tracking table (HF1 platform abstraction + HF4 manifest bypass audit). No impact on spec body structure / axioms / the 8 DO NOT TOUCH items. N=2 consecutive clean achieved.

### §11.6 "Non-axioms" — intentional blanks

- No Band 2/3 axiom — policy / marker attribute (§9).
- No Actor signature axiom — shell choice.
- No rate-limit axiom — L2 policy.
- No federation protocol axiom — E10 is an ID structure.
- No MMORPG tick-sync state axiom — scope refusal.

---

## §12. PostgreSQL projection schema overview

### §12.1 Design principles

1. Core tables carry generic names.
2. Multi-tenant `shell_id TEXT NOT NULL`.
3. Shell extensions: `shell_payload JSONB` (top-level key == shell_id) or a `<shell_id>_<entity>_ext` table.
4. Kernel entity id → BIGINT PK.
5. Partial index for active rows.
6. Beware JSONB GIN index write amplification (~20% throughput drop) — move large fields to separate tables.

### §12.2 Core 5 table summary

```sql
CREATE TABLE users (
    user_id           BIGINT PRIMARY KEY,
    gdpr_status       TEXT NOT NULL DEFAULT 'active',
    primary_auth_kind TEXT NOT NULL,
    created_tick      BIGINT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth_credentials (
    credential_id     BIGINT PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES users(user_id),
    kind              TEXT NOT NULL,
    kdf               TEXT NOT NULL CHECK (kdf IN ('argon2id','scrypt')),  -- C9/S2
    salt              BYTEA NOT NULL CHECK (octet_length(salt) = 16),
    credential_hash   BYTEA NOT NULL CHECK (octet_length(credential_hash) = 32),
    kdf_params        JSONB NOT NULL,                                       -- { m_cost, t_cost, p_cost }
    expires_tick      BIGINT,                                               -- S8 rotation
    bound_tick        BIGINT NOT NULL
);

CREATE TABLE actors (
    actor_id      BIGINT PRIMARY KEY,
    user_id       BIGINT REFERENCES users(user_id),
    shell_id      TEXT NOT NULL,
    handle        CITEXT NOT NULL,
    kind          TEXT NOT NULL,
    created_tick  BIGINT NOT NULL,
    shell_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (shell_id, handle)
);

CREATE TABLE spaces (
    space_id         BIGINT PRIMARY KEY,
    shell_id         TEXT NOT NULL,
    slug             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    visibility       TEXT NOT NULL,
    creator_id       BIGINT NOT NULL REFERENCES actors(actor_id),
    parent_space_id  BIGINT REFERENCES spaces(space_id),                    -- P5 immutable
    parent_depth     SMALLINT NOT NULL DEFAULT 0 CHECK (parent_depth <= 64),
    created_tick     BIGINT NOT NULL,
    shell_payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (shell_id, slug)
);

CREATE TABLE entries (
    entry_id           BIGINT PRIMARY KEY,
    shell_id           TEXT NOT NULL,
    space_id           BIGINT NOT NULL REFERENCES spaces(space_id),
    author_id          BIGINT NOT NULL REFERENCES actors(actor_id),
    parent_entry_id    BIGINT REFERENCES entries(entry_id),                 -- P5 immutable
    parent_depth       SMALLINT NOT NULL DEFAULT 0 CHECK (parent_depth <= 64),
    relay_of_entry_id  BIGINT REFERENCES entries(entry_id),                 -- P5 immutable
    relay_kind         TEXT,
    title              TEXT,
    body_hash          BYTEA NOT NULL CHECK (octet_length(body_hash) = 32),
    body_cache         TEXT,
    status             TEXT NOT NULL DEFAULT 'live',
    edit_seq           INT NOT NULL DEFAULT 0,
    created_tick       BIGINT NOT NULL,
    shell_payload      JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- DM (X3)
CREATE TABLE space_memberships (
    space_id    BIGINT NOT NULL REFERENCES spaces(space_id),
    actor_id    BIGINT NOT NULL REFERENCES actors(actor_id),
    joined_tick BIGINT NOT NULL,
    PRIMARY KEY (space_id, actor_id)
);

-- Activity with status (C2)
CREATE TABLE activities (
    activity_id               BIGINT PRIMARY KEY,
    shell_id                  TEXT NOT NULL,
    actor_id                  BIGINT NOT NULL REFERENCES actors(actor_id),
    verb_typecode             BIGINT NOT NULL,                              -- u32 widened
    target_kind               TEXT NOT NULL,                                -- 'entry'|'actor'|'space'|'activity'|'extension'
    target_id                 BIGINT NOT NULL,
    target_extension_typecode BIGINT,                                       -- NULL unless 'extension'
    target_shell_id           TEXT NOT NULL,                                -- C1 — shell-scoped idempotency
    at_tick                   BIGINT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'active'                -- C2 'active' | 'retracted'
                              CHECK (status IN ('active','retracted')),
    retracted_at_tick         BIGINT,                                       -- NULL if active
    extra_bytes               BYTEA,
    CHECK (target_shell_id = shell_id),                                     -- C1 cross-shell block
    UNIQUE (actor_id, verb_typecode, target_kind, target_id, status)        -- C2 unique on active only
);
-- Partial unique: active only — a new row on re-submit; previous becomes retracted tombstone
CREATE UNIQUE INDEX idx_activities_active_unique
    ON activities(actor_id, verb_typecode, target_kind, target_id)
    WHERE status = 'active';
CREATE INDEX idx_activities_target ON activities(target_kind, target_id, verb_typecode, at_tick DESC);
CREATE INDEX idx_activities_actor  ON activities(actor_id, verb_typecode, at_tick DESC);
```

### §12.3 Shell extension

BBS uses `shell_payload ->> 'is_concept'`. Separate tables: `bbs_board_creation_requests`, `casino_tables`, `casino_hands(transcript_url)`.

### §12.4 Kernel projection state + SLO (M-slo-metric)

```sql
CREATE TABLE kernel_projection_state (
    instance_id                   BIGINT PRIMARY KEY,
    last_applied_tick             BIGINT NOT NULL,
    last_applied_seq              BIGINT NOT NULL,
    chain_tip                     BYTEA NOT NULL CHECK (octet_length(chain_tip) = 32),
    chain_tip_signature           BYTEA NOT NULL CHECK (octet_length(chain_tip_signature) IN (64, 128)),  -- C3 Ed25519(64) or Hybrid(64+64)
    chain_tip_signature_key_id    BYTEA NOT NULL CHECK (octet_length(chain_tip_signature_key_id) = 32),   -- R5 M-R5-4 HSM key fingerprint
    signature_class               TEXT NOT NULL                                                           -- R5.2 GF5 — blocks type confusion
                                      CHECK (signature_class IN ('Ed25519','MlDsa65','Hybrid')),
    runtime_semver                TEXT NOT NULL,
    manifest_digest               BYTEA NOT NULL CHECK (octet_length(manifest_digest) = 32),
    observer_state                TEXT NOT NULL DEFAULT 'active'
        CHECK (observer_state IN ('active','degraded','replaying','dead')),
    last_applied_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    restart_attempts              INT NOT NULL DEFAULT 0
);
-- C3 read/write verifies chain_tip_signature. Key in HSM/KMS.
-- On restart, MC-check that the L0 InstanceView current tick matches last_applied_tick + chain_tip.
-- Mismatch → observer_state='dead' + operator alert + rollback blocked.
-- R5 M-R5-4 chain_tip_signature_key_id — HSM key fingerprint. On rotation, the old key is kept
--   verification-only (historical signature verification). Rotate via `runtime-doctor key-rotate`.
-- R5 FG8 — Ed25519 chain_tip key rotation 90d cadence + grace-period (90d+30d overlap verification window).
-- R5 R5-r4 — On HSM unavailable, switch observer_state='degraded' (new writes blocked, reads retained).
-- R5.2 GF5 — the signature_class column distinguishes Ed25519(64B) vs Hybrid(128B) vs MlDsa65(64B).
--   Verifier MC-branches on signature_class + key_id and cross-checks the WAL `SignatureClassPolicy` (§14.7 E13).

-- m2 unknown variant staging — replaces forward-version silent-skip with explicit staging.
CREATE TABLE unknown_variants (
    staging_id     BIGSERIAL PRIMARY KEY,
    wal_seq        BIGINT NOT NULL,
    type_code      BIGINT NOT NULL,
    variant_index  SMALLINT NOT NULL,
    raw_bytes      BYTEA NOT NULL,
    staged_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    replayed       BOOLEAN NOT NULL DEFAULT FALSE
);
-- On manifest update (Runtime/shell semver bump), `runtime-doctor replay-unknown-variants`
-- replays staged records with the new variant interpretation → projection.

-- S5 / veteran N3 doctor audit
CREATE TABLE runtime_doctor_journal (
    journal_id       BIGSERIAL PRIMARY KEY,
    operator_pubkey  BYTEA NOT NULL,
    ed25519_sig      BYTEA NOT NULL,
    command          TEXT NOT NULL,
    reason           TEXT NOT NULL,
    before_digest    BYTEA NOT NULL,
    after_digest     BYTEA,
    executed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- append-only (trigger / partition / revoke UPDATE,DELETE)
```

**Prometheus / OpenTelemetry metrics** (M-slo / P2 / P3 + R5 veteran m-R5-2):

Runtime default export = **OpenTelemetry v1.30+ (2025)**. Prometheus scrape is kept compatible via OTel Collector passthrough. R5.1 recommendation: **OpenTelemetry v2** (2026+) — exemplar trace correlation + native histogram support, switch as soon as the SDK is ready.

- `arkhe_runtime_projection_lag_seconds{shell_id="..."}` gauge.
- `arkhe_runtime_action_duration_seconds` histogram.
- `arkhe_runtime_observer_restart_total{shell_id="..."}` counter.
- `arkhe_runtime_hook_timeout_total{shell_id="..."}` counter.
- `arkhe_runtime_gdpr_cascade_remaining_ops{user_id="..."}` gauge.
- `arkhe_runtime_component_read_cache_hit_ratio` gauge (P2).
- `arkhe_runtime_gdpr_cache_hit_ratio{shell_id="..."}` gauge (P3).
- `arkhe_runtime_wal_growth_bytes_per_sec{shell_id="..."}` gauge (P1 extra_bytes monitoring).
- `arkhe_runtime_idempotency_duplicate_total{shell_id="..."}` counter (C6).
- `arkhe_runtime_rate_limit_reject_total{axis, shell_id}` counter (R5 veteran m-R5-2, §5.2.1).
- `arkhe_runtime_dek_message_count{user_id}` gauge (R5 FG1, DEK rotation trigger 2^30 warn / 2^32 force).
- `arkhe_runtime_software_kek_alpha_mode` gauge (R5 FG5a — 0/1 permanent warning tag).
- `arkhe_runtime_hsm_unavailable_total{region}` counter (R5 FG2 degraded-mode trigger).
- `arkhe_runtime_event_total{event_type, shell_id}` counter (R5.3 m-R7-1, tracks core Event emit). Grafana dashboard template: see §15.5 v0.13 nice-to-have.
- `arkhe_runtime_kms_health_channels{channel, region}` gauge (R5.3 HF2 — mandatory parallel health checks via DNS-over-HTTPS / alternate region path).

**SLO**: projection_lag_seconds p99 < 30s. Violation → PagerDuty.

#### §12.4.1 SLO / alert policy table (R5.2 M-R6-1)

Per-metric threshold / severity / action / runbook — operators can copy directly into alerting rules:

| Metric | Threshold | Severity | Action | Runbook |
|---|---|---|---|---|
| `arkhe_runtime_projection_lag_seconds` | p99 > 30s for 5min | **High** | PagerDuty page | `docs/runbook/projection-lag.md` |
| `arkhe_runtime_projection_lag_seconds` | p99 > 120s for 10min | **Critical** | PagerDuty + on-call escalation | `docs/runbook/projection-lag.md` |
| `arkhe_runtime_action_duration_seconds` | p99 > 10ms for 15min | Warning | Slack `#runtime-ops` | — |
| `arkhe_runtime_observer_restart_total` | rate > 3/hour | **High** | PagerDuty page | `docs/runbook/observer-restart.md` |
| `arkhe_runtime_hook_timeout_total` | any increase (should be v1 OFF) | **High** | Urgent investigation (hook active is not allowed) | — |
| `arkhe_runtime_gdpr_cascade_remaining_ops` | > 1000 for 48h | Warning | Operator review + SLA check | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_gdpr_cascade_remaining_ops` | > 0 for 72h | **High** | Prepare regulator notification | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_component_read_cache_hit_ratio` | < 0.7 for 30min | Warning | Review cache sizing | — |
| `arkhe_runtime_gdpr_cache_hit_ratio` | < 0.8 for 30min | Warning | Review §14.9 tick cache | — |
| `arkhe_runtime_wal_growth_bytes_per_sec` | > 10MB/s for 15min | Warning | Check for shell extra_bytes abuse | — |
| `arkhe_runtime_idempotency_duplicate_total` | rate > 5/s for 10min | Warning | Check for L4 retry storm | — |
| `arkhe_runtime_idempotency_wal_scan_ms` | p99 > 5ms for 15min | Warning | Review §14.8 FG6 scan N tick reduction | — |
| `arkhe_runtime_rate_limit_reject_total` | rate > 100/s for 15min | Warning | Attack / legitimate burst analysis | — |
| `arkhe_runtime_dek_message_count` | value > 2^30 (warn) | Warning | Prepare §14.9.1 DEK rotation | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_dek_message_count` | forced rotation fails before reaching 2^32 | **Critical** | PagerDuty + write block | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_software_kek_alpha_mode` | value == 1 (permanent) | **Info (permanent warning)** | Confirm production deployment is blocked | — |
| `arkhe_runtime_hsm_unavailable_total` | > 0 (any) | **Critical** | PagerDuty + confirm degraded mode | `docs/runbook/hsm-degraded-mode.md` |
| `arkhe_runtime_kms_sync_lag_seconds` | p99 > 60s for 10min | **High** | Review §14.11.2 Multi-KMS sync | `docs/runbook/hsm-degraded-mode.md` |
| `arkhe_runtime_event_total{event_type="GdprPolicyViolation"}` | rate > 5/s for 10min | Warning | Check attack or deployment bug (expected near-zero in normal ops) | `docs/runbook/gdpr-violation.md` (v0.13) |
| `arkhe_runtime_kms_health_channels{channel, region}` | value < 2 (of 3) for 60s | **High** | Multi-channel N-of-M verdict — warns just before HF2 auto_promote trigger | `docs/runbook/hsm-degraded-mode.md` |

**Alertmanager routing recommendation**:
- Severity `Critical` → PagerDuty primary + SMS.
- Severity `High` → PagerDuty secondary.
- Severity `Warning` → Slack / email digest.
- Severity `Info` → dashboard only.

Severity / action combinations are alpha-calibrated. Re-evaluate thresholds at production transition (depending on user scale / tick rate).

### §12.5 Partial replay + observer shell filter

1. L0 `replay_into` re-validates the chain tip.
2. Reset `kernel_projection_state` → re-execute the WAL → reconstruct the projection.
3. **Observer shell_id filter (S7)**: each observer declares `shell_id_filter: BTreeSet<ShellId>`. Events outside the interest set are skipped — blocks cross-shell metadata leak. A cross-shell projection node also registers an explicit multi-shell filter.
4. Unknown TypeCode / variant handling (m2 revisited): **silent-skip retired**. Instead, record explicitly in the `unknown_variants` staging table (§12.4) — after a manifest/Runtime update, `runtime-doctor replay-unknown-variants` re-interprets them. Blocks WAL/projection consistency collapse. On shell removal (shell sunset §14.7), staging is skipped + audit logged.
5. **Replay path per-tick atomic inheritance (R5 NF7)**: the §5.5 contract (tick-level BEGIN/COMMIT) applies identically on replay. Failed-validator records are inserted into the `unknown_variants` staging table + audit log and the tick still COMMITs — no "half-applied tick". During `observer_state='replaying'`, L4 serving is disabled (§14.7 m3).

---

## §13. Multi-shell hybrid proof

### §13.1 Scenario

```
users [user_id=1 Alice | user_id=2 Bob]
actors
  actor=10 (shell=bbs,    user_id=1)   actor=11 (shell=bbs,    user_id=2)
  actor=20 (shell=guild,  user_id=1)   actor=21 (shell=guild,  user_id=2)
  actor=30 (shell=casino, user_id=1)   actor=31 (shell=casino, user_id=2)
spaces  (space=100 bbs, space=200 guild, space=300 casino)
entries (entry=1000 bbs, entry=2000 guild, entry=3000 casino)
activities (A1 Like→1000, A2 Follow→21, A3 Pin→3000)
```

### §13.2 Structural guarantees (reflecting E7 dual-tier)

**Isolation 1 — Cross-shell Activity submit-site** (E7 TP):
```
Can Alice's BBS Actor<'s1>(10) Follow Guild Bob Actor<'s2>(21)?
→ SubmitActivity::from_branded(Activity { brand: 's1, inner: { target: Actor(21) } })
  Here `'s1` is bbs; at runtime the target Actor(21) resolves to guild, but at the submit site
  the call `Activity::new(brand_bbs, record)` itself requires Bob actor's brand → compile error.
```

**Isolation 2 — Replay/admin double-check** (E7 RA):
```
Scenario where an adversarial or corrupted WAL contains a cross-shell ActivityRecord:
→ SubmitActivity::compute compares ctx.read::<ActorProfile>(actor).shell_id
  against ctx.read::<ActorProfile|EntryCore|SpaceConfig|ActivityRecord>(target).shell_id
  and rejects (B1 dual-check MC).
→ No Op is produced; a CrossShellActivity event is emitted.
```

**Isolation 3 — Entry parent/relay** (E7 + E-entry-2 + P5):
Is an Entry<'s_bbs>'s parent an Entry<'s_casino>? Type mismatch compile error + compute MC double-check.

**Integration 1 — GDPR lease + L1 MC (C3)**:
```
Alice GdprEraseUser(user_id=1):
→ compute: [SetComponent(ErasurePending), EmitEvent(UserErasureScheduled)]
→ L2 erasure-cascade observer → tick+1 bounded batch:
   per-shell Actor despawn, EntryBody removal, Activity retract.
→ During the ErasurePending window, all of Alice's Actors are rejected at L1 compute
   (gdpr_status check) — no new Activity/Entry creation.
→ §14.9 SLA p95 < 24h.
```

**Integration 2 — User-level audit**:
```sql
SELECT a.*, act.*
FROM actors a
JOIN activities act ON act.actor_id = a.actor_id
WHERE a.user_id = 1 AND act.at_tick > (now_tick - 24*3600*10)
  AND act.status = 'active'                    -- C2
ORDER BY act.at_tick DESC;
```

### §13.3 Kernel perspective + throughput

- All shell Actions within a single InstanceId share one WAL (A23).
- Shell distinction is a Component field.
- Single-thread serial (A2). ~200 Action/sec/instance (§10.4).
- 10k+ user scaling: §14.10.
- Projection shell_id filter.

### §13.4 Coexistence with shell-scoped primitives

Casino Session/Turn/Round is shell-scoped (`0x0201_XXXX`):
- A Casino hook (planned from v2+) submits `SubmitEntry` + `CasinoPlayerAction`.
- BBS/Guild are unaware — projection silent-skips unknown TypeCodes + shell_id filter.

### §13.5 Structural proof (5 lines)

1. **User/Actor 2-tier** — User is shared, Actor is isolated.
2. **ShellBrand `'s` submit-site** — cross-shell is a compile error (E7 TP).
3. **L1 compute shell_id dual-check** — MC double-defense on the replay/admin path (E7 RA).
4. **Core 5 + 4 extension axes** — absorbs shell specifics without modifying core.
5. **Active-passive L2 + idempotency key** — blocks multi-L2 races (§14.8).

Running BBS + GuildChat + Casino concurrently is **structurally sound**.

---

## §14. Open Questions — final verdicts + new sections

### §14.1 Room primitive — separate primitive (follow-up DIP)

(R2 auditor + team-lead). Withdraws the R1 "Entry(Ephemeral) + Activity(Say)" alternative (tuple idempotency). Gate §8.1. 2+ shell evidence satisfied. Runtime semver v0.12 → v0.13.

#### §14.1.1 Room primitive — SHAPE-only declaration (D-USER-5 (iii), Track C, v0.12 sealing cycle)

User decision **D-USER-5 = (iii) SHAPE-only** (recorded in `docs/runtime-sealing-plan.md` decision register): v0.12 ships the Room shape declaration without committing the implementation surface. The architect-V3 evidence-path tension between Layer-independence (third-party shell as first-class) and validated-repetition (R4' gate (b) — 2+ shell evidence in code form) resolves at the SHAPE level — third-party shells land on a uniform Room base from v0.12, while Component / Action / VerbCode allocations wait for v0.13 ecosystem evidence.

**Reserved type-level shape** (§14.6 ArkheUri pattern):

```rust
// Future v0.13 implementation surface — declared at v0.12 SHAPE only.
pub enum RoomMarker {}
impl kind_seal::Sealed for RoomMarker {}
impl EntityKind for RoomMarker {
    const TYPE_CODE: TypeCode = TypeCode(0x0001_5001);
}
```

The `RoomMarker` `EntityKind` impl follows the §14.6 pattern (`UserMarker` 0x0001_0001 / `ActorMarker` 0x0001_1001 / `SpaceMarker` 0x0001_2001 / `EntryMarker` 0x0001_3001 / `ActivityMarker` 0x0001_4001 / **`RoomMarker` 0x0001_5001** — next free in the `0x0001_X001` Core Entity sub-range progression). The TypeCode is doc-reserved at the code level via `arkhe_forge_core::typecode::ROOM_MARKER_RESERVED` (Track C.2) — the `EntityKind` trait + per-marker `impl` blocks themselves remain spec-text-only at v0.12, deferred to v0.13 alongside the §14.6 ArkheUri implementation surface.

**4-gate compliance section** (per `docs/runtime-sealing-plan.md` D-USER-5 (iii)):

| Gate | v0.12 SHAPE-only verdict | Significance |
|---|---|---|
| **Lifecycle** | Ephemeral (TTL-evicted, distinct from Entry's append-only) | Operational — lifecycle policy. WAL retention is a runbook concern; no chain-integrity coupling. |
| **Auth** | Actor-bound (Room membership requires Authenticated Actor) | **Cryptographic** — connects to E13 (`SignatureClassPolicy`). At v0.13 implementation time, Room operations must respect the shell-per-tick `auth.signature_class` manifest field; receipt class downgrade attacks are blocked by the same chain-anchored policy that protects Entry / Activity submissions. The cryptographic-significance flag pre-commits the v0.13 implementation gate. |
| **Scale** | High-throughput WAL TTL (sub-second latency tolerance, projection-side eviction) | Operational — SLO sizing. v0.12 reservation does not prescribe a specific TTL bound; v0.13 ecosystem evidence informs the operator-tunable default. |
| **WAL policy** | TTL-based eviction (distinct from Entry's append-only invariant — Room does not extend the `WalRecord` postcard field order under DO NOT TOUCH #8) | Operational — eviction integrates with the existing WAL streaming export (Track F). |

**Allocation freeze at v0.12** — by D-USER-5 (iii) decision:

- **0 Component allocations** — no `Room*` structs in the `arkhe-forge-core::component::*` registry. Per-shell Component sub-allocations (e.g., `RoomMembership`, `RoomBan`) wait for v0.13 ecosystem evidence.
- **0 Action allocations** — no `Room*` actions in the `arkhe-forge-core::action::*` registry. The verb set (`join` / `post` / `leave` / `kick` / etc.) is an ecosystem-driven extension at v0.13.
- **0 VerbCode allocations** — the `0x0002_0001..0x0002_03FF` canonical verb sub-range remains intact; Room-specific verbs land via the M-verbrange shell BLAKE3 sub-allocation pattern (§14.4) at v0.13, NOT as canonical verbs.

**v0.13+ cap-token family reservation note**: Room operations land alongside a dedicated capability-token family at v0.13 (e.g., `arkhe:room/{join, post, leave, ...}`) corresponding to the new Action verbs. v0.12 SHAPE does NOT include the cap-token reservation — `ObserverCapToken` (E15) and the future `RoomCapToken` family are independent dimensions; the deferral is structural, not scope creep.

**Sealed-completeness mutual lock** (cryptographer Q7 anchor): the SHAPE declaration is mirrored at code level by the doc-only `pub const ROOM_MARKER_RESERVED: u32 = 0x0001_5001;` constant in `arkhe-forge-core::typecode` (Track C.2). The two sources together (spec text + code constant) prevent v0.13 implementers from accidentally re-allocating `0x0001_5001` for a different EntityKind — sealing-cut foreclosure preserved without committing the implementation surface.

**Layer-independence rationale recap** (D-USER-1 (a) intent dispatch): the SHAPE declaration ensures third-party shells (BBS / Casino-style / federated-experience / Roblox-style multi-experience hubs) land on a uniform Room base from v0.12, even though the in-tree workspace ships zero shell artefacts. Each ecosystem shell consumes the spec's `RoomMarker: EntityKind` shape + 4-gate compliance section + TypeCode reservation as authoritative — the v0.13 evidence-driven implementation rolls out the Component / Action / VerbCode allocations once 2+ ecosystem shells demonstrate concrete need, satisfying the validated-repetition directive without serialising third-party shell development behind a single platform release.

### §14.2 Attachment — Axis 1 Component

`EntryAttachments { refs }` Component + `entry_attachment_refs` extension table. sha256 duplicate projection.

### §14.3 Session/Turn/Round — shell-scoped + Band attribute

Casino is shell-scoped. Band 3 uses the `#[arkhe(band = 3)]` Action attribute (NC3 integration).

### §14.4 VerbCode range — M-verbrange

Canonical 1023 / shell 64,512 via BLAKE3 deterministic sub-allocation. `runtime-typecode-allocations.toml` registry. const generic.

### §14.5 Hook v1-alpha OFF — confirmed

All hooks disabled in v1 alpha. Reasons: no hot-reload (C1), Send+Sync contradiction (M5), UnwindSafe not guaranteed (C3), dylint purity is build-time only (M2), confused-deputy risk (S1).

v1 scope: manifest policy only + single shell (BBS recommended). The range expressible by multi-shell manifest policy alone.

v2 reintroduction conditions: WASI sandbox + 10ms budget + resource limits + WASI async + post-hook policy re-validation (§5.3/§9.1).

**v1 flow note (auditor N2)**: the "Hook host" box in the §5.3 diagram is **pass-through (no-op)** in v1. Activated together with the post-hook re-validation step when v2 is enabled.

#### §14.5.1 Hook host v2 — v0.12 sealing-cycle realisation (Track B)

Tier-2 production opt-in via the `tier-2-hook-host-v2` Cargo feature on `arkhe-forge-platform`; Tier-0 / Tier-1 deployments continue to ship `NoopHookHost` (v1 alpha pass-through). Operators stating Tier-2 in the manifest pull in the wasmtime sandbox.

**Engine configuration (`WasmtimeEngineConfig`)** — pins the four E14.L2-Allow determinism axes:

| Axis | Field | v0.12 value | Effect |
|---|---|---|---|
| NaN canonicalisation | `nan_canonicalisation` | `true` | `cranelift_nan_canonicalization(true)` — defends replay against host-dependent NaN payload bits |
| SIMD opt-out | `wasm_simd_enabled` | `false` | `wasm_simd(false)` + `wasm_relaxed_simd(false)` — rejects SIMD instructions at module-load |
| Fuel metering | `fuel_metering` | `true` | `consume_fuel(true)` — enables per-invocation fuel ceiling |
| IEEE-754 strict | *(implicit)* | Cranelift default | No `Config` field; floating-point ops produce host-independent bits |
| Per-invocation budget | `fuel_budget` | `10_000_000` (1–100 M envelope) | `Store::set_fuel(...)` immediately before instantiation; ~10 ms wall-clock target on x64 server class. **Fail-secure direction** (under-budget → hook killed early; over-budget → DoS surface). |

**Capability-bounded `Linker` template** — three-layer defense:

1. **Pre-scan** (`scan_imports`) eager-rejects modules whose imports do not match the `arkhe:hook/*` allow-list, with explicit specific-error paths for the WASI deny-list (`wasi:random`, `wasi:clocks`, `wasi:filesystem`, `wasi:sockets`, `wasi:io`, `wasi:cli`, `wasi:http`). Boundary check confines deny-list matching to WIT package boundaries (`/`, `@`, end-of-string).
2. **Link-time deny-by-default** — `Linker::new` only `func_wrap`s the supported `arkhe:hook/*` host-fns; unknown imports fail at instantiation.
3. **Call-time capability check** — every host-fn body inspects `Caller::data().capabilities` and traps `CapabilityDenied` if the matching `CapToken` is absent.

**v0.12 host-fn allow set**:

| Import path | CapToken | Sig | Behaviour at v0.12 (Track B.5.b) |
|---|---|---|---|
| `arkhe:hook/state.read` | `StateRead` | `(key_ptr, key_len, val_ptr_out, val_buf_len) -> i32` | Reads `key` bytes from wasm memory, looks up `HookStoreData::scratchpad`, copies value to `val_ptr_out` (bounds-checked). Returns: `>=0` bytes copied / `-1` not found / `-2` buffer too small. |
| `arkhe:hook/state.write` | `StateWrite` | `(key_ptr, key_len, val_ptr, val_len)` | Reads key + value from wasm memory, inserts into `HookStoreData::scratchpad` (`BTreeMap<Vec<u8>, Vec<u8>>`). |
| `arkhe:hook/emit.extra_bytes` | `EmitExtraBytes` | `(ptr, len)` | Reads bytes from wasm memory, appends to `HookStoreData::extra` (the `ExtraBytesBuilder` moved in by `WasmtimeHookHost::invoke` from `HookContext::extra`). Traps if `extra` was not seeded (programmer-error guard). |
| `arkhe:hook/fuel.consumed` | `FuelConsumed` | `() -> i64` | Returns `initial_fuel - Caller::get_fuel()`. Saturating cast to `i64::MAX` for forward-compat. |

**Memory bounds-check contract** (`(ptr, len)` host-fn deref): all such inputs flow through `read_caller_memory` (input ranges) or `write_caller_memory` (output ranges). Both validate `len >= 0`, `ptr >= 0`, `ptr.checked_add(len)? <= Memory::data_size(&caller)`, and trap `OOB` with explicit reason on violation. Required to prevent FFI-shaped sandbox-escape primitives (cryptographer-anchored requirement, Track B.5.a + B.5.b).

**3-tier ingestion** (Track B.6) — `WasmtimeHookHost::register_module(bytes, expected_digest)` enforces:

- **Tier 1** (active in v0.12): BLAKE3 digest pin against operator-pinned `expected_digest` (typically sourced from manifest TOML). Mismatch → `DigestMismatch` at registration time, before any wasmtime engagement.
- **Tier 2** (sigstore sign-before-load) — scaffolded via `HookAttestationVerifier` trait; v0.13+ integration.
- **Tier 3** (cargo-vet provenance) — scaffolded; v0.13+.

The default `Tier1OnlyVerifier` **loud-rejects** any `(signature, vet_attestation)` payload supplied to `verify` (returns `UnexpectedTier23Payload`). This prevents confused-deputy migrations where a caller wires Tier 2/3 inputs believing they are validated while v0.12 only enforces Tier 1.

**Manifest signature scope** (cryptographer P2): manifest signature verification (operator key → manifest TOML signing) is outside the v0.12 hook host scope; `manifest_digest` is recorded as a chain-anchor for replay verification, and the operator-side trust establishment lands at the manifest layer integration (post-v0.12 DIP).

**Chain anchoring**: every successful `register_module` emits a `HookModuleRegister` event (TypeCode `0x0003_0F0B`) carrying `(manifest_digest, module_digest, register_tick, attestation_class)`. **Replay-side verification path** (cryptographer P1): on replay, the recorded `HookModuleRegister.module_digest` is matched against `blake3(registered_bytes)`; mismatch → `ReplayError::HookModuleDriftQuarantined` + compute-path quarantine (L0 A22 inheritance).

**Per-host trap counter**: `WasmtimeHookHost::trap_count` (`AtomicU64`, lock-free) increments on every `invoke()` Err. Operator telemetry surface; future `runtime_doctor_journal` integration routes per-trap entries chain-signed. **Era distinction** (cryptographer P3): Track B.5.b activated real wasm execution, so the counter narrows from "invoke() Err of any shape" to "actual wasm-execution traps" (`BudgetExceeded` from fuel exhaustion / `Trapped` from wasmtime trap propagation / capability-deny / OOB). The `AtomicU64` field shape is preserved across the era boundary; only the semantic narrows.

**Invoke pipeline (Track B.5.b)**: `WasmtimeHookHost::invoke(ctx)` builds a per-invocation `Store<HookStoreData>` seeded with `ctx.capabilities` + `fuel_budget` + the extra-bytes builder taken from `ctx.extra` via `std::mem::take`. Instantiates the registered module via the cached `Linker`, looks up the conventional `"hook"` export (signature `() -> ()`), seeds fuel via `Store::set_fuel(fuel_budget)`, and calls the entry point. After return — whether success or trap — the (possibly mutated) extra-bytes builder is moved back into `ctx.extra` so the post-hook policy re-validation step sees it. Wasmtime errors are translated coarsely: fuel exhaustion → `HookError::BudgetExceeded`; everything else → `HookError::Trapped` with a static reason tag (operator stderr + `runtime_doctor_journal` carry the rich detail).

**Post-hook policy re-validation** (spec §5.3 / cryptographer C8 confused-deputy defense): the submission pipeline re-runs the same policy predicates against the post-hook `extra_bytes` buffer. A hook that mutated the buffer to flip policy outcome is rejected at the re-validation step → `HookError::PolicyReValidationFailed`. The hook host exposes the post-hook builder; the pipeline owns the re-validation call.

#### §14.5.2 Observer host v2 — v0.12 sealing-cycle realisation (Track A.2)

Tier-2 production opt-in via the `tier-2-observer-host-v2` Cargo feature on `arkhe-forge-platform`; Tier-0 / Tier-1 deployments continue to ship `NoopObserverHost` (v1 alpha pass-through). The two wasmtime hosts (`tier-2-hook-host-v2` + `tier-2-observer-host-v2`) are **independent** — operators may enable just one, just the other, or both; Cargo dedups the shared `wasmtime` dep.

**E14.L2 vs E15 axis distinction**: hook host (E14.L2) is *chain-affecting* compute (`Action::compute` host hook on the submission hot path) — determinism axes pinned (NaN canonicalisation / SIMD off / IEEE-754 strict). Observer host (E15) is *chain-non-affecting* side-effect dispatch (post-commit projection / metric / vault sinks) — determinism axes deliberately UNPINNED (replay-determinism is unnecessary because observer execution does not contribute to the L0 chain hash). Shared mechanism (wasmtime engine + capability-bounded `Linker`) + branched invariant (chain-affecting determinism vs chain-non-affecting confinement).

**Engine configuration (`WasmtimeObserverEngineConfig`)** — pins the panic-close + fuel-metering axes only:

| Axis | Field | v0.12 value | Effect |
|---|---|---|---|
| Fuel metering | `fuel_metering` | `true` | `consume_fuel(true)` — required for fine-grained sandbox-boundary trap delivery (panic close E15.a) |
| Per-invocation budget | `fuel_budget` | `100_000_000` (1 M–1 G envelope) | `Store::set_fuel(...)` immediately before instantiation; ~100 ms wall-clock target on x64 server class. Generous vs hook's 10⁷ because observer is post-commit + tolerates PG round-trip latency. **Fail-secure direction** (under-budget kills observer early; over-budget DoS surface for projection pipeline). |
| NaN canonicalisation | *(not pinned)* | — | E15 chain-non-affecting → replay-determinism unnecessary. Operators may override per deployment policy. |
| SIMD opt-out | *(not pinned)* | — | Same rationale — chain-non-affecting. |

**Capability-bounded `Linker` template** — three-layer defense (mirrors hook host pattern):

1. **Pre-scan** (`scan_imports`) eager-rejects modules whose imports do not match the `arkhe:observer/*` allow-list, with explicit specific-error paths for the WASI deny-list (`wasi:random`, `wasi:clocks`, `wasi:filesystem`, `wasi:sockets`, `wasi:io`, `wasi:cli`, `wasi:http`). Boundary check confines deny-list matching to WIT package boundaries (`/`, `@`, end-of-string).
2. **Link-time deny-by-default** — `Linker::new` only `func_wrap`s the `arkhe:observer/pg.write` dispatch shim that routes through registered `ObserverCapability` impls. Unknown imports (typos within the allow-list) fail at instantiation.
3. **Call-time capability check** — every dispatch shim inspects `Caller::data().capabilities` (the per-invocation `ObserverStoreData::capabilities` `BTreeSet<ObserverCapToken>`) and traps `CapabilityDenied` if the matching `ObserverCapToken` is absent.

**v0.12 host-fn allow set**:

| Import path | CapToken | Sig | Behaviour at v0.12 (Track A.2.3) |
|---|---|---|---|
| `arkhe:observer/pg.write` | `PgWrite` | `(ptr: i32, len: i32) -> ()` | Reads `len` bytes from wasm memory at `ptr` (bounds-checked via shared `read_caller_memory<ObserverStoreData>`), looks up the `PgWrite`-tagged `ObserverCapability` impl in the host's registry, calls `execute(&bytes)`. `CapabilityExecutionError` (e.g. PG unreachable) is silently swallowed at the wasm boundary — operational metric, NOT chain-anchored Quarantine. Future v0.13+ DIP routes operational failures to typed metric + `runtime_doctor_journal` entry. |

Additional capabilities (KMS / metric / etc.) wait for BBS-dogfood evidence per the validated-repetition directive — non-breaking additive expansion of the `ObserverCapToken` `#[non_exhaustive]` enum.

**`ObserverCapability` trait** (E15.b interface — host-side abstraction): `Send + Sync + Debug` only; `execute(&self, bytes: &[u8]) -> Result<(), CapabilityExecutionError>` carries the `&[u8]` payload-only signature that enforces chain-non-affecting clause 2 at type-level. v0.12 ships `PgWriteCapability` (unit struct, zero fields = trivially chain-orthogonal) + `MockPgWriteCapability` (test helper). Real PG connection wiring is deferred to v0.13+ shell-territory DIP.

**Memory bounds-check contract** (`(ptr, len)` host-fn deref): the dispatch shim flows through `read_caller_memory<ObserverStoreData>` — the same generic helper as the hook host's `read_caller_memory<HookStoreData>`. Both share the cryptographer-pinned B.5 invariant: `len >= 0`, `ptr >= 0`, `ptr.checked_add(len)? <= Memory::data_size(&caller)`, OOB trap on violation. Drift-avoidance: the helper is generic over the wasmtime Store data type `T` and lives in `arkhe-forge-platform/src/wasm_runtime_common/`, ensuring single source of truth.

**3-tier ingestion** (Track A.2.2) — `WasmtimeObserverHost::register_module(bytes, expected_digest)` enforces:

- **Tier 1** (active in v0.12): BLAKE3 digest pin against operator-pinned `expected_digest`. Mismatch → `DigestMismatch` at registration time, before any wasmtime engagement.
- **Tier 2** (sigstore sign-before-load) — scaffolded via the `attestation_class` field on `ObserverQuarantine`; v0.13+ integration mirrors the hook host's `HookAttestationVerifier` pattern.
- **Tier 3** (cargo-vet provenance) — scaffolded; v0.13+.

**Chain anchoring** (cryptographer-anchored chain-non-affecting clause 3 — host-supervised emission): when an observer wasm execution trips a sandbox-boundary failure, the runtime supervisor generates an `ObserverQuarantine` event (TypeCode `0x0003_0F0C`) carrying `(observer_module_digest, quarantine_tick, trap_class, attestation_class)`. The observer *triggers* emission via its trap, but does NOT *generate* it — the cryptographic chain anchor is host-owned. **Replay-side verification path**: on replay, the recorded `ObserverQuarantine.observer_module_digest` is matched against `blake3(registered_bytes)`; mismatch indicates manifest tampering or operator mis-deployment.

**`attestation_class` semantics (cryptographer A.2.4 anchor)**: the `attestation_class: RuntimeSignatureClass` field records the *observer module ingestion* attestation tier (Tier 1 BLAKE3 digest pin only at v0.12 → typically `None`; Tier 2/3 future paths set Ed25519 / MlDsa65 / Hybrid). NOT the event-signing class — the `ObserverQuarantine` event itself is chain-anchored under the runtime's standard signing path (E13 shell-per-tick `SignatureClassPolicy`), independent of this field. Same `RuntimeSignatureClass` enum, context-specific reading (mirrors `HookModuleRegister.attestation_class` C14).

**Trap classification** (Track A.2.3 `run_wasm_invoke`): wasmtime errors are translated coarsely:
- Fuel exhaustion → `ObserverError::BudgetExceeded` → `ObserverTrapClass::BudgetExceeded` Quarantine
- "called without `<Token>` capability" trap → `ObserverError::CapabilityDenied(token)` → `ObserverTrapClass::CapabilityDenied` Quarantine
- Other (incl. operator-config error "no impl registered" + OOB bounds-check + module instantiation failure + wasm panic) → `ObserverError::Trapped(static reason)` → `ObserverTrapClass::Panic` or `ObserverTrapClass::Other` depending on root-cause classification at supervisor side

**Quarantine boundary (cryptographer A.2.4 anchor)**: `ObserverError` variants trigger Quarantine emission (chain-anchored). `CapabilityExecutionError` from the `ObserverCapability::execute` impl (e.g., PG connection broken, write conflict) is **operational, NOT chain-anchored** — surfaces via metric / `runtime_doctor_journal` instead (v0.13+ DIP candidate). The boundary preserves the sealed-completeness distinction between sandbox-boundary failures (cryptographic concern → chain anchor) and downstream destination failures (operational concern → operator alert).

**Chain-non-affecting invariant (cryptographer-anchored 4-clause firm contract)**:

1. **No chain-mutation host-fn** — every binding under `arkhe:observer/*` routes to a side-effect destination outside the chain (PG projection, metric sink, KMS rotation receipt). No binding calls `Op::EmitEvent`, `Op::SpawnEntity`, or any chain-head-write primitive.
2. **Effect signature is chain-orthogonal** — every `ObserverCapability::execute(&self, bytes: &[u8])` impl carries its effect to a layer outside the chain. Borrow checker enforces no chain reference at type-level.
3. **Quarantine emission is host-supervised** — observer triggers via trap, *host* generates the chain-anchored receipt. Cryptographic chain anchor is host-owned.
4. **Panic isolation preserves chain progression** — wasmtime trap caught at `WasmtimeObserverHost::invoke` boundary; chain progression continues independently. Next-tick chain hash is unaffected by observer existence or panic state.

The 4-clause invariant + compile-time `_OBSERVER_CONTEXT_SHAPE_CHECK` const sentinel (verifies `ObserverContext` carries only the capability slice — future field additions trip the build) form the structural enforcement of E15 at the v0.12 cut.

**Per-host trap counter**: `WasmtimeObserverHost::trap_count` (`AtomicU64`, lock-free) increments on every `invoke()` Err. Operator telemetry surface; future trap_count threshold + module digest blacklist policy is a v0.13+ operator-runbook scope (E15 axiom body declares the *mechanism* — invariant 3 host-supervised emission — without prescribing a *threshold*).

### §14.6 ArkheUri included from R3+ — partial type-level (theorist m3)

> **`RoomMarker` reserved at SHAPE-only level** (§14.1.1, Track C, v0.12 sealing cycle): `RoomMarker` is the next free slot in the `0x0001_X001` Core Entity sub-range progression (`0x0001_5001`). The `EntityKind` impl shape is declared at v0.12 as spec text only — code-side TypeCode reservation lives in `arkhe_forge_core::typecode::ROOM_MARKER_RESERVED`. Implementation surface (Component / Action / VerbCode allocations + the `EntityKind` trait + per-marker `impl` blocks themselves) is deferred to v0.13 ecosystem-driven addition per D-USER-5 (iii).

```rust
mod kind_seal { pub trait Sealed {} }
pub trait EntityKind: kind_seal::Sealed + 'static {
    const TYPE_CODE: TypeCode;
}

pub enum UserMarker {}       impl kind_seal::Sealed for UserMarker {}
                             impl EntityKind for UserMarker   { const TYPE_CODE: TypeCode = TypeCode(0x0001_0001); }
pub enum ActorMarker {}      impl kind_seal::Sealed for ActorMarker {}
                             impl EntityKind for ActorMarker  { const TYPE_CODE: TypeCode = TypeCode(0x0001_1001); }
pub enum SpaceMarker {}      impl kind_seal::Sealed for SpaceMarker {}
                             impl EntityKind for SpaceMarker  { const TYPE_CODE: TypeCode = TypeCode(0x0001_2001); }
pub enum EntryMarker {}      impl kind_seal::Sealed for EntryMarker {}
                             impl EntityKind for EntryMarker  { const TYPE_CODE: TypeCode = TypeCode(0x0001_3001); }
pub enum ActivityMarker {}   impl kind_seal::Sealed for ActivityMarker {}
                             impl EntityKind for ActivityMarker { const TYPE_CODE: TypeCode = TypeCode(0x0001_4001); }
// RoomMarker — SHAPE-only declaration at v0.12 (§14.1.1); v0.13 ecosystem-driven implementation.
// pub enum RoomMarker {}    impl kind_seal::Sealed for RoomMarker {}
//                            impl EntityKind for RoomMarker { const TYPE_CODE: TypeCode = TypeCode(0x0001_5001); }

pub struct ArkheUri<K: EntityKind> {
    instance: InstanceId,
    shell: ShellId,
    local: EntityId,
    _kind: PhantomData<K>,
}

impl<K: EntityKind> fmt::Display for ArkheUri<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "arkhe://{}/{}/{}/{}",
               self.instance.get(), self.shell, K::TYPE_CODE.0, self.local.get())
    }
}

impl<K: EntityKind> FromStr for ArkheUri<K> {
    /// M4 strictened — instance prefix required. If absent, reject.
    /// Blocks federation v0.99+ gateway confused-deputy.
    fn from_str(s: &str) -> Result<Self, UriError> { /* requires instance prefix */ }
}

impl<K: EntityKind> ArkheUri<K> {
    /// Context-aware parse. For URIs internal to the same instance (prefix omitted).
    pub fn parse_within(instance_id: InstanceId, s: &str) -> Result<Self, UriError> { /* ... */ }
    pub fn canonical_bytes(&self) -> Vec<u8> { /* instance always included */ }
}

// Reserved for federation v0.99+ — Ed25519 signed wrapper (cross-instance URI integrity).
pub struct SignedArkheUri<K: EntityKind> {
    pub uri: ArkheUri<K>,
    pub signature: [u8; 64],   // Ed25519 (or PQC, §14.7 M8)
    pub signer_instance: InstanceId,
}
```

For a single instance, an **externally-entering URI must carry an instance prefix** (M4). `parse_within` alone permits a default instance. Blocks gateway confused-deputy — even if an adversary assigns instance B the same `(shell_id, local)` as instance A, from_str distinguishes them.

### §14.7 Runtime semver upgrade path — R4'.1 extension (retires sidecar + moves to in-band event)

**R4' sidecar approach retired (cryptographer C2)**: the `{wal_path}.runtime_meta` sidecar proposed in R4' has an integrity gap — an adversary with backup access can rewrite only the sidecar to keep the original L0 chain hash while swapping manifest_digest → tamper with `SpaceKind::Extension` semantics + replay-with-rewrite attack. Bypasses chain immutability.

**R4'.1 in-band event approach (C2 / E12)**:

```rust
/// Runtime bootstrap event — included in-band in the L0 chain hash.
/// Respects DO NOT TOUCH #8 (WalRecord postcard field order) — no L0 modification required.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F01 /* R5 NF5 — core Event subrange allocation */, schema_version = 1)]
pub struct RuntimeBootstrap {
    pub runtime_semver: SemVer,          // Runtime-defined in §14.7 (NR6-6)
    pub manifest_digest: [u8; 32],        // canonical TOML BLAKE3 (C5)
    #[arkhe(canonical_sort)]             // R5.3 R7-NR3 — field attribute opt-in (§3.5)
    pub typecode_pins: Vec<TypeCode>,    // snapshot of active TypeCodes (the derive sorts before serialize)
    pub bootstrap_tick: Tick,
}

/// R5 FG5 — chain-anchor for a shell's signature_class.
/// Reject Ed25519-only audit receipts after the tick at which a shell declared Hybrid.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F06, schema_version = 1)]
pub struct SignatureClassPolicy {
    pub shell_id: ShellId,
    pub class: RuntimeSignatureClass,
    pub effective_tick: Tick,
}
```

**R5.2 NR6-5 / R5.3 R7-NR3 `typecode_pins` canonical-bytes stability**: declared via the `#[arkhe(canonical_sort)]` field attribute (§3.5) — the derive auto-injects `sort_unstable()` on ascending `TypeCode(u32)` just before serialize. E12 MC digest stability — if manifest_digest changes due to different insertion orders of the same set, replay drift false-positives follow. Opt-in preserves arrival-order semantics of other `Vec<T>` fields by default.

**R5.2 NR6-6 — Runtime-defined `SemVer`**:

The `semver` crate (SemVer 2.0 spec) has variable-length pre-release / build metadata strings — postcard canonical bytes are unstable. The Runtime adopts a minimal fixed-layout struct:

```rust
/// Runtime's own SemVer (R5.2 NR6-6). No pre-release / build metadata.
/// postcard canonical = u16 × 3 = 6 bytes. Inherits A17.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct SemVer {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl SemVer {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self { Self { major, minor, patch } }
    /// Used in manifest runtime_min / runtime_max comparison.
    pub fn lex_cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}
```

Manifest `runtime_min = "0.12"` is parsed by `parse_semver()` into `SemVer::new(0, 12, 0)`. Pre-release suffixes (`"0.12.0-rc.1"`) are rejected — SemVer 2.0 compatibility is sacrificed, canonical-bytes stability prioritized.

**R5 M-R5-1 / R5.2 NR6-4 — `RuntimeSignatureClass` (L0 DO NOT TOUCH #3 protection)**:

L0 `arkhe_kernel::SignatureClass` inspection (R5.2 NR6-4, as of 2026-04-24):

- **Visibility**: `pub enum SignatureClass` (arkhe-kernel/src/persist/signature.rs:28). Accessible to external crates.
- **Variants**: `None` (unit) + `Ed25519 { signing_key: SigningKey, verifying_key: VerifyingKey }` (struct variant, holds key material).
- **Attrs**: `#[non_exhaustive]`, `#[derive(Default)]`, **no `Serialize/Deserialize`** — because `SigningKey` must never be included in WAL bytes (operational configuration).

**Structural implications**:
- L0 `SignatureClass` is **operational runtime config** (holds keys).
- Runtime `RuntimeSignatureClass` is a **wire-format class tag** (receipt / policy event).
- Keep the two concepts distinct via a separate enum + explicit `From` path.

```rust
/// Runtime-only wire-format class tag — keeps L0 SignatureClass derive unchanged (DO NOT TOUCH #3).
/// postcard canonical = 1 byte (repr(u8)). Inherits A17.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RuntimeSignatureClass {
    None    = 0,
    Ed25519 = 1,
    MlDsa65 = 2,   // Dilithium (FIPS 204) — PQC
    Hybrid  = 3,   // Ed25519 + MlDsa65 dual-sign
}

/// L0 operational config → wire-format class tag. Drop keys, extract only the class.
impl From<&arkhe_kernel::SignatureClass> for RuntimeSignatureClass {
    fn from(k: &arkhe_kernel::SignatureClass) -> Self {
        use arkhe_kernel::SignatureClass as L0;
        match k {
            L0::None                => Self::None,
            L0::Ed25519 { .. }      => Self::Ed25519,
            // When L0 v0.12+ introduces MlDsa65/Hybrid, extend this match (separate L0 DIP).
        }
    }
}
```

Reference-based `From<&L0::SignatureClass>` — the L0 value must not have its key dropped, so borrow instead of move to copy only the class tag. At Runtime v0.12, adding L0 variants proceeds as a **separate L0 DIP** — this DIP preserves "no L0 modification".

**Type distinction along the audit receipt signing path**:
- L2 receipt issuers branch on `RuntimeSignatureClass` (including MlDsa65 / Hybrid).
- L0 WAL chain-hash signing uses the L0 `SignatureClass` value as-is (currently Ed25519 only). PQC chain-level promotion requires an L0 DIP — the Runtime selects PQC only along the audit / projection signature path.

**§14.11 audit receipt path explicit**: the receipt issuer reads the manifest `[audit.signature_class]` value and signs with the corresponding key. Receipts issued after `SignatureClassPolicy` event's `effective_tick` enforce that class — the verifier cross-checks against the event snapshot. **Snapshot evaluation is monotone** (sticky: a shell that declared Hybrid at tick T cannot revert to Ed25519 at tick T+k; derives from A14 append-only — see `formal/tla-plus/cr3_replay_determinism.tla` INV E13 enforcement at lines 196-221 plus `PolicyMonotonic_Derivable` theorem at lines 223-256 for the formal-method anchor).

**Emission times** (`RuntimeBootstrap`):
1. WAL first tick (instance initial start).
2. On every manifest change (first tick after runtime restart).
3. On Runtime semver bump.

**Emission times** (`SignatureClassPolicy`, R5 FG5):
1. On shell manifest `[audit.signature_class]` change (first tick after restart).
2. At completion of PQC migration (`arkhe-runtime-doctor pqc-reseal`) rewrite.

**Replay integrity (E12 MC + R5 FG7 ManifestDrift opacity)**:
- On replay init, MC-check that `manifest_digest` in the WAL's `RuntimeBootstrap` event matches the canonical digest of the currently-loaded manifest.
- Mismatch → `ReplayError::ManifestDrift` + replay reject.
- **Public error surface is opaque (R5 FG7)** — `ReplayError::ManifestDrift`'s Debug/Display is limited to "manifest mismatch (see operator log)". Expected digest / actual digest not exposed (blocks adversary oracle). Detailed values only recorded in `runtime_doctor_journal`.
- `runtime_semver` forward-compat rules retained below.

**Forward-compatible rules** (R4'/R5 integrated, R5 NF3 duplicate removal):
- Adding new TypeCodes OK.
- Removal of existing TypeCodes forbidden.
- Bumping schema_version of an existing TypeCode — on replay, existing records decode with the schema_version at that point.
- Adding a field to an existing TypeCode schema — only via `#[serde(default)]` or `Option<T>`. Field removal forbidden.

**Existing WAL migration** (R5 NF4 — "sidecar" wording substitution complete):
- WALs from before R4' using sidecar metadata have `RuntimeBootstrap` events retroactively prepended via the `runtime-doctor chain-prepend` command. Operator Ed25519 signs + `runtime_doctor_journal` append. Accompanied by a chain-tip change (explicit operator approval required).
- **R5 R5-r3 — transparency log verification recommendation**: the result of `chain-prepend` should be recorded in Sigstore/Rekor (or an in-house Merkle + periodic publish) as an entry with operator signature + new chain-tip digest. External auditors can independently verify prepend time · signer · before/after digest.

**Conclusion regarding the WAL header**: DO NOT TOUCH #8 (WalRecord postcard field order) is **immutable**. Modifying L0 `WalRecord` requires an L0 DIP first. R4'.1 / R5.1 solves the problem with an in-band event — zero L0 modification.

**Enum WAL compat (C10 / S3 / auditor N3)**:
- Every `#[non_exhaustive]` enum has `#[repr(u8)]` or serde `tag` explicit index.
- No reordering of existing variants, no removal.
- New variants appended only at the end.
- Extension variant is always last.
- Default reject on the compute path (§3.4 NC5).

**Replay upgrade** (R5 NF4 — RuntimeBootstrap-event based):
- `RuntimeBootstrap.runtime_semver` < current = forward replay OK.
- `RuntimeBootstrap.runtime_semver` > current (downgrade) = `ReplayError::RuntimeVersionTooNew` reject.
- `typecode_pins` superset OK, subset reject.

**Shell sunset policy (veteran N4)**:
- Shell uninstall = manifest `[deprecated]` flag.
- TypeCode pins retained; new Entity creation L2-gate rejected.
- Existing records replay-only.
- `arkhe-runtime-doctor sunset-audit` command — reports remaining record count + last-access for the deprecated shell.

**CI gate** (auditor N6 / S9):
- `arkhe-forge-abi-check` — build-time check that the currently-registered TypeCodes of the crate form a superset of the previous semver. CI fails on commits that remove a registered TypeCode. Build-time MC promotion.

**PQC migration path (M8 + R5 C-R5-5b timeline enforcement)**:

`RuntimeSignatureClass` is defined above as a Runtime-only enum separated from L0 `SignatureClass` — protects L0 DO NOT TOUCH #3.

- default = `Ed25519` (v0.11 compatible).
- Shells select via manifest `[audit.signature_class]`. Timeline validation (§5.6): Ed25519-only is rejected when `runtime_max ≥ "0.30"`.
- **2030 dual-signing recommended** (safety margin for CRQC, NIST recommendation).
- **2035 PQC-only target** (Ed25519-only audit records carry forgery risk).
- During 2027–2029, Ed25519-only shells carry a warning flag + marketplace UI exposure.
- `arkhe-runtime-doctor pqc-reseal` — rewrites existing Ed25519 records as Hybrid. Changes chain tip + mandatory operator Ed25519/MlDsa65 sign + `runtime_doctor_journal` record + emits `SignatureClassPolicy` event (FG5).
- `arkhe-runtime-doctor pqc-timeline-audit` — signature_class vs runtime_max timeline readiness dashboard for all shells.
- **BLAKE3 is Grover-resistant**: current 32-byte output = 128-bit post-quantum security (post-Grover). Consider `BLAKE3::extended` in v0.99+ if 512-bit output is required. Current safety margin explicit.

**R5.2 M-R6-4 — Alpha→beta crypto migration (software-kek → HSM)**:

Path to upgrade a WAL run under `software-kek` at `runtime_max ≤ "0.15"` to the `runtime_max ≥ "0.16"` HSM backend. The master key reference mismatch is the structural problem.

**R5.3 HF1 — Tier-0 software-kek process protection obligation (shared prerequisite for Options 1 / 2)**:

A software-kek-operating process is obliged at the operational stage to protect key-material memory residency:

1. **`mlock_all()`** — blocks paging / swap (no VM swap disk residue).
2. **`prctl(PR_SET_DUMPABLE, 0)`** — blocks core dump creation (blocks key-material dump on panic).
3. **ptrace-protection enabled** — setuid capability or `yama.ptrace_scope = 2` recommendation (restricts kernel-level root-account ptrace).
4. **Runtime startup capability check** — if any of the above 3 fails to activate, `RuntimeInitError::ProcessProtectionUnavailable` + startup reject (alpha but no protection bypass).

Threat model: assume the host-OS access holder is effectively the master-key holder. Internet isolation / air-gap operation recommended (reflected in §14.9.1 §§12 Tier-0 annotation).

**Option 1 (default, team-lead recommendation)**: full erasure of alpha data.
- Basis for "software-kek = **test-only assumption**". No real users (§14.9.1 Tier-0).
- `runtime-doctor wipe-alpha --confirm <phrase>` — deletes all of WAL + projection + tombstone_log (operator Ed25519 + journal append).
- Then HSM initialization + new WAL start. Minimum migration cost.
- With process protection active, wipe and restart the process — eliminates memory fragments at the source (R5.3 HF1).

**Option 2 (advanced, when data preservation is required)**: `runtime-doctor crypto-migrate-software-to-hsm` offline batch.
- Step 1: HSM generates a new per-user DEK + wrap (§14.9.1 §§2 envelope).
- Step 2: decrypt every `EncryptedPii<T>` ciphertext with the software-kek DEK → re-encrypt with the new HSM DEK.
- Step 3: emit `DekMigrationCompleted { old_dek_id, new_dek_id, user_id, migrated_tick }` event (new TypeCode 0x0003_0F09 reserved) + change chain tip.
- Step 4 (**R5.3 HF1 restated**): record the software-kek DEK in the tombstone log + **full process restart**. After migration completes, a runtime process restart is mandatory — since plaintext DEKs transiently reside in process memory during re-encryption, restart eliminates memory fragments at the source.
- Operator Ed25519 sign + `runtime_doctor_journal` append mandatory. External auditor confirms `DekMigrationCompleted` event count == user count.
- **Note**: during migration `observer_state='degraded'` — L2 new writes blocked, resume after migration + restart complete.
- Option 2 batch tool planned for v0.12+ (implementation scope is in the v0.12 implementation DIP).

`DekMigrationCompleted` Event TypeCode **0x0003_0F09** reserved (§3.2 table only marks R5.2 reservation; formal struct definition at v0.12).

**L2 serving disable during replay (m3)**: during replay, `AuthCredential`s whose `bound_tick` is future-dated may be temporarily invalid — L4 serving can respond with false negatives. Solution: **disable L2 serving entirely during replay** — when `kernel_projection_state.observer_state = 'replaying'`, L4 requests get 503 Service Unavailable + `Retry-After` header. Resume when replay finishes.

**Runtime BLAKE3 domain string list (m4)**:

| Domain string | Use | Location |
|---|---|---|
| `arkhe-forge-verb-alloc` | verb sub-range determination (shell_id BLAKE3) | §3.2 |
| `arkhe-forge-manifest-digest` | canonical TOML digest | §5.6 |
| `arkhe-forge-audit-receipt` | Ed25519/PQC audit receipt MAC | §5.2, §14.11 |
| `arkhe-forge-runtime-bootstrap` | RuntimeBootstrap event MAC | §14.7 |
| `arkhe-forge-signature-class-policy` | SignatureClassPolicy event MAC | §14.7 / E13 |
| `arkhe-forge-entity-id` | deterministic EntityId generation | §4.7 |

CI (extension of `arkhe-forge-abi-check`) scans the entire source and fails on use of an unregistered domain string. List changes are accompanied by updates to this §14.7 document.

**Offline migration tool — `arkhe-runtime-doctor`** (veteran N3 / S5):
- `manifest-digest-recompute` — recompute canonical TOML (C5).
- Prints WAL header `runtime_semver` / `manifest_digest`.
- TypeCode-range record statistics.
- Snapshot rebuild.
- `sunset-audit` — residual records of a deprecated shell.
- schema_version bump rewrite of legacy records (optional, accompanied by chain-tip change — explicit operator consent).
- **Operator authentication + audit**: every rewrite command requires an Ed25519 signature (reusing A16). `runtime_doctor_journal` table is append-only (§12.4). Public chain-tip publish (GitHub release or internal transparency log).

### §14.8 Multi-L2 model — extension (X6 + C6 idempotency)

**R4' operational model**: **active-passive 1+N** + **client-supplied idempotency key**.

- Only the active L2 calls kernel `submit`.
- Passive L2 is read-only via WAL projection, synchronized.
- Failover: active failure → passive promotion (operator or lease expiry).

**Idempotency key (C6 / veteran N2 / R5 Axis 3 PG-only primary + FG6 WAL anchor)**:
- The L4 request header `X-Arkhe-Idempotency-Key: <UUID v4>` is mandatory. L2 pass-through via the `idempotency_key: Option<[u8; 16]>` field of an **`#[arkhe(idempotent)]` opt-in L1 Action** — the Action body is included as postcard-encoded inside the WAL record payload (no impact on L0 WalRecord field order DO NOT TOUCH #8).
- **Primary dedup (R5 Axis 3)**: PG `UNIQUE INDEX (idempotency_key) + INSERT ON CONFLICT DO NOTHING + expires_at TIMESTAMPTZ` + background TTL cleanup (partition drop, default 10min retention). 5–10min dedup window.
- **Redis `SETNX` alternative**: activated only in production with < 5ms SLA requirement. Selected via manifest `[quota.storage_backend = "redis"]`.
- During failover, client retry with the same key → duplicate response (returns prior submit_result) — PG row or Redis key hit.
- Metric `arkhe_runtime_idempotency_duplicate_total`.

**R5 FG6 — blocks active-passive failover idempotency race (aligned with Axis 3 PG-only)**:

A two-phase race (SETNX pending → submit → SET result) allows the active to crash right after SETNX — after passive promote, the same key can be resubmitted → duplicate Op emission. R5.1 / R5.2 solution:

1. **Opt-in `idempotency_key: Option<[u8; 16]>` field on the L1 Action body** — only Actions declared with the `#[arkhe(idempotent)]` attribute (R5.2 NR6-2) get the derive compile-time assert. Non-idempotent Actions keep the existing structure. `#[derive(ArkheAction)]` verifies the field's presence.
2. **compute-internal scan** — call `ctx.idempotency_lookup(&self.idempotency_key)` (R5.2 NR6-3 / §3.3). On hit return the existing `(entity_id, tick)` → deterministic noop (no Op regeneration). On miss process as new.
3. **Crash recovery** — on passive promotion, catch-up replay from `kernel_projection_state.last_applied_tick`. `idempotency_lookup` finds the same key → skips already-applied Actions + returns the stored response.
4. **Redis not required**: the WAL chain alone shrinks the race window (single primary) + backup replay is consistent. Satisfies the alpha/beta PG-only environment.

**2-layer dedup structure (R5.2 mNF-A)**: the §5.2 table makes this explicit — L2 PG `UNIQUE INDEX` fast pre-filter (5–10min window, absorbs normal traffic) + L1 WAL scan via `idempotency_lookup` crash-recovery backstop (scenario: passive promote + simultaneous PG/Redis loss). The two paths are orthogonal — on L2 fail-open, L1 is the backstop; the L1 scan cost is not on the hot path.

Metric `arkhe_runtime_idempotency_wal_scan_ms` histogram (scan cost monitoring, target: N-tick scan < 5ms p99).

**R5.2 m-R6-1 — L0 `SubmitAction` extension boundary**: R5.1 wording said "Runtime-owned", but in reality L0 `SubmitAction` (and the `WalRecord` postcard field order, DO NOT TOUCH #8) are kernel-defined. **Adding an `idempotency_key` field is a precondition for an L0 v0.12 DIP**. Within the scope of this DIP (v0.12 Runtime):

- Operate the **PG `UNIQUE INDEX` path** (§5.2 table / §14.8 primary dedup) as the sole channel.
- The `idempotency_lookup` trait method activates once L0 v0.13+ provides a WAL auxiliary index (R5.4 theorist L0 version notation consistency — aligned with the §5.2 R7-NR4 footnote). At Runtime v0.12 implementation time, only L0 v0.11 is available, so this is a **no-op stub** (always returns `None`) — functionally depends only on the PG UNIQUE INDEX.
- An Action declared `#[arkhe(idempotent)]` may still be defined in v0.12 Runtime, but is **ineffective because the stub returns None**. Actual WAL scan activation after L0 v0.12 DIP completion.

This separation respects "L0 DO NOT TOUCH" while fixing the Runtime API surface in advance — Runtime client code needs no modification when L0 is extended.

**Active writer same-tick ordering (M1)**:
- When multiple L4 Actions arrive on the same tick, **L4 arrival-timestamp strict FIFO** + order preservation within the same L4 connection.
- Timing-critical shells (Casino etc.) declare `manifest [shell.ordering_policy = "commit_reveal"]` — the active writer applies commit/reveal phase-based reordering (Band 3 shell responsibility).
- Front-running defense by network latency advantage: because FIFO-by-arrival depends on net latency, **publishing the low-latency peer connection topology** is recommended. Truly fair ordering requires shell-level commit-reveal.

**Mutex race cannot arise** (single active → manifest mutex validation sequential).

**Multi-active is a separate DIP**. Candidate solutions:
- Promote mutex groups to L1 kernel state → extension of Band 1 invariants (high cost).
- L2 distributed lock (Redis RedLock) — determinism contamination risk.
- Active shard split (active L2 per shell_id) — split-brain management on redistribution.

R1-R4' scope is single-active.

### §14.9 GDPR cascade policy — extension (X1 / C3 / P3)

**Problem**: 10^8 Ops in a single compute stops the L0 single-thread.

**Solution** (lease + L2 background):
1. `GdprEraseUser::compute` → `[SetComponent(UserProfile{gdpr_status: ErasurePending}), EmitEvent(UserErasureScheduled)]` only.
2. L2 erasure-cascade observer → per-tick bounded batch (config default 1,000 Op/tick):
   - From tick T+1: Actor lookup (user_id=target), per tick despawn N actors + EntryBody removal + Activity retract.
   - Each batch `Op::ScheduleAction` re-submitted at tick+1 (E11).
3. Completion condition: remaining Actor/Activity = 0 → `SetComponent(UserProfile{gdpr_status: Erased}) + EmitEvent(UserErasureCompleted)`.

**L1 compute MC gate (C3 / B3 resolution)**:
- gdpr_status check on every actor-originated compute (§3.3).
- Any Action from an actor with `gdpr_status == ErasurePending` is rejected.
- The L2 gate is a pre-filter, but L1 compute is the final defense — a double MC barrier.
- `GdprPolicyViolation` event recorded in the kernel WAL (audit trail).

**Tick-scoped gdpr cache (P3)**:
- Within the same tick, gdpr_status reads for the same user_id share a single lookup.
- Reuses L0 InstanceView's tick-scoped cache (P2).
- Metric `arkhe_runtime_gdpr_cache_hit_ratio{shell_id}`.

**SLA (E-user-3 RA)**:
- p95 completion < 24h.
- p99 < 72h (power user: 30 shells × 10^6 entries).
- Beyond 72h → operator alert.

**Safeguards**:
- Per-user Op ceiling 10^7 (config). Exceed = operator confirmation.
- Mid-cascade failure → resume from the projection.
- Progress via Prometheus `arkhe_runtime_gdpr_cascade_remaining_ops`.

#### §14.9.1 Crypto-erasure policy — R5.1 rewrite (M5 / GDPR Art. 17 + R5 C-R5-1/3/4 + FG3/FG4 + M-R5-2/3 + NF8)

**Reading order (R5.3 m-R7-2)**: determine your environment by §§12 Compliance Tier → §§1 EncryptedPii wire → §§10 (§14.9.1.1) Operator runbook → rest of the deep material. Subsection order is not by importance — deep-read only the subsections for your chosen tier.

**Problem**: the §14.9 cascade is Component-level `RemoveComponent(EntryBody)` only. The original WAL `SubmitEntry` permanently preserves `handle`, `body_hash`, `extra_bytes` (L0 A14 chain immutability). `body_hash` is PII under rainbow-table pre-image (GDPR Recital 26). During regulatory audit, residual WAL PII → up to 4% annual revenue fine risk.

**Solution (Envelope-based crypto-erasure)**:

##### 1. `EncryptedPii<T>` — type-safe wire format (R5 C-R5-4)

R4'.1 `EncryptedPii<T>` lacked a T bound + T information on the wire → **type confused-deputy** (decrypting the same ciphertext as a different T could leak handle as body). R5.1 redesign:

```rust
/// PII payload trait — wire-embedded code + canonical encode.
/// R5.2 NR6-7 — sealed. Only the Runtime crate may impl (PII_CODE 0x0001..=0x00FF).
/// Shell-scoped PII uses a separate `ShellPiiType` wrapper + manifest registration path (see below).
pub trait PiiType: CanonicalEncode + pii_seal::Sealed {
    /// `PII_CODE` is fixed at 2B on the wire — blocks the type confused-deputy.
    /// Runtime canonical: 0x0001..=0x00FF. Shell-scoped: 0x0100..=0xFFFF.
    const PII_CODE: u16;
}

mod pii_seal { pub trait Sealed {} }

/// Wrapper holding a PII encrypted under the per-user DEK.
/// canonical_bytes = (dek_id, pii_code, aead_kind, nonce, ciphertext).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct EncryptedPii<T: PiiType> {
    pub dek_id: DekId,              // HSM/KMS key reference (per-user)
    pub pii_code: u16,              // R5 C-R5-4 included on wire (2B) — cross-checked with T::PII_CODE
    pub aead_kind: AeadKind,        // R5 C-R5-1 — AEAD choice on the wire (misuse-resistant)
    pub nonce: NonceBytes,          // 12B (AES-GCM) / 24B (XChaCha20) / 12B (AES-GCM-SIV)
    pub ciphertext: bytes::Bytes,   // AEAD tag included (last 16B)
    _marker: PhantomData<T>,
}

#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AeadKind {
    XChaCha20Poly1305 = 0,   // default — 192-bit nonce, misuse-resistant
    Aes256Gcm         = 1,   // hardware acceleration
    Aes256GcmSiv      = 2,   // RFC 8452 — nonce-reuse resistance
}

impl<T: PiiType> EncryptedPii<T> {
    /// R5.2 NR6-1 — AEAD AAD = dek_id || pii_code.to_be_bytes() || (aead_kind as u8).
    /// Tampering with the wrap fields fails AEAD tag verification → `PiiError::AadMismatch`.
    fn compute_aad(dek_id: &DekId, pii_code: u16, kind: AeadKind) -> [u8; 19] {
        let mut aad = [0u8; 19];
        aad[..16].copy_from_slice(&dek_id.0);
        aad[16..18].copy_from_slice(&pii_code.to_be_bytes());
        aad[18] = kind as u8;
        aad
    }

    pub fn encrypt(
        dek: &[u8],
        dek_id: DekId,
        kind: AeadKind,
        plaintext: &T,
    ) -> Self {
        let aad = Self::compute_aad(&dek_id, T::PII_CODE, kind);
        let nonce = gen_nonce(kind);                          // kind-specific nonce generation
        let pt_bytes = plaintext.canonical_bytes();
        let ciphertext = aead_encrypt(kind, dek, &nonce, &aad, &pt_bytes);
        Self {
            dek_id,
            pii_code: T::PII_CODE,
            aead_kind: kind,
            nonce,
            ciphertext,
            _marker: PhantomData,
        }
    }

    pub fn decrypt(
        self,
        dek: &[u8],
        manifest_cipher: AeadKind,   // R5.2 GF2 — manifest `[audit.pii_cipher]` injected
    ) -> Result<T, PiiError> {
        // R5 C-R5-4 — blocks the type confused-deputy
        if self.pii_code != T::PII_CODE {
            return Err(PiiError::TypeMismatch);
        }
        // R5.2 GF2 — AeadKind downgrade block (manifest-anchored check)
        // mismatch between current manifest pii_cipher and the record's aead_kind → reject.
        // Exception path — when a manifest bump (§9.1 GF2) permits the old cipher by policy,
        // verify the record's pii_cipher at the time of creation from the shell manifest history table.
        if self.aead_kind != manifest_cipher {
            return Err(PiiError::CipherDowngrade);
        }
        // R5.2 NR6-1 — recompute AAD then AEAD verify
        let aad = Self::compute_aad(&self.dek_id, self.pii_code, self.aead_kind);
        let pt_bytes = aead_decrypt(self.aead_kind, dek, &self.nonce, &aad, &self.ciphertext)
            .map_err(|_| PiiError::AadMismatch)?;
        T::from_canonical_bytes(&pt_bytes).map_err(PiiError::DecodeFailed)
    }
}

/// `DekId` is an HSM/KMS key reference — the Runtime holds only the id, no plaintext key.
pub struct DekId(pub [u8; 16]);

/// Shell-scoped PII wrapper (R5.2 NR6-7). 0x0100..=0xFFFF.
/// Shell crate extends via `impl ShellPiiType for MyShellPayload`.
/// The Runtime pins per-shell ranges via manifest `[audit.shell_pii_code_range = { from, to }]`
/// + prevents overlap. Shell PII is shell-owned — the Runtime keeps only PII_CODE range separation.
pub trait ShellPiiType: CanonicalEncode {
    const PII_CODE: u16;      // within the manifest-registered range
}
```

**PII_CODE allocation convention (R5.2 NR6-7)**:

| Range | Owner | Reservation |
|---|---|---|
| `0x0001..=0x00FF` | **Runtime canonical** — `PiiType` sealed, only Runtime-internal impls allowed | Currently 4 (ActorHandle=0x0001 / EntryBody=0x0002 / ActivityExtraBytes=0x0003 / AuthCredentialSecret=0x0004). A new allocation = Runtime DIP. |
| `0x0100..=0xFFFF` | **Shell-scoped** — `ShellPiiType` wrapper trait, usable after shell manifest `[audit.shell_pii_code_range]` registration | Runtime rejects per-shell duplicate registration (registry). Shell owns PII definition + wire format. |
| `0x0000` | **reserved** (wire-level tombstone — do not use) | — |

**PII_CODE reservation (R5.1 C-R5-4)**:

| PII type | `PII_CODE` | Applied Component |
|---|---|---|
| `ActorHandle` | `0x0001` | `ActorProfile.handle` |
| `EntryBody` | `0x0002` | `EntryBody.body_plaintext` (optional) |
| `ActivityExtraBytes` | `0x0003` | `ActivityRecord.extra_bytes` (shell discretion) |
| `AuthCredentialSecret` | `0x0004` | auxiliary credential secret (the default KDF salt is already per-credential random) |

Allocation of a new PII type requires updating this table + a schema_version bump.

##### 2. Envelope encryption — HSM-generated DEK (R5 C-R5-3)

R4'.1 had two simultaneously-true propositions that were **impossible**: the `blake3::derive_key("arkhe-forge-user-dek", master_kms_key || user_id_bytes)` derivation and the statement "DEK exists only in HSM/KMS" (all DEKs recoverable once the master key leaks). R5.1 solution — **envelope encryption redesign**:

1. **The HSM generates the per-user DEK with its own randomness** — the Runtime does not derive it. The derivation formula is removed.
2. **The HSM master wraps the DEK** → the Runtime stores only `DekId` + `wrapped_dek: Bytes` (plaintext DEK remains inside the HSM).
3. **Encryption** — when the Runtime writes a PII field, it requests the HSM `Decrypt(wrapped_dek) → plaintext_dek` (fast inside HSM), then AEAD encrypts with the result. The plaintext DEK is zeroized and discarded from Runtime process memory.
4. **Erasure** — HSM `delete_key(dek_id)` → plaintext DEK removed. The `wrapped_dek` becomes permanently unwrappable → ciphertext undecryptable.
5. **HSM master rotation (FIPS 140-3 recommends 1 year)** — envelope re-wrap (fast inside HSM; no ciphertext re-encryption).

##### 3. AEAD choice (R5 C-R5-1) — nonce reuse / 2^32 message limit

AES-GCM, per NIST SP 800-38D, carries a birthday bound of ~2^32 messages with random 96-bit nonces — across 10 years × 10^6 entries/user × 30 shells, cumulative collision is possible. On collision, GCM integrity is destroyed globally + plaintext leaks.

**R5.1 policy**:
- **Default = XChaCha20-Poly1305** (192-bit nonce, misuse-resistant). Default when shell manifest `[audit.pii_cipher]` is omitted.
- When choosing `AeadKind::Aes256Gcm`, **deterministic counter nonce** is mandatory — `nonce = counter_be_bytes[8] ++ random[4]`. DEK rotation right before counter overflow.
- `AeadKind::Aes256GcmSiv` (RFC 8452) — hybrid option (HW acceleration + nonce-reuse resistance).
- **DEK rotation trigger**: track per-DEK message count (metric `arkhe_runtime_dek_message_count{user_id}`).
  - Warn at 2^30 messages.
  - **Force rotation + envelope re-wrap** before 2^32. HSM generates a new DEK → existing ciphertext remains decryptable only by the former DEK (keep both wrapped_deks for a short window).

##### 4. PII scope + body_hash salt (R5 NF8)

- `ActorProfile.handle` — the handle itself is an identifier → `EncryptedPii<ActorHandle>` (PII_CODE 0x0001).
- `EntryBody.body_hash` — **per-user + per-record nonce** (R5 NF8 linkability block):
  ```
  body_hash = BLAKE3(body || user_salt || entry_nonce)
  ```
  - `user_salt`: per-user 128-bit HSM-held. **R5.2 mNF-C — immutable**: generated by the HSM at user creation, unchangeable until `GdprEraseUser` cascade DEK shred. `user_salt` rotation requires **full re-write of the user's PII** — operationally disallowed. On shred, all entries become undecryptable.
  - `entry_nonce`: per-record 128-bit, a plaintext field of `EntryBody` (replay-deterministic).
  - **Responsibility boundary**: L2 reads `user_salt` from the HSM + pre-computes `body_hash` → L1 only stores the finished `body_hash`. HSM calls are forbidden inside L1 compute (inheriting A11 pure).
- `AuthCredential.credential_hash` — already salted Argon2id/Scrypt (§4.1). Extra encryption unnecessary.
- `ActivityRecord.extra_bytes` — shell discretion (per-user encrypt recommended). Uses PII_CODE 0x0003.
- `SpaceConfig.slug` — public identifier (not an encryption target).

##### 5. DEK lifecycle + shred receipt

1. At user creation, the HSM generates a DEK + wraps with the master → Runtime stores `(DekId, wrapped_dek)`.
2. Per-user PII writes go through the envelope path above.
3. On `GdprEraseUser` cascade completion, HSM `delete_key(dek_id)` → plaintext DEK removed.
4. Subsequent ciphertext is undecryptable = effective erasure.
5. Shred evidence: `Op::EmitEvent(UserErasureCompleted { user, dek_shred_tick, attestation })` — `attestation` = HSM "key destruction attestation" serialized bytes (Ed25519 or PQC signature, §14.7 M8).

**SLA**:
- p95 DEK shred < 24h.
- p99 < 72h.
- Beyond 72h → operator alert + regulator notification preparation.

##### 6. HSM SPOF + degraded mode (R5 C-R5-5a)

**HSM/KMS required** by default. Exception (team-lead directive 2026-04-24):
- `[audit.dek_backend = "software-kek"]` is valid only in the `runtime_max ≤ "0.15"` alpha milestone (§5.6). Replaced by process-memory master key + audit log, for ≤1k-user test environments only. Permanent warning tag on dashboards/logs (`arkhe_runtime_software_kek_alpha_mode=1`).

**On HSM outage (R5 R5-r4 degraded mode + R5.2 M-R6-2 threshold concretization)**:
- **Degraded mode trigger** (R5.2 M-R6-2): transition to `observer_state='degraded'` when any of the following holds.
  - **5 consecutive HSM timeouts** (per-request timeout default 2s), or
  - **Error rate ≥ 50% within a 60s window** (sum of HTTP 5xx / network error / auth failure).
  - Transition is automatic — no manual operator intervention required. Recovery is automatic when **error rate ≤ 5% for 30 consecutive seconds** is reached.
- `observer_state='degraded'` → L2 new writes **blocked** (PII writes impossible), read path retained (decryption after HSM recovery).
- `arkhe_runtime_hsm_unavailable_total{region}` counter + PagerDuty Critical (§12.4.1 SLO table).
- `runtime-doctor hsm-health` command — current error rate / consecutive timeout count / fallback-active dashboard.
- Multi-KMS primary/secondary pattern (§14.11.2) — on primary outage, operator-initiated promote to secondary (automatic fallback only when m-R6-2 `[audit.kms_auto_promote = "after_60min"]` is selected).

##### 7. DEK replication policy (R5 M-R5-3)

Manifest `[audit.dek_replication]`:

| Value | Meaning | Applicability |
|---|---|---|
| `global-hsm` (default) | Global replication by a single HSM vendor (e.g. AWS KMS multi-region key). All-or-nothing shred, SLO lag < 5min. | General deployments |
| `per-region` | Separate DEK per region. Cross-region access via re-encryption. For jurisdictions with strict per-jurisdiction data residency (EU / SG / KR). | Regulatory-sensitive |

##### 8. HSM insider threat mitigation (R5 FG3)

An HSM root operator can forge attestations → risk of issuing a "destroyed" receipt without actual destruction. R5.1 defenses:

1. **Multi-party threshold HSM (t-of-n Shamir)** — the master key permits export/destroy only with `t` approvers. Recommended: `t=3, n=5`. A single operator cannot tamper with keys.
2. **Public transparency log** — register `UserErasureCompleted` event hash + HSM attestation in **Sigstore/Rekor** (or an in-house Merkle + periodic publish). External auditors verify independently.
3. **Tamper-evident counter** — include the destruction log sequence number (monotonic counter) in HSM attestation. Detect gap / rewind.
4. **§14.11 runbook items** (below) — procedures for periodic attestation verification.

##### 9. GDPR precedent / regulatory citations (R5 FG4)

Legal basis that crypto-erasure satisfies GDPR Art. 17 "effective erasure":

- **EDPB Guidelines 04/2019** (Controller/Processor) — rendering data into an irrecoverable state.
- **EDPB Opinion 04/2022 on Transfers** — pseudonymisation → anonymisation via key destruction.
- **Article 29 WP Opinion 05/2014 on Anonymisation Techniques** — irreversibility criteria + crypto-erasure path.
- **ICO Anonymisation guidance (2023)** — key destruction recognized as "unrecoverable".
- **UK DPA 2018 Schedule 3** — cryptographic erasure as part of technical measures.

Detailed evidence is in `docs/Legal/gdpr-crypto-erasure.md` (separate doc accompanied by legal review). §14.9.1 covers operational policy only.

##### 10. §14.9.1.1 Operator runbook (R5 M-R5-2)

GDPR erasure request processing sequence:

1. L2 UI submits a `GdprEraseUser` Action → `UserErasureScheduled` event recorded in the WAL.
2. L2 erasure-cascade observer starts Component-level removal batches (§14.9).
3. On completion of all Component removal, L2 calls HSM `delete_key(dek_id)`.
4. The HSM's returned attestation → emit `UserErasureCompleted` event (in WAL).
5. `BackupErasurePropagated` event — after per-region tombstone apply (§14.11.1).

**HSM call failure handling (exp backoff ×3)**:

| Attempt | Wait | Action |
|---|---|---|
| 1 | Immediate | HSM `delete_key` call |
| 2 | 1 min | Retry |
| 3 | 5 min | Retry |
| 4 | 30 min | Retry + operator PagerDuty |
| >4 | — | `observer_state='degraded'` + regulator notification preparation |

**Receipt re-verification path**: `runtime-doctor erasure-verify --user <id>` — re-verifies the attestation of the `UserErasureCompleted` event in the WAL against the HSM public attestation key.

Detailed runbook (command sequence / rollback rule / cross-region propagation verification) is in `docs/runbook/crypto-erasure.md` (separate doc planned).

##### 11. Coexistence basis: L0 A14 vs GDPR Art. 17

L0 A14 guarantees "WAL bit-identical replay"; GDPR Art. 17 demands "personal data erasure". Crypto-erasure makes both principles coexist:
- WAL ciphertext preserved permanently (L0 A14 maintained).
- Plaintext irrecoverable via DEK shred — GDPR "effective erasure" (formally acknowledged by ICO/EDPB).
- Replay is bit-identical at the ciphertext level — L0 A1 maintained.
- Plaintext-level replay is impossible for erased users (interprets the L0 A14 scope at the ciphertext level).

**E-user-3 extension**: retains RUNTIME-ASSERTED (SLA-based). Crypto-shred completion is anchored by the L0 WAL `UserErasureCompleted` event, externally verifiable via HSM attestation + transparency log.

##### 12. Compliance Tier — R5.2 C-R6-1 introduced

BBS minimal shell (nickname + post password + telnet) illustrates a small-scale deployment with real users that cannot roll out alpha under an HSM-only cost structure. Three tiers make operating cost vs compliance requirements explicit — resolves the mismatch between spec and realistic operators.

| Tier | Condition | DEK backend | GDPR response | Monthly KMS cost (2026 baseline) | Target |
|---|---|---|---|---|---|
| **Tier-0** (dev/alpha) | `runtime_current ≤ "0.15"` + `runtime_max ≤ "0.15"` (GF1 cross-check) | `software-kek` | **Not guaranteed** — real users forbidden | $0 (process memory) | Dev/integration tests, private staging |
| **Tier-1** (small shell) | production runtime + AWS KMS free-tier (monthly 20,000 requests free) or GCP Cloud KMS free-tier | `kms` (vendor managed) | **Compliant** — Art. 17 crypto-erasure possible | $0–$50 (1–10k users, using the monthly DEK round-trip ≤ 20k req) | **BBS reference shell realistic alpha/beta path**, individual developers / small communities |
| **Tier-2** (production) | 10k+ users + high-throughput + strict regulation | `hsm` + Multi-KMS (§14.11.2) + threshold HSM (§14.11.3) + transparency log (§14.11.4) | **Enterprise-compliant** — full-stack audit / regulator response | $500+ (Multi-region HSM + transparency) | Commercial services, regulated industries |

**Tier migration paths**:
- **Tier-0 → Tier-1**: full erasure (§14.7 Option 1 default). No real user data, no loss.
- **Tier-1 → Tier-2**: live migration — re-wrap DEK envelopes to a new Multi-KMS environment (HSM-to-HSM exchange) + activate transparency log. `runtime-doctor tier-upgrade --to 2` command (v0.13+ implementation). During migration not in `observer_state='degraded'` — re-wrap is an HSM-internal operation; the Runtime only updates the wrapped_dek pointer.

**AWS KMS free-tier deployment guide** (Tier-1): `docs/guide/kms-free-tier.md` as a separate document — AWS KMS symmetric key + GenerateDataKey API + per-user DEK envelope + DEK round-trip pattern within the monthly 20k req. Linked from §15.5 roadmap v0.13 BBS deployment guide.

**Tier declaration** (manifest):
```toml
[audit]
compliance_tier = 1     # 0 | 1 | 2 — operator declaration; validation cross-checks against the above conditions
```
`compliance_tier = 0` parses successfully only in alpha-only manifests. `compliance_tier = 2` forces the Multi-KMS + transparency log manifest blocks.

**R5.3 mR7-α — tier ↔ backend cross-check**: `compliance_tier` is an operational policy declaration; `dek_backend` is a technical choice. Validation cross-checks their consistency — both values are required manifest fields. Example: `compliance_tier = 0` + `dek_backend = "hsm"` is inconsistent (Tier-0 is software-kek only) → `ManifestError::TierBackendMismatch`. Conversely `compliance_tier = 2` + `dek_backend = "software-kek"` is also rejected.

**R5.3 HF1 Tier-0 threat model annotation**: Tier-0 (software-kek) assumes a holder of host-OS access is **effectively a master-key holder**. Internet isolation + air-gap operation recommended. Process protection (§14.7 M-R6-4 HF1) offers only capability / dump / ptrace-level protection — cannot defend against a host-root attacker. Do not introduce real-user PII into a Tier-0 environment.

##### 13. Multi-region atomic shred — R5.2 GF4 / 2PC

GDPR erasure must achieve DEK deletion across all regions **all-or-nothing**. If only some regions delete + other regions retain independent DEKs, an adversary can restore the incomplete-region backup + HSM unwrap → decrypt PII.

**2PC procedure**:

1. **Phase 1 (prepare)**: L2 erasure-cascade fans out `delete_key(dek_id)` to every region HSM (concurrent). Wait for each region's response.
2. **Per-region progress event**: on receiving each region's attestation, emit `Op::EmitEvent(PerRegionErasureProgress { user, region, shred_tick, attestation_class, attestation_bytes })` (§3.2 TypeCode 0x0003_0F08). WAL chain-anchored.
3. **Phase 2 (commit)**: emit `UserErasureCompleted` **only after every region's PerRegionErasureProgress has been received**. Concatenate every region's attestation into `UserErasureCompleted.attestation_bytes`, or include as a separate multi-region attestation structure.
4. **Retry + SLA**: on individual region failure, apply the §14.9.1.1 runbook backoff (1m/5m/30m ×3). If not all regions complete **within SLA (p95 < 24h)** → operator alert + regulator notification preparation. `PerRegionErasureProgress` emits only for partially-complete regions — `UserErasureCompleted` is held.

   **R5.3 mR7-β — auto resume on L2 passive promotion**: during failover, when a passive L2 transitions to `observer_state='active'`, `runtime-doctor per-region-erasure-audit` auto-pushes users who emitted `PerRegionErasureProgress` without a final `UserErasureCompleted` onto a resume queue. Runbook backoff retry applied sequentially; operator intervention only on SLA miss. The transition itself is a path that restarts user-visible behavior — recommended to always execute promote and audit together.
5. **Restore flow (§14.11.1 integration)**: on restore, cross-check the tombstone_log + WAL `PerRegionErasureProgress`. Missing a region's tombstone = restore refuse. Partial progress existing for all regions + no final `UserErasureCompleted` = **incomplete erasure state** — skip/delete all that user's region ciphertext on restore (fail-safe).

**Operator tools**:
- `runtime-doctor per-region-erasure-audit --user <hashed-id>` — dashboard of each region's `PerRegionErasureProgress` status + `UserErasureCompleted` emission.
- Partial-completion user list + SLA monitoring.

**Single-region environment**: with `[audit.dek_replication = "global-hsm"]` + the vendor's own multi-region replication, 2PC degenerates to unary (region count = 1). Single `PerRegionErasureProgress` event + immediate `UserErasureCompleted`.

### §14.10 Scaling Path — new section (veteran m2)

**Current upper bound**: single instance ~200 Action/sec (§10.4).

**Scaling options**:

**Option A — shell-per-instance sharding** (connects to v0.99+ federation)
- Each shell gets its own kernel instance.
- Cross-shell User via the identity federation layer (v0.99+) → projection.
- Pros: per-instance load reduced. Cons: User cascade distributed, cross-shell query needs a per-adapter layer.
- Out of R1-R4' scope — requires federation DIP first.

**Option B — user-range sharding** (production candidate)
- Instance per user-ID range (e.g. user_id mod 16 = instance index).
- Pros: distributes a single shell's high load. Cons: user migration cost, cross-instance Activity required (inverse of Option A).
- Out of R1-R4' scope.

**Option C — L2 read-replica + PG-only tiered** (realistic for alpha/beta, integrates R5 Axis 3)
- Single active L2 writer, N passive readers.
- Read path distributed via PostgreSQL read replicas (+ Redis cache in production).
- Write path still a single kernel instance (inherits A2 determinism).
- Pros: read 10–100x scale. Cons: write-side upper bound unchanged.
- **Within R1-R5.1 scope. Default deployment model for alpha/beta.**

**Explicit storage tier (R5 Axis 3 — team-lead directive 2026-04-24, unanimous among 4)**:

| Tier | User scale | req/s | Primary store | Redis |
|---|---|---|---|---|
| alpha | < 1k | < 100 | PG-only (UNLOGGED idempotency/rate-limit + LISTEN/NOTIFY fanout) | **Not required** |
| beta | 1–10k | < 1k | PG primary | optional (dedicated idempotency/rate-limit) |
| production | > 10k | > 1k | PG + Redis required | **Required** (cache/queue, bypasses PG lock contention) |

- alpha / beta use the PG-only path to ease operator learning + reduce security surface (cryptographer recommendation — Redis CVE-2022-0543 RCE, Sentinel master election race, RedLock critique, ACL misconfiguration).
- Production transition requires Redis — absorbs the §10.4 single-thread ceiling.

**Production-verdict path**:
- alpha (< 1k users) / beta (< 10k users): Option C PG-only / PG+optional-Redis.
- Production (> 10k users): Option C PG+Redis → at v0.99+, re-evaluate Option A and introduce federation.
- MMORPG-scale demand is refused in §1.2 + separate DIP in §8.4.

### §14.11 Backup & Disaster Recovery — new section (C7 / N5 / P4 / S6)

**Policy summary**:
- **WAL-first strategy**: L0 WAL is the primary backup. Inherits append-only + fsync ordering.
- **Projection = re-derived by WAL replay**: on corruption, reconstruct via §12.5 partial replay.
- **Multi-region WAL streaming replication**: async (non-blocking for the critical path). primary region → secondary region replicates fsync'd WAL appends.
- **RPO target** < 1 min (WAL streaming lag bound).
- **RTO target** < 30 min (cold start + WAL replay + projection rebuild).

**Backup digest verification** (3-tuple, R5 NF4 — "sidecar" wording substitution):
```
(manifest_digest, chain_tip, runtime_semver)
```
- `manifest_digest` canonical TOML BLAKE3 (C5).
- `chain_tip` L0 WAL BLAKE3 chain tip (A13).
- `runtime_semver` in-band `RuntimeBootstrap` event in the WAL (§14.7 / E12).
- On backup restore, verify the 3-tuple — mismatch = corruption.

**Offsite at-rest encryption** (S6):
- Backup storage encryption **mandatory**.
- HSM/KMS recommended (concrete deployment at discretion — AWS KMS / GCP Cloud KMS / on-prem HSM).
- Key-rotation policy annotation (e.g. 90d cadence).
- Backup key separated from the WAL key — backup compromise independent from live WAL compromise.

**Weekly backup integrity audit**:
- `arkhe-runtime-doctor backup-verify` — random-sample WAL slice replay + 3-tuple re-verification.
- On audit failure → PagerDuty + operator intervention.

**Snapshot rotation (P4)**:
- Daily snapshot + 7-day retention (hot).
- Weekly snapshot + 12-week retention (warm).
- Monthly snapshot + 5-year retention (cold archive, offsite).
- A snapshot is L0 `KernelSnapshot` + L2 projection digest.
- `arkhe-runtime-doctor snapshot-rotate` command.

**WAL retention**:
- 90-day hot (replay RTO bound — a 10-yr WAL implies replay RTO hours~days → infeasible).
- > 90d archived (offsite cold storage, encrypted).
- Snapshot + most-recent 90d WAL achieves RTO < 30min.
- On replay, start from a snapshot (inherits L0 snapshot support).

**Runbook**:
- **Primary region outage** → secondary region promote (passive → active) + redirect WAL streaming source.
- **Projection corruption** → `runtime-doctor reset-projection` + WAL replay.
- **WAL corruption** (chain tip mismatch) → restore backup snapshot + replay to the verified last-known-good.
- **Silent data corruption** → weekly audit catches it → restore backup + re-review the changed delta.

**Multi-region setup (recommended for v1 alpha/beta)**:
- Primary: single region active.
- Secondary: 1–2 regions passive (WAL streaming).
- On disaster, operator-initiated promotion.
- Full multi-master is the same as §14.8 multi-active — separate DIP.

#### §14.11.1 Erasure propagation to offsite backup — new section (M6)

**Problem**: the leader S6 backup encryption is at-rest only. During a backup rotation cycle (e.g. 30 days), erased-user PII remains as ciphertext. On restore, deleted records resurface → GDPR violation.

**Solution (integrated with M5 crypto-erasure)**:
1. **Per-user DEK deletion = simultaneous invalidation of all backup-replica ciphertext**. Since the DEK exists only in HSM/KMS, post-shred no backup can decrypt the ciphertext.
2. **Tombstone log**: write a separate `tombstone_log` to backup storage — `TombstoneForUser { user_id, erased_tick, receipt_class: RuntimeSignatureClass, receipt_bytes: Bytes }`. Propagate to every offsite replica. The receipt is signed with the key corresponding to manifest `[audit.signature_class]` (§14.7 / E13).
3. **Per-region tombstone (R5.2 GF4)**: under multi-region deployment (`dek_replication = "per-region"`), write a `tombstone_log` per region. Include a `region` field in `TombstoneForUser`. **Restore flow**: on restore, cross-check every region's tombstone + WAL `PerRegionErasureProgress` events. Missing a region's tombstone → **restore refuse** (`RestoreError::MissingRegionTombstone`). For users in partially-complete state, restore skips/deletes the ciphertext (fail-safe).
4. **Restore consistency**: apply tombstones first → skip/delete ciphertext of users without a DEK. Post-restore verify `UserErasureCompleted` event count == tombstone count (refuse restart on mismatch).
5. **Propagation SLA**: offsite backup tombstone apply **p99 < 7 days** (meets regional legal requirements).
6. **Evidence log**: `Op::EmitEvent(BackupErasurePropagated { user, region, applied_tick, receipt_class, receipt_bytes })` — per-region apply evidence. Permanently anchored in the WAL chain. See §3.2 Event struct definitions.
7. `arkhe-runtime-doctor backup-erasure-audit` command — dashboard of every region's tombstone-apply status + `PerRegionErasureProgress` completion status.

#### §14.11.2 Multi-KMS primary/secondary — R5 C-R5-5a / FG2 runbook

**Purpose**: eliminate HSM/KMS single-vendor SPOF. On primary KMS outage, auto-fallback to secondary.

**Composition**:
- Primary KMS (e.g. AWS KMS multi-region key, globally-replicated DEK) — normal path.
- Secondary KMS (e.g. GCP Cloud KMS or on-prem HSM) — fallback path.
- The DEK envelope is **wrapped on both KMS and each wrapped copy is retained** — `wrapped_dek_primary` + `wrapped_dek_secondary` Runtime state. Decryption possible with whichever is live.

**Fallback procedure**:
1. Repeated primary KMS timeout / 5xx (§14.9.1 §§6 threshold) → L2 health check fails → `observer_state='degraded'`.
2. **R5.2 m-R6-2 — operator 60-min SLA**: after degraded transition, the operator is obligated to decide on promotion within 60 min. Manifest `[audit.kms_auto_promote]`:
   - `"manual"` (default) — operator manual promote. PagerDuty escalation after 60 min.
   - `"after_60min"` — automatic fallback (accepts split-brain risk). After 60 min, secondary auto-promoted + audit log.
3. Promote command: `runtime-doctor kms-promote --to secondary --reason <incident-id>` — mandatory operator Ed25519 sign + `runtime_doctor_journal` append. In auto mode, the runtime signs with a substitute (system key) + journal record.
4. Post-promote, secondary takes primary's role. New DEKs are created on secondary + re-wrapped after primary recovers.
5. After primary recovers: `runtime-doctor kms-rewrap-all` — regenerate primary wrapped copies for all active DEKs.

**DEK sync SLA**: Primary→Secondary wrap synchronization p99 < 60s (HSM vendor cross-region replication). Sync lag warning metric `arkhe_runtime_kms_sync_lag_seconds`.

**R5.2 GF6 — Multi-KMS shred path unified**: on `GdprEraseUser` cascade, **operator-issued single command** concurrently fans out `delete_key(dek_id)` to primary + secondary KMS. `UserErasureCompleted` **must never** be emitted before attestations from both are received — same principle as §14.9.1 §§13 GF4 2PC, extended to the KMS layer. Restoring a backup while one KMS is shred-complete and the other is not + unwrapping via the remaining KMS = PII decryptable — this path is blocked. Per-KMS progress is emitted explicitly via the `KmsIdentifier` variant of `PerRegionErasureProgress.scope` (R5.3 mR7-γ).

#### §14.11.2.1 Auto Promote Trust Model (R5.3 HF2)

The manifest `[audit.kms_auto_promote]` default remains `"manual"` — only opt-in to `"after_60min"` in production is recommended. The auto-promote path is a security-critical trust shift; explicitly acknowledge the following model:

**Split-brain risk acknowledgement**:
- Via BGP hijack / DNS poisoning / TLS mis-issuance, an adversary can selectively block the primary KMS → after the 60-min timer, **auto-fallback to an adversary-controlled secondary** may occur.
- Distinguishing whether a timeout is a network-level attack or a genuine KMS outage — not possible with a single-channel health check.

**Mitigations (mandatory when auto-promote is enabled)**:
1. **Multi-channel health check** — the `arkhe_runtime_kms_health_channels{channel, region}` metric (§12.4) runs health checks **in parallel** via DNS-over-HTTPS (DoH) / alternate region path / static-IP fallback. Do not trigger auto-promote on a single-channel failure — only on simultaneous failure of N-of-M channels (recommended 2-of-3).
2. **Require threshold-HSM operator pre-sign (t-of-n Shamir)** — auto-promote must not be signed by the system key alone (restricts the system-key path in §14.11.2 existing fallback procedure §3). Distribute `t=2 of 3` operator pre-signed authorization tokens in advance + consume them on use. When auto-promote fires, record the consumed token in `runtime_doctor_journal` — an external auditor can see operator-approval evidence.
3. **Explicit admin-UI enablement recommended** — a path enabled by manifest edits alone carries silent-enable risk on deployment-pipeline leak. Recommend a 2-step: explicit activation in the admin UI (separate ACL + MFA), then manifest reflection. Scope of the v0.13 admin dashboard.

**Default retention**: `"manual"` — operator manual promote is the safest path. Auto-promote should be opt-in only in environments with high availability demand + all 3 mitigations in place.

#### §14.11.3 HSM attestation public transparency log — R5 FG3

**Purpose**: defense against HSM insider threat + attestation forgery.

**Composition**:
- Register every `UserErasureCompleted` event's `attestation` + HSM destruction log sequence number in **Sigstore/Rekor** (recommended) or an in-house Merkle log + periodic publish.
- In-house Merkle log path: Runtime inserts tick-level attestation hash batches into `transparency_log_entries(log_index BIGSERIAL, attestation_hash BYTEA, published_tick BIGINT)` + publicly publishes the log root as a weekly GitHub release / internal publish.
- External auditors cross-check the `/erasure-receipt/{user_id}` endpoint (§14.11.4) with the transparency log index — independently verify that the HSM attestation was logged.

**Tamper-evident counter**:
- HSM attestation payload includes a destruction log sequence number (monotonic counter).
- Gap / rewind detection: the transparency log verifies counter continuity (missing seq → alert).

**Periodic audit**:
- Weekly `runtime-doctor transparency-verify` command — cross-checks the last 100 attestations against the transparency log; any mismatch → PagerDuty + regulator notification preparation.

#### §14.11.4 Public erasure receipt endpoint — R5 veteran m-R5-1

**Purpose**: GDPR regulators / users / external auditors independently confirm erasure evidence.

**Endpoint**: `GET /erasure-receipt/{user_id}` (L2 public HTTP).

**Response (JWT-signed)**:
```json
{
  "user_id": "<hash-of-user-id>",         // privacy: raw user_id not exposed
  "erased_tick": 1234567,
  "dek_shred_tick": 1234580,
  "hsm_attestation": "<base64>",
  "transparency_log_index": 9876543,
  "signature_class": "Hybrid",
  "jwt_signature": "<Ed25519 or MlDsa65 over above fields>"
}
```

**Signer key** = Runtime `chain_tip_signature` key (§12.4). Rotation 90d + grace (FG8).

**Regulator public key whitelist**: manifest `[audit.regulator_verify_keys]` lists GDPR regulator public keys — on JWT verification, confirm the signature is verifiable under one of these keys, then trust.

**CLI helper**: `arkhe-verify erasure-receipt --user <hashed-id> --endpoint https://...` — JWT + transparency log independent verification.

**R5.3 HF3 — direct WAL chain-tip re-verification (fail-close)**: the public endpoint responds only after **re-verification against the WAL chain tip**, not the `kernel_projection_state` row cache. The projection row is a read cache — to forge a row an adversary would have to also forge the Ed25519/PQC signature (requires HSM key possession) — but this blocks the cache-staleness / compromise path at the source. Fail-close policy: **on WAL re-verification failure return endpoint 5xx; cache response is forbidden**. Re-verification directly queries L0 `InstanceView.current_chain_tip()` + verifies `chain_tip_signature` / `signature_class` (§12.4 GF5) under the corresponding key. Implementation cost adds ~10–30ms to the read path — acceptable given the nature of a public endpoint.

---

## §15. ArkheForge Runtime naming decision

**Confirmed**: **ArkheForge Runtime** (team-lead 2026-04-24).

### §15.1 Linux kernel / userland analogy

L0 ArkheKernel = Linux kernel — resource allocation, deterministic state, WAL, single-thread scheduling. On top of L0, L1 (primitive + compute) + L2 (policy / projection / manifest / hook host) = Linux userland runtime services: just as glibc + systemd + D-Bus sustain the process ecosystem above the kernel, ArkheForge Runtime sustains the primitive-execution ecosystem above ArkheKernel.

R1's "Engine" risked conflict with the L0 kernel category, carrying the "core itself" image of browser/game engines. "Runtime" makes transparent that L0 is already the kernel position.

### §15.2 "Forge" choice

- R1 alternatives "Stage / Loom / Axis" are outcome-oriented, weaker on the production-process image.
- "Forge" implies a repetitive hammering production process. The opposite axis to the Rails/Meteor failure — forging empirically demonstrated duplication.
- Pronounces cleanly across languages.
- A smithy metaphor — hammering primitive raw materials to manufacture shells.

### §15.3 Full naming

| Component | Name |
|---|---|
| Microkernel | ArkheKernel |
| Runtime | **ArkheForge Runtime** |
| Runtime crate | `arkhe-forge` |
| L1 primitive crate | `arkhe-forge-core` |
| L2 platform crate | `arkhe-forge-platform` |
| Offline migration tool | `arkhe-runtime-doctor` |
| ABI compat CI gate | `arkhe-forge-abi-check` |
| Admin access | `arkhe-runtime-admin` |
| Reference shell 1 | ArkheNet BBS |
| Reference shell 2 | ArkheCasino |
| Reference shell 3 (planned) | GuildChat |
| Audit verifier | `arkhe-verify` (shared L0) |
| Casino verifier | `arkhe-casino-verify` (shell-provided) |

The "Engine" / "engine-*" prefix is **retired entirely** after R4'.

### §15.4 v0.13 DIP candidate roadmap (C4 Band 3 primitive official registration)

In R4'.1 cryptographer C4, Band 3 engine support was confirmed as option B (scope refusal). The future entry path is officially registered as the following roadmap:

**v0.13 DIP candidate — Band 3 primitive promotion**:
- **Prerequisite**: completion of empirical evidence from **3 or more shells** among E2E DM / threshold vote / Casino.
- **Promotion content**:
  - `BandThreePhase` Component (phase FSM state).
  - `Band3Action::required_phase()` compile-time enforcement — R5 m-R5-1 preview:
    ```rust
    // v0.13 preview — per-Action phase compile-time enforcement via associated const
    pub trait Band3Action {
        const REQUIRED_PHASE: Phase;
    }
    // compute compares the phase Component against Self::REQUIRED_PHASE → mismatch rejects.
    // May be further promoted via a typestate wrapper (BandThreePhase<Expected>).
    ```
  - Standardization of `arkhe-<shell>-verify` tool interface (common trait `Band3VerifierAdapter`) + shell binary chain-attestation (R5 R5-r5) — binary BLAKE3 digest + Ed25519/PQC operator signature + Sigstore/Rekor transparency log entry. Manifest `[shell.verifier_attestation]` pins digest + log index.
- **Refusal conditions** (re-review gate):
  - If 2+ of the 3 shells prove "sufficient" via a shell-scoped implementation, refuse primitive promotion.
  - If the Runtime semver impact breaks 2+ shells, split into a derivative DIP (v0.13.1).
- **Tier goal**: promote Band 3 phase ordering to **TYPE-PROVEN** (typestate `BandThreePhase<Expected>`).

Current scope remains **Runtime core Band 3 non-commitment** — the shell is responsible for its own FSM + audit tool (§9.3 scope refusal).

### §15.5 Runtime semver roadmap — R5 M-R5-5 introduced

Officially registers future DIP candidates for the ArkheForge Runtime. Each DIP carries gate criteria + dependencies + target semver. Versioning increments as integers 0.11 → 0.12 → ... → 0.99 → 0.100 (1.0 is never reached).

| DIP candidate | Target semver | Gate criteria | Dependency |
|---|---|---|---|
| **Room primitive** | v0.13 | 2+ shell evidence (2 of BBS conversation rooms / TubeLike live / GuildChat) | — |
| **Band 3 primitive (`BandThreePhase`)** | v0.13 | 2+ shell evidence (Casino + one of E2E DM / threshold vote) + agreement on the `Band3VerifierAdapter` standard trait | (optional) Room — may be included together |
| **SpaceMembership primitive** | v0.14 | 3-shell evidence (BBS / Guild permissioning / DM) + completion of Room membership-absorption analysis | Room |
| **Attachment → dedicated primitive promotion** | v0.14+ | Currently judged sufficient as Axis 1 Component (§8.2). Re-evaluate only with 5-shell evidence + blob scale pressure. | — |
| **Active-multi L2** | v0.15+ | 10k+ user deployment + empirical limits of PG-only resolution for mutex races. Distributed lock design without determinism contamination must precede. | — |
| **Multi-instance active federation** | v0.16+ | User-range or shell-per-instance sharding evidence (§14.10 Option A/B) | — |
| **Federation (cross-instance)** | v0.99+ | `SignedArkheUri` + protocol spec + identity federation layer completion | ArkheUri E10 + SignedArkheUri + completed PQC transition |

**v0.12 alpha blocker docs (R5.2 M-R6-3 / R5.4 R8-m2 extension)** — must be completed before alpha release:

| Document | Path | Owner | Purpose |
|---|---|---|---|
| Operator runbook (crypto-erasure) | `docs/runbook/crypto-erasure.md` | veteran + cryptographer | §14.9.1.1 HSM call sequence + backoff + re-verification |
| GDPR legal basis | `docs/Legal/gdpr-crypto-erasure.md` | legal reviewer (external) + cryptographer | §14.9.1 §§9 precedent-based documentation |
| AWS KMS free-tier guide | `docs/guide/kms-free-tier.md` | veteran + BBS maintainer | Tier-1 (§14.9.1 §§12) deployment instructions, monthly 20k req free path |
| HSM degraded mode runbook | `docs/runbook/hsm-degraded-mode.md` | veteran | §14.9.1 §§6 threshold + fallback + recovery |
| Alpha → beta promote runbook | `docs/runbook/alpha-to-beta-promote.md` | veteran + BBS maintainer | R5.4 R8-m2 — (a) `AuthCredential` rotation procedure (`bound_tick` promote + `expires_tick` grace window) (b) user notification template (email / in-session notice) (c) non-rotated users blocked from login (`alpha_credential_rotation_required = true` enforcement) (d) rollback path (emergency `bound_tick` revert) |

Entering the v0.12 implementation DIP requires all 5 drafts complete. Final review before alpha release.

**v0.12 implementation tracking (R5.4 R8 handoff, 2 items)** — spec-level decisions are done; resolved in the implementation DIP:

| Item | Source | Owner | Implementation scope |
|---|---|---|---|
| Process protection platform abstraction | R5.4 cryptographer HF1 handoff | cryptographer + veteran | Abstract Linux (`mlock_all()` + `prctl(PR_SET_DUMPABLE, 0)` + `yama.ptrace_scope=2` or setuid) / macOS (`PT_DENY_ATTACH` + `VM_MAKE_NOMAP`) / Windows (`SetProcessMitigationPolicy(ProcessDynamicCodePolicy + ProcessExtensionPolicyInformation)` + `DebugSetProcessKillOnExit`) behind a `trait ProcessProtection`. Runtime startup selects the platform impl. Flattens §14.7 M-R6-4 HF1 3-part requirements. |
| Manifest bypass audit | R5.4 cryptographer HF4 handoff | cryptographer | The combination `[frontend.alpha_credential_rotation_required = false]` + `runtime_max ≥ "0.16"` produces a **WARN** (not a reject) + prints deployment guide notice. Appends to `runtime_doctor_journal` (operator identity + timestamp + bypass reason — manifest comment required). Leaves the operator's bypass declaration accountability in the audit trail. |

**v0.13 BBS reference shell deployment guide (R5.2 C-R6-1 / R5.3 M-R7-1 / HF4)**:
- `docs/guide/bbs-deployment.md` — nickname + post password + telnet-over-TLS (RFC 2946) + stunnel configuration + AWS KMS free-tier connection.
- Demonstrates that a BBS shell's minimal scope (1 board + 1 chat room) can be deployed at Tier-1 — aligning spec with operator reality.
- **Telnet client TLS wrap matrix (R5.3 M-R7-1)** — client configuration range per platform:
  - **macOS**: `stunnel` (brew install stunnel) + example config.
  - **Windows**: PuTTY + TLS-Telnet plugin, or the Windows stunnel binary.
  - **Linux**: `stunnel` or `socat` (openssl-wrapper).
  - **Mobile (iOS / Android)**: native telnet clients lack TLS support — **recommend the WebSocket-over-TLS alternative**. The BBS reference shell plans to provide a `telnet-ws` adapter (WebSocket frame ↔ Telnet NVT variant) (v0.13 scope).
  - Setup scripts as per-platform deliverables (`docs/guide/bbs-telnet-tls-<platform>.sh`).
- **Alpha → beta credential rotation (R5.3 HF4)**: `AuthCredential`s created during the alpha period (Tier-0 software-kek) **must** be rotated + session tokens invalidated on beta promote. Default: manifest `[frontend.alpha_credential_rotation_required = true]`. Rotation procedure: ask every user to re-register credentials → set existing AuthCredentials' `expires_tick` to the promote tick → non-rotated users are blocked from login in the beta environment.

**v0.13 nice-to-have docs (R5.3 veteran m-R7-1 carryover)**:
- `docs/guide/grafana-dashboard-templates.md` — Grafana dashboard JSON templates based on §12.4 metrics + §12.4.1 SLO table. Includes `arkhe_runtime_event_total{event_type, shell_id}` / `_projection_lag_seconds` / `_hsm_unavailable_total` / `_dek_message_count` / `_kms_sync_lag_seconds`. v0.13 deliverable; v0.12 alpha leaves operators to configure themselves.

**v0.13 DIP candidate (R5.3 auditor mR7-δ carryover)**:
- `ComplianceTierChange` event — records tier transitions (Tier-0 → Tier-1 etc.) chain-anchored. TypeCode `0x0003_0F0A` reserved. Necessity: a tier change is a runtime operations policy change, subject to external audit — currently only logged in the operator journal; v0.13 considers event promotion.

**Common gate requirements**:
- 1 of the §7.4 4 gates + 2+ shell evidence (for New-Primitive).
- Runtime semver impact assessment — split into derivative DIP on 2+ shell breakage.
- Confirm no impact on the 8 L0 DO NOT TOUCH items + BoundedString sealed wrapper.

**Consistency when running concurrently**:
- When multiple DIPs target the same semver (e.g. v0.13) — the leader decides on integration. Integrated: single clean-round cycle; split: each DIP proceeds independently.
- Federation (v0.99+) depends on results from other DIPs — cannot be pursued standalone.

**Refusal / deferred**:
- MMORPG tick-sync state primitive — rejected in §1.2, scoped out via the separate DIP "game-kernel overlay" in §8.4.
- Active-master Sync primitive — cannot inherit determinism; out of Runtime scope.

---

## §16. References

- `arkhe-kernel` v0.11 — `/arkhe-kernel/`.
- `book/src/architecture/invariants.md` — L0 A1-A24 + S1.
- `book/src/architecture/threat-model.md` — L0 AI-adversary.
- `book/src/architecture/domain-spec.md` — L0 L1 boundary.
- `book/src/architecture/overview.md` — L0 overview.
- Shell requirements catalogs — maintained per shell repository (e.g., `arkhe-shell-bbs`). This repo houses only L0 + Runtime.
- **`docs/Review/r2-findings-2026-04-24.md`** — R2 cold-read archive (basis for R3 integration).
- **`docs/Review/r4-findings-2026-04-24.md`** — R4 cold-read archive + leader performance/security (basis for R4' integration).
- **`docs/Review/bounded-string-analysis-2026-04-24.md`** — `BoundedString<N>` crate selection analysis (basis for §3.4).
- **`docs/Review/r4-cryptographer-findings-2026-04-24.md`** — R4 cryptographer cold-read (basis for R4'.1 micro-revision). 17 items: Critical 4 / Major 9 / Minor 4.
- **`docs/Review/r5-findings-2026-04-24.md`** — R5 4-person cold-read (basis for R5.1 micro-revision). Critical 5 / Major 12 / Minor 15+ + Axis 3 PG-only tiered (unanimous among 4) + HSM fallback (team-lead directive 2026-04-24).
- **`docs/Review/r6-findings-2026-04-24.md`** — R6 4-person full clean round (basis for R5.2 micro-revision). Critical 1 / Major 11 / Minor 13. Team-lead option 2 confirmed.
- **`docs/Review/r7-findings-2026-04-24.md`** — R7 4-person clean round (basis for R5.3 micro-revision). Critical 0 / Major 3 / Minor 15 (12 reflected, 3 deferred). Team-lead option B confirmed.
- **R8 verification round** (2026-04-24, basis for R5.4 micro-patch) — Critical 0 / Major 0 / 5 new Minor (3 reflected in spec + 2 handed off to v0.12 implementation). N=2 consecutive clean achieved. Team-lead decision: skip R9 + close via leader self-review → enter v0.12 implementation DIP.
- **`docs/runbook/crypto-erasure.md`** — operator runbook (v0.12 alpha blocker, see §14.9.1.1 / §15.5).
- **`docs/Legal/gdpr-crypto-erasure.md`** — GDPR crypto-erasure legal basis (v0.12 alpha blocker, see §14.9.1 §§9 / §15.5).
- **`docs/guide/kms-free-tier.md`** — Tier-1 AWS KMS free-tier deployment (v0.12 alpha blocker, see §14.9.1 §§12 / §15.5).
- **`docs/runbook/hsm-degraded-mode.md`** — HSM outage runbook (v0.12 alpha blocker, see §14.9.1 §§6 / §15.5).
- **`docs/guide/bbs-deployment.md`** — BBS reference shell deployment (v0.13 target, see §15.5).
- L0 DO NOT TOUCH: `DOMAIN_CTX`, `InvariantLifetime`, `Principal`/`KernelEvent`/`StepStage` derives (including L0 `SignatureClass` — per R5.2 NR6-4 inspection, the Runtime extends this with `RuntimeSignatureClass`, §14.7), A11 MC tag, ROADMAP v0.99+ Deferred, R4-X DAG, `EventMask` bit allocation, `WalRecord` postcard field order.
- Runtime dylint CI gate: `#[arkhe_runtime_forbidden_modifier]` (§2.3).
- Runtime ABI CI gate: `arkhe-forge-abi-check` (§14.7).

**End of Runtime Spec.**
