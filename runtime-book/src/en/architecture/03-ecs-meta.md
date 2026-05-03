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
- `arkhe-runtime-doctor-journal-chain` — §12.4 `runtime_doctor_journal` chain hash domain (HF2 audit-log tamper-resistance, §14.11.2)

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

