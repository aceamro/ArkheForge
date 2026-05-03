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

