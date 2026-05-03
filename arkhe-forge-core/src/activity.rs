//! Activity primitive — actor→target verb (spec §4.5).
//!
//! Three-layer split (R4' C1 / NC1):
//! - [`ActivityRecord`] — storage-safe Component, `'static`, postcard-canonical.
//! - [`Activity<'s>`] — runtime-only branded wrapper used at submit-site for
//!   compile-time shell isolation.
//! - [`SubmitActivity`] — brand-less Action consumed by L1 compute.
//!
//! Verb codes live in two sub-ranges: canonical (`0x0002_0001..=0x0002_03FF`,
//! 1023 slots) and shell-extensible (`0x0002_0400..=0x0002_FFFF`, BLAKE3-derived
//! 256-verb sub-range per manifest).

use arkhe_kernel::abi::{EntityId, Tick, TypeCode};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::action::ActionCompute;
use crate::actor::ActorId;
use crate::brand::{ShellBrand, ShellId};
use crate::context::{ActionContext, ActionError};
use crate::entry::EntryId;
use crate::space::SpaceId;
use crate::ArkheAction;
use crate::ArkheComponent;
// E14.L1-Deny enforcement on Action::compute (auditor cross-review Q2(i)).
use crate::arkhe_pure;

/// Opaque handle into the runtime Activity namespace.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActivityId(EntityId);

impl ActivityId {
    /// Construct an `ActivityId` from a runtime-allocated `EntityId`. Callers
    /// must hold proof (spawn event, admin scope, or test fixture) that the
    /// id belongs to the Activity namespace — this constructor does not verify.
    #[inline]
    #[must_use]
    pub fn new(id: EntityId) -> Self {
        Self(id)
    }

    /// Underlying entity handle.
    #[inline]
    #[must_use]
    pub fn get(self) -> EntityId {
        self.0
    }
}

/// Canonical verb witness — `const C` pinned to `0x0002_0001..=0x0002_03FF`.
///
/// Value-level construction is gated: only the module-level constants in
/// [`canonical_verbs`] (which pin `C` in-range) yield a value. User code
/// cannot forge an out-of-range `CanonicalVerb<X>`.
pub struct CanonicalVerb<const C: u32> {
    _private: (),
}

/// Shell-extensible verb witness — `const C` pinned to
/// `0x0002_0400..=0x0002_FFFF`.
///
/// Value-level construction is guarded by [`ShellVerb::try_new`], which
/// checks the const `C` at invocation time; out-of-range values yield
/// `None`. Shell code typically places the construction inside a `const`
/// binding so monomorphization fails loudly when the range is violated.
pub struct ShellVerb<const C: u32> {
    _private: (),
}

impl<const C: u32> ShellVerb<C> {
    /// Construct a `ShellVerb<C>` witness iff `C` lies in the shell verb
    /// sub-range `0x0002_0400..=0x0002_FFFF` (spec §3.2).
    #[inline]
    #[must_use]
    pub const fn try_new() -> Option<Self> {
        if C >= 0x0002_0400 && C <= 0x0002_FFFF {
            Some(Self { _private: () })
        } else {
            None
        }
    }
}

/// Canonical or shell-extension verb code, wrapped for serialization.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerbCode(TypeCode);

impl VerbCode {
    /// Wrap a canonical verb.
    #[inline]
    #[must_use]
    pub const fn canonical<const C: u32>(_witness: CanonicalVerb<C>) -> Self {
        Self(TypeCode(C))
    }

    /// Wrap a shell-extensible verb.
    #[inline]
    #[must_use]
    pub const fn shell<const C: u32>(_witness: ShellVerb<C>) -> Self {
        Self(TypeCode(C))
    }

    /// Underlying dispatch code.
    #[inline]
    #[must_use]
    pub const fn code(self) -> TypeCode {
        self.0
    }
}

/// ActivityStreams-aligned canonical verb witnesses.
pub mod canonical_verbs {
    use super::CanonicalVerb;

    /// Like / upvote.
    pub const LIKE: CanonicalVerb<0x0002_0001> = CanonicalVerb { _private: () };
    /// Follow.
    pub const FOLLOW: CanonicalVerb<0x0002_0002> = CanonicalVerb { _private: () };
    /// Bookmark.
    pub const BOOKMARK: CanonicalVerb<0x0002_0003> = CanonicalVerb { _private: () };
    /// Report (moderation).
    pub const REPORT: CanonicalVerb<0x0002_0004> = CanonicalVerb { _private: () };
    /// Mute.
    pub const MUTE: CanonicalVerb<0x0002_0005> = CanonicalVerb { _private: () };
    /// Block.
    pub const BLOCK: CanonicalVerb<0x0002_0006> = CanonicalVerb { _private: () };
    /// Pin.
    pub const PIN: CanonicalVerb<0x0002_0007> = CanonicalVerb { _private: () };
    /// Flag (policy infraction).
    pub const FLAG: CanonicalVerb<0x0002_0008> = CanonicalVerb { _private: () };
}

/// Target entity of an Activity. `#[non_exhaustive]` so additional canonical
/// target families can append.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TargetKind {
    /// Entry target.
    Entry(EntryId) = 0,
    /// Actor target.
    Actor(ActorId) = 1,
    /// Space target.
    Space(SpaceId) = 2,
    /// Activity target (meta-verb — flag on a report, etc.).
    Activity(ActivityId) = 3,
    /// Shell-defined extension target.
    Extension {
        /// Extension dispatch code.
        type_code: TypeCode,
        /// Target entity handle.
        id: EntityId,
    } = 4,
}

/// BTreeMap key for Active-Activity idempotency index (E-act-1 / C1).
///
/// Includes `target_shell_id` so cross-shell bypass via type-erased entity
/// id is impossible (E-act-2 dual-tier).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub struct TargetKey {
    /// `1`=Entry, `2`=Actor, `3`=Space, `4`=Activity, `5`=Extension.
    pub kind_code: u8,
    /// `TypeCode(0)` except for Extension targets.
    pub type_code: TypeCode,
    /// Underlying entity handle.
    pub id: EntityId,
    /// Shell of the target entity — closes brand-bypass gap (E-act-2 MC).
    pub target_shell_id: ShellId,
}

impl TargetKind {
    /// Derive the idempotency key from a target descriptor.
    ///
    /// The `ActionContext` is currently unused — once `ctx.read::<C>()`
    /// ships, the target's shell is resolved from the matching storage
    /// component (`EntryCore.shell_id`, `ActorProfile.shell_id`,
    /// `SpaceConfig.shell_id`, `ActivityRecord.shell_id`, or
    /// `EntityShellId.shell_id` for Extension targets). Until then the
    /// current skeleton returns a zeroed `ShellId` placeholder; callers
    /// that need the real shell must pass it explicitly via
    /// [`TargetKind::key_with_shell`].
    #[must_use]
    pub fn key(&self, _ctx: &ActionContext<'_>) -> TargetKey {
        self.key_with_shell(ShellId([0u8; 16]))
    }

    /// Build a `TargetKey` using an explicit `target_shell_id`. Useful when
    /// the caller has already resolved the target's owner (e.g. submit-site
    /// with a freshly-authenticated `ShellBrand`).
    #[must_use]
    pub fn key_with_shell(&self, target_shell_id: ShellId) -> TargetKey {
        let (kind_code, type_code, id) = match self {
            Self::Entry(e) => (1u8, TypeCode(0), e.get()),
            Self::Actor(a) => (2u8, TypeCode(0), a.get()),
            Self::Space(s) => (3u8, TypeCode(0), s.get()),
            Self::Activity(a) => (4u8, TypeCode(0), a.get()),
            Self::Extension { type_code, id } => (5u8, *type_code, *id),
        };
        TargetKey {
            kind_code,
            type_code,
            id,
            target_shell_id,
        }
    }
}

/// Marker Component tracking the shell owner of an Extension target entity
/// (invariant E-act-7, immutable after first SetComponent).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0402, schema_version = 1)]
pub struct EntityShellId {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Owning shell.
    pub shell_id: ShellId,
}

/// Activity lifecycle status. Retracted entries are tombstoned (E-act-4).
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActivityStatus {
    /// Indexed in the `(actor, verb, target.key())` BTreeMap.
    Active = 0,
    /// Removed from the index; preserved as tombstone with retraction tick.
    Retracted {
        /// Retraction tick.
        at: Tick,
    } = 1,
}

/// Storage-safe Activity record. `'static`, postcard-DeserializeOwned,
/// brand-free — this is what the WAL stores and observers read (spec §4.5 C1).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0401, schema_version = 1)]
pub struct ActivityRecord {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Shell identity — double-checked on replay vs `ActorProfile.shell_id`.
    pub shell_id: ShellId,
    /// Acting actor.
    pub actor: ActorId,
    /// Verb code.
    pub verb: VerbCode,
    /// Target descriptor.
    pub target: TargetKind,
    /// Emission tick.
    pub at_tick: Tick,
    /// Lifecycle status.
    pub status: ActivityStatus,
    /// Shell-defined opaque payload. Runtime does not interpret — schema
    /// change implies a new `VerbCode` (E-act-3).
    pub extra_bytes: Bytes,
}

/// Runtime-only branded Activity wrapper — used at submit-site for
/// compile-time shell isolation (spec §4.5 C1).
#[derive(Clone)]
pub struct Activity<'s> {
    brand: ShellBrand<'s>,
    inner: ActivityRecord,
}

impl<'s> Activity<'s> {
    /// Construct a branded `Activity<'s>`. Caller supplies the `ShellBrand`
    /// obtained from [`ShellBrand::run`](crate::brand::ShellBrand::run) — the
    /// brand's invariant lifetime keeps this primitive from leaking across
    /// shells at the type level.
    #[inline]
    #[must_use]
    pub fn new(brand: ShellBrand<'s>, inner: ActivityRecord) -> Self {
        Self { brand, inner }
    }

    /// Borrow the underlying storage-safe record.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &ActivityRecord {
        &self.inner
    }

    /// Shell brand of this Activity.
    #[inline]
    #[must_use]
    pub fn brand(&self) -> ShellBrand<'s> {
        self.brand
    }
}

/// Submit an Activity to the runtime. Brand-less wire format — the branded
/// `Activity<'s>` is unwrapped at submit-site via [`SubmitActivity::from_branded`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0401, schema_version = 1, band = 1, idempotent)]
pub struct SubmitActivity {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Record payload.
    pub record: ActivityRecord,
    /// Opt-in idempotency key (spec §3.3 NR6-2). `None` = non-idempotent.
    pub idempotency_key: Option<[u8; 16]>,
}

impl SubmitActivity {
    /// Convert a branded `Activity<'s>` to a brand-less submit payload.
    #[inline]
    #[must_use]
    pub fn from_branded(a: Activity<'_>) -> Self {
        Self {
            schema_version: 1,
            record: a.inner,
            idempotency_key: None,
        }
    }

    /// Attach an idempotency key.
    #[inline]
    #[must_use]
    pub fn with_idempotency_key(mut self, key: [u8; 16]) -> Self {
        self.idempotency_key = Some(key);
        self
    }
}

/// Retract an existing Activity — tombstones its record and removes it from
/// the `(actor, verb, target.key())` idempotency index (E-act-4).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0402, schema_version = 1, band = 1)]
pub struct RetractActivity {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Target Activity handle.
    pub activity: ActivityId,
}

impl ActionCompute for SubmitActivity {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // E-user-3 C3 MC — refuse if the actor's backing user is in
        // `GdprStatus::ErasurePending`. Cascade owns the only legal write
        // path until completion (spec §3.3 C3).
        ctx.ensure_actor_eligible(self.record.actor, ctx.tick())?;

        if let Some(key) = self.idempotency_key {
            if ctx.idempotency_lookup(&key).is_some() {
                return Err(ActionError::IdempotencyConflict(key));
            }
        }

        // E-act-5 MC — self-loop rejection. The `preview_next_id_for` peek
        // yields the `EntityId` that the upcoming `spawn_entity_for` call
        // will produce; if the activity targets itself we refuse before
        // any `Op` is pushed to the buffer (spec §4.5 invariant E-act-5).
        let predicted = ctx.preview_next_id_for::<ActivityRecord>()?;
        if let TargetKind::Activity(target) = &self.record.target {
            if target.get() == predicted {
                return Err(ActionError::InvalidInput("activity self-loop"));
            }
        }

        let activity_entity = ctx.spawn_entity_for::<ActivityRecord>()?;
        ctx.set_component(activity_entity, &self.record)?;
        Ok(())
    }
}

impl ActionCompute for RetractActivity {
    #[arkhe_pure]
    fn compute<'i>(&self, _ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // A future release reads the existing `ActivityRecord` via
        // `ctx.read::<C>(activity_id)`, produces a tombstone variant, and
        // pushes `Op::SetComponent` with the updated status + index delta.
        Ok(())
    }
}

/// Hard cap on meta-verb depth — the runtime WAL bound on
/// `manifest.moderation.appeal_max_depth` (E-act-5). Shell manifest values must
/// fall in `1..=APPEAL_MAX_DEPTH_CAP`.
pub const APPEAL_MAX_DEPTH_CAP: u8 = 8;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::action::ArkheAction;
    use crate::component::ArkheComponent;

    fn ent(v: u64) -> EntityId {
        EntityId::new(v).unwrap()
    }

    #[test]
    fn verb_code_canonical_extraction() {
        let vc = VerbCode::canonical(canonical_verbs::LIKE);
        assert_eq!(vc.code(), TypeCode(0x0002_0001));
    }

    #[test]
    fn verb_code_canonical_vs_shell_differ() {
        let like = VerbCode::canonical(canonical_verbs::LIKE);
        let custom = VerbCode::shell(ShellVerb::<0x0002_0400>::try_new().unwrap());
        assert_ne!(like, custom);
    }

    #[test]
    fn shell_verb_try_new_rejects_out_of_range_const() {
        assert!(ShellVerb::<0x0001_0000>::try_new().is_none());
        assert!(ShellVerb::<0x0003_0000>::try_new().is_none());
        assert!(ShellVerb::<0x0002_0400>::try_new().is_some());
        assert!(ShellVerb::<0x0002_FFFF>::try_new().is_some());
    }

    #[test]
    fn activity_record_serde_roundtrip_postcard() {
        let rec = ActivityRecord {
            schema_version: 1,
            shell_id: ShellId([0u8; 16]),
            actor: ActorId::new(ent(1)),
            verb: VerbCode::canonical(canonical_verbs::LIKE),
            target: TargetKind::Entry(EntryId::new(ent(2))),
            at_tick: Tick(5),
            status: ActivityStatus::Active,
            extra_bytes: Bytes::new(),
        };
        let bytes = postcard::to_stdvec(&rec).unwrap();
        let back: ActivityRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn submit_activity_preserves_record_on_branded_unwrap() {
        ShellBrand::run(|brand| {
            let rec = ActivityRecord {
                schema_version: 1,
                shell_id: ShellId([0u8; 16]),
                actor: ActorId::new(ent(1)),
                verb: VerbCode::canonical(canonical_verbs::FOLLOW),
                target: TargetKind::Actor(ActorId::new(ent(2))),
                at_tick: Tick(0),
                status: ActivityStatus::Active,
                extra_bytes: Bytes::new(),
            };
            let activity = Activity::new(brand, rec.clone());
            let submit = SubmitActivity::from_branded(activity);
            assert_eq!(submit.record, rec);
            assert!(submit.idempotency_key.is_none());
        });
    }

    #[test]
    fn submit_activity_with_idempotency_key_attaches() {
        let rec = ActivityRecord {
            schema_version: 1,
            shell_id: ShellId([0u8; 16]),
            actor: ActorId::new(ent(1)),
            verb: VerbCode::canonical(canonical_verbs::LIKE),
            target: TargetKind::Entry(EntryId::new(ent(2))),
            at_tick: Tick(0),
            status: ActivityStatus::Active,
            extra_bytes: Bytes::new(),
        };
        let submit = SubmitActivity {
            schema_version: 1,
            record: rec,
            idempotency_key: None,
        }
        .with_idempotency_key([0xCD; 16]);
        assert_eq!(submit.idempotency_key, Some([0xCD; 16]));
    }

    #[test]
    fn activity_types_expose_trait_consts() {
        assert_eq!(ActivityRecord::TYPE_CODE, 0x0003_0401);
        assert_eq!(EntityShellId::TYPE_CODE, 0x0003_0402);
        assert_eq!(SubmitActivity::TYPE_CODE, 0x0001_0401);
        assert_eq!(SubmitActivity::BAND, 1);
        assert_eq!(RetractActivity::TYPE_CODE, 0x0001_0402);
        const { assert!(SubmitActivity::IDEMPOTENT) };
        const { assert!(!RetractActivity::IDEMPOTENT) };
    }

    #[test]
    fn target_kind_key_with_shell_stamps_discriminant_and_shell() {
        let entry = TargetKind::Entry(EntryId::new(ent(7)));
        let shell = ShellId([0x33u8; 16]);
        let k = entry.key_with_shell(shell);
        assert_eq!(k.kind_code, 1);
        assert_eq!(k.id.get(), 7);
        assert_eq!(k.target_shell_id, shell);

        let ext = TargetKind::Extension {
            type_code: TypeCode(0x0100_0001),
            id: ent(9),
        };
        let k2 = ext.key_with_shell(shell);
        assert_eq!(k2.kind_code, 5);
        assert_eq!(k2.type_code, TypeCode(0x0100_0001));
    }

    #[test]
    fn appeal_cap_is_eight() {
        assert_eq!(APPEAL_MAX_DEPTH_CAP, 8);
    }
}
