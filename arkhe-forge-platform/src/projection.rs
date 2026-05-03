//! L2 Projection observer pipeline (spec §5.5 / §12).
//!
//! L0 emits deterministic events; L2 turns those events into denormalized
//! read-model rows that PG (or another store) serves to higher layers. This
//! module ships the skeleton: the [`Projection`] trait, a
//! [`ProjectionRouter`] that dispatches [`EventRecord`]s by `TypeCode`,
//! a [`ProjectionStore`] abstraction, an in-memory store, and active /
//! passive / draining lifecycle transitions.
//!
//! The PG-backed store, the L0 observer bridge, and the
//! `kernel_projection_state` chain-anchored view all land in a future release.

use core::marker::PhantomData;
use std::collections::HashMap;

use arkhe_forge_core::activity::{ActivityId, ActivityRecord, EntityShellId};
use arkhe_forge_core::actor::{ActorId, ActorProfile, UserBinding};
use arkhe_forge_core::brand::ShellId;
use arkhe_forge_core::context::EventRecord;
use arkhe_forge_core::entry::{EntryBody, EntryCore, EntryId, EntryParentDepth};
use arkhe_forge_core::event::{ArkheEvent, CrossShellActivity};
use arkhe_forge_core::space::{ParentChainDepth, SpaceConfig, SpaceId, SpaceMembership};
use arkhe_kernel::abi::{InstanceId, Tick, TypeCode};
use serde::{Deserialize, Serialize};

use crate::manifest::ManifestSnapshot;

// ===================== Lifecycle + Context + Errors =====================

/// Observer worker lifecycle (active-passive HA). Spec §14.11.2.
///
/// * `Passive` — read-only secondary. Consumes events for warm standby but
///   does not commit writes upstream.
/// * `Active` — primary writer. The only projection state permitted to call
///   `ProjectionStore` mutators.
/// * `Draining` — graceful shutdown. Rejects new work, flushes in-flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObserverState {
    /// Not primary; events are observed but writes are blocked.
    Passive,
    /// Primary writer.
    Active,
    /// Winding down — rejects new work.
    Draining,
}

/// Outcome of an auto-promote policy evaluation (spec §14.11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PromotionDecision {
    /// Policy + elapsed time justify a `Passive → Active` transition.
    Promote,
    /// Policy requires additional wait / manual operator approval.
    Wait,
}

/// Minimum number of KMS health channels that must report `Healthy` for the
/// `after_60min` auto-promote policy to clear its guardrail. Matches the
/// default HF2 2-of-3 quorum — operators that provision more channels
/// can re-tune via a future manifest field.
pub const HF2_HEALTH_QUORUM_MIN: usize = 2;

/// Per-dispatch context carried alongside an [`EventRecord`]. The `'i`
/// lifetime reserves the slot that a future release binds to the L0
/// `Effect<'i, Authorized>` borrow, and also scopes the optional manifest
/// snapshot reference.
pub struct ProjectionContext<'i> {
    /// Tick at which the event is being applied.
    pub tick: Tick,
    /// Runtime instance identifier.
    pub instance_id: InstanceId,
    /// Active manifest snapshot, if one has been loaded. `None` is legal
    /// for Tier-0 dev bootstrap paths that run before the first manifest
    /// has been emitted via `RuntimeBootstrap`.
    pub manifest: Option<&'i ManifestSnapshot>,
    _phantom: PhantomData<&'i ()>,
}

impl<'i> ProjectionContext<'i> {
    /// Construct a projection dispatch context without a manifest.
    #[inline]
    #[must_use]
    pub fn new(tick: Tick, instance_id: InstanceId) -> Self {
        Self {
            tick,
            instance_id,
            manifest: None,
            _phantom: PhantomData,
        }
    }

    /// Construct a projection dispatch context with an attached manifest
    /// snapshot. Callers that have loaded a manifest should use this path
    /// so projection workers can key on shell policy (tier, cipher, etc.).
    #[inline]
    #[must_use]
    pub fn with_manifest(
        tick: Tick,
        instance_id: InstanceId,
        manifest: &'i ManifestSnapshot,
    ) -> Self {
        Self {
            tick,
            instance_id,
            manifest: Some(manifest),
            _phantom: PhantomData,
        }
    }
}

/// Projection-side failure taxonomy.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    /// Event sequence moved backward (corruption or mis-routed dispatch).
    #[error("projection sequence backward: last {last}, incoming {incoming}")]
    SequenceBackward {
        /// Last sequence applied by this projection.
        last: u64,
        /// Sequence number of the rejected incoming event.
        incoming: u64,
    },

    /// A sequence number was skipped — the replay harness needs to fetch the
    /// missing range before this projection can advance.
    #[error("projection sequence gap: last {last}, incoming {incoming}")]
    SequenceGap {
        /// Last sequence applied by this projection.
        last: u64,
        /// Sequence number of the event that exposed the gap.
        incoming: u64,
    },

    /// Caller attempted a mutation in a non-`Active` state (observer is
    /// Passive or Draining).
    #[error("observer not active: current state {state:?}")]
    NotActive {
        /// Observer state at the time of the attempted mutation.
        state: ObserverState,
    },

    /// Storage-layer error (in-memory corruption, PG driver, …).
    #[error("projection storage error: {0}")]
    Storage(&'static str),

    /// Event payload failed to decode.
    #[error("event decode failed: {0}")]
    DecodeFailed(&'static str),

    /// An event targeted an Actor / Space / Entry / Activity that the
    /// projection has no row for.
    #[error("projection row missing")]
    MissingRow,
}

// ===================== Projection trait =====================

/// L2 projection worker. Each implementor owns a read-model view that is
/// kept in sync with the L1 event stream for a specific set of `TypeCode`s.
///
/// Implementors must be `Send + Sync` so the `ProjectionRouter` can run
/// across worker threads; dedup / gap detection is centralised in the
/// router using [`Projection::last_applied`].
pub trait Projection: Send + Sync {
    /// TypeCodes this projection observes — the router filters incoming
    /// events against this slice.
    fn observes(&self) -> &[TypeCode];

    /// Apply an event. Called only after router-side dedup + gap checks
    /// have succeeded. Implementations must:
    ///
    /// 1. Update their internal view state.
    /// 2. Bump `last_applied` to the event's `(sequence, tick)`.
    fn on_event(
        &mut self,
        event: &EventRecord,
        ctx: &ProjectionContext<'_>,
    ) -> Result<(), ProjectionError>;

    /// React to a worker-state transition (Passive ↔ Active ↔ Draining).
    /// Default is no-op.
    fn on_state_change(&mut self, _new_state: ObserverState) -> Result<(), ProjectionError> {
        Ok(())
    }

    /// Last `(sequence, tick)` applied — `None` if the projection is fresh.
    fn last_applied(&self) -> Option<(u64, Tick)>;
}

// ===================== Projection view structs =====================

/// `(u64, Tick)` pair tracking the last event applied.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectionCursor {
    /// Last sequence number applied.
    pub sequence: u64,
    /// Tick at which the last event was applied.
    pub tick: Tick,
}

/// Actor-facing read-model row — `ActorProfile` + optional `UserBinding`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorProjection {
    /// Wire schema version.
    pub schema_version: u16,
    /// Actor identity.
    pub actor_id: ActorId,
    /// Authoritative `ActorProfile` Component.
    pub profile: ActorProfile,
    /// `UserBinding` is present iff the actor is `Authenticated` (E-actor-2).
    pub user_binding: Option<UserBinding>,
    /// Event cursor — dedup / gap anchor.
    pub cursor: Option<ProjectionCursor>,
}

/// Space read-model row — `SpaceConfig` + parent-chain cache + membership.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpaceProjection {
    /// Wire schema version.
    pub schema_version: u16,
    /// Space identity.
    pub space_id: SpaceId,
    /// Authoritative `SpaceConfig` Component.
    pub config: SpaceConfig,
    /// Cached parent-chain depth (E-space-4 O(1)).
    pub parent_chain_depth: Option<ParentChainDepth>,
    /// Membership list for PrivateInvite Spaces.
    pub membership: Option<SpaceMembership>,
    /// Event cursor.
    pub cursor: Option<ProjectionCursor>,
}

/// Entry read-model row — `EntryCore` + body metadata + depth cache.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryProjection {
    /// Wire schema version.
    pub schema_version: u16,
    /// Entry identity.
    pub entry_id: EntryId,
    /// Authoritative `EntryCore` Component.
    pub core: EntryCore,
    /// `EntryBody` — absent when soft-deleted (E-entry-5).
    pub body: Option<EntryBody>,
    /// Cached parent-chain depth (E-entry-3).
    pub parent_depth: Option<EntryParentDepth>,
    /// Event cursor.
    pub cursor: Option<ProjectionCursor>,
}

/// Activity read-model row — `ActivityRecord` + optional Extension-target
/// shell marker.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActivityProjection {
    /// Wire schema version.
    pub schema_version: u16,
    /// Activity identity.
    pub activity_id: ActivityId,
    /// Authoritative `ActivityRecord` Component.
    pub record: ActivityRecord,
    /// Shell marker for Extension-target Activities (E-act-7).
    pub entity_shell_id: Option<EntityShellId>,
    /// Event cursor.
    pub cursor: Option<ProjectionCursor>,
}

// ===================== ProjectionStore =====================

/// Storage abstraction for projection rows. v0.11 ships an in-memory
/// implementation; PG-backed storage lands alongside the L2 service layer.
pub trait ProjectionStore: Send + Sync {
    /// Upsert an Actor row. `Active` observer only.
    fn upsert_actor(&mut self, row: &ActorProjection) -> Result<(), ProjectionError>;

    /// Upsert a Space row. `Active` observer only.
    fn upsert_space(&mut self, row: &SpaceProjection) -> Result<(), ProjectionError>;

    /// Upsert an Entry row. `Active` observer only.
    fn upsert_entry(&mut self, row: &EntryProjection) -> Result<(), ProjectionError>;

    /// Upsert an Activity row. `Active` observer only.
    fn upsert_activity(&mut self, row: &ActivityProjection) -> Result<(), ProjectionError>;

    /// Read an Actor row.
    fn get_actor(&self, actor_id: ActorId) -> Option<ActorProjection>;
    /// Read a Space row.
    fn get_space(&self, space_id: SpaceId) -> Option<SpaceProjection>;
    /// Read an Entry row.
    fn get_entry(&self, entry_id: EntryId) -> Option<EntryProjection>;
    /// Read an Activity row.
    fn get_activity(&self, activity_id: ActivityId) -> Option<ActivityProjection>;
}

/// In-memory [`ProjectionStore`] — intended for tests and Tier-0 dev runs.
#[derive(Debug, Default)]
pub struct InMemoryProjectionStore {
    actors: HashMap<ActorId, ActorProjection>,
    spaces: HashMap<SpaceId, SpaceProjection>,
    entries: HashMap<EntryId, EntryProjection>,
    activities: HashMap<ActivityId, ActivityProjection>,
}

impl InMemoryProjectionStore {
    /// Construct an empty store.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProjectionStore for InMemoryProjectionStore {
    fn upsert_actor(&mut self, row: &ActorProjection) -> Result<(), ProjectionError> {
        self.actors.insert(row.actor_id, row.clone());
        Ok(())
    }
    fn upsert_space(&mut self, row: &SpaceProjection) -> Result<(), ProjectionError> {
        self.spaces.insert(row.space_id, row.clone());
        Ok(())
    }
    fn upsert_entry(&mut self, row: &EntryProjection) -> Result<(), ProjectionError> {
        self.entries.insert(row.entry_id, row.clone());
        Ok(())
    }
    fn upsert_activity(&mut self, row: &ActivityProjection) -> Result<(), ProjectionError> {
        self.activities.insert(row.activity_id, row.clone());
        Ok(())
    }
    fn get_actor(&self, actor_id: ActorId) -> Option<ActorProjection> {
        self.actors.get(&actor_id).cloned()
    }
    fn get_space(&self, space_id: SpaceId) -> Option<SpaceProjection> {
        self.spaces.get(&space_id).cloned()
    }
    fn get_entry(&self, entry_id: EntryId) -> Option<EntryProjection> {
        self.entries.get(&entry_id).cloned()
    }
    fn get_activity(&self, activity_id: ActivityId) -> Option<ActivityProjection> {
        self.activities.get(&activity_id).cloned()
    }
}

// ===================== Router =====================

/// Event-stream dispatcher. Matches incoming events to registered
/// projections by `TypeCode`, enforces dedup + gap detection via
/// `Projection::last_applied`, and propagates observer state transitions.
pub struct ProjectionRouter {
    projections: Vec<Box<dyn Projection>>,
    state: ObserverState,
}

impl ProjectionRouter {
    /// Build a router in the `Passive` state — promote to `Active` before
    /// committing writes.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            projections: Vec::new(),
            state: ObserverState::Passive,
        }
    }

    /// Register a projection.
    pub fn register(&mut self, projection: Box<dyn Projection>) {
        self.projections.push(projection);
    }

    /// Current observer state.
    #[inline]
    #[must_use]
    pub fn state(&self) -> ObserverState {
        self.state
    }

    /// Transition to `Active` — fails if currently `Draining`.
    pub fn promote_to_active(&mut self) -> Result<(), ProjectionError> {
        if self.state == ObserverState::Draining {
            return Err(ProjectionError::NotActive { state: self.state });
        }
        self.transition(ObserverState::Active)
    }

    /// Evaluate the shell's `kms_auto_promote` policy against three inputs:
    /// the elapsed outage, the multi-channel KMS health quorum, and the
    /// threshold-HSM share readiness.
    ///
    /// Policy values (spec §14.11.2):
    ///
    /// | `kms_auto_promote`  | Decision matrix |
    /// |---------------------|-----------------|
    /// | `"manual"`          | Always `Some(Wait)` — operator drives the promotion manually. |
    /// | `"after_60min"`     | `Some(Promote)` iff `primary_down_duration >= 1h` **and** the KMS health quorum has at least [`HF2_HEALTH_QUORUM_MIN`] channels healthy; otherwise `Some(Wait)`. |
    /// | `"threshold_hsm"`   | `Some(Promote)` iff `threshold_ready` (t-of-n shares collected); otherwise `Some(Wait)`. |
    /// | other               | `None` — unrecognised policy string, operator intervention required. |
    ///
    /// Returning `None` is conservative by design: callers treat unknown
    /// policies as "do not auto-promote" and fall back to manual operator
    /// action.
    #[must_use]
    pub fn evaluate_auto_promote(
        &self,
        manifest: &crate::manifest::ManifestSnapshot,
        primary_down_duration: core::time::Duration,
        health: &crate::hf2_kms::health::MultiChannelHealth,
        threshold_ready: bool,
    ) -> Option<PromotionDecision> {
        match manifest.audit.kms_auto_promote.as_str() {
            "manual" => Some(PromotionDecision::Wait),
            "after_60min" => {
                let elapsed_ok = primary_down_duration >= core::time::Duration::from_secs(60 * 60);
                let health_ok = health.healthy_count() >= HF2_HEALTH_QUORUM_MIN;
                if elapsed_ok && health_ok {
                    Some(PromotionDecision::Promote)
                } else {
                    Some(PromotionDecision::Wait)
                }
            }
            "threshold_hsm" => {
                if threshold_ready {
                    Some(PromotionDecision::Promote)
                } else {
                    Some(PromotionDecision::Wait)
                }
            }
            _ => None,
        }
    }

    /// Transition to `Passive`. Used when ceding primary to a peer.
    pub fn demote_to_passive(&mut self) -> Result<(), ProjectionError> {
        self.transition(ObserverState::Passive)
    }

    /// Transition to `Draining`. Terminal — no further state changes.
    pub fn begin_draining(&mut self) -> Result<(), ProjectionError> {
        self.transition(ObserverState::Draining)
    }

    fn transition(&mut self, next: ObserverState) -> Result<(), ProjectionError> {
        for p in &mut self.projections {
            p.on_state_change(next)?;
        }
        self.state = next;
        Ok(())
    }

    /// Dispatch an event to every matching projection. Returns `Ok(n)`
    /// where `n` is the number of projections that applied the event.
    ///
    /// Only the `Active` state may dispatch — `Passive` and `Draining`
    /// reject with [`ProjectionError::NotActive`]. The `Passive` rejection
    /// is the production guardrail for active-passive HA: a secondary
    /// observer that mistakenly accepts writes would create split-brain
    /// rows in the PG-backed store. The dylint `arkhe-trait-default-check`
    /// CI gate ensures the contract is honoured by every L2 deployment.
    pub fn dispatch(
        &mut self,
        event: &EventRecord,
        ctx: &ProjectionContext<'_>,
    ) -> Result<usize, ProjectionError> {
        if self.state != ObserverState::Active {
            return Err(ProjectionError::NotActive { state: self.state });
        }
        let tc = TypeCode(event.type_code);
        let mut applied = 0usize;
        for p in &mut self.projections {
            if !p.observes().contains(&tc) {
                continue;
            }
            if let Some((last_seq, _)) = p.last_applied() {
                if event.sequence == last_seq {
                    continue; // duplicate — silent no-op
                }
                if event.sequence < last_seq {
                    return Err(ProjectionError::SequenceBackward {
                        last: last_seq,
                        incoming: event.sequence,
                    });
                }
                if event.sequence > last_seq.saturating_add(1) {
                    return Err(ProjectionError::SequenceGap {
                        last: last_seq,
                        incoming: event.sequence,
                    });
                }
            }
            p.on_event(event, ctx)?;
            applied += 1;
        }
        Ok(applied)
    }
}

impl Default for ProjectionRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ===================== CrossShellActivity fanout =====================

/// Read-only fanout projection for `CrossShellActivity`. Stores cross-shell
/// notifications keyed by the target shell — never touches the source
/// shell's rows, preserving shell isolation (E-act-2 RA tier).
#[derive(Debug)]
pub struct CrossShellActivityFanout {
    observes: [TypeCode; 1],
    by_target_shell: HashMap<ShellId, Vec<CrossShellActivity>>,
    cursor: Option<ProjectionCursor>,
}

impl Default for CrossShellActivityFanout {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossShellActivityFanout {
    /// Construct a fresh fanout, pre-wired to observe `CrossShellActivity`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            observes: [TypeCode(CrossShellActivity::TYPE_CODE)],
            by_target_shell: HashMap::new(),
            cursor: None,
        }
    }

    /// Borrow the notification queue for a shell (read-only).
    #[inline]
    #[must_use]
    pub fn notifications_for(&self, shell: &ShellId) -> &[CrossShellActivity] {
        self.by_target_shell
            .get(shell)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

impl Projection for CrossShellActivityFanout {
    fn observes(&self) -> &[TypeCode] {
        &self.observes
    }

    fn on_event(
        &mut self,
        event: &EventRecord,
        _ctx: &ProjectionContext<'_>,
    ) -> Result<(), ProjectionError> {
        let notice: CrossShellActivity = postcard::from_bytes(&event.payload)
            .map_err(|_| ProjectionError::DecodeFailed("CrossShellActivity payload"))?;
        self.by_target_shell
            .entry(notice.target_shell_id)
            .or_default()
            .push(notice);
        self.cursor = Some(ProjectionCursor {
            sequence: event.sequence,
            tick: event.tick,
        });
        Ok(())
    }

    fn last_applied(&self) -> Option<(u64, Tick)> {
        self.cursor.map(|c| (c.sequence, c.tick))
    }
}

// ===================== Tests =====================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arkhe_forge_core::actor::ActorKind;
    use arkhe_forge_core::component::BoundedString;
    use arkhe_kernel::abi::EntityId;
    use bytes::Bytes;

    fn sid(byte: u8) -> ShellId {
        ShellId([byte; 16])
    }

    fn ent(v: u64) -> EntityId {
        EntityId::new(v).unwrap()
    }

    fn make_cross_shell_event(seq: u64, tick: u64, target: ShellId) -> EventRecord {
        let notice = CrossShellActivity {
            schema_version: 1,
            actor: ActorId::new(ent(1)),
            target_shell_id: target,
            record_shell_id: sid(0xAA),
            detected_tick: Tick(tick),
        };
        EventRecord {
            type_code: CrossShellActivity::TYPE_CODE,
            sequence: seq,
            tick: Tick(tick),
            payload: Bytes::from(postcard::to_stdvec(&notice).unwrap()),
        }
    }

    fn ctx(tick: u64) -> ProjectionContext<'static> {
        ProjectionContext::new(Tick(tick), InstanceId::new(1).unwrap())
    }

    #[test]
    fn router_defaults_to_passive() {
        let r = ProjectionRouter::new();
        assert_eq!(r.state(), ObserverState::Passive);
    }

    #[test]
    fn router_promote_then_demote_then_drain() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        assert_eq!(r.state(), ObserverState::Active);
        r.demote_to_passive().unwrap();
        assert_eq!(r.state(), ObserverState::Passive);
        r.begin_draining().unwrap();
        assert_eq!(r.state(), ObserverState::Draining);
        // Draining is terminal — promote rejects.
        assert!(r.promote_to_active().is_err());
    }

    #[test]
    fn cross_shell_fanout_routes_to_target_shell_only() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x33);
        let ev = make_cross_shell_event(0, 100, target);
        let applied = r.dispatch(&ev, &ctx(100)).unwrap();
        assert_eq!(applied, 1);
    }

    #[test]
    fn dispatcher_skips_projection_with_no_matching_observer() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let other_event = EventRecord {
            type_code: 0x0003_0F02, // UserErasureScheduled
            sequence: 0,
            tick: Tick(1),
            payload: Bytes::new(),
        };
        let applied = r.dispatch(&other_event, &ctx(1)).unwrap();
        assert_eq!(applied, 0, "non-observed TypeCode must not hit the fanout");
    }

    #[test]
    fn dispatcher_dedups_duplicate_sequence() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        let ev = make_cross_shell_event(0, 5, target);
        r.dispatch(&ev, &ctx(5)).unwrap();
        let applied_again = r.dispatch(&ev, &ctx(5)).unwrap();
        assert_eq!(applied_again, 0, "duplicate sequence must no-op");
    }

    #[test]
    fn dispatcher_rejects_gap() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        r.dispatch(&make_cross_shell_event(0, 5, target), &ctx(5))
            .unwrap();
        // Jump to sequence 5 — gap (1..=4 missing).
        let err = r
            .dispatch(&make_cross_shell_event(5, 6, target), &ctx(6))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceGap { .. }));
    }

    #[test]
    fn dispatcher_rejects_backward_sequence() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        r.dispatch(&make_cross_shell_event(2, 5, target), &ctx(5))
            .unwrap();
        let err = r
            .dispatch(&make_cross_shell_event(1, 5, target), &ctx(5))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceBackward { .. }));
    }

    #[test]
    fn draining_rejects_dispatch() {
        let mut r = ProjectionRouter::new();
        r.begin_draining().unwrap();
        let err = r
            .dispatch(&make_cross_shell_event(0, 1, sid(0)), &ctx(1))
            .unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::NotActive {
                state: ObserverState::Draining
            }
        ));
    }

    #[test]
    fn passive_rejects_dispatch() {
        // `ProjectionRouter::new()` starts in Passive — dispatch must reject
        // until the worker is promoted, otherwise an active-passive HA pair
        // could create split-brain rows in the PG-backed store.
        let mut r = ProjectionRouter::new();
        assert_eq!(r.state(), ObserverState::Passive);
        let err = r
            .dispatch(&make_cross_shell_event(0, 1, sid(0)), &ctx(1))
            .unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::NotActive {
                state: ObserverState::Passive
            }
        ));
    }

    #[test]
    fn demote_to_passive_blocks_subsequent_dispatch() {
        // After a successful Active dispatch, demoting back to Passive must
        // immediately stop accepting writes — covers the failover-back path.
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        r.dispatch(&make_cross_shell_event(0, 5, sid(0x10)), &ctx(5))
            .unwrap();
        r.demote_to_passive().unwrap();
        let err = r
            .dispatch(&make_cross_shell_event(1, 6, sid(0x10)), &ctx(6))
            .unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::NotActive {
                state: ObserverState::Passive
            }
        ));
    }

    #[test]
    fn in_memory_store_roundtrip_actor() {
        let mut store = InMemoryProjectionStore::new();
        let row = ActorProjection {
            schema_version: 1,
            actor_id: ActorId::new(ent(42)),
            profile: ActorProfile {
                schema_version: 1,
                shell_id: sid(0x01),
                handle: BoundedString::<32>::new("alice").unwrap(),
                kind: ActorKind::Human,
                created_tick: Tick(1),
            },
            user_binding: None,
            cursor: None,
        };
        store.upsert_actor(&row).unwrap();
        let fetched = store.get_actor(ActorId::new(ent(42))).unwrap();
        assert_eq!(fetched, row);
    }

    #[test]
    fn cross_shell_fanout_preserves_shell_partition() {
        let mut fanout = CrossShellActivityFanout::new();
        let shell_a = sid(0xAA);
        let shell_b = sid(0xBB);
        fanout
            .on_event(&make_cross_shell_event(0, 10, shell_a), &ctx(10))
            .unwrap();
        fanout
            .on_event(&make_cross_shell_event(1, 11, shell_b), &ctx(11))
            .unwrap();
        assert_eq!(fanout.notifications_for(&shell_a).len(), 1);
        assert_eq!(fanout.notifications_for(&shell_b).len(), 1);
        assert_eq!(fanout.last_applied(), Some((1, Tick(11))));
    }

    #[test]
    fn projection_cursor_roundtrip() {
        let c = ProjectionCursor {
            sequence: 5,
            tick: Tick(10),
        };
        let bytes = postcard::to_stdvec(&c).unwrap();
        let back: ProjectionCursor = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(c, back);
    }

    /// Manifest auto-promote matrix — spec §14.11.2 decision table.
    /// Run via a small helper that builds a `ManifestSnapshot` with a
    /// configurable `kms_auto_promote` string.
    #[test]
    fn auto_promote_policy_matrix() {
        use crate::hf2_kms::health::{Channel, MultiChannelHealth, Status};
        use crate::manifest::{
            AuditSection, FrontendSection, ManifestSnapshot, RuntimeSection, ShellSection,
        };
        use core::time::Duration;

        fn manifest_with(policy: &str) -> ManifestSnapshot {
            ManifestSnapshot {
                schema_version: 1,
                shell: ShellSection {
                    shell_id: "test".to_string(),
                    display_name: "Test".to_string(),
                },
                runtime: RuntimeSection {
                    runtime_max: "0.15".to_string(),
                    runtime_current: "0.11".to_string(),
                },
                audit: AuditSection {
                    pii_cipher: "xchacha20-poly1305".to_string(),
                    dek_backend: "software-kek".to_string(),
                    kms_auto_promote: policy.to_string(),
                    signature_class: "ed25519".to_string(),
                    compliance_tier: 0,
                },
                frontend: FrontendSection::default(),
            }
        }

        fn healthy_trio() -> MultiChannelHealth {
            let mut h = MultiChannelHealth::new(&[
                Channel::Default,
                Channel::DnsOverHttps,
                Channel::StaticIp,
            ]);
            for c in [Channel::Default, Channel::DnsOverHttps, Channel::StaticIp] {
                h.set_status(c, Status::Healthy);
            }
            h
        }

        fn degraded_trio() -> MultiChannelHealth {
            // Only one channel healthy — below HF2 2/3 quorum.
            let mut h = MultiChannelHealth::new(&[
                Channel::Default,
                Channel::DnsOverHttps,
                Channel::StaticIp,
            ]);
            h.set_status(Channel::Default, Status::Healthy);
            h.set_status(Channel::DnsOverHttps, Status::Failing);
            h.set_status(Channel::StaticIp, Status::Failing);
            h
        }

        let r = ProjectionRouter::new();
        let healthy = healthy_trio();
        let degraded = degraded_trio();

        // Manual policy → always Wait (operator drives the promotion).
        assert_eq!(
            r.evaluate_auto_promote(
                &manifest_with("manual"),
                Duration::from_secs(7200),
                &healthy,
                true,
            ),
            Some(PromotionDecision::Wait),
        );

        // after_60min, short outage → Wait even with full health.
        assert_eq!(
            r.evaluate_auto_promote(
                &manifest_with("after_60min"),
                Duration::from_secs(59 * 60),
                &healthy,
                false,
            ),
            Some(PromotionDecision::Wait),
        );

        // after_60min, outage cleared but health below quorum → Wait.
        assert_eq!(
            r.evaluate_auto_promote(
                &manifest_with("after_60min"),
                Duration::from_secs(60 * 60),
                &degraded,
                false,
            ),
            Some(PromotionDecision::Wait),
        );

        // after_60min, outage cleared AND health quorum met → Promote.
        assert_eq!(
            r.evaluate_auto_promote(
                &manifest_with("after_60min"),
                Duration::from_secs(60 * 60),
                &healthy,
                false,
            ),
            Some(PromotionDecision::Promote),
        );

        // threshold_hsm, shares not collected → Wait.
        assert_eq!(
            r.evaluate_auto_promote(
                &manifest_with("threshold_hsm"),
                Duration::from_secs(60 * 60),
                &degraded,
                false,
            ),
            Some(PromotionDecision::Wait),
        );

        // threshold_hsm, shares collected → Promote (health is not gating here).
        assert_eq!(
            r.evaluate_auto_promote(
                &manifest_with("threshold_hsm"),
                Duration::from_secs(0),
                &degraded,
                true,
            ),
            Some(PromotionDecision::Promote),
        );

        // Unknown policy string → None (conservative default — operator must act).
        assert!(r
            .evaluate_auto_promote(
                &manifest_with("unknown"),
                Duration::from_secs(86_400),
                &healthy,
                true,
            )
            .is_none());
    }
}
