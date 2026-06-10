//! L2 Projection observer pipeline.
//!
//! L0 emits deterministic events; L2 turns those events into denormalized
//! read-model rows that PG (or another store) serves to higher layers. This
//! module exposes: the [`Projection`] trait, a
//! [`ProjectionRouter`] that dispatches [`EventRecord`]s by `TypeCode`,
//! a [`ProjectionStore`] abstraction, an in-memory store, and active /
//! passive / draining lifecycle transitions.
//!
//! The PG-backed store, the L0 observer bridge, and the
//! `kernel_projection_state` chain-anchored view route through the trait surface.

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
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::manifest::ManifestSnapshot;

// ===================== Lifecycle + Context + Errors =====================

/// Observer worker lifecycle (active-passive HA).
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

/// Outcome of an auto-promote policy evaluation.
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
/// default 2-of-3 quorum — operators that provision more channels
/// can re-tune via a future manifest field.
pub const HF2_HEALTH_QUORUM_MIN: usize = 2;

/// Per-dispatch context carried alongside an [`EventRecord`]. The `'i`
/// lifetime reserves the slot that binds to the L0
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
    /// The event stream moved backward (corruption, mis-ordered redelivery,
    /// or two computes sharing one tick — see
    /// [`ProjectionRouter::dispatch`]).
    #[error("projection stream backward: last {last:?}, incoming {incoming:?}")]
    SequenceBackward {
        /// Stream head the incoming event was ordered against — the last
        /// accepted event or, when a failed dispatch is awaiting retry,
        /// the pinned unapplied position.
        last: ProjectionCursor,
        /// Position of the rejected incoming event.
        incoming: ProjectionCursor,
    },

    /// The stream skipped an event — a same-tick sequence jump, or a new
    /// tick whose batch does not start at sequence 0. The replay harness
    /// needs to fetch the missing range before dispatch can advance.
    #[error("projection stream gap: last {last:?}, incoming {incoming:?}")]
    SequenceGap {
        /// Stream head the incoming event was ordered against — the last
        /// accepted event or, when a failed dispatch is awaiting retry,
        /// the pinned unapplied position.
        last: ProjectionCursor,
        /// Position of the event that exposed the gap.
        incoming: ProjectionCursor,
    },

    /// A DIFFERENT event arrived at a position the router has already
    /// pinned — the accepted cursor position, or a failed dispatch's
    /// pending-retry pin. Two same-tick computes collided on the
    /// `(tick, sequence)` identity (driver contract violation),
    /// distinguished from a true redelivery/retry by event identity
    /// (type code + payload).
    #[error("projection stream position conflict at {at:?}")]
    PositionConflict {
        /// The contested stream position.
        at: ProjectionCursor,
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
/// across worker threads. Stream dedup / gap detection is centralised in
/// the router's own cursor; the router additionally consults
/// [`Projection::last_applied`] to skip events a projection has already
/// applied (catch-up after a router rebuild or a partially failed
/// fan-out).
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
    /// The router skips any event at or before this position (tick-major
    /// order), so the `on_event` bump is what makes application
    /// at-most-once across redeliveries.
    fn last_applied(&self) -> Option<(u64, Tick)>;
}

// ===================== Projection view structs =====================

/// Composite event-stream position. `EventRecord.sequence` is
/// per-compute — it restarts at 0 for every action's `ActionContext` — so
/// an event is identified in the stream by the `(tick, sequence)` pair,
/// ordered tick-major.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectionCursor {
    /// Sequence number within the emitting compute's batch.
    pub sequence: u64,
    /// Tick at which the event was emitted.
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

/// Storage abstraction for projection rows. An in-memory
/// implementation ships with this crate; PG-backed storage plugs in
/// at the L2 service layer.
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
/// projections by `TypeCode`, enforces stream-order dedup + gap detection
/// via a router-held `(tick, sequence)` cursor, and propagates observer
/// state transitions.
pub struct ProjectionRouter {
    projections: Vec<Box<dyn Projection>>,
    /// `TypeCode -> projection indices that observe it`, built at
    /// `register()` time. Indices are stored in registration order, so
    /// dispatch visits matching projections in the same order a linear scan
    /// would — dispatch-order semantics are preserved (see `dispatch`).
    observers_by_code: HashMap<TypeCode, Vec<usize>>,
    /// Position of the last event accepted by `dispatch`, including events
    /// no projection observes — gap detection needs the full stream, not
    /// the per-projection filtered view. Advanced only after a fully
    /// successful fan-out so a failed dispatch stays retryable.
    cursor: Option<ProjectionCursor>,
    /// Identity (type code + payload) of the last accepted event — lets
    /// the cursor-equality path distinguish a true redelivery (`Ok(0)`)
    /// from a DIFFERENT event colliding on the same position
    /// ([`ProjectionError::PositionConflict`]).
    last_event: Option<(u32, Bytes)>,
    /// Position + identity (type code, payload) of the event a failed
    /// fan-out left unapplied — set on every failed fan-out (a
    /// projection apply error), first or mid-stream; ordering
    /// rejections never move it (re-pinning to a stray position would
    /// deadlock the legitimate retry). Only a retry of this exact
    /// EVENT may proceed: a skip-ahead would silently advance past the
    /// lost event, and a DIFFERENT event at the same position would
    /// conflate same-tick compute streams.
    pending_retry: Option<(ProjectionCursor, u32, Bytes)>,
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
            observers_by_code: HashMap::new(),
            cursor: None,
            last_event: None,
            pending_retry: None,
            state: ObserverState::Passive,
        }
    }

    /// Register a projection. Its observed `TypeCode`s are folded into the
    /// dispatch index so `dispatch` only visits matching projections.
    pub fn register(&mut self, projection: Box<dyn Projection>) {
        let idx = self.projections.len();
        for &tc in projection.observes() {
            self.observers_by_code.entry(tc).or_default().push(idx);
        }
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
        self.transition(ObserverState::Active)
    }

    /// Evaluate the shell's `kms_auto_promote` policy against three inputs:
    /// the elapsed outage, the multi-channel KMS health quorum, and the
    /// threshold-HSM share readiness.
    ///
    /// Policy values:
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
        // Draining is terminal: once a graceful shutdown begins, no
        // transition path (including Draining → Passive → Active) may
        // resurrect the router. Gating here covers every public
        // transition method with a single guard.
        if self.state == ObserverState::Draining {
            return Err(ProjectionError::NotActive { state: self.state });
        }
        for p in &mut self.projections {
            p.on_state_change(next)?;
        }
        self.state = next;
        Ok(())
    }

    /// Dispatch an event to every matching projection. Returns `Ok(n)`
    /// where `n` is the number of projections that applied the event.
    ///
    /// Matching projections are visited in registration order (the dispatch
    /// index stores their indices in that order), so a projection registered
    /// earlier always sees an event before one registered later — callers may
    /// rely on that ordering. A `TypeCode` with no registered observer is a
    /// cheap miss (no index entry) returning `Ok(0)` — the event still
    /// advances the stream cursor.
    ///
    /// ## Stream-order contract
    ///
    /// `EventRecord.sequence` is per-compute: every compute's batch starts
    /// at 0 and is contiguous, so an event's stream identity is the
    /// composite `(tick, sequence)` pair, ordered tick-major. Callers must
    /// feed every drained event of a compute in emission order and must
    /// advance the tick between computes. The kernel scheduler permits
    /// same-tick scheduled actions, but two same-tick computes emit
    /// colliding positions — this router rejects the collision loudly
    /// rather than conflating the streams: a colliding head behind the
    /// cursor is [`ProjectionError::SequenceBackward`], and a DIFFERENT
    /// event at exactly the cursor position (the single-event-batch
    /// shape) is [`ProjectionError::PositionConflict`], distinguished
    /// from a true redelivery by event identity (type code + payload).
    ///
    /// Checks against the stream cursor (last accepted event):
    ///
    /// * the same `(tick, sequence)` redelivered with the same identity —
    ///   duplicate, `Ok(0)`;
    /// * a different event at the cursor position —
    ///   [`ProjectionError::PositionConflict`];
    /// * a position behind the cursor —
    ///   [`ProjectionError::SequenceBackward`];
    /// * a same-tick sequence jump, or a new tick whose batch does not
    ///   start at sequence 0 — [`ProjectionError::SequenceGap`];
    /// * a fresh router (no cursor yet) accepts any position as its
    ///   resume anchor.
    ///
    /// The cursor advances only after a fully successful fan-out. A
    /// FAILED fan-out (first or mid-stream) pins the unapplied event's
    /// position AND identity: only a retry of that exact event may
    /// proceed — a skip-ahead is a gap (it would silently advance past
    /// the lost event), a different event at the pinned position is a
    /// [`ProjectionError::PositionConflict`] — and the projections that
    /// already applied it before the failure are skipped on the retry
    /// via [`Projection::last_applied`].
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
        let incoming = ProjectionCursor {
            sequence: event.sequence,
            tick: event.tick,
        };
        if let Some(last) = self.cursor {
            if incoming == last {
                // Same position: a true redelivery is a no-op, but a
                // DIFFERENT event here means two same-tick computes
                // collided on the cursor — never conflate silently.
                let is_redelivery = self.last_event.as_ref().is_some_and(|(tc, payload)| {
                    *tc == event.type_code && *payload == event.payload
                });
                if is_redelivery {
                    return Ok(0);
                }
                return Err(ProjectionError::PositionConflict { at: incoming });
            }
        }
        if let Some((pending, pending_tc, pending_payload)) = &self.pending_retry {
            // A prior dispatch failed at `pending` (first or mid-stream)
            // and was never applied — accept only the retry of that exact
            // EVENT: a skip-ahead would lose it silently, and a different
            // event at the same position would conflate same-tick compute
            // streams. The pending position already passed the ordering
            // checks against the cursor when it first arrived.
            let pending = *pending;
            if (incoming.tick, incoming.sequence) < (pending.tick, pending.sequence) {
                return Err(ProjectionError::SequenceBackward {
                    last: pending,
                    incoming,
                });
            }
            if incoming != pending {
                return Err(ProjectionError::SequenceGap {
                    last: pending,
                    incoming,
                });
            }
            if *pending_tc != event.type_code || *pending_payload != event.payload {
                return Err(ProjectionError::PositionConflict { at: incoming });
            }
        } else if let Some(last) = self.cursor {
            if (incoming.tick, incoming.sequence) < (last.tick, last.sequence) {
                return Err(ProjectionError::SequenceBackward { last, incoming });
            }
            let contiguous = if incoming.tick == last.tick {
                incoming.sequence == last.sequence.saturating_add(1)
            } else {
                // A new tick means a new compute whose sequence restarts
                // at 0 — anything else is a missing batch head.
                incoming.sequence == 0
            };
            if !contiguous {
                return Err(ProjectionError::SequenceGap { last, incoming });
            }
        }
        let tc = TypeCode(event.type_code);
        // Split-borrow the disjoint fields: the index slice (immutable) and
        // the projection vec (mutable) are borrowed independently so the loop
        // can mutate `projections[i]` while reading the matching index list.
        let Self {
            projections,
            observers_by_code,
            cursor,
            last_event,
            pending_retry,
            ..
        } = self;
        // Indices are already in registration order.
        let mut applied = 0usize;
        if let Some(matching) = observers_by_code.get(&tc) {
            for &i in matching {
                let p = &mut projections[i];
                if let Some((last_seq, last_tick)) = p.last_applied() {
                    // Already applied — catch-up redelivery into a rebuilt
                    // router or a retry after a partial fan-out failure.
                    if (incoming.tick, incoming.sequence) <= (last_tick, last_seq) {
                        continue;
                    }
                }
                if let Err(e) = p.on_event(event, ctx) {
                    *pending_retry = Some((incoming, event.type_code, event.payload.clone()));
                    return Err(e);
                }
                applied += 1;
            }
        }
        *cursor = Some(incoming);
        *last_event = Some((event.type_code, event.payload.clone()));
        *pending_retry = None;
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use arkhe_forge_core::actor::ActorKind;
    use arkhe_forge_core::component::BoundedString;
    use arkhe_kernel::abi::EntityId;
    use bytes::Bytes;

    fn sid(byte: u8) -> ShellId {
        ShellId([byte; 16])
    }

    /// Counts `on_event` applications — observability for fan-out and
    /// at-most-once assertions once the projection is boxed into a router.
    struct CountingProjection {
        observes: [TypeCode; 1],
        cursor: Option<ProjectionCursor>,
        applied: Arc<AtomicUsize>,
    }

    impl CountingProjection {
        fn new(applied: Arc<AtomicUsize>) -> Self {
            Self {
                observes: [TypeCode(CrossShellActivity::TYPE_CODE)],
                cursor: None,
                applied,
            }
        }
    }

    impl Projection for CountingProjection {
        fn observes(&self) -> &[TypeCode] {
            &self.observes
        }

        fn on_event(
            &mut self,
            event: &EventRecord,
            _ctx: &ProjectionContext<'_>,
        ) -> Result<(), ProjectionError> {
            self.applied.fetch_add(1, Ordering::SeqCst);
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

    /// Fails its first `on_event`, succeeds afterwards — drives the
    /// partial-fan-out retry path.
    struct FailOnceProjection {
        observes: [TypeCode; 1],
        cursor: Option<ProjectionCursor>,
        failed: bool,
    }

    impl FailOnceProjection {
        fn new() -> Self {
            Self {
                observes: [TypeCode(CrossShellActivity::TYPE_CODE)],
                cursor: None,
                failed: false,
            }
        }
    }

    impl Projection for FailOnceProjection {
        fn observes(&self) -> &[TypeCode] {
            &self.observes
        }

        fn on_event(
            &mut self,
            event: &EventRecord,
            _ctx: &ProjectionContext<'_>,
        ) -> Result<(), ProjectionError> {
            if !self.failed {
                self.failed = true;
                return Err(ProjectionError::Storage("injected first-apply failure"));
            }
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
        // Draining is terminal — EVERY transition out rejects through the
        // single gate: promote, the Draining → Passive resurrection edge,
        // and a repeated drain.
        assert!(r.promote_to_active().is_err());
        assert!(r.demote_to_passive().is_err());
        assert!(r.begin_draining().is_err());
        assert_eq!(r.state(), ObserverState::Draining);
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

    /// #21 — the dispatch index must fan an event out to EVERY projection
    /// that observes its TypeCode, in registration order. Two fanouts both
    /// observing `CrossShellActivity` must each apply the same event.
    #[test]
    fn dispatcher_fans_out_to_all_matching_in_registration_order() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x44);
        let ev = make_cross_shell_event(0, 100, target);
        let applied = r.dispatch(&ev, &ctx(100)).unwrap();
        assert_eq!(applied, 2, "both matching projections must apply the event");
    }

    /// #21 — a TypeCode with no registered observer is a cheap index miss
    /// (no entry) and returns Ok(0) without scanning any projection.
    #[test]
    fn dispatcher_unobserved_typecode_is_index_miss() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let other_event = EventRecord {
            type_code: 0x0003_0F02, // UserErasureScheduled — not observed
            sequence: 0,
            tick: Tick(1),
            payload: Bytes::new(),
        };
        assert_eq!(r.dispatch(&other_event, &ctx(1)).unwrap(), 0);
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
    fn dispatcher_dedups_redelivered_event() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        let ev = make_cross_shell_event(0, 5, target);
        r.dispatch(&ev, &ctx(5)).unwrap();
        let applied_again = r.dispatch(&ev, &ctx(5)).unwrap();
        assert_eq!(applied_again, 0, "redelivered (tick, sequence) must no-op");
    }

    #[test]
    fn dispatcher_rejects_same_tick_gap() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        r.dispatch(&make_cross_shell_event(0, 5, target), &ctx(5))
            .unwrap();
        // Jump to sequence 2 within tick 5 — sequence 1 missing.
        let err = r
            .dispatch(&make_cross_shell_event(2, 5, target), &ctx(5))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceGap { .. }));
    }

    #[test]
    fn dispatcher_rejects_new_tick_missing_batch_head() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        r.dispatch(&make_cross_shell_event(0, 5, target), &ctx(5))
            .unwrap();
        // Tick 6 batch must start at sequence 0 — sequence 3 means the
        // head of the new compute's batch is missing.
        let err = r
            .dispatch(&make_cross_shell_event(3, 6, target), &ctx(6))
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
    fn dispatcher_rejects_backward_tick() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        r.dispatch(&make_cross_shell_event(0, 5, target), &ctx(5))
            .unwrap();
        let err = r
            .dispatch(&make_cross_shell_event(0, 4, target), &ctx(4))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceBackward { .. }));
    }

    /// Drivers must advance the tick between computes. If two computes
    /// share a tick, the second batch head `(tick, 0)` lands behind the
    /// cursor and must be rejected loudly — never silently dropped as a
    /// duplicate.
    #[test]
    fn same_tick_second_compute_head_rejected_loudly() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let target = sid(0x10);
        r.dispatch(&make_cross_shell_event(0, 5, target), &ctx(5))
            .unwrap();
        r.dispatch(&make_cross_shell_event(1, 5, target), &ctx(5))
            .unwrap();
        let err = r
            .dispatch(&make_cross_shell_event(0, 5, target), &ctx(5))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceBackward { .. }));
    }

    /// Same-tick compute collision with SINGLE-event batches: the second
    /// compute's head lands exactly on the cursor, so the equality path
    /// must compare event identity — a DIFFERENT event there is a
    /// `PositionConflict`, never a silent `Ok(0)` "redelivery".
    #[test]
    fn same_tick_single_event_batches_conflict_loudly() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        r.dispatch(&make_cross_shell_event(0, 5, sid(0x10)), &ctx(5))
            .unwrap();
        // Distinct payload (different target shell) at the same (5, 0).
        let err = r
            .dispatch(&make_cross_shell_event(0, 5, sid(0x20)), &ctx(5))
            .unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::PositionConflict {
                at: ProjectionCursor {
                    sequence: 0,
                    tick: Tick(5)
                }
            }
        ));
    }

    /// A failed FIRST dispatch must not let a later position anchor the
    /// cursor silently past the lost event: only the exact retry may
    /// proceed.
    #[test]
    fn failed_first_dispatch_pins_the_anchor_until_retried() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(FailOnceProjection::new()));
        let ev = make_cross_shell_event(0, 5, sid(0x10));
        assert!(r.dispatch(&ev, &ctx(5)).is_err());
        // Skipping ahead past the failed event is a loud gap...
        let err = r
            .dispatch(&make_cross_shell_event(0, 6, sid(0x10)), &ctx(6))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceGap { .. }));
        // ...while retrying the exact position succeeds and re-anchors.
        assert_eq!(r.dispatch(&ev, &ctx(5)).unwrap(), 1);
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 6, sid(0x10)), &ctx(6))
                .unwrap(),
            1
        );
    }

    /// The failed-position pin holds the event IDENTITY too: a
    /// DIFFERENT event arriving at the never-accepted position is a
    /// `PositionConflict`, never silently absorbed as the "retry" —
    /// otherwise two same-tick computes would conflate through the
    /// failure window.
    #[test]
    fn failed_first_dispatch_rejects_a_different_event_at_the_pinned_position() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(FailOnceProjection::new()));
        let ev = make_cross_shell_event(0, 5, sid(0x10));
        assert!(r.dispatch(&ev, &ctx(5)).is_err());
        // Distinct payload (different target shell) at the pinned (5, 0).
        let err = r
            .dispatch(&make_cross_shell_event(0, 5, sid(0x20)), &ctx(5))
            .unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::PositionConflict {
                at: ProjectionCursor {
                    sequence: 0,
                    tick: Tick(5)
                }
            }
        ));
        // The genuine retry still proceeds.
        assert_eq!(r.dispatch(&ev, &ctx(5)).unwrap(), 1);
    }

    /// The retry pin covers MID-STREAM failures, not only the first
    /// dispatch: after a successful anchor, a failed event must not be
    /// lost to a skip-ahead (the new-tick batch-head rule would
    /// otherwise accept it) nor replaced by a different same-position
    /// event.
    #[test]
    fn failed_mid_stream_dispatch_pins_the_retry() {
        struct FailSecondProjection {
            observes: [TypeCode; 1],
            cursor: Option<ProjectionCursor>,
            calls: usize,
        }
        impl Projection for FailSecondProjection {
            fn observes(&self) -> &[TypeCode] {
                &self.observes
            }
            fn on_event(
                &mut self,
                event: &EventRecord,
                _ctx: &ProjectionContext<'_>,
            ) -> Result<(), ProjectionError> {
                self.calls += 1;
                if self.calls == 2 {
                    return Err(ProjectionError::Storage("transient"));
                }
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

        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(FailSecondProjection {
            observes: [TypeCode(CrossShellActivity::TYPE_CODE)],
            cursor: None,
            calls: 0,
        }));
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 5, sid(0x10)), &ctx(5))
                .unwrap(),
            1
        );
        let failed = make_cross_shell_event(0, 6, sid(0x10));
        assert!(r.dispatch(&failed, &ctx(6)).is_err());
        // Skip-ahead past the failed event is a loud gap (the new-tick
        // batch-head rule must not absorb it)...
        let err = r
            .dispatch(&make_cross_shell_event(0, 7, sid(0x10)), &ctx(7))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceGap { .. }));
        // ...a different event at the pinned position is a conflict...
        let err = r
            .dispatch(&make_cross_shell_event(0, 6, sid(0x20)), &ctx(6))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::PositionConflict { .. }));
        // ...and the genuine retry proceeds, after which the stream
        // continues normally.
        assert_eq!(r.dispatch(&failed, &ctx(6)).unwrap(), 1);
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 7, sid(0x10)), &ctx(7))
                .unwrap(),
            1
        );
    }

    /// Two successive actions each get a fresh compute whose event sequence
    /// restarts at 0. The second `(tick+1, 0)` event is a distinct stream
    /// position — it must apply, not vanish as a "duplicate" of the first.
    #[test]
    fn successive_computes_restarting_sequence_zero_both_apply() {
        let applied = Arc::new(AtomicUsize::new(0));
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CountingProjection::new(applied.clone())));
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 100, sid(0x01)), &ctx(100))
                .unwrap(),
            1
        );
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 101, sid(0x02)), &ctx(101))
                .unwrap(),
            1,
            "second compute's sequence-0 event must not be conflated"
        );
        assert_eq!(applied.load(Ordering::SeqCst), 2);
    }

    /// Gap detection is stream-level: an event nobody observes still
    /// advances the cursor, so a subsequent same-tick jump is a gap and
    /// the contiguous successor applies.
    #[test]
    fn unobserved_events_advance_stream_cursor() {
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CrossShellActivityFanout::new()));
        let unobserved = EventRecord {
            type_code: 0x0003_0F02, // UserErasureScheduled — not observed
            sequence: 0,
            tick: Tick(5),
            payload: Bytes::new(),
        };
        assert_eq!(r.dispatch(&unobserved, &ctx(5)).unwrap(), 0);
        let err = r
            .dispatch(&make_cross_shell_event(2, 5, sid(0x10)), &ctx(5))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::SequenceGap { .. }));
        assert_eq!(
            r.dispatch(&make_cross_shell_event(1, 5, sid(0x10)), &ctx(5))
                .unwrap(),
            1
        );
    }

    /// A projection carrying state from a previous run skips events at or
    /// before its `last_applied` when a rebuilt router replays the stream.
    #[test]
    fn rebuilt_router_skips_already_applied_events() {
        let applied = Arc::new(AtomicUsize::new(0));
        let mut p = CountingProjection::new(applied.clone());
        p.on_event(&make_cross_shell_event(0, 10, sid(0x01)), &ctx(10))
            .unwrap();
        assert_eq!(applied.load(Ordering::SeqCst), 1);

        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(p));
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 10, sid(0x01)), &ctx(10))
                .unwrap(),
            0,
            "catch-up redelivery must not double-apply"
        );
        assert_eq!(applied.load(Ordering::SeqCst), 1);
        assert_eq!(
            r.dispatch(&make_cross_shell_event(0, 11, sid(0x01)), &ctx(11))
                .unwrap(),
            1
        );
        assert_eq!(applied.load(Ordering::SeqCst), 2);
    }

    /// A projection failure mid-fan-out leaves the cursor unadvanced: the
    /// same event redispatches, projections that already applied it are
    /// skipped, and the failed projection gets its retry.
    #[test]
    fn failed_fanout_retry_does_not_double_apply() {
        let applied = Arc::new(AtomicUsize::new(0));
        let mut r = ProjectionRouter::new();
        r.promote_to_active().unwrap();
        r.register(Box::new(CountingProjection::new(applied.clone())));
        r.register(Box::new(FailOnceProjection::new()));
        let ev = make_cross_shell_event(0, 5, sid(0x10));
        assert!(r.dispatch(&ev, &ctx(5)).is_err());
        assert_eq!(applied.load(Ordering::SeqCst), 1);
        assert_eq!(
            r.dispatch(&ev, &ctx(5)).unwrap(),
            1,
            "retry applies only the previously failed projection"
        );
        assert_eq!(applied.load(Ordering::SeqCst), 1);
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

    /// Manifest auto-promote decision table.
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
                    runtime_current: "0.13".to_string(),
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
            // Only one channel healthy — below 2/3 quorum.
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
