//! L1 compute context — primitive-facing interface for Action `compute()`.
//!
//! `ActionContext<'i>` carries the per-tick state an Action needs to produce
//! effects: derived entity id generator, `EventRecord` buffer, `Op`
//! accumulator (bridges into the L0 dispatch path), principal / caps,
//! idempotency-key lookup.
//!
//! ## L0 bridge model
//!
//! Each `compute()` invocation accumulates L0 `Op`s (`SpawnEntity` /
//! `SetComponent` / `RemoveComponent` / `EmitEvent` / …) into an internal
//! `Vec<Op>`. The L2 service layer (`RuntimeService` in
//! `arkhe-forge-platform`; reference by name only — forge-core does not
//! import forge-platform, layer-independence directive) drives the
//! [`Kernel::submit`](arkhe_kernel::Kernel::submit) +
//! [`Kernel::step`](arkhe_kernel::Kernel::step) loop; the kernel-side
//! [`ActionCompute`](arkhe_kernel::state::ActionCompute) impl emitted
//! by `#[derive(ArkheAction)]` invokes
//! [`crate::bridge::kernel_compute`], which reconstructs a fresh
//! `ActionContext` from the kernel's read-only context view, runs the
//! forge `compute()` body, and returns the drained `Vec<Op>` to the
//! kernel. The kernel performs authorize → dispatch → WAL append on
//! its own internal `Effect<'i, _>` lifecycle (the `Effect` constructor
//! and `authorize` function are kernel-private, by design).
//!
//! ## `'i` brand
//!
//! The `'i` lifetime parameter is currently a phantom on the public
//! API surface, reserved for a future L0 expansion that exposes the
//! `Effect<'i, _>` brand to the L2 service layer. The kernel keeps
//! the `Effect` brand internal, so the forge-side `'i` cannot be
//! wired to a kernel-side `Effect<'i, _>` cross-call. The phantom
//! position is preserved on the public API so a later release can
//! switch from phantom to real-brand without breaking signatures.

use core::marker::PhantomData;

use arkhe_kernel::abi::{CapabilityMask, EntityId, InstanceId, Principal, Tick, TypeCode};
use arkhe_kernel::state::Op;
use arkhe_kernel::InstanceView;
use bytes::Bytes;
use serde::Serialize;

use crate::actor::{ActorId, UserBinding};
use crate::brand::ShellId;
use crate::component::{ArkheComponent, BoundedString};
use crate::derive_entity_id;
use crate::user::{GdprStatus, UserId, UserProfile};

/// L2-provided dedup backend — resolves idempotency keys to prior
/// `(EntityId, Tick)` assignments.
///
/// `arkhe-forge-platform::dedup` ships an in-memory implementation; the
/// production path swaps in a PG-UNIQUE-INDEX-backed impl.
/// The L0 kernel may layer a WAL-scan fallback underneath the same trait.
pub trait IdempotencyIndex: Send + Sync {
    /// Look up a prior assignment of `key`. `None` indicates the key is
    /// unused (callers may then insert).
    fn lookup(&self, key: &[u8; 16]) -> Option<(EntityId, Tick)>;
}

/// L2-provided `(shell_id, handle) → ActorId` index, backing E-actor-3
/// uniqueness enforcement.
///
/// `InstanceView::component(...)` is keyed by `EntityId`, so the runtime
/// cannot scan for an Actor by `(shell, handle)` directly. The L2 layer
/// maintains a BTreeMap projection (deterministic, L0 A5 succession) and
/// hands a `&dyn ActorHandleIndex` to the [`ActionContext`] before
/// dispatching `compute`.
pub trait ActorHandleIndex: Send + Sync {
    /// Return the `ActorId` already holding `(shell, handle)`, if any.
    /// `None` means the handle is free for the caller's spawn / rename.
    fn lookup(&self, shell: ShellId, handle: &BoundedString<32>) -> Option<ActorId>;
}

/// Taxonomy of compute-time rejections. `ActionCompute::compute` returns
/// `Result<(), ActionError>`; the pipeline converts these to rejection
/// records while preserving deterministic bytes (no panicking paths).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    /// Authorization gate rejected the caller (L2 capability missing or
    /// principal unsuitable for the Action).
    #[error("authorization failed: {0}")]
    AuthorizationFailed(&'static str),

    /// Idempotency-key collision — the key hit a prior record.
    #[error("idempotency conflict")]
    IdempotencyConflict([u8; 16]),

    /// A capability bit was absent from the caller's mask.
    #[error("capability denied: {0}")]
    CapabilityDenied(&'static str),

    /// Schema-version mismatch (wire version does not match a runtime
    /// decoder).
    #[error("schema version mismatch: expected {expected}, got {got}")]
    SchemaMismatch {
        /// Expected schema version.
        expected: u16,
        /// Observed schema version.
        got: u16,
    },

    /// Replay / admin path detected a cross-shell activity (E-act-2 RA).
    #[error("cross-shell activity")]
    CrossShellActivity,

    /// User has `ErasurePending` GDPR status; actor-originated Actions are
    /// blocked until the cascade completes (C3 contract).
    #[error("GDPR policy violation")]
    GdprPolicyViolation,

    /// `derive_entity_id` exhausted its retry bound.
    #[error("id exhaustion")]
    IdExhaustion,

    /// Action input failed a compute-path validator (KDF params, depth cap,
    /// etc.).
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    /// E-user-3 C3 — actor's backing user is in `GdprStatus::ErasurePending`,
    /// so any actor-originated Action is blocked until the cascade finalises.
    #[error("user erasure pending: {user:?} scheduled at {scheduled_tick:?}")]
    UserErasurePending {
        /// Backing user whose erasure is in flight.
        user: UserId,
        /// Tick at which the cascade was scheduled.
        scheduled_tick: Tick,
    },

    /// E-act-7 — an Action attempted to overwrite an entity's existing
    /// `EntityShellId` with a different shell. The runtime refuses the
    /// reassignment to defend against type-erased-id brand bypass (spec
    /// E-act-2 Extension MC).
    #[error("EntityShellId reassign rejected for {entity:?}: {old_shell:?} → {new_shell:?}")]
    EntityShellIdReassign {
        /// Target entity.
        entity: EntityId,
        /// Currently bound shell.
        old_shell: ShellId,
        /// Attempted new shell.
        new_shell: ShellId,
    },

    /// E-actor-3 — `(shell_id, handle)` is already held by another Actor.
    /// Spawning or renaming with a colliding handle is rejected (spec
    /// E-actor-3 invariant).
    #[error("actor handle collision in shell {shell_id:?}: {handle:?}")]
    ActorHandleCollision {
        /// Shell scope of the collision.
        shell_id: ShellId,
        /// Offending handle.
        handle: BoundedString<32>,
    },
}

/// Deterministic event record — what `emit_event` accumulates per tick
/// before the pipeline drains them into the WAL `Op::EmitEvent` stream.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EventRecord {
    /// Event TypeCode (runtime registry pin).
    pub type_code: u32,
    /// Per-context monotone sequence — establishes emission order within
    /// the same tick.
    pub sequence: u64,
    /// Tick at which the event was emitted.
    pub tick: Tick,
    /// Postcard-serialized event payload.
    pub payload: Bytes,
}

/// Per-Action compute context.
///
/// The `'i` lifetime is currently a phantom on the public API surface.
/// The kernel keeps `Effect<'i, _>` private, so the forge-side `'i`
/// brand cannot be wired to a kernel-side brand cross-call; the
/// position is preserved so a future L0 expansion can switch to a
/// real-brand binding without breaking the forge signature.
pub struct ActionContext<'i> {
    world_seed: [u8; 32],
    instance_id: InstanceId,
    tick: Tick,
    principal: Principal,
    caps: CapabilityMask,
    id_seq: u32,
    event_seq: u64,
    events: Vec<EventRecord>,
    ops: Vec<Op>,
    view: Option<&'i InstanceView<'i>>,
    idempotency_index: Option<&'i dyn IdempotencyIndex>,
    actor_handle_index: Option<&'i dyn ActorHandleIndex>,
    _phantom: PhantomData<&'i ()>,
}

impl<'i> ActionContext<'i> {
    /// Construct a fresh context. The `world_seed` is a non-exportable
    /// L0 configuration secret; tests may pass any fixed
    /// 32-byte value.
    #[must_use]
    pub fn new(
        world_seed: [u8; 32],
        instance_id: InstanceId,
        tick: Tick,
        principal: Principal,
        caps: CapabilityMask,
    ) -> Self {
        Self {
            world_seed,
            instance_id,
            tick,
            principal,
            caps,
            id_seq: 0,
            event_seq: 0,
            events: Vec::new(),
            ops: Vec::new(),
            view: None,
            idempotency_index: None,
            actor_handle_index: None,
            _phantom: PhantomData,
        }
    }

    /// Attach an L0 `InstanceView` snapshot — enables
    /// [`ActionContext::read`] lookups. Method-chain builder style so
    /// callers can write `ActionContext::new(...).with_view(&view)`.
    #[inline]
    #[must_use]
    pub fn with_view(mut self, view: &'i InstanceView<'i>) -> Self {
        self.view = Some(view);
        self
    }

    /// Attach an `IdempotencyIndex` backend — enables
    /// [`ActionContext::idempotency_lookup`] to consult the L2 PG UNIQUE
    /// INDEX (or equivalent). Without this call the lookup always returns
    /// `None` (forward-compat stub).
    #[inline]
    #[must_use]
    pub fn with_idempotency_index(mut self, index: &'i dyn IdempotencyIndex) -> Self {
        self.idempotency_index = Some(index);
        self
    }

    /// Attach an [`ActorHandleIndex`] backend — enables
    /// [`ActionContext::actor_by_handle`] to enforce E-actor-3 uniqueness
    /// Without this call `actor_by_handle` always returns
    /// `None`, so handle-collision rejection only fires when an L2
    /// implementation is bound.
    #[inline]
    #[must_use]
    pub fn with_actor_handle_index(mut self, index: &'i dyn ActorHandleIndex) -> Self {
        self.actor_handle_index = Some(index);
        self
    }

    /// Current tick.
    #[inline]
    #[must_use]
    pub fn tick(&self) -> Tick {
        self.tick
    }

    /// Caller principal (authorization subject).
    #[inline]
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Caller capability mask (L2-granted authority set).
    #[inline]
    #[must_use]
    pub fn caps(&self) -> CapabilityMask {
        self.caps
    }

    /// Instance identifier.
    #[inline]
    #[must_use]
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    /// Derive the next `EntityId` for a given `type_code`. Increments the
    /// internal per-context sequence so repeated calls within the same
    /// tick produce distinct entities.
    pub fn next_id(&mut self, type_code: u32) -> Result<EntityId, ActionError> {
        let seq = self.id_seq;
        self.id_seq = self.id_seq.wrapping_add(1);
        derive_entity_id(
            &self.world_seed,
            self.instance_id,
            TypeCode(type_code),
            self.tick,
            seq,
        )
        .ok_or(ActionError::IdExhaustion)
    }

    /// Emit an event. Dual-path — the payload is appended to the
    /// [`EventRecord`] buffer (drained by [`drain_events`](Self::drain_events),
    /// the L1 [`pipeline::process_action`](crate::pipeline::process_action)
    /// surface) **and** pushed onto the L0 `Op::EmitEvent` accumulator
    /// (drained via [`ActionContext::drain_ops`] by the L2 service
    /// layer's bridge into the kernel).
    pub fn emit_event<E>(&mut self, event: &E) -> Result<(), ActionError>
    where
        E: Serialize + crate::event::ArkheEvent,
    {
        let payload = postcard::to_stdvec(event)
            .map_err(|_| ActionError::InvalidInput("event serialization failed"))?;
        let payload_bytes: Bytes = Bytes::from(payload);

        let record = EventRecord {
            type_code: E::TYPE_CODE,
            sequence: self.event_seq,
            tick: self.tick,
            payload: payload_bytes.clone(),
        };
        self.event_seq = self.event_seq.saturating_add(1);
        self.events.push(record);

        self.ops.push(Op::EmitEvent {
            actor: None,
            event_type_code: TypeCode(E::TYPE_CODE),
            event_bytes: payload_bytes,
        });
        Ok(())
    }

    /// Spawn a fresh entity in the namespace of `C`. Allocates an
    /// `EntityId` via [`ActionContext::next_id`] using `C::TYPE_CODE` as
    /// the id-derivation namespace, and pushes a matching
    /// `Op::SpawnEntity` into the accumulator.
    ///
    /// The component itself is **not** attached here — follow with
    /// [`ActionContext::set_component`] to attach the payload.
    pub fn spawn_entity_for<C: ArkheComponent>(&mut self) -> Result<EntityId, ActionError> {
        let id = self.next_id(C::TYPE_CODE)?;
        let owner = self.principal.clone();
        self.ops.push(Op::SpawnEntity { id, owner });
        Ok(id)
    }

    /// Attach (or replace) component `component` on `entity`. Serializes
    /// the payload via postcard and pushes a `Op::SetComponent`. The
    /// runtime ledger uses the encoded size for quota accounting (L0
    /// memory budget enforcement).
    pub fn set_component<C: ArkheComponent>(
        &mut self,
        entity: EntityId,
        component: &C,
    ) -> Result<(), ActionError> {
        let bytes = postcard::to_stdvec(component)
            .map_err(|_| ActionError::InvalidInput("component serialization failed"))?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.ops.push(Op::SetComponent {
            entity,
            type_code: TypeCode(C::TYPE_CODE),
            bytes: Bytes::from(bytes),
            size,
        });
        Ok(())
    }

    /// Detach component `C` from `entity`. `prior_size` must match the
    /// size the matching `SetComponent` reported — the ledger uses it to
    /// balance the memory budget (L0 quota discipline). The kernel does
    /// not currently expose a back-channel for the runtime to look up
    /// the prior size; callers pass it explicitly so the size delta in
    /// the emitted `Op::RemoveComponent` is balanced against the
    /// preceding `Op::SetComponent`.
    pub fn remove_component<C: ArkheComponent>(
        &mut self,
        entity: EntityId,
        prior_size: u64,
    ) -> Result<(), ActionError> {
        self.ops.push(Op::RemoveComponent {
            entity,
            type_code: TypeCode(C::TYPE_CODE),
            size: prior_size,
        });
        Ok(())
    }

    /// Drain accumulated L0 `Op`s. The L2 service layer calls this after
    /// `compute()` returns, wraps each `Op` in `Effect<'i, Unverified>`,
    /// and submits through the authorize → dispatch path.
    pub fn drain_ops(&mut self) -> Vec<Op> {
        core::mem::take(&mut self.ops)
    }

    /// Borrow the accumulated `Op` buffer without draining — for tests
    /// and debug tooling.
    #[inline]
    #[must_use]
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Idempotency-key lookup. Consults the attached `IdempotencyIndex`
    /// (see [`ActionContext::with_idempotency_index`]) if one is bound;
    /// otherwise returns `None` for forward-compat.
    ///
    /// The production path uses PG UNIQUE INDEX; the L0
    /// kernel may layer a WAL-scan fallback beneath the same interface.
    #[inline]
    #[must_use]
    pub fn idempotency_lookup(&self, key: &[u8; 16]) -> Option<(EntityId, Tick)> {
        self.idempotency_index.and_then(|idx| idx.lookup(key))
    }

    /// Read a component from the attached `InstanceView` (NC2 contract).
    ///
    /// Returns:
    /// * `Ok(Some(component))` — the view is bound and the component was
    ///   decoded successfully.
    /// * `Ok(None)` — no view bound, or the component is not attached to
    ///   `entity` in the view.
    /// * `Err(ActionError::InvalidInput)` — the view returned bytes but
    ///   postcard decoding failed (version drift or corrupt state).
    pub fn read<C: ArkheComponent>(&self, entity: EntityId) -> Result<Option<C>, ActionError> {
        let Some(view) = self.view else {
            return Ok(None);
        };
        let Some(bytes) = view.component(entity, TypeCode(C::TYPE_CODE)) else {
            return Ok(None);
        };
        let decoded = postcard::from_bytes::<C>(bytes)
            .map_err(|_| ActionError::InvalidInput("component decode failed"))?;
        Ok(Some(decoded))
    }

    /// Read a component, taking into account `Op` mutations staged so far in
    /// the current `compute()` call. This is the staging-aware sibling of
    /// [`ActionContext::read`] — same return shape, but a same-tick
    /// `set_component` (or `remove_component`) earlier in the compute body
    /// shadows the view's bytes.
    ///
    /// The Op accumulator is scanned in reverse, so the most-recent mutation
    /// wins. A `RemoveComponent` makes the staged read return `Ok(None)`
    /// even if the view still holds the prior value.
    ///
    /// Used by E-act-7 reassign rejection: a compute that issues a
    /// `set_component::<EntityShellId>` for an entity already shadowed by a
    /// staged op must still see the staged shell, not the stale view.
    pub fn staged_read<C: ArkheComponent>(
        &self,
        entity: EntityId,
    ) -> Result<Option<C>, ActionError> {
        let target_tc = TypeCode(C::TYPE_CODE);
        for op in self.ops.iter().rev() {
            match op {
                Op::SetComponent {
                    entity: e,
                    type_code,
                    bytes,
                    ..
                } if *e == entity && *type_code == target_tc => {
                    let decoded = postcard::from_bytes::<C>(bytes)
                        .map_err(|_| ActionError::InvalidInput("staged component decode failed"))?;
                    return Ok(Some(decoded));
                }
                Op::RemoveComponent {
                    entity: e,
                    type_code,
                    ..
                } if *e == entity && *type_code == target_tc => {
                    return Ok(None);
                }
                _ => {}
            }
        }
        self.read::<C>(entity)
    }

    /// Resolve `(ShellId, BoundedString<32>) → ActorId` via the bound
    /// [`ActorHandleIndex`]. Returns `None` if no index is attached or
    /// the handle is unused.
    ///
    /// The compute path uses this to enforce E-actor-3 uniqueness before
    /// spawning a fresh `ActorProfile`.
    #[must_use]
    pub fn actor_by_handle(&self, shell: ShellId, handle: &BoundedString<32>) -> Option<ActorId> {
        self.actor_handle_index
            .and_then(|idx| idx.lookup(shell, handle))
    }

    /// Resolve the backing [`UserId`] for an authenticated [`ActorId`] via
    /// the staged-aware [`UserBinding`] read. Returns:
    ///
    /// * `Ok(Some(user_id))` — actor has an authenticated `UserBinding`.
    /// * `Ok(None)` — no view or no binding (anonymous / pre-bind).
    /// * `Err(...)` — view bytes failed to decode (state corruption).
    pub fn authenticated_actor_user(&self, actor: ActorId) -> Result<Option<UserId>, ActionError> {
        let binding = self.staged_read::<UserBinding>(actor.get())?;
        Ok(binding.map(|b| b.user_id))
    }

    /// Resolve the GDPR status of `user` via the staged-aware
    /// [`UserProfile`] read. Returns `Ok(None)` when no profile is
    /// reachable; the compute caller decides whether that is a soft
    /// pass (Tier-0 / pre-Bootstrap dev) or a hard reject.
    pub fn user_gdpr_status(&self, user: UserId) -> Result<Option<GdprStatus>, ActionError> {
        let profile = self.staged_read::<UserProfile>(user.get())?;
        Ok(profile.map(|p| p.gdpr_status))
    }

    /// E-user-3 C3 helper — fail an actor-originated compute when the
    /// actor's backing user is in `GdprStatus::ErasurePending`. `Ok(None)`
    /// from the underlying reads (no view bound, anonymous actor, etc.)
    /// is treated as a soft pass — the L2 service layer guarantees the
    /// view is bound for production paths.
    pub fn ensure_actor_eligible(
        &self,
        actor: ActorId,
        scheduled_tick: Tick,
    ) -> Result<(), ActionError> {
        let Some(user) = self.authenticated_actor_user(actor)? else {
            return Ok(());
        };
        if matches!(
            self.user_gdpr_status(user)?,
            Some(GdprStatus::ErasurePending)
        ) {
            return Err(ActionError::UserErasurePending {
                user,
                scheduled_tick,
            });
        }
        Ok(())
    }

    /// Preview the `EntityId` that the next [`ActionContext::next_id`] /
    /// [`ActionContext::spawn_entity_for`] call would produce, **without**
    /// bumping the internal sequence counter.
    ///
    /// Useful for pre-spawn validation (e.g. E-act-5 Activity self-loop
    /// rejection): compute the predicted id, compare against the target,
    /// then commit the actual spawn.
    pub fn preview_next_id_for<C: ArkheComponent>(&self) -> Result<EntityId, ActionError> {
        derive_entity_id(
            &self.world_seed,
            self.instance_id,
            TypeCode(C::TYPE_CODE),
            self.tick,
            self.id_seq,
        )
        .ok_or(ActionError::IdExhaustion)
    }

    /// Drain accumulated events. Called by the pipeline after `compute()`
    /// returns so the WAL append path can stream them in sequence order.
    pub fn drain_events(&mut self) -> Vec<EventRecord> {
        core::mem::take(&mut self.events)
    }

    /// Borrow the accumulated event buffer without draining — for tests
    /// and debug tooling.
    #[inline]
    #[must_use]
    pub fn events(&self) -> &[EventRecord] {
        &self.events
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::event::{ArkheEvent as _, UserErasureScheduled};
    use crate::user::UserId;

    fn fixture_ctx() -> ActionContext<'static> {
        ActionContext::new(
            [0x11u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(100),
            Principal::System,
            CapabilityMask::SYSTEM,
        )
    }

    #[test]
    fn context_exposes_principal_and_caps() {
        let ctx = fixture_ctx();
        assert_eq!(*ctx.principal(), Principal::System);
        assert!(ctx.caps().contains(CapabilityMask::SYSTEM));
        assert_eq!(ctx.tick(), Tick(100));
    }

    #[test]
    fn next_id_is_deterministic_and_monotone_within_context() {
        let mut ctx = fixture_ctx();
        let a = ctx.next_id(0x0003_0001).unwrap();
        let b = ctx.next_id(0x0003_0001).unwrap();
        assert_ne!(a, b, "sequential next_id calls must yield distinct ids");
    }

    #[test]
    fn emit_event_appends_record_in_sequence() {
        let mut ctx = fixture_ctx();
        let user = UserId::new(arkhe_kernel::abi::EntityId::new(42).unwrap());
        let ev = UserErasureScheduled {
            schema_version: 1,
            user,
            scheduled_tick: Tick(100),
        };
        ctx.emit_event(&ev).unwrap();
        ctx.emit_event(&ev).unwrap();
        let drained = ctx.drain_events();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].sequence, 0);
        assert_eq!(drained[1].sequence, 1);
        assert_eq!(drained[0].type_code, UserErasureScheduled::TYPE_CODE);
        assert!(ctx.events().is_empty());
    }

    #[test]
    fn idempotency_lookup_returns_none_by_default() {
        let ctx = fixture_ctx();
        assert!(ctx.idempotency_lookup(&[0u8; 16]).is_none());
    }

    #[test]
    fn ops_buffer_starts_empty_and_drains() {
        let mut ctx = fixture_ctx();
        assert!(ctx.ops().is_empty());
        let user = UserId::new(arkhe_kernel::abi::EntityId::new(7).unwrap());
        ctx.emit_event(&UserErasureScheduled {
            schema_version: 1,
            user,
            scheduled_tick: Tick(100),
        })
        .unwrap();
        assert_eq!(ctx.ops().len(), 1, "emit_event pushes Op::EmitEvent");
        let drained = ctx.drain_ops();
        assert_eq!(drained.len(), 1);
        matches!(drained[0], Op::EmitEvent { .. });
        assert!(ctx.ops().is_empty());
    }

    #[test]
    fn spawn_entity_for_derives_id_and_pushes_spawn_op() {
        use crate::user::UserProfile;
        let mut ctx = fixture_ctx();
        let id = ctx.spawn_entity_for::<UserProfile>().unwrap();
        let ops = ctx.drain_ops();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            Op::SpawnEntity {
                id: spawn_id,
                owner,
            } => {
                assert_eq!(*spawn_id, id);
                assert!(matches!(owner, Principal::System));
            }
            other => panic!("expected SpawnEntity, got {:?}", other),
        }
    }

    #[test]
    fn set_component_encodes_via_postcard_and_tracks_size() {
        use crate::user::{AuthKind, GdprStatus, UserProfile};
        let mut ctx = fixture_ctx();
        let profile = UserProfile {
            schema_version: 1,
            created_tick: Tick(1),
            primary_auth_kind: AuthKind::Passkey,
            gdpr_status: GdprStatus::Active,
        };
        let entity = ctx.spawn_entity_for::<UserProfile>().unwrap();
        ctx.set_component(entity, &profile).unwrap();
        let ops = ctx.drain_ops();
        assert_eq!(ops.len(), 2);
        match &ops[1] {
            Op::SetComponent {
                entity: e,
                type_code,
                bytes,
                size,
            } => {
                assert_eq!(*e, entity);
                assert_eq!(*type_code, TypeCode(UserProfile::TYPE_CODE));
                assert_eq!(*size, bytes.len() as u64);
                let back: UserProfile = postcard::from_bytes(bytes).unwrap();
                assert_eq!(back, profile);
            }
            other => panic!("expected SetComponent, got {:?}", other),
        }
    }

    #[test]
    fn remove_component_pushes_remove_op_with_reported_size() {
        use crate::user::UserProfile;
        let mut ctx = fixture_ctx();
        let entity = ctx.spawn_entity_for::<UserProfile>().unwrap();
        ctx.remove_component::<UserProfile>(entity, 128).unwrap();
        let ops = ctx.drain_ops();
        match &ops[1] {
            Op::RemoveComponent {
                entity: e,
                type_code,
                size,
            } => {
                assert_eq!(*e, entity);
                assert_eq!(*type_code, TypeCode(UserProfile::TYPE_CODE));
                assert_eq!(*size, 128);
            }
            other => panic!("expected RemoveComponent, got {:?}", other),
        }
    }

    #[test]
    fn emit_event_dual_path_event_record_and_op() {
        let mut ctx = fixture_ctx();
        let user = UserId::new(arkhe_kernel::abi::EntityId::new(9).unwrap());
        ctx.emit_event(&UserErasureScheduled {
            schema_version: 1,
            user,
            scheduled_tick: Tick(100),
        })
        .unwrap();
        // Both buffers populated — drain independently.
        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].type_code, UserErasureScheduled::TYPE_CODE);

        let ops = ctx.drain_ops();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            Op::EmitEvent {
                actor,
                event_type_code,
                event_bytes: _,
            } => {
                assert!(actor.is_none());
                assert_eq!(*event_type_code, TypeCode(UserErasureScheduled::TYPE_CODE));
            }
            other => panic!("expected EmitEvent, got {:?}", other),
        }
    }

    /// A local `IdempotencyIndex` impl for unit-testing the
    /// `with_idempotency_index` wiring without pulling in the
    /// `arkhe-forge-platform` dedup crate.
    struct FixedIndex {
        key: [u8; 16],
        binding: (arkhe_kernel::abi::EntityId, Tick),
    }

    impl IdempotencyIndex for FixedIndex {
        fn lookup(&self, key: &[u8; 16]) -> Option<(arkhe_kernel::abi::EntityId, Tick)> {
            if *key == self.key {
                Some(self.binding)
            } else {
                None
            }
        }
    }

    #[test]
    fn idempotency_lookup_consults_attached_index() {
        let idx = FixedIndex {
            key: [0x77u8; 16],
            binding: (arkhe_kernel::abi::EntityId::new(5).unwrap(), Tick(42)),
        };
        let ctx = fixture_ctx().with_idempotency_index(&idx);
        assert_eq!(
            ctx.idempotency_lookup(&[0x77u8; 16]),
            Some((arkhe_kernel::abi::EntityId::new(5).unwrap(), Tick(42))),
        );
        // Missing key still returns None.
        assert!(ctx.idempotency_lookup(&[0x00u8; 16]).is_none());
    }

    #[test]
    fn read_returns_none_when_no_view_is_bound() {
        use crate::user::UserProfile;
        let ctx = fixture_ctx();
        let out: Option<UserProfile> = ctx
            .read::<UserProfile>(arkhe_kernel::abi::EntityId::new(1).unwrap())
            .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn preview_next_id_does_not_bump_sequence() {
        use crate::user::UserProfile;
        let mut ctx = fixture_ctx();
        let a = ctx.preview_next_id_for::<UserProfile>().unwrap();
        let b = ctx.preview_next_id_for::<UserProfile>().unwrap();
        assert_eq!(a, b, "preview must not bump the id sequence");
        let committed = ctx.next_id(UserProfile::TYPE_CODE).unwrap();
        assert_eq!(
            committed, a,
            "the first committed next_id matches the prior preview",
        );
    }
}
