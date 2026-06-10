//! Actor primitive — per-shell activity subject.
//!
//! `Actor<'s, S>` carries two compile-time proofs: the shell brand `'s`
//! (typed isolation) and the `ActorState` typestate (authentication status).
//! Transition methods consume `self` so there is no way to forge a phantom
//! state change.

use core::marker::PhantomData;

use arkhe_kernel::abi::{EntityId, Tick};
use serde::{Deserialize, Serialize};

use crate::action::{ActionCompute, ArkheAction as _};
use crate::brand::{ShellBrand, ShellId};
use crate::component::{ArkheComponent as _, BoundedString};
use crate::context::{ensure_schema_version, ActionContext, ActionError};
use crate::user::UserId;
use crate::ArkheAction;
use crate::ArkheComponent;
// E14.L1-Deny enforcement on Action::compute.
use crate::arkhe_pure;

/// Opaque handle into the runtime Actor namespace.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActorId(EntityId);

impl ActorId {
    /// Construct an `ActorId` from a runtime-allocated `EntityId`. Callers
    /// must hold proof (spawn event, admin scope, or test fixture) that the
    /// id belongs to the Actor namespace — this constructor does not verify.
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

/// Actor role family.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActorKind {
    /// Human operator.
    Human = 0,
    /// Automated bot with declared manifest.
    Bot = 1,
    /// System actor (moderation bot, migration worker).
    System = 2,
    /// Unauthenticated / pseudonymous.
    Anonymous = 3,
}

mod state_seal {
    /// Module-private sealed trait — prevents downstream `impl ActorState`.
    pub trait Sealed {}
}

/// Sealed typestate marker for [`Actor`] authentication status.
///
/// Implementors are the three zero-variant marker types [`Anonymous`],
/// [`Authenticated`], [`Suspended`]. Additional states cannot be added
/// downstream (sealed).
pub trait ActorState: state_seal::Sealed + 'static {
    /// Canonical lower-case short name — used in metrics / logs.
    const NAME: &'static str;
}

/// Typestate: actor has not (or not yet) authenticated.
#[derive(Debug)]
pub enum Anonymous {}
/// Typestate: actor holds a verified `UserBinding`.
#[derive(Debug)]
pub enum Authenticated {}
/// Typestate: actor is banned / quarantined — Actions reject at compute.
#[derive(Debug)]
pub enum Suspended {}

impl state_seal::Sealed for Anonymous {}
impl state_seal::Sealed for Authenticated {}
impl state_seal::Sealed for Suspended {}

impl ActorState for Anonymous {
    const NAME: &'static str = "anonymous";
}
impl ActorState for Authenticated {
    const NAME: &'static str = "authenticated";
}
impl ActorState for Suspended {
    const NAME: &'static str = "suspended";
}

/// Shell-branded, typestate-tagged Actor handle.
///
/// The `'s` brand prevents cross-shell leakage at the type level; the
/// [`ActorState`] phantom prevents calling authenticated-only API on an
/// unauthenticated actor.
pub struct Actor<'s, S: ActorState> {
    brand: ShellBrand<'s>,
    id: ActorId,
    _state: PhantomData<fn() -> S>,
}

impl<'s, S: ActorState> Clone for Actor<'s, S> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
impl<'s, S: ActorState> Copy for Actor<'s, S> {}

impl<'s, S: ActorState> core::fmt::Debug for Actor<'s, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Actor")
            .field("id", &self.id)
            .field("state", &S::NAME)
            .finish()
    }
}

impl<'s, S: ActorState> Actor<'s, S> {
    /// Actor identity.
    #[inline]
    #[must_use]
    pub fn id(self) -> ActorId {
        self.id
    }

    /// Shell brand (zero-sized) — for passing through to other branded APIs.
    #[inline]
    #[must_use]
    pub fn brand(self) -> ShellBrand<'s> {
        self.brand
    }
}

impl<'s> Actor<'s, Anonymous> {
    /// Construct an unauthenticated Actor handle.
    #[inline]
    #[must_use]
    pub fn new_anonymous(brand: ShellBrand<'s>, id: ActorId) -> Self {
        Self {
            brand,
            id,
            _state: PhantomData,
        }
    }

    /// Consume the Anonymous handle and produce an Authenticated one. The
    /// caller is expected to have verified `user_id` via the L2 credential
    /// layer — this method only attaches the type-level marker.
    #[inline]
    #[must_use]
    pub fn authenticate(self, _user_id: UserId) -> Actor<'s, Authenticated> {
        Actor {
            brand: self.brand,
            id: self.id,
            _state: PhantomData,
        }
    }
}

impl<'s> Actor<'s, Authenticated> {
    /// Consume the Authenticated handle, producing a Suspended handle on
    /// moderation action. Subsequent Actions by this actor reject at compute
    /// time until the L2 suspension policy clears.
    #[inline]
    #[must_use]
    pub fn suspend(self) -> Actor<'s, Suspended> {
        Actor {
            brand: self.brand,
            id: self.id,
            _state: PhantomData,
        }
    }
}

/// Actor profile Component — exactly one per Actor (invariant E-actor-1).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0101, schema_version = 1)]
pub struct ActorProfile {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Shell identity — immutable after creation (E-actor-5).
    pub shell_id: ShellId,
    /// Display handle — unique within `shell_id` (E-actor-3).
    pub handle: BoundedString<32>,
    /// Role family.
    pub kind: ActorKind,
    /// Tick of spawn.
    pub created_tick: Tick,
}

/// Binding from Actor to the backing User — present iff the actor is
/// Authenticated (invariant E-actor-2).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0102, schema_version = 1)]
pub struct UserBinding {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Backing user identity.
    pub user_id: UserId,
}

/// Register a fresh `Actor` bound to an existing User — the production
/// write that makes the GDPR admission gate
/// ([`ActionContext::ensure_actor_eligible`]) live for this actor: the
/// gate resolves actor → user through the [`UserBinding`] attached here,
/// so an actor created without it has no resolvable user scope and the
/// gate soft-passes it (system / anonymous actors).
///
/// Follows the spawn-then-set discipline of
/// [`RegisterUser`](crate::user::RegisterUser): the actor entity is spawned
/// first (the kernel ledger no-ops a `SetComponent` on a never-spawned
/// entity), then `ActorProfile` (E-actor-1) and `UserBinding` (E-actor-2)
/// are attached.
///
/// System-scoped with an explicit `user` target field: this action runs in
/// the registration flow immediately after `RegisterUser`, when the actor
/// credential does not exist yet — there is no authenticated actor to
/// inject, so the integrator's registration path submits it as the system
/// principal and names the freshly created user explicitly. A binding that
/// names a never-registered user does not produce an ungateable actor: the
/// admission gate fails closed on a resolved binding whose user has no
/// `UserGdprState` ([`ActionError::UserLifecycleUnresolved`]).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0101, schema_version = 1, band = 1)]
pub struct RegisterActor {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Profile Component contents (E-actor-1 — exactly one per Actor).
    pub profile: ActorProfile,
    /// Backing user the new actor authenticates as (E-actor-2).
    pub user: UserId,
}

impl ActionCompute for RegisterActor {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // Validate-then-copy: wire schema versions are checked against the
        // canonical constants before any other gate, so a stale or forged
        // version never reaches the stored profile.
        ensure_schema_version(Self::SCHEMA_VERSION, self.schema_version)?;
        ensure_schema_version(ActorProfile::SCHEMA_VERSION, self.profile.schema_version)?;

        // E-actor-3 — `(shell_id, handle)` uniqueness. Soft-passes when no
        // index is bound, matching the other L1 index-backed gates.
        if ctx
            .actor_by_handle(self.profile.shell_id, &self.profile.handle)
            .is_some()
        {
            return Err(ActionError::ActorHandleCollision {
                shell_id: self.profile.shell_id,
                handle: self.profile.handle.clone(),
            });
        }

        let actor_entity = ctx.spawn_entity_for::<ActorProfile>()?;
        ctx.set_component(actor_entity, &self.profile)?;
        ctx.set_component(
            actor_entity,
            &UserBinding {
                schema_version: UserBinding::SCHEMA_VERSION,
                user_id: self.user,
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::component::ArkheComponent;

    fn ent(v: u64) -> EntityId {
        EntityId::new(v).unwrap()
    }

    #[test]
    fn actor_typestate_transitions_anonymous_authenticated_suspended() {
        ShellBrand::run(|brand| {
            let id = ActorId::new(ent(1));
            let anon: Actor<'_, Anonymous> = Actor::new_anonymous(brand, id);
            let user_id = UserId::new(ent(2));
            let auth: Actor<'_, Authenticated> = anon.authenticate(user_id);
            let susp: Actor<'_, Suspended> = auth.suspend();
            assert_eq!(susp.id(), id);
        });
    }

    #[test]
    fn actor_state_names_are_distinct() {
        assert_eq!(Anonymous::NAME, "anonymous");
        assert_eq!(Authenticated::NAME, "authenticated");
        assert_eq!(Suspended::NAME, "suspended");
    }

    #[test]
    fn actor_profile_serde_roundtrip_postcard() {
        let p = ActorProfile {
            schema_version: 1,
            shell_id: ShellId([0xAB; 16]),
            handle: BoundedString::<32>::new("alice").unwrap(),
            kind: ActorKind::Human,
            created_tick: Tick(100),
        };
        let bytes = postcard::to_stdvec(&p).unwrap();
        let back: ActorProfile = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn actor_profile_exposes_type_code_and_schema_version() {
        assert_eq!(ActorProfile::TYPE_CODE, 0x0003_0101);
        assert_eq!(ActorProfile::SCHEMA_VERSION, 1);
    }

    fn test_ctx() -> ActionContext<'static> {
        use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal};
        ActionContext::new(
            [0u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(7),
            Principal::System,
            CapabilityMask::SYSTEM,
        )
    }

    fn register_actor(v: u64) -> RegisterActor {
        RegisterActor {
            schema_version: 1,
            profile: ActorProfile {
                schema_version: 1,
                shell_id: ShellId([0xAB; 16]),
                handle: BoundedString::<32>::new("alice").unwrap(),
                kind: ActorKind::Human,
                created_tick: Tick(7),
            },
            user: UserId::new(ent(v)),
        }
    }

    #[test]
    fn register_actor_spawns_actor_then_sets_profile_and_binding() {
        use arkhe_kernel::abi::TypeCode;
        use arkhe_kernel::state::Op;

        let mut c = test_ctx();
        register_actor(7).compute(&mut c).expect("compute ok");
        let ops = c.drain_ops();
        assert_eq!(ops.len(), 3, "spawn + ActorProfile + UserBinding");

        let Op::SpawnEntity { id: actor_id, .. } = &ops[0] else {
            panic!("op 0 must spawn the actor entity, got {:?}", ops[0]);
        };
        match &ops[1] {
            Op::SetComponent {
                entity, type_code, ..
            } => {
                assert_eq!(entity, actor_id, "profile lands on the spawned actor");
                assert_eq!(*type_code, TypeCode(ActorProfile::TYPE_CODE));
            }
            other => panic!("expected SetComponent(ActorProfile), got {:?}", other),
        }
        match &ops[2] {
            Op::SetComponent {
                entity,
                type_code,
                bytes,
                ..
            } => {
                assert_eq!(entity, actor_id, "binding lands on the spawned actor");
                assert_eq!(*type_code, TypeCode(UserBinding::TYPE_CODE));
                let binding: UserBinding = postcard::from_bytes(bytes).unwrap();
                assert_eq!(binding.user_id, UserId::new(ent(7)));
            }
            other => panic!("expected SetComponent(UserBinding), got {:?}", other),
        }
    }

    #[test]
    fn register_actor_rejects_handle_collision_via_index() {
        use crate::context::ActorHandleIndex;

        struct OneOccupant {
            shell: ShellId,
            handle: BoundedString<32>,
            holder: ActorId,
        }
        impl ActorHandleIndex for OneOccupant {
            fn lookup(&self, shell: ShellId, handle: &BoundedString<32>) -> Option<ActorId> {
                (shell == self.shell && *handle == self.handle).then_some(self.holder)
            }
        }

        let act = register_actor(7);
        let index = OneOccupant {
            shell: act.profile.shell_id,
            handle: act.profile.handle.clone(),
            holder: ActorId::new(ent(99)),
        };
        let mut c = test_ctx().with_actor_handle_index(&index);
        let err = act
            .compute(&mut c)
            .expect_err("occupied handle must reject");
        match err {
            ActionError::ActorHandleCollision { shell_id, handle } => {
                assert_eq!(shell_id, act.profile.shell_id);
                assert_eq!(handle, act.profile.handle);
            }
            other => panic!("expected ActorHandleCollision, got {:?}", other),
        }
        assert!(c.ops().is_empty(), "no Ops on rejection");
    }

    #[test]
    fn register_actor_rejects_wire_schema_mismatch() {
        let mut c = test_ctx();

        let mut act = register_actor(7);
        act.schema_version = 0xBEEF;
        let err = act.compute(&mut c).expect_err("action field");
        assert!(
            matches!(
                err,
                ActionError::SchemaMismatch {
                    expected: 1,
                    got: 0xBEEF,
                }
            ),
            "got {err:?}",
        );
        assert!(c.ops().is_empty(), "no Ops on rejection");

        let mut act = register_actor(7);
        act.profile.schema_version = 0xBEEF;
        let err = act.compute(&mut c).expect_err("profile field");
        assert!(
            matches!(
                err,
                ActionError::SchemaMismatch {
                    expected: 1,
                    got: 0xBEEF,
                }
            ),
            "got {err:?}",
        );
        assert!(c.ops().is_empty(), "no Ops on rejection");
    }

    #[test]
    fn register_actor_exposes_trait_consts() {
        use crate::action::ArkheAction;
        assert_eq!(RegisterActor::TYPE_CODE, 0x0001_0101);
        assert_eq!(RegisterActor::SCHEMA_VERSION, 1);
        assert_eq!(RegisterActor::BAND, 1);
        const { assert!(!RegisterActor::IDEMPOTENT) };
    }
}
