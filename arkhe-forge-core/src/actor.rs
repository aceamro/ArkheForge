//! Actor primitive — per-shell activity subject.
//!
//! `Actor<'s, S>` carries two compile-time proofs: the shell brand `'s`
//! (typed isolation) and the `ActorState` typestate (authentication status).
//! Transition methods consume `self` so there is no way to forge a phantom
//! state change.

use core::marker::PhantomData;

use arkhe_kernel::abi::{EntityId, Tick};
use serde::{Deserialize, Serialize};

use crate::brand::{ShellBrand, ShellId};
use crate::component::BoundedString;
use crate::user::UserId;
use crate::ArkheComponent;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
}
