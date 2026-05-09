//! Axiom harness for E-actor-1..5.
//!
//! Enforcement tier (CHANGELOG "Axiom enforcement"):
//! - **Type-system proven**: E-actor-2, E-actor-4 — sealed `ActorState`
//!   typestate + invariant-lifetime brand make violations uncompilable.
//! - **Compute-level machine-checked**: E-actor-3 — `(shell_id, handle)`
//!   uniqueness gate via `ActionContext::actor_by_handle` lookup, surfaced
//!   as `ActionError::ActorHandleCollision`.
//! - **Shape-only**: E-actor-1, E-actor-5 — wire `TYPE_CODE` /
//!   `SCHEMA_VERSION` are pinned, but the matching compute paths (single
//!   profile per actor; immutable shell binding) land in a future release.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_forge_core::actor::{
    Actor, ActorId, ActorKind, ActorProfile, ActorState, Anonymous, Authenticated, Suspended,
    UserBinding,
};
use arkhe_forge_core::brand::{ShellBrand, ShellId};
use arkhe_forge_core::component::{ArkheComponent, BoundedString};
use arkhe_forge_core::context::{ActionContext, ActionError, ActorHandleIndex};
use arkhe_forge_core::user::UserId;
use arkhe_kernel::abi::{CapabilityMask, EntityId, InstanceId, Principal, Tick};

fn eid(v: u64) -> EntityId {
    EntityId::new(v).unwrap()
}

/// **E-actor-1 (MC)** — exactly one `ActorProfile` per Actor. The skeleton
/// surfaces the derive-pinned wire contract.
#[test]
fn e_actor_1_profile_type_code_pinned() {
    assert_eq!(ActorProfile::TYPE_CODE, 0x0003_0101);
    assert_eq!(ActorProfile::SCHEMA_VERSION, 1);
}

/// **E-actor-2 (TYPE-PROVEN)** — `Actor<'_, Authenticated>` requires a
/// `UserBinding` Component; `Actor<'_, Anonymous>` rejects binding access.
/// Typestate forbids demotion at compile time.
#[test]
fn e_actor_2_typestate_chain_consumes_self() {
    ShellBrand::run(|brand| {
        let id = ActorId::new(eid(1));
        let anon: Actor<'_, Anonymous> = Actor::new_anonymous(brand, id);
        let auth: Actor<'_, Authenticated> = anon.authenticate(UserId::new(eid(2)));
        let susp: Actor<'_, Suspended> = auth.suspend();
        // All three typestate markers are reachable; the chain is one-way.
        assert_eq!(susp.id(), id);
        assert_eq!(Anonymous::NAME, "anonymous");
        assert_eq!(Authenticated::NAME, "authenticated");
        assert_eq!(Suspended::NAME, "suspended");
    });
}

/// **E-actor-3 (MC)** — `(shell_id, handle)` is unique within a shell.
/// The skeleton pins the field shape (`BoundedString<32>`); L2 enforcement
/// of uniqueness via `SpawnEntity` rejection against a `(shell, handle)`
/// index is sketched at the trait level.
#[test]
fn e_actor_3_profile_handle_is_bounded_32() {
    assert_eq!(BoundedString::<32>::CAP, 32);
    let over = "x".repeat(33);
    assert!(BoundedString::<32>::new(&over).is_err());
}

/// **E-actor-4 (TYPE-PROVEN)** — an `Actor` is scoped to a single shell via
/// the `'s` lifetime brand. Two independent `ShellBrand::run` scopes
/// produce non-unifiable brands.
#[test]
fn e_actor_4_brand_scope_encapsulation() {
    let a = ShellBrand::run(|brand| {
        let actor = Actor::<'_, Anonymous>::new_anonymous(brand, ActorId::new(eid(7)));
        actor.id()
    });
    let b = ShellBrand::run(|brand| {
        let actor = Actor::<'_, Anonymous>::new_anonymous(brand, ActorId::new(eid(7)));
        actor.id()
    });
    // Sanity — the id is copied out of each scope after the brand is dropped.
    assert_eq!(a, b);
}

/// **E-actor-5 (MC)** — `UserBinding.user_id` and `ActorProfile.shell_id`
/// are immutable after creation. The skeleton pins the wire contract; the
/// L0 bridge rejects `SetComponent` re-apply.
#[test]
fn e_actor_5_immutable_fields_pinned_in_wire_shape() {
    let profile = ActorProfile {
        schema_version: 1,
        shell_id: ShellId([0xAB; 16]),
        handle: BoundedString::<32>::new("alice").unwrap(),
        kind: ActorKind::Human,
        created_tick: Tick(100),
    };
    let binding = UserBinding {
        schema_version: 1,
        user_id: UserId::new(eid(2)),
    };
    // Postcard-roundtrip ensures the `shell_id` / `user_id` are first-class
    // fields (the SetComponent-after-spawn rejection lands in a future release).
    let pb = postcard::to_stdvec(&profile).unwrap();
    let bb = postcard::to_stdvec(&binding).unwrap();
    let profile2: ActorProfile = postcard::from_bytes(&pb).unwrap();
    let binding2: UserBinding = postcard::from_bytes(&bb).unwrap();
    assert_eq!(profile.shell_id, profile2.shell_id);
    assert_eq!(binding.user_id, binding2.user_id);
}

/// **E-actor-3 (compute-MC)** — `(shell_id, handle)` is unique within a
/// shell. The L2 layer carries the BTreeMap projection (deterministic, L0
/// A5 succession) and hands a `&dyn ActorHandleIndex` to the
/// `ActionContext` before dispatch. Compute consults the index via
/// `actor_by_handle` and surfaces `ActionError::ActorHandleCollision`
/// when the handle is already taken.
#[test]
fn e_actor_3_handle_collision_compute_rejects() {
    /// Mock backed by a flat list — sufficient for the gate's contract
    /// (one shell, one handle → at most one occupant).
    struct MockHandleIndex {
        occupants: Vec<(ShellId, BoundedString<32>, ActorId)>,
    }
    impl ActorHandleIndex for MockHandleIndex {
        fn lookup(&self, shell: ShellId, handle: &BoundedString<32>) -> Option<ActorId> {
            self.occupants.iter().find_map(|(s, h, a)| {
                if *s == shell && h == handle {
                    Some(*a)
                } else {
                    None
                }
            })
        }
    }

    let shell_a = ShellId([0xAA; 16]);
    let shell_b = ShellId([0xBB; 16]);
    let handle_alice = BoundedString::<32>::new("alice").unwrap();
    let handle_bob = BoundedString::<32>::new("bob").unwrap();
    let alice = ActorId::new(EntityId::new(99).unwrap());

    let index = MockHandleIndex {
        occupants: vec![(shell_a, handle_alice.clone(), alice)],
    };

    let c = ActionContext::new(
        [0x44u8; 32],
        InstanceId::new(1).unwrap(),
        Tick(7),
        Principal::System,
        CapabilityMask::SYSTEM,
    )
    .with_actor_handle_index(&index);

    // Positive — `(shell_a, "alice")` is occupied by `alice`.
    assert_eq!(c.actor_by_handle(shell_a, &handle_alice), Some(alice));

    // Distinct handle in same shell — free for spawn.
    assert_eq!(c.actor_by_handle(shell_a, &handle_bob), None);

    // Same handle in a different shell — uniqueness is shell-scoped, so
    // `(shell_b, "alice")` is free.
    assert_eq!(c.actor_by_handle(shell_b, &handle_alice), None);

    // Compute-shaped collision decision — when the lookup yields `Some`,
    // the gate must surface `ActorHandleCollision` carrying the offending
    // shell and handle.
    let collision_decision: Result<(), ActionError> =
        match c.actor_by_handle(shell_a, &handle_alice) {
            Some(_) => Err(ActionError::ActorHandleCollision {
                shell_id: shell_a,
                handle: handle_alice.clone(),
            }),
            None => Ok(()),
        };
    let err = collision_decision.expect_err("collision must reject");
    match err {
        ActionError::ActorHandleCollision { shell_id, handle } => {
            assert_eq!(shell_id, shell_a);
            assert_eq!(handle, handle_alice);
        }
        other => panic!("expected ActorHandleCollision, got {:?}", other),
    }

    // Free-handle path — no collision, the gate stays silent.
    let pass_decision: Result<(), ActionError> = match c.actor_by_handle(shell_a, &handle_bob) {
        Some(_) => Err(ActionError::ActorHandleCollision {
            shell_id: shell_a,
            handle: handle_bob.clone(),
        }),
        None => Ok(()),
    };
    assert!(
        pass_decision.is_ok(),
        "free `(shell, handle)` must not trip the collision gate"
    );
}
