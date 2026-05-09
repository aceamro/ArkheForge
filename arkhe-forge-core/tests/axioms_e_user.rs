//! Axiom harness for E-user-1..4.
//!
//! Enforcement tier (CHANGELOG "Axiom enforcement"):
//! - **Type-system proven**: E-user-1, E-user-2, E-user-4 — typed
//!   `UserId(EntityId)` newtype + sealed Component impls + `RegisterUser`
//!   compute path make wire violations uncompilable.
//! - **Compute-level machine-checked**: E-user-3 cascade scheduling
//!   (RUNTIME-ASSERTED) and E-user-3 C3 (`ActionContext::ensure_actor_eligible`
//!   reject in `CreateSpace::compute` / `SubmitActivity::compute`,
//!   surfaced via `ActionError::UserErasurePending`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_forge_core::action::ActionCompute;
use arkhe_forge_core::actor::{ActorId, UserBinding};
use arkhe_forge_core::brand::ShellId;
use arkhe_forge_core::component::{ArkheComponent, BoundedString};
use arkhe_forge_core::context::{ActionContext, ActionError};
use arkhe_forge_core::event::{ArkheEvent, UserErasureScheduled};
use arkhe_forge_core::space::{CreateSpace, SpaceConfig, SpaceKind, Visibility};
use arkhe_forge_core::user::{
    AuthCredential, AuthKind, GdprEraseUser, GdprStatus, KdfKind, KdfParams, RegisterUser, UserId,
    UserProfile,
};
use arkhe_kernel::abi::{CapabilityMask, EntityId, InstanceId, Principal, Tick};

fn eid(v: u64) -> EntityId {
    EntityId::new(v).unwrap()
}

fn ctx() -> ActionContext<'static> {
    ActionContext::new(
        [0x11u8; 32],
        InstanceId::new(1).unwrap(),
        Tick(100),
        Principal::System,
        CapabilityMask::SYSTEM,
    )
}

/// **E-user-1 (MC)** — exactly one `UserProfile` per User. Derive pins the
/// `TYPE_CODE` + `SCHEMA_VERSION`, so the wire-level identity cannot be
/// duplicated under a collision.
#[test]
fn e_user_1_profile_type_code_pinned() {
    assert_eq!(UserProfile::TYPE_CODE, 0x0003_0001);
    assert_eq!(UserProfile::SCHEMA_VERSION, 1);
}

/// **E-user-2 (MC)** — `AuthCredential` KDF minima. Argon2id parameters
/// below OWASP 2024 baseline are rejected by `validate_kdf_params`. Spec
/// S2 / C9 anchors.
#[test]
fn e_user_2_kdf_minima_enforced() {
    let weak = KdfParams {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    };
    assert!(!AuthCredential::validate_kdf_params(
        KdfKind::Argon2id,
        &weak
    ));

    let minimum = KdfParams {
        m_cost: AuthCredential::MIN_ARGON2ID_M_COST,
        t_cost: AuthCredential::MIN_ARGON2ID_T_COST,
        p_cost: AuthCredential::MIN_ARGON2ID_P_COST,
    };
    assert!(AuthCredential::validate_kdf_params(
        KdfKind::Argon2id,
        &minimum
    ));
}

/// **E-user-2 (MC)** — `RegisterUser` compute rejects weak KDF at the L1
/// boundary.
#[test]
fn e_user_2_register_rejects_weak_kdf() {
    let act = RegisterUser {
        schema_version: 1,
        profile: UserProfile {
            schema_version: 1,
            created_tick: Tick(0),
            primary_auth_kind: AuthKind::Passkey,
            gdpr_status: GdprStatus::Active,
        },
        credential: AuthCredential {
            schema_version: 1,
            kind: AuthKind::Passkey,
            kdf: KdfKind::Argon2id,
            salt: [0u8; 16],
            credential_hash: [0u8; 32],
            kdf_params: KdfParams {
                m_cost: 1024,
                t_cost: 1,
                p_cost: 1,
            },
            expires_tick: None,
            bound_tick: Tick(0),
        },
    };
    let mut c = ctx();
    let err = act.compute(&mut c).unwrap_err();
    assert!(matches!(err, ActionError::InvalidInput(_)));
}

/// **E-user-3 (RUNTIME-ASSERTED)** — `GdprEraseUser` is a lease, not an
/// immediate cascade. The Action emits `UserErasureScheduled` with a tick
/// pointer and the erasure-cascade observer drives the p95 < 24h SLA.
/// erasure-cascade observer.
#[test]
fn e_user_3_gdpr_erase_emits_lease_event() {
    let act = GdprEraseUser {
        schema_version: 1,
        user: UserId::new(eid(42)),
    };
    let mut c = ctx();
    act.compute(&mut c).unwrap();
    let events = c.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].type_code, UserErasureScheduled::TYPE_CODE);
    assert_eq!(events[0].tick, Tick(100));
}

/// **E-user-4 (TYPE-PROVEN)** — `UserId` wraps a `NonZeroU64` (A6 succession).
/// Zero is structurally unrepresentable; `EntityId::new(0)` returns `None`
/// at type-construction time.
#[test]
fn e_user_4_user_id_non_zero_at_the_type_level() {
    assert!(EntityId::new(0).is_none());
    let uid = UserId::new(eid(1));
    assert_eq!(uid.get().get(), 1);
}

/// **E-user-3 C3 (compute-MC)** — actor-originated compute paths reject when
/// the actor's backing user is in `GdprStatus::ErasurePending`. The cascade
/// owns the only legal write path until completion (E-user-3 cascade,
/// NC2 contract). The test stages a `UserBinding` + `UserProfile { gdpr_status:
/// ErasurePending }` directly into the context's Op buffer (visible through
/// `staged_read`), then drives `CreateSpace::compute` and asserts the
/// gate fires before any Space-bound Op is pushed.
#[test]
fn e_user_3_c3_erasing_actor_compute_rejects() {
    let user = UserId::new(eid(7));
    let actor = ActorId::new(eid(8));

    let mut c = ctx();

    // Stage `UserBinding` for the actor entity and `UserProfile` for the
    // backing user. `staged_read` (used by `ensure_actor_eligible`) walks
    // the Op buffer in reverse, so the most recent SetComponent wins —
    // no `InstanceView` mock is needed.
    c.set_component(
        actor.get(),
        &UserBinding {
            schema_version: 1,
            user_id: user,
        },
    )
    .expect("stage UserBinding");
    c.set_component(
        user.get(),
        &UserProfile {
            schema_version: 1,
            created_tick: Tick(50),
            primary_auth_kind: AuthKind::Passkey,
            gdpr_status: GdprStatus::ErasurePending,
        },
    )
    .expect("stage UserProfile");

    let staged_ops = c.ops().len();

    let action = CreateSpace {
        schema_version: 1,
        config: SpaceConfig {
            schema_version: 1,
            shell_id: ShellId([0xC3; 16]),
            slug: BoundedString::<32>::new("forbidden").unwrap(),
            kind: SpaceKind::Flat,
            visibility: Visibility::Public,
            creator: actor,
            parent_space: None,
            created_tick: Tick(100),
        },
    };
    let err = action.compute(&mut c).expect_err("compute must reject");

    match err {
        ActionError::UserErasurePending {
            user: u,
            scheduled_tick,
        } => {
            assert_eq!(u, user, "error must carry the backing user id");
            assert_eq!(
                scheduled_tick,
                Tick(100),
                "scheduled_tick must equal ctx.tick() at the rejection moment"
            );
        }
        other => panic!("expected UserErasurePending, got {:?}", other),
    }

    // No new Op was pushed by `CreateSpace` — only the two staging
    // `set_component` calls remain in the buffer. Spawn / SetComponent for
    // the would-be Space entity is absent.
    assert_eq!(
        c.ops().len(),
        staged_ops,
        "compute must not push any Space Ops after the GDPR gate fires"
    );
}
