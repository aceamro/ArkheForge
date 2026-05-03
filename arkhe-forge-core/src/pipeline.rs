//! L1 compute pipeline — orchestrates authorization + idempotency check +
//! `compute()` + event drain.
//!
//! Currently a skeleton: the pipeline delegates authorization to caller-provided
//! capability bits (checked by `ensure_caps`) and treats idempotency as a
//! pass-through (the `ActionContext::idempotency_lookup` stub returns `None`).
//! A future release plugs the L2 layer into manifest-driven authz policy and a
//! WAL-backed idempotency index.

use arkhe_kernel::abi::CapabilityMask;

use crate::action::ActionCompute;
use crate::context::{ActionContext, ActionError, EventRecord};

/// Run an Action through the L1 compute pipeline. On success the drained
/// event buffer is returned; on rejection the context keeps any events the
/// compute accumulated before failing (callers usually discard them).
pub fn process_action<A>(
    action: &A,
    ctx: &mut ActionContext<'_>,
) -> Result<Vec<EventRecord>, ActionError>
where
    A: ActionCompute,
{
    ensure_caps(ctx.caps())?;
    action.compute(ctx)?;
    Ok(ctx.drain_events())
}

/// Authorization gate — the current skeleton requires the caller to carry a
/// non-empty capability mask. A future release replaces this body with L2
/// manifest-driven role-to-caps mapping.
fn ensure_caps(caps: CapabilityMask) -> Result<(), ActionError> {
    if caps.is_empty() {
        return Err(ActionError::CapabilityDenied("empty capability mask"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arkhe_kernel::abi::{EntityId, InstanceId, Principal, Tick};

    use crate::event::ArkheEvent as _;
    use crate::user::{
        AuthCredential, AuthKind, GdprEraseUser, GdprStatus, KdfKind, KdfParams, RegisterUser,
        UserId, UserProfile,
    };

    fn ctx(caps: CapabilityMask) -> ActionContext<'static> {
        ActionContext::new(
            [0x11u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(100),
            Principal::System,
            caps,
        )
    }

    #[test]
    fn empty_caps_reject() {
        let mut c = ctx(CapabilityMask::empty());
        let act = GdprEraseUser {
            schema_version: 1,
            user: UserId::new(EntityId::new(1).unwrap()),
        };
        let err = process_action(&act, &mut c).unwrap_err();
        matches!(err, ActionError::CapabilityDenied(_));
    }

    #[test]
    fn gdpr_erase_emits_schedule_event() {
        let mut c = ctx(CapabilityMask::SYSTEM);
        let act = GdprEraseUser {
            schema_version: 1,
            user: UserId::new(EntityId::new(42).unwrap()),
        };
        let events = process_action(&act, &mut c).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].type_code,
            crate::event::UserErasureScheduled::TYPE_CODE
        );
    }

    #[test]
    fn register_user_rejects_weak_kdf() {
        let mut c = ctx(CapabilityMask::SYSTEM);
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
        let err = process_action(&act, &mut c).unwrap_err();
        assert!(matches!(err, ActionError::InvalidInput(_)));
    }
}
