//! L1 compute pipeline — invokes `compute()` on a forge `ActionCompute`
//! and returns the drained per-tick `EventRecord` buffer.
//!
//! [`process_action`] is the forge-side L1 entry: it gates the caller's
//! capability mask via the private `ensure_caps` helper, runs
//! `compute()`, and drains the [`ActionContext`] event buffer for the
//! caller to inspect. The
//! drained `EventRecord` stream is the consumer-side proof of replay
//! determinism (same `(action, ctx)` → byte-identical payloads); see
//! `examples/card_primitives/tests/forge_integration.rs`.
//!
//! ## Relation to the L2 service layer
//!
//! `process_action` is the **event-only** L1 surface. It does **not**
//! drive the kernel `Op`s the same `compute()` call also accumulates
//! (those flow through `ActionContext::drain_ops`). For end-to-end L0
//! state mutation + WAL append, callers use the L2 service layer
//! `RuntimeService` from `arkhe-forge-platform` (layer independence:
//! forge-core does not import forge-platform, so the cross-crate
//! reference is by name only). The L2 layer wraps a
//! [`Kernel`](arkhe_kernel::Kernel) and drives the kernel's
//! authorize → dispatch → WAL append loop via the forge → kernel
//! [`bridge`](crate::bridge) emitted by `#[derive(ArkheAction)]`.
//!
//! ## Authorization
//!
//! The L1 capability gate (see the private `ensure_caps` helper)
//! requires the caller's capability mask to be non-empty. This is
//! the L1 surface's only authorization gate; the kernel's `step()`
//! re-authorizes every drained `Op` against the same caps in the L2
//! path, so the L1 rejection is an early-out optimisation rather
//! than the security boundary.
//!
//! ## Idempotency
//!
//! The current build treats idempotency as a pass-through (the
//! `ActionContext::idempotency_lookup` accessor returns `None` unless
//! a backing [`IdempotencyIndex`](crate::context::IdempotencyIndex) is
//! attached). A production wiring binds the L2 PG-UNIQUE-INDEX
//! implementation through `ActionContext::with_idempotency_index`;
//! the L1 pipeline itself stays the same shape.

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

/// Authorization gate — requires the caller's capability mask to be
/// non-empty. The kernel re-authorizes every drained `Op` against the
/// same caps in `Kernel::step` (L2 path), so this gate is an early-out
/// optimisation rather than the security boundary; manifest-driven
/// role-to-caps mapping is an L2 service layer concern (see
/// `arkhe-forge-platform`).
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
        AuthCredential, AuthKind, GdprEraseUser, KdfKind, KdfParams, RegisterUser, UserId,
        UserProfile,
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
