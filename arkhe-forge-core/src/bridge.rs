//! L0 ↔ Forge `ActionCompute` bridge.
//!
//! `#[derive(ArkheAction)]` emits a kernel-side
//! [`arkhe_kernel::state::traits::ActionCompute`] impl whose body
//! delegates to [`kernel_compute`] (this module). The bridge
//! reconstructs a forge [`ActionContext`] from the kernel's read-only
//! view, runs the forge compute body, and drains the resulting
//! `Vec<Op>` back to the kernel for its authorize → dispatch → WAL
//! append loop in `Kernel::step`.
//!
//! ## Known limitations
//!
//! These are the L0-surface gaps that the published kernel API leaves
//! unaddressed; the bridge documents them honestly rather than
//! papering over with optimistic framing.
//!
//! 1. **`world_seed = [0u8; 32]` placeholder.** The kernel does not
//!    expose `Instance::world_seed` to external callers, so
//!    id-derivation through [`ActionContext::next_id`] produces ids
//!    stable per `(instance_id, type_code, tick, seq)` but not
//!    per-world. The reference `RecordHandShowdown` action in
//!    `examples/card_primitives` does not call `next_id`, so the
//!    limitation is inert for the published demo. `Instance::world_seed`
//!    is not exposed through the kernel `ActionContext` accessor.
//!
//! 2. **Principal / capabilities pinned to
//!    `Principal::System` / `CapabilityMask::SYSTEM` here.** The
//!    kernel re-authorizes every drained `Op` against the
//!    caller-supplied caps in `Kernel::step`, so the bridge's pinned
//!    values cannot relax the security gate — they are local to the
//!    forge-side compute body. A forge compute that branches on
//!    [`ActionContext::principal`] will see `System`. The caller
//!    principal is not exposed through the kernel `ActionContext`
//!    accessor.
//!
//! 3. **Forge `compute()` returning `Err(ActionError)` is suppressed
//!    to an empty `Vec<Op>`.** The kernel sees an action that
//!    produced no Ops; the `WalRecord` envelope still records the
//!    submission but with empty `stage.events`. A future release that
//!    surfaces the rejection via a dedicated `EffectFailed` kernel
//!    event will let callers distinguish "action rejected" from
//!    "action accepted but no-op". The audit-completeness gap
//!    (rejections invisible in the WAL stream) is tracked as a
//!    future hardening carry.
//!
//! 4. **Viewless context — the in-compute GDPR `ErasurePending` gate
//!    soft-passes here.** The bridge builds an
//!    `ActionContext` with no bound `InstanceView` (the kernel exposes
//!    no per-entity read into compute), so
//!    [`ActionContext::ensure_actor_eligible`] cannot resolve the
//!    actor's `UserBinding` / `UserProfile` and returns `Ok` (soft
//!    pass). This is NOT a hole: the E-user-3 C3 gate is enforced at
//!    the L2 boundary by the `RuntimeService::dispatch` admission gate
//!    (forge-platform), which reads the action's `GdprGuard::gdpr_actor`,
//!    binds the kernel `InstanceView`, and runs the same
//!    `ensure_actor_eligible` check BEFORE `submit` — rejecting an
//!    erasure-pending action before it reaches the WAL. The direct
//!    `ActionContext::new(...).with_view(&view)` path (non-dispatch
//!    callers) enforces the gate in-compute because it binds a view.
//!
//! ## Caller preconditions
//!
//! The bridge is currently scoped to a narrow forge-action shape; the
//! preconditions below are not enforced at compile time but are
//! documented contract requirements for any forge action driven
//! through `RuntimeService`:
//!
//! - **Determinism band must be `1` (Core).** Kernel-side `ActionDeriv`
//!   does not propagate forge `BAND` / `IDEMPOTENT` metadata, so a
//!   `BAND = 2` (Projection) or `BAND = 3` (Protocol) action would
//!   dispatch through the same kernel path as Core, breaking
//!   forge-side band-specific dispatch invariants. A future release
//!   wires band-aware kernel routing.
//!
//! - **`IDEMPOTENT` must be `false`.** Idempotent forge actions
//!   require the kernel-side
//!   [`IdempotencyIndex`](crate::context::IdempotencyIndex) integration
//!   (production fix: PG-UNIQUE-INDEX) before they can
//!   flow through this bridge safely.
//!
//! - **`compute()` body must not branch on
//!   [`ActionContext::principal`] / [`ActionContext::caps`] / the
//!   `world_seed`.** The bridge pins these to constants (limitation
//!   2 above + the zero `world_seed`); branching on them would force
//!   a single replay path regardless of kernel-side caller intent,
//!   masking principal-aware behaviour. A future release exposes the
//!   kernel principal / caps through the bridge.

use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal, Tick};
use arkhe_kernel::state::{ActionContext as KernelActionContext, Op};

use crate::action::ActionCompute;
use crate::context::ActionContext;

/// Bridge entry point invoked by the kernel-side `ActionCompute::compute`
/// impl emitted by `#[derive(ArkheAction)]`.
///
/// See the [module-level docs](self) for the known limitations
/// (`world_seed = 0`, principal pinning, error suppression).
pub fn kernel_compute<A>(action: &A, kernel_ctx: &KernelActionContext<'_>) -> Vec<Op>
where
    A: ActionCompute,
{
    kernel_compute_inner(action, kernel_ctx.instance_id, kernel_ctx.now)
}

/// Testable inner helper — split out so the bridge can be unit-tested
/// without reaching for a `KernelActionContext`, whose constructor is
/// `pub(crate)` in the kernel and therefore unreachable from
/// `arkhe-forge-core`.
fn kernel_compute_inner<A>(action: &A, instance_id: InstanceId, now: Tick) -> Vec<Op>
where
    A: ActionCompute,
{
    let mut forge_ctx = ActionContext::new(
        [0u8; 32],
        instance_id,
        now,
        Principal::System,
        CapabilityMask::SYSTEM,
    );
    if <A as ActionCompute>::compute(action, &mut forge_ctx).is_ok() {
        forge_ctx.drain_ops()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use arkhe_kernel::abi::{EntityId, TypeCode};

    use crate::event::ArkheEvent as _;
    use crate::event::UserErasureScheduled;
    use crate::user::{
        AuthCredential, AuthKind, GdprEraseUser, GdprStatus, KdfKind, KdfParams, RegisterUser,
        UserId, UserProfile,
    };

    fn fixture_args() -> (InstanceId, Tick) {
        (InstanceId::new(7).unwrap(), Tick(99))
    }

    #[test]
    fn ok_compute_returns_drained_ops() {
        let (iid, tick) = fixture_args();
        let action = GdprEraseUser {
            schema_version: 1,
            user: UserId::new(EntityId::new(42).unwrap()),
        };
        let ops = kernel_compute_inner(&action, iid, tick);
        assert_eq!(ops.len(), 1, "GdprEraseUser emits one event Op");
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

    #[test]
    fn err_compute_returns_empty_vec() {
        let (iid, tick) = fixture_args();
        // RegisterUser with sub-baseline KDF params is rejected by the
        // forge compute body (see `arkhe-forge-core/src/pipeline.rs`
        // tests). The bridge must collapse that `Err` to an empty
        // `Vec<Op>` — kernel sees a no-op submission.
        let action = RegisterUser {
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
        let ops = kernel_compute_inner(&action, iid, tick);
        assert!(
            ops.is_empty(),
            "weak-KDF RegisterUser must collapse to empty Op vec",
        );
    }

    #[test]
    fn determinism_same_input_same_ops() {
        // Bridge is a pure function: same `(action, instance_id, tick)`
        // → byte-identical drained `Vec<Op>`. This is the consumer-side
        // proof of A1 D1-Total replay determinism through the bridge.
        // `arkhe_kernel::state::Op` does not implement `PartialEq`, so
        // equality is asserted on the postcard-encoded form (which is
        // what the kernel hashes into the WAL chain anyway).
        let (iid, tick) = fixture_args();
        let action = GdprEraseUser {
            schema_version: 1,
            user: UserId::new(EntityId::new(101).unwrap()),
        };
        let a = kernel_compute_inner(&action, iid, tick);
        let b = kernel_compute_inner(&action, iid, tick);
        assert_eq!(a.len(), b.len(), "Op count must match");
        for (op_a, op_b) in a.iter().zip(b.iter()) {
            let bytes_a = postcard::to_allocvec(op_a).expect("encode Op a");
            let bytes_b = postcard::to_allocvec(op_b).expect("encode Op b");
            assert_eq!(
                bytes_a, bytes_b,
                "bridge output must be byte-identical across runs",
            );
        }
    }
}
