//! `ArkheAction` + `ActionCompute` sealed traits.
//!
//! `ArkheAction` is the wire-metadata trait produced by
//! `#[derive(ArkheAction)]`. `ActionCompute` pairs with it: each Action
//! implements the `compute()` body directly, consuming a `&mut ActionContext`
//! to derive entity ids, emit events, and signal rejection via `ActionError`.

use arkhe_kernel::abi::TypeCode;
use serde::{Deserialize, Serialize};

use crate::actor::ActorId;
use crate::context::{ActionContext, ActionError};

/// Determinism band classification.
///
/// * `1` — Core (L0 replay-identical).
/// * `2` — Projection (eventually consistent).
/// * `3` — Protocol-correctness (shell-level).
pub type Band = u8;

/// Sealed marker trait for runtime Action types. Implementations come only
/// from `#[derive(ArkheAction)]`.
pub trait ArkheAction:
    crate::__sealed::__Sealed + Serialize + for<'de> Deserialize<'de> + 'static
{
    /// Runtime `TypeCode` registry pin.
    const TYPE_CODE: u32;

    /// Monotone schema version — bump rules identical to `ArkheComponent`.
    const SCHEMA_VERSION: u16;

    /// Determinism band — `1` (Core) / `2` (Projection) / `3` (Protocol).
    const BAND: Band;

    /// Opt-in idempotency flag. `true` iff the deriving struct carries an
    /// `idempotency_key: Option<[u8; 16]>` field (validated at derive time).
    /// `false` by default — non-idempotent Actions are still legal.
    const IDEMPOTENT: bool = false;

    /// Convenience `TypeCode` accessor.
    fn type_code() -> TypeCode {
        TypeCode(Self::TYPE_CODE)
    }
}

/// Compute-phase trait. Each `ArkheAction` implementor provides the body
/// of this method manually — business logic per Action is unique, so
/// `compute` is intentionally not derive-generated.
///
/// Implementations must be deterministic and side-effect-free outside of
/// `ctx` (L0 A11 pure-compute succession).
pub trait ActionCompute: crate::__sealed::__Sealed + ArkheAction {
    /// Run the compute body. Emit events via `ctx.emit_event`, derive new
    /// ids via `ctx.next_id`, and return `Err(ActionError::...)` to reject.
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError>;
}

/// L2 admission hook for the GDPR `ErasurePending` (C3) gate.
///
/// The kernel `compute` path drives forge actions through
/// [`crate::bridge::kernel_compute`], which builds a viewless
/// [`ActionContext`]. With no bound view,
/// [`ActionContext::ensure_actor_eligible`] soft-passes (it cannot read
/// the actor's `UserBinding` / `UserProfile`). The L2 service layer
/// therefore reads this trait BEFORE submitting: if `gdpr_actor` returns
/// `Some(actor)`, the service binds a fresh `InstanceView` and runs the
/// in-compute eligibility check as an admission gate, rejecting an
/// `ErasurePending`-backed action before it reaches the WAL.
///
/// The default returns `None` (not user-scoped) so kernel-only actions and
/// any action that does not gate on actor erasure compile unchanged.
pub trait GdprGuard {
    /// Actor whose erasure-eligibility must be checked before admission.
    /// `None` = the action is not user-scoped (default).
    fn gdpr_actor(&self) -> Option<ActorId> {
        None
    }
}
