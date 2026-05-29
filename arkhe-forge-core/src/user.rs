//! User primitive — Identity Subject.
//!
//! Runtime-global identity carrier. `UserProfile` tracks GDPR lifecycle; one
//! or more `AuthCredential`s attach Argon2id / Scrypt KDF secrets. The User
//! is intentionally shell-agnostic — legal / billing / GDPR obligations cross
//! shell boundaries.

use arkhe_kernel::abi::{EntityId, Tick};
use serde::{Deserialize, Serialize};

use crate::action::{ActionCompute, GdprGuard};
use crate::context::{ActionContext, ActionError};
use crate::event::UserErasureScheduled;
use crate::ArkheAction;
use crate::ArkheComponent;
// E14.L1-Deny enforcement on Action::compute.
use crate::arkhe_pure;

/// Opaque handle into the runtime User namespace.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(EntityId);

impl UserId {
    /// Construct a `UserId` from a runtime-allocated `EntityId`. Callers must
    /// hold proof (spawn event, admin scope, or test fixture) that the id
    /// belongs to the User namespace — this constructor does not verify.
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

/// Authentication channel family. `#[non_exhaustive]` so new variants
/// (WebAuthn extensions, social federation) can append without breaking
/// compatibility.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuthKind {
    /// WebAuthn / FIDO2 credential.
    Passkey = 0,
    /// Email OTP / magic link.
    Email = 1,
    /// Platform handle + password.
    Handle = 2,
    /// Wallet / on-chain address.
    Address = 3,
}

/// GDPR lifecycle state. Transition to `ErasurePending` blocks all
/// actor-originated Actions on the user (compute MC gate, contract #5).
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum GdprStatus {
    /// Normal state — user can operate.
    Active = 0,
    /// Scheduled for crypto-erasure; cascade observer completes soon.
    ErasurePending = 1,
    /// Crypto-erasure completed — DEK shredded, no content recoverable.
    Erased = 2,
}

/// Password-hashing algorithm family.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum KdfKind {
    /// Argon2id (OWASP 2024 recommended default).
    Argon2id = 0,
    /// Scrypt (fallback for legacy imports).
    Scrypt = 1,
}

/// KDF cost parameters.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost (KiB for Argon2id).
    pub m_cost: u32,
    /// Time cost (iteration count).
    pub t_cost: u32,
    /// Parallelism factor.
    pub p_cost: u32,
}

/// User profile Component — exactly one per User entity (invariant E-user-1).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0001, schema_version = 1)]
pub struct UserProfile {
    /// Wire-level schema version tag (A15 succession).
    pub schema_version: u16,
    /// Tick at which `RegisterUser` completed.
    pub created_tick: Tick,
    /// Auth family of the initial `AuthCredential`.
    pub primary_auth_kind: AuthKind,
    /// GDPR lifecycle pointer.
    pub gdpr_status: GdprStatus,
}

/// Stored authentication credential — at least one per User (invariant
/// E-user-2). Secret material is a KDF output; no raw password is stored.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0002, schema_version = 1)]
pub struct AuthCredential {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Channel family.
    pub kind: AuthKind,
    /// Hash family. `Argon2id` is the runtime default.
    pub kdf: KdfKind,
    /// Per-credential random salt (16 bytes).
    pub salt: [u8; 16],
    /// KDF output: `kdf(password, salt, params)`.
    pub credential_hash: [u8; 32],
    /// Cost parameters used for `credential_hash`.
    pub kdf_params: KdfParams,
    /// Optional rotation deadline (S8 anchor).
    pub expires_tick: Option<Tick>,
    /// Tick at which the credential was bound.
    pub bound_tick: Tick,
}

impl AuthCredential {
    /// Runtime default KDF — OWASP 2024 recommendation.
    pub const DEFAULT_KDF: KdfKind = KdfKind::Argon2id;
    /// Minimum Argon2id memory cost (19 MiB).
    pub const MIN_ARGON2ID_M_COST: u32 = 19_456;
    /// Minimum Argon2id iteration count.
    pub const MIN_ARGON2ID_T_COST: u32 = 2;
    /// Minimum Argon2id parallelism.
    pub const MIN_ARGON2ID_P_COST: u32 = 1;
    /// Minimum Scrypt cost N (power-of-two, ≥ 2^15).
    pub const MIN_SCRYPT_N_COST: u32 = 1 << 15;
    /// Minimum Scrypt block-size `r`.
    pub const MIN_SCRYPT_R_COST: u32 = 8;

    /// L1-compute validator for KDF parameters — rejects weak settings.
    #[must_use]
    pub fn validate_kdf_params(kdf: KdfKind, p: &KdfParams) -> bool {
        match kdf {
            KdfKind::Argon2id => {
                p.m_cost >= Self::MIN_ARGON2ID_M_COST
                    && p.t_cost >= Self::MIN_ARGON2ID_T_COST
                    && p.p_cost >= Self::MIN_ARGON2ID_P_COST
            }
            KdfKind::Scrypt => {
                p.m_cost >= Self::MIN_SCRYPT_N_COST
                    && p.t_cost >= Self::MIN_SCRYPT_R_COST
                    && p.p_cost >= 1
            }
        }
    }
}

/// Register a fresh `User` with the supplied profile and credential.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0001, schema_version = 1, band = 1)]
pub struct RegisterUser {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Profile Component contents.
    pub profile: UserProfile,
    /// Initial credential.
    pub credential: AuthCredential,
}

/// Request GDPR crypto-erasure for an existing User. Lease — actual cascade
/// runs via the erasure-cascade observer with p95 < 24h SLA.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0003, schema_version = 1, band = 1)]
pub struct GdprEraseUser {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Target User.
    pub user: UserId,
}

impl ActionCompute for RegisterUser {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        if !AuthCredential::validate_kdf_params(self.credential.kdf, &self.credential.kdf_params) {
            return Err(ActionError::InvalidInput("KDF params below minimum"));
        }
        let user_entity = ctx.spawn_entity_for::<UserProfile>()?;
        ctx.set_component(user_entity, &self.profile)?;
        ctx.set_component(user_entity, &self.credential)?;
        Ok(())
    }
}

impl ActionCompute for GdprEraseUser {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        let event = UserErasureScheduled {
            schema_version: 1,
            user: self.user,
            scheduled_tick: ctx.tick(),
        };
        ctx.emit_event(&event)?;
        Ok(())
    }
}

// `RegisterUser` creates a new user — there is no prior backing user to gate.
impl GdprGuard for RegisterUser {}

// `GdprEraseUser` is the cascade trigger itself; gating it on
// `ErasurePending` would deadlock the only legal write path (C3). Default.
impl GdprGuard for GdprEraseUser {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_uid(v: u64) -> UserId {
        UserId::new(EntityId::new(v).unwrap())
    }

    #[test]
    fn user_id_preserves_underlying_entity() {
        let uid = make_uid(42);
        assert_eq!(uid.get().get(), 42);
    }

    #[test]
    fn auth_credential_validates_default_argon2id_params() {
        let params = KdfParams {
            m_cost: AuthCredential::MIN_ARGON2ID_M_COST,
            t_cost: AuthCredential::MIN_ARGON2ID_T_COST,
            p_cost: AuthCredential::MIN_ARGON2ID_P_COST,
        };
        assert!(AuthCredential::validate_kdf_params(
            KdfKind::Argon2id,
            &params
        ));
    }

    #[test]
    fn auth_credential_rejects_under_cost_argon2id() {
        let params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(!AuthCredential::validate_kdf_params(
            KdfKind::Argon2id,
            &params
        ));
    }

    #[test]
    fn gdpr_status_roundtrip_via_postcard() {
        let s = GdprStatus::ErasurePending;
        let b = postcard::to_stdvec(&s).unwrap();
        let back: GdprStatus = postcard::from_bytes(&b).unwrap();
        assert_eq!(s, back);
    }
}
