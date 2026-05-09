//! PII wire format + AEAD AAD helper + DEK message counter.
//!
//! Surface: AAD 19-byte composition for AEAD tag binding, per-DEK message
//! counter, `compute_body_hash` helper for L2 pre-compute, the
//! sealed [`PiiType`] trait plus its four canonical marker types
//! (`ActorHandle`, `EntryBody`, `ActivityExtraBytes`, `AuthCredentialSecret`),
//! and the [`ShellPiiType`] wrapper carrying shell-registered markers on the
//! `0x0100..=0xFFFF` range (manifest-hooked, runtime-dispatched).
//! [`UserSalt`] is the typed per-user anchor fed into [`compute_body_hash`].

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DEK identifier — 16-byte reference to an HSM/KMS key. The runtime never
/// holds plaintext key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DekId(pub [u8; 16]);

/// AEAD algorithm family — serialized as a single discriminant byte (spec
/// AEAD policy hook).
///
/// `XChaCha20Poly1305` is the runtime default — misuse-resistant with a
/// 192-bit nonce.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadKind {
    /// 192-bit nonce + Poly1305 tag — misuse-resistant, default.
    XChaCha20Poly1305 = 0,
    /// AES-256-GCM — hardware-accelerated; requires deterministic counter nonce.
    Aes256Gcm = 1,
    /// AES-256-GCM-SIV (RFC 8452) — nonce-reuse resistance plus hardware acceleration.
    Aes256GcmSiv = 2,
}

/// Runtime-canonical `PII_CODE` reservations (`0x0001..=0x00FF`) — spec
/// Each constant is the wire tag for the corresponding PII
/// family; shell-scoped codes (`0x0100..=0xFFFF`) are layered on top.
pub mod pii_code {
    /// `ActorProfile.handle` — shell-scoped identifier.
    pub const ACTOR_HANDLE: u16 = 0x0001;
    /// `EntryBody.body_plaintext` — user content.
    pub const ENTRY_BODY: u16 = 0x0002;
    /// `ActivityRecord.extra_bytes` — shell discretion; per-user encryption recommended.
    pub const ACTIVITY_EXTRA_BYTES: u16 = 0x0003;
    /// AuthCredential auxiliary secret — stored separately from the KDF salt.
    pub const AUTH_CREDENTIAL_SECRET: u16 = 0x0004;
}

// ===================== ShellPiiType =====================

/// Audit / observer sensitivity level for a shell-registered PII type —
/// Higher levels trigger stricter logging policies
/// and can bind the type to specific AEAD / Tier requirements.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensitivity {
    /// Analytics-friendly identifier — still encrypted at rest but
    /// appears in operator dashboards under coarse pseudonymisation.
    Low = 0,
    /// Standard PII (e.g., free-form handles, message bodies).
    Medium = 1,
    /// Credential-adjacent or regulator-scrutinised material — Tier-2
    /// compliance is expected; audit trail keeps HSM attestations.
    High = 2,
}

/// Shell-registered PII marker living in the `0x0100..=0xFFFF` range
/// Canonical `0x0001..=0x00FF` codes are reserved
/// for the sealed [`PiiType`] trait; shell-scoped types flow through
/// this runtime-dispatched wrapper so manifests can declare additional
/// PII families without editing the runtime crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellPiiType {
    /// Wire tag — must be in the shell-scoped band `0x0100..=0xFFFF`.
    pii_code: u16,
    /// Operator / audit sensitivity level.
    sensitivity: Sensitivity,
    /// AEAD family the shell has pinned for this PII type. Must match
    /// the shell manifest `[audit.pii_cipher]` at decrypt time (see
    /// cipher-downgrade gate).
    aead_kind: AeadKind,
}

/// Shell-scoped wire range — `0x0100..=0xFFFF`.
pub const SHELL_PII_CODE_RANGE: core::ops::RangeInclusive<u16> = 0x0100..=0xFFFF;

impl ShellPiiType {
    /// Construct a shell PII marker. Returns [`PiiError::ShellPiiCodeOutOfRange`]
    /// if `pii_code` is outside `0x0100..=0xFFFF`.
    pub fn new(
        pii_code: u16,
        sensitivity: Sensitivity,
        aead_kind: AeadKind,
    ) -> Result<Self, PiiError> {
        if !SHELL_PII_CODE_RANGE.contains(&pii_code) {
            return Err(PiiError::ShellPiiCodeOutOfRange);
        }
        Ok(Self {
            pii_code,
            sensitivity,
            aead_kind,
        })
    }

    /// Wire tag in the shell-scoped range.
    #[inline]
    #[must_use]
    pub fn pii_code(&self) -> u16 {
        self.pii_code
    }

    /// Audit sensitivity level.
    #[inline]
    #[must_use]
    pub fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    /// Shell-pinned AEAD for this marker.
    #[inline]
    #[must_use]
    pub fn aead_kind(&self) -> AeadKind {
        self.aead_kind
    }
}

/// Runtime-local registry of shell-scoped PII markers. Populated from
/// the shell manifest at load time; subsequent encrypt / decrypt paths
/// look up the marker by its wire `pii_code` rather than carrying a
/// generic type parameter.
///
/// Duplicate registrations and out-of-range codes are refused; the
/// registry is otherwise append-only (sunset flow mirrors the shell
/// sunset policy and is out of scope for this module).
#[derive(Debug, Default)]
pub struct ShellPiiRegistry {
    entries: BTreeMap<u16, ShellPiiType>,
}

impl ShellPiiRegistry {
    /// Empty registry.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a shell PII marker. Rejects if `pii_code` is outside
    /// `0x0100..=0xFFFF` or has already been registered.
    pub fn register(&mut self, entry: ShellPiiType) -> Result<(), PiiError> {
        if !SHELL_PII_CODE_RANGE.contains(&entry.pii_code) {
            return Err(PiiError::ShellPiiCodeOutOfRange);
        }
        if self.entries.contains_key(&entry.pii_code) {
            return Err(PiiError::ShellPiiAlreadyRegistered);
        }
        self.entries.insert(entry.pii_code, entry);
        Ok(())
    }

    /// Look up a registered marker by its wire tag. Returns `None`
    /// when the code is unregistered — callers treat that as a shell
    /// drift and refuse the operation.
    #[inline]
    #[must_use]
    pub fn get(&self, pii_code: u16) -> Option<&ShellPiiType> {
        self.entries.get(&pii_code)
    }

    /// Number of registered markers.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// AEAD AAD (Additional Authenticated Data) — **exactly 19 bytes**.
///
/// Layout: `dek_id (16) || pii_code.to_be_bytes() (2) || aead_kind as u8 (1)` = 19 B.
///
/// Wrap-field tampering causes AEAD tag verification failure → `PiiError::AadMismatch`.
/// This helper is reused for recomputation on both encrypt and decrypt paths.
#[must_use]
pub fn compute_aad(dek_id: &DekId, pii_code: u16, aead_kind: AeadKind) -> [u8; 19] {
    let mut aad = [0u8; 19];
    aad[..16].copy_from_slice(&dek_id.0);
    aad[16..18].copy_from_slice(&pii_code.to_be_bytes());
    aad[18] = aead_kind as u8;
    aad
}

/// Per-user 128-bit salt held by the HSM. Shredding
/// the salt renders every `body_hash` derived from it pre-image-unsafe
/// — the crypto-erasure pairing for content hashes.
///
/// The buffer is zeroised on drop so in-process handling after an HSM
/// fetch does not leak material into memory dumps. `UserSalt` is
/// intentionally not `Clone` to keep a single owner per fetch; callers
/// borrow or re-fetch from the HSM.
///
/// Production HSM backends supply `UserSalt` via the
/// `KmsBackend::fetch_user_salt(user_id) -> Result<UserSalt, _>` hook
/// — that path keeps the user erasure
/// semantics aligned (DEK + salt drop together under a single
/// `delete_user(user_id)` call).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserSalt([u8; 16]);

impl UserSalt {
    /// Construct from a 16-byte buffer — normally produced by an HSM
    /// `fetch_user_salt` call. Callers remain responsible for wiping
    /// their own buffer after handing it off.
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the salt material — used by [`compute_body_hash`]. The
    /// returned reference is never persisted; callers feed it straight
    /// into BLAKE3.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for UserSalt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserSalt").finish_non_exhaustive()
    }
}

/// `body_hash = BLAKE3(body || user_salt || entry_nonce)`.
///
/// `user_salt` is held per-user by the HSM (shred → all entries unhashable).
/// `entry_nonce` is a per-record 128-bit plaintext field. The L2 pre-compute
/// path calls this helper; L1 simply stores the finalized `body_hash` (A11
/// pure succession).
#[must_use]
pub fn compute_body_hash(body: &[u8], user_salt: &UserSalt, entry_nonce: &[u8; 16]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(body);
    h.update(user_salt.as_bytes());
    h.update(entry_nonce);
    *h.finalize().as_bytes()
}

/// Per-DEK message-count metric.
///
/// Warn at 2^30 messages, force rotation before 2^32 (well clear of the
/// birthday bound). Observed backends plug into
/// `arkhe_runtime_dek_message_count{user_id}`.
#[derive(Debug, Clone)]
pub struct DekMessageCounter {
    dek_id: DekId,
    count: u64,
}

/// DEK rotation trigger state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationTrigger {
    /// Healthy — threshold not yet reached.
    Healthy,
    /// 2^30 warn threshold reached — operator warning.
    WarnApproachingLimit,
    /// 2^32 - cooldown — immediate rotation required (force).
    MustRotate,
}

impl DekMessageCounter {
    /// New counter — keyed by `dek_id`.
    pub fn new(dek_id: DekId) -> Self {
        Self { dek_id, count: 0 }
    }

    /// DEK id.
    #[must_use]
    pub fn dek_id(&self) -> DekId {
        self.dek_id
    }

    /// Current count.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Called on successful encrypt — count += 1.
    pub fn record_message(&mut self) {
        self.count = self.count.saturating_add(1);
    }

    /// Rotation trigger decision. 2^30 warn / 2^31 force.
    ///
    /// Force threshold set at 2^31 — clear margin before the 2^32 birthday
    /// bound (~50% earlier trigger).
    #[must_use]
    pub fn rotation_trigger(&self) -> RotationTrigger {
        const WARN_THRESHOLD: u64 = 1u64 << 30;
        const FORCE_THRESHOLD: u64 = 1u64 << 31;
        if self.count >= FORCE_THRESHOLD {
            RotationTrigger::MustRotate
        } else if self.count >= WARN_THRESHOLD {
            RotationTrigger::WarnApproachingLimit
        } else {
            RotationTrigger::Healthy
        }
    }
}

// ===================== PiiType sealed trait =====================

/// Internal seal — [`PiiType`] impls may come only from this module.
mod pii_seal {
    /// Sealed marker keeping shell code from implementing [`super::PiiType`].
    pub trait Sealed {}
}

/// Runtime-canonical PII marker — identifies a wire-tagged PII family
/// The trait is **sealed** — only the four canonical
/// marker types in this module implement it. Shell-scoped PII uses the
/// separate `ShellPiiType` channel with manifest registration.
///
/// Implementors carry a single `const PII_CODE: u16` pin in the runtime
/// canonical range `0x0001..=0x00FF`; the 2-byte field is folded into the
/// AEAD AAD so a ciphertext cannot be decrypted under a mismatched PII
/// marker (type-confused-deputy mitigation).
pub trait PiiType: pii_seal::Sealed + Serialize + for<'de> Deserialize<'de> {
    /// Wire-tag constant — fixed at the module boundary so canonical
    /// `0x0001..=0x00FF` codes are stable across releases.
    const PII_CODE: u16;
}

/// `ActorProfile.handle` marker — `PII_CODE = 0x0001`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorHandle(pub Vec<u8>);
impl pii_seal::Sealed for ActorHandle {}
impl PiiType for ActorHandle {
    const PII_CODE: u16 = pii_code::ACTOR_HANDLE;
}

/// `EntryBody.body_plaintext` marker — `PII_CODE = 0x0002`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryBody(pub Vec<u8>);
impl pii_seal::Sealed for EntryBody {}
impl PiiType for EntryBody {
    const PII_CODE: u16 = pii_code::ENTRY_BODY;
}

/// `ActivityRecord.extra_bytes` marker — `PII_CODE = 0x0003`. Shell
/// discretion; per-user encrypt recommended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityExtraBytes(pub Vec<u8>);
impl pii_seal::Sealed for ActivityExtraBytes {}
impl PiiType for ActivityExtraBytes {
    const PII_CODE: u16 = pii_code::ACTIVITY_EXTRA_BYTES;
}

/// Supplementary credential secret marker — `PII_CODE = 0x0004`. The
/// primary `AuthCredential` KDF salt is already per-credential random; this
/// marker covers auxiliary secret storage kept encrypted alongside the
/// credential (PII_CODE table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCredentialSecret(pub Vec<u8>);
impl pii_seal::Sealed for AuthCredentialSecret {}
impl PiiType for AuthCredentialSecret {
    const PII_CODE: u16 = pii_code::AUTH_CREDENTIAL_SECRET;
}

// ===================== PiiError =====================

/// Crypto-erasure + PII handling failure taxonomy.
///
/// The display strings are intentionally brief — public error surfaces
/// stay opaque; operator-facing detail is logged separately.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PiiError {
    /// Current feature set rejects encryption — the caller is running at
    /// Tier-0 (default) with no KMS backend wired.
    #[error("compliance tier too low for encryption")]
    TierTooLow,

    /// Wire `pii_code` did not match the expected `T::PII_CODE` — the
    /// ciphertext was presented for decryption under the wrong marker
    /// type (type-confused-deputy mitigation).
    #[error("PII type marker mismatch")]
    TypeMismatch,

    /// The record's `aead_kind` did not match the manifest policy
    /// (`[audit.pii_cipher]`). Downgrade attempts are refused at the
    /// decryption boundary.
    #[error("AEAD cipher downgrade rejected")]
    CipherDowngrade,

    /// AEAD tag verification failed — the AAD was tampered with, the DEK
    /// is wrong, or the ciphertext is corrupt.
    #[error("AEAD tag verification failed")]
    AadMismatch,

    /// The plaintext decoded correctly at the AEAD layer but failed
    /// postcard decoding into `T`. Usually a schema_version drift.
    #[error("payload decode failed")]
    DecodeFailed,

    /// `Dek` buffer was not the expected 32 bytes — construction-time
    /// guard (`Dek::from_bytes` never hands out a short key).
    #[error("DEK must be exactly 32 bytes")]
    InvalidKeyLength,

    /// AEAD encryption primitive reported an internal error. Opaque on
    /// purpose; operator log holds the crate-level detail.
    #[error("AEAD encrypt failed")]
    EncryptFailed,

    /// The coordinator was invoked against an unsupported `AeadKind`
    /// under the current feature set — e.g. AES-GCM under `tier-1-kms`
    /// alone.
    #[error("AEAD kind unsupported for current feature set")]
    UnsupportedAead,

    /// Per-DEK monotonic counter reached `u64::MAX` — the AES-GCM /
    /// AES-GCM-SIV paths cannot issue another deterministic nonce
    /// without risking reuse. Operator must rotate the DEK before
    /// further encryption.
    #[error("DEK nonce counter exhausted; rotation required")]
    DekExhausted,

    /// Shell-scoped PII marker declared a `pii_code` outside the
    /// reserved `0x0100..=0xFFFF` range. Canonical
    /// codes (`0x0001..=0x00FF`) are owned by the sealed [`PiiType`]
    /// trait and cannot be registered through the shell channel.
    #[error("shell PII code outside the 0x0100..=0xFFFF range")]
    ShellPiiCodeOutOfRange,

    /// Shell manifest tried to register a `pii_code` that another
    /// entry in the same registry already owns. Registration is
    /// append-only; removals flow through the shell sunset
    /// policy.
    #[error("shell PII code already registered")]
    ShellPiiAlreadyRegistered,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn aad_is_exactly_19_bytes_and_deterministic() {
        let dek_id = DekId([0xAB; 16]);
        let aad1 = compute_aad(&dek_id, pii_code::ACTOR_HANDLE, AeadKind::XChaCha20Poly1305);
        let aad2 = compute_aad(&dek_id, pii_code::ACTOR_HANDLE, AeadKind::XChaCha20Poly1305);
        assert_eq!(aad1.len(), 19);
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn aad_differs_on_pii_code_change() {
        let dek_id = DekId([0u8; 16]);
        let a = compute_aad(&dek_id, pii_code::ACTOR_HANDLE, AeadKind::XChaCha20Poly1305);
        let b = compute_aad(&dek_id, pii_code::ENTRY_BODY, AeadKind::XChaCha20Poly1305);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_differs_on_aead_kind_change() {
        let dek_id = DekId([0u8; 16]);
        let a = compute_aad(&dek_id, pii_code::ACTOR_HANDLE, AeadKind::XChaCha20Poly1305);
        let b = compute_aad(&dek_id, pii_code::ACTOR_HANDLE, AeadKind::Aes256Gcm);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_layout_dek_first_then_code_then_kind() {
        let dek_id = DekId([0x11; 16]);
        let aad = compute_aad(&dek_id, 0xABCD, AeadKind::Aes256GcmSiv);
        assert_eq!(&aad[..16], &[0x11; 16]);
        assert_eq!(&aad[16..18], &[0xAB, 0xCD]); // big-endian
        assert_eq!(aad[18], AeadKind::Aes256GcmSiv as u8);
    }

    #[test]
    fn body_hash_deterministic_and_32_bytes() {
        let body = b"hello world";
        let salt = UserSalt::from_bytes([0x01; 16]);
        let nonce = [0x02; 16];
        let h1 = compute_body_hash(body, &salt, &nonce);
        let h2 = compute_body_hash(body, &salt, &nonce);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn body_hash_differs_on_salt_change() {
        let body = b"x";
        let s1 = UserSalt::from_bytes([0x01; 16]);
        let s2 = UserSalt::from_bytes([0x02; 16]);
        let nonce = [0u8; 16];
        assert_ne!(
            compute_body_hash(body, &s1, &nonce),
            compute_body_hash(body, &s2, &nonce)
        );
    }

    #[test]
    fn user_salt_debug_does_not_leak_material() {
        let salt = UserSalt::from_bytes([0xBB; 16]);
        let s = format!("{:?}", salt);
        assert!(!s.contains("BB"));
        assert!(!s.contains("bb"));
    }

    #[test]
    fn shell_pii_type_rejects_canonical_code() {
        // 0x0050 is inside the canonical band 0x0001..=0x00FF.
        let err = ShellPiiType::new(0x0050, Sensitivity::Medium, AeadKind::XChaCha20Poly1305)
            .unwrap_err();
        assert!(matches!(err, PiiError::ShellPiiCodeOutOfRange));
    }

    #[test]
    fn shell_pii_type_accepts_shell_code() {
        let t = ShellPiiType::new(0x0200, Sensitivity::High, AeadKind::Aes256Gcm).unwrap();
        assert_eq!(t.pii_code(), 0x0200);
        assert_eq!(t.sensitivity(), Sensitivity::High);
        assert_eq!(t.aead_kind(), AeadKind::Aes256Gcm);
    }

    #[test]
    fn shell_pii_registry_rejects_duplicate() {
        let mut reg = ShellPiiRegistry::new();
        let a = ShellPiiType::new(0x0300, Sensitivity::Low, AeadKind::XChaCha20Poly1305).unwrap();
        reg.register(a).unwrap();
        let dup = ShellPiiType::new(0x0300, Sensitivity::Medium, AeadKind::Aes256Gcm).unwrap();
        let err = reg.register(dup).unwrap_err();
        assert!(matches!(err, PiiError::ShellPiiAlreadyRegistered));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn shell_pii_registry_lookup_returns_entry() {
        let mut reg = ShellPiiRegistry::new();
        assert!(reg.is_empty());
        let entry = ShellPiiType::new(0x0400, Sensitivity::Medium, AeadKind::Aes256GcmSiv).unwrap();
        reg.register(entry).unwrap();
        let found = reg.get(0x0400).expect("registered marker");
        assert_eq!(found.aead_kind(), AeadKind::Aes256GcmSiv);
        assert!(reg.get(0x0401).is_none());
    }

    #[test]
    fn shell_pii_registry_rejects_out_of_range() {
        let mut reg = ShellPiiRegistry::new();
        // Manifest carrying a 0x00FF code must be refused even if it
        // somehow passes `ShellPiiType::new` in a hostile build.
        let leaked = ShellPiiType {
            pii_code: 0x00FF,
            sensitivity: Sensitivity::Medium,
            aead_kind: AeadKind::XChaCha20Poly1305,
        };
        let err = reg.register(leaked).unwrap_err();
        assert!(matches!(err, PiiError::ShellPiiCodeOutOfRange));
    }

    #[test]
    fn rotation_trigger_transitions() {
        let dek_id = DekId([0u8; 16]);
        let mut c = DekMessageCounter::new(dek_id);
        assert_eq!(c.rotation_trigger(), RotationTrigger::Healthy);

        // Warn threshold: 2^30.
        c.count = 1u64 << 30;
        assert_eq!(c.rotation_trigger(), RotationTrigger::WarnApproachingLimit);

        // Force threshold: 2^31.
        c.count = 1u64 << 31;
        assert_eq!(c.rotation_trigger(), RotationTrigger::MustRotate);
    }

    #[test]
    fn counter_saturates_at_u64_max() {
        let dek_id = DekId([0u8; 16]);
        let mut c = DekMessageCounter::new(dek_id);
        c.count = u64::MAX;
        c.record_message();
        assert_eq!(c.count(), u64::MAX); // saturating_add
    }
}
