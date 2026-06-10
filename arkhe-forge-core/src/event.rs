//! `ArkheEvent` sealed trait + Core Event catalog.
//!
//! The trait is the runtime's wire-contract marker — `#[derive(ArkheEvent)]`
//! in `arkhe-forge-macros` is the only way to satisfy it. The catalog in
//! this module defines all twelve Core-range Events
//! (`0x0003_0F01..=0x0003_0F0E`): the `ReplicaIdAllocation` +
//! `AuditReceiptKeyPolicy` pair reserves the forward-looking event
//! surface for federation / long-term audit activation.
//!
//! ## Forward-looking events — 0-emission posture
//!
//! These events are **define-only**: type + `ArkheEvent`
//! derive + `TypeCode` reservation, but **no production code path emits
//! them**. A 3-layer 0-emission defense:
//!
//! - **(a) `emit()` not called** — runtime never invokes
//!   `emit_event::<…>` for either type. A workspace grep test verifies
//!   0 production occurrences.
//! - **(b) Cargo feature gate on type definition** — each type sits
//!   behind a semantic feature flag (`federation-archive-hardened` /
//!   `audit-receipt-key-identified`) so default builds do not even
//!   compile the type.
//! - **(c) Registry test under default features** — the runtime registry
//!   inventory does not contain the reserved TypeCodes when the feature
//!   gates are off.

use arkhe_kernel::abi::{ExternalId, Tick, TypeCode};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::actor::ActorId;
use crate::brand::ShellId;
use crate::component::BoundedString;
use crate::pii::DekId;
use crate::user::UserId;
// `ArkheEvent` here refers to the runtime-derive macro (re-exported by the
// crate root from `arkhe-forge-macros`); the type-level `ArkheEvent` trait
// defined below lives in the trait namespace, so both names coexist.
use crate::ArkheEvent;

/// Sealed marker trait for runtime Event types. Implementations come only
/// from `#[derive(ArkheEvent)]`.
pub trait ArkheEvent:
    crate::__sealed::__Sealed + Serialize + for<'de> Deserialize<'de> + 'static
{
    /// Runtime `TypeCode` registry pin — Core Events live in
    /// `0x0003_0F00..=0x0003_FFFF` (TypeCode sub-range split).
    const TYPE_CODE: u32;

    /// Monotone schema version — same rules as `ArkheComponent`.
    const SCHEMA_VERSION: u16;

    /// Convenience `TypeCode` accessor.
    fn type_code() -> TypeCode {
        TypeCode(Self::TYPE_CODE)
    }
}

// ===================== Support types =====================

/// Runtime SemVer — fixed-layout 3-tuple, postcard-stable.
///
/// `semver` crate's pre-release / build metadata strings are variable-width;
/// the Runtime reserves a minimal 6-byte canonical shape instead.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub struct SemVer {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

impl SemVer {
    /// Construct from components.
    #[inline]
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Runtime-only wire-format class tag for audit receipts.
///
/// Distinct from L0 `arkhe_kernel::persist::SignatureClass` (which
/// holds key material). The L0 type is unserializable by design; this type
/// is the serializable projection.
///
/// On-wire tag is the postcard VARIANT INDEX (0..N in declaration order), not
/// the `repr(u8)` discriminant — the explicit values are a C-ABI hint, never
/// the serialized byte.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum RuntimeSignatureClass {
    /// No signature attached.
    None = 0,
    /// Classical Ed25519.
    Ed25519 = 1,
    /// Post-quantum ML-DSA-65 (Dilithium, FIPS 204).
    MlDsa65 = 2,
    /// Hybrid Ed25519 + ML-DSA-65 dual-sign.
    Hybrid = 3,
}

impl RuntimeSignatureClass {
    /// Parse the manifest `audit.signature_class` token.
    ///
    /// Canonical tokens: `"none"`, `"ed25519"`, `"ml-dsa-65"`,
    /// `"hybrid"`. Any other string yields `None` so the manifest
    /// validator can reject an unknown class with a typed error rather
    /// than silently defaulting.
    #[must_use]
    pub fn from_manifest_str(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "ed25519" => Some(Self::Ed25519),
            "ml-dsa-65" => Some(Self::MlDsa65),
            "hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }
}

/// Compliance tier classifier — crypto-erasure protection level
/// Compliance tier indicator.
///
/// On-wire tag is the postcard VARIANT INDEX (0..N in declaration order), not
/// the `repr(u8)` discriminant — the explicit values are a C-ABI hint, never
/// the serialized byte.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ComplianceTier {
    /// Tier-0 — software KEK (dev / non-production).
    Tier0 = 0,
    /// Tier-1 — single KMS free-tier.
    Tier1 = 1,
    /// Tier-2 — production Multi-KMS + threshold HSM (t-of-n Shamir).
    Tier2 = 2,
}

/// Progress scope selector for multi-region / multi-KMS erasure progress
/// (TypeCode reservation).
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProgressScope {
    /// Region scope — geographic / cloud region identifier.
    Region(BoundedString<64>),
    /// KMS identifier scope.
    KmsIdentifier(BoundedString<64>),
}

// ===================== Core Events =====================

/// `RuntimeBootstrap` — replay-anchored bootstrap receipt (the E12 axiom).
///
/// Emitted at instance first-tick, manifest change, and runtime semver bump.
/// The receipt is re-derived bit-identically from the chain-recorded
/// `Submit` inputs on every replay, and the kernel's default `replay_into`
/// validates the WAL header's `manifest_digest`
/// (`ReplayError::ManifestDigestMismatch`) — together these pin the runtime
/// environment to what produced the log.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F01, schema_version = 1)]
pub struct RuntimeBootstrap {
    /// Wire schema version.
    pub schema_version: u16,
    /// L0 kernel semver at the bootstrap tick.
    pub l0_semver: SemVer,
    /// Runtime semver at the bootstrap tick.
    pub runtime_semver: SemVer,
    /// Canonical BLAKE3 digest of the manifest TOML.
    pub manifest_digest: [u8; 32],
    /// Active TypeCode registry snapshot — derive injects
    /// canonical ascending sort before serialize.
    #[arkhe(canonical_sort)]
    pub typecode_pins: Vec<TypeCode>,
    /// Tick at which bootstrap was recorded.
    pub bootstrap_tick: Tick,
}

/// `UserErasureScheduled` — GDPR erasure lease accepted; cascade observer
/// will complete the crypto-shred.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F02, schema_version = 1)]
pub struct UserErasureScheduled {
    /// Wire schema version.
    pub schema_version: u16,
    /// Target User.
    pub user: UserId,
    /// Tick at which erasure was scheduled.
    pub scheduled_tick: Tick,
}

/// `UserErasureCompleted` — crypto-erasure completion receipt
/// (replay-anchored transparency — re-derived bit-identically from
/// chain-recorded `Submit` inputs).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F03, schema_version = 1)]
pub struct UserErasureCompleted {
    /// Wire schema version.
    pub schema_version: u16,
    /// Target User.
    pub user: UserId,
    /// Tick at which the DEK was shredded.
    pub dek_shred_tick: Tick,
    /// Signature class used for the attestation payload.
    pub attestation_class: RuntimeSignatureClass,
    /// HSM attestation bytes (typically 64 or 128 B).
    pub attestation_bytes: Bytes,
    /// Transparency-log entry index.
    pub transparency_log_index: u64,
}

/// `BackupErasurePropagated` — per-region offsite tombstone evidence
/// Restore must refuse if any region is missing.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F04, schema_version = 1)]
pub struct BackupErasurePropagated {
    /// Wire schema version.
    pub schema_version: u16,
    /// Target User.
    pub user: UserId,
    /// Region identifier (e.g. `"eu-west-1"`).
    pub region: BoundedString<32>,
    /// Tick at which the tombstone was applied.
    pub applied_tick: Tick,
    /// Signature class used for the receipt.
    pub receipt_class: RuntimeSignatureClass,
    /// Receipt payload bytes.
    pub receipt_bytes: Bytes,
}

/// `GdprPolicyViolation` — audit trail for an actor-originated Action that
/// targeted an ErasurePending User (L1 compute MC gate).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F05, schema_version = 1)]
pub struct GdprPolicyViolation {
    /// Wire schema version.
    pub schema_version: u16,
    /// Acting actor.
    pub actor: ActorId,
    /// Tick at which the violating Action was attempted.
    pub attempted_tick: Tick,
    /// TypeCode of the rejected Action.
    pub action_type_code: TypeCode,
}

/// `SignatureClassPolicy` — replay-anchored shell audit signature policy
/// (the E13 axiom; re-derived bit-identically from chain-recorded
/// `Submit` inputs). Downgrade-resistant by construction.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F06, schema_version = 1)]
pub struct SignatureClassPolicy {
    /// Wire schema version.
    pub schema_version: u16,
    /// Shell for which this policy applies.
    pub shell_id: ShellId,
    /// Required signature class.
    pub class: RuntimeSignatureClass,
    /// Tick at which the policy becomes effective.
    pub effective_tick: Tick,
}

/// `CrossShellActivity` — audit trail for a replay/admin path that
/// observed a record whose `shell_id` mismatched the actor's shell
/// (E-act-2 dual-tier RA side).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F07, schema_version = 1)]
pub struct CrossShellActivity {
    /// Wire schema version.
    pub schema_version: u16,
    /// Acting actor.
    pub actor: ActorId,
    /// Shell the target entity actually belongs to.
    pub target_shell_id: ShellId,
    /// Shell the record claimed the activity belongs to.
    pub record_shell_id: ShellId,
    /// Tick at which the mismatch was detected.
    pub detected_tick: Tick,
}

/// `PerRegionErasureProgress` — multi-region or multi-KMS DEK-shred progress
/// record (two-phase-commit).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F08, schema_version = 1)]
pub struct PerRegionErasureProgress {
    /// Wire schema version.
    pub schema_version: u16,
    /// Target User.
    pub user: UserId,
    /// Progress scope — region or KMS identifier.
    pub scope: ProgressScope,
    /// Tick at which this scope's shred completed.
    pub shred_tick: Tick,
    /// Signature class used for the attestation payload.
    pub attestation_class: RuntimeSignatureClass,
    /// HSM attestation bytes for this scope.
    pub attestation_bytes: Bytes,
}

/// `DekMigrationCompleted` — alpha→beta DEK rotation receipt
/// Emitted when `runtime-doctor pqc-reseal` or similar
/// rotation completes for a user.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F09, schema_version = 1)]
pub struct DekMigrationCompleted {
    /// Wire schema version.
    pub schema_version: u16,
    /// Target User.
    pub user: UserId,
    /// Previous DEK identifier.
    pub old_dek_id: DekId,
    /// New DEK identifier after rotation.
    pub new_dek_id: DekId,
    /// Tick at which the migration completed.
    pub migrated_tick: Tick,
}

/// `ComplianceTierChange` — operator-driven Tier transition record
/// Compliance tier indicator.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0A, schema_version = 1)]
pub struct ComplianceTierChange {
    /// Wire schema version.
    pub schema_version: u16,
    /// Previous compliance tier.
    pub old_tier: ComplianceTier,
    /// New compliance tier.
    pub new_tier: ComplianceTier,
    /// Tick at which the transition becomes effective.
    pub effective_tick: Tick,
    /// External identity of the operator who authorized the change.
    pub operator: ExternalId,
}

// ============================================================================
// Cryptographic primitives — Attestation newtype +
// AttestationSignerPolicy enum.
// ============================================================================

/// Length-sealed 64-byte attestation signature wrapper.
///
/// Constructed only via [`Attestation::from_bytes`] (which takes a
/// `[u8; 64]` literal — length statically enforced by the Rust type
/// system). The wire format is a postcard length-prefixed byte
/// sequence (`Vec<u8>`-equivalent) with a strict 64-byte length check
/// on deserialize. This combination produces a *length-sealed* type:
///
/// - **Constructor side**: any caller producing an `Attestation` does
///   so via the `[u8; 64]` constructor — the type system rejects any
///   other byte width at compile time.
/// - **Deserialize side**: any wire bytes whose payload length is
///   not exactly 64 produce a `serde::de::Error`, never a panic.
///
/// **Why a custom serde impl** (rather than `#[derive]` over `[u8; 64]`):
/// serde's stock array deserializer caps at 32 bytes — the L0
/// `WalRecord.signature` workaround uses `Vec<u8>` with length
/// validation at the application layer. `Attestation` lifts the
/// length invariant from convention to the type itself: any value of
/// type `Attestation` that exists has 64 bytes, and the Deserialize
/// impl is the exhaustive admission check.
///
/// Used by `ReplicaIdAllocation::registry_attestation` and
/// `AuditReceiptKeyPolicy::attestation`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Attestation {
    /// 64-byte payload. Private to enforce the constructor invariant —
    /// any `Attestation` value that exists has `inner.len() == 64`.
    inner: Vec<u8>,
}

impl Attestation {
    /// Construct an [`Attestation`] from a fixed 64-byte signature.
    ///
    /// The `[u8; 64]` parameter type makes the length invariant
    /// statically enforced by the Rust type system — any caller
    /// passing a non-64-byte input is rejected at compile time.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Borrow the underlying 64-byte payload as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

impl Serialize for Attestation {
    /// Serializes as the underlying `Vec<u8>` (postcard length-prefix
    /// plus bytes). Wire format is identical to a bare `Vec<u8>` of
    /// length 64, so the wire baseline is preserved byte-for-byte.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Attestation {
    /// Deserializes from a `Vec<u8>` and rejects (with `serde::de::Error`,
    /// never a panic) any payload whose length is not exactly 64. This
    /// makes `Attestation` the single admission check for the 64-byte
    /// invariant on the wire side.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let inner: Vec<u8> = Vec::deserialize(deserializer)?;
        if inner.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Attestation: expected 64 bytes, got {}",
                inner.len()
            )));
        }
        Ok(Self { inner })
    }
}

/// Signer policy for `AuditReceiptKeyPolicy::attestation`.
///
/// Each `AuditReceiptKeyPolicy` entry's attestation signature binds
/// the inventory entry to *some* signing authority — but "which
/// authority" is an operator-policy choice the runtime merely records.
/// Three variants cover the expected operator topologies;
/// `#[non_exhaustive]` lets additive variants land without breaking
/// existing wire bytes.
///
/// The enum is paired with `AuditReceiptKeyPolicy::attestation` at
/// the same struct level — currently no other event references it,
/// so cohesion is preferred over abstraction. If a second user
/// emerges, the enum can be lifted to a shared type with no
/// wire-format change (additive non-breaking refactor).
///
/// **`Copy` derive — forward-compat constraint**: the derive
/// constrains future variants to be field-less. A variant carrying
/// data (e.g., `HardwareAttestation { tpm_version: u32 }` or
/// threshold-signature parameters) would require the `Copy` derive
/// to be removed, which is a breaking API change. Field-less policy
/// reservation is the contract; data-bearing variants would arrive
/// alongside the `Copy` removal as a coordinated breaking change.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttestationSignerPolicy {
    /// Successor key signed by predecessor key — rotation chain
    /// integrity. The recipient verifies the attestation against
    /// the predecessor entry's `public_key`.
    Predecessor,
    /// Direct signature by an operator-root authority (HW-signed
    /// or air-gapped key per `docs/release-keys.md §3` co-custody).
    /// The recipient verifies against the operator-root public key
    /// pinned in the runtime's release-keys metadata.
    OperatorRoot,
    /// Genesis self-signed proof-of-possession — the signing key
    /// signs its own inventory entry. Reserved for the very first
    /// inventory entry (no predecessor, no operator-root yet
    /// pinned). Recipient verification = fixed-point check against
    /// the entry's own `public_key`.
    SelfSigned,
}

/// `ReplicaIdAllocation` — federation-replica registration receipt
/// **Define-only**: the type sits behind the
/// `federation-archive-hardened` Cargo feature so default builds do
/// not compile the type at all (3-layer 0-emission defense, layer
/// (b)).
///
/// Activation: when a federation registry signs off on a new replica
/// entering the federation, the runtime would emit one
/// `ReplicaIdAllocation` event into the chain so cross-replica audit
/// can trace the membership lineage. The wire surface (TypeCode +
/// schema) is reserved here. Activation gate: federation prerequisites
/// complete (archive-hardening + `SignedArkheUri` + identity
/// federation layer).
///
/// **0-emission posture**: no production code path calls
/// `emit_event::<ReplicaIdAllocation>(..)`. A workspace grep test
/// confirms zero emission sites; Cargo feature gating provides
/// compile-time exclusion.
#[cfg(feature = "federation-archive-hardened")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0D, schema_version = 1)]
pub struct ReplicaIdAllocation {
    /// Wire schema version.
    pub schema_version: u16,
    /// Federation identifier (128-bit). `[16]` is collision-resistant
    /// for any plausible federation count.
    pub federation_id: [u8; 16],
    /// Replica identifier within the federation. The width is u64
    /// (federation-scale collision-resistant — ~10^19
    /// replicas/federation, well beyond any plausible ultra-scale
    /// federation deployment). A narrower u32 would cap at ~4B
    /// replicas, an order-of-magnitude tight bound on the long tail
    /// of federated systems.
    pub replica_id: u64,
    /// 32-bit nonce drawn at allocation time, fed into the
    /// registry attestation signature alongside the (federation,
    /// replica, tick) tuple. Defends against replay of older
    /// allocation requests.
    pub allocation_nonce: u32,
    /// Tick at which the allocation became effective (replay-derived
    /// ordering anchor relative to other federation events).
    pub effective_tick: Tick,
    /// Federation-registry attestation over (federation_id,
    /// replica_id, allocation_nonce, effective_tick). 64-byte
    /// signature (Ed25519 width) wrapped in [`Attestation`] —
    /// length-sealed at construction (`from_bytes([u8; 64])`) and
    /// strictly verified on deserialize (length invariant lifted from
    /// convention to type). The signer is the federation registry;
    /// the signer-policy enum reservation lives on
    /// `AuditReceiptKeyPolicy::signer_policy` (audit-receipt key
    /// rotation context where signer choice is operator-variable).
    pub registry_attestation: Attestation,
}

/// `AuditReceiptKeyPolicy` — audit-receipt key inventory + rotation
/// manifest (the E13 axiom). **Define-only**: the type sits
/// behind the `audit-receipt-key-identified` Cargo feature so default
/// builds do not compile the type (3-layer 0-emission defense, layer
/// (b)).
///
/// Activation: when the operator rotates the audit-receipt signing key
/// (or initially declares the genesis key in the
/// `docs/release-keys.md §1` inventory), the runtime would emit one
/// `AuditReceiptKeyPolicy` event into the chain so audit-trail
/// consumers can verify which key was active at which tick. The wire
/// surface is reserved here. Activation gate: operator-side carry-over
/// (g) "audit-receipt key identity declared in `docs/release-keys.md`
/// inventory anchor.
///
/// **0-emission posture**: identical to `ReplicaIdAllocation` —
/// production code path emits zero, a workspace grep test verifies,
/// Cargo feature gating closes the compile.
#[cfg(feature = "audit-receipt-key-identified")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0E, schema_version = 2)]
pub struct AuditReceiptKeyPolicy {
    /// Wire schema version.
    pub schema_version: u16,
    /// Audit-receipt key identifier. The width is `[u8; 16]` (128-bit,
    /// UUID-class collision space). A narrower 8-byte width would give
    /// only a 2^32 birthday bound, tight at federation scale where
    /// multiple operators independently mint keys; 16 bytes raises the
    /// bound to 2^64 = computationally infeasible across any plausible
    /// key population. The `docs/release-keys.md §1` inventory entry
    /// maps this identifier to the physical key material.
    pub key_id: [u8; 16],
    /// Signature class for receipts under this key. Reuses the
    /// `RuntimeSignatureClass` enum so the wire
    /// tagging is consistent with `SignatureClassPolicy` (E13).
    pub algorithm: RuntimeSignatureClass,
    /// Public-key wire bytes. Variable length to accommodate
    /// classical (Ed25519, 32 bytes), post-quantum (ML-DSA-65,
    /// ~1952 bytes), and hybrid representations. Bounded by the
    /// runtime's per-event size cap on encode.
    pub public_key: Bytes,
    /// Predecessor `key_id` if this entry succeeds an earlier key
    /// (rotation chain). `None` = genesis (first entry in the
    /// inventory) or an operator-policy-determined unrelated key.
    /// Width matches `key_id` ([u8; 16]).
    pub predecessor_key_id: Option<[u8; 16]>,
    /// Tick at which this key entry becomes effective for new
    /// audit-receipt signatures.
    pub effective_tick: Tick,
    /// Tick at which this key entry retires (no further new
    /// signatures, but historical receipts remain valid). `None`
    /// for the currently-active entry.
    pub retirement_tick: Option<Tick>,
    /// Signer policy for the [`Self::attestation`] field —
    /// declares whether the signature was produced by the
    /// predecessor key (rotation chain), an operator-root authority,
    /// or as a genesis self-signed proof-of-possession. The enum +
    /// field reservation lets emission code populate the value per
    /// operator policy without further schema work.
    /// `#[non_exhaustive]` keeps additive variants forward-compat.
    pub signer_policy: AttestationSignerPolicy,
    /// Attestation signature binding the inventory entry to the
    /// operator's signing authority. 64-byte signature (Ed25519
    /// width) wrapped in [`Attestation`] — length-sealed at
    /// construction and strictly verified on deserialize (length
    /// invariant lifted from convention to type). Recipient
    /// verification path is selected by [`Self::signer_policy`].
    pub attestation: Attestation,
    /// Post-quantum half of the attestation envelope (schema v2).
    ///
    /// Coherence with [`Self::algorithm`]: this field MUST be `Some`
    /// for the PQC-bearing classes (`MlDsa65`, `Hybrid`) and `None`
    /// otherwise (`None`, `Ed25519`). For `MlDsa65` it carries the
    /// 3309-byte ML-DSA-65 signature; for `Hybrid` the 3309-byte
    /// ML-DSA-65 half (the Ed25519 half lives in [`Self::attestation`]).
    /// The verifier (`arkhe-forge-platform` `verify_receipt_envelope`)
    /// enforces this algorithm<->slot coherence before dispatching.
    ///
    /// Wire compatibility: postcard encodes `None` as a single trailing
    /// `0x00`, so a schema-1 `None`/`Ed25519` receipt re-encodes
    /// byte-identically under schema-2 when this field is left `None`.
    pub attestation_pqc: Option<Vec<u8>>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn runtime_bootstrap_serde_roundtrip() {
        let rb = RuntimeBootstrap {
            schema_version: 1,
            l0_semver: SemVer::new(0, 11, 0),
            runtime_semver: SemVer::new(0, 11, 0),
            manifest_digest: [0xABu8; 32],
            typecode_pins: vec![TypeCode(0x0003_0001), TypeCode(0x0003_0002)],
            bootstrap_tick: Tick(1),
        };
        let bytes = postcard::to_stdvec(&rb).unwrap();
        let back: RuntimeBootstrap = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(rb, back);
    }

    #[test]
    fn per_region_progress_with_region_scope_roundtrip() {
        let ev = PerRegionErasureProgress {
            schema_version: 1,
            user: crate::user::UserId::new(arkhe_kernel::abi::EntityId::new(42).unwrap()),
            scope: ProgressScope::Region(BoundedString::<64>::new("eu-west-1").unwrap()),
            shred_tick: Tick(100),
            attestation_class: RuntimeSignatureClass::Ed25519,
            attestation_bytes: Bytes::from_static(&[0u8; 64]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: PerRegionErasureProgress = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn core_event_type_code_pins_match_spec() {
        assert_eq!(RuntimeBootstrap::TYPE_CODE, 0x0003_0F01);
        assert_eq!(UserErasureScheduled::TYPE_CODE, 0x0003_0F02);
        assert_eq!(UserErasureCompleted::TYPE_CODE, 0x0003_0F03);
        assert_eq!(BackupErasurePropagated::TYPE_CODE, 0x0003_0F04);
        assert_eq!(GdprPolicyViolation::TYPE_CODE, 0x0003_0F05);
        assert_eq!(SignatureClassPolicy::TYPE_CODE, 0x0003_0F06);
        assert_eq!(CrossShellActivity::TYPE_CODE, 0x0003_0F07);
        assert_eq!(PerRegionErasureProgress::TYPE_CODE, 0x0003_0F08);
        assert_eq!(DekMigrationCompleted::TYPE_CODE, 0x0003_0F09);
        assert_eq!(ComplianceTierChange::TYPE_CODE, 0x0003_0F0A);
        // Forward-looking event TypeCode pins are verified only when
        // the activation feature is enabled (cfg-gate per 3-layer
        // 0-emission defense, layer (b)). The TypeCode constants in
        // `typecode::core_event` remain unconditional anchors.
        #[cfg(feature = "federation-archive-hardened")]
        assert_eq!(ReplicaIdAllocation::TYPE_CODE, 0x0003_0F0D);
        #[cfg(feature = "audit-receipt-key-identified")]
        assert_eq!(AuditReceiptKeyPolicy::TYPE_CODE, 0x0003_0F0E);
    }

    #[test]
    fn from_manifest_str_parses_all() {
        assert_eq!(
            RuntimeSignatureClass::from_manifest_str("none"),
            Some(RuntimeSignatureClass::None)
        );
        assert_eq!(
            RuntimeSignatureClass::from_manifest_str("ed25519"),
            Some(RuntimeSignatureClass::Ed25519)
        );
        assert_eq!(
            RuntimeSignatureClass::from_manifest_str("ml-dsa-65"),
            Some(RuntimeSignatureClass::MlDsa65)
        );
        assert_eq!(
            RuntimeSignatureClass::from_manifest_str("hybrid"),
            Some(RuntimeSignatureClass::Hybrid)
        );
        assert_eq!(RuntimeSignatureClass::from_manifest_str("ML-DSA-65"), None);
        assert_eq!(RuntimeSignatureClass::from_manifest_str("dilithium"), None);
    }

    #[test]
    fn semver_roundtrip_is_stable() {
        let v = SemVer::new(0, 11, 0);
        let a = postcard::to_stdvec(&v).unwrap();
        let b = postcard::to_stdvec(&v).unwrap();
        assert_eq!(a, b);
        let back: SemVer = postcard::from_bytes(&a).unwrap();
        assert_eq!(back, v);
    }

    // ----- Forward-looking event tests -----
    //
    // Each test is feature-gated to its activation flag (3-layer
    // 0-emission defense, layer (b)). The default-features build skips
    // these tests because the underlying type is not compiled.

    #[cfg(feature = "federation-archive-hardened")]
    #[test]
    fn replica_id_allocation_serde_roundtrip() {
        let ev = ReplicaIdAllocation {
            schema_version: 1,
            federation_id: [0xF1u8; 16],
            replica_id: 7,
            allocation_nonce: 0xCAFE_BABE,
            effective_tick: Tick(1234),
            registry_attestation: Attestation::from_bytes([0x55u8; 64]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: ReplicaIdAllocation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    /// Verify u64 width preserved for replica_id values above
    /// `u32::MAX`. Regression sentinel against any schema width
    /// change that would silently truncate the high 32 bits
    /// (federation-scale concern). Pin chosen to span the upper
    /// half of u64 so byte-level postcard varint
    /// encoding exercises the >5-byte continuation path.
    #[cfg(feature = "federation-archive-hardened")]
    #[test]
    fn replica_id_allocation_high_replica_id_preserves_u64_width() {
        let high_replica = 0x1234_5678_9ABC_DEF0u64;
        assert!(high_replica > u64::from(u32::MAX));
        let ev = ReplicaIdAllocation {
            schema_version: 1,
            federation_id: [0xA5u8; 16],
            replica_id: high_replica,
            allocation_nonce: 0xDEAD_BEEF,
            effective_tick: Tick(99_999),
            registry_attestation: Attestation::from_bytes([0x33u8; 64]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: ReplicaIdAllocation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
        assert_eq!(back.replica_id, high_replica);
    }

    #[cfg(feature = "federation-archive-hardened")]
    #[test]
    fn replica_id_allocation_type_code_matches_typecode_constant() {
        assert_eq!(
            ReplicaIdAllocation::TYPE_CODE,
            crate::typecode::core_event::REPLICA_ID_ALLOCATION
        );
    }

    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_serde_roundtrip_with_genesis_entry() {
        let ev = AuditReceiptKeyPolicy {
            schema_version: 2,
            key_id: [0xABu8; 16],
            algorithm: RuntimeSignatureClass::Ed25519,
            public_key: Bytes::from_static(&[0u8; 32]),
            predecessor_key_id: None,
            effective_tick: Tick(0),
            retirement_tick: None,
            signer_policy: AttestationSignerPolicy::SelfSigned,
            attestation: Attestation::from_bytes([0x77u8; 64]),
            attestation_pqc: None,
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: AuditReceiptKeyPolicy = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_serde_roundtrip_with_rotation_entry() {
        let ev = AuditReceiptKeyPolicy {
            schema_version: 2,
            key_id: [0xCDu8; 16],
            algorithm: RuntimeSignatureClass::MlDsa65,
            public_key: Bytes::from_static(&[0xEEu8; 1952]), // ML-DSA-65 wire size
            predecessor_key_id: Some([0xABu8; 16]),
            effective_tick: Tick(100),
            retirement_tick: Some(Tick(1000)),
            signer_policy: AttestationSignerPolicy::Predecessor,
            attestation: Attestation::from_bytes([0x99u8; 64]),
            attestation_pqc: Some(vec![0xEEu8; 3309]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: AuditReceiptKeyPolicy = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    /// Verify [u8; 16] width preserved with high-entropy distinct
    /// bytes in both `key_id` and `predecessor_key_id`. Repeated-byte
    /// literals like `[0xABu8; 16]` / `[0xCDu8; 16]` would silently
    /// round-trip through any narrower
    /// width that happens to truncate to the same repeated byte. This
    /// test pins distinct bytes per position so a regression to
    /// `[u8; 8]` would catch on the upper-half `key_id[8..16]` and
    /// `predecessor_key_id[8..16]` byte mismatch. Belt-and-suspenders
    /// against silent width truncation.
    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_distinct_bytes_preserve_full_16_byte_widths() {
        let key_id: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let predecessor_key_id: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xF0, 0x0D, 0xFA, 0xCE, 0x12, 0x34,
            0x56, 0x78,
        ];
        let ev = AuditReceiptKeyPolicy {
            schema_version: 2,
            key_id,
            algorithm: RuntimeSignatureClass::Ed25519,
            public_key: Bytes::from_static(&[0xC3u8; 32]),
            predecessor_key_id: Some(predecessor_key_id),
            effective_tick: Tick(2_500),
            retirement_tick: Some(Tick(5_000)),
            signer_policy: AttestationSignerPolicy::OperatorRoot,
            attestation: Attestation::from_bytes([0x44u8; 64]),
            attestation_pqc: None,
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: AuditReceiptKeyPolicy = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
        assert_eq!(back.key_id, key_id);
        assert_eq!(back.predecessor_key_id, Some(predecessor_key_id));
        // Explicit upper-half spot-check (catches truncation regression
        // even if compiler accepted [u8; 8] literal somehow).
        assert_eq!(back.key_id[8..16], key_id[8..16]);
    }

    /// Schema-1 vs schema-2 byte-identity for the `None` pqc slot.
    ///
    /// postcard has no struct framing — a struct encodes as the bare
    /// concatenation of its fields, and `Option::None` is a single
    /// trailing `0x00`. So a schema-2 receipt with `attestation_pqc:
    /// None` encodes as the schema-1 field run (reproduced here as the
    /// matching field tuple) followed by exactly one `0x00`. This is
    /// the wire-compat guarantee: schema-1 `None`/`Ed25519` receipts
    /// re-encode byte-identical under schema-2 modulo that one byte.
    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_none_pqc_appends_single_zero_byte() {
        let ev = AuditReceiptKeyPolicy {
            schema_version: 2,
            key_id: [0xABu8; 16],
            algorithm: RuntimeSignatureClass::Ed25519,
            public_key: Bytes::from_static(&[0u8; 32]),
            predecessor_key_id: None,
            effective_tick: Tick(0),
            retirement_tick: None,
            signer_policy: AttestationSignerPolicy::SelfSigned,
            attestation: Attestation::from_bytes([0x77u8; 64]),
            attestation_pqc: None,
        };
        let full = postcard::to_stdvec(&ev).unwrap();

        // The schema-1 field run = the same fields WITHOUT the pqc slot.
        // postcard encodes a tuple as the concatenation of its elements,
        // identical to a struct's field run, so this reproduces the
        // pre-field byte layout.
        let pre_field = postcard::to_stdvec(&(
            ev.schema_version,
            ev.key_id,
            ev.algorithm,
            ev.public_key.clone(),
            ev.predecessor_key_id,
            ev.effective_tick,
            ev.retirement_tick,
            ev.signer_policy,
            ev.attestation.clone(),
        ))
        .unwrap();

        // `None` appends exactly one trailing 0x00 to the pre-field run.
        assert_eq!(full.len(), pre_field.len() + 1);
        assert_eq!(&full[..pre_field.len()], pre_field.as_slice());
        assert_eq!(full[full.len() - 1], 0x00);
    }

    /// PQC slot round-trip — a 3309-byte ML-DSA-65 signature in the
    /// `attestation_pqc` slot survives a postcard round-trip intact.
    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_pqc_slot_round_trip() {
        let ev = AuditReceiptKeyPolicy {
            schema_version: 2,
            key_id: [0x5Au8; 16],
            algorithm: RuntimeSignatureClass::MlDsa65,
            public_key: Bytes::from_static(&[0x11u8; 1952]),
            predecessor_key_id: None,
            effective_tick: Tick(7),
            retirement_tick: None,
            signer_policy: AttestationSignerPolicy::SelfSigned,
            attestation: Attestation::from_bytes([0u8; 64]),
            attestation_pqc: Some(vec![0xABu8; 3309]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: AuditReceiptKeyPolicy = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
        assert_eq!(back.attestation_pqc.as_deref().map(<[u8]>::len), Some(3309));
    }

    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_type_code_matches_typecode_constant() {
        assert_eq!(
            AuditReceiptKeyPolicy::TYPE_CODE,
            crate::typecode::core_event::AUDIT_RECEIPT_KEY_POLICY
        );
    }

    /// 0-emission posture confirmation (layer (a) — `emit()` not
    /// called). The `ArkheEvent` trait makes the type *eligible* for
    /// chain emission via `Op::EmitEvent`, but **no production code**
    /// calls `emit_event::<ReplicaIdAllocation>(..)` or
    /// `emit_event::<AuditReceiptKeyPolicy>(..)`. A workspace grep
    /// verification scans the source tree and asserts 0 occurrences.
    /// This test is the structural anchor — type definitions exist,
    /// but the trait constants alone do not constitute emission.
    ///
    /// Feature-gated under both activation flags so the test compiles
    /// only when the types compile (cfg-gate, layer (b)).
    #[cfg(all(
        feature = "federation-archive-hardened",
        feature = "audit-receipt-key-identified"
    ))]
    #[test]
    fn forward_looking_events_are_define_only() {
        // The TYPE_CODE constants exist + are pinned. ReplicaIdAllocation
        // stays at schema 1; AuditReceiptKeyPolicy is at schema 2 (the
        // additive attestation_pqc slot). No emission entry point is
        // defined for either type. This test is the structural anchor.
        assert_eq!(ReplicaIdAllocation::SCHEMA_VERSION, 1);
        assert_eq!(AuditReceiptKeyPolicy::SCHEMA_VERSION, 2);
        assert_eq!(ReplicaIdAllocation::TYPE_CODE, 0x0003_0F0D);
        assert_eq!(AuditReceiptKeyPolicy::TYPE_CODE, 0x0003_0F0E);
    }

    // ----- Attestation newtype + AttestationSignerPolicy tests.
    // These are unconditional (no cfg-gate) because the types themselves
    // live unconditionally in the module — only the events that
    // *consume* them are cfg-gated under the activation flags.

    /// `Attestation` round-trips through postcard byte-identical to a
    /// bare `Vec<u8>` of length 64 (wire baseline preservation).
    #[test]
    fn attestation_serde_round_trip_preserves_64_bytes() {
        let payload: [u8; 64] = [0xA1; 64];
        let att = Attestation::from_bytes(payload);
        let bytes = postcard::to_stdvec(&att).unwrap();
        let back: Attestation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(att, back);
        assert_eq!(back.as_bytes(), &payload);
        assert_eq!(back.as_bytes().len(), 64);
    }

    /// Wire format invariance with bare `Vec<u8>` of length 64. The
    /// custom `Serialize` impl delegates to `Vec<u8>::serialize`, so
    /// an `Attestation` and an equivalent `vec![0x..; 64]` produce
    /// byte-for-byte identical postcard output. This preserves the
    /// sealed wire baseline — any emitted bytes decode equivalently
    /// whether the receiver expects `Attestation` or `Vec<u8>`.
    #[test]
    fn attestation_wire_format_byte_identical_to_vec_u8_length_64() {
        let payload: [u8; 64] = [0xC7; 64];
        let att_bytes = postcard::to_stdvec(&Attestation::from_bytes(payload)).unwrap();
        let vec_bytes = postcard::to_stdvec(&payload.to_vec()).unwrap();
        assert_eq!(att_bytes, vec_bytes);
    }

    /// `Attestation` deserialize **rejects** payloads whose length is
    /// not exactly 64 with a `serde::de::Error`, never a panic. This is
    /// the single admission check that lifts the 64-byte invariant from
    /// convention to type.
    #[test]
    fn attestation_deserialize_rejects_short_payload() {
        // Postcard-encode a 32-byte Vec<u8> (still serde-valid, but
        // shorter than the Attestation contract).
        let short_payload: Vec<u8> = vec![0xBB; 32];
        let bytes = postcard::to_stdvec(&short_payload).unwrap();
        let result: Result<Attestation, _> = postcard::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "32-byte payload must be rejected as not-64-bytes"
        );
    }

    #[test]
    fn attestation_deserialize_rejects_long_payload() {
        let long_payload: Vec<u8> = vec![0xCC; 65];
        let bytes = postcard::to_stdvec(&long_payload).unwrap();
        let result: Result<Attestation, _> = postcard::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "65-byte payload must be rejected as not-64-bytes"
        );
    }

    #[test]
    fn attestation_deserialize_rejects_empty_payload() {
        let empty_payload: Vec<u8> = Vec::new();
        let bytes = postcard::to_stdvec(&empty_payload).unwrap();
        let result: Result<Attestation, _> = postcard::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "empty payload must be rejected as not-64-bytes"
        );
    }

    /// All three [`AttestationSignerPolicy`] variants round-trip
    /// through postcard. The variant tag is a postcard varint; an
    /// additive variant (operator-policy expansion) lands as a new
    /// tag without disturbing existing tags (`#[non_exhaustive]` on
    /// the enum + variant order preservation).
    #[test]
    fn attestation_signer_policy_round_trip_all_three_variants() {
        for variant in [
            AttestationSignerPolicy::Predecessor,
            AttestationSignerPolicy::OperatorRoot,
            AttestationSignerPolicy::SelfSigned,
        ] {
            let bytes = postcard::to_stdvec(&variant).unwrap();
            let back: AttestationSignerPolicy = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(variant, back);
        }
    }
}
