//! `ArkheEvent` sealed trait + Core Event catalog (spec §3.2 / §14.5 /
//! §14.7 / §14.9.1).
//!
//! The trait is the runtime's wire-contract marker — `#[derive(ArkheEvent)]`
//! in `arkhe-forge-macros` is the only way to satisfy it. The catalog in
//! this module defines all fourteen Core-range Events
//! (`0x0003_0F01..=0x0003_0F0E`); `HookModuleRegister` (Track B.6, DIP-N1)
//! anchors hook-module ingestion receipts, `ObserverQuarantine`
//! (Track A.2.4, DIP-N2) anchors observer-host trap quarantines, and the
//! Track H.1 (DIP-N3) pair `ReplicaIdAllocation` + `AuditReceiptKeyPolicy`
//! reserves the §14.7 forward-looking event surface for v0.99+ federation
//! / long-term audit activation.
//!
//! ## Track H.1 — 0-emission forward-looking events
//!
//! The two §14.7 events ship as **define-only** at v0.12: type +
//! `ArkheEvent` derive + `TypeCode` reservation, but **no production
//! code path emits them**. The 3-layer 0-emission defense (cryptographer
//! + auditor cycle plan agreement):
//!
//! - **(a) `emit()` not defined** — runtime never calls `emit_event::<…>`
//!   for either type, enforced structurally by the absence of the call
//!   site. Workspace grep test in Track H.3 verifies 0 production
//!   occurrences.
//! - **(b) Cargo feature gate on type definition** — Track H.2 wraps
//!   each type behind a semantic feature flag (`federation-archive-
//!   hardened` / `audit-receipt-key-identified`) so default builds do
//!   not even compile the type.
//! - **(d) Registry test under default features** — Track H.3 verifies
//!   the runtime registry inventory does not contain the reserved
//!   TypeCodes when the feature gates are off.
//!
//! At H.1 (this commit) only layer (a) is in place — the types compile
//! unconditionally, but no emit site exists. H.2 + H.3 close the
//! remaining defense layers.

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
    /// `0x0003_0F00..=0x0003_FFFF` (spec §3.2 sub-range split).
    const TYPE_CODE: u32;

    /// Monotone schema version — same rules as `ArkheComponent`.
    const SCHEMA_VERSION: u16;

    /// Convenience `TypeCode` accessor.
    fn type_code() -> TypeCode {
        TypeCode(Self::TYPE_CODE)
    }
}

// ===================== Support types =====================

/// Runtime SemVer — fixed-layout 3-tuple, postcard-stable (spec §14.7 NR6-6).
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

/// Runtime-only wire-format class tag for audit receipts (spec §14.7 NR6-4).
///
/// Distinct from L0 `arkhe_kernel::persist::SignatureClass` (which
/// holds key material). The L0 type is unserializable by design; this type
/// is the serializable projection.
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

/// Compliance tier classifier — crypto-erasure protection level
/// (spec §14.11.2 / §14.9.1 §§12).
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

/// Trap classification for [`ObserverQuarantine`] — surfaced into the
/// chain-anchored receipt so replay + audit can distinguish each
/// sandbox-boundary failure mode. Track A.2.4 (DIP-N2 v0.12 sealing
/// cycle).
///
/// **Wire-stable enum** (R5.2 NF-B pattern, mirrors `RuntimeSignatureClass`
/// / `ComplianceTier`): `#[repr(u8)]` + `#[non_exhaustive]` so additive
/// expansion is non-breaking. Each variant has a fixed discriminant so
/// the postcard wire format stays stable across schema-version bumps.
///
/// Mirrored as a host-internal type by `arkhe_forge_platform::observer_host`
/// (re-exports this same enum). Single source of truth lives here in
/// `arkhe-forge-core` because the value enters the L0 chain via the
/// `ObserverQuarantine` event.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObserverTrapClass {
    /// wasm panic / cranelift trap — observer code itself faulted.
    Panic = 0,
    /// Fuel exhaustion — observer exceeded the per-invocation budget.
    BudgetExceeded = 1,
    /// Observer attempted to call a host-fn for which the active
    /// per-invocation capability set lacks the matching token.
    CapabilityDenied = 2,
    /// Catch-all for cranelift trap variants not classified above
    /// (incl. operator host-config errors like "no capability impl
    /// registered" — distinguished only at audit-log granularity).
    Other = 3,
}

/// Progress scope selector for multi-region / multi-KMS erasure progress
/// (spec §3.2).
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProgressScope {
    /// Region scope — geographic / cloud region identifier.
    Region(BoundedString<64>),
    /// KMS identifier scope.
    KmsIdentifier(BoundedString<64>),
}

// ===================== Core Events =====================

/// `RuntimeBootstrap` — chain-anchored bootstrap receipt (spec §14.7 E12).
///
/// Emitted at instance first-tick, manifest change, and runtime semver bump.
/// The `manifest_digest` + `typecode_pins` pair is how WAL replay validates
/// that the runtime environment matches what produced the log.
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
/// will complete the crypto-shred (spec §14.9).
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
/// (spec §14.9.1 FG3, chain-anchored transparency).
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
    /// Transparency-log entry index (spec §14.11.3).
    pub transparency_log_index: u64,
}

/// `BackupErasurePropagated` — per-region offsite tombstone evidence
/// (spec §14.11.1). Restore must refuse if any region is missing.
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
/// targeted an ErasurePending User (spec §3.3 L1 compute MC gate).
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

/// `SignatureClassPolicy` — chain-anchored shell audit signature policy
/// (spec §14.7 FG5 / E13). Downgrade-resistant by construction.
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
/// (spec §4.5 / §13.2, E-act-2 dual-tier RA side).
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
/// record (spec §14.9.1 §§13 GF4 two-phase-commit).
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
/// (spec §14.7 M-R6-4 Option 2). Emitted when `runtime-doctor
/// pqc-reseal` or similar rotation completes for a user.
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
/// (spec §14.11.2 / §14.9.1 §§12).
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

/// `HookModuleRegister` — chain-anchored Hook host v2 module-registration
/// receipt (spec §14.5 / E14.L2). Track B.6 (DIP-N1 v0.12 sealing cycle).
///
/// Emitted by the wasmtime hook host on every successful
/// `register_module(bytes, expected_digest)`. Pairs the operator's
/// manifest digest (which pins the expected module digest) with the
/// actually-registered module digest — replay validates the host
/// instantiated the module the manifest demanded, not a substitute.
///
/// **3-tier ingestion** anchored here:
///
/// - **Tier 1 (BLAKE3 digest pin)** — `module_digest` matches the value
///   the operator pinned in `manifest_digest`-anchored manifest TOML.
///   Catches operator config typos + accidental file substitution. v0.12
///   first cut implements this tier fully.
/// - **Tier 2 (sigstore sign-before-load)** — recorded via
///   `attestation_class` field but actual verification deferred to
///   v0.13+ (sigstore client integration). Tier 1 alone is sufficient
///   for v0.12 sealing-cut: operator config is the trust root.
/// - **Tier 3 (cargo-vet provenance)** — build-time check; runtime only
///   records the attestation hash for chain-anchored audit. Future work.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0B, schema_version = 1)]
pub struct HookModuleRegister {
    /// Wire schema version.
    pub schema_version: u16,
    /// BLAKE3 digest of the manifest TOML that pinned the expected
    /// module digest. Replay uses this to verify the manifest itself
    /// was unchanged between registration time and replay time.
    ///
    /// **Caller responsibility** (cryptographer C13): this field is
    /// host-side recorded but NOT host-side enforced. The integration
    /// layer (`arkhe-forge-platform/src/manifest.rs` at B.7+) is
    /// responsible for hashing the operator's manifest TOML and
    /// passing the result through to the event emission. v0.12
    /// scaffold; the manifest-signature verification closure that
    /// makes this field cryptographically meaningful lands at B.7+
    /// alongside `arkhe-forge-platform/src/manifest.rs` integration.
    pub manifest_digest: [u8; 32],
    /// BLAKE3 digest of the registered wasm module bytes. Equals the
    /// `expected_digest` parameter the operator passed; recorded so
    /// replay can re-verify the module bytes against the same hash.
    pub module_digest: [u8; 32],
    /// Tick at which the module was registered.
    pub register_tick: Tick,
    /// Attestation class signalling Tier 2/3 presence for future
    /// migration. v0.12 first cut: always [`RuntimeSignatureClass::None`]
    /// (Tier 1 BLAKE3 digest pin only — see Track B.6). Tier 2 sigstore
    /// integration in v0.13+ wires this to `Ed25519` / `MlDsa65` /
    /// `HybridEd25519MlDsa65`.
    ///
    /// **Semantics distinction** (cryptographer C14): in this
    /// `HookModuleRegister` context `None` means
    /// "Tier 1 BLAKE3 digest pin only; no Tier 2/3 attestation
    /// present". Distinct from §14.7's audit-receipt `None`
    /// (= "no signature class") which carries different operational
    /// semantics. Same enum, context-specific reading.
    pub attestation_class: RuntimeSignatureClass,
}

/// `ObserverQuarantine` — chain-anchored Observer host v2 trap-
/// quarantine receipt (spec §14.X.Y / E15). Track A.2.4 (DIP-N2 v0.12
/// sealing cycle).
///
/// Emitted by the runtime supervisor when an observer wasm execution
/// trips a sandbox-boundary failure (panic / budget / capability
/// denial / other trap). The receipt anchors the operator's audit
/// trail without observer wasm authorship — cryptographer-pinned
/// chain-non-affecting clause 3: the *host* supervises emission.
///
/// **Trigger boundary** (cryptographer A.2.4 anchor): only `ObserverError`
/// variants from the host trip Quarantine emission. `CapabilityExecutionError`
/// (PG unreachable etc.) is **operational, NOT chain-anchored** — those
/// surface via metric / `runtime_doctor_journal` instead (v0.13+ DIP).
///
/// **Replay-side verification**: replay re-checks the `observer_module_digest`
/// against the bytes the manifest pinned at registration time
/// (mirrors `HookModuleRegister`'s replay verification). Mismatch
/// indicates manifest tampering or operator mis-deployment.
///
/// **3-tier ingestion mirror**: `attestation_class` records the observer
/// module's ingestion attestation tier (Tier 1 BLAKE3 digest pin
/// active in v0.12; Tier 2 sigstore + Tier 3 cargo-vet scaffolded
/// for v0.13+). Per-Quarantine the `attestation_class` reflects the
/// state at registration time so audit logs distinguish "trapped
/// after Tier-1-only ingestion" from future Tier-2/3 paths.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0C, schema_version = 1)]
pub struct ObserverQuarantine {
    /// Wire schema version.
    pub schema_version: u16,
    /// BLAKE3 digest of the registered observer module bytes that
    /// trapped. Equals the `expected_digest` the operator pinned at
    /// registration; recorded so replay can re-verify the module
    /// bytes against the same hash.
    pub observer_module_digest: [u8; 32],
    /// Tick at which the trap occurred + Quarantine was emitted by
    /// the host supervisor.
    pub quarantine_tick: Tick,
    /// Trap classification — distinguishes panic / budget / cap-
    /// deny / other for forensic + operator triage.
    pub trap_class: ObserverTrapClass,
    /// Attestation class signalling the Tier 2/3 ingestion state at
    /// registration time. v0.12 first cut: typically
    /// [`RuntimeSignatureClass::None`] (Tier 1 BLAKE3 digest pin
    /// only). Future Tier 2/3 paths set Ed25519 / MlDsa65 / Hybrid.
    ///
    /// **Semantics distinction** (cryptographer A.2.4 anchor): in
    /// this `ObserverQuarantine` context the value records the
    /// *observer module ingestion* attestation tier — NOT the event-
    /// signing class. The Quarantine event itself is chain-anchored
    /// under the runtime's standard signing path (E13 shell-per-tick
    /// `SignatureClassPolicy`), independent of this field.
    pub attestation_class: RuntimeSignatureClass,
}

// ============================================================================
// Track H.1 cryptographic primitives (DIP-N4 N4.3) — Attestation newtype +
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
/// `WalRecord.signature` workaround is to use `Vec<u8>` and validate
/// length at the application layer (cryptographer F.2 noted this is
/// where the H.1 commit landed). `Attestation` lifts the length
/// invariant from convention to the type itself: any value of type
/// `Attestation` that exists has 64 bytes, and the Deserialize impl
/// is the exhaustive admission check.
///
/// **DIP-N4 N4.3** absorption: cryptographer F.2 carry-forward
/// (signer policy + length verification) and auditor H.1 carry-
/// forward (emission length verification deferred to `Vec<u8>`)
/// converge here. Used by `ReplicaIdAllocation::registry_attestation`
/// and `AuditReceiptKeyPolicy::attestation`.
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
    /// plus bytes). Wire format identical to a bare `Vec<u8>` of
    /// length 64, so the Track H.1 wire baseline is preserved byte-
    /// for-byte.
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
/// Each `AuditReceiptKeyPolicy` entry's attestation signature
/// binds the inventory entry to *some* signing authority — but
/// "which authority" is an operator-policy choice the runtime
/// merely records. v0.12 reserves three variants covering the
/// expected operator topologies; future operator-policy expansions
/// land via `#[non_exhaustive]` additive variants without breaking
/// existing wire bytes.
///
/// The variant is paired with `AuditReceiptKeyPolicy::attestation`
/// at the same struct level — at v0.12, no other event references
/// this enum, so cohesion is preferred over abstraction. If a
/// post-v0.13 second user emerges, the enum can be lifted to a
/// shared type with no wire-format change (additive non-breaking
/// refactor).
///
/// **`Copy` derive — forward-compat constraint** (cryptographer N4.3
/// cross-review note): the `Copy` derive constrains future variants
/// to be field-less. A future variant carrying data (e.g.,
/// `HardwareAttestation { tpm_version: u32 }` or threshold-signature
/// parameters) would require the `Copy` derive to be removed —
/// which is a breaking API change. Field-less policy reservation is
/// the v0.12 design contract; data-bearing variants are deferred to
/// v0.13+ DIP scope and will arrive alongside the `Copy` removal as
/// a coordinated breaking change.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttestationSignerPolicy {
    /// Successor key signed by predecessor key — rotation chain
    /// integrity. The recipient verifies the attestation against
    /// the predecessor entry's `public_key`.
    Predecessor,
    /// Direct signature by an operator-root authority (HW-signed
    /// or air-gapped key per `release-keys.md §3` co-custody).
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
/// (spec §14.7 / §15.5). Track H.1 (DIP-N3 v0.12 sealing cycle,
/// **define-only**); Track H.2 (DIP-N3) wraps the type behind the
/// `federation-archive-hardened` Cargo feature so default builds do
/// not compile the type at all (3-layer 0-emission defense layer (b)).
///
/// Future emission: when a federation registry signs off on a new
/// replica entering the federation, the runtime emits one
/// `ReplicaIdAllocation` event into the chain so subsequent
/// cross-replica audit can trace the membership lineage. v0.12 cut
/// reserves only the wire surface (TypeCode + schema). Activation
/// gate: federation prerequisites complete (archive-hardening +
/// `SignedArkheUri` + identity federation layer per §15.5).
///
/// **0-emission posture (cryptographer + auditor F.1 carry-forward
/// ack)**: no production code path calls
/// `emit_event::<ReplicaIdAllocation>(..)` at v0.12. Track H.3 grep
/// verification confirms zero emission sites; Track H.2 adds Cargo
/// feature gating for compile-time exclusion.
#[cfg(feature = "federation-archive-hardened")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0D, schema_version = 1)]
pub struct ReplicaIdAllocation {
    /// Wire schema version.
    pub schema_version: u16,
    /// Federation identifier (128-bit). `[16]` is collision-resistant
    /// for any plausible federation count; v0.13+ may extend if a
    /// stronger uniqueness anchor is required.
    pub federation_id: [u8; 16],
    /// Replica identifier within the federation. v0.12 fixes the
    /// width at u64 (federation-scale collision-resistant — DIP-N4
    /// N4.1 widened from u32 per cryptographer F.2 federation-scale
    /// concern; ~10^19 replicas/federation, well beyond any plausible
    /// ultra-scale federation deployment). The earlier u32 design
    /// would have capped at ~4B replicas, an order-of-magnitude tight
    /// bound on the long tail of federated systems; widening pre-
    /// emission avoids any post-cut migration debt.
    pub replica_id: u64,
    /// 32-bit nonce drawn at allocation time, fed into the
    /// registry attestation signature alongside the (federation,
    /// replica, tick) tuple. Defends against replay of older
    /// allocation requests.
    pub allocation_nonce: u32,
    /// Tick at which the allocation became effective (chain-anchor
    /// for ordering relative to other federation events).
    pub effective_tick: Tick,
    /// Federation-registry attestation over (federation_id,
    /// replica_id, allocation_nonce, effective_tick). 64-byte
    /// signature (Ed25519 width) wrapped in [`Attestation`] —
    /// length-sealed at construction (`from_bytes([u8; 64])`) and
    /// strictly verified on deserialize (DIP-N4 N4.3 absorbed
    /// cryptographer F.2 + auditor H.1 carry-forwards: invariant
    /// lifted from convention to type). The signer is the federation
    /// registry; signer-policy enum reservation lives on
    /// `AuditReceiptKeyPolicy::signer_policy` (audit-receipt key
    /// rotation context where signer choice is operator-variable).
    pub registry_attestation: Attestation,
}

/// `AuditReceiptKeyPolicy` — audit-receipt key inventory + rotation
/// manifest (spec §14.7 NR6-4 / E13). Track H.1 (DIP-N3 v0.12
/// sealing cycle, **define-only**); Track H.2 wraps the type behind
/// the `audit-receipt-key-identified` Cargo feature so default builds
/// do not compile the type (3-layer 0-emission defense layer (b)).
///
/// Future emission: when the operator rotates the audit-receipt
/// signing key (or initially declares the genesis key in the
/// `release-keys.md §1` inventory), the runtime emits one
/// `AuditReceiptKeyPolicy` event into the chain so subsequent
/// audit-trail consumers can verify which key was active at which
/// tick. v0.12 cut reserves only the wire surface. Activation gate:
/// operator-side carry-over (g) "audit-receipt key identity declared
/// in `release-keys.md §1` inventory" (cryptographer Track H gate).
///
/// **0-emission posture**: identical to `ReplicaIdAllocation` —
/// production code path emits zero, Track H.3 verifies, Track H.2
/// gates the compile.
#[cfg(feature = "audit-receipt-key-identified")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F0E, schema_version = 1)]
pub struct AuditReceiptKeyPolicy {
    /// Wire schema version.
    pub schema_version: u16,
    /// Audit-receipt key identifier. v0.12 fixes the width at
    /// `[u8; 16]` (128-bit, UUID-class collision space — DIP-N4 N4.2
    /// widened from `[u8; 8]` per cryptographer F.2 collision-
    /// resistance concern). The earlier 8-byte width gave a 2^32
    /// birthday bound, tight at federation scale where multiple
    /// operators independently mint keys; 16-byte raises the bound
    /// to 2^64 = computationally infeasible across any plausible
    /// key population. The `release-keys.md §1` inventory entry
    /// maps this identifier to the physical key material.
    pub key_id: [u8; 16],
    /// Signature class for receipts under this key. Reuses the
    /// `RuntimeSignatureClass` enum (spec §14.7 NR6-4) so the wire
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
    /// Width matches `key_id` ([u8; 16] post-DIP-N4 N4.2).
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
    /// predecessor key (rotation chain), an operator-root
    /// authority, or as a genesis self-signed proof-of-possession.
    /// DIP-N4 N4.3 absorbed cryptographer F.2 carry-forward #3
    /// (v0.13+ signer-policy decision queued at H.1) by reserving
    /// the enum + field at v0.12; future emission DIP populates
    /// the value per operator policy without further schema work.
    /// `#[non_exhaustive]` keeps additive variants forward-compat.
    pub signer_policy: AttestationSignerPolicy,
    /// Attestation signature binding the inventory entry to the
    /// operator's signing authority. 64-byte signature (Ed25519
    /// width) wrapped in [`Attestation`] — length-sealed at
    /// construction and strictly verified on deserialize (DIP-N4
    /// N4.3 absorbed auditor H.1 carry-forward: emission length
    /// verification lifted from convention to type). Recipient
    /// verification path is selected by [`Self::signer_policy`].
    pub attestation: Attestation,
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
        assert_eq!(HookModuleRegister::TYPE_CODE, 0x0003_0F0B);
        assert_eq!(ObserverQuarantine::TYPE_CODE, 0x0003_0F0C);
        // Track H.2 — forward-looking event TypeCode pins are verified
        // only when the activation feature is enabled (cfg-gate per
        // 3-layer 0-emission defense layer (b)). The TypeCode constants
        // in `typecode::core_event` remain unconditional anchors.
        #[cfg(feature = "federation-archive-hardened")]
        assert_eq!(ReplicaIdAllocation::TYPE_CODE, 0x0003_0F0D);
        #[cfg(feature = "audit-receipt-key-identified")]
        assert_eq!(AuditReceiptKeyPolicy::TYPE_CODE, 0x0003_0F0E);
    }

    #[test]
    fn hook_module_register_serde_roundtrip() {
        let ev = HookModuleRegister {
            schema_version: 1,
            manifest_digest: [0xAAu8; 32],
            module_digest: [0xBBu8; 32],
            register_tick: Tick(123),
            attestation_class: RuntimeSignatureClass::None,
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: HookModuleRegister = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn hook_module_register_type_code_matches_typecode_constant() {
        // The typecode.rs core_event::HOOK_MODULE_REGISTER constant and
        // the #[arkhe(type_code = ...)] derive must agree — guards against
        // accidental drift between the catalog and the struct attribute.
        assert_eq!(
            HookModuleRegister::TYPE_CODE,
            crate::typecode::core_event::HOOK_MODULE_REGISTER
        );
    }

    #[test]
    fn observer_quarantine_serde_roundtrip() {
        let ev = ObserverQuarantine {
            schema_version: 1,
            observer_module_digest: [0xCCu8; 32],
            quarantine_tick: Tick(456),
            trap_class: ObserverTrapClass::Panic,
            attestation_class: RuntimeSignatureClass::None,
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: ObserverQuarantine = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn observer_quarantine_type_code_matches_typecode_constant() {
        assert_eq!(
            ObserverQuarantine::TYPE_CODE,
            crate::typecode::core_event::OBSERVER_QUARANTINE
        );
    }

    #[test]
    fn observer_trap_class_wire_discriminants_stable() {
        // Verify each variant's wire-stable discriminant — `#[repr(u8)]`
        // pins these so the postcard format stays bit-identical across
        // schema-version bumps. Drift here = wire breakage.
        for (variant, expected_disc) in [
            (ObserverTrapClass::Panic, 0u8),
            (ObserverTrapClass::BudgetExceeded, 1u8),
            (ObserverTrapClass::CapabilityDenied, 2u8),
            (ObserverTrapClass::Other, 3u8),
        ] {
            // Round-trip through postcard verifies the wire byte
            // matches the declared discriminant. (postcard encodes
            // unit-variant enums as a single varint of the
            // discriminant.)
            let bytes = postcard::to_stdvec(&variant).unwrap();
            assert_eq!(
                bytes,
                vec![expected_disc],
                "ObserverTrapClass::{variant:?} discriminant drift"
            );
        }
    }

    #[test]
    fn observer_quarantine_with_each_trap_class_roundtrips() {
        for trap_class in [
            ObserverTrapClass::Panic,
            ObserverTrapClass::BudgetExceeded,
            ObserverTrapClass::CapabilityDenied,
            ObserverTrapClass::Other,
        ] {
            let ev = ObserverQuarantine {
                schema_version: 1,
                observer_module_digest: [0u8; 32],
                quarantine_tick: Tick(1),
                trap_class,
                attestation_class: RuntimeSignatureClass::None,
            };
            let bytes = postcard::to_stdvec(&ev).unwrap();
            let back: ObserverQuarantine = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(ev.trap_class, back.trap_class);
        }
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

    // ----- Track H.1 (DIP-N3) — forward-looking event tests -----
    //
    // Each test is feature-gated to its activation flag (Track H.2
    // 3-layer 0-emission defense layer (b)). default-features build
    // skips these tests because the underlying type is not compiled.

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

    /// DIP-N4 N4.1 — verify u64 width preserved for replica_id values
    /// above `u32::MAX`. Regression sentinel against any future schema
    /// width change that would silently truncate the high 32 bits
    /// (cryptographer F.2 federation-scale concern). Pin chosen to
    /// span the upper half of u64 so byte-level postcard varint
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
            schema_version: 1,
            key_id: [0xABu8; 16],
            algorithm: RuntimeSignatureClass::Ed25519,
            public_key: Bytes::from_static(&[0u8; 32]),
            predecessor_key_id: None,
            effective_tick: Tick(0),
            retirement_tick: None,
            signer_policy: AttestationSignerPolicy::SelfSigned,
            attestation: Attestation::from_bytes([0x77u8; 64]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: AuditReceiptKeyPolicy = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_serde_roundtrip_with_rotation_entry() {
        let ev = AuditReceiptKeyPolicy {
            schema_version: 1,
            key_id: [0xCDu8; 16],
            algorithm: RuntimeSignatureClass::MlDsa65,
            public_key: Bytes::from_static(&[0xEEu8; 1952]), // ML-DSA-65 wire size
            predecessor_key_id: Some([0xABu8; 16]),
            effective_tick: Tick(100),
            retirement_tick: Some(Tick(1000)),
            signer_policy: AttestationSignerPolicy::Predecessor,
            attestation: Attestation::from_bytes([0x99u8; 64]),
        };
        let bytes = postcard::to_stdvec(&ev).unwrap();
        let back: AuditReceiptKeyPolicy = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    /// DIP-N4 N4.2 — verify [u8; 16] width preserved with high-
    /// entropy distinct bytes in both `key_id` and `predecessor_key_id`.
    /// Earlier `[0xABu8; 16]` / `[0xCDu8; 16]` literals use repeated
    /// bytes, which would silently round-trip through any narrower
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
            schema_version: 1,
            key_id,
            algorithm: RuntimeSignatureClass::Ed25519,
            public_key: Bytes::from_static(&[0xC3u8; 32]),
            predecessor_key_id: Some(predecessor_key_id),
            effective_tick: Tick(2_500),
            retirement_tick: Some(Tick(5_000)),
            signer_policy: AttestationSignerPolicy::OperatorRoot,
            attestation: Attestation::from_bytes([0x44u8; 64]),
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

    #[cfg(feature = "audit-receipt-key-identified")]
    #[test]
    fn audit_receipt_key_policy_type_code_matches_typecode_constant() {
        assert_eq!(
            AuditReceiptKeyPolicy::TYPE_CODE,
            crate::typecode::core_event::AUDIT_RECEIPT_KEY_POLICY
        );
    }

    /// 0-emission posture confirmation (layer (a) — `emit()` not
    /// defined). The `ArkheEvent` trait makes the type *eligible*
    /// for chain emission via `Op::EmitEvent`, but Track H.1 commits
    /// **no production code** that calls
    /// `emit_event::<ReplicaIdAllocation>(..)` or
    /// `emit_event::<AuditReceiptKeyPolicy>(..)`. Track H.3 grep
    /// verification scans the workspace and asserts 0 occurrences.
    /// At H.1 this test is a structural anchor — type definitions
    /// exist, but the trait constants alone do not constitute
    /// emission.
    ///
    /// Track H.2: feature-gated under both activation flags so the
    /// test compiles only when the types compile (cfg-gate layer (b)).
    #[cfg(all(
        feature = "federation-archive-hardened",
        feature = "audit-receipt-key-identified"
    ))]
    #[test]
    fn forward_looking_events_are_define_only_at_v0_12() {
        // The TYPE_CODE constants exist + are pinned. Schema version
        // is 1 (initial wire format). No emission entry point is
        // defined for either type — verified structurally by Track
        // H.3 grep. This test is the architecture anchor.
        assert_eq!(ReplicaIdAllocation::SCHEMA_VERSION, 1);
        assert_eq!(AuditReceiptKeyPolicy::SCHEMA_VERSION, 1);
        assert_eq!(ReplicaIdAllocation::TYPE_CODE, 0x0003_0F0D);
        assert_eq!(AuditReceiptKeyPolicy::TYPE_CODE, 0x0003_0F0E);
    }

    // ----- DIP-N4 N4.3 — Attestation newtype + AttestationSignerPolicy
    // tests. These are unconditional (no cfg-gate) because the types
    // themselves live unconditionally in the module — only the events
    // that *consume* them are cfg-gated under the activation flags.

    /// DIP-N4 N4.3 — `Attestation` round-trips through postcard byte-
    /// identical to a bare `Vec<u8>` of length 64 (Track H.1 wire
    /// baseline preservation).
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

    /// DIP-N4 N4.3 — wire format invariance with bare `Vec<u8>` of
    /// length 64. The custom `Serialize` impl delegates to
    /// `Vec<u8>::serialize`, so an `Attestation` and an equivalent
    /// `vec![0x..; 64]` produce byte-for-byte identical postcard
    /// output. This preserves the H.1 sealed wire baseline — any
    /// previously emitted bytes (none yet, but the contract holds for
    /// when emission lands) decode equivalently with the new type.
    #[test]
    fn attestation_wire_format_byte_identical_to_vec_u8_length_64() {
        let payload: [u8; 64] = [0xC7; 64];
        let att_bytes = postcard::to_stdvec(&Attestation::from_bytes(payload)).unwrap();
        let vec_bytes = postcard::to_stdvec(&payload.to_vec()).unwrap();
        assert_eq!(att_bytes, vec_bytes);
    }

    /// DIP-N4 N4.3 — `Attestation` deserialize **rejects** payloads
    /// whose length is not exactly 64 with a `serde::de::Error`,
    /// never a panic. This is the single admission check that lifts
    /// the 64-byte invariant from convention to type.
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

    /// DIP-N4 N4.3 — all three [`AttestationSignerPolicy`] variants
    /// round-trip through postcard. The variant tag is a postcard
    /// varint; a future additive variant (post-v0.13 operator-policy
    /// expansion) lands as a new tag without disturbing existing
    /// tags (`#[non_exhaustive]` on the enum + variant order
    /// preservation).
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
