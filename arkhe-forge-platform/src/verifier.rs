//! Audit-receipt attestation verifier — L2 erasure-receipt signature check.
//!
//! Verifies the signatures carried by L2 audit receipts under a
//! policy-pinned [`RuntimeSignatureClass`]. Mirrors the L0 kernel's
//! WAL-record signature pattern (domain separation, canonical decode,
//! Hybrid AND-mode) but is a self-contained L2 surface: the kernel's
//! `PqcSigner`/`PqcVerifier` are sealed + `pub(crate)` + WAL-only, so this
//! module takes a direct `ml-dsa` dependency (gated on `tier-2-pqc-receipts`).
//!
//! # Feature layering
//!
//! The module is exported unconditionally (`pub mod verifier;`), so the
//! dispatcher, [`VerifyError`], the domain helper, the Ed25519 arm, and
//! [`dek_shred_message`] compile in the DEFAULT build. The ML-DSA-using
//! code (`verify_ml_dsa65`'s real body, [`ReceiptSigner`]) is gated on
//! `tier-2-pqc-receipts`; the default build links a stub
//! `verify_ml_dsa65` that returns [`VerifyError::PqcUnavailable`].

use arkhe_forge_core::event::RuntimeSignatureClass;
use ed25519_dalek::{Signature, VerifyingKey};

#[cfg(feature = "tier-2-pqc-receipts")]
use ml_dsa::signature::{Keypair, Signer};
#[cfg(feature = "tier-2-pqc-receipts")]
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, B32};
#[cfg(feature = "tier-2-pqc-receipts")]
use zeroize::Zeroize;

/// Ed25519 public-key width (RFC 8032).
const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature width (RFC 8032).
const ED25519_SIG_LEN: usize = 64;
/// ML-DSA-65 verifying-key width (NIST FIPS 204 §4).
const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature width (NIST FIPS 204 §4).
const MLDSA65_SIG_LEN: usize = 3309;

/// Domain-separation prefix bound into every L2 audit-receipt signature.
///
/// Distinct from the kernel WAL-record domain
/// (`arkhe-kernel v0.14 WAL record signature domain`) — signing
/// `FORGE_RECEIPT_SIG_DOMAIN || message` scopes a signature to the
/// audit-receipt domain so the same key reused in the WAL protocol (or
/// any other) cannot yield a cross-valid signature (prevents
/// cross-protocol key reuse). Applied symmetrically on sign and verify.
pub(crate) const FORGE_RECEIPT_SIG_DOMAIN: &[u8] =
    b"arkhe-forge v0.14 audit receipt attestation domain";

/// Prefix `message` with the audit-receipt domain tag (`TAG ++ message`).
///
/// Single source of truth — both the signer ([`ReceiptSigner`]) and the
/// verifier ([`verify_attestation`]) route every message through this
/// helper, so the domain binding is symmetric by construction.
pub(crate) fn domain_separated(message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(FORGE_RECEIPT_SIG_DOMAIN.len() + message.len());
    m.extend_from_slice(FORGE_RECEIPT_SIG_DOMAIN);
    m.extend_from_slice(message);
    m
}

/// Failure modes for [`verify_attestation`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The policy-pinned class was [`RuntimeSignatureClass::None`] — a
    /// receipt that carries no signature cannot satisfy a class that
    /// requires one.
    #[error("a signature is required but the policy class is None")]
    SignatureRequired,
    /// The supplied public key was not the expected width for the class.
    #[error("public key has the wrong length for the signature class")]
    WrongKeyLength,
    /// The supplied signature was not the expected width for the class.
    #[error("signature has the wrong length for the signature class")]
    WrongSignatureLength,
    /// The signature did not validate against the message under the key.
    #[error("signature did not validate")]
    Mismatch,
    /// An ML-DSA-65 verify was requested but the `tier-2-pqc-receipts`
    /// feature is not compiled in.
    #[error("PQC verification unavailable; build with feature tier-2-pqc-receipts")]
    PqcUnavailable,
    /// The receipt envelope is internally inconsistent — e.g. an
    /// `MlDsa65`/`Hybrid` algorithm with no PQC signature material.
    #[error("receipt envelope is internally incoherent")]
    EnvelopeIncoherent,
}

/// Verify an audit-receipt attestation under a **policy-pinned** class.
///
/// # Security contract — `class` is policy-pinned, never wire-sourced
///
/// `class` is the REQUIRED signature class taken out-of-band from the
/// trusted policy: the manifest `audit.signature_class` (the E13 axiom)
/// or the audit-receipt key-policy `algorithm` field. It MUST NOT be
/// read from the attacker-controlled receipt envelope field. A caller
/// that pinned `class` from the wire would turn this function into a
/// downgrade oracle: an attacker could present a receipt claiming
/// `Hybrid` while passing `class = Ed25519`, skipping the ML-DSA half
/// entirely and defeating the post-quantum guarantee. The policy class
/// is the only safe source.
///
/// The message is domain-separated exactly once and the SAME bytes are
/// passed to every arm — for `Hybrid` this guarantees both halves bind
/// the identical message (AND-mode soundness).
///
/// # Errors
///
/// Returns [`VerifyError`] when the key/signature widths are wrong, the
/// signature does not validate, the policy class is `None`, or (for an
/// ML-DSA arm) the `tier-2-pqc-receipts` feature is absent.
pub fn verify_attestation(
    class: RuntimeSignatureClass,
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), VerifyError> {
    // Domain-separate once; reuse the same bytes across every arm so the
    // Hybrid halves bind an identical message (AND-mode soundness).
    let m = domain_separated(message);
    match class {
        RuntimeSignatureClass::None => Err(VerifyError::SignatureRequired),
        RuntimeSignatureClass::Ed25519 => verify_ed25519(public_key, &m, sig),
        RuntimeSignatureClass::MlDsa65 => verify_ml_dsa65(public_key, &m, sig),
        RuntimeSignatureClass::Hybrid => {
            // Split key into ed25519(32) ++ mldsa(1952) and signature into
            // ed25519(64) ++ mldsa(3309) with EXPLICIT length checks. We do
            // not use `split_at_checked` — it sits at the 1.80 MSRV
            // knife-edge; an explicit length guard + slicing is portable.
            if public_key.len() != ED25519_PK_LEN + MLDSA65_PK_LEN {
                return Err(VerifyError::WrongKeyLength);
            }
            if sig.len() != ED25519_SIG_LEN + MLDSA65_SIG_LEN {
                return Err(VerifyError::WrongSignatureLength);
            }
            let (ed_pk, mldsa_pk) = public_key.split_at(ED25519_PK_LEN);
            let (ed_sig, mldsa_sig) = sig.split_at(ED25519_SIG_LEN);
            // AND-mode: both must pass. Verify Ed25519 first (cheap), then
            // ML-DSA-65 — short-circuit on the first failure.
            verify_ed25519(ed_pk, &m, ed_sig)?;
            verify_ml_dsa65(mldsa_pk, &m, mldsa_sig)
        }
        // `RuntimeSignatureClass` is `#[non_exhaustive]`; a future variant
        // has no defined verify semantics here and is rejected.
        _ => Err(VerifyError::Mismatch),
    }
}

/// Verify an audit-receipt attestation envelope.
///
/// `algorithm` is the POLICY-PINNED class (the manifest
/// `audit.signature_class` / the audit-receipt key-policy `algorithm`
/// field), never the wire field — see [`verify_attestation`] for why a
/// wire-sourced class is a downgrade oracle.
///
/// This is the wire-shape entry point: the envelope splits its
/// signature material into the 64-byte classical half (`attestation_64`,
/// the key-policy `attestation` bytes) and an optional PQC half
/// (`attestation_pqc`, the key-policy `attestation_pqc` slot). It first
/// enforces algorithm<->slot COHERENCE — the PQC slot must be present
/// iff the class is PQC-bearing (`MlDsa65`/`Hybrid`) — then assembles
/// the canonical signature bytes and dispatches to
/// [`verify_attestation`].
///
/// # Errors
///
/// - [`VerifyError::EnvelopeIncoherent`] — the PQC slot presence does
///   not match the policy class.
/// - [`VerifyError::SignatureRequired`] — the class is `None`.
/// - any error from [`verify_attestation`] for the dispatched arm.
pub fn verify_receipt_envelope(
    algorithm: RuntimeSignatureClass,
    public_key: &[u8],
    message: &[u8],
    attestation_64: &[u8],
    attestation_pqc: Option<&[u8]>,
) -> Result<(), VerifyError> {
    // Coherence: the PQC slot must be populated iff the policy class
    // carries a post-quantum half. A mismatch is an incoherent envelope
    // (e.g. an MlDsa65 receipt with no PQC bytes, or an Ed25519 receipt
    // smuggling PQC bytes), rejected before any verify.
    let pqc_required = matches!(
        algorithm,
        RuntimeSignatureClass::MlDsa65 | RuntimeSignatureClass::Hybrid
    );
    if attestation_pqc.is_some() != pqc_required {
        return Err(VerifyError::EnvelopeIncoherent);
    }
    match algorithm {
        RuntimeSignatureClass::None => Err(VerifyError::SignatureRequired),
        RuntimeSignatureClass::Ed25519 => verify_attestation(
            RuntimeSignatureClass::Ed25519,
            public_key,
            message,
            attestation_64,
        ),
        RuntimeSignatureClass::MlDsa65 => {
            // pqc_required holds => the slot is Some; bind it without
            // unwrap so a future refactor can never panic here.
            match attestation_pqc {
                Some(pqc) => {
                    verify_attestation(RuntimeSignatureClass::MlDsa65, public_key, message, pqc)
                }
                None => Err(VerifyError::EnvelopeIncoherent),
            }
        }
        RuntimeSignatureClass::Hybrid => match attestation_pqc {
            Some(pqc) => {
                // Reassemble the canonical Hybrid signature:
                // ed25519(64) ++ mldsa(3309). verify_attestation applies
                // the explicit length checks.
                let mut sig = Vec::with_capacity(attestation_64.len() + pqc.len());
                sig.extend_from_slice(attestation_64);
                sig.extend_from_slice(pqc);
                verify_attestation(RuntimeSignatureClass::Hybrid, public_key, message, &sig)
            }
            None => Err(VerifyError::EnvelopeIncoherent),
        },
        // Future `#[non_exhaustive]` variant: no defined envelope shape.
        _ => Err(VerifyError::Mismatch),
    }
}

/// Verify an Ed25519 signature over `m` under `vk_bytes`.
///
/// `verify_strict` rejects non-canonical / small-order signatures (RFC
/// 8032 §5.1 strict path), closing Ed25519 signature malleability.
fn verify_ed25519(vk_bytes: &[u8], m: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    if vk_bytes.len() != ED25519_PK_LEN {
        return Err(VerifyError::WrongKeyLength);
    }
    if sig.len() != ED25519_SIG_LEN {
        return Err(VerifyError::WrongSignatureLength);
    }
    let mut pk = [0u8; ED25519_PK_LEN];
    pk.copy_from_slice(vk_bytes);
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::Mismatch)?;
    let mut sb = [0u8; ED25519_SIG_LEN];
    sb.copy_from_slice(sig);
    let sig_obj = Signature::from_bytes(&sb);
    vk.verify_strict(m, &sig_obj)
        .map_err(|_| VerifyError::Mismatch)
}

/// Verify an ML-DSA-65 signature over `m` under `vk_bytes` (real path).
///
/// Canonical decode: `Signature::decode` returns `Option`, so a
/// non-canonical signature is rejected. ML-DSA-65 verification is
/// EUF-CMA secure (NIST FIPS 204); this path does not claim SUF-CMA.
#[cfg(feature = "tier-2-pqc-receipts")]
fn verify_ml_dsa65(vk_bytes: &[u8], m: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    use ml_dsa::signature::Verifier as _;

    if sig.len() != MLDSA65_SIG_LEN {
        return Err(VerifyError::WrongSignatureLength);
    }
    if vk_bytes.len() != MLDSA65_PK_LEN {
        return Err(VerifyError::WrongKeyLength);
    }
    let mut sb = EncodedSignature::<MlDsa65>::default();
    sb.as_mut_slice().copy_from_slice(sig);
    let sig_obj = ml_dsa::Signature::<MlDsa65>::decode(&sb).ok_or(VerifyError::Mismatch)?;
    let mut kb = EncodedVerifyingKey::<MlDsa65>::default();
    kb.as_mut_slice().copy_from_slice(vk_bytes);
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&kb);
    vk.verify(m, &sig_obj).map_err(|_| VerifyError::Mismatch)
}

/// Verify an ML-DSA-65 signature (stub — `tier-2-pqc-receipts` absent).
///
/// The default build cannot perform a real ML-DSA verify, so every
/// ML-DSA arm reports [`VerifyError::PqcUnavailable`] rather than
/// silently passing.
#[cfg(not(feature = "tier-2-pqc-receipts"))]
fn verify_ml_dsa65(_vk_bytes: &[u8], _m: &[u8], _sig: &[u8]) -> Result<(), VerifyError> {
    Err(VerifyError::PqcUnavailable)
}

/// Canonical message bytes for a DEK-erasure attestation.
///
/// Frozen layout: `dek_id.0 (16) ++ log_index.to_be_bytes() (8)` = 24
/// bytes. This is the bare message; [`verify_attestation`] /
/// [`ReceiptSigner::sign`] apply the domain prefix. The layout is pinned
/// by a test so any reordering / width change is caught.
#[must_use]
pub fn dek_shred_message(dek_id: &arkhe_forge_core::pii::DekId, log_index: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + 8);
    m.extend_from_slice(&dek_id.0);
    m.extend_from_slice(&log_index.to_be_bytes());
    m
}

/// Software ML-DSA-65 receipt signer (NIST FIPS 204, security category 3).
///
/// Holds an in-memory `SigningKey<MlDsa65>` plus the cached encoded
/// verifying-key bytes. `Debug` redacts the signing key. Production HSM /
/// KMS signers would land via a separate surface; this is the software
/// path used to attest L2 erasure receipts.
#[cfg(feature = "tier-2-pqc-receipts")]
pub struct ReceiptSigner {
    signing_key: ml_dsa::SigningKey<MlDsa65>,
    verifying_key_bytes: Vec<u8>,
}

#[cfg(feature = "tier-2-pqc-receipts")]
impl ReceiptSigner {
    /// Construct deterministically from a 32-byte seed (FIPS 204
    /// ML-DSA.KeyGen_internal — same seed yields the same key pair).
    ///
    /// The caller's transient `seed` copy is scrubbed before return; the
    /// long-lived [`ReceiptSigner`] retains the key material in the
    /// `SigningKey`, which zeroizes on drop via the ml-dsa `zeroize`
    /// feature.
    #[must_use]
    pub fn mldsa65_from_seed(mut seed: [u8; 32]) -> Self {
        let xi: B32 = seed.into();
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&xi);
        let verifying_key_bytes = signing_key.verifying_key().encode().to_vec();
        // Scrub the caller's transient seed copy; the SigningKey itself
        // zeroizes on drop (ml-dsa `zeroize` feature).
        seed.zeroize();
        Self {
            signing_key,
            verifying_key_bytes,
        }
    }

    /// Sign `message` and return the 3309-byte ML-DSA-65 signature over
    /// the domain-separated bytes. ML-DSA `try_sign` is deterministic (no
    /// RNG) and infallible on the software path.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let m = domain_separated(message);
        // WHY: try_sign on the software SigningKey is the infallible
        // deterministic path (no RNG, no provider I/O); a failure here is
        // a logic bug, not a runtime condition.
        #[allow(clippy::expect_used)]
        let sig: ml_dsa::Signature<MlDsa65> = self
            .signing_key
            .try_sign(&m)
            .expect("ml-dsa-65 software try_sign is infallible (deterministic, no RNG)");
        sig.encode().to_vec()
    }

    /// Borrow the cached encoded verifying-key bytes (1952 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.verifying_key_bytes
    }
}

#[cfg(feature = "tier-2-pqc-receipts")]
impl core::fmt::Debug for ReceiptSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ReceiptSigner {{ verifying_key_bytes: <1952B>, signing_key: <redacted> }}"
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arkhe_forge_core::pii::DekId;

    #[test]
    fn domain_separated_prefixes_tag() {
        let m = domain_separated(b"payload");
        assert!(m.starts_with(FORGE_RECEIPT_SIG_DOMAIN));
        assert_eq!(&m[FORGE_RECEIPT_SIG_DOMAIN.len()..], b"payload");
    }

    #[test]
    fn forge_domain_distinct_from_kernel_wal_domain() {
        // Cross-protocol key-reuse defence: the L2 receipt domain must not
        // collide with the kernel WAL domain.
        assert_ne!(
            FORGE_RECEIPT_SIG_DOMAIN,
            b"arkhe-kernel v0.14 WAL record signature domain".as_slice()
        );
    }

    #[test]
    fn dek_shred_message_canonical_layout_frozen() {
        // Frozen layout: dek_id.0 (16) ++ log_index.to_be_bytes() (8).
        let dek_id = DekId([0xAB; 16]);
        let m = dek_shred_message(&dek_id, 0x0102_0304_0506_0708);
        assert_eq!(m.len(), 24);
        assert_eq!(&m[..16], &[0xAB; 16]);
        assert_eq!(
            &m[16..24],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn none_class_requires_signature() {
        let err = verify_attestation(RuntimeSignatureClass::None, &[], b"m", &[]).unwrap_err();
        assert_eq!(err, VerifyError::SignatureRequired);
    }

    #[test]
    fn ed25519_round_trip_validates() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let message = b"erasure receipt body";
        let m = domain_separated(message);
        let sig = sk.sign(&m);
        assert!(verify_attestation(
            RuntimeSignatureClass::Ed25519,
            &vk.to_bytes(),
            message,
            &sig.to_bytes()
        )
        .is_ok());
    }

    #[test]
    fn ed25519_wrong_key_length_rejected() {
        let err = verify_attestation(RuntimeSignatureClass::Ed25519, &[0u8; 31], b"m", &[0u8; 64])
            .unwrap_err();
        assert_eq!(err, VerifyError::WrongKeyLength);
    }

    #[test]
    fn ed25519_wrong_sig_length_rejected() {
        let err = verify_attestation(RuntimeSignatureClass::Ed25519, &[0u8; 32], b"m", &[0u8; 63])
            .unwrap_err();
        assert_eq!(err, VerifyError::WrongSignatureLength);
    }

    #[test]
    fn ed25519_corrupt_sig_rejected() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let message = b"body";
        let m = domain_separated(message);
        let mut sig = sk.sign(&m).to_bytes();
        sig[0] ^= 0xFF;
        let err = verify_attestation(
            RuntimeSignatureClass::Ed25519,
            &vk.to_bytes(),
            message,
            &sig,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Mismatch);
    }

    #[cfg(not(feature = "tier-2-pqc-receipts"))]
    #[test]
    fn ml_dsa65_unavailable_in_default_build() {
        let err = verify_attestation(
            RuntimeSignatureClass::MlDsa65,
            &[0u8; MLDSA65_PK_LEN],
            b"m",
            &[0u8; MLDSA65_SIG_LEN],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::PqcUnavailable);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn ml_dsa65_round_trip_validates() {
        let signer = ReceiptSigner::mldsa65_from_seed([11u8; 32]);
        let message = b"ml-dsa receipt body";
        let sig = signer.sign(message);
        assert_eq!(sig.len(), MLDSA65_SIG_LEN);
        assert_eq!(signer.public_key_bytes().len(), MLDSA65_PK_LEN);
        assert!(verify_attestation(
            RuntimeSignatureClass::MlDsa65,
            signer.public_key_bytes(),
            message,
            &sig
        )
        .is_ok());
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn ml_dsa65_corrupt_sig_rejected() {
        let signer = ReceiptSigner::mldsa65_from_seed([13u8; 32]);
        let message = b"body";
        let mut sig = signer.sign(message);
        sig[0] ^= 0xFF;
        let err = verify_attestation(
            RuntimeSignatureClass::MlDsa65,
            signer.public_key_bytes(),
            message,
            &sig,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Mismatch);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn hybrid_round_trip_validates_and_mode() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let ed_sk = SigningKey::from_bytes(&[23u8; 32]);
        let ed_vk = ed_sk.verifying_key();
        let pqc = ReceiptSigner::mldsa65_from_seed([29u8; 32]);
        let message = b"hybrid receipt body";
        let m = domain_separated(message);
        let ed_sig = ed_sk.sign(&m).to_bytes();
        let pqc_sig = pqc.sign(message);

        let mut public_key = Vec::new();
        public_key.extend_from_slice(&ed_vk.to_bytes());
        public_key.extend_from_slice(pqc.public_key_bytes());
        let mut sig = Vec::new();
        sig.extend_from_slice(&ed_sig);
        sig.extend_from_slice(&pqc_sig);
        assert_eq!(public_key.len(), ED25519_PK_LEN + MLDSA65_PK_LEN);
        assert_eq!(sig.len(), ED25519_SIG_LEN + MLDSA65_SIG_LEN);

        assert!(
            verify_attestation(RuntimeSignatureClass::Hybrid, &public_key, message, &sig).is_ok()
        );
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn hybrid_rejects_when_pqc_half_corrupt() {
        // AND-mode: a valid Ed25519 half with a broken ML-DSA half fails.
        use ed25519_dalek::{Signer as _, SigningKey};
        let ed_sk = SigningKey::from_bytes(&[31u8; 32]);
        let ed_vk = ed_sk.verifying_key();
        let pqc = ReceiptSigner::mldsa65_from_seed([37u8; 32]);
        let message = b"body";
        let m = domain_separated(message);
        let ed_sig = ed_sk.sign(&m).to_bytes();
        let mut pqc_sig = pqc.sign(message);
        pqc_sig[0] ^= 0xFF;

        let mut public_key = Vec::new();
        public_key.extend_from_slice(&ed_vk.to_bytes());
        public_key.extend_from_slice(pqc.public_key_bytes());
        let mut sig = Vec::new();
        sig.extend_from_slice(&ed_sig);
        sig.extend_from_slice(&pqc_sig);
        let err = verify_attestation(RuntimeSignatureClass::Hybrid, &public_key, message, &sig)
            .unwrap_err();
        assert_eq!(err, VerifyError::Mismatch);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn hybrid_rejects_when_ed25519_half_corrupt() {
        // AND-mode: a broken Ed25519 half (with valid ML-DSA) fails first.
        use ed25519_dalek::{Signer as _, SigningKey};
        let ed_sk = SigningKey::from_bytes(&[41u8; 32]);
        let ed_vk = ed_sk.verifying_key();
        let pqc = ReceiptSigner::mldsa65_from_seed([43u8; 32]);
        let message = b"body";
        let m = domain_separated(message);
        let mut ed_sig = ed_sk.sign(&m).to_bytes();
        ed_sig[0] ^= 0xFF;
        let pqc_sig = pqc.sign(message);

        let mut public_key = Vec::new();
        public_key.extend_from_slice(&ed_vk.to_bytes());
        public_key.extend_from_slice(pqc.public_key_bytes());
        let mut sig = Vec::new();
        sig.extend_from_slice(&ed_sig);
        sig.extend_from_slice(&pqc_sig);
        let err = verify_attestation(RuntimeSignatureClass::Hybrid, &public_key, message, &sig)
            .unwrap_err();
        assert_eq!(err, VerifyError::Mismatch);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn hybrid_wrong_key_length_rejected() {
        let err = verify_attestation(
            RuntimeSignatureClass::Hybrid,
            &[0u8; ED25519_PK_LEN + MLDSA65_PK_LEN - 1],
            b"m",
            &[0u8; ED25519_SIG_LEN + MLDSA65_SIG_LEN],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::WrongKeyLength);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn hybrid_wrong_sig_length_rejected() {
        let err = verify_attestation(
            RuntimeSignatureClass::Hybrid,
            &[0u8; ED25519_PK_LEN + MLDSA65_PK_LEN],
            b"m",
            &[0u8; ED25519_SIG_LEN + MLDSA65_SIG_LEN - 1],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::WrongSignatureLength);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn receipt_signer_debug_redacts_key() {
        let signer = ReceiptSigner::mldsa65_from_seed([0u8; 32]);
        let dbg = format!("{:?}", signer);
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn envelope_ed25519_ok() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let sk = SigningKey::from_bytes(&[59u8; 32]);
        let vk = sk.verifying_key();
        let message = b"envelope ed25519 body";
        let m = domain_separated(message);
        let sig = sk.sign(&m).to_bytes();
        assert!(verify_receipt_envelope(
            RuntimeSignatureClass::Ed25519,
            &vk.to_bytes(),
            message,
            &sig,
            None,
        )
        .is_ok());
    }

    #[test]
    fn envelope_incoherent_ed25519_with_pqc_slot() {
        // Ed25519 must NOT carry a PQC slot.
        let err = verify_receipt_envelope(
            RuntimeSignatureClass::Ed25519,
            &[0u8; ED25519_PK_LEN],
            b"m",
            &[0u8; ED25519_SIG_LEN],
            Some(&[0u8; MLDSA65_SIG_LEN]),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::EnvelopeIncoherent);
    }

    #[test]
    fn envelope_incoherent_mldsa65_without_pqc_slot() {
        // MlDsa65 requires a PQC slot — a None slot is incoherent.
        let err = verify_receipt_envelope(
            RuntimeSignatureClass::MlDsa65,
            &[0u8; MLDSA65_PK_LEN],
            b"m",
            &[],
            None,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::EnvelopeIncoherent);
    }

    #[test]
    fn envelope_none_class_requires_signature() {
        let err =
            verify_receipt_envelope(RuntimeSignatureClass::None, &[], b"m", &[], None).unwrap_err();
        assert_eq!(err, VerifyError::SignatureRequired);
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn envelope_mldsa65_ok() {
        let signer = ReceiptSigner::mldsa65_from_seed([61u8; 32]);
        let message = b"envelope ml-dsa body";
        let sig = signer.sign(message);
        assert_eq!(sig.len(), MLDSA65_SIG_LEN);
        assert!(verify_receipt_envelope(
            RuntimeSignatureClass::MlDsa65,
            signer.public_key_bytes(),
            message,
            &[],
            Some(&sig),
        )
        .is_ok());
    }

    #[cfg(feature = "tier-2-pqc-receipts")]
    #[test]
    fn envelope_hybrid_ok() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let ed_sk = SigningKey::from_bytes(&[67u8; 32]);
        let ed_vk = ed_sk.verifying_key();
        let pqc = ReceiptSigner::mldsa65_from_seed([71u8; 32]);
        let message = b"envelope hybrid body";
        let m = domain_separated(message);
        let ed_sig = ed_sk.sign(&m).to_bytes();
        let pqc_sig = pqc.sign(message);

        let mut public_key = Vec::new();
        public_key.extend_from_slice(&ed_vk.to_bytes());
        public_key.extend_from_slice(pqc.public_key_bytes());
        assert!(verify_receipt_envelope(
            RuntimeSignatureClass::Hybrid,
            &public_key,
            message,
            &ed_sig,
            Some(&pqc_sig),
        )
        .is_ok());
    }
}
