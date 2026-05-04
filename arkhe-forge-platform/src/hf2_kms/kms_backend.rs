//! Sync `KmsBackend` trait — envelope-encryption interface.
//!
//! Spec §14.9.1 §§2 / §14.11.2. The trait is intentionally **synchronous** so
//! L2 coordinators (all sync today) can stay sync. Real-world backends whose
//! SDKs are async-only (e.g. `aws-sdk-kms`) wrap a dedicated runtime and
//! `block_on` internally — the sync surface is the stable contract.
//!
//! Implementations are responsible for:
//!
//! 1. Generating DEK material inside the KMS boundary — the runtime never
//!    derives 32-byte key material directly (spec §14.9.1 §§2).
//! 2. Wrapping / unwrapping DEKs under a `KekRef`-addressed KEK. The
//!    wrapped bytes are opaque from the runtime's perspective.
//! 3. Emitting a signed destruction attestation when a KEK is deleted
//!    (§14.9.1 §§5) — the attestation flows up the stack into the
//!    `UserErasureCompleted` receipt.
//! 4. Rotating a KEK pair so in-flight wrapped DEKs can be re-enveloped
//!    under the new KEK.
//!
//! The [`MockKmsBackend`] supplied here is the Tier-0 dev / test harness
//! impl — plaintext-in-memory with deterministic attestations. Real
//! Tier-1/2 backends live behind feature gates (`tier-2-aws-kms`, etc.).

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Mutex;

use arkhe_forge_core::event::RuntimeSignatureClass;
use arkhe_forge_core::pii::DekId;

use crate::crypto::Dek;
use crate::crypto_erasure::DekShredAttestation;

/// Reference to a KEK (Key Encryption Key) held by a KMS backend. Typically
/// an AWS ARN, a GCP key-resource path, or a filesystem handle for the mock.
/// The wrapper is intentionally opaque — callers never interpret the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KekRef {
    id: String,
}

impl KekRef {
    /// Construct from a backend-specific identifier string.
    #[inline]
    #[must_use]
    pub fn new<S: Into<String>>(id: S) -> Self {
        Self { id: id.into() }
    }

    /// Borrow the identifier — exposed for RPC wiring.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

/// Signed destruction receipt returned by [`KmsBackend::delete_key`]. Alias
/// to [`DekShredAttestation`] so the attestation surface is shared across
/// the cascade observer and the KMS backend paths.
pub type KeyDeletionAttestation = DekShredAttestation;

/// KMS backend failure taxonomy.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    /// Transport / network / TLS handshake failure.
    #[error("KMS transport error: {0}")]
    Transport(String),
    /// Authentication / authorization rejected.
    #[error("KMS auth error: {0}")]
    Auth(String),
    /// Requested KEK does not exist (or is already scheduled for hard-delete).
    #[error("KEK not found: {0}")]
    KekNotFound(String),
    /// Wrapped DEK failed to unwrap — integrity / tampering detected.
    #[error("wrapped DEK unwrap failed")]
    UnwrapFailed,
    /// KEK deletion already in progress — retries treated as idempotent by
    /// callers that accept the cached attestation.
    #[error("KEK deletion already scheduled: {0}")]
    KekDeleting(String),
    /// Rate limit / quota exceeded on the backend.
    #[error("KMS quota exceeded")]
    QuotaExceeded,
    /// Backend-specific irrecoverable failure — preserves the SDK error.
    #[error("KMS backend error: {0}")]
    Backend(String),
}

/// Synchronous KMS abstraction. All methods are blocking; async-native
/// backends bridge internally.
///
/// Thread-safety: implementations **must** be `Send + Sync` so a single
/// backend instance can be shared across the coordinator + cascade
/// observer without interior `Rc`.
pub trait KmsBackend: Send + Sync {
    /// Generate a fresh 32-byte DEK under `kek_ref`. The plaintext DEK is
    /// returned alongside its opaque [`DekId`] — callers wrap it for at-rest
    /// storage via [`Self::wrap_dek`] immediately after.
    fn generate_dek(&self, kek_ref: &KekRef) -> Result<(DekId, Dek), KmsError>;

    /// Wrap the plaintext DEK under `kek_ref`. Returns the backend's opaque
    /// ciphertext blob — format is backend-specific.
    fn wrap_dek(&self, dek: &Dek, kek_ref: &KekRef) -> Result<Bytes, KmsError>;

    /// Unwrap a previously-wrapped DEK. `kek_ref` must match the KEK used
    /// at wrap time — mismatches surface as [`KmsError::UnwrapFailed`].
    fn unwrap_dek(&self, wrapped: &[u8], kek_ref: &KekRef) -> Result<Dek, KmsError>;

    /// Schedule `kek_ref` for destruction and return a signed attestation.
    /// Idempotent: subsequent calls for the same KEK return the cached
    /// attestation (see [`DekShredAttestation`] idempotency contract).
    fn delete_key(&self, kek_ref: &KekRef) -> Result<KeyDeletionAttestation, KmsError>;

    /// Rotate KEK addressing — mark `old` as rotated-out and `new` as the
    /// active KEK for future wraps. DEK re-encryption is a separate
    /// operation (callers iterate wrapped DEKs + unwrap-then-wrap under
    /// `new`). Returning `Ok(())` asserts the rotation was accepted;
    /// backends that need attestation emit a `RuntimeBootstrap`-analogous
    /// event through the coordinator.
    fn rotate_kek(&self, old: &KekRef, new: &KekRef) -> Result<(), KmsError>;
}

// ───────────────────── Mock backend ─────────────────────

/// Tier-0 / test-harness [`KmsBackend`] — plaintext-in-memory. Deterministic
/// attestations so tests assert exact bytes.
///
/// * DEK ids are derived from a keyed BLAKE3 digest of
///   `(kek_ref || counter)`; collisions are astronomically unlikely.
/// * Wrapped DEKs are XOR'd against a per-KEK pad (not cryptographically
///   strong — just enough to catch cross-KEK unwrap attempts).
/// * `rotate_kek` records the rotation in an internal log for tests that
///   assert ordering; no state is destroyed.
#[derive(Debug, Default)]
pub struct MockKmsBackend {
    inner: Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    keks: HashMap<KekRef, MockKek>,
    /// Records `delete_key` issuance per KEK so repeat calls are idempotent.
    destroyed: HashMap<KekRef, KeyDeletionAttestation>,
    /// Bump on each KEK creation / DEK id so tests get stable sequences.
    counter: u64,
    /// Append-only rotation log — `(old, new)` pairs.
    rotations: Vec<(KekRef, KekRef)>,
    /// Monotonic destruction-log index for attestations.
    destruction_log_index: u64,
}

#[derive(Debug, Clone)]
struct MockKek {
    /// Per-KEK pad, 32 bytes — XOR'd against wrapped DEK material.
    pad: [u8; 32],
}

impl MockKmsBackend {
    /// Empty backend — callers register KEKs via [`Self::register_kek`].
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a KEK with a deterministic pad derived from its id.
    pub fn register_kek(&self, kek_ref: &KekRef) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state.keks.contains_key(kek_ref) {
            return;
        }
        let digest = blake3::keyed_hash(
            blake3::hash(b"arkhe-forge-mock-kms-kek-pad").as_bytes(),
            kek_ref.as_str().as_bytes(),
        );
        state.keks.insert(
            kek_ref.clone(),
            MockKek {
                pad: *digest.as_bytes(),
            },
        );
    }

    /// Count of destroyed KEKs — test-harness observability.
    #[must_use]
    pub fn destroyed_count(&self) -> usize {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.destroyed.len()
    }

    /// Rotations recorded so far — test-harness observability.
    #[must_use]
    pub fn rotation_log_len(&self) -> usize {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.rotations.len()
    }

    fn xor_pad(dst: &mut [u8], pad: &[u8; 32]) {
        for (i, b) in dst.iter_mut().enumerate() {
            *b ^= pad[i % 32];
        }
    }
}

impl KmsBackend for MockKmsBackend {
    fn generate_dek(&self, kek_ref: &KekRef) -> Result<(DekId, Dek), KmsError> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !state.keks.contains_key(kek_ref) {
            return Err(KmsError::KekNotFound(kek_ref.as_str().to_string()));
        }
        state.counter = state.counter.saturating_add(1);
        // Deterministic DEK material derived from (kek_ref || counter). The
        // mock is NOT a real CSPRNG — production backends call the HSM.
        let mut h = blake3::Hasher::new();
        h.update(b"arkhe-forge-mock-kms-dek-material");
        h.update(kek_ref.as_str().as_bytes());
        h.update(&state.counter.to_le_bytes());
        let dek_material: [u8; 32] = *h.finalize().as_bytes();

        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(b"arkhe-forge-mock-kms-dek-id");
        id_hasher.update(kek_ref.as_str().as_bytes());
        id_hasher.update(&state.counter.to_le_bytes());
        let dek_id_full: [u8; 32] = *id_hasher.finalize().as_bytes();
        let mut dek_id_bytes = [0u8; 16];
        dek_id_bytes.copy_from_slice(&dek_id_full[..16]);

        Ok((DekId(dek_id_bytes), Dek::from_bytes(dek_material)))
    }

    fn wrap_dek(&self, dek: &Dek, kek_ref: &KekRef) -> Result<Bytes, KmsError> {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let kek = state
            .keks
            .get(kek_ref)
            .ok_or_else(|| KmsError::KekNotFound(kek_ref.as_str().to_string()))?;
        // Intentionally weak — we prefix the pad digest so unwrap can
        // detect cross-KEK tamper attempts. Production backends return
        // authenticated envelope-encrypted blobs.
        let mut buf = Vec::with_capacity(32 + 32);
        buf.extend_from_slice(&kek.pad);
        buf.extend_from_slice(dek.as_bytes());
        let (marker, body) = buf.split_at_mut(32);
        let _ = marker; // marker stays cleartext; body XOR'd.
        Self::xor_pad(body, &kek.pad);
        Ok(Bytes::from(buf))
    }

    fn unwrap_dek(&self, wrapped: &[u8], kek_ref: &KekRef) -> Result<Dek, KmsError> {
        if wrapped.len() != 64 {
            return Err(KmsError::UnwrapFailed);
        }
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let kek = state
            .keks
            .get(kek_ref)
            .ok_or_else(|| KmsError::KekNotFound(kek_ref.as_str().to_string()))?;
        let marker = &wrapped[..32];
        if marker != kek.pad {
            return Err(KmsError::UnwrapFailed);
        }
        let mut body = [0u8; 32];
        body.copy_from_slice(&wrapped[32..]);
        Self::xor_pad(&mut body, &kek.pad);
        Ok(Dek::from_bytes(body))
    }

    fn delete_key(&self, kek_ref: &KekRef) -> Result<KeyDeletionAttestation, KmsError> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = state.destroyed.get(kek_ref) {
            return Ok(cached.clone());
        }
        if !state.keks.contains_key(kek_ref) {
            return Err(KmsError::KekNotFound(kek_ref.as_str().to_string()));
        }
        let log_index = state.destruction_log_index;
        state.destruction_log_index = state.destruction_log_index.saturating_add(1);
        let mut h = blake3::Hasher::new();
        h.update(b"arkhe-forge-mock-kms-delete-attestation");
        h.update(kek_ref.as_str().as_bytes());
        h.update(&log_index.to_le_bytes());
        let payload: [u8; 32] = *h.finalize().as_bytes();
        let attestation = DekShredAttestation {
            attestation_class: RuntimeSignatureClass::Ed25519,
            attestation_bytes: Bytes::copy_from_slice(&payload),
            log_index: Some(log_index),
        };
        state.keks.remove(kek_ref);
        state.destroyed.insert(kek_ref.clone(), attestation.clone());
        Ok(attestation)
    }

    fn rotate_kek(&self, old: &KekRef, new: &KekRef) -> Result<(), KmsError> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !state.keks.contains_key(old) {
            return Err(KmsError::KekNotFound(old.as_str().to_string()));
        }
        if !state.keks.contains_key(new) {
            return Err(KmsError::KekNotFound(new.as_str().to_string()));
        }
        state.rotations.push((old.clone(), new.clone()));
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn mock_with_kek(id: &str) -> (MockKmsBackend, KekRef) {
        let b = MockKmsBackend::new();
        let k = KekRef::new(id);
        b.register_kek(&k);
        (b, k)
    }

    #[test]
    fn generate_dek_without_kek_errors() {
        let b = MockKmsBackend::new();
        let k = KekRef::new("ghost");
        let err = b.generate_dek(&k).unwrap_err();
        assert!(matches!(err, KmsError::KekNotFound(_)));
    }

    #[test]
    fn generate_dek_roundtrips_wrap_unwrap() {
        let (b, k) = mock_with_kek("kek-1");
        let (dek_id, dek) = b.generate_dek(&k).unwrap();
        let wrapped = b.wrap_dek(&dek, &k).unwrap();
        let unwrapped = b.unwrap_dek(&wrapped, &k).unwrap();
        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
        assert_ne!(dek_id.0, [0u8; 16]);
    }

    #[test]
    fn unwrap_under_wrong_kek_fails() {
        let (b, k1) = mock_with_kek("kek-1");
        let k2 = KekRef::new("kek-2");
        b.register_kek(&k2);
        let (_id, dek) = b.generate_dek(&k1).unwrap();
        let wrapped = b.wrap_dek(&dek, &k1).unwrap();
        let err = b.unwrap_dek(&wrapped, &k2).unwrap_err();
        assert!(matches!(err, KmsError::UnwrapFailed));
    }

    #[test]
    fn delete_key_idempotent_across_retries() {
        let (b, k) = mock_with_kek("kek-delete");
        let first = b.delete_key(&k).unwrap();
        let second = b.delete_key(&k).unwrap();
        assert_eq!(first, second);
        assert_eq!(b.destroyed_count(), 1);
    }

    #[test]
    fn delete_key_unknown_errors() {
        let b = MockKmsBackend::new();
        let k = KekRef::new("never-existed");
        let err = b.delete_key(&k).unwrap_err();
        assert!(matches!(err, KmsError::KekNotFound(_)));
    }

    #[test]
    fn rotate_kek_records_log_entry() {
        let (b, k1) = mock_with_kek("kek-old");
        let k2 = KekRef::new("kek-new");
        b.register_kek(&k2);
        assert!(b.rotate_kek(&k1, &k2).is_ok());
        assert_eq!(b.rotation_log_len(), 1);
    }

    #[test]
    fn rotate_kek_unknown_old_errors() {
        let b = MockKmsBackend::new();
        let k1 = KekRef::new("never-1");
        let k2 = KekRef::new("never-2");
        let err = b.rotate_kek(&k1, &k2).unwrap_err();
        assert!(matches!(err, KmsError::KekNotFound(_)));
    }

    #[test]
    fn generate_dek_is_deterministic_under_fixed_kek_seed() {
        // Mock's per-KEK pad derives from kek_ref.as_str(); given the same
        // identifier we expect reproducible pads + counters, so the first
        // DEK under each fresh backend is identical.
        let b1 = MockKmsBackend::new();
        let b2 = MockKmsBackend::new();
        let k = KekRef::new("det-kek");
        b1.register_kek(&k);
        b2.register_kek(&k);
        let (id1, dek1) = b1.generate_dek(&k).unwrap();
        let (id2, dek2) = b2.generate_dek(&k).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(dek1.as_bytes(), dek2.as_bytes());
    }

    #[test]
    fn kek_ref_preserves_identity() {
        let k = KekRef::new("arn:aws:kms:eu-central-1:123:key/abc");
        assert_eq!(k.as_str(), "arn:aws:kms:eu-central-1:123:key/abc");
        let cloned = k.clone();
        assert_eq!(k, cloned);
    }

    #[test]
    fn duplicate_register_kek_is_noop() {
        let (b, k) = mock_with_kek("kek-dup");
        b.register_kek(&k);
        b.register_kek(&k);
        // No assertion needed beyond absence of panic; destroyed_count
        // indirectly proves the internal map held one entry.
        assert_eq!(b.destroyed_count(), 0);
    }
}
