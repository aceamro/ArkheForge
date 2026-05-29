//! Crypto-erasure coordinator — Tier-1+ AEAD envelope encryption.
//!
//! Provides:
//!
//! * [`Dek`] — 32-byte key material with zeroise-on-drop semantics. The
//!   runtime never handles wrapped key material; that lives in the
//!   HSM/KMS backend.
//! * [`EncryptedPii`] — generic wrapper over an opaque ciphertext + tag +
//!   nonce + `DekId` + `AeadKind`. The wire tag binds the PII marker
//!   (`T::PII_CODE`) via AAD, defeating the type-confused-deputy path.
//! * [`CryptoCoordinator`] — stateful entry-point that dispatches
//!   `encrypt` / `decrypt` by the shell manifest's declared `AeadKind`
//!   and compliance tier. Under the default (Tier-0) feature set the
//!   coordinator refuses encryption with [`PiiError::TierTooLow`].
//! * [`rotate_dek`] — slice-level DEK rotation helper. Callers must hold
//!   a single-writer lock; the helper is atomic per-element and rolls
//!   the whole slice back on the first failure.
//!
//! Feature matrix:
//!
//! | Feature                | `XChaCha20-Poly1305` | `AES-256-GCM` | `AES-256-GCM-SIV` |
//! |------------------------|----------------------|---------------|-------------------|
//! | *(default — Tier-0)*   | rejected             | rejected      | rejected          |
//! | `tier-1-kms`           | ✓                    | rejected      | rejected          |
//! | `tier-2-multi-kms`     | ✓                    | ✓             | ✓                 |
//!
//! The coordinator's public surface is stable. HSM / KMS wrap-unwrap
//! integration and the Sigstore transparency anchor route through `hf2_kms`.

use arkhe_forge_core::pii::{
    compute_aad, AeadKind, DekId, DekMessageCounter, PiiError, PiiType, RotationTrigger,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===================== Dek =====================

/// Construction-time configuration for a [`Dek`]. Single-writer
/// deployments use the default (all fields zero); federation builds
/// populate `replica_id` from the per-instance manifest anchor so two
/// regions sharing the same DEK material cannot collide their
/// deterministic nonces (the F6 invocation-field reservation).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DekConfig {
    /// 4-byte invocation field for the AES-GCM(-SIV) nonce. Must be
    /// instance-pinned immutable (L0 A11 pure compute); Runtime
    /// reconfig **must not** mutate this value without a full
    /// RuntimeBootstrap re-emit and DEK rotation cycle.
    pub replica_id: u32,
}

/// DEK lifetime relative to the process. The distinction is a nonce-reuse
/// safety boundary for the deterministic counter nonce:
///
/// * [`DekLifecycle::Ephemeral`] — the `Dek` lives for at most the current
///   process; the in-memory counter is authoritative for its whole life, so
///   the deterministic counter never repeats and plain AES-256-GCM is safe.
/// * [`DekLifecycle::LongLived`] — the `Dek` was reconstructed from durable
///   wrapped material (a KMS `unwrap_dek`) and may outlive the process. The
///   counter resets to `0` on every reconstruction, so plain AES-256-GCM
///   would reuse nonces under a fixed key (catastrophic). Such DEKs are
///   admitted only under the nonce-misuse-resistant `Aes256GcmSiv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DekLifecycle {
    /// Process-bound; counter is authoritative for the key's whole life.
    Ephemeral,
    /// Reconstructed from durable wrapped material; counter resets on each
    /// reconstruction, so plain AES-256-GCM is unsafe (must use SIV).
    LongLived,
}

/// Per-user 32-byte DEK material. The byte buffer is
/// wiped on `Drop` via the `zeroize` crate; callers obtain a `Dek` from
/// an HSM unwrap — the runtime never derives key material directly
/// (envelope encryption).
///
/// A per-DEK monotonic counter drives the deterministic 96-bit nonce
/// for AES-GCM / AES-GCM-SIV under the NIST SP 800-38D §8.2.1
/// construction (4-byte invocation field = [`DekConfig::replica_id`] +
/// 8-byte counter, big-endian). XChaCha20-Poly1305 uses a 192-bit
/// random nonce and leaves the counter alone. Counter exhaustion at
/// `u64::MAX` surfaces [`PiiError::DekExhausted`] so the operator
/// rotates the DEK before any nonce reuse.
///
/// `replica_id` is held by the DEK itself and is **immutable after
/// construction** — changing it post-hoc would violate L0 A11 pure
/// compute (replay determinism depends on stable nonce bytes). Default
/// single-writer deployments use `replica_id = 0`; federation builds
/// populate a per-replica id via [`Dek::with_config`].
///
/// `Dek` is intentionally **not** `Clone` — two copies of the same key
/// material with independent counters would collide their nonces under
/// AES-GCM (catastrophic integrity loss). Callers must hold a single
/// owner per key; rotation yields a fresh `Dek` via [`Dek::from_bytes`]
/// whose counter starts at `0`.
///
/// The interior `Cell<u64>` counter makes `Dek` implicitly `!Sync`, so
/// the compiler refuses naive cross-thread sharing. If a deployment
/// genuinely needs to share a DEK across task boundaries (e.g., an
/// L2 async runtime feeding multiple encrypt handlers), wrap it in
/// `Arc<Mutex<Dek>>` or `Arc<parking_lot::Mutex<Dek>>` at the caller
/// site — the mutex guards the counter advance and keeps the
/// deterministic-nonce invariant intact. Single-writer deployments
/// (L0 A2 single-thread) hold a plain owned `Dek` without
/// synchronisation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek {
    material: [u8; 32],
    /// Monotonic message counter used by the AES-GCM(-SIV) nonce
    /// construction. Not sensitive; skipped by zeroize.
    #[zeroize(skip)]
    counter: Cell<u64>,
    /// Invocation field for the nonce construction. Immutable after
    /// construction — see [`DekConfig::replica_id`].
    #[zeroize(skip)]
    replica_id: u32,
    /// Lifetime classification — gates the AES-256-GCM nonce-reuse guard.
    /// Not sensitive; skipped by zeroize.
    #[zeroize(skip)]
    lifecycle: DekLifecycle,
}

impl Dek {
    /// Construct from a 32-byte buffer using default configuration
    /// (`replica_id = 0`, single-writer). The input is copied; callers
    /// remain responsible for wiping their own buffer. Counter starts
    /// at `0`.
    #[inline]
    #[must_use]
    pub fn from_bytes(material: [u8; 32]) -> Self {
        Self::with_config(material, DekConfig::default())
    }

    /// Construct from a 32-byte buffer with an explicit [`DekConfig`].
    /// Federation path consumes this entry point with a non-zero
    /// `replica_id`; single-writer deployments use [`Dek::from_bytes`].
    /// Lifecycle is [`DekLifecycle::Ephemeral`] — process-bound.
    #[inline]
    #[must_use]
    pub fn with_config(material: [u8; 32], config: DekConfig) -> Self {
        Self {
            material,
            counter: Cell::new(0),
            replica_id: config.replica_id,
            lifecycle: DekLifecycle::Ephemeral,
        }
    }

    /// Construct a [`DekLifecycle::LongLived`] DEK from durable wrapped
    /// material — the KMS `unwrap_dek` entry point. Because the counter
    /// resets to `0` on every reconstruction, a long-lived DEK is admitted
    /// only under `AeadKind::Aes256GcmSiv`; the AES-256-GCM encrypt path
    /// rejects it with [`PiiError::NonceReuseRisk`].
    #[inline]
    #[must_use]
    pub fn from_unwrapped(material: [u8; 32], config: DekConfig) -> Self {
        Self {
            material,
            counter: Cell::new(0),
            replica_id: config.replica_id,
            lifecycle: DekLifecycle::LongLived,
        }
    }

    /// Lifetime classification — see [`DekLifecycle`].
    #[inline]
    #[must_use]
    #[cfg_attr(not(feature = "tier-2-multi-kms"), allow(dead_code))]
    pub fn lifecycle(&self) -> DekLifecycle {
        self.lifecycle
    }

    /// Construct from a byte slice. Rejects the call with
    /// [`PiiError::InvalidKeyLength`] when `bytes.len() != 32`.
    /// Counter starts at `0` with default [`DekConfig`]; lifecycle is
    /// [`DekLifecycle::Ephemeral`].
    ///
    /// The length check is a single `usize` compare against the
    /// constant `32` — no byte-by-byte value comparison happens on
    /// the reject path, so there is no timing side-channel the
    /// `subtle` crate would mitigate. `copy_from_slice` runs in
    /// time dependent on the buffer length, not its contents.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, PiiError> {
        if bytes.len() != 32 {
            return Err(PiiError::InvalidKeyLength);
        }
        let mut material = [0u8; 32];
        material.copy_from_slice(bytes);
        Ok(Self {
            material,
            counter: Cell::new(0),
            replica_id: 0,
            lifecycle: DekLifecycle::Ephemeral,
        })
    }

    /// Borrow the underlying 32-byte key. Intentionally crate-visible so
    /// downstream crypto primitives can feed the AEAD `Key` type without
    /// leaking the buffer through the public surface.
    #[inline]
    #[must_use]
    #[cfg_attr(
        not(any(feature = "tier-1-kms", feature = "tier-2-multi-kms")),
        allow(dead_code)
    )]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.material
    }

    /// Return the current counter value and advance to the next. Used
    /// by the AES-GCM(-SIV) encrypt paths to produce deterministic
    /// nonces. Returns [`PiiError::DekExhausted`] when the counter has
    /// already reached `u64::MAX` — a rotation is required before any
    /// further encryption.
    #[cfg_attr(not(feature = "tier-2-multi-kms"), allow(dead_code))]
    fn advance_counter(&self) -> Result<u64, PiiError> {
        let n = self.counter.get();
        if n == u64::MAX {
            return Err(PiiError::DekExhausted);
        }
        self.counter.set(n.wrapping_add(1));
        Ok(n)
    }

    /// Test-only accessor — set the counter to an arbitrary value to
    /// exercise exhaustion and rotation paths.
    #[cfg(all(test, feature = "tier-2-multi-kms"))]
    pub(crate) fn set_counter_for_test(&self, n: u64) {
        self.counter.set(n);
    }

    /// Test-only accessor — read the current counter.
    #[cfg(all(test, feature = "tier-2-multi-kms"))]
    pub(crate) fn get_counter_for_test(&self) -> u64 {
        self.counter.get()
    }
}

/// NIST SP 800-38D §8.2.1 deterministic nonce: 4-byte invocation
/// field (`replica_id`) + 8-byte big-endian counter. The 96-bit
/// layout is the native nonce size for both AES-GCM and AES-GCM-SIV.
///
/// `replica_id = 0` is the single-writer default. Federation builds
/// supply a per-replica id via [`DekConfig::replica_id`] so two
/// regions sharing the same DEK material cannot collide their
/// counters. The value is captured at `Dek` construction and is
/// immutable for the lifetime of the key (L0 A11 pure compute);
/// changing it later would surface in the WAL as different ciphertext
/// bytes and therefore must ship behind a manifest-anchored policy
/// event when the federation activation lands.
#[cfg_attr(not(feature = "tier-2-multi-kms"), allow(dead_code))]
#[inline]
fn aes_gcm_nonce_from_counter(replica_id: u32, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&replica_id.to_be_bytes());
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    n
}

impl core::fmt::Debug for Dek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.debug_struct("Dek").finish_non_exhaustive()
    }
}

// ===================== EncryptedPii =====================

/// Per-AEAD-kind nonce carrier — XChaCha20-Poly1305 uses 24 bytes, the
/// AES-256-GCM family uses 12. A single variant enum keeps the on-wire
/// layout round-trip stable under postcard. Variants use postcard's
/// default untagged discriminant (enum index byte).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NonceBytes {
    /// 24-byte nonce — `XChaCha20-Poly1305`.
    X24([u8; 24]),
    /// 12-byte nonce — `AES-256-GCM` / `AES-256-GCM-SIV`.
    Short12([u8; 12]),
}

impl NonceBytes {
    /// Expected length for the given `AeadKind`. Forward-compat unknown
    /// variants map to `0` so callers can catch the mismatch as
    /// [`PiiError::UnsupportedAead`].
    #[inline]
    #[must_use]
    pub fn expected_len(kind: AeadKind) -> usize {
        match kind {
            AeadKind::XChaCha20Poly1305 => 24,
            AeadKind::Aes256Gcm | AeadKind::Aes256GcmSiv => 12,
            _ => 0,
        }
    }

    /// Returns the nonce bytes as a slice regardless of variant.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::X24(b) => b,
            Self::Short12(b) => b,
        }
    }
}

/// Per-PII-marker ciphertext envelope.
///
/// The wire shape is
/// `(dek_id, pii_code, aead_kind, nonce, ciphertext_with_tag)` —
/// every input to the AEAD AAD is mirrored on the envelope so the
/// receiver can recompute the 19-byte AAD exactly. `ciphertext`
/// includes the 16-byte Poly1305 / GCM tag appended by the AEAD
/// primitive.
///
/// The generic parameter `T` is a *phantom* — the wire layout is purely
/// data-bearing, and a manual (de)serialize impl threads around the
/// `PhantomData` so postcard can round-trip the struct.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedPii<T: PiiType> {
    /// HSM/KMS key reference.
    pub dek_id: DekId,
    /// Wire tag. Validated against `T::PII_CODE` at
    /// decrypt time.
    pub pii_code: u16,
    /// AEAD family used for the ciphertext.
    pub aead_kind: AeadKind,
    /// Nonce — length varies per AEAD kind.
    pub nonce: NonceBytes,
    /// Ciphertext with the 16-byte AEAD tag appended.
    pub ciphertext: Bytes,
    pub(crate) _marker: PhantomData<fn() -> T>,
}

// Manual Clone — `T` carries no data on the envelope (the PhantomData is
// `fn() -> T` for variance), so cloning never calls into `T::clone`.
impl<T: PiiType> Clone for EncryptedPii<T> {
    fn clone(&self) -> Self {
        Self {
            dek_id: self.dek_id,
            pii_code: self.pii_code,
            aead_kind: self.aead_kind,
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            _marker: PhantomData,
        }
    }
}

/// Data-only mirror of [`EncryptedPii`] — used as the serde surface so
/// the generic phantom does not reach the wire.
#[derive(Serialize, Deserialize)]
struct EncryptedPiiWire {
    dek_id: DekId,
    pii_code: u16,
    aead_kind: AeadKind,
    nonce: NonceBytes,
    ciphertext: Bytes,
}

impl<T: PiiType> Serialize for EncryptedPii<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EncryptedPiiWire {
            dek_id: self.dek_id,
            pii_code: self.pii_code,
            aead_kind: self.aead_kind,
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de, T: PiiType> Deserialize<'de> for EncryptedPii<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EncryptedPiiWire::deserialize(deserializer)?;
        Ok(Self {
            dek_id: wire.dek_id,
            pii_code: wire.pii_code,
            aead_kind: wire.aead_kind,
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
            _marker: PhantomData,
        })
    }
}

impl<T: PiiType> EncryptedPii<T> {
    /// Construct from components — intended for deserialization paths /
    /// tests that need to reassemble a postcard-decoded envelope into
    /// its typed form. Encryption path callers use
    /// [`CryptoCoordinator::encrypt`].
    #[inline]
    #[must_use]
    pub fn new(dek_id: DekId, aead_kind: AeadKind, nonce: NonceBytes, ciphertext: Bytes) -> Self {
        Self {
            dek_id,
            pii_code: T::PII_CODE,
            aead_kind,
            nonce,
            ciphertext,
            _marker: PhantomData,
        }
    }
}

// ===================== CryptoCoordinator =====================

/// Tier-1+ AEAD coordinator.
///
/// The coordinator carries the shell-declared `AeadKind` (from
/// `[audit.pii_cipher]`) plus an opaque `nonce_source` the caller
/// supplies so tests and production paths can share the same
/// dispatcher. Tier-0 (default feature set) consumers may still
/// instantiate a coordinator — every mutating call returns
/// [`PiiError::TierTooLow`].
#[derive(Debug)]
pub struct CryptoCoordinator<N: NonceSource = OsNonceSource> {
    manifest_cipher: AeadKind,
    // Only consumed by the XChaCha20-Poly1305 (tier-1-kms) path — the
    // AES-GCM(-SIV) paths use a DEK-local deterministic counter (NIST
    // SP 800-38D §8.2.1) rather than the nonce source.
    #[cfg_attr(not(feature = "tier-1-kms"), allow(dead_code))]
    nonce_source: N,
}

/// Per-kind nonce generator. Production uses [`OsNonceSource`] (the
/// `getrandom` syscall wrapper baked into the AEAD crates). Tests plug
/// in a fixed value for bit-identical fixtures.
pub trait NonceSource {
    /// Fill `out` with `len` fresh nonce bytes. `len` matches
    /// [`NonceBytes::expected_len`] for the active AEAD kind; panics /
    /// short writes are illegal — return an error via the caller's
    /// wrapper if needed.
    fn fill(&self, out: &mut [u8]);
}

/// OS-backed nonce source. On `tier-1-kms` / `tier-2-multi-kms` this
/// pulls from the underlying AEAD crate's default RNG hook (itself
/// `getrandom`-backed). On the default feature set it is still
/// constructible — encryption paths reject before the nonce source is
/// consulted.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsNonceSource;

impl NonceSource for OsNonceSource {
    #[cfg(feature = "tier-1-kms")]
    fn fill(&self, out: &mut [u8]) {
        use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
        OsRng.fill_bytes(out);
    }

    #[cfg(not(feature = "tier-1-kms"))]
    fn fill(&self, out: &mut [u8]) {
        // No crypto feature active — zero-fill. Encrypt paths reject
        // before the nonce is read, so the value is never observed.
        for byte in out.iter_mut() {
            *byte = 0;
        }
    }
}

impl<N: NonceSource> CryptoCoordinator<N> {
    /// Construct a coordinator that enforces `manifest_cipher` at the
    /// encrypt / decrypt boundary.
    #[inline]
    #[must_use]
    pub fn new(manifest_cipher: AeadKind, nonce_source: N) -> Self {
        Self {
            manifest_cipher,
            nonce_source,
        }
    }

    /// Borrow the manifest-declared cipher.
    #[inline]
    #[must_use]
    pub fn manifest_cipher(&self) -> AeadKind {
        self.manifest_cipher
    }

    /// AEAD-encrypt a PII payload under the given DEK. The 19-byte AAD
    /// is computed from `(dek_id, T::PII_CODE, manifest_cipher)` so a
    /// downstream decrypt call with a tampered envelope fails the tag
    /// check.
    pub fn encrypt<T: PiiType>(
        &self,
        plaintext: &T,
        dek: &Dek,
        dek_id: DekId,
    ) -> Result<EncryptedPii<T>, PiiError> {
        let aad = compute_aad(&dek_id, T::PII_CODE, self.manifest_cipher);
        let pt_bytes = postcard::to_stdvec(plaintext).map_err(|_| PiiError::EncryptFailed)?;
        let (nonce, ciphertext) = self.encrypt_raw(dek, &aad, &pt_bytes)?;
        Ok(EncryptedPii::new(
            dek_id,
            self.manifest_cipher,
            nonce,
            Bytes::from(ciphertext),
        ))
    }

    /// Inverse of [`CryptoCoordinator::encrypt`]. Checks the wire PII
    /// marker, refuses cipher downgrades, then verifies the AEAD tag
    /// against a recomputed AAD.
    pub fn decrypt<T: PiiType>(
        &self,
        envelope: &EncryptedPii<T>,
        dek: &Dek,
    ) -> Result<T, PiiError> {
        if envelope.pii_code != T::PII_CODE {
            return Err(PiiError::TypeMismatch);
        }
        if envelope.aead_kind != self.manifest_cipher {
            return Err(PiiError::CipherDowngrade);
        }
        let aad = compute_aad(&envelope.dek_id, envelope.pii_code, envelope.aead_kind);
        let pt = self.decrypt_raw(
            dek,
            envelope.aead_kind,
            &envelope.nonce,
            &aad,
            &envelope.ciphertext,
        )?;
        postcard::from_bytes::<T>(&pt).map_err(|_| PiiError::DecodeFailed)
    }

    /// Variant of [`CryptoCoordinator::decrypt`] that tolerates a
    /// legacy `AeadKind` — used by the DEK rotation path so a slice of
    /// ciphertexts written under an older manifest `pii_cipher` can be
    /// migrated in place. Borrows the envelope directly (no per-element
    /// clone); the manifest downgrade check is bypassed (equivalence
    /// relation anchored to the envelope's own `aead_kind`).
    fn decrypt_raw_under<T: PiiType>(
        &self,
        dek: &Dek,
        envelope: &EncryptedPii<T>,
    ) -> Result<Vec<u8>, PiiError> {
        let aad = compute_aad(&envelope.dek_id, envelope.pii_code, envelope.aead_kind);
        self.decrypt_raw(
            dek,
            envelope.aead_kind,
            &envelope.nonce,
            &aad,
            &envelope.ciphertext,
        )
    }

    fn encrypt_raw(
        &self,
        dek: &Dek,
        aad: &[u8; 19],
        plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        match self.manifest_cipher {
            AeadKind::XChaCha20Poly1305 => self.encrypt_xchacha(dek, aad, plaintext),
            AeadKind::Aes256Gcm => self.encrypt_aes_gcm(dek, aad, plaintext),
            AeadKind::Aes256GcmSiv => self.encrypt_aes_gcm_siv(dek, aad, plaintext),
            _ => Err(PiiError::UnsupportedAead),
        }
    }

    fn decrypt_raw(
        &self,
        dek: &Dek,
        kind: AeadKind,
        nonce: &NonceBytes,
        aad: &[u8; 19],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        match kind {
            AeadKind::XChaCha20Poly1305 => self.decrypt_xchacha(dek, nonce, aad, ciphertext),
            AeadKind::Aes256Gcm => self.decrypt_aes_gcm(dek, nonce, aad, ciphertext),
            AeadKind::Aes256GcmSiv => self.decrypt_aes_gcm_siv(dek, nonce, aad, ciphertext),
            _ => Err(PiiError::UnsupportedAead),
        }
    }

    // ----- XChaCha20-Poly1305 — tier-1-kms gated -----

    #[cfg(feature = "tier-1-kms")]
    fn encrypt_xchacha(
        &self,
        dek: &Dek,
        aad: &[u8; 19],
        plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

        let key = Key::from_slice(dek.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let mut nonce_buf = [0u8; 24];
        self.nonce_source.fill(&mut nonce_buf);
        let nonce = XNonce::from_slice(&nonce_buf);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| PiiError::EncryptFailed)?;
        Ok((NonceBytes::X24(nonce_buf), ciphertext))
    }

    #[cfg(not(feature = "tier-1-kms"))]
    fn encrypt_xchacha(
        &self,
        _dek: &Dek,
        _aad: &[u8; 19],
        _plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        Err(PiiError::TierTooLow)
    }

    #[cfg(feature = "tier-1-kms")]
    fn decrypt_xchacha(
        &self,
        dek: &Dek,
        nonce: &NonceBytes,
        aad: &[u8; 19],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

        let bytes_24 = match nonce {
            NonceBytes::X24(b) => b,
            NonceBytes::Short12(_) => return Err(PiiError::AadMismatch),
        };
        let key = Key::from_slice(dek.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XNonce::from_slice(bytes_24);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| PiiError::AadMismatch)
    }

    #[cfg(not(feature = "tier-1-kms"))]
    fn decrypt_xchacha(
        &self,
        _dek: &Dek,
        _nonce: &NonceBytes,
        _aad: &[u8; 19],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        Err(PiiError::TierTooLow)
    }

    // ----- AES-256-GCM — tier-2-multi-kms gated -----

    #[cfg(feature = "tier-2-multi-kms")]
    fn encrypt_aes_gcm(
        &self,
        dek: &Dek,
        aad: &[u8; 19],
        plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Nonce-reuse guard — a long-lived (KMS-unwrapped) DEK resets its
        // counter to 0 on every reconstruction, so plain AES-256-GCM would
        // reuse nonces under a fixed key (catastrophic). Reject; such DEKs
        // must use the misuse-resistant SIV path.
        if dek.lifecycle() == DekLifecycle::LongLived {
            return Err(PiiError::NonceReuseRisk);
        }

        // Deterministic counter nonce (NIST SP 800-38D §8.2.1). Counter
        // exhaustion is surfaced by `advance_counter` before any AEAD
        // work starts, so a failed call never consumes a nonce value.
        let counter = dek.advance_counter()?;
        let nonce_buf = aes_gcm_nonce_from_counter(dek.replica_id, counter);
        let key = Key::<Aes256Gcm>::from_slice(dek.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_buf);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| PiiError::EncryptFailed)?;
        Ok((NonceBytes::Short12(nonce_buf), ciphertext))
    }

    #[cfg(not(feature = "tier-2-multi-kms"))]
    fn encrypt_aes_gcm(
        &self,
        _dek: &Dek,
        _aad: &[u8; 19],
        _plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        Err(PiiError::UnsupportedAead)
    }

    #[cfg(feature = "tier-2-multi-kms")]
    fn decrypt_aes_gcm(
        &self,
        dek: &Dek,
        nonce: &NonceBytes,
        aad: &[u8; 19],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let bytes_12 = match nonce {
            NonceBytes::Short12(b) => b,
            NonceBytes::X24(_) => return Err(PiiError::AadMismatch),
        };
        let key = Key::<Aes256Gcm>::from_slice(dek.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(bytes_12);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| PiiError::AadMismatch)
    }

    #[cfg(not(feature = "tier-2-multi-kms"))]
    fn decrypt_aes_gcm(
        &self,
        _dek: &Dek,
        _nonce: &NonceBytes,
        _aad: &[u8; 19],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        Err(PiiError::UnsupportedAead)
    }

    // ----- AES-256-GCM-SIV — tier-2-multi-kms gated -----

    #[cfg(feature = "tier-2-multi-kms")]
    fn encrypt_aes_gcm_siv(
        &self,
        dek: &Dek,
        aad: &[u8; 19],
        plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
        use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};

        // Deterministic counter nonce — AES-GCM-SIV already tolerates
        // nonce reuse but the counter construction removes the chance
        // entirely under single-writer (L0 A2) semantics.
        let counter = dek.advance_counter()?;
        let nonce_buf = aes_gcm_nonce_from_counter(dek.replica_id, counter);
        let key = Key::<Aes256GcmSiv>::from_slice(dek.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(&nonce_buf);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| PiiError::EncryptFailed)?;
        Ok((NonceBytes::Short12(nonce_buf), ciphertext))
    }

    #[cfg(not(feature = "tier-2-multi-kms"))]
    fn encrypt_aes_gcm_siv(
        &self,
        _dek: &Dek,
        _aad: &[u8; 19],
        _plaintext: &[u8],
    ) -> Result<(NonceBytes, Vec<u8>), PiiError> {
        Err(PiiError::UnsupportedAead)
    }

    #[cfg(feature = "tier-2-multi-kms")]
    fn decrypt_aes_gcm_siv(
        &self,
        dek: &Dek,
        nonce: &NonceBytes,
        aad: &[u8; 19],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
        use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};

        let bytes_12 = match nonce {
            NonceBytes::Short12(b) => b,
            NonceBytes::X24(_) => return Err(PiiError::AadMismatch),
        };
        let key = Key::<Aes256GcmSiv>::from_slice(dek.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(bytes_12);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| PiiError::AadMismatch)
    }

    #[cfg(not(feature = "tier-2-multi-kms"))]
    fn decrypt_aes_gcm_siv(
        &self,
        _dek: &Dek,
        _nonce: &NonceBytes,
        _aad: &[u8; 19],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, PiiError> {
        Err(PiiError::UnsupportedAead)
    }
}

// ===================== DEK rotation =====================

/// Re-wrap every element of `ciphertexts` under `new_dek` using a fresh
/// `new_dek_id`. Decrypts under `old_dek` first, re-encrypts under the
/// new key material, and rolls the slice back if any element fails
/// (atomic-per-call semantics).
///
/// Callers must hold a single-writer lock across the slice while this
/// helper runs — the coordinator does not expose its own synchronisation.
/// The update also ticks `counter` (by the slice length) so the operator
/// can observe the per-DEK rotation metric. On a partial-failure rollback
/// the `counter` is restored to its entry value alongside the ciphertexts,
/// so the metric always matches the slice state.
pub fn rotate_dek<T: PiiType>(
    coordinator: &CryptoCoordinator<impl NonceSource>,
    old_dek: &Dek,
    new_dek: &Dek,
    new_dek_id: DekId,
    ciphertexts: &mut [EncryptedPii<T>],
    counter: &mut DekMessageCounter,
) -> Result<(), PiiError> {
    let originals: Vec<EncryptedPii<T>> = ciphertexts.to_vec();
    // Snapshot the rotation metric so a rollback restores it in lockstep
    // with the ciphertexts — otherwise the metric would over-count the
    // elements re-encrypted before the failing one.
    let counter_snapshot = counter.clone();
    let aad = compute_aad(&new_dek_id, T::PII_CODE, coordinator.manifest_cipher);
    // Index-based loop so the rollback can re-borrow the slice mutably
    // without conflicting with a held element borrow.
    for idx in 0..ciphertexts.len() {
        let step = coordinator
            .decrypt_raw_under(old_dek, &ciphertexts[idx])
            .and_then(|plaintext_bytes| coordinator.encrypt_raw(new_dek, &aad, &plaintext_bytes));
        match step {
            Ok((nonce, new_ct)) => {
                ciphertexts[idx] = EncryptedPii::new(
                    new_dek_id,
                    coordinator.manifest_cipher,
                    nonce,
                    Bytes::from(new_ct),
                );
                counter.record_message();
            }
            Err(err) => {
                for (target, backup) in ciphertexts.iter_mut().zip(originals.iter()) {
                    *target = backup.clone();
                }
                *counter = counter_snapshot;
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Helper — extract the rotation trigger for a post-rotation counter.
#[inline]
#[must_use]
pub fn rotation_advice(counter: &DekMessageCounter) -> RotationTrigger {
    counter.rotation_trigger()
}

// ===================== Tests =====================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use arkhe_forge_core::pii::ActorHandle;

    #[derive(Clone, Copy, Default)]
    struct FixedNonce;

    impl NonceSource for FixedNonce {
        fn fill(&self, out: &mut [u8]) {
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = (i & 0xFF) as u8;
            }
        }
    }

    fn make_dek(byte: u8) -> Dek {
        Dek::from_bytes([byte; 32])
    }

    fn make_dek_id(byte: u8) -> DekId {
        DekId([byte; 16])
    }

    #[test]
    fn dek_from_bytes_exposes_material_via_crate_accessor() {
        let d = make_dek(0x42);
        assert_eq!(d.as_bytes(), &[0x42u8; 32]);
    }

    #[test]
    fn dek_try_from_slice_rejects_short_key() {
        let err = Dek::try_from_slice(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, PiiError::InvalidKeyLength));
    }

    #[test]
    fn dek_try_from_slice_accepts_32_bytes() {
        let key = [0x77u8; 32];
        let dek = Dek::try_from_slice(&key).unwrap();
        assert_eq!(dek.as_bytes(), &key);
    }

    #[test]
    fn dek_debug_does_not_expose_material() {
        let d = make_dek(0xAB);
        let s = format!("{:?}", d);
        assert!(!s.contains("AB"), "Debug output must not leak key bytes");
        assert!(!s.contains("ab"));
    }

    #[test]
    fn nonce_bytes_expected_len_matches_kind() {
        assert_eq!(NonceBytes::expected_len(AeadKind::XChaCha20Poly1305), 24);
        assert_eq!(NonceBytes::expected_len(AeadKind::Aes256Gcm), 12);
        assert_eq!(NonceBytes::expected_len(AeadKind::Aes256GcmSiv), 12);
    }

    #[test]
    fn encrypted_pii_wire_layout_roundtrips_through_postcard() {
        let envelope = EncryptedPii::<ActorHandle>::new(
            make_dek_id(0x11),
            AeadKind::XChaCha20Poly1305,
            NonceBytes::X24([0x22; 24]),
            Bytes::from_static(&[0x33; 48]),
        );
        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let back: EncryptedPii<ActorHandle> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(envelope, back);
        assert_eq!(back.pii_code, ActorHandle::PII_CODE);
    }

    // --- Default (Tier-0) — encryption is rejected across the board. ---

    #[cfg(not(feature = "tier-1-kms"))]
    #[test]
    fn tier0_default_rejects_encryption() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let err = coord
            .encrypt::<ActorHandle>(
                &ActorHandle(b"alice".to_vec()),
                &make_dek(0x00),
                make_dek_id(0x11),
            )
            .unwrap_err();
        assert!(matches!(err, PiiError::TierTooLow));
    }

    // --- tier-1-kms — XChaCha20-Poly1305 round trip. ---

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn tier1_xchacha_encrypt_decrypt_roundtrip() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let handle = ActorHandle(b"alice".to_vec());
        let dek = make_dek(0xA5);
        let dek_id = make_dek_id(0x11);
        let env = coord.encrypt(&handle, &dek, dek_id).unwrap();
        assert_eq!(env.aead_kind, AeadKind::XChaCha20Poly1305);
        assert_eq!(env.pii_code, ActorHandle::PII_CODE);
        let back: ActorHandle = coord.decrypt(&env, &dek).unwrap();
        assert_eq!(back, handle);
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn tier1_xchacha_aad_tamper_fails_tag() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let handle = ActorHandle(b"alice".to_vec());
        let dek = make_dek(0x01);
        let mut env = coord.encrypt(&handle, &dek, make_dek_id(0x11)).unwrap();
        // Tamper with the dek_id on the envelope — AAD recompute changes,
        // tag verification must fail.
        env.dek_id = make_dek_id(0x12);
        let err = coord.decrypt::<ActorHandle>(&env, &dek).unwrap_err();
        assert!(matches!(err, PiiError::AadMismatch));
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn tier1_ciphertext_tamper_fails_tag() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let handle = ActorHandle(b"alice".to_vec());
        let dek = make_dek(0x03);
        let env = coord.encrypt(&handle, &dek, make_dek_id(0x11)).unwrap();
        let mut ct = env.ciphertext.to_vec();
        if let Some(first) = ct.first_mut() {
            *first ^= 0x01;
        }
        let tampered =
            EncryptedPii::<ActorHandle>::new(env.dek_id, env.aead_kind, env.nonce, Bytes::from(ct));
        let err = coord.decrypt::<ActorHandle>(&tampered, &dek).unwrap_err();
        assert!(matches!(err, PiiError::AadMismatch));
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn tier1_wrong_pii_code_rejected_as_type_mismatch() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let handle = ActorHandle(b"alice".to_vec());
        let dek = make_dek(0x07);
        let env = coord.encrypt(&handle, &dek, make_dek_id(0x11)).unwrap();
        // Overwrite pii_code with a different marker. decrypt::<ActorHandle>
        // spots the mismatch without touching AEAD.
        let wrong = EncryptedPii::<ActorHandle> {
            dek_id: env.dek_id,
            pii_code: arkhe_forge_core::pii::EntryBody::PII_CODE,
            aead_kind: env.aead_kind,
            nonce: env.nonce,
            ciphertext: env.ciphertext,
            _marker: PhantomData,
        };
        let err = coord.decrypt::<ActorHandle>(&wrong, &dek).unwrap_err();
        assert!(matches!(err, PiiError::TypeMismatch));
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn tier1_aead_downgrade_rejected_by_coordinator_manifest() {
        // Coordinator is pinned to XChaCha20-Poly1305; envelope is written
        // with AES-GCM. decrypt must refuse.
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let env = EncryptedPii::<ActorHandle>::new(
            make_dek_id(0x11),
            AeadKind::Aes256Gcm,
            NonceBytes::Short12([0u8; 12]),
            Bytes::from_static(&[0u8; 48]),
        );
        let err = coord
            .decrypt::<ActorHandle>(&env, &make_dek(0x00))
            .unwrap_err();
        assert!(matches!(err, PiiError::CipherDowngrade));
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn tier1_aes_gcm_without_tier2_is_unsupported() {
        // Coordinator is pinned to AES-GCM; under tier-1 only, encrypt
        // must surface UnsupportedAead.
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let handle = ActorHandle(b"alice".to_vec());
        let out = coord.encrypt(&handle, &make_dek(0x00), make_dek_id(0x11));
        #[cfg(feature = "tier-2-multi-kms")]
        assert!(out.is_ok());
        #[cfg(not(feature = "tier-2-multi-kms"))]
        assert!(matches!(out, Err(PiiError::UnsupportedAead)));
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn tier2_aes_gcm_roundtrip() {
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let handle = ActorHandle(b"aes-user".to_vec());
        let dek = make_dek(0x5A);
        let env = coord.encrypt(&handle, &dek, make_dek_id(0x21)).unwrap();
        assert_eq!(env.aead_kind, AeadKind::Aes256Gcm);
        assert!(matches!(env.nonce, NonceBytes::Short12(_)));
        let back: ActorHandle = coord.decrypt(&env, &dek).unwrap();
        assert_eq!(back, handle);
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn tier2_aes_gcm_siv_roundtrip() {
        let coord = CryptoCoordinator::new(AeadKind::Aes256GcmSiv, FixedNonce);
        let handle = ActorHandle(b"aes-siv-user".to_vec());
        let dek = make_dek(0x7B);
        let env = coord.encrypt(&handle, &dek, make_dek_id(0x22)).unwrap();
        assert_eq!(env.aead_kind, AeadKind::Aes256GcmSiv);
        let back: ActorHandle = coord.decrypt(&env, &dek).unwrap();
        assert_eq!(back, handle);
    }

    /// #3 regression — a long-lived (KMS-unwrapped) DEK MUST be refused on
    /// the plain AES-256-GCM path. The deterministic counter resets to 0 on
    /// every reconstruction, so plain GCM would reuse nonces under a fixed
    /// key. The guard rejects with `NonceReuseRisk`.
    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn long_lived_dek_rejected_under_plain_aes_gcm() {
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let dek = Dek::from_unwrapped([0x9C; 32], DekConfig::default());
        assert_eq!(dek.lifecycle(), DekLifecycle::LongLived);
        let handle = ActorHandle(b"long-lived".to_vec());
        let out = coord.encrypt(&handle, &dek, make_dek_id(0x31));
        assert!(
            matches!(out, Err(PiiError::NonceReuseRisk)),
            "long-lived DEK must be refused under plain AES-256-GCM",
        );
    }

    /// #3 regression — under SIV, a long-lived DEK reconstructed twice (each
    /// reconstruction resets the counter to 0, so both encrypts use the SAME
    /// nonce) does NOT catastrophically leak: SIV is nonce-misuse-resistant,
    /// so identical (key, nonce, aad, plaintext) yields identical ciphertext
    /// (deterministic, safe) and each round-trips correctly. This is the
    /// smallest cure that keeps deterministic replay intact.
    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn long_lived_dek_under_siv_survives_counter_reset() {
        let coord = CryptoCoordinator::new(AeadKind::Aes256GcmSiv, FixedNonce);
        let handle = ActorHandle(b"siv-survivor".to_vec());

        // First process incarnation.
        let dek1 = Dek::from_unwrapped([0xA1; 32], DekConfig::default());
        let env1 = coord.encrypt(&handle, &dek1, make_dek_id(0x41)).unwrap();
        assert_eq!(env1.aead_kind, AeadKind::Aes256GcmSiv);

        // Second incarnation — same material, counter reset to 0 → SAME nonce.
        let dek2 = Dek::from_unwrapped([0xA1; 32], DekConfig::default());
        let env2 = coord.encrypt(&handle, &dek2, make_dek_id(0x41)).unwrap();

        let NonceBytes::Short12(n1) = &env1.nonce else {
            panic!("SIV returns Short12");
        };
        let NonceBytes::Short12(n2) = &env2.nonce else {
            panic!("SIV returns Short12");
        };
        assert_eq!(n1, n2, "counter reset reproduces the same nonce");
        // SIV determinism: same (key, nonce, aad, plaintext) → same ciphertext.
        // Under plain GCM this nonce reuse would be catastrophic; under SIV it
        // is merely a deterministic re-encryption that still round-trips.
        assert_eq!(
            env1.ciphertext, env2.ciphertext,
            "SIV is deterministic; reuse is non-catastrophic",
        );
        assert_eq!(coord.decrypt::<ActorHandle>(&env1, &dek2).unwrap(), handle);
        assert_eq!(coord.decrypt::<ActorHandle>(&env2, &dek1).unwrap(), handle);
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn aes_gcm_nonce_is_deterministic_counter() {
        // First two encrypts under the same DEK must produce nonces 0
        // and 1 in the 8-byte big-endian counter tail; the 4-byte
        // invocation field is zero for the single-writer deployment.
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let dek = make_dek(0x5A);
        let handle = ActorHandle(b"alice".to_vec());

        let env1 = coord.encrypt(&handle, &dek, make_dek_id(0x11)).unwrap();
        let env2 = coord.encrypt(&handle, &dek, make_dek_id(0x11)).unwrap();

        let NonceBytes::Short12(n1) = &env1.nonce else {
            panic!("AES-GCM always returns Short12");
        };
        let NonceBytes::Short12(n2) = &env2.nonce else {
            panic!("AES-GCM always returns Short12");
        };
        assert_eq!(&n1[0..4], &[0u8; 4], "invocation field zeros");
        assert_eq!(&n1[4..12], &0u64.to_be_bytes());
        assert_eq!(&n2[4..12], &1u64.to_be_bytes());
        assert_ne!(n1, n2);

        // Round-trip still holds under the new construction.
        assert_eq!(coord.decrypt::<ActorHandle>(&env1, &dek).unwrap(), handle);
        assert_eq!(coord.decrypt::<ActorHandle>(&env2, &dek).unwrap(), handle);
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn aes_gcm_nonce_honours_dek_replica_id() {
        // Federation path — a non-zero `replica_id` must appear as the
        // 4-byte invocation field prefix of the nonce. Two DEKs with
        // identical material but distinct replica ids produce
        // disjoint nonce spaces (0-counter slot differs).
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let dek_a = Dek::with_config([0xC3; 32], DekConfig { replica_id: 0 });
        let dek_b = Dek::with_config(
            [0xC3; 32],
            DekConfig {
                replica_id: 0xDEAD_BEEF,
            },
        );
        let handle = ActorHandle(b"alice".to_vec());

        let env_a = coord.encrypt(&handle, &dek_a, make_dek_id(0x11)).unwrap();
        let env_b = coord.encrypt(&handle, &dek_b, make_dek_id(0x11)).unwrap();

        let NonceBytes::Short12(na) = &env_a.nonce else {
            panic!("AES-GCM returns Short12");
        };
        let NonceBytes::Short12(nb) = &env_b.nonce else {
            panic!("AES-GCM returns Short12");
        };
        assert_eq!(&na[0..4], &0u32.to_be_bytes());
        assert_eq!(&nb[0..4], &0xDEAD_BEEFu32.to_be_bytes());
        // Counter portion is the same (both at position 0) but the
        // full nonce differs because of the replica id prefix.
        assert_eq!(&na[4..12], &0u64.to_be_bytes());
        assert_eq!(&nb[4..12], &0u64.to_be_bytes());
        assert_ne!(na, nb);
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn aes_gcm_siv_nonce_is_deterministic_counter() {
        // SIV path also consumes the DEK counter — defence-in-depth
        // despite AES-GCM-SIV's own nonce-reuse resistance.
        let coord = CryptoCoordinator::new(AeadKind::Aes256GcmSiv, FixedNonce);
        let dek = make_dek(0x7B);
        let handle = ActorHandle(b"siv".to_vec());

        let env1 = coord.encrypt(&handle, &dek, make_dek_id(0x22)).unwrap();
        let NonceBytes::Short12(n1) = &env1.nonce else {
            panic!("AES-GCM-SIV returns Short12");
        };
        assert_eq!(&n1[4..12], &0u64.to_be_bytes());
        assert_eq!(dek.get_counter_for_test(), 1);
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn dek_counter_exhaustion_errors() {
        // Counter at u64::MAX rejects further encryption — no nonce is
        // consumed, operator must rotate.
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let dek = make_dek(0xA5);
        dek.set_counter_for_test(u64::MAX);

        let handle = ActorHandle(b"alice".to_vec());
        let err = coord.encrypt(&handle, &dek, make_dek_id(0x11)).unwrap_err();
        assert!(matches!(err, PiiError::DekExhausted));
        // Counter unchanged — failed call did not advance.
        assert_eq!(dek.get_counter_for_test(), u64::MAX);
    }

    #[cfg(feature = "tier-2-multi-kms")]
    #[test]
    fn rotate_dek_starts_new_counter_from_zero() {
        // `rotate_dek` decrypts under the old DEK (no counter use) and
        // re-encrypts under the new DEK (counter advances 0..N). After
        // rotating N elements the new DEK's counter reflects exactly N.
        let coord = CryptoCoordinator::new(AeadKind::Aes256Gcm, FixedNonce);
        let old = make_dek(0x10);
        let new = make_dek(0x20);
        let new_id = make_dek_id(0x02);

        let plaintexts: Vec<ActorHandle> = (0..3u8).map(|i| ActorHandle(vec![i; 8])).collect();
        let mut envs: Vec<EncryptedPii<ActorHandle>> = plaintexts
            .iter()
            .map(|pt| coord.encrypt(pt, &old, make_dek_id(0x01)).unwrap())
            .collect();
        assert_eq!(old.get_counter_for_test(), 3);
        assert_eq!(new.get_counter_for_test(), 0);

        let mut rotation_metric = DekMessageCounter::new(new_id);
        rotate_dek(&coord, &old, &new, new_id, &mut envs, &mut rotation_metric).unwrap();

        assert_eq!(new.get_counter_for_test(), 3);
        assert_eq!(rotation_metric.count(), 3);
        for (i, env) in envs.iter().enumerate() {
            let NonceBytes::Short12(n) = &env.nonce else {
                panic!("AES-GCM returns Short12");
            };
            assert_eq!(
                &n[4..12],
                &(i as u64).to_be_bytes(),
                "counter values run 0,1,2 under new DEK"
            );
        }
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn dek_rotate_preserves_plaintext() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let old = make_dek(0x10);
        let new = make_dek(0x20);
        let new_id = make_dek_id(0x02);
        let plaintexts: Vec<ActorHandle> = (0..4u8).map(|i| ActorHandle(vec![i; 8])).collect();
        let mut envelopes: Vec<EncryptedPii<ActorHandle>> = plaintexts
            .iter()
            .map(|pt| coord.encrypt(pt, &old, make_dek_id(0x01)).unwrap())
            .collect();
        let mut counter = DekMessageCounter::new(make_dek_id(0x02));
        rotate_dek(&coord, &old, &new, new_id, &mut envelopes, &mut counter).unwrap();
        assert_eq!(counter.count(), 4);
        for (env, pt) in envelopes.iter().zip(plaintexts.iter()) {
            assert_eq!(env.dek_id, new_id);
            assert_eq!(&coord.decrypt::<ActorHandle>(env, &new).unwrap(), pt);
        }
    }

    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn dek_rotate_with_wrong_old_key_rolls_back() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let real_old = make_dek(0x10);
        let wrong_old = make_dek(0xFF);
        let new = make_dek(0x20);
        let original_envelope = coord
            .encrypt(
                &ActorHandle(b"alice".to_vec()),
                &real_old,
                make_dek_id(0x01),
            )
            .unwrap();
        let mut envelopes = vec![original_envelope.clone()];
        let mut counter = DekMessageCounter::new(make_dek_id(0x02));
        let err = rotate_dek(
            &coord,
            &wrong_old,
            &new,
            make_dek_id(0x02),
            &mut envelopes,
            &mut counter,
        )
        .unwrap_err();
        assert!(matches!(err, PiiError::AadMismatch));
        // Slice rolled back — original envelope intact.
        assert_eq!(envelopes[0], original_envelope);
    }

    /// #9 regression — a partial-failure rollback must restore the
    /// `DekMessageCounter` to its entry value, not leave it counting the
    /// elements re-encrypted before the failing one. Element 0 rotates
    /// (counter would tick to 1), element 1 has a corrupted ciphertext so
    /// its decrypt fails; the rollback must restore both the slice AND the
    /// counter so the metric matches the rolled-back (untouched) state.
    #[cfg(feature = "tier-1-kms")]
    #[test]
    fn dek_rotate_partial_failure_rolls_back_counter() {
        let coord = CryptoCoordinator::new(AeadKind::XChaCha20Poly1305, FixedNonce);
        let old = make_dek(0x10);
        let new = make_dek(0x20);
        let new_id = make_dek_id(0x02);

        let good = coord
            .encrypt(&ActorHandle(b"first".to_vec()), &old, make_dek_id(0x01))
            .unwrap();
        // Corrupt a copy so its decrypt under `old` fails the tag check —
        // forces a rollback after element 0 has already been processed.
        let mut corrupt_ct = good.ciphertext.to_vec();
        corrupt_ct[0] ^= 0xFF;
        let corrupt = EncryptedPii::<ActorHandle>::new(
            good.dek_id,
            good.aead_kind,
            good.nonce.clone(),
            Bytes::from(corrupt_ct),
        );
        let mut envelopes = vec![good.clone(), corrupt.clone()];

        // Pre-tick the counter so we can prove the snapshot is the *entry*
        // value, not a fresh zero.
        let mut counter = DekMessageCounter::new(new_id);
        counter.record_message();
        counter.record_message();
        let entry_count = counter.count();
        assert_eq!(entry_count, 2);

        let err = rotate_dek(&coord, &old, &new, new_id, &mut envelopes, &mut counter).unwrap_err();
        assert!(matches!(err, PiiError::AadMismatch));
        // Ciphertexts rolled back.
        assert_eq!(envelopes[0], good);
        assert_eq!(envelopes[1], corrupt);
        // Counter restored to its entry value — element 0's tick is undone.
        assert_eq!(counter.count(), entry_count);
    }
}
