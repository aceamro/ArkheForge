//! `runtime_doctor_journal` chain-signed persistence — audit-log
//! tamper-resistance.
//!
//! Each [`JournalEntry`] links to its predecessor through a BLAKE3 chain
//! hash and carries an Ed25519 signature over that hash; readers verify the
//! whole log with [`PersistentJournal::verify_chain`] — a single tamper
//! surfaces as [`JournalError::ChainIntegrity`] or
//! [`JournalError::SignatureInvalid`].
//!
//! # Layering
//!
//! - [`ConsumedToken`] — the audit payload (Shamir token identifier,
//!   consuming operator fingerprint, tick).
//! - [`JournalEntry`] — `ConsumedToken` + `prev_hash` + `entry_hash` +
//!   `signature`. Entry hash is a BLAKE3 keyed hash over `prev_hash || token
//!   canonical bytes` under the `arkhe-runtime-doctor-journal-chain` domain.
//! - [`JournalSigner`] — signing trait; the real HW-key-backed signer
//!   (YubiKey / NitroKey per `docs/release-keys.md` §3) lives outside this
//!   module. [`InMemoryJournalSigner`] ships only for dev / unit tests.
//! - [`PersistentJournal`] — pluggable backend trait. [`InMemoryJournal`]
//!   is the dev impl; [`WalBackedJournal`] wires against
//!   `arkhe-kernel` WAL.
//!
//! # `KmsBackend` integration
//!
//! The journal append path lives in the **upper coordinator**, not
//! inside `KmsBackend` (e.g. auto_promote evaluator, crypto-erasure
//! coordinator), which calls it. This preserves the sync trait
//! surface and avoids `AwsKmsBackend`'s `tokio::block_on` bridge
//! re-entrance. Detailed wiring lives in `kms_backend.rs`.
//!
//! # Signer injection
//!
//! The runtime process **does not directly hold** private Ed25519
//! key material — a `JournalSigner` trait object is injected from
//! the 2-person co-custody HW key described in
//! `docs/release-keys.md` §3. The trait keeps backend selection
//! orthogonal: `InMemoryJournalSigner` covers the dev path,
//! HW-backed signers (e.g. `YubiKeyJournalSigner`) plug in via the
//! same trait.

use blake3::derive_key;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// BLAKE3 domain separator for journal chain hashing. Registered in spec
/// `Runtime BLAKE3 domain string list` (canonical mirror);
/// `runtime_doctor_journal` chain hash cross-ref.
pub const JOURNAL_CHAIN_DOMAIN: &str = "arkhe-runtime-doctor-journal-chain";

/// Genesis `prev_hash` — the first entry uses a zero prev_hash.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Consumed Shamir authorization token — the audit payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedToken {
    /// Token identifier (BLAKE3 hash of share set, 32 byte).
    pub token_hash: [u8; 32],
    /// Consuming operator fingerprint (Ed25519 pubkey first 8 byte).
    pub operator_fingerprint: [u8; 8],
    /// Consumed at tick.
    pub consumed_at_tick: u64,
}

impl ConsumedToken {
    /// Canonical byte encoding — field order + lengths are pinned so chain
    /// hashes stay stable across releases.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8 + 8);
        buf.extend_from_slice(&self.token_hash);
        buf.extend_from_slice(&self.operator_fingerprint);
        buf.extend_from_slice(&self.consumed_at_tick.to_be_bytes());
        buf
    }
}

/// Chain-signed journal entry.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Audit payload.
    pub token: ConsumedToken,
    /// Previous entry's `entry_hash` (or [`GENESIS_PREV_HASH`] for the first
    /// entry).
    pub prev_hash: [u8; 32],
    /// `BLAKE3-derive_key(JOURNAL_CHAIN_DOMAIN, prev_hash || token_canonical_bytes)`.
    pub entry_hash: [u8; 32],
    /// `Ed25519 sign(entry_hash)`.
    pub signature: [u8; 64],
    /// Signer's Ed25519 public key.
    pub signer_pubkey: [u8; 32],
}

impl JournalEntry {
    /// Re-compute `entry_hash` from `prev_hash` + `token` canonical bytes.
    pub fn compute_entry_hash(prev_hash: &[u8; 32], token: &ConsumedToken) -> [u8; 32] {
        let mut payload = Vec::with_capacity(32 + 48);
        payload.extend_from_slice(prev_hash);
        payload.extend_from_slice(&token.canonical_bytes());
        derive_key(JOURNAL_CHAIN_DOMAIN, &payload)
    }
}

/// Signing abstraction — the real HW-key signer (YubiKey / NitroKey) lives
/// behind this trait so the journal never touches raw `SigningKey` material.
///
/// `Send + Sync` are required so `&dyn JournalSigner` survives future L2
/// multi-consumer transport (audit replicator / transparency-log publisher)
/// even though the current single-active L2 path only crosses threads via
/// the observer pool. Impls are expected to be cheap to share — an
/// `Arc<SigningKey>` wrapper or HW-backed handle.
pub trait JournalSigner: Send + Sync {
    /// Sign `message` and return the 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> [u8; 64];
    /// Signer's Ed25519 public key (32 byte) — embedded in each entry for
    /// independent verification.
    fn public_key(&self) -> [u8; 32];
}

/// Dev-only signer backed by an in-process `SigningKey`. **Production**:
/// replace with a HW-backed signer (e.g. `YubiKeyJournalSigner`) so private
/// key material never enters the process address space
/// (`docs/release-keys.md` §3).
pub struct InMemoryJournalSigner {
    key: SigningKey,
}

impl InMemoryJournalSigner {
    /// Wrap an in-process `SigningKey`. Callers must ensure the key material
    /// stays inside the [`process_protection`](super::super::process_protection)
    /// boundary (Tier-0 software-kek) or is supplied exclusively via test
    /// fixtures.
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// Verify handle — exposed mostly so tests can assert signature
    /// validity without reaching into the crate internals.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl JournalSigner for InMemoryJournalSigner {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig: Signature = self.key.sign(message);
        sig.to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// Journal operation error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JournalError {
    /// Same-token reuse detected — replay attack.
    #[error("duplicate token consume attempt")]
    DuplicateToken,
    /// Chain hash recomputation mismatch — tamper detected.
    #[error("journal chain integrity violation at entry {index}")]
    ChainIntegrity {
        /// 0-based index of the first failing entry.
        index: usize,
    },
    /// Ed25519 signature verification failed.
    #[error("journal signature invalid at entry {index}")]
    SignatureInvalid {
        /// 0-based index of the first failing entry.
        index: usize,
    },
    /// An entry's `signer_pubkey` did not match the pinned trust anchor.
    /// `verify_chain` (self-consistency) cannot catch this — a forged log
    /// re-signed under an attacker key is internally consistent. Only the
    /// trust-anchored check ([`InMemoryJournal::verify_chain_anchored`])
    /// rejects it.
    #[error("journal signer key mismatch at entry {index}")]
    SignerKeyMismatch {
        /// 0-based index of the first entry signed under the wrong key.
        index: usize,
    },
    /// The chain tip hash did not match the caller's pinned expectation —
    /// the log was rewritten or replaced wholesale.
    #[error("journal tip hash mismatch")]
    TipMismatch,
    /// The chain length did not match the caller's pinned expectation —
    /// e.g. a truncated (rolled-back) log.
    #[error("journal length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Length the caller pinned.
        expected: usize,
        /// Length actually present.
        actual: usize,
    },
    /// Backend I/O error — used by the WAL-backed path.
    #[error("journal backend error: {0}")]
    BackendIo(String),
}

/// Append-only chain-signed journal — pluggable backend.
pub trait PersistentJournal {
    /// Append a consumed token. Duplicate `token_hash` is rejected with
    /// [`JournalError::DuplicateToken`]. Success returns the newly-created
    /// entry so the caller can verify / publish it.
    fn append(
        &mut self,
        token: ConsumedToken,
        signer: &dyn JournalSigner,
    ) -> Result<JournalEntry, JournalError>;

    /// **Self-consistency check only.** Returns `Ok(())` if every entry's
    /// `entry_hash` matches its re-computation **and** every signature
    /// validates under the entry's OWN embedded `signer_pubkey`; otherwise
    /// surfaces the first failing index.
    ///
    /// This does NOT establish producer authenticity: each entry is verified
    /// against its own embedded key, so an attacker holding any keypair can
    /// re-sign every entry and forge a fully self-consistent journal that
    /// passes this check. Use
    /// [`InMemoryJournal::verify_chain_anchored`] to pin a trusted key plus
    /// the expected tip + length when the producer is untrusted (mirror of
    /// the kernel's `verify_chain` vs `verify_chain_anchored` split).
    fn verify_chain(&self) -> Result<(), JournalError>;

    /// Last entry's `entry_hash`, or [`GENESIS_PREV_HASH`] for an empty
    /// journal. Useful for external publishing (transparency log).
    fn tip_hash(&self) -> [u8; 32];

    /// Count entries.
    fn len(&self) -> usize;

    /// Empty journal check.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Duplicate check — O(n) linear scan on in-memory, backend-specific on
    /// WAL-backed.
    fn is_duplicate(&self, token_hash: &[u8; 32]) -> bool;
}

/// Marker trait for WAL-backed journal impls — the real `arkhe-kernel`
/// WAL integration routes through `WalBackedJournal`. Tier-1 operators
/// use [`InMemoryJournal`] for dev / single-node deployments.
pub trait WalBackedJournal: PersistentJournal {
    // Stub — `WalBackedJournal` adds `persist_to_wal(...)` +
    // `reconstruct_from_wal(...)` surface when L0 WAL exposes the hook.
}

/// Dev-only in-memory chain-signed journal.
#[derive(Debug, Default)]
pub struct InMemoryJournal {
    entries: Vec<JournalEntry>,
}

impl InMemoryJournal {
    /// Empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the full entry list — read-only view for transparency-log
    /// publishers.
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// Trust-anchored verification — the consumer-side check under an
    /// untrusted-producer threat model. Mirrors the kernel's
    /// `verify_chain_anchored`: in addition to the self-consistency check
    /// run by [`verify_chain`](PersistentJournal::verify_chain), it
    ///
    /// * asserts every entry was signed under `trusted_pubkey` (rejects a
    ///   forged log re-signed under an attacker key —
    ///   [`JournalError::SignerKeyMismatch`]),
    /// * asserts the chain tip equals `expected_tip`
    ///   ([`JournalError::TipMismatch`]),
    /// * asserts the entry count equals `expected_len`
    ///   ([`JournalError::LengthMismatch`] — catches truncation / rollback).
    ///
    /// `verify_chain()` alone is insufficient when the producer is
    /// untrusted: each entry validates against its OWN embedded
    /// `signer_pubkey`, so any keypair forges a self-consistent log.
    pub fn verify_chain_anchored(
        &self,
        trusted_pubkey: &[u8; 32],
        expected_tip: &[u8; 32],
        expected_len: usize,
    ) -> Result<(), JournalError> {
        if self.entries.len() != expected_len {
            return Err(JournalError::LengthMismatch {
                expected: expected_len,
                actual: self.entries.len(),
            });
        }
        // Self-consistency (chain hashes + per-entry signatures) first.
        self.verify_chain()?;
        // Then pin every signer to the trust anchor.
        for (idx, entry) in self.entries.iter().enumerate() {
            if &entry.signer_pubkey != trusted_pubkey {
                return Err(JournalError::SignerKeyMismatch { index: idx });
            }
        }
        if &self.tip_hash() != expected_tip {
            return Err(JournalError::TipMismatch);
        }
        Ok(())
    }
}

impl PersistentJournal for InMemoryJournal {
    fn append(
        &mut self,
        token: ConsumedToken,
        signer: &dyn JournalSigner,
    ) -> Result<JournalEntry, JournalError> {
        if self.is_duplicate(&token.token_hash) {
            return Err(JournalError::DuplicateToken);
        }
        let prev_hash = self.tip_hash();
        let entry_hash = JournalEntry::compute_entry_hash(&prev_hash, &token);
        let signature = signer.sign(&entry_hash);
        let entry = JournalEntry {
            token,
            prev_hash,
            entry_hash,
            signature,
            signer_pubkey: signer.public_key(),
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    fn verify_chain(&self) -> Result<(), JournalError> {
        let mut expected_prev = GENESIS_PREV_HASH;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Err(JournalError::ChainIntegrity { index: idx });
            }
            let recomputed = JournalEntry::compute_entry_hash(&entry.prev_hash, &entry.token);
            if recomputed != entry.entry_hash {
                return Err(JournalError::ChainIntegrity { index: idx });
            }
            let verifying_key = VerifyingKey::from_bytes(&entry.signer_pubkey)
                .map_err(|_| JournalError::SignatureInvalid { index: idx })?;
            let sig = Signature::from_bytes(&entry.signature);
            verifying_key
                .verify(&entry.entry_hash, &sig)
                .map_err(|_| JournalError::SignatureInvalid { index: idx })?;
            expected_prev = entry.entry_hash;
        }
        Ok(())
    }

    fn tip_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(GENESIS_PREV_HASH)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_duplicate(&self, token_hash: &[u8; 32]) -> bool {
        self.entries
            .iter()
            .any(|e| &e.token.token_hash == token_hash)
    }
}

/// Backward-compatible alias — other modules (e.g. `threshold.rs`
/// module-doc) still references this name.
pub type ConsumedTokenJournal = InMemoryJournal;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_signer(seed: u8) -> InMemoryJournalSigner {
        let secret = [seed; 32];
        InMemoryJournalSigner::new(SigningKey::from_bytes(&secret))
    }

    fn make_token(tag: u8, tick: u64) -> ConsumedToken {
        ConsumedToken {
            token_hash: [tag; 32],
            operator_fingerprint: [tag; 8],
            consumed_at_tick: tick,
        }
    }

    #[test]
    fn journal_initial_empty_and_genesis_tip() {
        let j = InMemoryJournal::new();
        assert!(j.is_empty());
        assert_eq!(j.len(), 0);
        assert_eq!(j.tip_hash(), GENESIS_PREV_HASH);
    }

    #[test]
    fn append_produces_chained_entry() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x01);
        let entry = j.append(make_token(0x11, 100), &signer).unwrap();
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(j.tip_hash(), entry.entry_hash);
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn second_entry_chains_to_first() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x02);
        let first = j.append(make_token(0x11, 1), &signer).unwrap();
        let second = j.append(make_token(0x22, 2), &signer).unwrap();
        assert_eq!(second.prev_hash, first.entry_hash);
    }

    #[test]
    fn duplicate_token_rejected() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x03);
        let token = make_token(0x42, 200);
        assert!(j.append(token.clone(), &signer).is_ok());
        assert_eq!(
            j.append(token, &signer).unwrap_err(),
            JournalError::DuplicateToken
        );
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn verify_chain_accepts_clean_log() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x04);
        j.append(make_token(0x01, 10), &signer).unwrap();
        j.append(make_token(0x02, 20), &signer).unwrap();
        j.append(make_token(0x03, 30), &signer).unwrap();
        assert!(j.verify_chain().is_ok());
    }

    #[test]
    fn verify_chain_detects_tampered_hash() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x05);
        j.append(make_token(0x01, 10), &signer).unwrap();
        j.append(make_token(0x02, 20), &signer).unwrap();
        // Tamper: flip one byte of the second entry's token tick.
        j.entries[1].token.consumed_at_tick = 99;
        match j.verify_chain() {
            Err(JournalError::ChainIntegrity { index: 1 }) => {}
            other => panic!("expected ChainIntegrity {{ index: 1 }}, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_detects_tampered_signature() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x06);
        j.append(make_token(0x01, 10), &signer).unwrap();
        // Flip a signature byte.
        j.entries[0].signature[0] ^= 0xFF;
        match j.verify_chain() {
            Err(JournalError::SignatureInvalid { index: 0 }) => {}
            other => panic!("expected SignatureInvalid {{ index: 0 }}, got {other:?}"),
        }
    }

    #[test]
    fn is_duplicate_query_matches_append_rejection() {
        let mut j = InMemoryJournal::new();
        let signer = test_signer(0x07);
        let hash = [0x55u8; 32];
        assert!(!j.is_duplicate(&hash));
        j.append(
            ConsumedToken {
                token_hash: hash,
                operator_fingerprint: [0u8; 8],
                consumed_at_tick: 1,
            },
            &signer,
        )
        .unwrap();
        assert!(j.is_duplicate(&hash));
    }

    #[test]
    fn backward_alias_still_usable() {
        // `ConsumedTokenJournal` alias keeps threshold.rs module-doc live.
        let j: ConsumedTokenJournal = InMemoryJournal::new();
        assert_eq!(j.len(), 0);
    }

    /// Rebuild a journal's entries from scratch, re-signing every entry under
    /// `forger` — produces a fully self-consistent forgery (each entry's
    /// embedded `signer_pubkey` matches its own signature).
    fn forge_under(original: &InMemoryJournal, forger: &InMemoryJournalSigner) -> InMemoryJournal {
        let mut j = InMemoryJournal::new();
        for e in original.entries() {
            j.append(e.token.clone(), forger)
                .expect("forged append must succeed");
        }
        j
    }

    /// #7 — a forged journal re-signed under an attacker key PASSES the
    /// self-consistency `verify_chain()` but FAILS `verify_chain_anchored()`
    /// because no entry was signed under the pinned trusted key.
    #[test]
    fn anchored_rejects_forged_resigned_journal() {
        let genuine_signer = test_signer(0x10);
        let trusted_pubkey = genuine_signer.public_key();

        let mut genuine = InMemoryJournal::new();
        genuine
            .append(make_token(0x01, 10), &genuine_signer)
            .unwrap();
        genuine
            .append(make_token(0x02, 20), &genuine_signer)
            .unwrap();
        let expected_tip = genuine.tip_hash();
        let expected_len = genuine.len();

        // Genuine journal passes the anchored check.
        assert!(genuine
            .verify_chain_anchored(&trusted_pubkey, &expected_tip, expected_len)
            .is_ok());

        // Forge: re-sign the same tokens under a DIFFERENT key.
        let forger = test_signer(0x99);
        let forged = forge_under(&genuine, &forger);

        // The forgery is internally consistent — self-check passes.
        assert!(
            forged.verify_chain().is_ok(),
            "forged log is self-consistent under its own key",
        );
        // But the trust anchor rejects it: entry 0 is signed under the wrong key.
        match forged.verify_chain_anchored(&trusted_pubkey, &expected_tip, expected_len) {
            Err(JournalError::SignerKeyMismatch { index: 0 }) => {}
            other => panic!("expected SignerKeyMismatch {{ index: 0 }}, got {other:?}"),
        }
    }

    /// #7 — a truncated journal fails the length / tip check.
    #[test]
    fn anchored_rejects_truncated_journal() {
        let signer = test_signer(0x11);
        let trusted_pubkey = signer.public_key();

        let mut j = InMemoryJournal::new();
        j.append(make_token(0x01, 10), &signer).unwrap();
        j.append(make_token(0x02, 20), &signer).unwrap();
        let full_tip = j.tip_hash();
        let full_len = j.len();

        // Truncate the last entry (rollback attack).
        j.entries.pop();

        // Length check fires first.
        match j.verify_chain_anchored(&trusted_pubkey, &full_tip, full_len) {
            Err(JournalError::LengthMismatch {
                expected: 2,
                actual: 1,
            }) => {}
            other => panic!("expected LengthMismatch, got {other:?}"),
        }

        // Even when the caller pins the truncated length, the tip mismatch fires.
        match j.verify_chain_anchored(&trusted_pubkey, &full_tip, j.len()) {
            Err(JournalError::TipMismatch) => {}
            other => panic!("expected TipMismatch, got {other:?}"),
        }
    }
}
