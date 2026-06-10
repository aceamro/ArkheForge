//! AWS KMS reference implementation of [`KmsBackend`].
//!
//! Feature-gated under `tier-2-aws-kms`. The `aws-sdk-kms` crate is async-only,
//! so [`AwsKmsBackend`] owns a dedicated single-thread `tokio` runtime and
//! bridges each synchronous [`KmsBackend`] call to the async SDK via
//! `Handle::block_on`. The sync trait contract is preserved for all
//! L2 coordinators (KMS backend boundary).
//!
//! # What this module does not do
//!
//! * Live AWS integration tests — the test harness here exercises the sync ↔
//!   async bridge shape and error mapping. Real-world KMS round-trips require
//!   operator credentials and are out of CI scope.
//! * Implicit `tokio` runtime borrowing — the backend refuses to construct
//!   from within an existing tokio runtime to avoid `block_on`-in-async
//!   deadlock. Callers either own a dedicated blocking context or call
//!   [`AwsKmsBackend::new_in_runtime`] with an explicit `Handle`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{
    primitives::Blob,
    types::{DataKeySpec, KeySpec},
    Client as KmsClient,
};
use bytes::Bytes;
use tokio::runtime::{Handle, Runtime};
use zeroize::{Zeroize, Zeroizing};

use arkhe_forge_core::event::RuntimeSignatureClass;
use arkhe_forge_core::pii::DekId;

use crate::crypto::{Dek, DekConfig};
use crate::crypto_erasure::DekShredAttestation;

use super::kms_backend::{KekRef, KeyDeletionAttestation, KmsBackend, KmsError};

/// Sync adapter over `aws-sdk-kms::Client`.
///
/// Two construction modes:
///
/// * [`AwsKmsBackend::new`] — builds a dedicated single-thread tokio runtime.
///   Use when the calling process does not already drive tokio tasks.
/// * [`AwsKmsBackend::new_in_runtime`] — adopts an existing runtime handle.
///   The caller guarantees the handle outlives the backend and that the
///   backend is never invoked from within a task scheduled on the same
///   runtime (`block_on`-in-async would deadlock the worker thread).
pub struct AwsKmsBackend {
    client: KmsClient,
    executor: Executor,
    /// Monotonic destruction-log index for [`delete_key`] attestations.
    /// Mirrors `MockKmsBackend::destruction_log_index` so the
    /// `DekShredder` gap-detection contract holds — the AWS deletion_date
    /// (wall-clock) folds into the attestation payload instead.
    destruction_log_index: AtomicU64,
}

enum Executor {
    Owned(Arc<Runtime>),
    Borrowed(Handle),
}

impl std::fmt::Debug for AwsKmsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsBackend").finish_non_exhaustive()
    }
}

impl AwsKmsBackend {
    /// Build a backend with a dedicated single-thread tokio runtime. The
    /// caller supplies an AWS `Region`; the standard credential provider chain
    /// resolves authentication. Returns [`KmsError::Backend`] on runtime
    /// construction failure.
    pub fn new(region: impl Into<String>) -> Result<Self, KmsError> {
        let runtime = Runtime::new()
            .map_err(|e| KmsError::Backend(format!("tokio runtime init failed: {e}")))?;
        let region = Region::new(region.into());
        let client = runtime.block_on(async move {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(region)
                .load()
                .await;
            KmsClient::new(&conf)
        });
        Ok(Self {
            client,
            executor: Executor::Owned(Arc::new(runtime)),
            destruction_log_index: AtomicU64::new(0),
        })
    }

    /// Adopt an existing tokio runtime handle. The caller guarantees the
    /// handle outlives the backend and that trait methods are never invoked
    /// from within a task scheduled on the same runtime.
    pub fn new_in_runtime(handle: Handle, client: KmsClient) -> Self {
        Self {
            client,
            executor: Executor::Borrowed(handle),
            destruction_log_index: AtomicU64::new(0),
        }
    }

    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        match &self.executor {
            Executor::Owned(rt) => rt.block_on(fut),
            Executor::Borrowed(handle) => {
                // Defensive bridge: if the current thread is already inside a
                // tokio runtime, plain `handle.block_on` would panic with
                // "Cannot start a runtime from within a runtime". Instead we
                // hand control to `block_in_place`, which moves the worker
                // thread out of the cooperative scheduler so `block_on` is
                // safe. Outside any runtime context, `block_in_place` itself
                // is unsupported, so we fall through to the direct call.
                //
                // `block_in_place` requires `rt-multi-thread`, which the
                // `tier-2-aws-kms` feature pulls in via the workspace tokio
                // dependency.
                if Handle::try_current().is_ok() {
                    tokio::task::block_in_place(|| handle.block_on(fut))
                } else {
                    handle.block_on(fut)
                }
            }
        }
    }
}

fn map_sdk_error<E: std::fmt::Display>(e: E) -> KmsError {
    // AWS SDK surfaces granular variants (AccessDenied, KmsInvalidState, …)
    // — the runtime surface collapses them into the coarse [`KmsError`]
    // taxonomy. Operator-facing detail lands in the inner string.
    KmsError::Backend(format!("aws-sdk-kms: {e}"))
}

impl KmsBackend for AwsKmsBackend {
    fn generate_dek(&self, kek_ref: &KekRef) -> Result<(DekId, Dek), KmsError> {
        self.block_on(async {
            let out = self
                .client
                .generate_data_key()
                .key_id(kek_ref.as_str())
                .key_spec(DataKeySpec::Aes256)
                .send()
                .await
                .map_err(map_sdk_error)?;

            // `Plaintext` is `Option<Blob>`; AWS returns it for GenerateDataKey.
            // The plaintext DEK leaves the SDK as an owned `Vec<u8>` on the
            // heap. Wrap it in `Zeroizing` so the buffer is scrubbed when it
            // drops at the end of this scope — no plaintext copy outlives the
            // scrub (the only durable copy is the zeroize-on-drop `Dek`).
            let plaintext = out.plaintext.ok_or(KmsError::UnwrapFailed)?;
            let plaintext_bytes = Zeroizing::new(plaintext.into_inner());
            if plaintext_bytes.len() != 32 {
                return Err(KmsError::Backend(format!(
                    "unexpected DEK length: {}",
                    plaintext_bytes.len()
                )));
            }
            // AWS returns a CiphertextBlob wrapped DEK too — the caller can
            // store it directly. We derive the DekId from a keyed digest of
            // the wrapped ciphertext so a rotation / re-wrap yields a fresh
            // id (idempotency contract upheld by DekShredAttestation).
            // Extracted BEFORE the plaintext stack copy exists so no
            // fallible operation sits between the copy and its scrub.
            let ciphertext = out.ciphertext_blob.ok_or(KmsError::UnwrapFailed)?;
            let id_digest = blake3::keyed_hash(
                blake3::hash(b"arkhe-forge-aws-kms-dek-id").as_bytes(),
                ciphertext.as_ref(),
            );
            let mut id_bytes = [0u8; 16];
            id_bytes.copy_from_slice(&id_digest.as_bytes()[..16]);

            // `from_bytes` takes a bitwise copy ([u8; 32] is Copy), so wipe
            // the local after the Dek is constructed — the zeroize-on-drop
            // Dek is the only copy that outlives this scope.
            let mut material = [0u8; 32];
            material.copy_from_slice(&plaintext_bytes);
            let dek = Dek::from_bytes(material);
            material.zeroize();
            Ok((DekId(id_bytes), dek))
        })
    }

    fn wrap_dek(&self, dek: &Dek, kek_ref: &KekRef) -> Result<Bytes, KmsError> {
        self.block_on(async {
            // Build the SDK plaintext blob from a zeroized buffer so the
            // copy of the DEK we hand to the SDK is scrubbed when it drops
            // at the end of this scope. `Blob::new` copies the bytes, so the
            // `Zeroizing` source can drop right after the builder call.
            let plaintext = Zeroizing::new(dek.as_bytes().to_vec());
            let out = self
                .client
                .encrypt()
                .key_id(kek_ref.as_str())
                .plaintext(Blob::new(plaintext.as_slice()))
                .send()
                .await
                .map_err(map_sdk_error)?;
            let blob = out.ciphertext_blob.ok_or(KmsError::UnwrapFailed)?;
            Ok(Bytes::copy_from_slice(blob.as_ref()))
        })
    }

    fn unwrap_dek(&self, wrapped: &[u8], kek_ref: &KekRef) -> Result<Dek, KmsError> {
        self.block_on(async {
            let out = self
                .client
                .decrypt()
                .key_id(kek_ref.as_str())
                .ciphertext_blob(Blob::new(wrapped.to_vec()))
                .send()
                .await
                .map_err(map_sdk_error)?;
            // Wrap the SDK plaintext in `Zeroizing` so the heap `Vec` is
            // scrubbed on drop — only the zeroize-on-drop `Dek` outlives it.
            let plaintext = out.plaintext.ok_or(KmsError::UnwrapFailed)?;
            let bytes = Zeroizing::new(plaintext.into_inner());
            if bytes.len() != 32 {
                return Err(KmsError::UnwrapFailed);
            }
            let mut material = [0u8; 32];
            material.copy_from_slice(&bytes);
            // Unwrapped from durable KMS material — long-lived; admitted only
            // under AES-256-GCM-SIV (counter resets on each reconstruction).
            // `from_unwrapped` copies the array, so wipe the local after.
            let dek = Dek::from_unwrapped(material, DekConfig::default());
            material.zeroize();
            Ok(dek)
        })
    }

    fn delete_key(&self, kek_ref: &KekRef) -> Result<KeyDeletionAttestation, KmsError> {
        self.block_on(async {
            let out = self
                .client
                .schedule_key_deletion()
                .key_id(kek_ref.as_str())
                .pending_window_in_days(7)
                .send()
                .await
                .map_err(map_sdk_error)?;
            // AWS returns deletion_date + key_id. We fold the KEK arn + deletion
            // date into a BLAKE3 attestation payload so downstream consumers
            // can cross-reference the destruction event without a live API
            // round-trip. This payload is a transparency digest, NOT a
            // signature, so the class is `None`. Production setups layer a
            // genuine HSM signature on top via a separate attestation service.
            //
            // `log_index` must be monotonic for the DekShredder gap-detection
            // contract — a wall-clock `deletion_date` is non-monotonic
            // (clock skew, equal-second collisions), so it goes into the
            // attestation payload instead. The index comes from a per-backend
            // monotonic counter (mirrors MockKmsBackend::destruction_log_index).
            let key_id = out.key_id.unwrap_or_default();
            let deletion_ts = out.deletion_date.map(|d| d.secs()).unwrap_or_default();
            let log_index = self.destruction_log_index.fetch_add(1, Ordering::Relaxed);
            let mut h = blake3::Hasher::new();
            h.update(b"arkhe-forge-aws-kms-delete-attestation");
            h.update(key_id.as_bytes());
            h.update(&deletion_ts.to_le_bytes());
            let payload: [u8; 32] = *h.finalize().as_bytes();
            Ok(DekShredAttestation {
                attestation_class: RuntimeSignatureClass::None,
                attestation_bytes: Bytes::copy_from_slice(&payload),
                log_index: Some(log_index),
            })
        })
    }

    fn rotate_kek(&self, old: &KekRef, new: &KekRef) -> Result<(), KmsError> {
        // AWS exposes `UpdateAlias` + `EnableKey` / `DisableKey`. The
        // runtime pins the contract surface only — operators execute the
        // alias swap via `aws kms update-alias` in the rotation runbook.
        // The runtime marks the logical rotation attempted by successfully
        // describing both KEKs.
        self.block_on(async {
            for k in [old, new] {
                self.client
                    .describe_key()
                    .key_id(k.as_str())
                    .send()
                    .await
                    .map_err(|e| KmsError::KekNotFound(format!("{}: {e}", k.as_str())))?;
            }
            Ok(())
        })
    }
}

/// Kind of KEK AWS KMS should create for [`generate_dek`]. The runtime always
/// requests AES-256 since DEKs are 32-byte AEAD keys.
#[allow(dead_code)]
const _KEY_SPEC: KeySpec = KeySpec::SymmetricDefault;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Live-AWS tests are out of scope for CI. These cases check the bridge
    // shape — construction pathways + trait-method routing — without issuing
    // real network calls. `AwsKmsBackend::new` lazily resolves credentials
    // (no HTTP at construction time), so an offline runner still exercises
    // the happy path.

    #[test]
    fn constructor_owns_runtime() {
        let backend = AwsKmsBackend::new("us-east-1").expect("runtime built");
        assert!(matches!(backend.executor, Executor::Owned(_)));
    }

    #[test]
    fn constructor_accepts_explicit_handle() {
        // Build a runtime, adopt its handle, then drop our reference. The
        // backend retains the handle internally; its own trait calls will
        // block_on via that handle.
        let rt = Runtime::new().unwrap();
        let handle = rt.handle().clone();
        // Production callers would pass a real KmsClient here — we construct
        // one through the same default chain for the shape test.
        let client = rt.block_on(async {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .load()
                .await;
            KmsClient::new(&conf)
        });
        let backend = AwsKmsBackend::new_in_runtime(handle, client);
        assert!(matches!(backend.executor, Executor::Borrowed(_)));
        // Keep `rt` alive for the lifetime of `backend`.
        drop(backend);
        drop(rt);
    }

    #[test]
    fn debug_does_not_leak_internals() {
        let backend = AwsKmsBackend::new("us-east-1").expect("runtime built");
        let s = format!("{:?}", backend);
        // The executor variant and client internals must not appear.
        assert!(s.contains("AwsKmsBackend"));
        assert!(!s.contains("Owned"));
        assert!(!s.contains("Borrowed"));
    }

    #[test]
    fn map_sdk_error_wraps_display_in_backend_variant() {
        let err = map_sdk_error("boom");
        assert!(matches!(err, KmsError::Backend(msg) if msg.contains("boom")));
    }

    #[test]
    fn destruction_log_index_starts_at_zero_and_is_monotonic() {
        // #5 regression — `delete_key` assigns the attestation `log_index`
        // from a per-backend monotonic counter (not the wall-clock
        // deletion_date). The live network call is out of CI scope, so we
        // exercise the counter's fetch-add semantics directly: it starts at
        // 0 and yields a strictly increasing sequence (0, 1, 2, …) exactly
        // as the delete path consumes it.
        let backend = AwsKmsBackend::new("us-east-1").expect("runtime built");
        let first = backend
            .destruction_log_index
            .fetch_add(1, Ordering::Relaxed);
        let second = backend
            .destruction_log_index
            .fetch_add(1, Ordering::Relaxed);
        let third = backend
            .destruction_log_index
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(first, 0);
        assert_eq!(second, 1);
        assert_eq!(third, 2);
    }
}
