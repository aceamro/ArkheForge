//! Erasure cascade observer — E-user-3 cascade activation.
//!
//! When the L1 compute emits `UserErasureScheduled` (via `GdprEraseUser`
//! lease), this observer drains the user's `EncryptedPii<T>` rows, writes
//! per-row tombstones, and emits the terminal `UserErasureCompleted`
//! receipt once the DEK has been shredded. The SLA is `p95 < 24h`; this
//! module ships the deterministic in-memory path used for tests + the
//! Tier-0 dev harness. The real HSM `delete_key` + multi-region 2PC
//! fanout land alongside the `hf2_kms` backend — the observer's
//! [`Projection`] surface is stable.
//!
//! The observer is **not** a Band-1 compute path; it is a Band-2 derived
//! projection that consumes WAL-anchored events. Every mutation goes
//! through the same `Projection::on_event` entry-point so the router's
//! dedup + gap detection catches replay drift.

use arkhe_forge_core::context::EventRecord;
use arkhe_forge_core::event::{
    ArkheEvent, PerRegionErasureProgress, ProgressScope, RuntimeSignatureClass,
    UserErasureCompleted, UserErasureScheduled,
};
use arkhe_forge_core::pii::DekId;
use arkhe_forge_core::user::UserId;
use arkhe_kernel::abi::{Tick, TypeCode};
use bytes::Bytes;
use std::collections::HashMap;

use crate::projection::{
    ObserverState, Projection, ProjectionContext, ProjectionCursor, ProjectionError,
};

// ===================== DEK shredder =====================

/// Per-user DEK shred backend. Production wires this
/// to an HSM `delete_key` RPC; the in-memory implementation (below) is
/// sufficient for the Tier-0 dev harness.
///
/// **Idempotency contract**: a compliant implementation caches the
/// attestation emitted on the first shred call for `dek_id` and returns
/// `Ok(cached)` on any subsequent call for the same id. `Err(AlreadyShredded)`
/// is reserved for stateless backends that cannot cache; the cascade
/// observer surfaces it as [`ProjectionError::Storage`] and refuses
/// completion — the emit path must never synthesise a replacement
/// attestation, otherwise the `UserErasureCompleted` receipt loses its
/// cryptographic binding to the HSM destruction event.
pub trait DekShredder: Send + Sync {
    /// Drop plaintext DEK material for `dek_id` and return an
    /// attestation payload the observer folds into the
    /// `UserErasureCompleted.attestation_bytes` field. See the trait-
    /// level idempotency contract for replay semantics.
    fn shred(&mut self, dek_id: DekId) -> Result<DekShredAttestation, DekShredError>;

    /// Multi-region 2PC variant. Real backends
    /// override this to drive a multi-KMS / multi-region shred and return
    /// the per-region progress entries so the cascade observer can emit
    /// matching `PerRegionErasureProgress` events.
    ///
    /// Default implementation calls [`Self::shred`] and wraps the result
    /// as a single-region [`ShredResult`] — preserves the current single-
    /// region semantics for backends that do not opt in.
    fn shred_with_regions(
        &mut self,
        dek_id: DekId,
        shred_tick: Tick,
    ) -> Result<ShredResult, DekShredError> {
        let overall = self.shred(dek_id)?;
        let region = RegionProgress {
            scope: default_region_scope(),
            shred_tick,
            attestation_class: overall.attestation_class,
            attestation_bytes: overall.attestation_bytes.clone(),
        };
        Ok(ShredResult {
            regions: vec![region],
            overall,
        })
    }
}

/// Per-region shred progress entry (two-phase commit).
///
/// Single-region backends emit one entry with [`ProgressScope::Region`] /
/// `"default-region"`; multi-region backends emit one entry per
/// participating region or KMS endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionProgress {
    /// Region or KMS scope identifier.
    pub scope: ProgressScope,
    /// Tick at which this scope's DEK shred completed.
    pub shred_tick: Tick,
    /// Signature class used for this scope's attestation payload.
    pub attestation_class: RuntimeSignatureClass,
    /// Signed attestation bytes for this scope.
    pub attestation_bytes: Bytes,
}

/// Multi-region aggregate result returned by
/// [`DekShredder::shred_with_regions`]. The `overall` attestation is what
/// the observer folds into the terminal `UserErasureCompleted` receipt;
/// the per-region `regions` list drives the intermediate
/// `PerRegionErasureProgress` events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShredResult {
    /// Per-region progress, in shred-completion order.
    pub regions: Vec<RegionProgress>,
    /// Aggregate attestation. For single-region backends this matches the
    /// only `RegionProgress` entry; for multi-region backends, the
    /// coordinator-signed roll-up.
    pub overall: DekShredAttestation,
}

/// Single-region default scope — `Region("default-region")`. Stable
/// sentinel for backends that do not opt into multi-region shred.
///
/// `"default-region"` is 14 ASCII bytes, well within `BoundedString::<64>`'s
/// cap, so construction is infallible; the `expect` documents the invariant.
#[allow(clippy::expect_used)]
fn default_region_scope() -> ProgressScope {
    let label = arkhe_forge_core::component::BoundedString::<64>::new("default-region")
        .expect("'default-region' is 14 bytes, within the BoundedString<64> cap");
    ProgressScope::Region(label)
}

/// HSM / KMS key-destruction receipt — what the shredder returns once a
/// DEK is gone. The attestation class + bytes are forwarded into the
/// `UserErasureCompleted` event.
///
/// `log_index` is `Option<u64>` so the no-DEK observer branch (cascade
/// for a user whose row store never held a DEK) can emit `None` rather
/// than the sentinel value `0` — the previous placeholder collided with
/// the genuine "first-shred" log entry of a real shredder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekShredAttestation {
    /// Signature class used for the attestation (`Ed25519`, `Hybrid`, …).
    pub attestation_class: RuntimeSignatureClass,
    /// Signed attestation payload.
    pub attestation_bytes: Bytes,
    /// Monotonic destruction-log sequence — used by the transparency
    /// layer for gap detection. `None` when the
    /// attestation is a synthetic no-DEK placeholder (no transparency
    /// entry to anchor); `Some(n)` when a real shredder issued the
    /// receipt. The type is **not** wire-serialised — observer-local
    /// state forwarded into `UserErasureCompleted` via
    /// [`ErasureCascadeObserver::into_completed_event`], where the
    /// caller supplies the WAL `transparency_log_index` independently.
    pub log_index: Option<u64>,
}

/// DEK shred failure taxonomy.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum DekShredError {
    /// `dek_id` was not recognised — benign on replay of an already
    /// shredded user, fatal if the observer is first-seeing the event.
    #[error("DEK id unknown to the shredder")]
    UnknownDek,
    /// DEK had been shredded on a previous call — the observer treats
    /// this as a no-op + reuses the cached attestation.
    #[error("DEK already shredded")]
    AlreadyShredded,
    /// Backend-specific failure — network, auth, RPC error. Observers
    /// surface this via `ProjectionError::Storage`.
    #[error("shredder backend error: {0}")]
    Backend(&'static str),
}

/// In-memory [`DekShredder`] — deterministic transparency-digest
/// placeholder for tests and the Tier-0 harness. The payload is a BLAKE3
/// keyed hash (a MAC / transparency digest), NOT a signature, so the
/// attestation class is [`RuntimeSignatureClass::None`]: a verifier
/// presented with this attestation correctly rejects it as "not a
/// signature". Real ML-DSA-65 receipt signing is provided by
/// `SigningDekShredder` under the `tier-2-pqc-receipts` feature.
#[derive(Debug, Default)]
pub struct InMemoryDekShredder {
    live: HashMap<DekId, ()>,
    shredded: HashMap<DekId, DekShredAttestation>,
    next_log_index: u64,
}

impl InMemoryDekShredder {
    /// Construct an empty shredder — no DEKs registered.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a DEK the observer will later be asked to shred. The
    /// shredder does not store plaintext key material — just the id.
    pub fn register(&mut self, dek_id: DekId) {
        self.live.insert(dek_id, ());
    }

    /// Check whether a given DEK id was shredded.
    #[must_use]
    pub fn is_shredded(&self, dek_id: &DekId) -> bool {
        self.shredded.contains_key(dek_id)
    }

    fn issue_attestation(&mut self, dek_id: DekId) -> DekShredAttestation {
        let log_index = self.next_log_index;
        self.next_log_index = self.next_log_index.saturating_add(1);
        // Deterministic payload — domain-separated BLAKE3 keyed by
        // `dek_id`. This is a MAC / transparency digest, NOT a signature,
        // so the class is `None`. Production paths sign with an HSM-held
        // or ML-DSA key (see `SigningDekShredder`).
        let key = blake3::derive_key("arkhe-forge-dek-shred-attestation", &dek_id.0);
        let mut h = blake3::Hasher::new_keyed(&key);
        h.update(&log_index.to_be_bytes());
        let digest = h.finalize();
        DekShredAttestation {
            attestation_class: RuntimeSignatureClass::None,
            attestation_bytes: Bytes::copy_from_slice(digest.as_bytes()),
            log_index: Some(log_index),
        }
    }

    /// Overwrite the cached attestation for `dek_id` (idempotency-cache
    /// coherence). Used by [`SigningDekShredder`] to keep the cache in
    /// sync after re-issuing a real ML-DSA-65 signature, so a replay
    /// returns the signed attestation rather than the digest placeholder.
    #[cfg(feature = "tier-2-pqc-receipts")]
    pub(crate) fn set_cached_attestation(&mut self, dek_id: DekId, att: DekShredAttestation) {
        self.shredded.insert(dek_id, att);
    }
}

impl DekShredder for InMemoryDekShredder {
    fn shred(&mut self, dek_id: DekId) -> Result<DekShredAttestation, DekShredError> {
        if let Some(cached) = self.shredded.get(&dek_id) {
            return Ok(cached.clone());
        }
        if self.live.remove(&dek_id).is_none() {
            return Err(DekShredError::UnknownDek);
        }
        let attestation = self.issue_attestation(dek_id);
        self.shredded.insert(dek_id, attestation.clone());
        Ok(attestation)
    }
}

/// ML-DSA-65 signing [`DekShredder`] — wraps an [`InMemoryDekShredder`]
/// and re-issues a real 3309-byte ML-DSA-65 signature over the canonical
/// DEK-shred message (`tier-2-pqc-receipts`). The inner shredder drives
/// the live→shredded transition, the monotonic `log_index`, and the
/// idempotency cache; this wrapper replaces the placeholder digest with a
/// genuine signature (class [`RuntimeSignatureClass::MlDsa65`]) and keeps
/// the inner cache coherent so a replay returns the signed attestation.
#[cfg(feature = "tier-2-pqc-receipts")]
#[derive(Debug)]
pub struct SigningDekShredder {
    inner: InMemoryDekShredder,
    signer: crate::verifier::ReceiptSigner,
}

#[cfg(feature = "tier-2-pqc-receipts")]
impl SigningDekShredder {
    /// Construct from an inner shredder and a receipt signer.
    #[must_use]
    pub fn new(inner: InMemoryDekShredder, signer: crate::verifier::ReceiptSigner) -> Self {
        Self { inner, signer }
    }

    /// Register a DEK with the inner shredder.
    pub fn register(&mut self, dek_id: DekId) {
        self.inner.register(dek_id);
    }

    /// Borrow the signer's verifying-key bytes (1952 bytes) so a verifier
    /// can check the emitted attestation under a policy-pinned class.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.signer.public_key_bytes()
    }
}

#[cfg(feature = "tier-2-pqc-receipts")]
impl DekShredder for SigningDekShredder {
    fn shred(&mut self, dek_id: DekId) -> Result<DekShredAttestation, DekShredError> {
        // Drive the live→shredded transition + log_index + idempotency via
        // the inner shredder, then re-issue a real ML-DSA-65 signature.
        let placeholder = self.inner.shred(dek_id)?;
        let Some(log_index) = placeholder.log_index else {
            // No transparency entry to anchor a signature against — pass
            // the inner attestation through unchanged.
            return Ok(placeholder);
        };
        let message = crate::verifier::dek_shred_message(&dek_id, log_index);
        let sig = self.signer.sign(&message);
        let signed = DekShredAttestation {
            attestation_class: RuntimeSignatureClass::MlDsa65,
            attestation_bytes: Bytes::from(sig),
            log_index: Some(log_index),
        };
        // Keep the inner idempotency cache coherent: a replay must return
        // the signed attestation, not the digest placeholder.
        self.inner.set_cached_attestation(dek_id, signed.clone());
        Ok(signed)
    }
}

// ===================== PII tombstone store =====================

/// Per-user encrypted-PII row descriptor — opaque to the cascade. The
/// observer never decrypts; it just rewrites the row into a tombstone
/// and re-emits a DEK shred signal.
#[derive(Debug, Clone, Default)]
pub struct UserPiiRows {
    /// Encrypted-PII row ids attached to the user.
    pub rows: Vec<u64>,
    /// `DekId` the user's ciphertexts are wrapped under.
    pub dek_id: Option<DekId>,
}

/// Per-user store — production uses a PG-backed table; this in-memory
/// map suits tests.
pub trait PiiRowStore: Send + Sync {
    /// Fetch the set of encrypted-PII rows attached to `user`. Returns
    /// a fresh `UserPiiRows` (possibly empty) when the user has none.
    fn rows_for(&self, user: UserId) -> UserPiiRows;
    /// Mark every row as tombstoned. Idempotent — a repeat call after
    /// cascade completion must be a no-op.
    fn tombstone(&mut self, user: UserId) -> Result<(), ProjectionError>;
    /// Whether `user`'s rows have already been tombstoned.
    fn is_tombstoned(&self, user: UserId) -> bool;
}

/// In-memory [`PiiRowStore`] for tests.
#[derive(Debug, Default)]
pub struct InMemoryPiiRowStore {
    users: HashMap<UserId, UserPiiRows>,
    tombstoned: HashMap<UserId, ()>,
}

impl InMemoryPiiRowStore {
    /// Empty store.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach `rows` to `user` under the given DEK id. Test fixture
    /// setter.
    pub fn upsert(&mut self, user: UserId, rows: Vec<u64>, dek_id: DekId) {
        self.users.insert(
            user,
            UserPiiRows {
                rows,
                dek_id: Some(dek_id),
            },
        );
    }
}

impl PiiRowStore for InMemoryPiiRowStore {
    fn rows_for(&self, user: UserId) -> UserPiiRows {
        self.users.get(&user).cloned().unwrap_or_default()
    }

    fn tombstone(&mut self, user: UserId) -> Result<(), ProjectionError> {
        self.users.remove(&user);
        self.tombstoned.insert(user, ());
        Ok(())
    }

    fn is_tombstoned(&self, user: UserId) -> bool {
        self.tombstoned.contains_key(&user)
    }
}

// ===================== ErasureCascadeObserver =====================

/// Completion record — one per user, accumulated as the observer runs.
/// The router exposes these to callers that want to emit the matching
/// `PerRegionErasureProgress` (one per `regions` entry) plus the terminal
/// `UserErasureCompleted` event onto the WAL (`ctx.emit_event`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureCompletion {
    /// Subject.
    pub user: UserId,
    /// Tick at which the cascade finished.
    pub completed_tick: Tick,
    /// Row count tombstoned.
    pub tombstoned_rows: usize,
    /// Aggregate DEK shred attestation — folded into
    /// `UserErasureCompleted.attestation_bytes`.
    pub attestation: DekShredAttestation,
    /// Per-region progress entries (single-element Vec for single-region
    /// backends). Each entry maps 1:1 to a `PerRegionErasureProgress`
    /// event the caller emits before the terminal `UserErasureCompleted`
    /// (two-phase commit).
    pub regions: Vec<RegionProgress>,
}

/// L2 observer that drives the **E-user-3 cascade**. On every
/// `UserErasureScheduled` event it:
///
/// 1. Looks up the user's encrypted-PII rows via the attached
///    [`PiiRowStore`].
/// 2. Calls [`PiiRowStore::tombstone`] to mark every row soft-deleted.
/// 3. Invokes the attached [`DekShredder`] to drop the underlying DEK.
/// 4. Records an [`ErasureCompletion`] the caller can convert into a
///    `UserErasureCompleted` event on the next tick.
///
/// The observer holds its own cursor — the router still centralises
/// dedup + gap detection via the `Projection` trait.
pub struct ErasureCascadeObserver {
    observes: [TypeCode; 1],
    cursor: Option<ProjectionCursor>,
    rows: Box<dyn PiiRowStore>,
    shredder: Box<dyn DekShredder>,
    completions: Vec<ErasureCompletion>,
}

impl ErasureCascadeObserver {
    /// Construct the observer with concrete backends.
    #[must_use]
    pub fn new(rows: Box<dyn PiiRowStore>, shredder: Box<dyn DekShredder>) -> Self {
        Self {
            observes: [TypeCode(UserErasureScheduled::TYPE_CODE)],
            cursor: None,
            rows,
            shredder,
            completions: Vec::new(),
        }
    }

    /// Drain accumulated [`ErasureCompletion`]s. The caller feeds each
    /// one back into an `ActionContext::emit_event(UserErasureCompleted
    /// { ... })` so the next WAL tick anchors the receipt.
    pub fn drain_completions(&mut self) -> Vec<ErasureCompletion> {
        core::mem::take(&mut self.completions)
    }

    /// Borrow the store for inspection — tests only.
    #[must_use]
    pub fn pii_rows(&self) -> &dyn PiiRowStore {
        self.rows.as_ref()
    }

    /// Borrow the shredder for inspection — tests only.
    #[must_use]
    pub fn shredder(&self) -> &dyn DekShredder {
        self.shredder.as_ref()
    }

    /// Convenience — build a `UserErasureCompleted` event from a
    /// drained completion. The caller chooses the `schema_version` /
    /// transparency log index from its own anchor; this helper wires
    /// the remaining five fields.
    #[must_use]
    pub fn into_completed_event(
        completion: &ErasureCompletion,
        schema_version: u16,
        transparency_log_index: u64,
    ) -> UserErasureCompleted {
        UserErasureCompleted {
            schema_version,
            user: completion.user,
            dek_shred_tick: completion.completed_tick,
            attestation_class: completion.attestation.attestation_class,
            attestation_bytes: completion.attestation.attestation_bytes.clone(),
            transparency_log_index,
        }
    }

    /// Convenience — fan out a completion's per-region progress entries
    /// as `PerRegionErasureProgress` events (two-phase
    /// commit). Single-region backends emit one event; multi-
    /// region backends emit one event per participating region. The
    /// caller emits these *before* the terminal `UserErasureCompleted`
    /// receipt so external consumers see the full erasure transcript.
    #[must_use]
    pub fn per_region_events(
        completion: &ErasureCompletion,
        schema_version: u16,
    ) -> Vec<PerRegionErasureProgress> {
        completion
            .regions
            .iter()
            .map(|r| PerRegionErasureProgress {
                schema_version,
                user: completion.user,
                scope: r.scope.clone(),
                shred_tick: r.shred_tick,
                attestation_class: r.attestation_class,
                attestation_bytes: r.attestation_bytes.clone(),
            })
            .collect()
    }
}

impl Projection for ErasureCascadeObserver {
    fn observes(&self) -> &[TypeCode] {
        &self.observes
    }

    fn on_event(
        &mut self,
        event: &EventRecord,
        ctx: &ProjectionContext<'_>,
    ) -> Result<(), ProjectionError> {
        let scheduled: UserErasureScheduled = postcard::from_bytes(&event.payload)
            .map_err(|_| ProjectionError::DecodeFailed("UserErasureScheduled payload"))?;
        let user = scheduled.user;
        let rows = self.rows.rows_for(user);
        let tombstoned = rows.rows.len();

        // 2PC ordering — **shred first**, tombstone second. A failure in
        // the shred step aborts before any row state changes, so rows
        // remain live + DEK live (a clean retry state). A failure in the
        // tombstone step (post-shred) leaves the ciphertext already
        // crypto-erased: replay re-runs tombstone under the cached
        // attestation the idempotent shredder returns. The inverse order
        // would expose a backup-replay window where rows look dead while
        // the DEK is still live, letting an adversary with a pre-
        // tombstone snapshot unwrap the ciphertext.
        let result: ShredResult = match rows.dek_id {
            Some(dek_id) => match self.shredder.shred_with_regions(dek_id, ctx.tick) {
                Ok(r) => r,
                Err(DekShredError::AlreadyShredded) => {
                    // Shredder violated the idempotency contract (must
                    // cache + replay `Ok`). Refuse completion so the
                    // operator can re-register the DEK rather than emit
                    // an empty-attestation receipt that a regulator
                    // would reject as invalid proof of destruction.
                    return Err(ProjectionError::Storage(
                        "shredder returned AlreadyShredded; implementations must cache attestation",
                    ));
                }
                Err(DekShredError::UnknownDek) => {
                    return Err(ProjectionError::Storage("DEK unknown to shredder"));
                }
                Err(DekShredError::Backend(msg)) => return Err(ProjectionError::Storage(msg)),
            },
            None => ShredResult {
                regions: Vec::new(),
                overall: DekShredAttestation {
                    attestation_class: RuntimeSignatureClass::None,
                    attestation_bytes: Bytes::new(),
                    log_index: None,
                },
            },
        };

        // DEK is destroyed; tombstone the rows for storage hygiene. If
        // this step fails the ciphertext is already GDPR-erased and the
        // next replay redoes the tombstone idempotently.
        self.rows.tombstone(user)?;

        self.completions.push(ErasureCompletion {
            user,
            completed_tick: ctx.tick,
            tombstoned_rows: tombstoned,
            attestation: result.overall,
            regions: result.regions,
        });

        self.cursor = Some(ProjectionCursor {
            sequence: event.sequence,
            tick: event.tick,
        });
        Ok(())
    }

    fn on_state_change(&mut self, _new_state: ObserverState) -> Result<(), ProjectionError> {
        // No-op — completions persist across promotions. Demotion /
        // drain callers pull pending completions via
        // `drain_completions` before ceding primary.
        Ok(())
    }

    fn last_applied(&self) -> Option<(u64, Tick)> {
        self.cursor.map(|c| (c.sequence, c.tick))
    }
}

// ===================== Tests =====================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::projection::ProjectionRouter;
    use arkhe_kernel::abi::{EntityId, InstanceId};

    fn uid(v: u64) -> UserId {
        UserId::new(EntityId::new(v).unwrap())
    }

    fn make_scheduled_event(user: UserId, seq: u64, tick: u64) -> EventRecord {
        let ev = UserErasureScheduled {
            schema_version: 1,
            user,
            scheduled_tick: Tick(tick),
        };
        EventRecord {
            type_code: UserErasureScheduled::TYPE_CODE,
            sequence: seq,
            tick: Tick(tick),
            payload: Bytes::from(postcard::to_stdvec(&ev).unwrap()),
        }
    }

    fn ctx(tick: u64) -> ProjectionContext<'static> {
        ProjectionContext::new(Tick(tick), InstanceId::new(1).unwrap())
    }

    #[test]
    fn observer_observes_user_erasure_scheduled_only() {
        let obs = ErasureCascadeObserver::new(
            Box::new(InMemoryPiiRowStore::new()),
            Box::new(InMemoryDekShredder::new()),
        );
        assert_eq!(obs.observes(), &[TypeCode(UserErasureScheduled::TYPE_CODE)]);
    }

    #[test]
    fn cascade_tombstones_rows_and_shreds_dek() {
        let mut store = InMemoryPiiRowStore::new();
        let user = uid(42);
        let dek_id = DekId([0xAB; 16]);
        store.upsert(user, vec![10, 11, 12], dek_id);
        let mut shredder = InMemoryDekShredder::new();
        shredder.register(dek_id);
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(shredder));

        obs.on_event(&make_scheduled_event(user, 0, 100), &ctx(100))
            .unwrap();

        assert!(obs.pii_rows().is_tombstoned(user));
        let completions = obs.drain_completions();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].user, user);
        assert_eq!(completions[0].tombstoned_rows, 3);
        assert_eq!(completions[0].completed_tick, Tick(100));
        assert_eq!(
            completions[0].attestation.attestation_class,
            RuntimeSignatureClass::None
        );
    }

    #[test]
    fn cascade_no_rows_still_emits_completion() {
        let obs_store = InMemoryPiiRowStore::new();
        let shredder = InMemoryDekShredder::new();
        let mut obs = ErasureCascadeObserver::new(Box::new(obs_store), Box::new(shredder));
        let user = uid(7);
        obs.on_event(&make_scheduled_event(user, 0, 5), &ctx(5))
            .unwrap();
        let completions = obs.drain_completions();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].tombstoned_rows, 0);
        assert_eq!(
            completions[0].attestation.attestation_class,
            RuntimeSignatureClass::None
        );
        // m13 — synthetic no-DEK attestation must not collide with the
        // genuine `Some(0)` log entry of a real shredder.
        assert_eq!(completions[0].attestation.log_index, None);
    }

    #[test]
    fn first_shred_log_index_is_some_zero_distinct_from_no_dek() {
        // m13 regression — `InMemoryDekShredder::issue_attestation`
        // hands out `Some(0)` on the first shred. Cascading a user
        // with a real DEK and another with no DEK must show the two
        // attestations are distinguishable on `log_index` alone.
        let mut store = InMemoryPiiRowStore::new();
        let user_real = uid(101);
        let dek_id = DekId([0xAA; 16]);
        store.upsert(user_real, vec![1], dek_id);
        let mut shredder = InMemoryDekShredder::new();
        shredder.register(dek_id);
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(shredder));

        obs.on_event(&make_scheduled_event(user_real, 0, 50), &ctx(50))
            .unwrap();
        let real = obs.drain_completions();
        assert_eq!(real[0].attestation.log_index, Some(0));

        let user_empty = uid(202);
        obs.on_event(&make_scheduled_event(user_empty, 1, 51), &ctx(51))
            .unwrap();
        let empty = obs.drain_completions();
        assert_eq!(empty[0].attestation.log_index, None);
    }

    #[test]
    fn cascade_unknown_dek_surfaces_storage_error() {
        let mut store = InMemoryPiiRowStore::new();
        let user = uid(9);
        // DEK referenced by the store is NOT registered with the shredder.
        store.upsert(user, vec![1], DekId([0x99; 16]));
        let shredder = InMemoryDekShredder::new();
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(shredder));
        let err = obs
            .on_event(&make_scheduled_event(user, 0, 5), &ctx(5))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Storage(_)));
        // Shred-first ordering — failure aborts before tombstone.
        assert!(!obs.pii_rows().is_tombstoned(user));
    }

    #[test]
    fn shred_failure_keeps_rows_live() {
        // Backend error during shred must leave rows untombstoned so a
        // replay can retry without a backup-replay window.
        struct FailingShredder;
        impl DekShredder for FailingShredder {
            fn shred(&mut self, _dek_id: DekId) -> Result<DekShredAttestation, DekShredError> {
                Err(DekShredError::Backend("inject: KMS unavailable"))
            }
        }

        let mut store = InMemoryPiiRowStore::new();
        let user = uid(777);
        let dek_id = DekId([0xAA; 16]);
        store.upsert(user, vec![1, 2, 3], dek_id);
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(FailingShredder));

        let err = obs
            .on_event(&make_scheduled_event(user, 0, 10), &ctx(10))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Storage(_)));

        // Rows must survive — tombstone was never attempted.
        assert!(!obs.pii_rows().is_tombstoned(user));
        assert_eq!(obs.pii_rows().rows_for(user).rows.len(), 3);

        // No completion emitted.
        assert!(obs.drain_completions().is_empty());
    }

    #[test]
    fn already_shredded_surfaces_as_storage_error() {
        // A shredder that breaks the idempotency contract by returning
        // `AlreadyShredded` instead of the cached attestation must be
        // refused — the observer will not synthesise a replacement
        // attestation that would fail regulator verification.
        struct BrokenShredder;
        impl DekShredder for BrokenShredder {
            fn shred(&mut self, _dek_id: DekId) -> Result<DekShredAttestation, DekShredError> {
                Err(DekShredError::AlreadyShredded)
            }
        }

        let mut store = InMemoryPiiRowStore::new();
        let user = uid(999);
        let dek_id = DekId([0xCC; 16]);
        store.upsert(user, vec![1], dek_id);
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(BrokenShredder));

        let err = obs
            .on_event(&make_scheduled_event(user, 0, 30), &ctx(30))
            .unwrap_err();
        assert!(matches!(err, ProjectionError::Storage(_)));
        // Shred-first ordering preserved row state for retry.
        assert!(!obs.pii_rows().is_tombstoned(user));
        assert!(obs.drain_completions().is_empty());
    }

    #[test]
    fn cascade_replay_after_tombstone_holds_rows_dead() {
        // Backup-restore smoke — a crashed cascade replayed from the WAL
        // finds the rows already tombstoned. The in-memory store drops
        // the DEK reference on tombstone, so the replay takes the no-
        // rows branch and emits a placeholder completion; the key
        // invariant is that rows stay tombstoned throughout and no
        // panic / data resurface occurs.
        let mut store = InMemoryPiiRowStore::new();
        let user = uid(1234);
        let dek_id = DekId([0xEF; 16]);
        store.upsert(user, vec![1, 2], dek_id);
        let mut shredder = InMemoryDekShredder::new();
        shredder.register(dek_id);
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(shredder));

        obs.on_event(&make_scheduled_event(user, 0, 40), &ctx(40))
            .unwrap();
        let first = obs.drain_completions();
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].attestation.attestation_class,
            RuntimeSignatureClass::None
        );
        assert!(obs.pii_rows().is_tombstoned(user));

        // Replay (WAL-driven recovery).
        obs.on_event(&make_scheduled_event(user, 1, 41), &ctx(41))
            .unwrap();
        let replayed = obs.drain_completions();
        assert_eq!(replayed.len(), 1);
        assert_eq!(
            replayed[0].attestation.attestation_class,
            RuntimeSignatureClass::None
        );
        assert!(obs.pii_rows().is_tombstoned(user));
    }

    #[test]
    fn cascade_participates_in_projection_router_dispatch() {
        let mut store = InMemoryPiiRowStore::new();
        let user = uid(123);
        let dek_id = DekId([0xEE; 16]);
        store.upsert(user, vec![1, 2], dek_id);
        let mut shredder = InMemoryDekShredder::new();
        shredder.register(dek_id);

        let mut router = ProjectionRouter::new();
        router.promote_to_active().unwrap();
        router.register(Box::new(ErasureCascadeObserver::new(
            Box::new(store),
            Box::new(shredder),
        )));

        let applied = router
            .dispatch(&make_scheduled_event(user, 0, 300), &ctx(300))
            .unwrap();
        assert_eq!(applied, 1);
    }

    #[test]
    fn completed_event_roundtrip_via_helper() {
        let completion = ErasureCompletion {
            user: uid(1),
            completed_tick: Tick(250),
            tombstoned_rows: 4,
            attestation: DekShredAttestation {
                attestation_class: RuntimeSignatureClass::Hybrid,
                attestation_bytes: Bytes::from_static(&[0u8; 128]),
                log_index: Some(7),
            },
            regions: Vec::new(),
        };
        let event = ErasureCascadeObserver::into_completed_event(&completion, 1, 99);
        assert_eq!(event.user, uid(1));
        assert_eq!(event.dek_shred_tick, Tick(250));
        assert_eq!(event.attestation_class, RuntimeSignatureClass::Hybrid);
        assert_eq!(event.transparency_log_index, 99);

        // Wire-level roundtrip — confirm the event struct postcard-encodes.
        let bytes = postcard::to_stdvec(&event).unwrap();
        let back: UserErasureCompleted = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn per_region_events_default_emits_one_entry_per_completion() {
        // Single-region default — `DekShredder::shred_with_regions` wraps
        // the single attestation as a 1-element Vec, so the cascade emits
        // exactly one `PerRegionErasureProgress` per user.
        let mut store = InMemoryPiiRowStore::new();
        let user = uid(11);
        let dek_id = DekId([0xAA; 16]);
        store.upsert(user, vec![1, 2, 3], dek_id);
        let mut shredder = InMemoryDekShredder::new();
        shredder.register(dek_id);
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(shredder));

        obs.on_event(&make_scheduled_event(user, 0, 100), &ctx(100))
            .unwrap();
        let completions = obs.drain_completions();
        assert_eq!(completions.len(), 1);
        let completion = &completions[0];
        assert_eq!(
            completion.regions.len(),
            1,
            "single-region default emits 1 entry"
        );
        let region = &completion.regions[0];
        assert!(matches!(region.scope, ProgressScope::Region(_)));
        assert_eq!(region.shred_tick, Tick(100));
        assert_eq!(region.attestation_class, RuntimeSignatureClass::None);

        let events = ErasureCascadeObserver::per_region_events(completion, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user, user);
        assert_eq!(events[0].shred_tick, Tick(100));

        // Wire-level roundtrip on the per-region event.
        let bytes = postcard::to_stdvec(&events[0]).unwrap();
        let back: PerRegionErasureProgress = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, events[0]);
    }

    #[test]
    fn per_region_events_no_dek_user_emits_zero_entries() {
        // A user whose row store never carried a DEK has `regions` left
        // empty (the synthetic `RuntimeSignatureClass::None` attestation
        // is overall-only) — zero `PerRegionErasureProgress` events.
        let store = InMemoryPiiRowStore::new();
        let user = uid(12);
        let shredder = InMemoryDekShredder::new();
        let mut obs = ErasureCascadeObserver::new(Box::new(store), Box::new(shredder));

        obs.on_event(&make_scheduled_event(user, 0, 200), &ctx(200))
            .unwrap();
        let completions = obs.drain_completions();
        assert_eq!(completions.len(), 1);
        assert!(completions[0].regions.is_empty());
        let events = ErasureCascadeObserver::per_region_events(&completions[0], 1);
        assert!(events.is_empty());
    }

    /// **E-user-3 integration** — the axiom harness in `arkhe-forge-core`
    /// pins that `GdprEraseUser::compute` emits `UserErasureScheduled`.
    /// This platform-level test shows the cascade observer picks the
    /// event up and reaches the `UserErasureCompleted` completion
    /// record — E-user-3 cascade trigger.
    #[test]
    fn e_user_3_cascade_activates_end_to_end() {
        use arkhe_forge_core::action::ActionCompute;
        use arkhe_forge_core::context::ActionContext as L1ActionContext;
        use arkhe_forge_core::user::GdprEraseUser;
        use arkhe_kernel::abi::{CapabilityMask, Principal};

        let user = uid(7777);

        // 1. Run the L1 compute to produce the scheduling event.
        let act = GdprEraseUser {
            schema_version: 1,
            user,
        };
        let mut l1 = L1ActionContext::new(
            [0u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(100),
            Principal::System,
            CapabilityMask::SYSTEM,
        );
        act.compute(&mut l1).unwrap();
        let mut events = l1.drain_events();
        assert_eq!(events.len(), 1);
        let scheduling_record = events.pop().unwrap();

        // 2. Feed the event into the cascade observer.
        let mut store = InMemoryPiiRowStore::new();
        let dek_id = DekId([0xCD; 16]);
        store.upsert(user, vec![100, 101, 102, 103], dek_id);
        let mut shredder = InMemoryDekShredder::new();
        shredder.register(dek_id);
        let mut router = ProjectionRouter::new();
        router.promote_to_active().unwrap();
        router.register(Box::new(ErasureCascadeObserver::new(
            Box::new(store),
            Box::new(shredder),
        )));
        let event_record = EventRecord {
            type_code: scheduling_record.type_code,
            sequence: 0,
            tick: scheduling_record.tick,
            payload: scheduling_record.payload.clone(),
        };
        let applied = router.dispatch(&event_record, &ctx(100)).unwrap();
        assert_eq!(applied, 1);
    }
}
