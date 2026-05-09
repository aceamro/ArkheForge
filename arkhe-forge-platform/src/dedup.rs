//! L2 idempotency-key dedup service.
//!
//! Primary production path: PG UNIQUE INDEX on the `idempotency_keys`
//! projection table. This module ships the trait surface plus an
//! in-memory implementation suitable for Tier-0 dev and unit tests.
//! The PG-backed implementation and a potential L0 kernel WAL-scan
//! fallback plug in under the same [`IdempotencyIndex`] contract.

use std::collections::HashMap;

use arkhe_forge_core::context::IdempotencyIndex;
use arkhe_kernel::abi::{EntityId, Tick};

/// Insert-side failure taxonomy for dedup stores. Lookup is always
/// infallible (returns `Option`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DedupError {
    /// The same key was inserted twice with different bindings.
    #[error("idempotency key conflict: {0:x?}")]
    Conflict([u8; 16]),
}

/// In-memory [`IdempotencyIndex`] — `HashMap`-backed. Suitable for tests
/// and Tier-0 dev; the PG-backed production implementation lands alongside
/// the L2 service layer.
#[derive(Debug, Default)]
pub struct InMemoryIdempotencyIndex {
    inner: HashMap<[u8; 16], (EntityId, Tick)>,
}

impl InMemoryIdempotencyIndex {
    /// Construct an empty store.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new `(key, entity, tick)` binding. Rejects with
    /// [`DedupError::Conflict`] if the key is already bound to a different
    /// `(entity, tick)` pair. Idempotent re-insert of the same binding is
    /// a no-op success.
    pub fn insert(
        &mut self,
        key: [u8; 16],
        entity: EntityId,
        tick: Tick,
    ) -> Result<(), DedupError> {
        if let Some(existing) = self.inner.get(&key) {
            if *existing == (entity, tick) {
                return Ok(());
            }
            return Err(DedupError::Conflict(key));
        }
        self.inner.insert(key, (entity, tick));
        Ok(())
    }

    /// Number of keys currently held.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` iff no keys are held.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl IdempotencyIndex for InMemoryIdempotencyIndex {
    fn lookup(&self, key: &[u8; 16]) -> Option<(EntityId, Tick)> {
        self.inner.get(key).copied()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ent(v: u64) -> EntityId {
        EntityId::new(v).unwrap()
    }

    #[test]
    fn empty_store_reports_no_hit() {
        let idx = InMemoryIdempotencyIndex::new();
        assert!(idx.is_empty());
        assert!(idx.lookup(&[0u8; 16]).is_none());
    }

    #[test]
    fn insert_then_lookup_returns_same_binding() {
        let mut idx = InMemoryIdempotencyIndex::new();
        let key = [0x11u8; 16];
        idx.insert(key, ent(42), Tick(100)).unwrap();
        assert_eq!(idx.lookup(&key), Some((ent(42), Tick(100))));
    }

    #[test]
    fn reinsert_same_binding_is_noop_success() {
        let mut idx = InMemoryIdempotencyIndex::new();
        let key = [0x22u8; 16];
        idx.insert(key, ent(7), Tick(1)).unwrap();
        idx.insert(key, ent(7), Tick(1)).unwrap();
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn conflict_returns_error() {
        let mut idx = InMemoryIdempotencyIndex::new();
        let key = [0x33u8; 16];
        idx.insert(key, ent(1), Tick(1)).unwrap();
        let err = idx.insert(key, ent(2), Tick(1)).unwrap_err();
        assert!(matches!(err, DedupError::Conflict(k) if k == key));
    }

    #[test]
    fn trait_object_usable_for_action_context() {
        let mut idx = InMemoryIdempotencyIndex::new();
        idx.insert([0x44u8; 16], ent(99), Tick(5)).unwrap();
        let trait_ref: &dyn IdempotencyIndex = &idx;
        assert_eq!(trait_ref.lookup(&[0x44u8; 16]), Some((ent(99), Tick(5))),);
    }
}
