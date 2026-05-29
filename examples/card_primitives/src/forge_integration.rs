//! ArkheForge L1 integration — wires the card-primitives showdown
//! receipt into the runtime `Action` / `Event` pipeline as a
//! reference example.
//!
//! [`RecordHandShowdown`] is an
//! `arkhe_forge_core::action::ArkheAction` that takes a
//! (commitment, seed, deck_order, hand_rank_bytes) tuple, reproduces
//! the verification path used by [`super::shuffle_proof`], and emits a
//! [`HandShowdownLanded`] event whose payload pins the canonical
//! 32-byte chain-hash anchor. The compute body uses only deterministic
//! `blake3` + the local `shuffle_proof::verify_shuffle_order` function;
//! the `#[arkhe_pure]` attribute is applied voluntarily as an E14.L1
//! Subset-Rust purity assertion (the workspace coverage scan in
//! `arkhe-trait-default-check` does not currently include the
//! `examples/` tree, but the property holds at the source-line level).
//!
//! ## Why this proves the framework "works"
//!
//! - **Sealed-trait surface.** `ArkheAction` / `ArkheEvent` are
//!   `__Sealed`-bound — only `#[derive(...)]`-emitted impls satisfy the
//!   bound. A consumer crate (`card-primitives`) successfully producing
//!   such impls demonstrates the derive-from-external pathway is open.
//! - **Pipeline determinism.** `arkhe_forge_core::pipeline::process_action`
//!   runs the compute body and drains the
//!   `arkhe_forge_core::context::EventRecord` buffer; same `(action,
//!   ctx)` → byte-identical event payload (verified by the integration
//!   test `replay_determinism_event_payload_byte_identical`).
//! - **Chain-hash continuity.** The chain-hash recomputed inside the
//!   Action body matches `ShowdownReceipt::chain_hash()` (same domain
//!   tag, same byte order) — so an off-runtime audience that only sees
//!   the runtime event stream can still reconstruct the showdown anchor.
//!
//! Educational scope — the example demonstrates the Forge L1
//! Action + Event shape; production deployments would add capability
//! gating, idempotency keys, and L2 dispatch wiring.

use serde::{Deserialize, Serialize};

use arkhe_forge_core::action::ActionCompute;
use arkhe_forge_core::context::{ActionContext, ActionError};
use arkhe_forge_core::{arkhe_pure, ArkheAction, ArkheEvent};

use crate::shuffle_proof::{verify_shuffle_order, ShuffleCommitment};

/// Domain-separation tag — matches `shuffle_proof::DOMAIN_SHOWDOWN`.
/// Duplicated here (rather than imported as a `pub const`) because the
/// shuffle_proof module keeps the tag private to its own scope; the
/// constant is byte-identical so the chain-hash reconstructed inside
/// the compute body matches `ShowdownReceipt::chain_hash()` exactly.
const DOMAIN_SHOWDOWN: &[u8] = b"arkhe-forge::shuffle_proof::v1::showdown::";

/// Length-sealed 52-byte deck order wrapper.
///
/// Stock `serde_derive` only auto-implements `Serialize` /
/// `Deserialize` for arrays up to 32 elements; the canonical 52-byte
/// deck order needs a manual impl. Pattern alignment with
/// `arkhe-forge-core::event::Attestation` (the workspace's reference
/// length-sealed bytes wrapper):
///
/// - **Constructor side** — `from_array([u8; 52])` is the only public
///   way in, so the type system rejects any other length at compile
///   time.
/// - **Deserialize side** — postcard wire bytes whose payload length
///   is not exactly 52 produce a `serde::de::Error`, never a panic.
///
/// Lifts the length invariant from convention to the type itself: any
/// `DeckOrderBytes` value that exists has 52 bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DeckOrderBytes {
    inner: [u8; 52],
}

impl DeckOrderBytes {
    /// Construct from a fixed 52-byte deck order. The `[u8; 52]`
    /// parameter type makes the length invariant statically enforced.
    #[must_use]
    pub fn from_array(bytes: [u8; 52]) -> Self {
        Self { inner: bytes }
    }

    /// Borrow the underlying 52-byte payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Copy out the fixed 52-byte payload. Trivial now that the backing
    /// is a fixed-size array — no length check, no panic-defense needed
    /// (the type invariant is the array length itself).
    #[must_use]
    pub fn as_array(&self) -> [u8; 52] {
        self.inner
    }
}

impl Serialize for DeckOrderBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Wire-byte-identical to a `Vec<u8>` backing: postcard emits a
        // length-prefix + the 52 bytes either way.
        self.inner.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeckOrderBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let inner: Vec<u8> = Vec::deserialize(deserializer)?;
        if inner.len() != 52 {
            return Err(serde::de::Error::custom(format!(
                "DeckOrderBytes: expected 52 bytes, got {}",
                inner.len()
            )));
        }
        let arr: [u8; 52] = inner
            .try_into()
            .map_err(|_| serde::de::Error::custom("DeckOrderBytes try_into failed"))?;
        Ok(Self { inner: arr })
    }
}

/// L1 Action — record a Hold'em hand showdown into the runtime event
/// log.
///
/// On `compute()`, the Action verifies the (commitment, seed,
/// deck_order) triple via the same path as the audience-side
/// [`verify_shuffle_order`] flow, then emits a [`HandShowdownLanded`]
/// event whose payload pins the canonical chain-hash anchor.
///
/// The `[u8; 6]` `hand_rank_bytes` is the canonical encoding of a
/// `HandRank` via `HandRank::to_chain_hash_bytes`; this Action does
/// not re-evaluate the hand from cards (the showdown evaluation is the
/// caller's responsibility) — it only **anchors** the receipt the
/// caller hands in.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0100_0001, schema_version = 1, band = 1)]
pub struct RecordHandShowdown {
    /// Wire-level schema version tag (first field — required by the
    /// `ArkheAction` derive macro).
    pub schema_version: u16,
    /// 32-byte BLAKE3 commitment broadcast by the dealer pre-shuffle.
    pub commitment: [u8; 32],
    /// 32-byte seed revealed by the dealer post-deal — must hash to
    /// `commitment` under the `shuffle_proof` commit domain tag.
    pub seed: [u8; 32],
    /// Canonical 52-byte deck order as dealt — each entry is a
    /// `Card::to_byte()` value 0..=51. Wrapped in [`DeckOrderBytes`]
    /// because stock `serde_derive` array support stops at 32 bytes.
    pub deck_order: DeckOrderBytes,
    /// Canonical 6-byte `HandRank::to_chain_hash_bytes()` encoding of
    /// the winning hand.
    pub hand_rank_bytes: [u8; 6],
}

/// L1 Event — emitted when [`RecordHandShowdown`] lands successfully
/// in the WAL stream.
///
/// The single payload field, `chain_hash`, is the same 32-byte digest
/// `ShowdownReceipt::chain_hash()` produces for the verbatim
/// (`deck_order`, `hand_rank_bytes`) pair, so an audience downstream
/// that only sees the event log can reconstruct the showdown anchor
/// without re-running the verification.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0100_0002, schema_version = 1)]
pub struct HandShowdownLanded {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// 32-byte BLAKE3 chain-hash anchor over (deck_order, hand_rank_bytes).
    pub chain_hash: [u8; 32],
}

impl ActionCompute for RecordHandShowdown {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // Stage 1 — commitment binding check. Recompute
        // `BLAKE3(domain || seed)` and compare against the broadcast
        // commitment. Both sides are lifted into `ShuffleCommitment`
        // so the equality check flows through `blake3::Hash`'s
        // constant-time `PartialEq` rather than a short-circuit
        // byte-array comparison — this is type-system consistency
        // with the broader ShuffleCommitment surface (the timing
        // discipline is not strictly required here because the
        // commitment is publicly broadcast).
        let recomputed = ShuffleCommitment::from_seed(&self.seed);
        let provided = ShuffleCommitment::from_bytes(self.commitment);
        if recomputed != provided {
            return Err(ActionError::InvalidInput("commitment mismatch"));
        }
        // Stage 2 — replay reproducibility check. Reuses the public
        // `verify_shuffle_order` API: rebuild a `Deck::standard`,
        // shuffle with `RngSource::from_seed(&seed)`, compare the
        // resulting 52-byte order to the receipt.
        let deck_order_arr = self.deck_order.as_array();
        verify_shuffle_order(&recomputed, &self.seed, &deck_order_arr)
            .map_err(|_| ActionError::InvalidInput("shuffle order invalid"))?;
        // Stage 3 — chain-hash recomputation. Byte-for-byte the same
        // path as `ShowdownReceipt::chain_hash` so downstream audiences
        // can reconstruct the anchor without re-running stages 1-2.
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_SHOWDOWN);
        h.update(self.deck_order.as_bytes());
        h.update(&self.hand_rank_bytes);
        let chain_hash = *h.finalize().as_bytes();
        // Stage 4 — emit canonical event. Pipeline drains and the
        // payload becomes part of the chain-anchored runtime log.
        ctx.emit_event(&HandShowdownLanded {
            schema_version: 1,
            chain_hash,
        })?;
        Ok(())
    }
}
