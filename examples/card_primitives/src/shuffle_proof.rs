//! Shuffle commit-reveal verifier — chain-hash anchoring.
//!
//! ## Design contract (atomic, non-negotiable)
//!
//! - **Commit-reveal binding.** The dealer picks a 32-byte seed, computes
//!   `commitment = BLAKE3(domain || seed)`, and broadcasts the
//!   commitment before the shuffle. After the deal, the seed is
//!   revealed — verifiers recompute the commitment and reproduce the
//!   shuffle to confirm the dealer could not have changed the deck
//!   ordering after committing.
//! - **PRNG = `arkhe_rand::RngSource`.** BLAKE3 KDF mode (context tag
//!   `"arkhe-rand stream v0.13"`) drives a single continuous XOF stream
//!   for the shuffle. Cryptographically equivalent to ChaCha20-style
//!   stream RNG for binding purposes; the audited `arkhe-rand` crate
//!   centralises the keyed-PRNG primitive once for all shell-side
//!   consumers (Zeroize seed, redacted Debug, sealed RandInt trait).
//! - **Domain separation.** Every BLAKE3 site uses a distinct ASCII
//!   prefix so the same byte string cannot serve two protocol roles:
//!   `commit::`, `showdown::`, plus the arkhe-rand KDF context for the
//!   PRNG channel. Cross-protocol substitution attacks structurally
//!   cannot apply.
//! - **`verify_shuffle` = pure function.** No `&mut` state, no I/O,
//!   no heap; deterministic in its inputs. Compatible with the runtime
//!   `#[arkhe_pure]` attribute (anyone-runnable; no dealer trust).
//! - **`ShowdownReceipt`** packs `(deck_order: [u8; 52], hand_rank:
//!   HandRank)` into the canonical chain-hash anchor input.
//!   `chain_hash()` returns a 32-byte BLAKE3 digest that downstream
//!   runtime event-log binding sites can pin verbatim.
//! - **No `Default` / no `Hash`.** Same chain-hash-anchoring discipline
//!   as `Card`, `Deck`, `HandRank` — domain-correct hashing must go
//!   through the explicit BLAKE3 sites here, not through the impl-
//!   defined `core::hash::Hash` derive.
//! - **PRNG seed scrubbing.** `arkhe_rand::RngSource` zeroizes its
//!   internal seed via `Zeroizing<[u8; 32]>` and replaces its XOF
//!   reader with a sentinel on drop, so seed material from the verifier
//!   path is wiped automatically. `ShuffleCommitment` is intentionally
//!   **not** zeroized: the commitment digest is broadcast publicly, so
//!   memory residue carries no extra disclosure. The `Hasher` instance
//!   inside `ShuffleCommitment::from_seed` is short-lived and not
//!   zeroized today; production hardening (a `blake3::Hasher: Zeroize`
//!   upstream feature) is a follow-on carry.
//! - **Type-strengthened commitment.** `ShuffleCommitment(blake3::Hash)`
//!   inherits `blake3::Hash`'s constant-time `PartialEq`.
//!   `[u8; 32]` newtype would have used `core::cmp::PartialEq` — variable-
//!   time array comparison is acceptable for *commitment* equality
//!   (no secret), but the typed form propagates the constant-time
//!   contract to any future site that accepts the type.
//! - **Single-party scope.** VRF binding (verifiable randomness from
//!   external entropy) and multi-party shuffle protocols (commit-share
//!   recombination) are deferred to a follow-on DIP cycle; the single-
//!   party commit-reveal demonstrated here is the foundation those
//!   build on.
//!
//! Educational scope. Band 3 axiom anchoring is deferred — the
//! `examples/` tree is exempt from the workspace axiom-cite gate.

use core::fmt;

use arkhe_rand::RngSource;
use blake3::Hasher;

use crate::card::Card;
use crate::deck::Deck;
use crate::hand_eval::HandRank;

/// Domain-separation tag for `ShuffleCommitment` BLAKE3 input.
const DOMAIN_COMMIT: &[u8] = b"arkhe-forge::shuffle_proof::v1::commit::";
/// Domain-separation tag for `ShowdownReceipt` BLAKE3 anchor.
const DOMAIN_SHOWDOWN: &[u8] = b"arkhe-forge::shuffle_proof::v1::showdown::";

// =========================================================================
// ShuffleCommitment
// =========================================================================

/// 32-byte BLAKE3 commitment to a shuffle seed.
///
/// `from_seed(seed)` returns `BLAKE3(DOMAIN_COMMIT || seed)`. The
/// dealer broadcasts the commitment before the shuffle; the seed is
/// revealed afterwards so verifiers can confirm the binding via
/// `verify_shuffle` / `verify_shuffle_order`.
///
/// Backed by [`blake3::Hash`] rather than a raw `[u8; 32]` newtype —
/// this propagates BLAKE3's constant-time `PartialEq` (constant-time
/// 32-byte equality) to all sites that accept this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShuffleCommitment(blake3::Hash);

impl ShuffleCommitment {
    /// Compute the commitment for a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Hasher::new();
        h.update(DOMAIN_COMMIT);
        h.update(seed);
        Self(h.finalize())
    }

    /// Construct from a raw 32-byte digest. The caller asserts this is
    /// the output of `BLAKE3(DOMAIN_COMMIT || seed)` for some seed; no
    /// recomputation is performed by this constructor.
    ///
    /// Used at deserialization boundaries — e.g. an `ArkheAction` whose
    /// wire format carries `commitment: [u8; 32]` lifts the raw bytes
    /// into a `ShuffleCommitment` so the subsequent equality check
    /// against `from_seed(...)` flows through the
    /// constant-time `blake3::Hash` `PartialEq` instead of the
    /// short-circuit byte-array comparison. The constant-time
    /// discipline is unnecessary for commitment values (publicly
    /// broadcast) but is propagated for type-system consistency with
    /// the broader ShuffleCommitment surface.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from(bytes))
    }

    /// 32-byte commitment digest as raw bytes. For equality checks
    /// prefer the type's `PartialEq` (constant-time via [`blake3::Hash`])
    /// over byte-array comparison.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

// =========================================================================
// verify_shuffle
// =========================================================================

/// Verifier error — distinguishes commitment-binding failure from
/// replay-reproducibility failure for diagnostic clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// `BLAKE3(domain || revealed_seed) != commitment` — the dealer
    /// either committed to a different seed or tampered with the
    /// commitment broadcast.
    CommitmentMismatch,
    /// The revealed seed produces a deck order that does not match the
    /// dealer-broadcast deck — the shuffle was not produced by
    /// `Deck::standard().shuffle(RngSource::from_seed(&seed))`.
    DeckMismatch,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::CommitmentMismatch => {
                f.write_str("shuffle commitment does not match BLAKE3(domain || revealed_seed)")
            }
            ProofError::DeckMismatch => {
                f.write_str("replayed shuffle does not match the broadcast deck order")
            }
        }
    }
}

/// Pure verifier (Deck-facing) — checks that `expected_deck` is the
/// canonical outcome of `Deck::standard().shuffle(RngSource::from_seed(revealed_seed))`
/// AND that `commitment` was honestly bound to that seed.
///
/// Use this when the verifier holds the post-shuffle [`Deck`] state
/// directly — typically the **pre-deal** moment, before any cards
/// have been drawn (the cursor / draw position is part of `Deck`'s
/// equality, so a partially-dealt deck would mismatch a freshly
/// shuffled one). For the post-deal showdown path, prefer
/// [`verify_shuffle_order`], which compares the canonical 52-byte
/// order array embedded in [`ShowdownReceipt`] and is cursor-agnostic.
///
/// Anyone-runnable: requires only the commitment, the revealed seed,
/// and the broadcast deck order. No dealer interaction; no &mut state;
/// deterministic in its inputs.
pub fn verify_shuffle(
    commitment: &ShuffleCommitment,
    revealed_seed: &[u8; 32],
    expected_deck: &Deck,
) -> Result<(), ProofError> {
    // Stage 1 — commitment binding: recompute and compare.
    let recomputed = ShuffleCommitment::from_seed(revealed_seed);
    if recomputed != *commitment {
        return Err(ProofError::CommitmentMismatch);
    }
    // Stage 2 — replay reproducibility: deal the deck from scratch
    // using the revealed seed and verify the order matches verbatim.
    let mut rng = RngSource::from_seed(revealed_seed);
    let mut replay = Deck::standard();
    replay.shuffle(&mut rng);
    if &replay != expected_deck {
        return Err(ProofError::DeckMismatch);
    }
    Ok(())
}

/// Pure verifier (order-facing) — checks that `expected_order` is the
/// canonical 52-byte deck order produced by replaying the shuffle from
/// `revealed_seed`, AND that `commitment` was honestly bound to that
/// seed.
///
/// Companion to [`verify_shuffle`]. Operates on the raw byte array
/// (e.g. [`ShowdownReceipt::deck_order`]) rather than a `Deck` value —
/// the verification is cursor-agnostic, so post-deal showdown receipts
/// (where some cards have already been drawn from the dealer-side
/// `Deck`) can be verified by the audience without reconstructing the
/// full `Deck` state.
///
/// Anyone-runnable: requires only the commitment, the revealed seed,
/// and the broadcast 52-byte order. No dealer interaction; no &mut
/// state; deterministic in its inputs.
pub fn verify_shuffle_order(
    commitment: &ShuffleCommitment,
    revealed_seed: &[u8; 32],
    expected_order: &[u8; 52],
) -> Result<(), ProofError> {
    // Stage 1 — commitment binding: recompute and compare.
    let recomputed = ShuffleCommitment::from_seed(revealed_seed);
    if recomputed != *commitment {
        return Err(ProofError::CommitmentMismatch);
    }
    // Stage 2 — replay reproducibility: deal the deck from scratch and
    // compare the canonical byte order. Cursor state is irrelevant.
    let mut rng = RngSource::from_seed(revealed_seed);
    let mut replay = Deck::standard();
    replay.shuffle(&mut rng);
    let mut replay_order = [0u8; 52];
    for (i, c) in replay.cards().iter().enumerate() {
        replay_order[i] = c.to_byte();
    }
    if replay_order != *expected_order {
        return Err(ProofError::DeckMismatch);
    }
    Ok(())
}

// =========================================================================
// ShowdownReceipt — chain-hash anchor input
// =========================================================================

/// Canonical showdown receipt — combines the revealed deck order with
/// the final hand strength. Hashing this receipt yields the chain-hash
/// anchor that downstream runtime event-log binding sites pin verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShowdownReceipt {
    /// Canonical 52-byte deck order — each entry is a `Card::to_byte()`
    /// value 0..=51, captured in the post-shuffle order.
    ///
    /// **Cursor-agnostic by design.** This field records the FULL
    /// 52-card permutation produced by the shuffle, regardless of how
    /// many cards have been drawn from the dealer-side `Deck` by the
    /// time the receipt is constructed. Audience verification via
    /// [`verify_shuffle_order`] only inspects this array; the receiving
    /// side never reconstructs the dealer's internal cursor position.
    /// [`verify_shuffle`] (which compares the full `Deck` value
    /// including its cursor) is the cursor-sensitive companion path —
    /// useful only at the pre-deal moment, before any cards have been
    /// drawn.
    pub deck_order: [u8; 52],
    /// Final hand strength evaluation.
    pub hand_rank: HandRank,
}

impl ShowdownReceipt {
    /// Build a receipt from a (possibly partially drawn) `Deck` plus
    /// the final `HandRank`. The receipt records the full 52-card order
    /// at receipt time.
    pub fn from_deck_and_hand(deck: &Deck, hand_rank: HandRank) -> Self {
        let cards = deck.cards();
        let mut deck_order = [0u8; 52];
        for (i, c) in cards.iter().enumerate() {
            deck_order[i] = c.to_byte();
        }
        Self {
            deck_order,
            hand_rank,
        }
    }

    /// Build a receipt directly from a 52-card slice (for tests /
    /// hand-constructed scenarios where no `Deck` is involved).
    ///
    /// Educational API surface — kept for callers that hold a raw
    /// `[Card; 52]` (e.g. multi-party shuffle protocols where the
    /// reconstructed order does not flow through `Deck`).
    pub fn from_cards_and_hand(cards: &[Card; 52], hand_rank: HandRank) -> Self {
        let mut deck_order = [0u8; 52];
        for (i, c) in cards.iter().enumerate() {
            deck_order[i] = c.to_byte();
        }
        Self {
            deck_order,
            hand_rank,
        }
    }

    /// Compute the canonical 32-byte BLAKE3 chain-hash anchor:
    /// `BLAKE3(DOMAIN_SHOWDOWN || deck_order || hand_rank.to_chain_hash_bytes())`.
    pub fn chain_hash(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(DOMAIN_SHOWDOWN);
        h.update(&self.deck_order);
        h.update(&self.hand_rank.to_chain_hash_bytes());
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::card::Rank;

    fn fixed_seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn nontrivial_seed() -> [u8; 32] {
        // Pseudo-random but deterministic — avoids the `[0; 32]` /
        // `[1; 32]` cases for richer testing.
        let mut s = [0u8; 32];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(5);
        }
        s
    }

    // --- ShuffleCommitment ---

    #[test]
    fn commitment_round_trip() {
        let seed = nontrivial_seed();
        let c1 = ShuffleCommitment::from_seed(&seed);
        let c2 = ShuffleCommitment::from_seed(&seed);
        assert_eq!(c1, c2, "same seed must yield identical commitment");
    }

    #[test]
    fn commitment_avalanche_1byte_flip() {
        let seed_a = nontrivial_seed();
        let mut seed_b = seed_a;
        seed_b[0] ^= 0x01;
        let c_a = ShuffleCommitment::from_seed(&seed_a);
        let c_b = ShuffleCommitment::from_seed(&seed_b);
        assert_ne!(
            c_a, c_b,
            "1-bit seed flip must change the commitment (BLAKE3 avalanche)"
        );
    }

    #[test]
    fn commitment_distinct_seeds_distinct() {
        let c0 = ShuffleCommitment::from_seed(&fixed_seed(0));
        let c1 = ShuffleCommitment::from_seed(&fixed_seed(1));
        let c_n = ShuffleCommitment::from_seed(&nontrivial_seed());
        assert_ne!(c0, c1);
        assert_ne!(c1, c_n);
        assert_ne!(c0, c_n);
    }

    // --- verify_shuffle (full happy path + 2 failure modes) ---

    fn shuffled_deck(seed: [u8; 32]) -> Deck {
        let mut deck = Deck::standard();
        let mut rng = RngSource::from_seed(&seed);
        deck.shuffle(&mut rng);
        deck
    }

    #[test]
    fn verify_shuffle_accepts_valid_proof() {
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let deck = shuffled_deck(seed);
        assert_eq!(verify_shuffle(&commitment, &seed, &deck), Ok(()));
    }

    #[test]
    fn verify_shuffle_rejects_commitment_mismatch() {
        let seed = nontrivial_seed();
        // Honest deck + commitment but caller passes the wrong revealed seed.
        let commitment = ShuffleCommitment::from_seed(&seed);
        let deck = shuffled_deck(seed);
        let mut wrong_seed = seed;
        wrong_seed[0] ^= 0xff;
        assert_eq!(
            verify_shuffle(&commitment, &wrong_seed, &deck),
            Err(ProofError::CommitmentMismatch)
        );
    }

    #[test]
    fn verify_shuffle_rejects_deck_mismatch() {
        // Honest commitment + revealed seed, but the broadcast deck was
        // tampered with (e.g., dealer reordered after committing).
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let mut deck = shuffled_deck(seed);
        // Tamper: draw 1 card to change the cursor + cards layout.
        let _ = deck.draw();
        assert_eq!(
            verify_shuffle(&commitment, &seed, &deck),
            Err(ProofError::DeckMismatch)
        );
    }

    #[test]
    fn verify_shuffle_rejects_completely_unrelated_deck() {
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let canonical = Deck::standard(); // unshuffled — definitely different
        assert_eq!(
            verify_shuffle(&commitment, &seed, &canonical),
            Err(ProofError::DeckMismatch)
        );
    }

    // --- verify_shuffle_order (cursor-agnostic, ShowdownReceipt-facing) ---

    fn shuffled_order(seed: [u8; 32]) -> [u8; 52] {
        let deck = shuffled_deck(seed);
        let mut order = [0u8; 52];
        for (i, c) in deck.cards().iter().enumerate() {
            order[i] = c.to_byte();
        }
        order
    }

    #[test]
    fn verify_shuffle_order_accepts_valid_proof() {
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let order = shuffled_order(seed);
        assert_eq!(verify_shuffle_order(&commitment, &seed, &order), Ok(()));
    }

    #[test]
    fn verify_shuffle_order_is_cursor_agnostic() {
        // Same seed → same canonical order, even after the dealer's
        // Deck has drawn cards (cursor advanced). The order array
        // captured at receipt time is what the verifier checks.
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let mut deck = shuffled_deck(seed);
        // Snapshot the order BEFORE any draws — this is what the
        // dealer broadcasts in the showdown receipt.
        let mut order = [0u8; 52];
        for (i, c) in deck.cards().iter().enumerate() {
            order[i] = c.to_byte();
        }
        // Now draw 5 cards (advancing the cursor). The Deck's equality
        // would change, but the canonical order array is unchanged.
        for _ in 0..5 {
            let _ = deck.draw();
        }
        // The post-draw Deck would FAIL verify_shuffle (cursor moved).
        assert_eq!(
            verify_shuffle(&commitment, &seed, &deck),
            Err(ProofError::DeckMismatch)
        );
        // But the snapshotted order PASSES verify_shuffle_order.
        assert_eq!(verify_shuffle_order(&commitment, &seed, &order), Ok(()));
    }

    #[test]
    fn verify_shuffle_order_rejects_commitment_mismatch() {
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let order = shuffled_order(seed);
        let mut wrong_seed = seed;
        wrong_seed[0] ^= 0xff;
        assert_eq!(
            verify_shuffle_order(&commitment, &wrong_seed, &order),
            Err(ProofError::CommitmentMismatch)
        );
    }

    #[test]
    fn verify_shuffle_order_rejects_byte_tamper() {
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let mut order = shuffled_order(seed);
        // Swap two adjacent bytes — order is no longer the canonical
        // shuffled order produced by the seed.
        order.swap(0, 1);
        assert_eq!(
            verify_shuffle_order(&commitment, &seed, &order),
            Err(ProofError::DeckMismatch)
        );
    }

    #[test]
    fn verify_shuffle_order_matches_showdown_receipt() {
        // End-to-end: a ShowdownReceipt's deck_order field is exactly
        // what verify_shuffle_order accepts.
        let seed = nontrivial_seed();
        let commitment = ShuffleCommitment::from_seed(&seed);
        let mut deck = shuffled_deck(seed);
        // Run a "deal" by drawing cards (cursor advances).
        for _ in 0..7 {
            let _ = deck.draw();
        }
        let receipt = ShowdownReceipt::from_deck_and_hand(&deck, HandRank::Straight(Rank::Ten));
        // Verifier receives the receipt and checks the shuffle order.
        assert_eq!(
            verify_shuffle_order(&commitment, &seed, &receipt.deck_order),
            Ok(())
        );
    }

    // --- ShowdownReceipt ---

    #[test]
    fn showdown_receipt_chain_hash_deterministic() {
        let seed = nontrivial_seed();
        let deck = shuffled_deck(seed);
        let rank = HandRank::Straight(Rank::Ten);
        let r1 = ShowdownReceipt::from_deck_and_hand(&deck, rank);
        let r2 = ShowdownReceipt::from_deck_and_hand(&deck, rank);
        assert_eq!(r1, r2);
        assert_eq!(r1.chain_hash(), r2.chain_hash());
    }

    #[test]
    fn showdown_receipt_changes_with_deck_order() {
        let rank = HandRank::Straight(Rank::Ten);
        let deck_a = shuffled_deck(fixed_seed(7));
        let deck_b = shuffled_deck(fixed_seed(11));
        let r_a = ShowdownReceipt::from_deck_and_hand(&deck_a, rank);
        let r_b = ShowdownReceipt::from_deck_and_hand(&deck_b, rank);
        assert_ne!(r_a.chain_hash(), r_b.chain_hash());
    }

    #[test]
    fn showdown_receipt_changes_with_hand_rank() {
        let deck = shuffled_deck(nontrivial_seed());
        let r_straight = ShowdownReceipt::from_deck_and_hand(&deck, HandRank::Straight(Rank::Ten));
        let r_flush = ShowdownReceipt::from_deck_and_hand(
            &deck,
            HandRank::Flush([Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]),
        );
        assert_ne!(r_straight.chain_hash(), r_flush.chain_hash());
    }

    #[test]
    fn showdown_receipt_chain_hash_includes_domain() {
        // Sanity: the chain hash is NOT just BLAKE3(deck_order || hand_rank);
        // it also folds in the DOMAIN_SHOWDOWN tag. We verify by
        // computing the un-tagged hash and confirming inequality.
        let deck = shuffled_deck(nontrivial_seed());
        let rank = HandRank::Straight(Rank::Ten);
        let r = ShowdownReceipt::from_deck_and_hand(&deck, rank);
        let tagged = r.chain_hash();
        let mut h = Hasher::new();
        h.update(&r.deck_order);
        h.update(&rank.to_chain_hash_bytes());
        let untagged = *h.finalize().as_bytes();
        assert_ne!(tagged, untagged, "domain tag must alter the digest");
    }
}
