//! Deck — fixed-size 52-card deck with cursor-based draw + Fisher-Yates shuffle.
//!
//! ## Design contract (atomic, non-negotiable)
//!
//! - **Storage = `[Card; 52]`** fixed array. Cardinality 52 lives in the
//!   type system; no `Vec`/`ArrayVec` (no_std-clean, fixed-size invariant).
//! - **Cursor `u8` 0..=52.** `cards[..cursor]` = drawn region (preserved
//!   through shuffle); `cards[cursor..]` = undrawn region (shuffle target).
//!   `draw()` advances the cursor monotonically; `cursor == 52` means the
//!   deck is exhausted (all subsequent `draw()` return `None`).
//! - **Shuffle = Fisher-Yates / Knuth.** Operates only on the undrawn region
//!   `cards[cursor..]`. Caller-supplied `RngCore`. The bounded-uniform
//!   integer draw at each iteration uses Lemire's debiased multiply-shift
//!   (see `unbiased_range_u32`) — modulo bias is mathematically zero
//!   given a uniform underlying RNG, satisfying GLI-19 §3.2.5's 1e-9
//!   bias bound by construction.
//! - **Draw = pop-from-end semantics.** `draw()` yields `cards[cursor]`
//!   then increments cursor. Combined with shuffle (which permutes
//!   `cards[cursor..]`), the deal is uniformly random over `52!`
//!   permutations when the supplied RNG is uniform.
//! - **No `Default` / no `Hash` / no `Copy`.** Deck construction always
//!   goes through `Deck::standard()` (canonical byte-order foundation);
//!   Hash is impl-defined non-canonical (chain-hash binding lives at
//!   shuffle-receipt anchoring); Copy is rejected because Clone
//!   semantics for a 52-byte struct should be explicit.
//! - **Audit view only.** [`Deck::cards`] exposes the FULL 52-card backing
//!   array including the undrawn region. The companion `verify_shuffle`
//!   API consumes a cursor=0 snapshot; for multi-player engines, `&Deck`
//!   MUST be access-controlled to trusted dealer scope only — never
//!   expose to player-side code paths. A production refactor may seal
//!   `cards()` to `pub(crate)` or replace it with a `drawn()` +
//!   `remaining_count()` split.
//! - **`no_std + alloc` ready.** Core API uses only `core::` paths; tests
//!   use `std::collections::BTreeSet` (alloc) for cardinality verification.
//!
//! Educational scope. Band 3 axiom anchoring is deferred — the
//! `examples/` tree is exempt from the workspace axiom-cite gate.

use rand_core::RngCore;

use crate::card::{Card, Rank, Suit};

// Compile-time invariant: the (Rank::ALL × Suit::ALL) cross-product fills
// the 52-card array exactly. Any future change to either ALL table that
// breaks the 13 × 4 = 52 product is caught at build time, before the
// runtime debug_assert in `Deck::standard()` would fire.
const _: () = {
    assert!(Rank::ALL.len() * Suit::ALL.len() == 52);
};

/// Uniform integer in `0..bound` via Lemire's debiased multiply-shift.
///
/// For `bound` values that don't divide `2³²` evenly, naive
/// `next_u32() % bound` produces a biased distribution where the low
/// outputs `0..(2³² mod bound)` are slightly more probable than the
/// high outputs. Fisher-Yates calls this site with `bound ∈ {2, 3, ..., 52}`,
/// and the worst-case naive modulo bias for `bound = 52` is
/// `1 / 2³² ≈ 2.33e-10` per output — which compounds non-trivially
/// across the 51 sequential draws of a single shuffle.
///
/// Lemire's method maps the 32-bit RNG output to a 64-bit space, uses
/// the high 32 bits as the candidate, and uses the low 32 bits as a
/// rejection signal. The expected number of RNG draws per call is
/// `1 + bound / 2³² ≈ 1 + 1.21e-8` for `bound ≤ 52`, so the rejection
/// loop terminates in ~one iteration with overwhelming probability.
///
/// Reference: D. Lemire, *"Fast Random Integer Generation in an
/// Interval"*, ACM TOMACS 2019, §3 — <https://arxiv.org/abs/1805.10941>.
///
/// GLI-19 §3.2.5 1e-9 bias bound is satisfied by construction: with a
/// uniform underlying RNG, the output distribution of this function is
/// **mathematically uniform** (the rejection loop equates the output
/// space to a multiple of `bound`). With BLAKE3 keyed-PRF as the
/// underlying RNG (see `shuffle_proof::ProofRng`), the statistical
/// distance from uniform is bounded by the BLAKE3 PRF security
/// parameter (≈ 2⁻¹²⁸), well below the 1e-9 regulatory threshold.
#[inline]
fn unbiased_range_u32<R: RngCore>(rng: &mut R, bound: u32) -> u32 {
    debug_assert!(bound > 0);
    let mut x = rng.next_u32();
    let mut m = (x as u64).wrapping_mul(bound as u64);
    let mut l = m as u32;
    if l < bound {
        // `t = (2³² - bound) mod bound = (2³² mod bound)` — the smallest
        // multiple of `bound` that fits in u32, expressed as a rejection
        // threshold. `bound.wrapping_neg()` is `2³² - bound` in u32
        // arithmetic.
        let t = bound.wrapping_neg() % bound;
        while l < t {
            x = rng.next_u32();
            m = (x as u64).wrapping_mul(bound as u64);
            l = m as u32;
        }
    }
    // `(m >> 32)` is the candidate, uniform on `0..bound` after the
    // rejection loop. Suppress the unused-variable lint for `x`: it's
    // the source of `m` and the rejection-loop body's only side effect
    // is the `m`/`l` updates.
    let _ = x;
    (m >> 32) as u32
}

/// 52-card playing deck with cursor-based draw + Fisher-Yates shuffle.
///
/// See module-level documentation for the design contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deck {
    cards: [Card; 52],
    /// Index of the next card to draw. `cursor == 52` ⇒ deck exhausted.
    cursor: u8,
}

impl Deck {
    /// Construct a fresh deck in canonical byte-order (`Two of Clubs` at
    /// index 0, `Ace of Spades` at index 51 — matches `Card::to_byte()`
    /// 0..=51 ordering). Cursor reset to 0.
    pub fn standard() -> Self {
        // Cardinality is enforced at compile time by the module-level
        // `const _: ()` assertion (Rank::ALL.len() × Suit::ALL.len() == 52),
        // so the nested loop unconditionally fills all 52 slots — no runtime
        // post-condition check needed.
        let mut cards = [Card::new(Rank::Two, Suit::Clubs); 52];
        let mut i: usize = 0;
        for &rank in &Rank::ALL {
            for &suit in &Suit::ALL {
                cards[i] = Card::new(rank, suit);
                i += 1;
            }
        }
        Deck { cards, cursor: 0 }
    }

    /// Shuffle the undrawn region `cards[cursor..]` in place via
    /// Fisher-Yates / Knuth. The drawn region `cards[..cursor]` is
    /// preserved verbatim — re-shuffle of a partially dealt deck is
    /// well-defined (only the unseen tail is permuted).
    ///
    /// Each inner-loop draw uses `unbiased_range_u32` (Lemire's
    /// rejection-sampling) so the resulting permutation is
    /// **mathematically uniform** over the symmetric group of the
    /// undrawn region — GLI-19 §3.2.5 1e-9 bias bound is satisfied by
    /// construction; no per-draw bias accumulates across the 51
    /// sequential swaps of a fresh-deck shuffle.
    pub fn shuffle<R: RngCore>(&mut self, rng: &mut R) {
        let start = self.cursor as usize;
        if start >= 52 {
            return;
        }
        let len = 52 - start;
        if len < 2 {
            return;
        }
        // Iterate i from len-1 down to 1 (inclusive). For each i, swap
        // cards[start + i] with cards[start + j] where j is uniform in
        // 0..=i (so the random integer is drawn from `0..(i+1)`).
        let mut i = len - 1;
        while i >= 1 {
            // j ∈ 0..=i — bounded-uniform via Lemire's debiased
            // multiply-shift. Cast to u32 is sound because `i ≤ 51`.
            let j = unbiased_range_u32(rng, (i + 1) as u32) as usize;
            self.cards.swap(start + i, start + j);
            i -= 1;
        }
    }

    /// Draw the next card from the top of the deck. Returns `None` when
    /// the deck is exhausted (`cursor == 52`). Advances the cursor by 1
    /// on success.
    pub fn draw(&mut self) -> Option<Card> {
        if self.cursor >= 52 {
            return None;
        }
        let card = self.cards[self.cursor as usize];
        self.cursor += 1;
        Some(card)
    }

    /// Number of undrawn cards remaining (52 minus draws issued).
    pub const fn remaining(&self) -> usize {
        // cursor ∈ 0..=52 invariant ⇒ subtraction never underflows.
        52 - self.cursor as usize
    }

    /// Read-only slice of the full 52-card backing array, in current order
    /// (drawn region preserved at the front; undrawn region at the back).
    /// Use `&deck.cards()[..deck.cursor()]` and `&deck.cards()[deck.cursor()..]`
    /// to inspect drawn vs undrawn regions; the cursor itself is exposed
    /// via [`Deck::cursor`].
    ///
    /// **Audit view only** — see the module-level *Audit view only*
    /// design-contract bullet. Multi-player engines MUST gate this method
    /// to trusted dealer scope; player-side code paths must not see the
    /// undrawn region. A production refactor may seal this method to
    /// `pub(crate)` or replace it with a `drawn()` + `remaining_count()`
    /// split.
    pub const fn cards(&self) -> &[Card] {
        &self.cards
    }

    /// Current cursor position (number of cards drawn so far, 0..=52).
    pub const fn cursor(&self) -> usize {
        self.cursor as usize
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::collections::BTreeSet;

    /// Deterministic LCG-style test RNG. Quality is sufficient for
    /// shuffle determinism + cardinality preservation tests; the
    /// production binary uses `shuffle_proof::ProofRng` (BLAKE3
    /// keyed-PRF), and a future hardening cycle may swap that for a
    /// system-RNG (`getrandom`) front-end.
    ///
    /// LCG constants from PCG-XSL-RR family: multiplier
    /// `0x5851_F42D_4C95_7F2D` is the canonical PCG default.
    struct TestCounterRng {
        state: u64,
    }

    impl TestCounterRng {
        const fn new(seed: u64) -> Self {
            // Avoid the all-zeros fixed point: seed | 1 forces an odd
            // initial state, ensuring the LCG produces a non-trivial
            // sequence even from `TestCounterRng::new(0)`.
            Self { state: seed | 1 }
        }
    }

    impl RngCore for TestCounterRng {
        fn next_u32(&mut self) -> u32 {
            self.state = self
                .state
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0xA3B1_9535_4A39_B70D);
            (self.state >> 32) as u32
        }

        fn next_u64(&mut self) -> u64 {
            ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                let bytes = self.next_u32().to_le_bytes();
                for (i, slot) in chunk.iter_mut().enumerate() {
                    *slot = bytes[i];
                }
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn collect_all(deck: &Deck) -> BTreeSet<Card> {
        deck.cards().iter().copied().collect()
    }

    #[test]
    fn deck_standard_has_52_cards() {
        let deck = Deck::standard();
        assert_eq!(deck.cards().len(), 52);
        assert_eq!(deck.remaining(), 52);
        assert_eq!(deck.cursor(), 0);
    }

    #[test]
    fn deck_standard_canonical_byte_order() {
        let deck = Deck::standard();
        for (i, card) in deck.cards().iter().enumerate() {
            assert_eq!(
                card.to_byte() as usize,
                i,
                "card at index {i} should have byte value {i}"
            );
        }
    }

    #[test]
    fn deck_standard_all_unique() {
        let deck = Deck::standard();
        let set = collect_all(&deck);
        assert_eq!(set.len(), 52);
    }

    #[test]
    fn deck_shuffle_preserves_cardinality_and_uniqueness() {
        let mut deck = Deck::standard();
        let mut rng = TestCounterRng::new(0xDEAD_BEEF);
        deck.shuffle(&mut rng);
        let set = collect_all(&deck);
        assert_eq!(set.len(), 52, "shuffle must preserve cardinality");
        assert_eq!(deck.remaining(), 52, "shuffle must not advance cursor");
    }

    #[test]
    fn deck_shuffle_deterministic_same_rng_same_permutation() {
        let mut deck1 = Deck::standard();
        let mut deck2 = Deck::standard();
        let mut rng1 = TestCounterRng::new(42);
        let mut rng2 = TestCounterRng::new(42);
        deck1.shuffle(&mut rng1);
        deck2.shuffle(&mut rng2);
        assert_eq!(deck1, deck2, "identical RNG state ⇒ identical permutation");
    }

    #[test]
    fn deck_shuffle_actually_shuffles() {
        let mut deck = Deck::standard();
        let canonical = Deck::standard();
        let mut rng = TestCounterRng::new(0xCAFE_F00D);
        deck.shuffle(&mut rng);
        assert_ne!(
            deck, canonical,
            "non-trivial RNG should produce a non-canonical permutation"
        );
    }

    #[test]
    fn deck_shuffle_different_rng_different_permutation() {
        let mut deck1 = Deck::standard();
        let mut deck2 = Deck::standard();
        let mut rng1 = TestCounterRng::new(1);
        let mut rng2 = TestCounterRng::new(2);
        deck1.shuffle(&mut rng1);
        deck2.shuffle(&mut rng2);
        assert_ne!(
            deck1, deck2,
            "distinct seeds should diverge into distinct permutations"
        );
    }

    #[test]
    fn deck_draw_decrements_remaining() {
        let mut deck = Deck::standard();
        assert_eq!(deck.remaining(), 52);
        for expected in (0..52).rev() {
            let _ = deck.draw().unwrap();
            assert_eq!(deck.remaining(), expected);
        }
        assert_eq!(deck.cursor(), 52);
    }

    #[test]
    fn deck_draw_yields_all_52_distinct() {
        let mut deck = Deck::standard();
        let mut seen = BTreeSet::new();
        for _ in 0..52 {
            let card = deck.draw().unwrap();
            assert!(seen.insert(card), "duplicate card drawn: {card}");
        }
        assert_eq!(seen.len(), 52);
    }

    #[test]
    fn deck_draw_after_exhaustion_returns_none() {
        let mut deck = Deck::standard();
        for _ in 0..52 {
            assert!(deck.draw().is_some());
        }
        assert!(deck.draw().is_none());
        assert!(deck.draw().is_none(), "exhaustion is sticky");
    }

    #[test]
    fn deck_draw_in_canonical_order_yields_byte_ascending() {
        let mut deck = Deck::standard();
        for expected_byte in 0..=51u8 {
            let card = deck.draw().unwrap();
            assert_eq!(card.to_byte(), expected_byte);
        }
    }

    #[test]
    fn deck_clone_independence() {
        let mut a = Deck::standard();
        let b = a.clone();
        let mut rng = TestCounterRng::new(7);
        a.shuffle(&mut rng);
        // b unaffected by a's shuffle
        assert_eq!(b, Deck::standard());
        let _ = a.draw();
        // b still unaffected by a's draw
        assert_eq!(b.remaining(), 52);
    }

    #[test]
    fn deck_shuffle_preserves_already_drawn_region() {
        let mut deck = Deck::standard();
        // Draw 5 cards (canonical Two-of-Clubs through Three-of-Diamonds —
        // bytes 0..=4).
        let drawn: Vec<Card> = (0..5).map(|_| deck.draw().unwrap()).collect();
        let drawn_snapshot: Vec<Card> = deck.cards()[..deck.cursor()].to_vec();
        assert_eq!(drawn_snapshot, drawn);
        // Shuffle only permutes cards[cursor..52].
        let mut rng = TestCounterRng::new(0xBAD0_CAFE);
        deck.shuffle(&mut rng);
        // Drawn region byte-identical post-shuffle.
        assert_eq!(&deck.cards()[..5], drawn.as_slice());
        // Undrawn region full cardinality 47 distinct.
        let undrawn: BTreeSet<Card> = deck.cards()[5..].iter().copied().collect();
        assert_eq!(undrawn.len(), 47);
    }

    #[test]
    fn deck_shuffle_on_exhausted_deck_is_noop() {
        let mut deck = Deck::standard();
        for _ in 0..52 {
            let _ = deck.draw();
        }
        let snapshot = deck.clone();
        let mut rng = TestCounterRng::new(0xFEED);
        deck.shuffle(&mut rng);
        assert_eq!(deck, snapshot, "shuffle on exhausted deck must be a no-op");
    }
}
