//! Hand evaluator — Texas Hold'em "Hi" 9-category strength ranking.
//!
//! ## Design contract (atomic, non-negotiable)
//!
//! - **9-variant `HandRank` enum** in ascending strength order. Derive
//!   `Ord` orders variants by declaration position (HighCard < Pair < ...
//!   < StraightFlush); within a variant, the typed tuple/array fields
//!   carry the canonical tiebreaker. Royal Flush = `StraightFlush(Ace)`
//!   sub-case (no separate variant — Display layer renders the label).
//! - **Combinatorial evaluation.** [`evaluate_5`] sorts ranks descending,
//!   groups consecutive duplicates into `[(count, rank); 5]`, sorts the
//!   groups by `(count, rank)` descending, and pattern-matches on
//!   `(counts[0], counts[1])`. The 6-pattern dispatch (4,_) / (3,2) /
//!   (3,_) / (2,2) / (2,_) / (1,_) is exhaustive for any 5-card multiset
//!   drawn from a standard 52-card deck (max 4 of any rank).
//! - **Best-5-of-7.** [`evaluate_7`] enumerates `C(7,2) = 21` exclusion
//!   pairs, evaluates the remaining 5 cards, and tracks the max via
//!   `Ord`. No allocator — fixed `[Card; 5]` work buffer.
//! - **Ace-low wheel.** A-2-3-4-5 (sorted desc as `[Ace, Five, Four,
//!   Three, Two]`) is detected by an explicit branch and returns
//!   `Straight(Five)`. Steel wheel = `StraightFlush(Five)` (lowest SF);
//!   Royal = `StraightFlush(Ace)` (highest SF).
//! - **panic-free.** No `unreachable!`, no `unwrap`. The 6-pattern
//!   dispatch ends in a `_ => HighCard(ranks)` saturating fallback that
//!   is structurally unreachable for any valid 5-card subset.
//! - **No allocator dependency.** Fixed-size buffers throughout
//!   (`[(u8, Rank); 5]` group buffer, `[Card; 5]` 7-card sub-hand work
//!   buffer); compatible with the `no_std + alloc` design intent shared
//!   by `card.rs` and `deck.rs`.
//! - **Hi only.** Lo / Hi-Lo / Omaha / Stud variants are deferred.
//! - **"Steel Wheel" label.** `category_label()` renders
//!   `StraightFlush(Five)` as "Steel Wheel" — informal poker slang for
//!   the 5-4-3-2-A straight flush, the lowest possible SF. The term is
//!   non-canonical; production code generating audit logs may prefer
//!   the neutral "Straight Flush, Five-high" form. The current label
//!   is preserved for tutorial recognizability and matches the
//!   `Royal Flush` (`StraightFlush(Ace)`) sibling treatment.
//!
//! Educational scope. Band 3 axiom anchoring is deferred — the
//! `examples/` tree is exempt from the workspace axiom-cite gate.

use core::cmp::Ordering;
use core::fmt;

use crate::card::{Card, Rank};

/// Texas Hold'em "Hi" hand strength — 9 categories in ascending order.
///
/// `Ord` derive yields the canonical strength comparison: variant
/// declaration order picks the category, and within a variant the
/// typed fields encode the tiebreaker. See module-level docs for the
/// per-variant semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HandRank {
    /// 5 unmatched ranks (no pair, no straight, no flush). Tuple is the
    /// 5 ranks sorted descending.
    HighCard([Rank; 5]),
    /// One pair. Tuple = (pair rank, 3 kickers descending).
    Pair(Rank, [Rank; 3]),
    /// Two pair. Tuple = (high pair rank, low pair rank, kicker).
    TwoPair(Rank, Rank, Rank),
    /// Three of a kind. Tuple = (trips rank, 2 kickers descending).
    ThreeOfAKind(Rank, [Rank; 2]),
    /// Straight (5 consecutive ranks). Tuple = top rank. Ace-low wheel
    /// (A-2-3-4-5) is `Straight(Five)`, the lowest possible straight.
    Straight(Rank),
    /// Flush (5 cards same suit, not a straight). Tuple = 5 ranks
    /// sorted descending.
    Flush([Rank; 5]),
    /// Full house. Tuple = (trips rank, pair rank).
    FullHouse(Rank, Rank),
    /// Four of a kind. Tuple = (quads rank, kicker).
    FourOfAKind(Rank, Rank),
    /// Straight flush. Tuple = top rank. Steel wheel = `StraightFlush(Five)`;
    /// Royal Flush = `StraightFlush(Ace)`.
    StraightFlush(Rank),
}

impl HandRank {
    /// Stable category index 0..=8 (HighCard = 0, StraightFlush = 8) —
    /// useful for histogram / frequency analysis without exposing the
    /// internal tiebreaker tuple.
    pub const fn category_index(&self) -> u8 {
        match self {
            HandRank::HighCard(_) => 0,
            HandRank::Pair(_, _) => 1,
            HandRank::TwoPair(_, _, _) => 2,
            HandRank::ThreeOfAKind(_, _) => 3,
            HandRank::Straight(_) => 4,
            HandRank::Flush(_) => 5,
            HandRank::FullHouse(_, _) => 6,
            HandRank::FourOfAKind(_, _) => 7,
            HandRank::StraightFlush(_) => 8,
        }
    }

    /// Plain-English category label. `StraightFlush(Ace)` renders as
    /// "Royal Flush"; `StraightFlush(Five)` as "Steel Wheel"; other
    /// straight flushes as "Straight Flush".
    pub fn category_label(&self) -> &'static str {
        match self {
            HandRank::HighCard(_) => "High Card",
            HandRank::Pair(_, _) => "Pair",
            HandRank::TwoPair(_, _, _) => "Two Pair",
            HandRank::ThreeOfAKind(_, _) => "Three of a Kind",
            HandRank::Straight(_) => "Straight",
            HandRank::Flush(_) => "Flush",
            HandRank::FullHouse(_, _) => "Full House",
            HandRank::FourOfAKind(_, _) => "Four of a Kind",
            HandRank::StraightFlush(top) => match top {
                Rank::Ace => "Royal Flush",
                Rank::Five => "Steel Wheel",
                _ => "Straight Flush",
            },
        }
    }

    /// Canonical 6-byte chain-hash encoding — direct input for the
    /// `ShowdownReceipt::chain_hash` anchor in `shuffle_proof.rs`.
    ///
    /// Layout: byte 0 = variant tag (`category_index`, 0..=8); bytes
    /// 1..=5 = rank face values (2..=14), with sentinel `0` padding for
    /// unused slots. The sentinel is collision-free with any valid Rank
    /// (Rank discriminants are 2..=14 by `card.rs` design contract).
    ///
    /// Per-variant layout:
    ///
    /// | Variant         | Bytes 1..5                             |
    /// |-----------------|----------------------------------------|
    /// | `HighCard`      | `[r0, r1, r2, r3, r4]` (desc)          |
    /// | `Pair`          | `[pair, k0, k1, k2, 0]`                |
    /// | `TwoPair`       | `[hi_pair, lo_pair, kicker, 0, 0]`     |
    /// | `ThreeOfAKind`  | `[trips, k0, k1, 0, 0]`                |
    /// | `Straight`      | `[top, 0, 0, 0, 0]`                    |
    /// | `Flush`         | `[r0, r1, r2, r3, r4]` (desc)          |
    /// | `FullHouse`     | `[trips, pair, 0, 0, 0]`               |
    /// | `FourOfAKind`   | `[quads, kicker, 0, 0, 0]`             |
    /// | `StraightFlush` | `[top, 0, 0, 0, 0]`                    |
    ///
    /// Injectivity (proof sketch): the variant tag picks the layout
    /// schema, and within each schema the rank tuples used by `Ord`
    /// fully determine the byte pattern. No two distinct `HandRank`
    /// values can collide.
    pub const fn to_chain_hash_bytes(self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        bytes[0] = self.category_index();
        match self {
            HandRank::HighCard(r) => {
                bytes[1] = r[0] as u8;
                bytes[2] = r[1] as u8;
                bytes[3] = r[2] as u8;
                bytes[4] = r[3] as u8;
                bytes[5] = r[4] as u8;
            }
            HandRank::Pair(p, k) => {
                bytes[1] = p as u8;
                bytes[2] = k[0] as u8;
                bytes[3] = k[1] as u8;
                bytes[4] = k[2] as u8;
            }
            HandRank::TwoPair(hi, lo, k) => {
                bytes[1] = hi as u8;
                bytes[2] = lo as u8;
                bytes[3] = k as u8;
            }
            HandRank::ThreeOfAKind(t, k) => {
                bytes[1] = t as u8;
                bytes[2] = k[0] as u8;
                bytes[3] = k[1] as u8;
            }
            HandRank::Straight(top) => {
                bytes[1] = top as u8;
            }
            HandRank::Flush(r) => {
                bytes[1] = r[0] as u8;
                bytes[2] = r[1] as u8;
                bytes[3] = r[2] as u8;
                bytes[4] = r[3] as u8;
                bytes[5] = r[4] as u8;
            }
            HandRank::FullHouse(t, p) => {
                bytes[1] = t as u8;
                bytes[2] = p as u8;
            }
            HandRank::FourOfAKind(q, k) => {
                bytes[1] = q as u8;
                bytes[2] = k as u8;
            }
            HandRank::StraightFlush(top) => {
                bytes[1] = top as u8;
            }
        }
        bytes
    }
}

impl fmt::Display for HandRank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.category_label())
    }
}

/// Evaluate a 5-card hand. Always panic-free — see the module-level
/// design contract.
pub fn evaluate_5(cards: &[Card; 5]) -> HandRank {
    // 1. Sort ranks descending — derive Ord on Rank (face-value 2..=14)
    //    gives ascending; reverse via `b.cmp(a)`.
    let mut ranks: [Rank; 5] = [
        cards[0].rank(),
        cards[1].rank(),
        cards[2].rank(),
        cards[3].rank(),
        cards[4].rank(),
    ];
    ranks.sort_unstable_by(|a, b| b.cmp(a));

    // 2. Flush detection — all 5 suits identical.
    let suit0 = cards[0].suit();
    let is_flush = cards.iter().all(|c| c.suit() == suit0);

    // 3. Straight detection — sorted-desc consecutive AND distinct, OR
    //    the Ace-low wheel.
    let is_normal_straight = ranks_are_consecutive_desc(&ranks);
    let is_wheel = ranks[0] == Rank::Ace
        && ranks[1] == Rank::Five
        && ranks[2] == Rank::Four
        && ranks[3] == Rank::Three
        && ranks[4] == Rank::Two;
    let is_straight = is_normal_straight || is_wheel;
    let straight_top = if is_wheel { Rank::Five } else { ranks[0] };

    // 4. StraightFlush short-circuit — wins over any non-SF category.
    if is_flush && is_straight {
        return HandRank::StraightFlush(straight_top);
    }

    // 5. Group ranks by count. Working buffer holds up to 5 (count, rank)
    //    pairs (5-card hand has at most 5 distinct ranks).
    let mut groups: [(u8, Rank); 5] = [(0, Rank::Two); 5];
    let mut group_count: usize = 0;
    let mut i: usize = 0;
    while i < 5 {
        let r = ranks[i];
        let mut count: u8 = 1;
        while (i + count as usize) < 5 && ranks[i + count as usize] == r {
            count += 1;
        }
        groups[group_count] = (count, r);
        group_count += 1;
        i += count as usize;
    }
    // Sort populated portion by (count, rank) descending — derive Ord on
    // tuples is element-wise lexicographic.
    let active = &mut groups[..group_count];
    active.sort_unstable_by(|a, b| b.cmp(a));

    // 6. Dispatch on top-2 group counts. The 6-pattern set is exhaustive
    //    for any 5-card multiset from a 52-card deck (max-of-rank = 4).
    //    The wildcard arm is structurally unreachable but maintains the
    //    workspace `panic=deny` lint compliance.
    match (groups[0].0, groups[1].0) {
        (4, _) => HandRank::FourOfAKind(groups[0].1, groups[1].1),
        (3, 2) => HandRank::FullHouse(groups[0].1, groups[1].1),
        (3, _) => HandRank::ThreeOfAKind(groups[0].1, [groups[1].1, groups[2].1]),
        (2, 2) => HandRank::TwoPair(groups[0].1, groups[1].1, groups[2].1),
        (2, _) => HandRank::Pair(groups[0].1, [groups[1].1, groups[2].1, groups[3].1]),
        (1, _) => {
            if is_flush {
                HandRank::Flush(ranks)
            } else if is_straight {
                HandRank::Straight(straight_top)
            } else {
                HandRank::HighCard(ranks)
            }
        }
        // Structurally unreachable — fallback to the most defensive
        // (lowest-strength) reading rather than panic.
        _ => HandRank::HighCard(ranks),
    }
}

/// Evaluate the best 5-card hand from 7 cards (Texas Hold'em hole +
/// community board). Enumerates all `C(7,2) = 21` 2-card exclusion
/// pairs and tracks the maximum via [`HandRank`]'s `Ord` impl.
pub fn evaluate_7(cards: &[Card; 7]) -> HandRank {
    // Sentinel — 5 Twos as HighCard is structurally unreachable from any
    // valid deck (only 4 Twos exist), and is dominated by every real
    // HandRank::HighCard since [Two, Two, Two, Two, Two] is lexically
    // less than [Two, Three, Four, Five, _] etc. The first iteration of
    // the loop will always replace it.
    let mut best = HandRank::HighCard([Rank::Two; 5]);
    let mut sub: [Card; 5] = [cards[0]; 5];
    for i in 0..7 {
        for j in (i + 1)..7 {
            // Fill `sub` with the 5 cards whose indices are NOT in {i, j}.
            let mut idx: usize = 0;
            for (k, card) in cards.iter().enumerate() {
                if k != i && k != j {
                    sub[idx] = *card;
                    idx += 1;
                }
            }
            let candidate = evaluate_5(&sub);
            if candidate > best {
                best = candidate;
            }
        }
    }
    best
}

/// Compare two evaluated hands. Convenience wrapper around `Ord::cmp`
/// for callsites that prefer the verb form.
pub fn compare_hands(a: &HandRank, b: &HandRank) -> Ordering {
    a.cmp(b)
}

/// True iff the 5 ranks (sorted **descending**) form a strictly
/// consecutive sequence with no gaps and no duplicates. Treats the
/// Ace-low wheel as a separate case — see the caller in [`evaluate_5`].
fn ranks_are_consecutive_desc(ranks: &[Rank; 5]) -> bool {
    let mut i = 0;
    while i < 4 {
        // ranks[i] = ranks[i+1] + 1 (face-value u8)
        let hi = ranks[i] as u8;
        let lo = ranks[i + 1] as u8;
        if hi != lo + 1 {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::card::Suit;

    /// Parse a space-separated 5-card hand string ("AS KH QD JC TS").
    fn parse_5(s: &str) -> [Card; 5] {
        let parsed: [Card; 5] = parse_n::<5>(s);
        parsed
    }

    /// Parse a space-separated 7-card hand string.
    fn parse_7(s: &str) -> [Card; 7] {
        parse_n::<7>(s)
    }

    fn parse_n<const N: usize>(s: &str) -> [Card; N] {
        let cards: Vec<Card> = s
            .split_whitespace()
            .map(|w| w.parse::<Card>().unwrap())
            .collect();
        assert_eq!(cards.len(), N, "expected {N} cards, got {}", cards.len());
        let mut out = [Card::new(Rank::Two, Suit::Clubs); N];
        for (i, c) in cards.iter().enumerate() {
            out[i] = *c;
        }
        out
    }

    // --- Category detection (9 variants) ---

    #[test]
    fn evaluate_5_detects_high_card() {
        let h = parse_5("AS KH QD JC 9S");
        assert!(matches!(evaluate_5(&h), HandRank::HighCard(_)));
    }

    #[test]
    fn evaluate_5_detects_pair() {
        let h = parse_5("AS AH QD JC 9S");
        assert!(matches!(evaluate_5(&h), HandRank::Pair(Rank::Ace, _)));
    }

    #[test]
    fn evaluate_5_detects_two_pair() {
        let h = parse_5("AS AH KD KC 9S");
        assert!(matches!(
            evaluate_5(&h),
            HandRank::TwoPair(Rank::Ace, Rank::King, Rank::Nine)
        ));
    }

    #[test]
    fn evaluate_5_detects_three_of_a_kind() {
        let h = parse_5("AS AH AD KC 9S");
        assert!(matches!(
            evaluate_5(&h),
            HandRank::ThreeOfAKind(Rank::Ace, _)
        ));
    }

    #[test]
    fn evaluate_5_detects_straight() {
        let h = parse_5("9S 8H 7D 6C 5S");
        assert_eq!(evaluate_5(&h), HandRank::Straight(Rank::Nine));
    }

    #[test]
    fn evaluate_5_detects_flush() {
        let h = parse_5("AS KS 9S 6S 4S");
        assert!(matches!(evaluate_5(&h), HandRank::Flush(_)));
    }

    #[test]
    fn evaluate_5_detects_full_house() {
        let h = parse_5("AS AH AD KC KS");
        assert_eq!(evaluate_5(&h), HandRank::FullHouse(Rank::Ace, Rank::King));
    }

    #[test]
    fn evaluate_5_detects_four_of_a_kind() {
        let h = parse_5("AS AH AD AC KS");
        assert_eq!(evaluate_5(&h), HandRank::FourOfAKind(Rank::Ace, Rank::King));
    }

    #[test]
    fn evaluate_5_detects_straight_flush() {
        let h = parse_5("9S 8S 7S 6S 5S");
        assert_eq!(evaluate_5(&h), HandRank::StraightFlush(Rank::Nine));
    }

    // --- Edge cases ---

    #[test]
    fn straight_ace_low_wheel_top_is_five() {
        let h = parse_5("AS 5H 4D 3C 2S");
        assert_eq!(evaluate_5(&h), HandRank::Straight(Rank::Five));
    }

    #[test]
    fn straight_flush_steel_wheel_top_is_five() {
        let h = parse_5("AS 5S 4S 3S 2S");
        assert_eq!(evaluate_5(&h), HandRank::StraightFlush(Rank::Five));
    }

    #[test]
    fn straight_flush_royal_top_is_ace() {
        let h = parse_5("AS KS QS JS TS");
        assert_eq!(evaluate_5(&h), HandRank::StraightFlush(Rank::Ace));
        assert_eq!(evaluate_5(&h).category_label(), "Royal Flush");
    }

    #[test]
    fn broken_high_sequence_is_high_card_not_straight() {
        // K-Q-J-T-8 — gap at T-8, not a straight.
        let h = parse_5("KS QH JD TC 8S");
        assert!(matches!(evaluate_5(&h), HandRank::HighCard(_)));
    }

    #[test]
    fn four_same_suit_plus_one_off_is_not_flush() {
        let h = parse_5("AS KS QS JS 9H");
        assert!(matches!(evaluate_5(&h), HandRank::HighCard(_)));
    }

    #[test]
    fn straight_with_ace_high_is_broadway() {
        // A-K-Q-J-T (no flush) — ace-high straight, top = Ace.
        let h = parse_5("AS KH QD JC TS");
        assert_eq!(evaluate_5(&h), HandRank::Straight(Rank::Ace));
    }

    #[test]
    fn straight_six_high_works() {
        let h = parse_5("6S 5H 4D 3C 2S");
        assert_eq!(evaluate_5(&h), HandRank::Straight(Rank::Six));
    }

    // --- Tiebreakers + ordering ---

    #[test]
    fn hand_category_ordering_strict() {
        let high = evaluate_5(&parse_5("AS KH QD JC 9S"));
        let pair = evaluate_5(&parse_5("AS AH QD JC 9S"));
        let two_pair = evaluate_5(&parse_5("AS AH KD KC 9S"));
        let trips = evaluate_5(&parse_5("AS AH AD KC 9S"));
        let straight = evaluate_5(&parse_5("9S 8H 7D 6C 5S"));
        let flush = evaluate_5(&parse_5("AS KS 9S 6S 4S"));
        let full = evaluate_5(&parse_5("AS AH AD KC KS"));
        let quads = evaluate_5(&parse_5("AS AH AD AC KS"));
        let sf = evaluate_5(&parse_5("9S 8S 7S 6S 5S"));

        assert!(high < pair);
        assert!(pair < two_pair);
        assert!(two_pair < trips);
        assert!(trips < straight);
        assert!(straight < flush);
        assert!(flush < full);
        assert!(full < quads);
        assert!(quads < sf);
    }

    #[test]
    fn pair_higher_rank_wins() {
        let aces = evaluate_5(&parse_5("AS AH 5D 3C 2S"));
        let kings = evaluate_5(&parse_5("KS KH QD JC TS"));
        // Aces beat Kings even when Kings has higher kickers.
        assert!(aces > kings);
    }

    #[test]
    fn pair_same_rank_kicker_breaks_tie() {
        let pair_ace_high = evaluate_5(&parse_5("AS AH KD JC 9S"));
        let pair_ace_low = evaluate_5(&parse_5("AS AH QD JC 9S"));
        assert!(pair_ace_high > pair_ace_low);
    }

    #[test]
    fn two_pair_high_pair_dominates() {
        let aces_twos = evaluate_5(&parse_5("AS AH 2D 2C 9S"));
        let kings_queens = evaluate_5(&parse_5("KS KH QD QC 9S"));
        assert!(aces_twos > kings_queens);
    }

    #[test]
    fn full_house_trips_rank_dominates_pair_rank() {
        let aces_full_of_twos = evaluate_5(&parse_5("AS AH AD 2C 2S"));
        let kings_full_of_aces = evaluate_5(&parse_5("KS KH KD AC AS"));
        assert!(aces_full_of_twos > kings_full_of_aces);
    }

    #[test]
    fn straight_top_rank_breaks_tie() {
        let nine_high = evaluate_5(&parse_5("9S 8H 7D 6C 5S"));
        let eight_high = evaluate_5(&parse_5("8S 7H 6D 5C 4S"));
        assert!(nine_high > eight_high);
        // Wheel (5-high) is the lowest straight.
        let wheel = evaluate_5(&parse_5("AS 5H 4D 3C 2S"));
        let six_high = evaluate_5(&parse_5("6S 5H 4D 3C 2S"));
        assert!(wheel < six_high);
    }

    #[test]
    fn straight_flush_royal_beats_steel_wheel() {
        let royal = evaluate_5(&parse_5("AS KS QS JS TS"));
        let steel_wheel = evaluate_5(&parse_5("AS 5S 4S 3S 2S"));
        assert!(royal > steel_wheel);
    }

    // --- Best-5-of-7 ---

    #[test]
    fn evaluate_7_picks_best_5() {
        // 7 cards containing a hidden full house: AAA KK + 23
        let h = parse_7("AS AH AD KC KS 3D 2C");
        assert_eq!(evaluate_7(&h), HandRank::FullHouse(Rank::Ace, Rank::King));
    }

    #[test]
    fn evaluate_7_hidden_straight_flush() {
        // Hole 9S 8S, board AS KS 7S 6S 5S — straight flush 9-high in spades.
        let h = parse_7("9S 8S AS KS 7S 6S 5S");
        // Possible 5-card best: 9-8-7-6-5 of spades = StraightFlush(Nine).
        // (Note: AS KS 9S 8S 7S etc. would be a flush but not consecutive.)
        assert_eq!(evaluate_7(&h), HandRank::StraightFlush(Rank::Nine));
    }

    #[test]
    fn evaluate_7_flush_picks_5_highest_suited() {
        // 5 spades + 2 hearts → flush of 5 highest spades.
        let h = parse_7("AS KS QS 5S 3S TH 9H");
        match evaluate_7(&h) {
            HandRank::Flush(ranks) => {
                assert_eq!(
                    ranks,
                    [Rank::Ace, Rank::King, Rank::Queen, Rank::Five, Rank::Three]
                );
            }
            other => panic!("expected flush, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_7_no_pair_picks_5_high() {
        let h = parse_7("AS KH QD JC 9S 7H 4D");
        match evaluate_7(&h) {
            HandRank::HighCard(ranks) => {
                assert_eq!(
                    ranks,
                    [Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]
                );
            }
            other => panic!("expected high card, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_7_quads_dominates_full_house() {
        // AAAA + KK + queen kicker — quads beats hidden full house.
        let h = parse_7("AS AH AD AC KS KH QD");
        assert_eq!(evaluate_7(&h), HandRank::FourOfAKind(Rank::Ace, Rank::King));
    }

    // --- Helpers + auxiliaries ---

    #[test]
    fn category_index_matches_variant_order() {
        let high = evaluate_5(&parse_5("AS KH QD JC 9S"));
        let sf = evaluate_5(&parse_5("9S 8S 7S 6S 5S"));
        assert_eq!(high.category_index(), 0);
        assert_eq!(sf.category_index(), 8);
    }

    #[test]
    fn compare_hands_matches_ord() {
        let a = evaluate_5(&parse_5("AS AH QD JC 9S"));
        let b = evaluate_5(&parse_5("KS KH QD JC 9S"));
        assert_eq!(compare_hands(&a, &b), Ordering::Greater);
        assert_eq!(compare_hands(&b, &a), Ordering::Less);
        assert_eq!(compare_hands(&a, &a), Ordering::Equal);
    }

    #[test]
    fn category_label_smoke() {
        assert_eq!(
            HandRank::StraightFlush(Rank::Ace).category_label(),
            "Royal Flush"
        );
        assert_eq!(
            HandRank::StraightFlush(Rank::Five).category_label(),
            "Steel Wheel"
        );
        assert_eq!(
            HandRank::StraightFlush(Rank::Nine).category_label(),
            "Straight Flush"
        );
        assert_eq!(
            HandRank::HighCard([Rank::Ace; 5]).category_label(),
            "High Card"
        );
    }

    // --- 5 tiebreaker regression tests ---
    // Pin tiebreaker comparisons across the four kicker-bearing categories
    // (Flush / Straight / Pair / Two Pair) so any future evaluator change
    // that breaks within-category ordering trips an assertion here before
    // chain-hash bindings downstream.

    #[test]
    fn flush_tiebreaker_by_rank_desc() {
        // Both flushes; ace-high beats king-high.
        let ace_high = evaluate_5(&parse_5("AS KS 9S 6S 4S"));
        let king_high = evaluate_5(&parse_5("KS QS 9S 6S 4S"));
        assert!(ace_high > king_high);
        // Same top, deeper kicker decides — A-K-9-6-4 vs A-K-9-6-3.
        let aces_4 = evaluate_5(&parse_5("AS KS 9S 6S 4S"));
        let aces_3 = evaluate_5(&parse_5("AS KS 9S 6S 3S"));
        assert!(aces_4 > aces_3);
    }

    #[test]
    fn quads_kicker_breaks_tie() {
        // Same quads rank (Aces), different kicker.
        let aces_with_king = evaluate_5(&parse_5("AS AH AD AC KS"));
        let aces_with_two = evaluate_5(&parse_5("AS AH AD AC 2S"));
        assert!(aces_with_king > aces_with_two);
    }

    #[test]
    fn full_house_pair_rank_breaks_tie() {
        // Same trips rank (Kings), different pair rank.
        let kings_full_aces = evaluate_5(&parse_5("KS KH KD AC AS"));
        let kings_full_twos = evaluate_5(&parse_5("KS KH KD 2C 2S"));
        assert!(kings_full_aces > kings_full_twos);
    }

    #[test]
    fn three_of_a_kind_kickers_break_tie() {
        // Same trips rank (Aces), different kickers.
        let aces_kq = evaluate_5(&parse_5("AS AH AD KC QS"));
        let aces_kj = evaluate_5(&parse_5("AS AH AD KC JS"));
        assert!(aces_kq > aces_kj);
        // Kicker[0] tie, kicker[1] decides.
        let aces_kj_again = evaluate_5(&parse_5("AS AH AD KC JS"));
        let aces_kt = evaluate_5(&parse_5("AS AH AD KC TS"));
        assert!(aces_kj_again > aces_kt);
    }

    #[test]
    fn high_card_full_descending_lex() {
        // A-K-Q-J-9 beats A-K-Q-J-8 (5th kicker).
        let akqj9 = evaluate_5(&parse_5("AS KH QD JC 9S"));
        let akqj8 = evaluate_5(&parse_5("AS KH QD JC 8S"));
        assert!(akqj9 > akqj8);
        // A-K-Q-T-9 beats A-K-Q-9-8 (4th kicker decides before 5th).
        let akqt9 = evaluate_5(&parse_5("AS KH QD TC 9S"));
        let akq98 = evaluate_5(&parse_5("AS KH QD 9C 8S"));
        assert!(akqt9 > akq98);
    }

    // --- to_chain_hash_bytes layout + injectivity ---

    #[test]
    fn to_chain_hash_bytes_layout_per_variant() {
        // Each variant emits its tag byte followed by the documented layout.
        let high = HandRank::HighCard([Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]);
        assert_eq!(high.to_chain_hash_bytes(), [0, 14, 13, 12, 11, 9]);

        let pair = HandRank::Pair(Rank::Ace, [Rank::King, Rank::Queen, Rank::Jack]);
        assert_eq!(pair.to_chain_hash_bytes(), [1, 14, 13, 12, 11, 0]);

        let two_pair = HandRank::TwoPair(Rank::Ace, Rank::King, Rank::Queen);
        assert_eq!(two_pair.to_chain_hash_bytes(), [2, 14, 13, 12, 0, 0]);

        let trips = HandRank::ThreeOfAKind(Rank::Ace, [Rank::King, Rank::Queen]);
        assert_eq!(trips.to_chain_hash_bytes(), [3, 14, 13, 12, 0, 0]);

        let straight = HandRank::Straight(Rank::Ten);
        assert_eq!(straight.to_chain_hash_bytes(), [4, 10, 0, 0, 0, 0]);

        let flush = HandRank::Flush([Rank::Ace, Rank::Jack, Rank::Nine, Rank::Six, Rank::Three]);
        assert_eq!(flush.to_chain_hash_bytes(), [5, 14, 11, 9, 6, 3]);

        let full = HandRank::FullHouse(Rank::Ace, Rank::King);
        assert_eq!(full.to_chain_hash_bytes(), [6, 14, 13, 0, 0, 0]);

        let quads = HandRank::FourOfAKind(Rank::Ace, Rank::King);
        assert_eq!(quads.to_chain_hash_bytes(), [7, 14, 13, 0, 0, 0]);

        let sf = HandRank::StraightFlush(Rank::Ace);
        assert_eq!(sf.to_chain_hash_bytes(), [8, 14, 0, 0, 0, 0]);
    }

    #[test]
    fn to_chain_hash_bytes_distinct_variants_distinct_bytes() {
        // Every variant has a distinct tag byte, so any two non-equal
        // HandRanks across variants produce distinct byte arrays.
        let samples = [
            HandRank::HighCard([Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]),
            HandRank::Pair(Rank::Ace, [Rank::King, Rank::Queen, Rank::Jack]),
            HandRank::TwoPair(Rank::Ace, Rank::King, Rank::Queen),
            HandRank::ThreeOfAKind(Rank::Ace, [Rank::King, Rank::Queen]),
            HandRank::Straight(Rank::Ten),
            HandRank::Flush([Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]),
            HandRank::FullHouse(Rank::Ace, Rank::King),
            HandRank::FourOfAKind(Rank::Ace, Rank::King),
            HandRank::StraightFlush(Rank::Ace),
        ];
        for (i, a) in samples.iter().enumerate() {
            for (j, b) in samples.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a.to_chain_hash_bytes(),
                        b.to_chain_hash_bytes(),
                        "variants {i} and {j} must produce distinct chain-hash bytes"
                    );
                }
            }
        }
    }

    #[test]
    fn to_chain_hash_bytes_pair_kickers_round_trip() {
        // Different pair ranks → different bytes. Same pair, different
        // kickers → different bytes.
        let aa_kqj = HandRank::Pair(Rank::Ace, [Rank::King, Rank::Queen, Rank::Jack]);
        let aa_kqt = HandRank::Pair(Rank::Ace, [Rank::King, Rank::Queen, Rank::Ten]);
        let kk_aqj = HandRank::Pair(Rank::King, [Rank::Ace, Rank::Queen, Rank::Jack]);
        assert_ne!(aa_kqj.to_chain_hash_bytes(), aa_kqt.to_chain_hash_bytes());
        assert_ne!(aa_kqj.to_chain_hash_bytes(), kk_aqj.to_chain_hash_bytes());
        // Specifically: `Pair(K, [A, Q, J])` byte 1 = K (13), not A (14).
        assert_eq!(kk_aqj.to_chain_hash_bytes()[1], 13);
        assert_eq!(kk_aqj.to_chain_hash_bytes()[2], 14);
    }

    #[test]
    fn to_chain_hash_bytes_high_card_descending() {
        // `HighCard` byte stream matches the descending-rank tuple.
        let h = HandRank::HighCard([Rank::Ace, Rank::Queen, Rank::Ten, Rank::Eight, Rank::Six]);
        let bytes = h.to_chain_hash_bytes();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], &[14, 12, 10, 8, 6]);
    }

    #[test]
    fn to_chain_hash_bytes_sentinel_is_zero_not_valid_rank() {
        // The padding sentinel `0` is collision-free with any valid Rank
        // discriminant (Rank: 2..=14). Any byte position that holds 0
        // unambiguously denotes "no rank in this slot".
        let straight = HandRank::Straight(Rank::Ten).to_chain_hash_bytes();
        for (i, &b) in straight.iter().enumerate().skip(2) {
            assert_eq!(b, 0, "byte {i} must be sentinel 0");
        }
        // Conversely, byte 1 holds a valid Rank (2..=14, never 0).
        for variant in [
            HandRank::Straight(Rank::Five),
            HandRank::FourOfAKind(Rank::Two, Rank::Three),
            HandRank::FullHouse(Rank::King, Rank::Two),
        ] {
            let b = variant.to_chain_hash_bytes();
            assert!(b[1] >= 2 && b[1] <= 14);
        }
    }
}
