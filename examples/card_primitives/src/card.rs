//! Card primitive — packed `Card(u8)` 0..=51 in `(rank-2)*4 + suit` form.
//!
//! ## Design contract (atomic, non-negotiable)
//!
//! - **Wire-canonical byte form.** `card.to_byte()` returns the single u8
//!   chain-hash input. Hash via `blake3::Hasher::update(&[card.to_byte()])`
//!   directly. Do **not** use `core::hash::Hash` (impl-defined non-canonical)
//!   or any other byte reinterpretation — this type intentionally omits the
//!   `Hash` derive.
//! - **Cardinality 52.** Exactly 52 distinct values (0..=51). `from_byte`
//!   rejects 52..=255 with `CardError::InvalidRank`. Custom `Deserialize`
//!   re-validates the same range on the wire — peer trust 0.
//! - **Rank-major ordering.** `Two of Spades < Three of Clubs`. Suit
//!   tiebreak follows Bridge convention `Clubs < Diamonds < Hearts < Spades`;
//!   used **only** for tiebreak — downstream `hand_eval.rs` treats hand
//!   category + rank-tuple as primary.
//! - **No `Default`.** Use `Option<Card>` or an explicit sentinel byte
//!   (e.g. `255`) when an absence-marker is needed.
//! - **No `Deserialize` derive.** Custom impl validates the byte range; the
//!   derive would silently accept 52..=255 as a transparent newtype.
//! - **`no_std + alloc` ready.** Core API uses only `core::` paths; `FromStr`
//!   / `Display` rely on `core::fmt` / `core::str` and do not allocate.
//!
//! Educational scope. Band 3 axiom anchoring is deferred — the
//! `examples/` tree is exempt from the workspace axiom-cite gate.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use static_assertions::assert_not_impl_any;

/// Rank — 13 face values with `#[repr(u8)]` discriminants 2..=14.
///
/// `rank as u8` returns the face value (Ace = 14, high). Derived `Ord` gives
/// numeric ascending `Two < Three < ... < Ace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[repr(u8)]
pub enum Rank {
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
    Nine = 9,
    Ten = 10,
    Jack = 11,
    Queen = 12,
    King = 13,
    Ace = 14,
}

impl Rank {
    /// All 13 ranks in ascending face-value order.
    pub const ALL: [Rank; 13] = [
        Rank::Two,
        Rank::Three,
        Rank::Four,
        Rank::Five,
        Rank::Six,
        Rank::Seven,
        Rank::Eight,
        Rank::Nine,
        Rank::Ten,
        Rank::Jack,
        Rank::Queen,
        Rank::King,
        Rank::Ace,
    ];

    /// Decode a face-value u8 (2..=14) into a `Rank`. Returns
    /// `CardError::InvalidRank(face)` for out-of-range input.
    ///
    /// Educational API surface — exercised by the inline test module
    /// for round-trip coverage. The demo flow in `main.rs` stays
    /// inside the typed `Rank` enum.
    pub const fn try_from_face(face: u8) -> Result<Self, CardError> {
        match face {
            2 => Ok(Rank::Two),
            3 => Ok(Rank::Three),
            4 => Ok(Rank::Four),
            5 => Ok(Rank::Five),
            6 => Ok(Rank::Six),
            7 => Ok(Rank::Seven),
            8 => Ok(Rank::Eight),
            9 => Ok(Rank::Nine),
            10 => Ok(Rank::Ten),
            11 => Ok(Rank::Jack),
            12 => Ok(Rank::Queen),
            13 => Ok(Rank::King),
            14 => Ok(Rank::Ace),
            _ => Err(CardError::InvalidRank(face)),
        }
    }
}

/// Suit — 4 variants, alphabetical (Bridge canonical) order, `#[repr(u8)]` 0..=3.
///
/// `Ord` is **explicitly implemented** (not derived) to carry the ordering
/// convention as a first-class doc-anchor — see the `impl Ord for Suit`
/// block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum Suit {
    Clubs = 0,
    Diamonds = 1,
    Hearts = 2,
    Spades = 3,
}

impl Suit {
    /// All 4 suits in alphabetical (Bridge canonical) order.
    pub const ALL: [Suit; 4] = [Suit::Clubs, Suit::Diamonds, Suit::Hearts, Suit::Spades];

    /// Decode a suit index u8 (0..=3) into a `Suit`. Returns
    /// `CardError::InvalidSuit(idx)` for out-of-range input.
    ///
    /// Educational API surface — exercised by the inline test module.
    pub const fn try_from_index(idx: u8) -> Result<Self, CardError> {
        match idx {
            0 => Ok(Suit::Clubs),
            1 => Ok(Suit::Diamonds),
            2 => Ok(Suit::Hearts),
            3 => Ok(Suit::Spades),
            _ => Err(CardError::InvalidSuit(idx)),
        }
    }
}

// SUIT-ORDER-CONVENTION: Bridge (C < D < H < S) — used ONLY for tiebreak;
// hand_eval.rs treats hand category + rank-tuple as primary. The explicit
// `impl Ord` (rather than `#[derive(Ord)]`) exists solely to anchor this
// convention as a first-class comment site.
impl Ord for Suit {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl PartialOrd for Suit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Card — packed u8 newtype 0..=51 in `(rank-2)*4 + suit` form.
///
/// See module-level documentation for the design contract. The single
/// inner byte **is** the wire-canonical chain-hash input — pass it
/// directly to `blake3::Hasher::update`, do not re-derive via
/// `core::hash::Hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[repr(transparent)]
pub struct Card(u8);

// Compile-time enforcement of the design-contract pin (module docs):
//   - `!Default` — no zero/sentinel value; consumers use `Option<Card>`
//     or an explicit out-of-range byte when an absence-marker is needed.
//   - `!core::hash::Hash` — impl-defined non-canonical; chain-hash input
//     MUST go through `card.to_byte()` and `blake3::Hasher::update`.
//
// Pattern alignment: arkhe-forge-platform/src/wal_export/buffered_sink.rs:132-136.
assert_not_impl_any!(Card: Default, core::hash::Hash);

impl Card {
    /// Construct from typed `Rank` + `Suit`. Infallible by construction —
    /// both arguments are bounded enums.
    pub const fn new(rank: Rank, suit: Suit) -> Self {
        // (rank as u8 - 2) ∈ 0..=12; * 4 → 0..=48; + (suit as u8) ∈ 0..=3
        // → final byte ∈ 0..=51 ✓
        Card((rank as u8 - 2) * 4 + (suit as u8))
    }

    /// Decode wire byte. Rejects `b > 51` with
    /// `CardError::InvalidRank(b/4 + 2)` — the implicit face value that
    /// would have been produced exceeds 14.
    pub const fn from_byte(b: u8) -> Result<Self, CardError> {
        if b > 51 {
            // u8 arithmetic safe: b ≤ 255 ⇒ b/4 ≤ 63 ⇒ b/4 + 2 ≤ 65.
            Err(CardError::InvalidRank((b / 4).wrapping_add(2)))
        } else {
            Ok(Card(b))
        }
    }

    /// Wire-canonical byte form. Use directly with
    /// `blake3::Hasher::update(&[card.to_byte()])` for chain-hash input.
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// Extract rank (face value, 2..=14).
    pub const fn rank(self) -> Rank {
        // Invariant: self.0 ∈ 0..=51 ⇒ self.0 / 4 ∈ 0..=12.
        // The wildcard arm uses `Rank::Ace` as a saturating fallback for
        // the unreachable 13..=63 region, preserving panic-free guarantee
        // (workspace deny: panic, unreachable!).
        match self.0 / 4 {
            0 => Rank::Two,
            1 => Rank::Three,
            2 => Rank::Four,
            3 => Rank::Five,
            4 => Rank::Six,
            5 => Rank::Seven,
            6 => Rank::Eight,
            7 => Rank::Nine,
            8 => Rank::Ten,
            9 => Rank::Jack,
            10 => Rank::Queen,
            11 => Rank::King,
            _ => Rank::Ace,
        }
    }

    /// Extract suit.
    pub const fn suit(self) -> Suit {
        // self.0 % 4 ∈ 0..=3 unconditionally; the four arms cover all cases.
        match self.0 % 4 {
            0 => Suit::Clubs,
            1 => Suit::Diamonds,
            2 => Suit::Hearts,
            _ => Suit::Spades,
        }
    }
}

/// Card decoding error — captures the offending u8 for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardError {
    /// Rank face-value out of `2..=14`.
    InvalidRank(u8),
    /// Suit index out of `0..=3`.
    InvalidSuit(u8),
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CardError::InvalidRank(v) => {
                write!(f, "invalid rank face-value {v} (expected 2..=14)")
            }
            CardError::InvalidSuit(v) => {
                write!(f, "invalid suit index {v} (expected 0..=3)")
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Card {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let b = u8::deserialize(deserializer)?;
        Self::from_byte(b).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Card {
    type Err = CardError;
    fn from_str(s: &str) -> Result<Self, CardError> {
        let bytes = s.as_bytes();
        if bytes.len() != 2 {
            // Length fault projected onto the rank dimension (sentinel 0 —
            // not a valid face value, so the caller sees a non-collision
            // diagnostic).
            return Err(CardError::InvalidRank(0));
        }
        let rank = match bytes[0] {
            b'2' => Rank::Two,
            b'3' => Rank::Three,
            b'4' => Rank::Four,
            b'5' => Rank::Five,
            b'6' => Rank::Six,
            b'7' => Rank::Seven,
            b'8' => Rank::Eight,
            b'9' => Rank::Nine,
            b'T' => Rank::Ten,
            b'J' => Rank::Jack,
            b'Q' => Rank::Queen,
            b'K' => Rank::King,
            b'A' => Rank::Ace,
            other => return Err(CardError::InvalidRank(other)),
        };
        let suit = match bytes[1] {
            b'C' => Suit::Clubs,
            b'D' => Suit::Diamonds,
            b'H' => Suit::Hearts,
            b'S' => Suit::Spades,
            other => return Err(CardError::InvalidSuit(other)),
        };
        Ok(Card::new(rank, suit))
    }
}

impl fmt::Display for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rank_char = match self.rank() {
            Rank::Two => '2',
            Rank::Three => '3',
            Rank::Four => '4',
            Rank::Five => '5',
            Rank::Six => '6',
            Rank::Seven => '7',
            Rank::Eight => '8',
            Rank::Nine => '9',
            Rank::Ten => 'T',
            Rank::Jack => 'J',
            Rank::Queen => 'Q',
            Rank::King => 'K',
            Rank::Ace => 'A',
        };
        let suit_char = match self.suit() {
            Suit::Clubs => 'C',
            Suit::Diamonds => 'D',
            Suit::Hearts => 'H',
            Suit::Spades => 'S',
        };
        write!(f, "{rank_char}{suit_char}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn round_trip_byte_all_52() {
        for b in 0..=51u8 {
            let card = Card::from_byte(b).unwrap();
            assert_eq!(card.to_byte(), b);
            // (rank, suit) reconstruction round-trip
            let reconstructed = Card::new(card.rank(), card.suit());
            assert_eq!(card, reconstructed);
        }
    }

    #[test]
    fn from_byte_rejects_out_of_range() {
        for b in 52..=255u8 {
            assert!(Card::from_byte(b).is_err(), "byte {b} should be rejected");
        }
    }

    #[test]
    fn card_all_has_52_unique_entries() {
        let mut all = BTreeSet::new();
        for &rank in &Rank::ALL {
            for &suit in &Suit::ALL {
                let card = Card::new(rank, suit);
                assert!(all.insert(card), "duplicate card {card}");
            }
        }
        assert_eq!(all.len(), 52);
        // Min/max anchoring — rank-major + bridge suit tiebreak.
        assert_eq!(
            *all.iter().next().unwrap(),
            Card::new(Rank::Two, Suit::Clubs)
        );
        assert_eq!(
            *all.iter().next_back().unwrap(),
            Card::new(Rank::Ace, Suit::Spades)
        );
    }

    #[test]
    fn ord_rank_major_then_suit_bridge() {
        // Rank-major: Two of Spades < Three of Clubs.
        assert!(Card::new(Rank::Two, Suit::Spades) < Card::new(Rank::Three, Suit::Clubs));
        // Same-rank suit tiebreak: Clubs < Diamonds < Hearts < Spades.
        let two_c = Card::new(Rank::Two, Suit::Clubs);
        let two_d = Card::new(Rank::Two, Suit::Diamonds);
        let two_h = Card::new(Rank::Two, Suit::Hearts);
        let two_s = Card::new(Rank::Two, Suit::Spades);
        assert!(two_c < two_d && two_d < two_h && two_h < two_s);
    }

    #[test]
    fn ord_transitivity_full_table() {
        // Triple-loop transitivity check across all 52 cards.
        // Pruned via a < b && b < c, keeping the work bounded.
        let cards: Vec<Card> = (0..=51u8).map(|b| Card::from_byte(b).unwrap()).collect();
        for a in &cards {
            for b in &cards {
                if a >= b {
                    continue;
                }
                for c in &cards {
                    if b >= c {
                        continue;
                    }
                    assert!(a < c, "transitivity broken: {a} < {b} < {c}");
                }
            }
        }
    }

    #[test]
    fn suit_ord_bridge_total() {
        let suits = Suit::ALL;
        for (i, a) in suits.iter().enumerate() {
            for (j, b) in suits.iter().enumerate() {
                assert_eq!(a.cmp(b), i.cmp(&j));
            }
        }
    }

    #[test]
    fn from_str_round_trip_all_52() {
        for &rank in &Rank::ALL {
            for &suit in &Suit::ALL {
                let card = Card::new(rank, suit);
                let s = format!("{card}");
                let parsed = s.parse::<Card>().unwrap();
                assert_eq!(parsed, card);
            }
        }
        // Spec sample: "AS" = Ace of Spades = byte 51.
        let ace_spades = "AS".parse::<Card>().unwrap();
        assert_eq!(ace_spades, Card::new(Rank::Ace, Suit::Spades));
        assert_eq!(ace_spades.to_byte(), 51);
    }

    #[test]
    fn from_str_rejects_invalid() {
        // Length faults
        assert!("".parse::<Card>().is_err());
        assert!("A".parse::<Card>().is_err());
        assert!("ACE".parse::<Card>().is_err());
        // Rank faults
        assert!("XS".parse::<Card>().is_err());
        assert!("1S".parse::<Card>().is_err());
        // Suit faults
        assert!("AX".parse::<Card>().is_err());
        assert!("A1".parse::<Card>().is_err());
    }

    #[test]
    fn serde_postcard_round_trip_all_52() {
        for b in 0..=51u8 {
            let card = Card::from_byte(b).unwrap();
            let bytes = postcard::to_allocvec(&card).unwrap();
            assert_eq!(
                bytes.len(),
                1,
                "expected 1-byte postcard encoding for Card({b})"
            );
            assert_eq!(bytes[0], b);
            let restored: Card = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(card, restored);
        }
    }

    #[test]
    fn serde_rejects_out_of_range_byte() {
        for b in 52..=255u8 {
            let bad = [b];
            let result: Result<Card, _> = postcard::from_bytes(&bad);
            assert!(result.is_err(), "postcard should reject byte {b}");
        }
    }

    #[test]
    fn rank_try_from_face_round_trip() {
        for face in 2u8..=14 {
            let rank = Rank::try_from_face(face).unwrap();
            assert_eq!(rank as u8, face);
        }
        for bad in [0u8, 1, 15, 100, 255] {
            assert!(matches!(
                Rank::try_from_face(bad),
                Err(CardError::InvalidRank(v)) if v == bad
            ));
        }
    }

    #[test]
    fn suit_try_from_index_round_trip() {
        for idx in 0u8..=3 {
            let suit = Suit::try_from_index(idx).unwrap();
            assert_eq!(suit as u8, idx);
        }
        for bad in [4u8, 100, 255] {
            assert!(matches!(
                Suit::try_from_index(bad),
                Err(CardError::InvalidSuit(v)) if v == bad
            ));
        }
    }

    #[test]
    fn card_byte_value_matches_packing_formula() {
        // Direct verification of the (rank-2)*4 + suit packing formula.
        for &rank in &Rank::ALL {
            for &suit in &Suit::ALL {
                let card = Card::new(rank, suit);
                let expected = (rank as u8 - 2) * 4 + (suit as u8);
                assert_eq!(card.to_byte(), expected);
            }
        }
    }

    // Compile-time `!Default` + `!core::hash::Hash` enforcement is at
    // module-level via `assert_not_impl_any!` (see card.rs near the
    // `Card` struct definition). No runtime test needed — any drift
    // produces a build error.
}
