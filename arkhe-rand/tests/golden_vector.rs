//! Cross-platform determinism regression — golden-vector byte-compare.
//!
//! P4 from the property surface. The fixture
//! `tests/golden/proof_rng_canonical_seq_v1.bin` (4 KiB) holds the first
//! 4096 bytes produced by `RngSource::from_seed(&[0u8; 32])`. Every CI
//! run byte-compares the host stream against the fixture; all
//! byte-to-integer conversions in the crate are explicit little-endian,
//! so a native-endian leak in the primitive diverges from the fixture.
//! CI additionally greps `arkhe-rand/src/` for `from_ne_bytes` /
//! `to_ne_bytes` (zero hits required). Pointer-width independence holds
//! by construction — `usize` sampling routes through the u64 Lemire
//! path on every target — and is pinned here by the shuffle golden
//! permutation plus the `usize`/`u64` identity test in `src/range.rs`.
//!
//! To regenerate the fixture (e.g., after KDF context tag rotation):
//!
//! ```bash
//! ARKHE_RAND_REGEN_GOLDEN=1 cargo test -p arkhe-rand --test golden_vector
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_rand::{shuffle, RngSource};

const CANONICAL_SEED: [u8; 32] = [0u8; 32];
const GOLDEN_LEN: usize = 4096;
const GOLDEN_PATH: &str = "tests/golden/proof_rng_canonical_seq_v1.bin";

#[test]
fn golden_vector_canonical_seq_v1() {
    let mut rng = RngSource::from_seed(&CANONICAL_SEED);
    let mut produced = vec![0u8; GOLDEN_LEN];
    rng.fill_bytes(&mut produced);

    if std::env::var_os("ARKHE_RAND_REGEN_GOLDEN").is_some() {
        std::fs::write(GOLDEN_PATH, &produced).expect("write golden vector");
        return;
    }

    let expected = std::fs::read(GOLDEN_PATH).expect("read golden vector");
    assert_eq!(
        produced.len(),
        expected.len(),
        "produced length {} != golden length {}",
        produced.len(),
        expected.len()
    );
    assert_eq!(
        produced, expected,
        "byte mismatch — endianness or KDF context drift"
    );
}

/// Shuffle determinism golden permutation. A 52-element deck shuffled
/// under the canonical seed must produce exactly this order on every
/// target — `shuffle` draws `usize` indices, and `usize` sampling is
/// pointer-width independent by construction, so the pinned vector
/// holds for 32-bit and 64-bit alike.
#[test]
fn golden_shuffle_52_element_permutation() {
    const EXPECTED: [u8; 52] = [
        5, 41, 20, 7, 25, 9, 11, 37, 6, 45, 14, 36, 34, 18, 19, 23, 1, 8, 16, 28, 13, 44, 21, 39,
        22, 12, 2, 15, 50, 33, 35, 31, 26, 24, 46, 3, 48, 43, 4, 27, 38, 17, 30, 47, 49, 42, 0, 10,
        40, 29, 51, 32,
    ];

    let mut rng = RngSource::from_seed(&CANONICAL_SEED);
    let mut deck: Vec<u8> = (0..52).collect();
    shuffle(&mut rng, &mut deck);
    assert_eq!(
        deck.as_slice(),
        EXPECTED.as_slice(),
        "permutation mismatch — usize sampling or stream consumption drift"
    );
}
