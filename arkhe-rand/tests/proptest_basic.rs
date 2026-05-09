//! Property-based tests for the arkhe-rand primitives.
//!
//! - **P1 split determinism**: same seed ⇒ same child seed.
//! - **P2 Lemire unbiased**: chi² uniform over `gen_range(0..7)`,
//!   sample = 1e6, α = 1e-4 (Bonferroni-aware family-wise level
//!   matching `examples/card_primitives/tests/statistical_rng_suite.rs`).
//! - **P3 fill_bytes monotonic**: one fill of N bytes equals two
//!   contiguous fills summing to N from the same seed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_rand::{gen_range, RngSource};
use proptest::prelude::*;

proptest! {
    /// P1: `RngSource::split()` is fully deterministic — two parents
    /// constructed from the same seed produce children that emit
    /// byte-identical streams.
    #[test]
    fn split_determinism(seed in any::<[u8; 32]>()) {
        let mut parent_a = RngSource::from_seed(&seed);
        let mut parent_b = RngSource::from_seed(&seed);

        let mut child_a = parent_a.split();
        let mut child_b = parent_b.split();

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        child_a.fill_bytes(&mut buf_a);
        child_b.fill_bytes(&mut buf_b);

        prop_assert_eq!(buf_a, buf_b);
    }

    /// P3: `fill_bytes(N)` advances the XOF stream by exactly N bytes.
    /// Splitting the read into two contiguous fills must produce the
    /// same byte sequence as a single fill of equal total length.
    #[test]
    fn fill_bytes_monotonic_advance(
        seed in any::<[u8; 32]>(),
        split_at in 0usize..=64usize,
    ) {
        let mut a = RngSource::from_seed(&seed);
        let mut b = RngSource::from_seed(&seed);

        let mut whole = [0u8; 64];
        a.fill_bytes(&mut whole);

        let mut combined = [0u8; 64];
        b.fill_bytes(&mut combined[..split_at]);
        b.fill_bytes(&mut combined[split_at..]);

        prop_assert_eq!(whole, combined);
    }
}

/// P2: Lemire unbiased range sampling. `gen_range(0..7)` over 1e6
/// samples must pass chi² uniformity at α = 1e-4 (df = 6, critical
/// value ≈ 27.86). The seed is fixed so the test is deterministic;
/// statistical-distribution drift would surface as a regression.
#[test]
fn lemire_unbiased_chi_square_n7() {
    const N: u32 = 7;
    const SAMPLES: u32 = 1_000_000;
    // chi² critical, df = 6, α = 1e-4 (NIST-style table value 27.856).
    const CHI2_CRIT_DF6_ALPHA_1E_4: f64 = 27.86;

    let seed = [0x42u8; 32];
    let mut rng = RngSource::from_seed(&seed);
    let mut counts = [0u64; N as usize];
    for _ in 0..SAMPLES {
        let r = gen_range(&mut rng, 0..N);
        counts[r as usize] += 1;
    }

    let expected = f64::from(SAMPLES) / f64::from(N);
    let chi_sq: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();

    assert!(
        chi_sq < CHI2_CRIT_DF6_ALPHA_1E_4,
        "chi² = {chi_sq} >= critical {CHI2_CRIT_DF6_ALPHA_1E_4} (α=1e-4, df=6)"
    );
}
