//! Property-based tests for the arkhe-rand primitives.
//!
//! - **P1 split determinism**: same seed ⇒ same child seed.
//! - **P2 Lemire unbiased**: chi² uniform over `gen_range(0..7)`,
//!   sample = 1e6, α = 1e-4 (Bonferroni-aware family-wise level
//!   matching `examples/card_primitives/tests/statistical_rng_suite.rs`).
//! - **P3 fill_bytes monotonic**: one fill of N bytes equals two
//!   contiguous fills summing to N from the same seed.
//! - **fill_bytes interleaving identity**: any chunking of reads emits
//!   the same byte sequence as one contiguous read (exercises the
//!   internal block-cache refill and bulk paths).
//! - **split stream accounting**: `split()` consumes exactly the next
//!   32 emitted stream bytes, at any cache offset.

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

    /// Interleaving identity: any sequence of request sizes — empty,
    /// sub-block, block-spanning, multi-block — emits the same byte
    /// sequence as one contiguous fill of the total length.
    #[test]
    fn fill_bytes_interleaving_identity(
        seed in any::<[u8; 32]>(),
        chunks in proptest::collection::vec(0usize..=200, 1..=12),
    ) {
        let total: usize = chunks.iter().sum();
        let mut a = RngSource::from_seed(&seed);
        let mut b = RngSource::from_seed(&seed);

        let mut whole = vec![0u8; total];
        a.fill_bytes(&mut whole);

        let mut pieced = vec![0u8; total];
        let mut offset = 0;
        for &c in &chunks {
            b.fill_bytes(&mut pieced[offset..offset + c]);
            offset += c;
        }

        prop_assert_eq!(whole, pieced);
    }

    /// `split()` consumes exactly the next 32 emitted stream bytes as
    /// the child seed, regardless of how far a preceding fill advanced
    /// the stream: the parent stays aligned with a fill-only twin, and
    /// the child equals `from_seed` over those 32 bytes.
    #[test]
    fn split_consumes_exactly_32_stream_bytes(
        seed in any::<[u8; 32]>(),
        pre in 0usize..=80,
    ) {
        let mut a = RngSource::from_seed(&seed);
        let mut b = RngSource::from_seed(&seed);

        let mut scratch = vec![0u8; pre];
        a.fill_bytes(&mut scratch);
        b.fill_bytes(&mut scratch);

        let mut child = a.split();
        let mut child_seed = [0u8; 32];
        b.fill_bytes(&mut child_seed);

        let mut tail_a = [0u8; 48];
        let mut tail_b = [0u8; 48];
        a.fill_bytes(&mut tail_a);
        b.fill_bytes(&mut tail_b);
        prop_assert_eq!(tail_a, tail_b);

        let mut expected_child = RngSource::from_seed(&child_seed);
        let mut child_out = [0u8; 48];
        let mut expected_out = [0u8; 48];
        child.fill_bytes(&mut child_out);
        expected_child.fill_bytes(&mut expected_out);
        prop_assert_eq!(child_out, expected_out);
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
