//! Cross-platform endianness regression — golden-vector byte-compare.
//!
//! P4 from the property surface. The fixture
//! `tests/golden/proof_rng_canonical_seq_v1.bin` (4 KiB) holds the first
//! 4096 bytes produced by `RngSource::from_seed(&[0u8; 32])` on an
//! x86_64 host. CI cross-compiles this test for `aarch64-unknown-linux-gnu`
//! and `wasm32-unknown-unknown` and byte-compares against the fixture —
//! any divergence reveals a host-endianness leak in the primitive
//! (e.g., an accidental native-endian byte conversion).
//!
//! To regenerate the fixture (e.g., after KDF context tag rotation):
//!
//! ```bash
//! ARKHE_RAND_REGEN_GOLDEN=1 cargo test -p arkhe-rand --test golden_vector
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_rand::RngSource;

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
