//! Threshold HSM pre-sign library — byte-level GF(256) Shamir secret sharing.
//!
//! Distributes the auto_promote
//! authorization token via `t-of-n` Shamir secret sharing; promotion consumes
//! `t` shares to reconstruct the token and appends an entry to the consumed
//! journal.
//!
//! The implementation keeps the cryptographic surface inside this crate
//! instead of pulling an external dep. For each secret byte we draw a random
//! polynomial of degree `t-1` over `GF(2^8)` with the irreducible polynomial
//! `x^8 + x^4 + x^3 + x + 1` (AES / NIST) and evaluate it at points `1..=n`.
//! Reconstruction interpolates the polynomial at `x = 0` via Lagrange basis.
//! Share index `0` is reserved for the secret and never appears on-wire.
//!
//! # Security notes
//!
//! * Per-byte independent polynomials — catastrophic failure of a single
//!   share reveals at most `t-1` bytes of leakage per coefficient.
//! * RNG: `getrandom::getrandom` via the OS CSPRNG. Absent entropy (e.g. a
//!   stripped-down embedded target with no `getrandom` backend) surfaces
//!   [`ThresholdError::EntropyFailure`] — callers must resolve upstream.
//! * The reconstruction path verifies every share index lies in `1..=255`,
//!   rejects duplicates, and bails if the caller submits fewer than `t` of
//!   them. Tampered shares are detected only insofar as the reconstructed
//!   secret disagrees with the expected value; integrity is layered on at
//!   the caller via `ConsumedTokenJournal` (token_hash match).

use getrandom::getrandom as os_getrandom;

/// Shamir threshold configuration — default `t=2, n=3`.
#[derive(Debug, Clone, Copy)]
pub struct ThresholdConfig {
    /// Minimum share count required for reconstruction.
    pub t: u8,
    /// Total share count.
    pub n: u8,
}

impl ThresholdConfig {
    /// Default config — 2-of-3.
    pub const DEFAULT: Self = Self { t: 2, n: 3 };

    /// `2 <= t <= n <= 255`. `n == 255` is allowed because index 0 is reserved (secret).
    pub fn is_valid(&self) -> bool {
        self.t >= 2 && self.t <= self.n
    }
}

/// Single Shamir share — index (`1..=n`) + per-byte y-coordinates of the
/// secret polynomial evaluated at `index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Share index — `1..=n`. `0` is reserved for the secret itself.
    pub index: u8,
    /// Share bytes — polynomial y-coordinates, one per secret byte.
    pub bytes: Vec<u8>,
}

/// Threshold computation error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThresholdError {
    /// `is_valid()` failed — `t < 2` or `t > n`.
    #[error("invalid threshold config: t={t} n={n}")]
    InvalidConfig {
        /// threshold.
        t: u8,
        /// total.
        n: u8,
    },
    /// `combine_shares` received fewer than `t` shares.
    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares {
        /// Required count.
        need: usize,
        /// Actual count.
        got: usize,
    },
    /// A share carries index `0` (reserved) or index `> 255` (impossible since
    /// the field is `u8`, but checked defensively).
    #[error("invalid share index: {index}")]
    InvalidShareIndex {
        /// Offending share index.
        index: u8,
    },
    /// Two or more shares presented the same index — ambiguous interpolation.
    #[error("duplicate share indices in combine input")]
    DuplicateShares,
    /// Shares carry mismatched byte-lengths — the caller has mixed sets from
    /// different splits.
    #[error("share byte length mismatch: expected {expected}, got {got}")]
    ShareLengthMismatch {
        /// Length of the first share.
        expected: usize,
        /// Length of the offending share.
        got: usize,
    },
    /// `getrandom` failed to deliver entropy on the target platform.
    #[error("entropy source failure: {0}")]
    EntropyFailure(String),
}

// ───────────────────── GF(2^8) arithmetic ─────────────────────

/// AES irreducible polynomial: `x^8 + x^4 + x^3 + x + 1`.
const GF_REDUCER: u16 = 0x11B;

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Russian-peasant multiplication in `GF(2^8)` reduced modulo `GF_REDUCER`.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r: u16 = 0;
    while a != 0 && b != 0 {
        if b & 1 == 1 {
            r ^= a as u16;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= (GF_REDUCER & 0xFF) as u8;
        }
        b >>= 1;
    }
    r as u8
}

/// Multiplicative inverse in `GF(2^8)` — extended Euclidean not needed; we use
/// `a^254 = a^{-1}` via exponentiation-by-squaring (Fermat's little theorem
/// in the field of 256 elements). Panics-free: for `a = 0` returns `0`, which
/// the caller must guard against (denominators never zero by construction).
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut result: u8 = 1;
    let mut base = a;
    let mut exp: u8 = 254;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Evaluate a polynomial (coefficients in ascending order: `c0, c1, ..., c_{k-1}`)
/// at point `x` over `GF(2^8)`. Horner form.
#[cfg(test)]
fn gf_poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc: u8 = 0;
    for &c in coeffs.iter().rev() {
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc
}

/// Evaluate `p(x) = const_term + c1*x + c2*x^2 + ...` at `x` over `GF(2^8)`,
/// where `coeffs = [c1, c2, ...]` are the higher-degree coefficients in
/// ascending order. Splitting the constant term out lets `split_secret`
/// evaluate one polynomial per `(secret-byte x share)` pair without
/// allocating a fresh coefficient `Vec` each time. Horner form.
#[inline]
fn gf_poly_eval_with_const(const_term: u8, coeffs: &[u8], x: u8) -> u8 {
    let mut acc: u8 = 0;
    for &c in coeffs.iter().rev() {
        acc = gf_add(gf_mul(acc, x), c);
    }
    // Final Horner step folds in the constant term.
    gf_add(gf_mul(acc, x), const_term)
}

// ───────────────────── Split / combine ─────────────────────

/// Split `secret` into `config.n` shares such that any `config.t` of them
/// suffice to reconstruct. Each share is the polynomial evaluated at a
/// distinct point `1..=n`; the constant term is the secret byte.
///
/// Returns [`ThresholdError::InvalidConfig`] when `config.is_valid()` fails,
/// [`ThresholdError::EntropyFailure`] when `getrandom` cannot deliver the
/// per-byte polynomial coefficients.
pub fn split_secret(secret: &[u8], config: ThresholdConfig) -> Result<Vec<Share>, ThresholdError> {
    if !config.is_valid() {
        return Err(ThresholdError::InvalidConfig {
            t: config.t,
            n: config.n,
        });
    }

    let t = config.t as usize;
    let n = config.n as usize;

    // For each secret byte we need `t-1` random coefficients (c1..c_{t-1});
    // c0 is the secret byte itself. One contiguous draw minimises getrandom
    // syscalls.
    let mut random_coeffs = vec![0u8; secret.len() * (t - 1)];
    if !random_coeffs.is_empty() {
        os_getrandom(&mut random_coeffs)
            .map_err(|e| ThresholdError::EntropyFailure(e.to_string()))?;
    }

    let mut shares: Vec<Share> = Vec::with_capacity(n);
    for share_idx in 1..=(n as u8) {
        let mut ys = Vec::with_capacity(secret.len());
        for (byte_idx, &secret_byte) in secret.iter().enumerate() {
            // Polynomial `p(x) = secret_byte + c1*x + c2*x^2 + ...`. The
            // higher-degree coefficients live in `random_coeffs`; eval them
            // in place with the secret byte as the constant term so no
            // per-pair coefficient Vec is allocated.
            let start = byte_idx * (t - 1);
            let end = start + (t - 1);
            let coeffs = &random_coeffs[start..end];
            ys.push(gf_poly_eval_with_const(secret_byte, coeffs, share_idx));
        }
        shares.push(Share {
            index: share_idx,
            bytes: ys,
        });
    }
    // Best-effort wipe: the caller-visible shares carry the evaluations; the
    // coefficient buffer holds sensitive polynomial state.
    random_coeffs.fill(0);
    Ok(shares)
}

/// Reconstruct the original secret from at least `config.t` distinct shares.
/// Interpolates the polynomial at `x = 0` per byte via Lagrange basis.
///
/// Validates that every share index is in `1..=255`, that indices are
/// unique, that all share byte-lengths match, and that the caller supplied
/// at least `config.t` shares.
pub fn combine_shares(
    shares: &[Share],
    config: ThresholdConfig,
) -> Result<Vec<u8>, ThresholdError> {
    if !config.is_valid() {
        return Err(ThresholdError::InvalidConfig {
            t: config.t,
            n: config.n,
        });
    }
    if shares.len() < config.t as usize {
        return Err(ThresholdError::InsufficientShares {
            need: config.t as usize,
            got: shares.len(),
        });
    }

    // Index 0 is reserved for the secret; `u8` rules out > 255.
    for s in shares {
        if s.index == 0 {
            return Err(ThresholdError::InvalidShareIndex { index: 0 });
        }
    }

    // Duplicate index check — O(n^2) is fine for the realistic `n <= 255`.
    for (i, a) in shares.iter().enumerate() {
        for b in &shares[i + 1..] {
            if a.index == b.index {
                return Err(ThresholdError::DuplicateShares);
            }
        }
    }

    let secret_len = shares[0].bytes.len();
    for s in shares {
        if s.bytes.len() != secret_len {
            return Err(ThresholdError::ShareLengthMismatch {
                expected: secret_len,
                got: s.bytes.len(),
            });
        }
    }

    // Use the first `t` shares — any subset reconstructs the same polynomial
    // since it is uniquely determined by any `t` evaluations.
    let selected = &shares[..config.t as usize];

    let mut secret = vec![0u8; secret_len];
    for (byte_idx, secret_byte) in secret.iter_mut().enumerate() {
        // Lagrange interpolation at x = 0:
        //   L(0) = Σ y_i * Π_{j != i}  (0 - x_j) / (x_i - x_j)
        //        = Σ y_i * Π_{j != i}  (x_j) / (x_i + x_j)         (GF(2) subtraction == addition).
        let mut acc: u8 = 0;
        for (i, s_i) in selected.iter().enumerate() {
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for (j, s_j) in selected.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = gf_mul(num, s_j.index);
                den = gf_mul(den, gf_add(s_i.index, s_j.index));
            }
            let basis = gf_mul(num, gf_inv(den));
            acc = gf_add(acc, gf_mul(s_i.bytes[byte_idx], basis));
        }
        *secret_byte = acc;
    }

    Ok(secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_2_of_3() {
        let c = ThresholdConfig::DEFAULT;
        assert_eq!(c.t, 2);
        assert_eq!(c.n, 3);
        assert!(c.is_valid());
    }

    #[test]
    fn reject_t_greater_than_n() {
        let c = ThresholdConfig { t: 5, n: 3 };
        assert!(!c.is_valid());
    }

    #[test]
    fn reject_t_below_two() {
        let c = ThresholdConfig { t: 1, n: 3 };
        assert!(!c.is_valid());
    }

    #[test]
    fn split_invalid_config_errors() {
        let err = split_secret(b"secret", ThresholdConfig { t: 1, n: 3 }).unwrap_err();
        assert!(matches!(err, ThresholdError::InvalidConfig { .. }));
    }

    /// An invalid config rejects up front — `t = 0` with an empty share
    /// set previously fell past the insufficient-shares guard
    /// (`0 < 0 == false`) into an out-of-bounds index panic.
    #[test]
    fn combine_invalid_config_errors() {
        let err = combine_shares(&[], ThresholdConfig { t: 0, n: 0 }).unwrap_err();
        assert!(matches!(err, ThresholdError::InvalidConfig { t: 0, n: 0 }));
    }

    #[test]
    fn combine_insufficient_shares_errors() {
        let config = ThresholdConfig::DEFAULT;
        let shares = vec![Share {
            index: 1,
            bytes: vec![0u8; 32],
        }];
        let err = combine_shares(&shares, config).unwrap_err();
        assert_eq!(err, ThresholdError::InsufficientShares { need: 2, got: 1 });
    }

    #[test]
    fn roundtrip_2_of_3() {
        let secret = b"auto-promote-token-sample-bytes!";
        assert_eq!(secret.len(), 32);
        let shares = split_secret(secret, ThresholdConfig::DEFAULT).unwrap();
        assert_eq!(shares.len(), 3);
        // Any 2 of 3 reconstruct.
        for pair in [(0, 1), (0, 2), (1, 2)] {
            let subset = vec![shares[pair.0].clone(), shares[pair.1].clone()];
            let recovered = combine_shares(&subset, ThresholdConfig::DEFAULT).unwrap();
            assert_eq!(&recovered[..], &secret[..]);
        }
    }

    #[test]
    fn roundtrip_3_of_5() {
        let config = ThresholdConfig { t: 3, n: 5 };
        let secret: Vec<u8> = (0..64).collect();
        let shares = split_secret(&secret, config).unwrap();
        assert_eq!(shares.len(), 5);
        // Pick a non-trivial subset.
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = combine_shares(&subset, config).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn share_indices_are_one_through_n() {
        let shares = split_secret(b"hi", ThresholdConfig { t: 2, n: 4 }).unwrap();
        let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
        assert_eq!(indices, vec![1, 2, 3, 4]);
    }

    #[test]
    fn fewer_than_t_reveals_no_info_sampled() {
        // A single share cannot reconstruct the secret. We do not assert
        // zero-knowledge cryptographically here (that would need many
        // samples); we only check that the combine path rejects the input.
        let shares = split_secret(b"topsecret", ThresholdConfig::DEFAULT).unwrap();
        let one_share = vec![shares[0].clone()];
        let err = combine_shares(&one_share, ThresholdConfig::DEFAULT).unwrap_err();
        assert!(matches!(err, ThresholdError::InsufficientShares { .. }));
    }

    #[test]
    fn reject_duplicate_share_indices() {
        let shares = split_secret(b"hi", ThresholdConfig::DEFAULT).unwrap();
        // Forge a duplicate of share #1.
        let forged = vec![shares[0].clone(), shares[0].clone()];
        let err = combine_shares(&forged, ThresholdConfig::DEFAULT).unwrap_err();
        assert_eq!(err, ThresholdError::DuplicateShares);
    }

    #[test]
    fn reject_zero_index_share() {
        let shares = split_secret(b"hi", ThresholdConfig::DEFAULT).unwrap();
        let mut with_zero = shares.clone();
        with_zero[0].index = 0;
        let err = combine_shares(&with_zero, ThresholdConfig::DEFAULT).unwrap_err();
        assert_eq!(err, ThresholdError::InvalidShareIndex { index: 0 });
    }

    #[test]
    fn reject_mismatched_share_length() {
        let shares = split_secret(b"hello", ThresholdConfig::DEFAULT).unwrap();
        let mut bad = shares[1].clone();
        bad.bytes.push(0xFF);
        let combined = vec![shares[0].clone(), bad];
        let err = combine_shares(&combined, ThresholdConfig::DEFAULT).unwrap_err();
        assert!(matches!(
            err,
            ThresholdError::ShareLengthMismatch {
                expected: 5,
                got: 6
            }
        ));
    }

    #[test]
    fn tampered_share_yields_wrong_secret_silently() {
        // Core Shamir does not detect byte-level tampering — that is the
        // caller's integrity layer (`ConsumedTokenJournal.token_hash`). The
        // reconstruction path simply returns the wrong secret, which the
        // caller catches via BLAKE3 mismatch.
        let secret = b"integrity-marker";
        let mut shares = split_secret(secret, ThresholdConfig::DEFAULT).unwrap();
        shares[1].bytes[0] ^= 0xFF;
        let recovered = combine_shares(&shares[..2], ThresholdConfig::DEFAULT).unwrap();
        assert_ne!(&recovered[..], &secret[..]);
    }

    // ───── GF(256) arithmetic sanity ─────

    #[test]
    fn gf_mul_matches_aes_vectors() {
        // AES MixColumns reference: {02} · {d4} = {b3}, {03} · {bf} = {da}.
        assert_eq!(gf_mul(0x02, 0xD4), 0xB3);
        assert_eq!(gf_mul(0x03, 0xBF), 0xDA);
        // Identity.
        assert_eq!(gf_mul(0x00, 0xFF), 0x00);
        assert_eq!(gf_mul(0x01, 0x57), 0x57);
    }

    #[test]
    fn gf_inv_is_multiplicative_identity() {
        for x in 1..=255u8 {
            let inv = gf_inv(x);
            assert_ne!(inv, 0, "inverse of {x} was zero");
            assert_eq!(gf_mul(x, inv), 1, "x={x}");
        }
    }

    #[test]
    fn gf_inv_of_zero_is_zero() {
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn poly_eval_with_const_matches_full_coeff_eval() {
        // #12 — the alloc-free `gf_poly_eval_with_const` must agree with the
        // reference `gf_poly_eval` over a contiguous `[c0, c1, ...]` vector
        // for every evaluation point. Exhaustive over x with a fixed
        // polynomial, plus a couple of degenerate cases.
        let const_term = 0x57u8;
        let coeffs = [0x01u8, 0x83, 0x2A, 0xFF];
        let mut full = Vec::with_capacity(1 + coeffs.len());
        full.push(const_term);
        full.extend_from_slice(&coeffs);
        for x in 0..=255u8 {
            assert_eq!(
                gf_poly_eval_with_const(const_term, &coeffs, x),
                gf_poly_eval(&full, x),
                "mismatch at x={x}"
            );
        }
        // Degenerate: no higher-degree coeffs → constant polynomial.
        for x in 0..=255u8 {
            assert_eq!(gf_poly_eval_with_const(0x9C, &[], x), 0x9C);
        }
    }
}
