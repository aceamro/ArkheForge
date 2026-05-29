//! Lemire `nearlydivisionless` unbiased range sampling.
//!
//! [`gen_range`] / [`gen_range_inclusive`] produce uniform integers
//! from a `Range` / `RangeInclusive` without modulo bias. Each call
//! consumes 4 or 8 bytes per accepted sample (rejection rate is
//! bounded by `2 * range_size / 2^32` for u32 and `2 * range_size /
//! 2^64` for u64); seed bytes are sourced via
//! [`RngSource::fill_bytes`].
//!
//! # Type support
//!
//! The sealed [`RandInt`] trait is implemented for `u8` / `u16` /
//! `u32` / `u64` / `usize`. Signed and `u128` are excluded —
//! Lemire's widening multiplication is only defined for u32 → u64
//! and u64 → u128.

use core::ops::{Range, RangeInclusive};

use crate::RngSource;

mod sealed {
    pub trait Sealed {}
}

/// Integer types accepted by [`gen_range`] / [`gen_range_inclusive`].
///
/// Sealed: only `u8` / `u16` / `u32` / `u64` / `usize` implement this
/// trait.
pub trait RandInt: sealed::Sealed + Copy + PartialOrd {
    #[doc(hidden)]
    fn lemire_bounded(rng: &mut RngSource, range_size: Self) -> Self;

    /// Uniform sample in the inclusive span `[low, high]`. The
    /// implementation computes the span size in a WIDENED type so a
    /// full-width range (`low == T::MIN && high == T::MAX`) does not
    /// overflow `T` to `0` — the widened size feeds Lemire directly,
    /// with the `2^32` / `2^64` full-range case handled inside
    /// [`lemire_u32`] / [`lemire_u64`] (`n == 0` sentinel).
    #[doc(hidden)]
    fn lemire_inclusive(rng: &mut RngSource, low: Self, high: Self) -> Self;

    #[doc(hidden)]
    fn add(self, n: Self) -> Self;

    #[doc(hidden)]
    fn sub(self, n: Self) -> Self;

    #[doc(hidden)]
    fn one() -> Self;
}

macro_rules! impl_rand_int_via_u32 {
    ($($t:ty),* $(,)?) => {
        $(
            impl sealed::Sealed for $t {}
            impl RandInt for $t {
                #[inline]
                fn lemire_bounded(rng: &mut RngSource, range_size: Self) -> Self {
                    lemire_u32(rng, range_size as u32) as Self
                }
                #[inline]
                fn lemire_inclusive(rng: &mut RngSource, low: Self, high: Self) -> Self {
                    // Widen to u64 so `high - low + 1` cannot overflow the
                    // narrow type (e.g. 255 - 0 + 1 = 256 for u8). The
                    // span maxes at 2^32 (full u32 range); pass 0 to
                    // `lemire_u32` as the "full range" sentinel in that case.
                    let span = (high as u64) - (low as u64) + 1;
                    let n = if span == (1u64 << 32) { 0u32 } else { span as u32 };
                    low.wrapping_add(lemire_u32(rng, n) as Self)
                }
                #[inline]
                fn add(self, n: Self) -> Self { self + n }
                #[inline]
                fn sub(self, n: Self) -> Self { self - n }
                #[inline]
                fn one() -> Self { 1 }
            }
        )*
    };
}

impl_rand_int_via_u32!(u8, u16, u32);

impl sealed::Sealed for u64 {}
impl RandInt for u64 {
    #[inline]
    fn lemire_bounded(rng: &mut RngSource, range_size: Self) -> Self {
        lemire_u64(rng, range_size)
    }
    #[inline]
    fn lemire_inclusive(rng: &mut RngSource, low: Self, high: Self) -> Self {
        // Widen to u128 so `high - low + 1` cannot overflow u64 (full
        // range 0..=u64::MAX → 2^64). Pass 0 to `lemire_u64` as the
        // "full range" sentinel for the 2^64 case.
        let span = (high as u128) - (low as u128) + 1;
        let n = if span == (1u128 << 64) {
            0u64
        } else {
            span as u64
        };
        low.wrapping_add(lemire_u64(rng, n))
    }
    #[inline]
    fn add(self, n: Self) -> Self {
        self + n
    }
    #[inline]
    fn sub(self, n: Self) -> Self {
        self - n
    }
    #[inline]
    fn one() -> Self {
        1
    }
}

impl sealed::Sealed for usize {}
impl RandInt for usize {
    #[inline]
    fn lemire_bounded(rng: &mut RngSource, range_size: Self) -> Self {
        #[cfg(target_pointer_width = "32")]
        {
            lemire_u32(rng, range_size as u32) as usize
        }
        #[cfg(target_pointer_width = "64")]
        {
            lemire_u64(rng, range_size as u64) as usize
        }
    }
    #[inline]
    fn lemire_inclusive(rng: &mut RngSource, low: Self, high: Self) -> Self {
        // Widen one step past pointer width so the full-range span never
        // overflows; pass 0 to the underlying Lemire as the "full range"
        // (2^32 / 2^64) sentinel.
        #[cfg(target_pointer_width = "32")]
        {
            let span = (high as u64) - (low as u64) + 1;
            let n = if span == (1u64 << 32) {
                0u32
            } else {
                span as u32
            };
            low.wrapping_add(lemire_u32(rng, n) as usize)
        }
        #[cfg(target_pointer_width = "64")]
        {
            let span = (high as u128) - (low as u128) + 1;
            let n = if span == (1u128 << 64) {
                0u64
            } else {
                span as u64
            };
            low.wrapping_add(lemire_u64(rng, n) as usize)
        }
    }
    #[inline]
    fn add(self, n: Self) -> Self {
        self + n
    }
    #[inline]
    fn sub(self, n: Self) -> Self {
        self - n
    }
    #[inline]
    fn one() -> Self {
        1
    }
}

/// Sample a uniformly-random value from `range` ∈ `[start, end)`.
///
/// # Panics
///
/// Debug builds panic on empty range (`start >= end`). Release builds
/// elide the assert (std `Range` API symmetry).
pub fn gen_range<T: RandInt>(rng: &mut RngSource, range: Range<T>) -> T {
    debug_assert!(range.start < range.end, "gen_range: empty range");
    let size = range.end.sub(range.start);
    range.start.add(T::lemire_bounded(rng, size))
}

/// Sample a uniformly-random value from `range` ∈ `[start, end]`.
///
/// The inclusive span size (`end - start + 1`) is computed in a widened
/// type, so a full-width range — `0u8..=255u8`, `0u16..=65535u16`,
/// `0u64..=u64::MAX` — is sampled uniformly without overflowing `T` to
/// `0` (which would otherwise divide-by-zero in Lemire under debug or
/// produce non-uniform output under release).
///
/// # Panics
///
/// Debug builds panic on an inverted range (`start > end`).
pub fn gen_range_inclusive<T: RandInt>(rng: &mut RngSource, range: RangeInclusive<T>) -> T {
    let (start, end) = range.into_inner();
    debug_assert!(start <= end, "gen_range_inclusive: inverted range");
    T::lemire_inclusive(rng, start, end)
}

/// Lemire's `nearlydivisionless` for u32. Returns `r ∈ [0, n)` uniformly.
///
/// `n == 0` is the full-range sentinel (`2^32`): every 32-bit value is
/// already uniform, so the raw draw is returned without rejection.
#[inline]
fn lemire_u32(rng: &mut RngSource, n: u32) -> u32 {
    let mut buf = [0u8; 4];
    if n == 0 {
        rng.fill_bytes(&mut buf);
        return u32::from_le_bytes(buf);
    }
    loop {
        rng.fill_bytes(&mut buf);
        let x = u32::from_le_bytes(buf);
        let m = u64::from(x) * u64::from(n);
        let l = m as u32;
        if l < n {
            let t = n.wrapping_neg() % n;
            if l < t {
                continue;
            }
        }
        return (m >> 32) as u32;
    }
}

/// Lemire's `nearlydivisionless` for u64. Returns `r ∈ [0, n)` uniformly.
///
/// `n == 0` is the full-range sentinel (`2^64`): every 64-bit value is
/// already uniform, so the raw draw is returned without rejection.
#[inline]
fn lemire_u64(rng: &mut RngSource, n: u64) -> u64 {
    let mut buf = [0u8; 8];
    if n == 0 {
        rng.fill_bytes(&mut buf);
        return u64::from_le_bytes(buf);
    }
    loop {
        rng.fill_bytes(&mut buf);
        let x = u64::from_le_bytes(buf);
        let m = u128::from(x) * u128::from(n);
        let l = m as u64;
        if l < n {
            let t = n.wrapping_neg() % n;
            if l < t {
                continue;
            }
        }
        return (m >> 64) as u64;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn rng() -> RngSource {
        RngSource::from_seed(&[0x5Au8; 32])
    }

    /// #12 — full narrow-type inclusive range must not panic (debug) or
    /// go non-uniform (release). `255 - 0 + 1` would overflow u8 to 0
    /// under the old `T`-typed size computation; the widened span avoids
    /// it. Runs identically in debug and release.
    #[test]
    fn full_range_u8_does_not_panic_and_covers_extremes() {
        let mut r = rng();
        let mut saw_min = false;
        let mut saw_max = false;
        for _ in 0..100_000 {
            let v = gen_range_inclusive(&mut r, 0u8..=255u8);
            if v == 0 {
                saw_min = true;
            }
            if v == 255 {
                saw_max = true;
            }
        }
        assert!(saw_min, "full u8 range must be able to yield 0");
        assert!(saw_max, "full u8 range must be able to yield 255");
    }

    /// #12 — full u16 range (`0..=65535`): `65535 - 0 + 1 = 65536`
    /// overflows u16 to 0 under the naive path. Widened span fixes it.
    #[test]
    fn full_range_u16_does_not_panic_and_covers_extremes() {
        let mut r = rng();
        let mut saw_min = false;
        let mut saw_max = false;
        for _ in 0..500_000 {
            let v = gen_range_inclusive(&mut r, 0u16..=65535u16);
            if v == 0 {
                saw_min = true;
            }
            if v == 65535 {
                saw_max = true;
            }
        }
        assert!(saw_min, "full u16 range must be able to yield 0");
        assert!(saw_max, "full u16 range must be able to yield 65535");
    }

    /// Full u32 range exercises the `2^32` sentinel in `lemire_u32`.
    #[test]
    fn full_range_u32_does_not_panic() {
        let mut r = rng();
        for _ in 0..10_000 {
            let _ = gen_range_inclusive(&mut r, 0u32..=u32::MAX);
        }
    }

    /// Full u64 range exercises the `2^64` sentinel in `lemire_u64`.
    #[test]
    fn full_range_u64_does_not_panic() {
        let mut r = rng();
        let mut saw_high = false;
        for _ in 0..10_000 {
            let v = gen_range_inclusive(&mut r, 0u64..=u64::MAX);
            if v > (u64::MAX >> 1) {
                saw_high = true;
            }
        }
        assert!(saw_high, "full u64 range must reach the upper half");
    }

    /// A narrow non-full inclusive range still samples correctly and
    /// stays within bounds (regression guard that the widened path did
    /// not perturb ordinary ranges — same byte stream as before).
    #[test]
    fn narrow_inclusive_range_stays_in_bounds() {
        let mut r = rng();
        for _ in 0..10_000 {
            let v = gen_range_inclusive(&mut r, 1u8..=6u8);
            assert!((1..=6).contains(&v));
        }
    }
}
