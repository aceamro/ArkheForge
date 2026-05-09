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
/// # Panics
///
/// Debug builds panic on inverted range (`start > end`) or when the
/// inclusive size overflows `T` (`start == T::MIN && end == T::MAX`
/// edge case for tightly-packed integer types). Use [`gen_range`]
/// with manual high-bound handling if you need full type range.
pub fn gen_range_inclusive<T: RandInt>(rng: &mut RngSource, range: RangeInclusive<T>) -> T {
    let (start, end) = range.into_inner();
    debug_assert!(start <= end, "gen_range_inclusive: inverted range");
    let size = end.sub(start).add(T::one());
    start.add(T::lemire_bounded(rng, size))
}

/// Lemire's `nearlydivisionless` for u32. Returns `r ∈ [0, n)` uniformly.
#[inline]
fn lemire_u32(rng: &mut RngSource, n: u32) -> u32 {
    debug_assert!(n > 0, "lemire_u32: n == 0");
    let mut buf = [0u8; 4];
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
#[inline]
fn lemire_u64(rng: &mut RngSource, n: u64) -> u64 {
    debug_assert!(n > 0, "lemire_u64: n == 0");
    let mut buf = [0u8; 8];
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
