//! Fisher-Yates in-place shuffle.

use crate::{gen_range_inclusive, RngSource};

/// In-place Fisher-Yates shuffle.
///
/// Iterates from end to start, swapping `slice[i]` with `slice[j]`
/// where `j ∈ [0, i]` is sampled uniformly via [`gen_range_inclusive`].
/// Allocation 0; uses `[T]::swap` for each transposition. Empty or
/// 1-element slices are no-ops.
pub fn shuffle<T>(rng: &mut RngSource, slice: &mut [T]) {
    let len = slice.len();
    if len < 2 {
        return;
    }
    let mut i = len - 1;
    while i > 0 {
        let j = gen_range_inclusive(rng, 0usize..=i);
        slice.swap(i, j);
        i -= 1;
    }
}
