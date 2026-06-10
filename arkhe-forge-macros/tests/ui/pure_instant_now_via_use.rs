//! Compile-fail: `#[arkhe_pure]` rejects `Instant::now` reached through
//! `use std::time::Instant` (multi-segment suffix match).
//! E14.L1-Deny clock category.
//!
//! The macro sees only the fn item, not the surrounding `use`
//! statements, so the cited deny entry is the lexicographically first
//! one sharing the `::Instant::now` suffix — the category (clock) is
//! what matters.

use arkhe_forge_macros::arkhe_pure;

use std::time::Instant;

#[arkhe_pure]
fn compute() -> u128 {
    let _now = Instant::now();
    0
}

fn main() {}
