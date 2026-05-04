//! Compile-fail: `#[arkhe_pure]` rejects `std::time::Instant::now`.
//! E14.L1-Deny clock category.

use arkhe_forge_macros::arkhe_pure;

#[arkhe_pure]
fn compute() -> u128 {
    let _now = std::time::Instant::now();
    0
}

fn main() {}
