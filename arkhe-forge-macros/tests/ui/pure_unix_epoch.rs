//! Compile-fail: `#[arkhe_pure]` rejects `std::time::UNIX_EPOCH` constant access.
//! E14.L1-Deny clock category.

use arkhe_forge_macros::arkhe_pure;

#[arkhe_pure]
fn compute() -> u128 {
    let _ = std::time::UNIX_EPOCH;
    0
}

fn main() {}
