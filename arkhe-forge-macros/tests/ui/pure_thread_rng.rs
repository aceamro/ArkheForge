//! Compile-fail: `#[arkhe_pure]` rejects `rand::thread_rng`.
//! E14.L1-Deny RNG category.
//!
//! `rand` is stubbed locally so the snapshot captures only the macro
//! error (no transitive rustc "unresolved module" noise).

use arkhe_forge_macros::arkhe_pure;

mod rand {
    pub fn thread_rng() -> u32 {
        0
    }
}

#[arkhe_pure]
fn compute() -> u32 {
    let _rng = rand::thread_rng;
    0
}

fn main() {}
