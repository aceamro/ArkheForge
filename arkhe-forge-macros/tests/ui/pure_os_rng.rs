//! Compile-fail: `#[arkhe_pure]` rejects `rand::rngs::OsRng`.
//! E14.L1-Deny RNG category.
//!
//! `rand` is stubbed locally so the snapshot captures only the macro
//! error (no transitive rustc "unresolved module" noise).

use arkhe_forge_macros::arkhe_pure;

mod rand {
    pub mod rngs {
        pub struct OsRng;
    }
}

#[arkhe_pure]
fn compute() -> u32 {
    let _ = rand::rngs::OsRng;
    0
}

fn main() {}
