//! Positive smoke test for `#[arkhe_pure]` (E14.L1 R4-J Subset-Rust purity).
//!
//! The compile-fail side is exhaustively covered by the 9 AST-visitor unit
//! tests in `arkhe-subset-rust-check/src/lib.rs`. This file's role is to
//! verify that the proc-macro re-emits a pure function unchanged so the
//! attribute is zero-cost when the body is clean.
//!
//! A future iteration adds `tests/ui/pure_*` trybuild fixtures with pinned
//! `.stderr` snapshots once cryptographer review converges on the expanded
//! deny-list (clock + RNG → clock + RNG + I/O + FFI).

use arkhe_forge_macros::arkhe_pure;

#[arkhe_pure]
fn pure_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

#[arkhe_pure]
fn pure_array(a: u8, b: u8) -> [u8; 2] {
    [a, b]
}

#[arkhe_pure]
fn pure_with_blake3(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

#[test]
fn pure_add_smoke() {
    assert_eq!(pure_add(3, 4), 7);
    assert_eq!(pure_add(u32::MAX, 1), 0); // wrapping
}

#[test]
fn pure_array_smoke() {
    assert_eq!(pure_array(1, 2), [1, 2]);
}

#[test]
fn pure_with_blake3_smoke() {
    let h = pure_with_blake3(b"deterministic");
    assert_eq!(h.len(), 32);
    // Determinism: same input → same hash.
    assert_eq!(h, pure_with_blake3(b"deterministic"));
}
