//! `card-primitives` library — re-exported modules for the binary
//! and the integration test suite.
//!
//! The companion `src/main.rs` consumes these modules to play a single
//! provably-fair Texas Hold'em hand. The companion `tests/` directory
//! consumes them to run the GLI-19 §3.2.5-compliant statistical RNG
//! suite (`tests/statistical_rng_suite.rs`).
//!
//! ## Educational scope
//!
//! These modules are pedagogical primitives — full API surface for the
//! tutorial demo, exercised by per-module inline tests, and the
//! `#![allow(dead_code)]` at the lib root is a deliberate choice to
//! keep all `pub` items accessible to readers without binary-crate
//! reachability noise. Production crates layer their own visibility
//! controls on top.

#![allow(dead_code)]

pub mod card;
pub mod deck;
pub mod forge_integration;
pub mod hand_eval;
pub mod shuffle_proof;
