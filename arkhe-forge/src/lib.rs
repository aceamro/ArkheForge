//! # ArkheForge Runtime — Umbrella Re-export
//!
//! The single Runtime entry point shell crates depend on. Bundles the L1
//! primitive surface and the L2 services behind one facade. Do not import
//! `arkhe-forge-core` or `arkhe-forge-platform` directly — depend on this
//! umbrella so version alignment and feature gating stay coherent.
//!
//! Public API is in pre-freeze; semantic breaks land only on a minor bump.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use arkhe_forge_core as core;
pub use arkhe_forge_platform as platform;

/// Umbrella re-export semver.
pub const SEMVER: (u16, u16, u16) = (0, 11, 0);
