//! # ArkheForge Runtime — L1 Primitives (`arkhe-forge-core`)
//!
//! Core 5 primitive types (User / Actor / Space / Entry / Activity), sealed
//! `ArkheComponent` / `ArkheAction` / `ArkheEvent` traits, `ShellBrand<'s>`
//! invariant-lifetime isolation, deterministic entity-id derivation.
//!
//! Pure compute — no I/O, no time, no randomness (L0 A11 succession). Only
//! depends on `arkhe-kernel` (L0) and `arkhe-macros` (derive provider).
//! `arkhe-forge-platform` must not be pulled in (layer-independence directive).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Self-alias so macro-generated `::arkhe_forge_core::...` paths resolve when
// the derive is applied inside this crate itself.
extern crate self as arkhe_forge_core;

pub mod action;
pub mod activity;
pub mod actor;
pub mod brand;
pub mod component;
pub mod context;
pub mod entry;
pub mod event;
pub mod pii;
pub mod pipeline;
// Internal sealed-trait machinery — `__sealed::__Sealed` is exposed only so
// the runtime derive macros can emit `impl __Sealed for UserType {}`.
// Downstream crates must never reference this module; the dylint CI gate
// flags any such usage. See `sealed.rs` for the soft-seal rationale.
#[doc(hidden)]
#[path = "sealed.rs"]
pub mod __sealed;
pub mod space;
pub mod typecode;
pub mod user;

/// Re-exports of the Runtime-layer derive + attribute macros from
/// `arkhe-forge-macros`. `#[arkhe_pure]` is the E14.L1 R4-J Subset-Rust
/// purity attribute for `Action::compute` bodies (v0.12 도입).
pub use arkhe_forge_macros::{arkhe_pure, ArkheAction, ArkheComponent, ArkheEvent};

use arkhe_kernel::abi::{EntityId, InstanceId, Tick, TypeCode};

/// ArkheForge Runtime semver triple — matches the repo release.
pub const RUNTIME_SEMVER: (u16, u16, u16) = (0, 11, 0);

/// Maximum retry count for zero-digest collision avoidance (spec §4.7).
pub const MAX_ID_DERIVE_RETRIES: u32 = 16;

/// Deterministic entity-id derivation (spec §4.7). Pure — no hidden state.
///
/// Given a 256-bit non-exportable `world_seed`, a per-runtime `instance_id`,
/// the primitive's `type_code`, and the spawning `tick` / `seq`, returns a
/// collision-resistant `EntityId`. Zero-valued outputs are retried by
/// incrementing `seq` up to [`MAX_ID_DERIVE_RETRIES`]; exhaustion returns
/// `None` so the caller can emit an `IdExhaustion` Failure event.
#[must_use]
pub fn derive_entity_id(
    world_seed: &[u8; 32],
    instance_id: InstanceId,
    type_code: TypeCode,
    tick: Tick,
    seq: u32,
) -> Option<EntityId> {
    let domain_key = blake3::derive_key("arkhe-forge-entity-id", world_seed);
    for bump in 0..MAX_ID_DERIVE_RETRIES {
        let candidate_seq = seq.wrapping_add(bump);
        let mut h = blake3::Hasher::new_keyed(&domain_key);
        h.update(&instance_id.get().to_be_bytes());
        h.update(&type_code.0.to_be_bytes());
        h.update(&tick.0.to_be_bytes());
        h.update(&candidate_seq.to_be_bytes());
        let out = h.finalize();
        let digest = out.as_bytes();
        let mut first_eight = [0u8; 8];
        first_eight.copy_from_slice(&digest[..8]);
        let raw = u64::from_be_bytes(first_eight);
        if let Some(id) = EntityId::new(raw) {
            return Some(id);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod lib_tests {
    use super::*;

    fn instance(v: u64) -> InstanceId {
        InstanceId::new(v).unwrap()
    }

    #[test]
    fn derive_entity_id_is_deterministic() {
        let seed = [0x11u8; 32];
        let iid = instance(1);
        let a = derive_entity_id(&seed, iid, TypeCode(0x0001_0001), Tick(42), 0);
        let b = derive_entity_id(&seed, iid, TypeCode(0x0001_0001), Tick(42), 0);
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn derive_entity_id_differs_across_type_code() {
        let seed = [0x11u8; 32];
        let iid = instance(1);
        let a = derive_entity_id(&seed, iid, TypeCode(0x0001_0001), Tick(1), 0);
        let b = derive_entity_id(&seed, iid, TypeCode(0x0001_0002), Tick(1), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_entity_id_differs_across_instance() {
        let seed = [0x11u8; 32];
        let a = derive_entity_id(&seed, instance(1), TypeCode(0x0001_0001), Tick(1), 0);
        let b = derive_entity_id(&seed, instance(2), TypeCode(0x0001_0001), Tick(1), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_entity_id_differs_across_world_seed() {
        let s1 = [0x01u8; 32];
        let s2 = [0x02u8; 32];
        let iid = instance(1);
        let a = derive_entity_id(&s1, iid, TypeCode(0x0001_0001), Tick(1), 0);
        let b = derive_entity_id(&s2, iid, TypeCode(0x0001_0001), Tick(1), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_entity_id_seq_changes_output() {
        let seed = [0x11u8; 32];
        let iid = instance(1);
        let a = derive_entity_id(&seed, iid, TypeCode(0x0001_0001), Tick(1), 0);
        let b = derive_entity_id(&seed, iid, TypeCode(0x0001_0001), Tick(1), 1);
        assert_ne!(a, b);
    }
}
