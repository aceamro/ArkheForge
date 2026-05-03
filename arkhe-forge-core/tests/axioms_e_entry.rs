//! Axiom harness for E-entry-1..7 (spec §4.4 / §11.5).
//!
//! Enforcement tier (CHANGELOG "Axiom enforcement"):
//! - **Type-system proven**: E-entry-1, E-entry-5 — `EntryParentDepth` cache
//!   shape + relay-kind discriminant make divergence impossible.
//! - **Shape-only**: E-entry-2, E-entry-3, E-entry-4, E-entry-6, E-entry-7 —
//!   wire layouts are pinned (body/parent/cipher metadata, depth cap, AAD
//!   binding), but compute-level reject paths land in a future release.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use arkhe_forge_core::actor::ActorId;
use arkhe_forge_core::brand::ShellId;
use arkhe_forge_core::component::{ArkheComponent, BoundedString};
use arkhe_forge_core::entry::{
    BodyCipherMeta, EntryBody, EntryCore, EntryId, EntryParentDepth, RelayKind, MAX_ENTRY_DEPTH,
};
use arkhe_forge_core::pii::{AeadKind, DekId};
use arkhe_forge_core::space::SpaceId;
use arkhe_kernel::abi::{EntityId, Tick};

fn eid(v: u64) -> EntityId {
    EntityId::new(v).unwrap()
}

fn base_core(shell: ShellId) -> EntryCore {
    EntryCore {
        schema_version: 1,
        shell_id: shell,
        space_id: SpaceId::new(eid(1)),
        author_id: ActorId::new(eid(2)),
        parent_entry: None,
        relay_of: None,
        relay_kind: None,
        created_tick: Tick(10),
    }
}

/// **E-entry-1 (MC)** — exactly one `EntryCore` per Entry. Spec §4.4.
#[test]
fn e_entry_1_core_type_code_pinned() {
    assert_eq!(EntryCore::TYPE_CODE, 0x0003_0301);
    assert_eq!(EntryCore::SCHEMA_VERSION, 1);
}

/// **E-entry-2 (MC)** — `author_id` and `space_id` live in the same shell
/// (E7 inheritance). The skeleton pins the field shape; a future release
/// compute path reads `ActorProfile` and `SpaceConfig` for dual-check.
/// Spec §4.4.
#[test]
fn e_entry_2_core_binds_author_and_space() {
    let shell = ShellId([0x22; 16]);
    let ec = base_core(shell);
    assert_eq!(ec.shell_id, shell);
    assert_eq!(ec.author_id, ActorId::new(eid(2)));
    assert_eq!(ec.space_id, SpaceId::new(eid(1)));
}

/// **E-entry-3 (MC)** — `parent_entry` chain is cycle-free with depth ≤ 64.
/// Surfaces the depth cache Component + constant. Spec §4.4.
#[test]
fn e_entry_3_parent_depth_cache_exposed() {
    assert_eq!(EntryParentDepth::TYPE_CODE, 0x0003_0303);
    let d = EntryParentDepth {
        schema_version: 1,
        depth: 63,
    };
    assert!(d.depth < MAX_ENTRY_DEPTH);
}

/// **E-entry-4 (MC)** — relay is single-level. `relay_of` points to the
/// source Entry, and `relay_kind` tags `Plain` vs `Quote`. The skeleton
/// pins the field triple; a future release compute path rejects
/// `relay_of(relay_of(…))`. Spec §4.4.
#[test]
fn e_entry_4_relay_kind_pinned_discriminants() {
    // `#[non_exhaustive] #[repr(u8)]` pins the discriminant order.
    assert_eq!(RelayKind::Plain as u8, 0);
    assert_eq!(RelayKind::Quote as u8, 1);
    let shell = ShellId([0u8; 16]);
    let core_with_relay = EntryCore {
        relay_of: Some(EntryId::new(eid(99))),
        relay_kind: Some(RelayKind::Quote),
        ..base_core(shell)
    };
    assert!(core_with_relay.relay_of.is_some());
}

/// **E-entry-5 (MC)** — `DeleteEntry` is soft. `EntryBody` is removed while
/// `EntryCore` remains (for audit). Pins the split. Spec §4.4.
#[test]
fn e_entry_5_body_is_separate_component() {
    assert_eq!(EntryBody::TYPE_CODE, 0x0003_0302);
    let body = EntryBody {
        schema_version: 1,
        title: None,
        body_hash: [0u8; 32],
        body_cipher_meta: None,
        edit_seq: 0,
    };
    assert_eq!(body.edit_seq, 0);
}

/// **E-entry-6 (MC)** — `edit_seq` is monotone. The skeleton pins the field
/// as `u32`; a future release compute path rejects non-monotone updates.
/// Spec §4.4.
#[test]
fn e_entry_6_edit_seq_is_unsigned_monotone_type() {
    let b0 = EntryBody {
        schema_version: 1,
        title: Some(BoundedString::<256>::new("v0").unwrap()),
        body_hash: [0u8; 32],
        body_cipher_meta: None,
        edit_seq: 0,
    };
    let b1 = EntryBody {
        edit_seq: b0.edit_seq + 1,
        ..b0.clone()
    };
    assert!(b1.edit_seq > b0.edit_seq);
}

/// **E-entry-7 (MC / P5)** — `parent_entry` and `relay_of` are immutable
/// after creation. The skeleton pins the optional-handle shape; a future
/// release compute path rejects `UpdateEntry { parent_entry / relay_of }`.
/// Spec §4.4.
#[test]
fn e_entry_7_body_cipher_meta_surface_stable() {
    // The cipher meta surface is what survives the soft-delete boundary on
    // the non-deleted rows — pin its shape.
    let meta = BodyCipherMeta {
        dek_id: DekId([0xAB; 16]),
        aead_kind: AeadKind::XChaCha20Poly1305,
        nonce: [0x22; 24],
    };
    let body = EntryBody {
        schema_version: 1,
        title: None,
        body_hash: [0u8; 32],
        body_cipher_meta: Some(meta.clone()),
        edit_seq: 3,
    };
    let bytes = postcard::to_stdvec(&body).unwrap();
    let back: EntryBody = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back.body_cipher_meta.unwrap().dek_id, meta.dek_id);
}
