//! TypeCode allocation bounds — core sub-split.
//!
//! Pins the sub-ranges carved out of L0 `TypeCode(u32)` for Runtime use. Each
//! Core 5 primitive allocates its specific TypeCode within these bounds; a
//! downstream proc-macro check validates that every `#[arkhe(type_code = N)]`
//! declaration falls in the right range.

/// Kernel reserved — L0.
pub const KERNEL_RESERVED: (u32, u32) = (0x0000_0000, 0x0000_FFFF);

/// ArkheForge core primitive Entity TypeCode.
pub const CORE_ENTITY: (u32, u32) = (0x0001_0000, 0x0001_FFFF);

/// Canonical Activity verb — 1023 slot.
pub const CORE_VERB_CANONICAL: (u32, u32) = (0x0002_0001, 0x0002_03FF);

/// Shell-extensible verb — shell_id BLAKE3 → 256-verb deterministic sub-range.
pub const SHELL_VERB: (u32, u32) = (0x0002_0400, 0x0002_FFFF);

/// ArkheForge core Component TypeCode.
pub const CORE_COMPONENT: (u32, u32) = (0x0003_0000, 0x0003_0EFF);

/// ArkheForge core Event TypeCode (sub-range split).
pub const CORE_EVENT: (u32, u32) = (0x0003_0F00, 0x0003_FFFF);

/// `RoomMarker` TypeCode reservation (SHAPE-only — Room
/// primitive declaration).
///
/// **Sealed-completeness mutual lock**: this doc-only constant
/// reserves the `0x0001_5001` slot at the source level, preventing
/// implementers from accidentally re-allocating it for a different
/// `EntityKind` impl. The `RoomMarker: EntityKind` shape is
/// deferred until ecosystem evidence justifies the implementation
/// surface; the slot foreclosure here is non-committal.
///
/// **SHAPE-only scope**:
///
/// - `EntityKind` trait + per-marker `impl` blocks remain spec-text-
///   only (paired with the ArkheUri implementation surface).
/// - **0 Component / 0 Action / 0 VerbCode** allocations under
///   `RoomMarker`. Room-specific verbs land via the shell BLAKE3
///   sub-allocation pattern, NOT as canonical verbs in
///   `CORE_VERB_CANONICAL`.
/// - The cap-token family `arkhe:room/{join, post, leave, ...}` is
///   an independent dimension — this constant reserves only the
///   Entity TypeCode slot.
///
/// **Slot rationale**: next free in the `0x0001_X001` Core Entity
/// sub-range progression — `UserMarker 0x0001_0001` /
/// `ActorMarker 0x0001_1001` / `SpaceMarker 0x0001_2001` /
/// `EntryMarker 0x0001_3001` / `ActivityMarker 0x0001_4001` /
/// **`RoomMarker 0x0001_5001`**.
pub const ROOM_MARKER_RESERVED: u32 = 0x0001_5001;

/// Reserved for future Runtime-layer primitives.
pub const RUNTIME_RESERVED: (u32, u32) = (0x0004_0000, 0x00FF_FFFF);

/// Shell-scoped Component / Action.
pub const SHELL_SCOPED: (u32, u32) = (0x0100_0000, 0xEFFF_FFFF);

/// Debug / test only.
pub const DEBUG_TEST: (u32, u32) = (0xF000_0000, 0xFFFF_FFFF);

/// Core Event TypeCode pins.
///
/// Each `#[derive(ArkheEvent)]` impl sets `#[arkhe(type_code = ...)]` to one
/// of these constants. Adding a new Event requires updating this list and
/// the TypeCode allocation table in the same change.
pub mod core_event {
    /// `RuntimeBootstrap` — E12 axiom.
    pub const RUNTIME_BOOTSTRAP: u32 = 0x0003_0F01;
    /// `UserErasureScheduled` — GDPR cascade.
    pub const USER_ERASURE_SCHEDULED: u32 = 0x0003_0F02;
    /// `UserErasureCompleted` — crypto-shred receipt.
    pub const USER_ERASURE_COMPLETED: u32 = 0x0003_0F03;
    /// `BackupErasurePropagated` — per-region propagation.
    pub const BACKUP_ERASURE_PROPAGATED: u32 = 0x0003_0F04;
    /// `GdprPolicyViolation` — L1 compute reject audit.
    pub const GDPR_POLICY_VIOLATION: u32 = 0x0003_0F05;
    /// `SignatureClassPolicy` — chain-anchored policy (E13 axiom).
    pub const SIGNATURE_CLASS_POLICY: u32 = 0x0003_0F06;
    /// `CrossShellActivity` — replay/admin reject audit.
    pub const CROSS_SHELL_ACTIVITY: u32 = 0x0003_0F07;
    /// `PerRegionErasureProgress` — two-phase commit.
    pub const PER_REGION_ERASURE_PROGRESS: u32 = 0x0003_0F08;
    /// `DekMigrationCompleted` — DEK rotation lifecycle receipt.
    pub const DEK_MIGRATION_COMPLETED: u32 = 0x0003_0F09;
    /// `ComplianceTierChange` — Tier-{0,1,2} transition record.
    pub const COMPLIANCE_TIER_CHANGE: u32 = 0x0003_0F0A;

    /// `ReplicaIdAllocation` — federation-replica registration
    /// receipt. Define-only — the Cargo feature
    /// `federation-archive-hardened` gates the type definition.
    ///
    /// **0-emission posture** — the runtime ships the type definition
    /// and reserves the wire slot, but no production code path ever
    /// calls `emit_event::<ReplicaIdAllocation>(..)`. Emission
    /// activates once the federation prerequisites (archive-hardening,
    /// `SignedArkheUri`, identity federation layer)
    /// are met.
    pub const REPLICA_ID_ALLOCATION: u32 = 0x0003_0F0D;

    /// `AuditReceiptKeyPolicy` — audit-receipt key inventory /
    /// rotation manifest. Define-only — the Cargo feature
    /// `audit-receipt-key-identified` gates the type definition.
    ///
    /// **0-emission posture** — production code path never emits;
    /// activation requires the operator-side carry-over (g)
    /// "audit-receipt key identity declared in `docs/release-keys.md`
    /// inventory anchor.
    pub const AUDIT_RECEIPT_KEY_POLICY: u32 = 0x0003_0F0E;
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `ROOM_MARKER_RESERVED` lands in the Core Entity sub-range, next
    /// free after `ActivityMarker 0x0001_4001`
    /// progression. Implementers must not collide.
    #[test]
    fn room_marker_reserved_value_is_pinned() {
        assert_eq!(ROOM_MARKER_RESERVED, 0x0001_5001);
    }

    /// Sealed-completeness mutual lock: the
    /// reserved slot must lie inside the Core Entity sub-range.
    /// Misallocation outside the range would silently break the
    /// `EntityKind` implementation surface.
    #[test]
    fn room_marker_reserved_lands_in_core_entity_subrange() {
        let (lo, hi) = CORE_ENTITY;
        assert!(
            (lo..=hi).contains(&ROOM_MARKER_RESERVED),
            "ROOM_MARKER_RESERVED 0x{ROOM_MARKER_RESERVED:08x} must lie in CORE_ENTITY \
             range 0x{lo:08x}..=0x{hi:08x}"
        );
    }

    /// SHAPE-only freeze: no other Core Entity constant can collide
    /// with the reserved slot. Core Entity allocations are limited to
    /// `UserMarker` / `ActorMarker` / `SpaceMarker` / `EntryMarker` /
    /// `ActivityMarker` plus the SHAPE-only `RoomMarker`
    /// reservation.
    #[test]
    fn room_marker_reserved_does_not_collide_with_other_pinned_slots() {
        let known_entity_slots = [
            0x0001_0001u32, // UserMarker
            0x0001_1001u32, // ActorMarker
            0x0001_2001u32, // SpaceMarker
            0x0001_3001u32, // EntryMarker
            0x0001_4001u32, // ActivityMarker
        ];
        for s in known_entity_slots {
            assert_ne!(
                ROOM_MARKER_RESERVED, s,
                "ROOM_MARKER_RESERVED collides with marker 0x{s:08x}"
            );
        }
    }

    /// Compile-time SHAPE-only confirmation: the reservation does NOT
    /// collide with any Core Event TypeCode (different sub-range).
    /// A misalloc that crosses the Entity / Event boundary would
    /// silently re-use a Core Event slot.
    #[test]
    fn room_marker_reserved_does_not_overlap_core_event_range() {
        let (lo, hi) = CORE_EVENT;
        assert!(
            !(lo..=hi).contains(&ROOM_MARKER_RESERVED),
            "ROOM_MARKER_RESERVED 0x{ROOM_MARKER_RESERVED:08x} must not enter \
             CORE_EVENT range"
        );
    }

    // ----- Forward-looking event TypeCode reservations -----

    /// `ReplicaIdAllocation` lands at the `0x0003_0F0D` Core Event
    /// slot (the `0x0003_0F0B..=0x0003_0F0C` slots are permanent
    /// gaps). Implementers must not collide.
    #[test]
    fn replica_id_allocation_typecode_pinned_at_0x0003_0f0d() {
        assert_eq!(core_event::REPLICA_ID_ALLOCATION, 0x0003_0F0D);
    }

    /// `AuditReceiptKeyPolicy` follows immediately after
    /// `ReplicaIdAllocation`. Together the pair reserves a contiguous
    /// 2-slot block for forward-looking events.
    #[test]
    fn audit_receipt_key_policy_typecode_pinned_at_0x0003_0f0e() {
        assert_eq!(core_event::AUDIT_RECEIPT_KEY_POLICY, 0x0003_0F0E);
    }

    /// Both forward-looking event TypeCodes lie inside the Core Event
    /// sub-range. Misallocation outside the range would silently break
    /// the runtime registry's range-based dispatch.
    #[test]
    fn forward_looking_event_typecodes_inside_core_event_range() {
        let (lo, hi) = CORE_EVENT;
        for slot in [
            core_event::REPLICA_ID_ALLOCATION,
            core_event::AUDIT_RECEIPT_KEY_POLICY,
        ] {
            assert!(
                (lo..=hi).contains(&slot),
                "forward-looking TypeCode 0x{slot:08x} must lie inside \
                 CORE_EVENT range 0x{lo:08x}..=0x{hi:08x}"
            );
        }
    }

    /// Forward-looking event TypeCodes do NOT collide with any
    /// previously pinned Core Event slot (`0x0003_0F01..=0x0003_0F0A`).
    #[test]
    fn forward_looking_event_typecodes_no_collision_with_existing() {
        let pinned_existing: &[u32] = &[
            core_event::RUNTIME_BOOTSTRAP,
            core_event::USER_ERASURE_SCHEDULED,
            core_event::USER_ERASURE_COMPLETED,
            core_event::BACKUP_ERASURE_PROPAGATED,
            core_event::GDPR_POLICY_VIOLATION,
            core_event::SIGNATURE_CLASS_POLICY,
            core_event::CROSS_SHELL_ACTIVITY,
            core_event::PER_REGION_ERASURE_PROGRESS,
            core_event::DEK_MIGRATION_COMPLETED,
            core_event::COMPLIANCE_TIER_CHANGE,
        ];
        for new_slot in [
            core_event::REPLICA_ID_ALLOCATION,
            core_event::AUDIT_RECEIPT_KEY_POLICY,
        ] {
            for old_slot in pinned_existing {
                assert_ne!(
                    new_slot, *old_slot,
                    "forward-looking TypeCode 0x{new_slot:08x} collides \
                     with previously pinned slot 0x{old_slot:08x}"
                );
            }
        }
    }

    /// Forward-looking event TypeCodes do NOT collide with the Core
    /// Entity sub-range (`ROOM_MARKER_RESERVED 0x0001_5001` and the
    /// marker series). Cross-band collision would break the
    /// Entity/Event sub-range invariant.
    #[test]
    fn forward_looking_event_typecodes_no_collision_with_core_entity_range() {
        let (lo, hi) = CORE_ENTITY;
        for new_slot in [
            core_event::REPLICA_ID_ALLOCATION,
            core_event::AUDIT_RECEIPT_KEY_POLICY,
        ] {
            assert!(
                !(lo..=hi).contains(&new_slot),
                "forward-looking TypeCode 0x{new_slot:08x} must NOT \
                 enter CORE_ENTITY range 0x{lo:08x}..=0x{hi:08x}"
            );
        }
    }

    /// The two forward-looking event TypeCodes are themselves distinct
    /// (no double-allocation).
    #[test]
    fn forward_looking_event_typecodes_distinct() {
        assert_ne!(
            core_event::REPLICA_ID_ALLOCATION,
            core_event::AUDIT_RECEIPT_KEY_POLICY,
            "REPLICA_ID_ALLOCATION and AUDIT_RECEIPT_KEY_POLICY must \
             be distinct"
        );
    }
}
