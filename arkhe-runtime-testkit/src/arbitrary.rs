//! `proptest::Arbitrary` impl for Runtime primitive types.
//!
//! 각 type 의 value 영역을 정확히 cover — spec 의 경계값 (TypeCode range
//! boundary / BoundedString N limit / Tick monotone) 을 fuzz 경로에 직접 주입.

use proptest::prelude::*;

use arkhe_forge_core::typecode;

/// Core Component TypeCode range strategy — `0x0003_0000..=0x0003_0EFF`.
pub fn core_component_typecode() -> impl Strategy<Value = u32> {
    typecode::CORE_COMPONENT.0..=typecode::CORE_COMPONENT.1
}

/// Core Event TypeCode range strategy — `0x0003_0F00..=0x0003_FFFF`.
pub fn core_event_typecode() -> impl Strategy<Value = u32> {
    typecode::CORE_EVENT.0..=typecode::CORE_EVENT.1
}

/// Canonical Activity verb range strategy — `0x0002_0001..=0x0002_03FF`.
pub fn canonical_verb_typecode() -> impl Strategy<Value = u32> {
    typecode::CORE_VERB_CANONICAL.0..=typecode::CORE_VERB_CANONICAL.1
}

/// Shell-scoped TypeCode strategy — used by the `shell_id` brand fuzz suite.
pub fn shell_scoped_typecode() -> impl Strategy<Value = u32> {
    typecode::SHELL_SCOPED.0..=typecode::SHELL_SCOPED.1
}

/// Tick value strategy — u64 전 영역 fuzz.
pub fn tick_value() -> impl Strategy<Value = u64> {
    0u64..=u64::MAX
}

/// NonZeroU64 entity id strategy — L0 A6 승계.
pub fn entity_id_nz() -> impl Strategy<Value = core::num::NonZeroU64> {
    (1u64..=u64::MAX).prop_map(|v| {
        // 1..=u64::MAX 이므로 NonZeroU64::new 가 Some 보장 — safe 경로.
        core::num::NonZeroU64::new(v).unwrap_or(core::num::NonZeroU64::MIN)
    })
}
