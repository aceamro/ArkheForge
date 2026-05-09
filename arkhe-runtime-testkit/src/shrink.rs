//! Scope-based shrinker — TypeCode-region per-shrink path.
//!
//! Runs a separate shrink path per TypeCode region. For example, a failure in
//! the core Component range (`0x0003_0000..=0x0003_0EFF`) is minimized within
//! that range only rather than migrated into the shell-scoped range, which
//! keeps the originating region pinned.

/// Shrink scope marker — TypeCode-region dispatch key for shrink paths.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShrinkScope {
    /// `0x0003_0000..=0x0003_0EFF`
    CoreComponent,
    /// `0x0003_0F00..=0x0003_FFFF`
    CoreEvent,
    /// `0x0002_0001..=0x0002_03FF`
    CanonicalVerb,
    /// `0x0002_0400..=0x0002_FFFF`
    ShellVerb,
    /// `0x0100_0000..=0xEFFF_FFFF`
    ShellScoped,
    /// `0xF000_0000..=0xFFFF_FFFF`
    DebugTest,
}

impl ShrinkScope {
    /// Classify a raw TypeCode to its shrink scope.
    pub fn of(type_code: u32) -> Option<Self> {
        use arkhe_forge_core::typecode::*;
        match type_code {
            c if (CORE_COMPONENT.0..=CORE_COMPONENT.1).contains(&c) => Some(Self::CoreComponent),
            c if (CORE_EVENT.0..=CORE_EVENT.1).contains(&c) => Some(Self::CoreEvent),
            c if (CORE_VERB_CANONICAL.0..=CORE_VERB_CANONICAL.1).contains(&c) => {
                Some(Self::CanonicalVerb)
            }
            c if (SHELL_VERB.0..=SHELL_VERB.1).contains(&c) => Some(Self::ShellVerb),
            c if (SHELL_SCOPED.0..=SHELL_SCOPED.1).contains(&c) => Some(Self::ShellScoped),
            c if (DEBUG_TEST.0..=DEBUG_TEST.1).contains(&c) => Some(Self::DebugTest),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_core_component() {
        assert_eq!(
            ShrinkScope::of(0x0003_0001),
            Some(ShrinkScope::CoreComponent)
        );
    }

    #[test]
    fn classify_core_event() {
        assert_eq!(ShrinkScope::of(0x0003_0F01), Some(ShrinkScope::CoreEvent));
    }

    #[test]
    fn classify_debug_test() {
        assert_eq!(ShrinkScope::of(0xFFFF_FFFF), Some(ShrinkScope::DebugTest));
    }
}
