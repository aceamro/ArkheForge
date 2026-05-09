//! Fallback — Tier-0 software-kek is rejected on this target.
//! On targets other than Linux / macOS / Windows, `apply_all()` always returns Err.

use super::{ProcessProtection, ProtectionError};

/// Fallback impl — unsupported target.
pub struct FallbackProcessProtection;

impl ProcessProtection for FallbackProcessProtection {
    fn lock_memory(&self) -> Result<(), ProtectionError> {
        Err(ProtectionError::Unsupported("lock_memory"))
    }

    fn disable_core_dump(&self) -> Result<(), ProtectionError> {
        Err(ProtectionError::Unsupported("disable_core_dump"))
    }

    fn disable_ptrace(&self) -> Result<(), ProtectionError> {
        Err(ProtectionError::Unsupported("disable_ptrace"))
    }
}
