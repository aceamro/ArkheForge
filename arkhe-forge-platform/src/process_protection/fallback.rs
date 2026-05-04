//! Fallback — Tier-0 software-kek 은 본 target 에서 reject.
//! Linux / macOS / Windows 외 target 에서는 `apply_all()` 이 항상 Err.

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
