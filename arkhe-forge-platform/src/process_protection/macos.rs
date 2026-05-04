//! macOS process protection — `setrlimit(RLIMIT_CORE, 0)` + `ptrace(PT_DENY_ATTACH)`.
//!
//! `lock_memory()` returns `Unsupported` on purpose: Darwin has no
//! `mlockall`, and per-region `mlock` requires caller-supplied address
//! ranges that a global `lock_memory()` hook cannot know. `VM_MAKE_NOMAP`
//! is a region-level hint, not a process-global lock. Tier-0 callers on
//! macOS must treat memory-residency of the KEK as unenforced by this
//! primitive and rely on process isolation (Secure Enclave-backed Tier-1
//! path is the production route).

#![allow(unsafe_code)]

use super::{ProcessProtection, ProtectionError};

/// macOS impl.
pub struct MacosProcessProtection;

/// `<sys/ptrace.h>` exposes `PT_DENY_ATTACH = 31`. The `libc` crate does not
/// always pin the constant on macOS targets, so we declare it locally.
const PT_DENY_ATTACH: libc::c_int = 31;

/// Read `errno` after a failing libc call.
///
/// SAFETY: `libc::__error` returns a pointer to a thread-local `int` owned
/// by the libSystem runtime; dereferencing it is always defined for the
/// current thread.
fn last_errno() -> i32 {
    unsafe { *libc::__error() }
}

impl ProcessProtection for MacosProcessProtection {
    fn lock_memory(&self) -> Result<(), ProtectionError> {
        // Darwin has no `mlockall`; per-region `mlock` needs the caller's
        // address ranges. Surface the gap explicitly rather than pretend.
        Err(ProtectionError::Unsupported(
            "macOS mlockall unavailable — use per-region mlock / Secure Enclave",
        ))
    }

    fn disable_core_dump(&self) -> Result<(), ProtectionError> {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit` reads the `rlimit` struct behind `&rlim`.
        // `rlim` is a stack-allocated valid object of the expected ABI; the
        // pointer is only live for the duration of the call.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if rc == 0 {
            Ok(())
        } else {
            Err(ProtectionError::SyscallFailed {
                op: "setrlimit(RLIMIT_CORE)",
                code: last_errno(),
            })
        }
    }

    fn disable_ptrace(&self) -> Result<(), ProtectionError> {
        // SAFETY: `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` is the documented
        // self-apply form — it takes no pointers into process memory and
        // targets the calling process.
        let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(ProtectionError::SyscallFailed {
                op: "ptrace(PT_DENY_ATTACH)",
                code: last_errno(),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lock_memory_is_unsupported() {
        let proto = MacosProcessProtection;
        assert!(
            matches!(proto.lock_memory(), Err(ProtectionError::Unsupported(_))),
            "lock_memory on macOS must be Unsupported"
        );
    }

    #[test]
    fn disable_core_dump_either_succeeds_or_reports_errno() {
        let proto = MacosProcessProtection;
        match proto.disable_core_dump() {
            Ok(()) => {}
            Err(ProtectionError::SyscallFailed { op, code }) => {
                assert_eq!(op, "setrlimit(RLIMIT_CORE)");
                assert!(code != 0);
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn apply_all_propagates_lock_memory_unsupported() {
        let proto = MacosProcessProtection;
        assert!(
            matches!(proto.apply_all(), Err(ProtectionError::Unsupported(_))),
            "apply_all must surface lock_memory Unsupported"
        );
    }
}
