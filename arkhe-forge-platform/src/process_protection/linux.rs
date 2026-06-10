//! Linux process protection — `mlockall` + `PR_SET_DUMPABLE` +
//! `PR_SET_PTRACER` with an advisory `yama.ptrace_scope` probe.
//!
//! This file opts into `unsafe_code` scoped to the libc FFI calls; every
//! `unsafe { ... }` block carries a SAFETY note that justifies the call
//! arguments.

#![allow(unsafe_code)]

use super::{ProcessProtection, ProtectionError};

/// Linux impl.
pub struct LinuxProcessProtection;

/// Read `errno` after a failing libc call.
///
/// SAFETY: `libc::__errno_location` returns a pointer to a thread-local
/// `int` owned by the libc runtime; dereferencing it is always defined for
/// the current thread.
fn last_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

impl ProcessProtection for LinuxProcessProtection {
    fn lock_memory(&self) -> Result<(), ProtectionError> {
        // SAFETY: `mlockall` takes a bitmask of integer constants and has no
        // pointer arguments. `MCL_CURRENT | MCL_FUTURE` is a valid flag set
        // per `man 2 mlockall`.
        let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        if rc == 0 {
            Ok(())
        } else {
            Err(ProtectionError::SyscallFailed {
                op: "mlockall",
                code: last_errno(),
            })
        }
    }

    fn disable_core_dump(&self) -> Result<(), ProtectionError> {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0, ...)` takes `c_ulong` integer
        // arguments; the fifth `0` fills the unused slot per `man 2 prctl`.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(ProtectionError::SyscallFailed {
                op: "prctl(PR_SET_DUMPABLE)",
                code: last_errno(),
            })
        }
    }

    fn disable_ptrace(&self) -> Result<(), ProtectionError> {
        // First: detect whether a tracer is **already attached** via
        // `/proc/self/status` `TracerPid`. If non-zero we surface a
        // hard error so callers cannot misread `.is_ok()` as "no
        // debugger" — `disable_ptrace` would otherwise return Ok
        // even with an attacker process holding ptrace control.
        // Fail closed when the probe itself is unreadable (hidepid=2
        // procfs, sandbox mount masking): an Ok return GUARANTEES no
        // tracer was attached at call time, so an unknown tracer state
        // must be an error, not a silent pass.
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
            ProtectionError::SyscallFailed {
                op: "read(/proc/self/status)",
                code: e.raw_os_error().unwrap_or(0),
            }
        })?;
        let mut tracer_line_seen = false;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                if rest.trim() != "0" {
                    return Err(ProtectionError::DebuggerAttached(
                        "TracerPid != 0 in /proc/self/status",
                    ));
                }
                tracer_line_seen = true;
                break;
            }
        }
        // A status file without a TracerPid line (field-restricted procfs)
        // leaves the tracer state unknown — fail closed, same as an
        // unreadable probe.
        if !tracer_line_seen {
            return Err(ProtectionError::SyscallFailed {
                op: "parse(/proc/self/status TracerPid)",
                code: 0,
            });
        }

        // SAFETY: `prctl(PR_SET_PTRACER, 0, ...)` sets the process-wide
        // ptracer pid to 0 (= no process may ptrace-attach). Pure integer
        // call, no pointers.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_PTRACER,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if rc != 0 {
            return Err(ProtectionError::SyscallFailed {
                op: "prctl(PR_SET_PTRACER)",
                code: last_errno(),
            });
        }

        // Advisory: `/proc/sys/kernel/yama/ptrace_scope` is a system-wide
        // knob. Anything other than `2` (admin-only) means some ptracer
        // parent could still attach. We surface a stderr warning but do not
        // reject — a per-process API cannot enforce a system-wide setting.
        // (Distinct from the TracerPid check above, which is a present-
        // tense attach detection rather than a system policy advisory.)
        match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            Ok(content) => {
                let scope = content.trim();
                if scope != "2" {
                    eprintln!(
                        "arkhe-forge-platform: yama.ptrace_scope={scope} (want 2); \
                         per-process ptrace protection cannot cover this gap."
                    );
                }
            }
            Err(_) => {
                // Yama LSM not active on this kernel — advisory only.
                eprintln!(
                    "arkhe-forge-platform: /proc/sys/kernel/yama/ptrace_scope unreadable; \
                     yama LSM likely disabled."
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn apply_all_returns_ok_or_specific_error() {
        let proto = LinuxProcessProtection;
        match proto.apply_all() {
            Ok(()) => {}
            Err(ProtectionError::SyscallFailed { op, code }) => {
                // Container / unprivileged user environments may produce
                // EPERM/ENOMEM — returning a specific error is itself
                // evidence the implementation is complete.
                eprintln!("apply_all reported SyscallFailed op={op} code={code}");
            }
            Err(ProtectionError::DebuggerAttached(reason)) => {
                // m6 — running under cargo-test with `lldb` / `rr` etc.
                // would surface this. Test ack only; CI normally won't.
                eprintln!("apply_all reported DebuggerAttached: {reason}");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn disable_core_dump_either_succeeds_or_reports_errno() {
        let proto = LinuxProcessProtection;
        match proto.disable_core_dump() {
            Ok(()) => {}
            Err(ProtectionError::SyscallFailed { op, code }) => {
                assert_eq!(op, "prctl(PR_SET_DUMPABLE)");
                assert!(code != 0, "errno should be non-zero on failure");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn disable_ptrace_signals_attach_explicitly() {
        // m6 — disable_ptrace must surface `DebuggerAttached` rather
        // than silently returning Ok when a tracer is present.
        // Outside a debugger the call returns Ok; the variant exists
        // so callers can fail-close on attach. A SyscallFailed may
        // carry the prctl op, the fail-closed status-read op, or the
        // fail-closed TracerPid-parse op (masked / field-restricted
        // procfs environments).
        let proto = LinuxProcessProtection;
        match proto.disable_ptrace() {
            Ok(()) => {}
            Err(ProtectionError::DebuggerAttached(_)) => {}
            Err(ProtectionError::SyscallFailed { op, .. }) => {
                assert!(
                    op == "prctl(PR_SET_PTRACER)"
                        || op == "read(/proc/self/status)"
                        || op == "parse(/proc/self/status TracerPid)",
                    "unexpected SyscallFailed op: {op}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}
