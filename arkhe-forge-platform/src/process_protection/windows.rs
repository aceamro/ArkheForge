//! Windows process protection — `SetProcessWorkingSetSizeEx` (HARDWS min
//! enable) + `SetErrorMode` (SEM_NOGPFAULTERRORBOX) + debugger probe.
//!
//! `SetProcessWorkingSetSizeEx` with `QUOTA_LIMITS_HARDWS_MIN_ENABLE` pins
//! the current minimum working set so the Win32 memory manager cannot
//! page it out — the closest Windows analogue of `mlockall`. A
//! page-by-page `VirtualLock` approach would need caller-supplied
//! address ranges, which are not known to this process-global hook.
//!
//! Windows has no portable "deny ptrace attach" primitive. We surface
//! `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` as a detection + warn
//! signal; a real denial requires `ProcessMitigationPolicy` or driver-level
//! attestation, both of which are out of scope for a Tier-0 software-kek
//! fallback.

#![allow(unsafe_code)]

use super::{ProcessProtection, ProtectionError};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, IsDebuggerPresent, SetErrorMode, SEM_FAILCRITICALERRORS,
    SEM_NOGPFAULTERRORBOX,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessWorkingSetSizeEx, SetProcessWorkingSetSizeEx,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, QUOTA_LIMITS_HARDWS_MIN_ENABLE};

/// Windows impl.
pub struct WindowsProcessProtection;

impl ProcessProtection for WindowsProcessProtection {
    fn lock_memory(&self) -> Result<(), ProtectionError> {
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle (constant
        // `-1`) that does not require close. No invalid pointers involved.
        let process = unsafe { GetCurrentProcess() };

        let mut min_ws: usize = 0;
        let mut max_ws: usize = 0;
        let mut flags: u32 = 0;
        // SAFETY: `GetProcessWorkingSetSizeEx` writes three out-parameters
        // whose lifetimes are bounded by the stack locals above. The
        // pseudo-handle is a valid first argument.
        let ok = unsafe {
            GetProcessWorkingSetSizeEx(
                process,
                &mut min_ws as *mut usize,
                &mut max_ws as *mut usize,
                &mut flags as *mut u32,
            )
        };
        if ok == 0 {
            // SAFETY: `GetLastError` reads a thread-local DWORD; always
            // defined for the current thread.
            let code = unsafe { GetLastError() } as i32;
            return Err(ProtectionError::SyscallFailed {
                op: "GetProcessWorkingSetSizeEx",
                code,
            });
        }

        // SAFETY: `SetProcessWorkingSetSizeEx` takes integer parameters and
        // the pseudo-handle; no pointers into process memory.
        let ok = unsafe {
            SetProcessWorkingSetSizeEx(
                process,
                min_ws,
                max_ws,
                flags | QUOTA_LIMITS_HARDWS_MIN_ENABLE,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() } as i32;
            return Err(ProtectionError::SyscallFailed {
                op: "SetProcessWorkingSetSizeEx",
                code,
            });
        }

        Ok(())
    }

    fn disable_core_dump(&self) -> Result<(), ProtectionError> {
        // Windows has no "core dump" per se; the closest analogue is the
        // Windows Error Reporting "GP fault" dialog + crash dump. Suppress
        // the dialog + fatal-error forwarding — this also keeps headless
        // hosts from pausing on uncaught faults.
        //
        // SAFETY: `SetErrorMode` reads a bit mask and returns the previous
        // mode. No pointers involved. The returned value is intentionally
        // discarded.
        let _previous = unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
        Ok(())
    }

    fn disable_ptrace(&self) -> Result<(), ProtectionError> {
        // Windows has no self-apply "deny debugger attach" primitive —
        // detect + reject. Surfacing `Err(DebuggerAttached)` lets the
        // caller fail-close (Tier-0 startup policy) rather than read
        // `.is_ok()` as "no debugger".
        //
        // SAFETY: `IsDebuggerPresent` reads a PEB flag via the Win32 API;
        // no pointer arguments.
        let local_attached = unsafe { IsDebuggerPresent() } != 0;

        // SAFETY: `GetCurrentProcess` pseudo-handle, `remote` out-ptr to a
        // stack-local BOOL.
        let process = unsafe { GetCurrentProcess() };
        let mut remote: i32 = 0;
        let ok = unsafe { CheckRemoteDebuggerPresent(process, &mut remote as *mut i32) };
        if ok == 0 {
            let code = unsafe { GetLastError() } as i32;
            return Err(ProtectionError::SyscallFailed {
                op: "CheckRemoteDebuggerPresent",
                code,
            });
        }

        if local_attached || remote != 0 {
            return Err(ProtectionError::DebuggerAttached(
                "IsDebuggerPresent or CheckRemoteDebuggerPresent reported attach",
            ));
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
        let proto = WindowsProcessProtection;
        match proto.apply_all() {
            Ok(()) => {}
            Err(ProtectionError::SyscallFailed { op, code }) => {
                eprintln!("apply_all SyscallFailed op={op} code={code}");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn disable_core_dump_never_errors_on_windows() {
        let proto = WindowsProcessProtection;
        // `SetErrorMode` has no failure path.
        proto.disable_core_dump().expect("SetErrorMode cannot fail");
    }
}
