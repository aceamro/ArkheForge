//! Process protection trait — spec LF4.
//!
//! Per-platform abstraction that lets a Tier-0 software-KEK process
//! protects the memory residency of
//! its key material.
//!
//! Three-platform implementation:
//!
//! - **Linux** — `mlockall(MCL_CURRENT|MCL_FUTURE)` for paging control,
//!   `prctl(PR_SET_DUMPABLE, 0)` for core-dump suppression, and
//!   `prctl(PR_SET_PTRACER, 0)` plus a `yama.ptrace_scope` advisory check for
//!   ptrace hardening.
//! - **macOS** — `setrlimit(RLIMIT_CORE, 0)` and `ptrace(PT_DENY_ATTACH)`;
//!   `lock_memory()` surfaces `Unsupported` because `mlockall` is absent on
//!   Darwin and per-region `mlock` requires address ranges that are only
//!   known to the caller (`VM_MAKE_NOMAP` is a region-level hint, not a
//!   process-global lock).
//! - **Windows** — `SetProcessWorkingSetSizeEx(... HARDWS_MIN_ENABLE)` to pin
//!   the current working set against paging, `SetErrorMode(SEM_NOGPFAULT...)`
//!   to suppress fault-report dialogs, and an `IsDebuggerPresent` +
//!   `CheckRemoteDebuggerPresent` probe (Windows has no portable "deny
//!   attach" primitive; we detect + surface rather than prevent).
//!
//! Runtime startup calls [`ProcessProtection::apply_all()`]; the per-step
//! syscall failure surfaces as [`ProtectionError::SyscallFailed`] and bubbles
//! up to `RuntimeInitError::ProcessProtectionUnavailable`.

/// Platform-agnostic process protection interface.
pub trait ProcessProtection {
    /// Lock all current + future process memory — block swap / paging.
    fn lock_memory(&self) -> Result<(), ProtectionError>;
    /// Disable core dump generation.
    fn disable_core_dump(&self) -> Result<(), ProtectionError>;
    /// Block ptrace / debugger attach.
    ///
    /// **Contract**: an `Ok(())` return guarantees that, at the moment
    /// of the call, no debugger is currently attached **and** the
    /// platform-specific deny / detect primitive succeeded. Existing
    /// attach is reported as [`ProtectionError::DebuggerAttached`] so
    /// callers cannot read `.is_ok()` as "no debugger" — the m6 silent-
    /// success regression is closed.
    ///
    /// Platform behaviour:
    /// - **Linux** — `prctl(PR_SET_PTRACER, 0)` proactively denies
    ///   future attaches; `/proc/self/status` `TracerPid != 0` returns
    ///   `DebuggerAttached`. The system-wide `yama.ptrace_scope`
    ///   advisory remains a stderr warning (per-process API cannot
    ///   override system policy).
    /// - **macOS** — `ptrace(PT_DENY_ATTACH)` actively denies, so a
    ///   successful call implies no attach.
    /// - **Windows** — `IsDebuggerPresent` / `CheckRemoteDebuggerPresent`
    ///   detection only; attach surfaces `DebuggerAttached`. Windows has
    ///   no portable self-deny primitive.
    fn disable_ptrace(&self) -> Result<(), ProtectionError>;

    /// Apply all three — Runtime startup capability check.
    fn apply_all(&self) -> Result<(), ProtectionError> {
        self.lock_memory()?;
        self.disable_core_dump()?;
        self.disable_ptrace()?;
        Ok(())
    }
}

/// Process protection application failure.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProtectionError {
    /// Platform or primitive unsupported — macOS `mlockall` absence is representative.
    #[error("platform unsupported: {0}")]
    Unsupported(&'static str),
    /// Syscall failure (errno + platform-specific detail go through the log path).
    #[error("syscall failed: {op} (code {code})")]
    SyscallFailed {
        /// syscall / API name.
        op: &'static str,
        /// Platform errno or HRESULT.
        code: i32,
    },
    /// Protection applied while a debugger / ptracer is already attached.
    /// If `disable_ptrace()` only emits a silent warn, a caller could
    /// misread `.is_ok()` as "no debugger". This variant is the explicit
    /// signal — operator should detach and retry, or fail-close at
    /// startup (Tier-0 policy).
    #[error("debugger attached: {0}")]
    DebuggerAttached(&'static str),
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxProcessProtection as ActiveImpl;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosProcessProtection as ActiveImpl;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsProcessProtection as ActiveImpl;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod fallback;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use fallback::FallbackProcessProtection as ActiveImpl;

#[cfg(test)]
mod tests {
    use super::*;

    struct Noop;
    impl ProcessProtection for Noop {
        fn lock_memory(&self) -> Result<(), ProtectionError> {
            Ok(())
        }
        fn disable_core_dump(&self) -> Result<(), ProtectionError> {
            Ok(())
        }
        fn disable_ptrace(&self) -> Result<(), ProtectionError> {
            Ok(())
        }
    }

    #[test]
    fn apply_all_composes_three_steps() {
        let noop = Noop;
        assert!(noop.apply_all().is_ok());
    }
}
