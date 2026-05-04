//! Generic wasm-memory `(ptr, len)` bounds-check helpers shared by hook
//! and observer hosts.
//!
//! Both `read_caller_memory<T>` and `write_caller_memory<T>` enforce the
//! cryptographer-pinned bounds-check rule order before touching wasm
//! linear memory:
//!
//! 1. negative `len` → trap
//! 2. negative `ptr` → trap (BEFORE `len == 0` short-circuit;
//!    defense-in-depth ordering)
//! 3. `len == 0` (or empty `bytes`) → no-op (memory export not required)
//! 4. missing `memory` export → trap
//! 5. `ptr + len` `u64` overflow → trap
//! 6. `ptr + len > memory.data_size()` → OOB trap
//!
//! Generic over the `wasmtime::Store` data type `T` — both
//! `HookStoreData` (chain-affecting) and `ObserverStoreData` (chain-
//! non-affecting) callers share one body, ensuring the bounds-check
//! invariant cannot drift between hosts.

use wasmtime::{Caller, Memory};

/// Read `len` bytes from the calling wasm module's exported `memory`
/// at `ptr`, applying the cryptographer-pinned bounds-check contract.
/// All `(ptr, len)` host-fn arguments MUST pass through this helper
/// before the host touches wasm memory.
///
/// Generic over the `wasmtime::Store` data type `T` — both
/// `HookStoreData` (chain-affecting) and `ObserverStoreData` (chain-
/// non-affecting) callers share one body, ensuring the bounds-check
/// invariant cannot drift between hosts.
///
/// # Bounds-check rules (in order)
///
/// 1. `len < 0` → trap (wasm i32 reinterpreted as signed; negative
///    is an invalid byte count).
/// 2. `ptr < 0` → trap. Input validation runs BEFORE the `len == 0`
///    short-circuit so a hostile module passing `(ptr = -1, len = 0)`
///    is caught at the input-validation layer, not silently masked
///    (defense-in-depth ordering).
/// 3. `len == 0` → return `Ok(Vec::new())` without consulting the
///    memory export. A wasm caller asking for zero bytes is well-
///    formed even if the module has no `memory` export at all.
/// 4. Module has no `memory` export → trap (`memory` resolution fails).
/// 5. `ptr.checked_add(len)` overflows `u64` → trap (arithmetic
///    overflow defense).
/// 6. `ptr + len > Memory::data_size(&caller)` → OOB trap.
///
/// On success, the bytes are copied into a fresh `Vec<u8>` (host owns
/// the copy; wasm memory is not aliased).
///
/// # Why these checks
///
/// Without the bounds-check, a malicious or buggy wasm module could
/// pass `(ptr = SIZE_MAX, len = 1)` and induce the host to deref
/// arbitrary memory beyond the wasm linear-memory sandbox — an
/// FFI-shaped sandbox-escape primitive. Belt-and-braces alongside
/// wasmtime's own internal memory-region tracking.
//
// `dead_code` allowed: under `tier-2-observer-host-v2` only (no hook
// feature), this helper may be unused at the local call site. The
// function compiles + type-checks under the observer-only feature so
// the contract stays pinned in the shared module regardless of which
// host dispatch is currently active (drift avoidance).
#[allow(dead_code)]
pub(crate) fn read_caller_memory<T>(
    caller: &mut Caller<'_, T>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, wasmtime::Error> {
    if len < 0 {
        return Err(wasmtime::Error::msg(format!(
            "OOB: negative length ({len})"
        )));
    }
    if ptr < 0 {
        return Err(wasmtime::Error::msg(format!(
            "OOB: negative pointer ({ptr})"
        )));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let memory: Memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("OOB: module does not export `memory`"))?;
    let memory_size = memory.data_size(&*caller) as u64;
    let ptr_u = ptr as u64;
    let len_u = len as u64;
    let end = ptr_u
        .checked_add(len_u)
        .ok_or_else(|| wasmtime::Error::msg("OOB: ptr + len overflowed u64"))?;
    if end > memory_size {
        return Err(wasmtime::Error::msg(format!(
            "OOB: ptr+len ({end}) exceeds memory size ({memory_size})"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    memory
        .read(&*caller, ptr as usize, &mut buf)
        .map_err(|e| wasmtime::Error::msg(format!("OOB: memory read failed: {e}")))?;
    Ok(buf)
}

/// Write `bytes` to the calling wasm module's exported `memory` at
/// `ptr`, applying the symmetric bounds-check contract for output data
/// flow. Used by host-fns that write back into wasm memory (e.g.
/// `state.read` returning a looked-up value).
///
/// Generic over the `wasmtime::Store` data type `T` — same rationale
/// as [`read_caller_memory`].
///
/// # Bounds-check rules (mirroring [`read_caller_memory`])
///
/// - `ptr < 0` → trap.
/// - `bytes.is_empty()` → return `Ok(())` without consulting memory
///   export (zero-byte write is a no-op).
/// - Module has no `memory` export → trap.
/// - `ptr.checked_add(bytes.len() as u64)` overflows `u64` → trap.
/// - `ptr + len > Memory::data_size(&caller)` → OOB trap.
///
/// On success, the bytes are copied into wasm linear memory at `ptr`.
/// The host's `bytes` slice ownership is unchanged; wasm side observes
/// a fresh byte sequence at the supplied pointer.
//
// `dead_code` allowed: same rationale as `read_caller_memory`.
#[allow(dead_code)]
pub(crate) fn write_caller_memory<T>(
    caller: &mut Caller<'_, T>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), wasmtime::Error> {
    if ptr < 0 {
        return Err(wasmtime::Error::msg(format!(
            "OOB: negative pointer ({ptr})"
        )));
    }
    if bytes.is_empty() {
        return Ok(());
    }
    let memory: Memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("OOB: module does not export `memory`"))?;
    let memory_size = memory.data_size(&*caller) as u64;
    let ptr_u = ptr as u64;
    let len_u = bytes.len() as u64;
    let end = ptr_u
        .checked_add(len_u)
        .ok_or_else(|| wasmtime::Error::msg("OOB: ptr + len overflowed u64"))?;
    if end > memory_size {
        return Err(wasmtime::Error::msg(format!(
            "OOB: ptr+len ({end}) exceeds memory size ({memory_size})"
        )));
    }
    memory
        .write(&mut *caller, ptr as usize, bytes)
        .map_err(|e| wasmtime::Error::msg(format!("OOB: memory write failed: {e}")))?;
    Ok(())
}
