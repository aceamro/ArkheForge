//! BLAKE3-keyed PRNG with `split()` determinism — Lemire unbiased range +
//! Fisher-Yates shuffle. Shell-side use (kernel/runtime forbids RNG for
//! deterministic replay).
//!
//! # Layer scope
//!
//! `arkhe-rand` is an **L3 Library** tier crate per the ArkheForge layer
//! model (L0 Kernel / L1 Runtime Primitives / L2 Runtime Services /
//! L3 Library / L4-L6 Shell). The kernel and forge runtime forbid RNG
//! entirely to preserve deterministic WAL replay; this crate is consumed
//! only by shell-side code (BBS, examples, downstream applications).
//!
//! # Cryptographic core
//!
//! Each [`RngSource`] wraps a BLAKE3 XOF stream constructed via the KDF
//! mode `Hasher::new_derive_key("arkhe-rand stream").update(seed)`. The
//! context string is a version-agnostic domain-separation tag: it scopes
//! the stream away from other BLAKE3 uses of the same seed, and is held
//! stable so stored seeds replay byte-identically.
//!
//! XOF reader monotonic property is inherited from the `blake3` crate
//! spec (audited via `supply-chain/audits.toml [[audits.blake3]]`).
//!
//! # API
//!
//! - [`RngSource::from_seed`] / [`RngSource::from_os_entropy`] /
//!   [`RngSource::split`] / [`RngSource::fill_bytes`]
//! - [`gen_range`] / [`gen_range_inclusive`] (Lemire `nearlydivisionless`)
//! - [`shuffle`] (Fisher-Yates, in-place)
//!
//! # Cross-platform determinism
//!
//! Byte-to-integer conversions use explicit little-endian
//! (`u32::from_le_bytes` / `u64::from_le_bytes`) regardless of host
//! endianness, and `usize` sampling routes through the u64 Lemire path
//! on every pointer width, so the same seed yields identical values
//! and identical stream consumption across targets. Enforcement: the
//! golden-vector byte-compare in `tests/golden_vector.rs`, a CI
//! self-grep that rejects native-endian conversion helpers under
//! `arkhe-rand/src/`, and a host identity test asserting `usize`
//! draws equal `u64` draws bit-for-bit.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;

use zeroize::Zeroizing;

mod range;
mod shuffle;

pub use range::{gen_range, gen_range_inclusive, RandInt};
pub use shuffle::shuffle;

/// BLAKE3 KDF context string — a version-agnostic domain-separation tag.
/// It scopes arkhe-rand's stream away from other BLAKE3 uses of the same
/// seed and is held stable across crate versions so stored seeds replay
/// byte-identically.
const KDF_CONTEXT: &str = "arkhe-rand stream";

/// BLAKE3 XOF output block length. `fill_bytes` prefetches one full
/// output block at a time so small draws (4/8 bytes per Lemire sample)
/// do not recompute a 64-byte block per call.
const XOF_BLOCK_LEN: usize = 64;

/// BLAKE3-keyed PRNG.
///
/// `RngSource` consumes 32 bytes of seed material (deterministic mode
/// via [`from_seed`]) or OS entropy (`os-entropy` feature, [`from_os_entropy`])
/// and produces a monotonic byte stream via BLAKE3's eXtendable Output
/// Function.
///
/// # Drop semantics
///
/// On drop, `seed` and the buffered (not-yet-emitted) stream block are
/// zeroized via `Zeroizing`. The internal XOF state is replaced with a
/// sentinel zero-keyed reader; the discarded reader drops normally —
/// allocator-dependent behavior, not internal-state wipe (blake3 does
/// not expose that surface). Best-effort defense-in-depth.
///
/// # Debug redaction
///
/// `Debug` prints `RngSource { .. }` only — seed bytes and XOF state
/// are never exposed.
///
/// [`from_seed`]: RngSource::from_seed
/// [`from_os_entropy`]: RngSource::from_os_entropy
pub struct RngSource {
    // `seed` is held purely as a drop-zeroize guard via `Zeroizing<T>` —
    // the bytes are consumed only at construction time inside
    // `from_seed` and never re-read by the API. The compiler flags it
    // as dead, but removing it would lose the guarantee that the seed
    // material is overwritten when the `RngSource` is dropped.
    #[allow(dead_code)]
    seed: Zeroizing<[u8; 32]>,
    xof: blake3::OutputReader,
    // One-block prefetch cache over the XOF stream: `block[pos..]`
    // holds bytes already computed but not yet emitted
    // (`pos == XOF_BLOCK_LEN` means empty). Purely an internal
    // representation — the emitted byte sequence is identical to
    // reading the XOF directly for every request-size interleaving.
    block: Zeroizing<[u8; XOF_BLOCK_LEN]>,
    pos: usize,
}

impl RngSource {
    /// Construct a deterministic `RngSource` from a 32-byte seed.
    ///
    /// Stream is produced via BLAKE3 KDF mode:
    /// `Hasher::new_derive_key(KDF_CONTEXT).update(seed).finalize_xof()`.
    /// Two `RngSource` instances built from the same seed produce
    /// byte-identical streams across all targets.
    ///
    /// Callers holding seed material in a non-`Zeroizing` buffer
    /// should wrap it themselves — this constructor only zeroizes the
    /// internal copy, not the caller's source bytes.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(KDF_CONTEXT);
        hasher.update(seed.as_slice());
        let xof = hasher.finalize_xof();
        Self {
            seed: Zeroizing::new(*seed),
            xof,
            block: Zeroizing::new([0u8; XOF_BLOCK_LEN]),
            pos: XOF_BLOCK_LEN,
        }
    }

    /// Construct an `RngSource` from OS entropy (`getrandom`).
    ///
    /// Returns `Err(RngError::OsEntropyUnavailable)` when the OS
    /// CSPRNG is unreachable (kernel pre-init / WASM without crypto
    /// interface). Never panics.
    #[cfg(feature = "os-entropy")]
    pub fn from_os_entropy() -> Result<Self, RngError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(RngError::OsEntropyUnavailable)?;
        Ok(Self::from_seed(&seed))
    }

    /// Derive an independent child `RngSource` from this stream.
    ///
    /// 32 bytes are consumed from the parent XOF stream and used as
    /// the child seed. Parent and child streams are independent —
    /// consuming one does not advance the other, and both remain
    /// deterministic given the original seed. Typical use: server /
    /// table / hand 3-level split for multiplayer deal isolation.
    pub fn split(&mut self) -> Self {
        // Local child seed is `Zeroizing`-wrapped to close the
        // stack-leak window between XOF read and `from_seed` copy.
        // The read goes through `fill_bytes` (not the raw XOF) so the
        // child seed is the next 32 bytes of the emitted stream, with
        // the prefetch cache accounted for.
        let mut child = Zeroizing::new([0u8; 32]);
        self.fill_bytes(child.as_mut_slice());
        Self::from_seed(&child)
    }

    /// Fill `buf` with `buf.len()` bytes from the XOF stream.
    ///
    /// Stream advance is monotonic — each call emits exactly the next
    /// `buf.len()` bytes of the stream (entropy accounting). The reader
    /// prefetches one 64-byte XOF output block at a time internally;
    /// the prefetch changes only the cost of small draws, never the
    /// emitted byte sequence. Timing is bounded by `buf.len()` only;
    /// no input-dependent timing leak.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut filled = 0;
        while filled < buf.len() {
            if self.pos == XOF_BLOCK_LEN {
                if buf.len() - filled >= XOF_BLOCK_LEN {
                    // Cache empty and a full block (or more) is wanted:
                    // serve the remainder straight from the XOF — same
                    // bytes, no copy through the cache.
                    self.xof.fill(&mut buf[filled..]);
                    return;
                }
                self.xof.fill(self.block.as_mut_slice());
                self.pos = 0;
            }
            let n = (buf.len() - filled).min(XOF_BLOCK_LEN - self.pos);
            buf[filled..filled + n].copy_from_slice(&self.block[self.pos..self.pos + n]);
            self.pos += n;
            filled += n;
        }
    }
}

impl Drop for RngSource {
    fn drop(&mut self) {
        // `seed` and `block` auto-zeroized by Zeroizing<T>::drop. XOF
        // state: best-effort sentinel replacement; the discarded
        // reader drops normally (blake3 does not expose internal
        // state wipe). See the type-level docs.
        let zero_seed = [0u8; 32];
        let mut sentinel = blake3::Hasher::new_derive_key(KDF_CONTEXT);
        sentinel.update(&zero_seed);
        self.xof = sentinel.finalize_xof();
    }
}

impl fmt::Debug for RngSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RngSource").finish_non_exhaustive()
    }
}

/// Error returned by [`RngSource::from_os_entropy`].
#[cfg(feature = "os-entropy")]
#[non_exhaustive]
#[derive(Debug)]
pub enum RngError {
    /// OS CSPRNG unreachable. The wrapped `getrandom::Error` carries
    /// the platform-specific cause.
    OsEntropyUnavailable(getrandom::Error),
}

#[cfg(feature = "os-entropy")]
impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OsEntropyUnavailable(e) => write!(f, "OS entropy unavailable: {e}"),
        }
    }
}
