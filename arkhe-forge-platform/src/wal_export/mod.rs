//! WAL streaming export — incremental record append for snapshot / backup.
//!
//! Track F (DIP-N3 v0.12 sealing-cycle). F.1 = interface declaration only;
//! the concrete buffer-then-export implementation lands at F.2.
//!
//! # Three firm requirements (cryptographer-pinned, F.1)
//!
//! 1. **Fixed-width `u64` big-endian length prefix** before every record
//!    in the stream — deterministic + cross-platform; varint deferred
//!    pending separate determinism review.
//! 2. **Bounds-check on the length prefix** before any deref of record
//!    bytes — `0 < prefix ≤ `[`MAX_RECORD_BYTES`]. Malformed prefixes
//!    MUST be rejected with
//!    [`WalExportError::InvalidFraming`]`(`[`InvalidFramingReason`]`)`.
//!    Pattern mirrors the DIP-N1 B.5 host-fn `(ptr, len)` bounds-check
//!    contract.
//! 3. **Stream header magic** [`STREAM_HEADER_MAGIC`] (`ARKHEXP1`)
//!    pinned at the beginning of every export stream so truncation can
//!    be distinguished from "the consumer is reading garbage that
//!    happens to start with a valid length prefix".
//!
//! # Type-level append-only invariant (A14 projection)
//!
//! [`WalRecordSink`] exposes only [`WalRecordSink::append_record`] and
//! [`WalRecordSink::flush`]. **Seek / truncate / rewrite operations are
//! deliberately absent from the trait surface** — external callers
//! cannot invoke them through the trait, and the L0 A14 append-only
//! invariant is projected into the L2 export layer **without touching
//! L0 source** (DO NOT TOUCH #8 preserved). Concrete implementations
//! (F.2) MAY add private internal positioning helpers but MUST NOT
//! expose them on the public surface.
//!
//! # DO NOT TOUCH #8 (postcard field order) invariant
//!
//! The streaming format wraps **unmodified L0 record bytes**. The
//! length-prefix + stream-header framing wraps the protected payload
//! from the outside; postcard field order inside each record is
//! preserved bit-exact. F.3 verifies this by comparing streamed record
//! bytes against `arkhe_kernel::persist::Wal::serialize` record bytes.
//!
//! # Forward-compatibility
//!
//! All public types are `#[non_exhaustive]` — adding variants or fields
//! does not break external matchers. [`WalRecordSink`] trait may grow
//! additional methods only if they preserve the append-only invariant
//! (no seek / truncate / rewrite).
//!
//! # Stability
//!
//! v0.12 sealing-cycle scaffold. After v0.12 cut the surface freezes
//! per the Runtime DO NOT TOUCH list (Track G).

use std::fmt;

pub mod buffered_sink;
pub mod reader;

pub use buffered_sink::BufferedWalSink;
pub use reader::{StreamingWalReader, WalStreamReader};

#[cfg(test)]
mod wire_stability;

#[cfg(test)]
mod round_trip_tests;

/// Magic bytes pinned at the start of every WAL export stream.
///
/// `ARKHEXP1` = "ArKhe EXPort version 1". Distinct from L0
/// `WalHeader::MAGIC` (`ARKHEWAL`) — the streaming export is a
/// separate transport format that wraps L0 records, so the stream-
/// header magic is independent of the WAL header magic. A future
/// version bump (`ARKHEXP2`, …) is a wire-format break and must be
/// handled by an explicit migration DIP, not by silent reuse —
/// see [`StreamMagic`] for the structured cross-version dispatch
/// surface that DIP-N4 N4.7 added to make the bump path mechanical.
pub const STREAM_HEADER_MAGIC: [u8; 8] = *b"ARKHEXP1";

/// Stream-header magic version dispatch (DIP-N4 N4.7 — cross-version
/// forward-compat scaffold). Each enum variant maps to a distinct
/// 8-byte ASCII tag at the start of an exported stream; the reader
/// dispatches on the recognised tag to select the corresponding
/// frame-format parser.
///
/// v0.12 reserves only `V1` (the `ARKHEXP1` baseline). Future
/// migration DIPs add `V2` / `V3` / … alongside this enum and the
/// reader-side `recognize` lookup. The `#[non_exhaustive]` attribute
/// makes the additive expansion non-breaking for external matchers.
///
/// **Wire-stability invariant**: the byte mapping for `V1` is
/// pinned at `*b"ARKHEXP1"` (unchanged from the F.3 wire-stability
/// golden vector — `0x41 0x52 0x4B 0x48 0x45 0x58 0x50 0x31`). Any
/// change to the V1 byte pattern is a wire-format break and requires
/// the same migration DIP machinery as a new variant.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum StreamMagic {
    /// `ARKHEXP1` — DIP-N3 F.1 wire baseline. Currently the only
    /// supported version at v0.12.
    V1,
}

impl StreamMagic {
    /// Return the 8-byte tag for this version. `const fn` so callers
    /// can pin the byte pattern at compile time + use the result in
    /// `const` contexts.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8; 8] {
        match self {
            Self::V1 => b"ARKHEXP1",
        }
    }

    /// Recognise a stream-header magic tag — `Some(variant)` when the
    /// 8-byte input matches a supported version, `None` for any
    /// unknown tag (caller surfaces via
    /// [`WalExportError::UnsupportedStreamVersion`]).
    ///
    /// **Fail-fast posture**: this lookup runs against a stack 8-byte
    /// array — no heap allocation, no buffer slicing beyond the
    /// caller's already-read header bytes (cryptographer Q5 carry-
    /// forward).
    #[must_use]
    pub fn recognize(bytes: &[u8; 8]) -> Option<Self> {
        if bytes == b"ARKHEXP1" {
            Some(Self::V1)
        } else {
            None
        }
    }
}

/// Maximum byte length accepted in a single record's length prefix.
///
/// 16 MiB fail-secure bound — any record whose length prefix exceeds
/// this is rejected as malformed framing per cryptographer firm
/// requirement #2 (bounds-check before deref). Production WAL records
/// sit far below the threshold (typical record < 64 KiB); 16 MiB =
/// ~256× typical, ample for legitimate growth and tight enough to
/// short-circuit attacker-supplied prefix-overflow + memory-DoS
/// before any deref attempt.
///
/// **Rationale (cryptographer fail-secure pattern, mirrors DIP-N1 C8
/// hook fuel budget 100M → 10M tightening)**: the bound serves both
/// (a) anti-overflow (length prefix arithmetic) and (b) anti-memory-DoS
/// (allocation cap before record-bytes deref). Choosing the tighter
/// of the two acceptable bounds (16 MiB vs 1 GiB) closes the memory-
/// DoS attack vector with zero impact on legitimate workloads.
///
/// **Absolute vs per-sink soft cap**: this constant is the **absolute
/// ceiling** baked into the wire-format contract. Concrete sinks
/// (F.2) MAY impose tighter per-deployment soft caps via their own
/// configuration (e.g., a 1 MiB sink for embedded targets) and
/// surface those rejections through [`WalExportError::BufferOverflow`].
/// The hard ceiling here remains 16 MiB irrespective of sink
/// configuration.
pub const MAX_RECORD_BYTES: u64 = 1 << 24;

/// Top-level streaming export error surface.
///
/// `#[non_exhaustive]` — variants may be added (e.g., compression /
/// signature validation surfaces in v0.13+) without breaking external
/// matchers.
#[derive(Debug)]
#[non_exhaustive]
pub enum WalExportError {
    /// Underlying sink I/O failure — operator-side disk / network /
    /// buffer error. Carries the upstream `std::io::Error` for
    /// diagnosis.
    Io(std::io::Error),
    /// Length-prefix or stream-header framing rejection. See
    /// [`InvalidFramingReason`] for the specific malformation.
    InvalidFraming(InvalidFramingReason),
    /// Append-only invariant violated — caller attempted to submit a
    /// record whose `seq` is not the strict successor of the most
    /// recently appended record's `seq`. Surface enforcement: the
    /// type-level invariant (no seek / truncate / rewrite methods)
    /// prevents the *machinery* from rewriting, and this runtime-side
    /// check prevents the *caller* from re-ordering.
    ///
    /// **Operator response**: fix the caller — the seq ordering
    /// invariant was violated by upstream. Distinguish from
    /// [`Self::SeqExhausted`] (intrinsic limit, rotate stream).
    AppendOnlyViolation {
        /// Expected next `seq` (most recent + 1, or 0 for a fresh
        /// stream).
        expected_seq: u64,
        /// `seq` carried by the offending record.
        got_seq: u64,
        /// **(DIP-N4 N4.5 forensic field)** Most recently appended
        /// `seq`, if any. `None` means no record had been appended
        /// yet at the time of the violation (fresh stream — and
        /// `expected_seq` will be `0`). Cryptographer F.1 forensic-
        /// visibility carry-forward — gives the operator the prior
        /// high-water mark independent of the violation triple,
        /// useful when the violation post-dates a long sequence of
        /// appends and the operator wants the prior-state context
        /// without re-deriving `expected_seq - 1`.
        previous_seq: Option<u64>,
    },
    /// **(DIP-N4 N4.5 NEW variant)** Sequence space exhausted —
    /// the most recently appended `seq` is `u64::MAX`, so any
    /// further append would require an arithmetic wraparound.
    /// Distinct from [`Self::AppendOnlyViolation`] because it
    /// signals an intrinsic limit rather than a caller ordering
    /// error. Architecturally unreachable on any real-world stream
    /// (u64::MAX appends at 1ns/append exceeds the universe lifetime
    /// by ~17 orders of magnitude), but the explicit variant makes
    /// the fail-secure posture mechanical rather than implicit.
    ///
    /// **Operator response**: rotate the stream — start a new
    /// stream, this one has exhausted its u64 seq space. The current
    /// stream's `last_seq = u64::MAX` state is preserved (no
    /// corruption), so the operator may rotate at leisure.
    SeqExhausted {
        /// The exhausted seq (always `u64::MAX` at v0.12).
        last_seq: u64,
    },
    /// **(DIP-N4 N4.7 NEW variant)** Stream header magic recognised
    /// no supported version. The reader (or framing-validation
    /// caller) read 8 bytes at the stream start, asked
    /// [`StreamMagic::recognize`] to dispatch, and the lookup returned
    /// `None`. Distinct from [`InvalidFramingReason::HeaderMissing`]
    /// because that variant signals "no magic at all" (truncated
    /// header) — `UnsupportedStreamVersion` signals "magic present
    /// but unrecognised" (e.g., a stream emitted by a future
    /// `ARKHEXP2` writer that the v0.12 reader does not yet know).
    ///
    /// **Operator response**: upgrade the reader, or downgrade the
    /// writer to a known version. The carrier `magic` field gives
    /// the operator the exact 8-byte tag for triage.
    UnsupportedStreamVersion {
        /// The 8-byte tag at stream start that did not match any
        /// recognised [`StreamMagic`] variant.
        magic: [u8; 8],
    },
    /// Internal buffer capacity exhausted before flush. Caller should
    /// flush to drain. Concrete sink implementations choose their own
    /// `capacity` — F.2 pins a 16 MiB default and exposes
    /// configuration knobs through the constructor.
    BufferOverflow {
        /// Sink's configured buffer capacity in bytes.
        capacity: usize,
        /// Bytes the caller attempted to append at overflow time.
        requested: usize,
        /// **(DIP-N4 N4.5 forensic field)** Bytes already buffered
        /// at overflow time. Combined with `capacity` and
        /// `requested`, gives the operator the full sizing context:
        /// `current_buffer + requested > capacity` is the predicate
        /// that triggered overflow. Cryptographer F.2 forensic-
        /// visibility carry-forward.
        current_buffer: usize,
    },
}

/// Reasons a streamed framing wrapper is rejected.
///
/// Distinct from [`WalExportError`] so callers can match the framing
/// failure mode without needing to reach into a tuple variant. F.2
/// uses the variants individually when constructing rejection paths.
#[derive(Debug)]
#[non_exhaustive]
pub enum InvalidFramingReason {
    /// Length prefix exceeds [`MAX_RECORD_BYTES`]. Carries both the
    /// observed prefix and the bound for caller diagnostics.
    ///
    /// **Operator response**: investigate hostile stream injection
    /// or fragment producer. The 16 MiB ceiling is a fail-secure
    /// hard bound — a legitimate producer should never emit a frame
    /// at this size.
    LengthExceedsMax {
        /// The prefix value that triggered rejection.
        prefix: u64,
        /// The bound that was exceeded — equals [`MAX_RECORD_BYTES`].
        max: u64,
    },
    /// Length prefix is zero — empty records are disallowed.
    ///
    /// **v0.12 stance**: every frame must carry a payload. Future
    /// keep-alive / heartbeat support (zero-payload frames as
    /// liveness signals) is post-v0.13 sealing future DIP scope —
    /// at v0.12 the reader rejects defensively to prevent
    /// silent-no-op streams.
    ///
    /// **Operator response**: re-emit (the producer should never
    /// emit a length-zero frame at v0.12).
    LengthZero,
    /// Stream truncated — bytes ended mid-record before the full
    /// length-prefixed payload arrived. Distinguishes operator-side
    /// disk failure from valid-but-shorter streams.
    ///
    /// **Operator response**: re-emit; source likely truncated mid-
    /// write (disk full, network drop, process crash). The reader
    /// surfaces this distinct from `HeaderMissing` so the operator
    /// can distinguish "never started" from "started but cut off".
    Truncated,
    /// Stream header magic missing or mismatched at stream start.
    /// Triggered when the leading 8 bytes do not equal
    /// [`STREAM_HEADER_MAGIC`].
    ///
    /// **Operator response**: verify the source stream is an
    /// ARKHEXP-format export (not, e.g., an L0 WAL file or an
    /// unrelated binary). Distinct from
    /// [`crate::wal_export::WalExportError::UnsupportedStreamVersion`]
    /// which signals "magic present but version unrecognised".
    HeaderMissing,
}

impl fmt::Display for WalExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "wal export io: {e}"),
            Self::InvalidFraming(r) => write!(f, "wal export framing rejected: {r}"),
            Self::AppendOnlyViolation {
                expected_seq,
                got_seq,
                previous_seq,
            } => match previous_seq {
                Some(prev) => write!(
                    f,
                    "wal export append-only violation: expected seq {expected_seq}, got {got_seq} (last appended {prev})"
                ),
                None => write!(
                    f,
                    "wal export append-only violation: expected seq {expected_seq}, got {got_seq} (fresh stream, no prior appends)"
                ),
            },
            Self::SeqExhausted { last_seq } => write!(
                f,
                "wal export seq space exhausted at last_seq {last_seq} — rotate stream"
            ),
            Self::UnsupportedStreamVersion { magic } => write!(
                f,
                "wal export unsupported stream version: magic {magic:?} not recognised"
            ),
            Self::BufferOverflow {
                capacity,
                requested,
                current_buffer,
            } => write!(
                f,
                "wal export buffer overflow: capacity {capacity} bytes, current {current_buffer}, requested {requested}"
            ),
        }
    }
}

impl fmt::Display for InvalidFramingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthExceedsMax { prefix, max } => {
                write!(f, "length prefix {prefix} exceeds maximum {max} bytes")
            }
            Self::LengthZero => write!(f, "length prefix is zero — empty records disallowed"),
            Self::Truncated => write!(f, "stream truncated mid-record"),
            Self::HeaderMissing => write!(
                f,
                "stream header magic missing or mismatched (expected ARKHEXP1)"
            ),
        }
    }
}

impl std::error::Error for WalExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidFraming(_)
            | Self::AppendOnlyViolation { .. }
            | Self::SeqExhausted { .. }
            | Self::UnsupportedStreamVersion { .. }
            | Self::BufferOverflow { .. } => None,
        }
    }
}

impl std::error::Error for InvalidFramingReason {}

impl From<std::io::Error> for WalExportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Append-only sink for streaming WAL records.
///
/// Implementations append fully-encoded record bytes (postcard
/// `WalRecord` output from `arkhe_kernel::persist::Wal::serialize`)
/// one record at a time, framing each with a fixed-width `u64` BE
/// length prefix and following the stream-header pin (firm
/// requirement #1 + #3). The trait deliberately exposes neither
/// seek nor truncate nor rewrite — A14 append-only is type-level
/// enforced by the absence of those methods.
///
/// Implementations are responsible for:
///
/// - validating the length prefix bounds (`0 < len ≤
///   `[`MAX_RECORD_BYTES`]) before deref (firm requirement #2);
/// - emitting the [`STREAM_HEADER_MAGIC`] pin at stream start;
/// - rejecting out-of-sequence `seq` with
///   [`WalExportError::AppendOnlyViolation`] (caller-side append-only);
/// - durable persistence on [`flush`](Self::flush) — concrete
///   implementations decide the persistence model (fsync per record
///   vs batched fsync on flush).
///
/// `Send + Sync` are not required by the trait itself — concrete sinks
/// may be `!Sync` if they wrap interior-mutable state. F.2's reference
/// implementation is `Send` but `!Sync` (uses an internal `&mut` cursor
/// into the buffer).
pub trait WalRecordSink {
    /// Append one record's encoded bytes to the sink. The implementation
    /// frames the bytes (length prefix + payload) and records them in
    /// append order. Callers MUST submit records in monotone-increasing
    /// `seq` order; out-of-order submissions trip
    /// [`WalExportError::AppendOnlyViolation`].
    ///
    /// The bytes parameter SHOULD be the postcard encoding of an L0
    /// `WalRecord`. F.3's bit-exact equality test verifies that
    /// streamed bytes match `Wal::serialize` record-section bytes
    /// without any field-order rewrite (DO NOT TOUCH #8).
    fn append_record(&mut self, record_bytes: &[u8]) -> Result<(), WalExportError>;

    /// Flush buffered records to the underlying durable storage.
    /// Returns `Ok(())` once the implementation's durability contract
    /// is satisfied (fsync completed, network ack received, etc.).
    /// Implementations are free to flush eagerly inside
    /// [`append_record`](Self::append_record) — `flush` then becomes
    /// a no-op.
    fn flush(&mut self) -> Result<(), WalExportError>;
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `STREAM_HEADER_MAGIC` is the 8-byte ASCII tag pinned at the
    /// start of every stream. Wire-stable for v0.12 — a value change
    /// is a wire-format break and requires a new magic value plus
    /// migration DIP, not silent reuse.
    #[test]
    fn stream_header_magic_is_arkhexp1() {
        assert_eq!(&STREAM_HEADER_MAGIC, b"ARKHEXP1");
    }

    /// DIP-N4 N4.7 — `StreamMagic::V1` byte mapping pinned at the
    /// F.3 wire-stability golden vector
    /// (`0x41 0x52 0x4B 0x48 0x45 0x58 0x50 0x31`). Drift between
    /// the enum dispatch and the legacy `STREAM_HEADER_MAGIC`
    /// constant trips this test — keeping the byte tag invariant
    /// across the cross-version refactor.
    #[test]
    fn stream_magic_v1_bytes_match_legacy_constant() {
        assert_eq!(StreamMagic::V1.bytes(), &STREAM_HEADER_MAGIC);
        assert_eq!(
            StreamMagic::V1.bytes(),
            &[0x41, 0x52, 0x4B, 0x48, 0x45, 0x58, 0x50, 0x31]
        );
    }

    /// DIP-N4 N4.7 — `StreamMagic::recognize` returns `Some(V1)` for
    /// the ARKHEXP1 byte tag and `None` for anything else. Sample
    /// `None` cases include an unallocated future version
    /// (`ARKHEXP2`) and an L0 WAL magic mistakenly fed to the export
    /// reader (`ARKHEWAL`) — both must reject without heap alloc.
    #[test]
    fn stream_magic_recognize_v1_and_rejects_unknown() {
        assert_eq!(StreamMagic::recognize(b"ARKHEXP1"), Some(StreamMagic::V1));
        // Unallocated future version (architectural placeholder, not yet
        // a supported variant).
        assert_eq!(StreamMagic::recognize(b"ARKHEXP2"), None);
        // L0 WAL magic — wrong transport, must reject.
        assert_eq!(StreamMagic::recognize(b"ARKHEWAL"), None);
        // Random eight bytes.
        assert_eq!(StreamMagic::recognize(b"\0\0\0\0\0\0\0\0"), None);
    }

    /// DIP-N4 N4.7 — `UnsupportedStreamVersion` Display surface
    /// distinguishable + carries the offending magic for operator
    /// triage.
    #[test]
    fn unsupported_stream_version_display_distinguishes_with_magic() {
        let err = WalExportError::UnsupportedStreamVersion {
            magic: *b"ARKHEXP2",
        };
        let msg = err.to_string();
        assert!(msg.contains("unsupported stream version"));
        assert!(msg.contains("not recognised"));
        // The offending magic appears in the message via Debug repr
        // so operators can pin the exact byte pattern.
        assert!(msg.contains("65")); // 0x41 is 'A' = 65 in decimal Debug
    }

    /// `STREAM_HEADER_MAGIC` distinct from L0 `WalHeader::MAGIC`
    /// (`ARKHEWAL`) — separate transport format, separate magic.
    #[test]
    fn stream_header_magic_distinct_from_l0_wal_magic() {
        assert_ne!(
            &STREAM_HEADER_MAGIC,
            &arkhe_kernel::persist::WalHeader::MAGIC
        );
    }

    /// `MAX_RECORD_BYTES` pinned at 16 MiB (fail-secure, ~256× typical
    /// record size). Bound short-circuits attacker-supplied length-
    /// prefix overflow + memory-DoS before any deref attempt.
    /// Tightened from the initial 1 GiB proposal per cryptographer
    /// fail-secure pattern (DIP-N1 C8 hook fuel budget mirror).
    #[test]
    fn max_record_bytes_is_sixteen_mib() {
        assert_eq!(MAX_RECORD_BYTES, 1 << 24);
        assert_eq!(MAX_RECORD_BYTES, 16_777_216);
    }

    /// `WalExportError` implements `Display` + `Error` + `Send + Sync`
    /// — standard error-type expectations. `Send + Sync` lets the
    /// error cross thread / async boundaries when sinks operate
    /// off-runtime-thread.
    #[test]
    fn wal_export_error_implements_standard_error_traits() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_error<T: std::error::Error>() {}
        assert_send_sync::<WalExportError>();
        assert_error::<WalExportError>();
        assert_send_sync::<InvalidFramingReason>();
        assert_error::<InvalidFramingReason>();
    }

    /// Display surface — each variant produces a non-empty
    /// distinguishable message. The exact strings are operator-facing
    /// log lines, not part of the wire protocol; F.3 does not verify
    /// them bit-exact.
    #[test]
    fn wal_export_error_display_is_distinguishable() {
        let io_err = WalExportError::Io(std::io::Error::other("test"));
        let framing_err = WalExportError::InvalidFraming(InvalidFramingReason::LengthZero);
        let append_err = WalExportError::AppendOnlyViolation {
            expected_seq: 5,
            got_seq: 3,
            previous_seq: Some(4),
        };
        let exhausted_err = WalExportError::SeqExhausted { last_seq: u64::MAX };
        let buf_err = WalExportError::BufferOverflow {
            capacity: 1024,
            requested: 2048,
            current_buffer: 768,
        };

        let io_msg = io_err.to_string();
        let framing_msg = framing_err.to_string();
        let append_msg = append_err.to_string();
        let exhausted_msg = exhausted_err.to_string();
        let buf_msg = buf_err.to_string();

        assert!(io_msg.contains("io"));
        assert!(framing_msg.contains("framing"));
        assert!(append_msg.contains("append-only"));
        assert!(append_msg.contains('5'));
        assert!(append_msg.contains('3'));
        assert!(append_msg.contains('4')); // previous_seq forensic
        assert!(exhausted_msg.contains("exhausted"));
        assert!(exhausted_msg.contains("rotate"));
        assert!(buf_msg.contains("buffer overflow"));
        assert!(buf_msg.contains("1024"));
        assert!(buf_msg.contains("2048"));
        assert!(buf_msg.contains("768")); // current_buffer forensic
    }

    /// DIP-N4 N4.5 — `AppendOnlyViolation` with `previous_seq: None`
    /// (fresh stream) renders a distinguishable Display string. The
    /// fresh-stream forensic case is what an operator hits when the
    /// caller submits a non-zero seq as the first record (e.g.,
    /// resuming a stream from a stale checkpoint).
    #[test]
    fn append_only_violation_fresh_stream_display_distinguishes_from_some_case() {
        let fresh = WalExportError::AppendOnlyViolation {
            expected_seq: 0,
            got_seq: 7,
            previous_seq: None,
        };
        let after = WalExportError::AppendOnlyViolation {
            expected_seq: 5,
            got_seq: 3,
            previous_seq: Some(4),
        };
        let fresh_msg = fresh.to_string();
        let after_msg = after.to_string();
        assert!(fresh_msg.contains("fresh stream"));
        assert!(fresh_msg.contains("no prior appends"));
        assert!(after_msg.contains("last appended"));
        assert!(after_msg.contains('4'));
        assert_ne!(fresh_msg, after_msg);
    }

    /// Each `InvalidFramingReason` variant produces a distinguishable
    /// Display message. Operators triage on these strings.
    #[test]
    fn invalid_framing_reason_display_is_distinguishable() {
        let exceeds = InvalidFramingReason::LengthExceedsMax {
            prefix: MAX_RECORD_BYTES + 1,
            max: MAX_RECORD_BYTES,
        };
        let zero = InvalidFramingReason::LengthZero;
        let trunc = InvalidFramingReason::Truncated;
        let hdr = InvalidFramingReason::HeaderMissing;

        assert!(exceeds.to_string().contains("exceeds maximum"));
        assert!(zero.to_string().contains("zero"));
        assert!(trunc.to_string().contains("truncated"));
        assert!(hdr.to_string().contains("ARKHEXP1"));
    }

    /// `WalExportError::source()` exposes the underlying `std::io::Error`
    /// when present so error-chain printers / observability hooks can
    /// drill down. Non-IO variants return `None`.
    #[test]
    fn wal_export_error_source_chains_through_io() {
        use std::error::Error;
        let io_err = WalExportError::Io(std::io::Error::other("test"));
        let framing_err = WalExportError::InvalidFraming(InvalidFramingReason::LengthZero);

        assert!(io_err.source().is_some());
        assert!(framing_err.source().is_none());
    }

    /// `From<std::io::Error>` — `?`-friendly conversion at concrete
    /// sink implementation sites (F.2 buffer + F.4 round-trip
    /// fixtures).
    #[test]
    fn from_io_error_lifts_to_wal_export_error() {
        let io_err = std::io::Error::other("test");
        let lifted: WalExportError = io_err.into();
        assert!(matches!(lifted, WalExportError::Io(_)));
    }

    /// No-op stub `WalRecordSink` impl — confirms the trait is
    /// satisfiable without seek / truncate. Concrete impl in F.2.
    /// Test asserts the trait's *method shape* alone.
    struct NoopSink;

    impl WalRecordSink for NoopSink {
        fn append_record(&mut self, _record_bytes: &[u8]) -> Result<(), WalExportError> {
            Ok(())
        }
        fn flush(&mut self) -> Result<(), WalExportError> {
            Ok(())
        }
    }

    /// Trait surface satisfiable without any positioning operation.
    /// If a future change to [`WalRecordSink`] adds a seek / truncate
    /// method, this test compiles trivially but its rationale
    /// docstring is the trip-wire for human review.
    #[test]
    fn wal_record_sink_satisfiable_without_seek() {
        let mut sink = NoopSink;
        sink.append_record(b"placeholder")
            .expect("noop sink succeeds");
        sink.flush().expect("noop flush");
    }
}
