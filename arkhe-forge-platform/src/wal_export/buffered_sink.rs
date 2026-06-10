//! `BufferedWalSink<W>` — concrete WAL streaming sink.
//!
//! Buffer-then-export pattern: encoded records accumulate in an
//! internal `Vec<u8>` until the caller invokes
//! [`WalRecordSink::flush`], which delegates to the underlying
//! `std::io::Write`r and clears the buffer. Operator-side durable
//! storage policy (fsync, network ack, replication) is delegated to
//! `W::flush` per the same trait contract.
//!
//! # Sink as the unique write path
//!
//! Module-level invariant: **`BufferedWalSink` is the sole `pub` write
//! path between the L1+L2 Runtime and operator-managed durable
//! storage**. The sink:
//!
//! - exposes neither `Seek` nor any inherent positioning method —
//!   compile-time `static_assertions::assert_not_impl_any!` enforces
//!   the absence of `std::io::Seek`. Adding a `Seek` impl in a future
//!   change fails to compile.
//! - keeps its internal cursor (`buffer` + `last_seq` + `header_emitted`)
//!   private. `pub` API is the [`WalRecordSink`] trait alone +
//!   [`BufferedWalSink::new`] / [`BufferedWalSink::with_capacity`]
//!   constructors. No `seek_to`, no `truncate_buffer`, no `rewind`.
//!
//! # A14 append-only invariant — runtime-side enforcement
//!
//! [`append_record`](BufferedWalSink::append_record) takes the record's
//! kind-agnostic monotonic `seq` as an explicit argument and rejects
//! out-of-order submissions with
//! [`WalExportError::AppendOnlyViolation`]. Production callers read the
//! seq through the typed `arkhe_kernel::WalRecord::seq()` accessor (see
//! `wal_to_sink`), so the coupling to the L0 record schema is
//! compiler-checked — the sink itself never parses payload bytes and is
//! agnostic to the kernel's kind-discriminated `Submit`/`Step` layout.
//!
//! Initial seq is learned from the first `append_record` call (callers
//! may stream from any record position; the sink does not require
//! seq-1 as its baseline). Subsequent records must carry
//! `seq == previous + 1`.
//!
//! # u64 seq wraparound — fail-secure reject
//!
//! `previous.checked_add(1)` returns `None` at `u64::MAX` →
//! [`WalExportError::SeqExhausted`] explicit reject. Practical impact
//! ≈ zero (1M ops/sec ≈ 584942 years to overflow), but the check
//! closes the structural gap rather than relying on the L0
//! `saturating_add` masking the boundary.
//!
//! # Stream framing (firm requirements #1 + #3)
//!
//! - First write to the buffer pins
//!   [`super::STREAM_HEADER_MAGIC`] (`ARKHEXP1`) at the stream start.
//! - Each subsequent record is framed as `[u64 BE length prefix][payload]`.
//! - Length is bounded by [`super::MAX_RECORD_BYTES`] (16 MiB
//!   fail-secure ceiling).

use std::io::Write;

use super::{InvalidFramingReason, StreamMagic, WalExportError, WalRecordSink, MAX_RECORD_BYTES};
// `STREAM_HEADER_MAGIC` is referenced only from test fixtures (the
// production path goes through `StreamMagic::V1.bytes()`). Cfg-gating
// keeps the lib build warning-free without hiding the import behind
// `#[allow]`.
#[cfg(test)]
use super::STREAM_HEADER_MAGIC;

/// Concrete sink implementing the buffer-then-export pattern over an
/// arbitrary `std::io::Write`r.
///
/// Typical instantiations:
///
/// - `BufferedWalSink<std::fs::File>` — durable backup file (operator
///   chooses the fsync policy on the inner file).
/// - `BufferedWalSink<Vec<u8>>` — in-memory testing / round-trip
///   fixtures.
///
/// The struct is `pub` but its fields are private — the only mutation
/// path runs through the [`WalRecordSink`] trait methods (and the
/// inherent constructors). This is the runtime-side companion to the
/// trait-level append-only invariant.
pub struct BufferedWalSink<W: Write> {
    writer: W,
    /// Buffered framing bytes pending [`flush`](WalRecordSink::flush).
    /// Includes the stream header (emitted at first append) and one
    /// `[u64 BE length prefix][payload]` block per record.
    buffer: Vec<u8>,
    /// Maximum bytes the buffer may hold between flushes. Defaults to
    /// [`Self::DEFAULT_CAPACITY`] (`MAX_RECORD_BYTES` + 16-byte framing
    /// reserve).
    capacity: usize,
    /// `false` until the first `append_record` writes
    /// [`STREAM_HEADER_MAGIC`] into the buffer; `true` thereafter.
    header_emitted: bool,
    /// Most recently appended record's `seq`, or `None` for a fresh
    /// stream. The first `append_record` learns the baseline; later
    /// records must satisfy `seq == prev + 1` or trip
    /// [`WalExportError::AppendOnlyViolation`].
    last_seq: Option<u64>,
}

// Compile-time invariant: BufferedWalSink does NOT implement
// `std::io::Seek`. Adding a `Seek` impl in a future change fails
// compilation here, surfacing the trait-level append-only invariant
// violation BEFORE merge.
//
// Coverage shape (std-only zero-new-dep posture):
//
// 1. `Vec<u8>` — the in-memory buffer typically used in tests.
// 2. `std::fs::File` — the file-backed sink typically used in
//    production backup pipelines. `File` itself implements `Seek`,
//    so a careless `impl Seek for BufferedWalSink<W>` (delegating to
//    the inner writer) would compile for `File` but not `Vec<u8>`;
//    covering both pins the invariant for the realistic deployment
//    shapes.
// 3. `&mut Vec<u8>` — the borrow-form of in-memory buffer used by
//    callers that own the underlying allocation elsewhere; closes
//    the auto-trait-leakage path where a borrow's `Seek` could
//    differ from the owned type's.
// 4. `std::io::BufWriter<Vec<u8>>` — the buffered-writer wrapper
//    commonly used to amortise small writes; the wrapper does NOT
//    implement `Seek` itself but the assertion pins the invariant
//    against any future stdlib auto-impl change.
// 5. `std::io::Cursor<Vec<u8>>` — the cursor wrapper commonly used
//    in test fixtures; `Cursor<Vec<u8>>` implements `Seek` (unlike
//    bare `Vec<u8>`), so a careless `impl Seek for BufferedWalSink<W>`
//    delegating to inner would compile here, making this the
//    strictest of the five assertions.
//
// Async wrappers (`tokio::fs::File`, `async_std::fs::File`,
// `tokio::io::AsyncSeek`) intentionally NOT covered: the Runtime is
// sync-only, and adding tokio/async-std as dev-deps purely for
// compile-time guards = bloat. An async expansion would add the
// corresponding assertions alongside the async surface.
static_assertions::assert_not_impl_any!(BufferedWalSink<Vec<u8>>: std::io::Seek);
static_assertions::assert_not_impl_any!(BufferedWalSink<std::fs::File>: std::io::Seek);
static_assertions::assert_not_impl_any!(BufferedWalSink<&mut Vec<u8>>: std::io::Seek);
static_assertions::assert_not_impl_any!(BufferedWalSink<std::io::BufWriter<Vec<u8>>>: std::io::Seek);
static_assertions::assert_not_impl_any!(BufferedWalSink<std::io::Cursor<Vec<u8>>>: std::io::Seek);

impl<W: Write> BufferedWalSink<W> {
    /// Default in-memory buffer capacity — the absolute hard ceiling on
    /// a single record ([`MAX_RECORD_BYTES`], 16 MiB) plus the 16-byte
    /// framing overhead (8-byte stream header + 8-byte length prefix),
    /// so a maximum-size legal record always fits a fresh sink.
    /// Operators with tighter memory constraints can pin a smaller
    /// buffer via [`with_capacity`](Self::with_capacity).
    pub const DEFAULT_CAPACITY: usize = (MAX_RECORD_BYTES as usize) + 16;

    /// Construct a sink with [`DEFAULT_CAPACITY`](Self::DEFAULT_CAPACITY).
    pub fn new(writer: W) -> Self {
        Self::with_capacity(writer, Self::DEFAULT_CAPACITY)
    }

    /// Construct a sink with a custom buffer capacity. Once the
    /// buffered bytes (including the header and all framed records)
    /// would exceed `capacity` on a new append,
    /// [`WalExportError::BufferOverflow`] is returned and the caller
    /// MUST flush to drain.
    pub fn with_capacity(writer: W, capacity: usize) -> Self {
        Self {
            writer,
            buffer: Vec::new(),
            capacity,
            header_emitted: false,
            last_seq: None,
        }
    }

    /// Validate the length prefix (firm requirement #2 — bounds-check
    /// before any deref of payload bytes). Returns the validated
    /// length on success.
    fn validate_length(record_bytes: &[u8]) -> Result<u64, WalExportError> {
        let len = record_bytes.len() as u64;
        if len == 0 {
            return Err(WalExportError::InvalidFraming(
                InvalidFramingReason::LengthZero,
            ));
        }
        if len > MAX_RECORD_BYTES {
            return Err(WalExportError::InvalidFraming(
                InvalidFramingReason::LengthExceedsMax {
                    prefix: len,
                    max: MAX_RECORD_BYTES,
                },
            ));
        }
        Ok(len)
    }

    /// Pin the [`StreamMagic::V1`] tag at the start of the buffer if
    /// not yet emitted. Idempotent — subsequent calls are no-ops once
    /// `header_emitted` is `true`.
    ///
    /// Uses [`StreamMagic::V1`] dispatch for forward-compat: a future
    /// writer wanting `V2` would call [`StreamMagic::V2.bytes()`] here
    /// without touching the rest of the buffered-sink machinery. The
    /// byte pattern is identical to [`STREAM_HEADER_MAGIC`]
    /// (wire-stability invariant pinned by the wire-stability golden
    /// vector).
    fn ensure_header(&mut self) {
        if !self.header_emitted {
            self.buffer.extend_from_slice(StreamMagic::V1.bytes());
            self.header_emitted = true;
        }
    }

    /// Test-only accessor: extract the inner writer post-flush.
    ///
    /// **Not part of the public surface** — `pub(crate)` + `#[cfg(test)]`
    /// gated. Used by wire-stability tests in the sibling
    /// `wire_stability` module to inspect the post-flush byte stream.
    /// Production code path should never see this method.
    #[cfg(test)]
    pub(crate) fn into_writer_for_test(self) -> W {
        self.writer
    }
}

impl<W: Write> WalRecordSink for BufferedWalSink<W> {
    fn append_record(&mut self, seq: u64, record_bytes: &[u8]) -> Result<(), WalExportError> {
        // Step 1: validate length BEFORE any deref of payload bytes.
        let len = Self::validate_length(record_bytes)?;

        // Step 2: verify append-only ordering on the declared seq.
        if let Some(prev) = self.last_seq {
            // u64::MAX wraparound: `checked_add(1)` returns None →
            // explicit fail-secure via dedicated `SeqExhausted`
            // variant — distinct from append-only violation since
            // this signals an intrinsic limit, not a caller ordering
            // error.
            let expected = match prev.checked_add(1) {
                Some(e) => e,
                None => return Err(WalExportError::SeqExhausted { last_seq: prev }),
            };
            if seq != expected {
                return Err(WalExportError::AppendOnlyViolation {
                    expected_seq: expected,
                    got_seq: seq,
                    previous_seq: Some(prev),
                });
            }
        }
        // Fresh stream (`self.last_seq == None`) — any seq is
        // accepted as the first record's anchor. This preserves
        // round-trip pipeline compatibility where streams may resume
        // from arbitrary L0 WAL anchor points (kernel-emitted seqs
        // start at 1, not 0). The forensic surface is preserved by
        // `AppendOnlyViolation { previous_seq: None }` if a later
        // record breaks monotonicity from this anchor.

        // Step 3: emit stream header at first append.
        self.ensure_header();

        // Step 4: enforce buffer capacity (8-byte BE length prefix +
        // payload).
        let frame_size = 8 + len as usize;
        let current_buffer = self.buffer.len();
        if current_buffer.saturating_add(frame_size) > self.capacity {
            return Err(WalExportError::BufferOverflow {
                capacity: self.capacity,
                requested: frame_size,
                current_buffer,
            });
        }

        // Step 5: append framed record (firm requirement #1 — u64 BE
        // length prefix; firm requirement #3 — header pinned at
        // stream start in step 3).
        self.buffer.extend_from_slice(&len.to_be_bytes());
        self.buffer.extend_from_slice(record_bytes);

        // Step 6: pin the new seq so the next call enforces
        // monotonicity against it.
        self.last_seq = Some(seq);

        Ok(())
    }

    fn flush(&mut self) -> Result<(), WalExportError> {
        // Firm requirement #3: every flushed export stream begins with
        // the header magic — emit it even when no record was appended,
        // so an empty WAL round-trips as a valid header-only stream
        // (the reader yields zero records) instead of a 0-byte file the
        // reader rejects as HeaderMissing.
        self.ensure_header();
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.writer.write_all(&self.buffer)?;
        // Delegate the operator-side durability contract to the
        // underlying writer (fsync / network ack / replication / ...).
        self.writer.flush()?;
        self.buffer.clear();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Synthesise an opaque record payload of `len` deterministic
    /// bytes. The sink never parses payload contents — the append-only
    /// check runs on the explicitly passed `seq` — so any byte pattern
    /// exercises the contract. The `round_trip_tests` module covers the
    /// real-WAL round-trip end-to-end (Kernel-driven WAL bytes).
    fn synth_record(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Fresh sink — empty buffer, no header, no seq baseline.
    #[test]
    fn fresh_sink_initial_state() {
        let sink = BufferedWalSink::new(Vec::<u8>::new());
        assert!(sink.buffer.is_empty());
        assert!(!sink.header_emitted);
        assert!(sink.last_seq.is_none());
    }

    /// `with_capacity` honours the operator-supplied capacity.
    #[test]
    fn with_capacity_pins_buffer_capacity() {
        let sink = BufferedWalSink::with_capacity(Vec::<u8>::new(), 1024);
        assert_eq!(sink.capacity, 1024);
    }

    /// First `append_record` emits the stream header + frames the
    /// record + pins the baseline seq.
    #[test]
    fn first_append_emits_header_and_pins_seq() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(1, &record).expect("first append OK");
        assert!(sink.header_emitted);
        assert_eq!(sink.last_seq, Some(1));
        // Buffer = magic (8) + length prefix (8) + record bytes.
        assert!(sink.buffer.starts_with(&STREAM_HEADER_MAGIC));
    }

    /// Multi-record append in monotone-increasing seq order succeeds.
    #[test]
    fn multi_record_append_in_order_succeeds() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        for seq in 1..=5 {
            sink.append_record(seq, &record)
                .unwrap_or_else(|e| panic!("append seq {seq} failed: {e}"));
        }
        assert_eq!(sink.last_seq, Some(5));
    }

    /// A fresh stream accepts any anchor seq (resume from an arbitrary
    /// L0 WAL position) and then enforces strict succession from it.
    #[test]
    fn fresh_stream_accepts_arbitrary_anchor_then_enforces_succession() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(41, &record).expect("anchor seq OK");
        let result = sink.append_record(43, &record);
        assert!(matches!(
            result,
            Err(WalExportError::AppendOnlyViolation {
                expected_seq: 42,
                got_seq: 43,
                previous_seq: Some(41),
            })
        ));
    }

    /// Out-of-sequence seq trips `AppendOnlyViolation` — verifies
    /// the `previous_seq: Some(prev)` forensic field.
    #[test]
    fn out_of_order_seq_rejected_with_append_only_violation() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(1, &record).expect("seq 1 OK");
        // Skip seq 2; submit seq 3 — should reject.
        let result = sink.append_record(3, &record);
        match result {
            Err(WalExportError::AppendOnlyViolation {
                expected_seq,
                got_seq,
                previous_seq,
            }) => {
                assert_eq!(expected_seq, 2);
                assert_eq!(got_seq, 3);
                assert_eq!(previous_seq, Some(1));
            }
            other => panic!("expected AppendOnlyViolation, got: {other:?}"),
        }
    }

    /// Re-submitting the same seq trips `AppendOnlyViolation`
    /// (replay attack defence) — verifies forensic `previous_seq`
    /// reflects the current high-water mark.
    #[test]
    fn duplicate_seq_rejected_with_append_only_violation() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(1, &record).expect("seq 1 OK");
        let result = sink.append_record(1, &record);
        assert!(matches!(
            result,
            Err(WalExportError::AppendOnlyViolation {
                expected_seq: 2,
                got_seq: 1,
                previous_seq: Some(1),
            })
        ));
    }

    /// Empty record rejected with `LengthZero`.
    #[test]
    fn empty_record_rejected_with_length_zero() {
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        let result = sink.append_record(1, &[]);
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::LengthZero
            ))
        ));
    }

    /// Buffer overflow: append records until the configured small
    /// capacity is exceeded → `BufferOverflow` — verifies the
    /// `current_buffer` forensic field reports the bytes already in
    /// the buffer at overflow time (the predicate `current_buffer +
    /// requested > capacity` is what triggers).
    #[test]
    fn buffer_overflow_rejected_with_capacity() {
        let record = synth_record(17);
        // Capacity just enough for the header + one record's frame.
        let single_frame = 8 + record.len();
        let cap = STREAM_HEADER_MAGIC.len() + single_frame;
        let mut sink = BufferedWalSink::with_capacity(Vec::<u8>::new(), cap);
        sink.append_record(1, &record).expect("first record fits");
        let result = sink.append_record(2, &record);
        match result {
            Err(WalExportError::BufferOverflow {
                capacity,
                requested,
                current_buffer,
            }) => {
                assert_eq!(capacity, cap);
                assert_eq!(requested, 8 + record.len());
                // Buffer holds magic + first record's full frame at
                // overflow check time.
                assert_eq!(current_buffer, STREAM_HEADER_MAGIC.len() + single_frame);
                // Sanity: predicate that triggered.
                assert!(current_buffer + requested > capacity);
            }
            other => panic!("expected BufferOverflow, got: {other:?}"),
        }
    }

    /// `flush` writes the buffered framing bytes to the underlying
    /// writer and clears the buffer.
    #[test]
    fn flush_writes_buffer_to_writer_and_clears() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        for seq in 1..=3 {
            sink.append_record(seq, &record).expect("append OK");
        }
        let buffered_len = sink.buffer.len();
        sink.flush().expect("flush OK");
        assert!(sink.buffer.is_empty(), "buffer cleared after flush");
        assert_eq!(
            sink.writer.len(),
            buffered_len,
            "writer received the buffered bytes verbatim"
        );
        assert!(sink.writer.starts_with(&STREAM_HEADER_MAGIC));
    }

    /// `flush` on a record-less sink emits a header-only stream — an
    /// empty WAL exports as a valid self-describing stream (firm
    /// requirement #3) that the reader opens and reads as zero records.
    /// A second flush adds nothing.
    #[test]
    fn empty_flush_emits_header_only_stream() {
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.flush().expect("empty flush OK");
        assert_eq!(sink.writer, STREAM_HEADER_MAGIC.to_vec());
        assert!(sink.header_emitted);
        sink.flush().expect("second empty flush OK");
        assert_eq!(sink.writer, STREAM_HEADER_MAGIC.to_vec());
    }

    /// `DEFAULT_CAPACITY` reserves the 16-byte framing overhead above
    /// the per-record ceiling so a maximum-size legal record fits a
    /// fresh sink (8-byte header + 8-byte length prefix +
    /// `MAX_RECORD_BYTES` payload).
    #[test]
    fn default_capacity_admits_a_max_size_record_frame() {
        assert_eq!(
            BufferedWalSink::<Vec<u8>>::DEFAULT_CAPACITY,
            (MAX_RECORD_BYTES as usize) + 8 + 8
        );
    }

    /// Double `flush` after appends — second flush is a no-op.
    #[test]
    fn double_flush_is_idempotent() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(1, &record).expect("append OK");
        sink.append_record(2, &record).expect("append OK");
        sink.flush().expect("first flush OK");
        let writer_len_after_first = sink.writer.len();
        sink.flush().expect("second flush OK");
        assert_eq!(
            sink.writer.len(),
            writer_len_after_first,
            "second flush is a no-op"
        );
    }

    /// Stream header is emitted exactly once across multiple appends.
    #[test]
    fn header_emitted_exactly_once() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        for seq in 1..=3 {
            sink.append_record(seq, &record).expect("append OK");
        }
        // Count occurrences of the magic bytes in the buffer.
        let count = sink
            .buffer
            .windows(STREAM_HEADER_MAGIC.len())
            .filter(|w| *w == STREAM_HEADER_MAGIC)
            .count();
        assert_eq!(count, 1, "header magic appears exactly once");
    }

    /// `last_seq` at `u64::MAX` rejects any further append via the
    /// dedicated `SeqExhausted` variant — distinct from
    /// `AppendOnlyViolation` because this is an intrinsic limit, not
    /// a caller ordering error. Architecturally unreachable on any
    /// real-world stream, but the structural reject must hold.
    #[test]
    fn seq_wraparound_at_u64_max_rejected_with_seq_exhausted() {
        let record = synth_record(17);
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        // Manually pin the boundary state — there is no public API to
        // reach u64::MAX in production (saturating_add caps in L0),
        // but the structural reject must hold.
        sink.last_seq = Some(u64::MAX);
        sink.header_emitted = true; // already-active stream
        let result = sink.append_record(0, &record);
        match result {
            Err(WalExportError::SeqExhausted { last_seq }) => {
                assert_eq!(last_seq, u64::MAX);
            }
            other => panic!("expected SeqExhausted, got: {other:?}"),
        }
    }

    /// Length validation rejects records exactly at `MAX_RECORD_BYTES + 1`.
    /// We construct a synthetic byte slice of that exact length —
    /// postcard parse will fail before length check, so we exercise
    /// the boundary via a smaller config. Demonstration kept small
    /// (allocating 16 MiB+1 in tests is wasteful); the
    /// `round_trip_tests` module covers the real-world boundary in
    /// integration.
    #[test]
    fn length_exceeds_max_rejected() {
        // Synthesize a max-length+1 byte slice using a small-cap sink
        // so the rejection path triggers without the 16 MiB alloc.
        // We directly call validate_length with a faked length via a
        // matching-size slice: not feasible at 16 MiB, so we test
        // the validate_length helper at a small synthetic boundary.
        let oversized = vec![0u8; (MAX_RECORD_BYTES + 1) as usize];
        let result = BufferedWalSink::<Vec<u8>>::validate_length(&oversized);
        match result {
            Err(WalExportError::InvalidFraming(InvalidFramingReason::LengthExceedsMax {
                prefix,
                max,
            })) => {
                assert_eq!(prefix, MAX_RECORD_BYTES + 1);
                assert_eq!(max, MAX_RECORD_BYTES);
            }
            other => panic!("expected LengthExceedsMax, got: {other:?}"),
        }
    }

    /// The sink is payload-agnostic: bytes that do not decode as any
    /// postcard shape are framed verbatim — only the declared seq and
    /// the length bounds gate an append.
    #[test]
    fn append_record_frames_arbitrary_payload_bytes_verbatim() {
        // 0xFF repeated is an unterminated postcard varint — under the
        // old payload-parsing design this was rejected; the framing
        // layer now passes it through untouched.
        let record = vec![0xFFu8; 9];
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(1, &record).expect("opaque payload OK");
        sink.flush().expect("flush OK");
        let frame_start = STREAM_HEADER_MAGIC.len() + 8;
        assert_eq!(
            &sink.writer[frame_start..frame_start + record.len()],
            record.as_slice(),
            "payload bytes pass through bit-exact"
        );
    }
}
