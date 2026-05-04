//! `WalStreamReader` — production reader-side surface.
//!
//! Consumes the byte stream produced by [`super::BufferedWalSink`] (or
//! any `[u64 BE length prefix][payload]`-framed sequence beginning
//! with a recognised [`StreamMagic`] tag) and yields per-record
//! payload borrows. The complement to the writer-side
//! [`super::BufferedWalSink`].
//!
//! # Streaming-iterator pattern
//!
//! `WalStreamReader::next_record` returns `Option<&[u8]>` where the
//! borrow is tied to `&mut self` — the slice is valid until the next
//! call mutates the internal buffer. Callers decode the borrowed
//! payload (typically via `postcard::from_bytes::<WalRecord>`) inside
//! the loop iteration and must not retain the slice across iterations.
//! This avoids the per-record allocation that an owned `Vec<u8>`
//! return would force, at the cost of giving up `std::iter::Iterator`
//! (whose lifetime contract precludes the borrow tie).
//!
//! # Fail-secure framing posture
//!
//! Five reject paths cover the framing surface:
//!
//! 1. **Unknown magic** at stream open → [`WalExportError::UnsupportedStreamVersion`].
//!    Stack-only 8-byte read, no heap alloc pre-rejection (fail-fast).
//! 2. **Truncated header** (fewer than 8 bytes) at open →
//!    [`InvalidFramingReason::HeaderMissing`] via `Truncated` mapping.
//! 3. **Length prefix exceeds bound** → [`InvalidFramingReason::LengthExceedsMax`]
//!    rejection BEFORE allocating the payload buffer (16 MiB
//!    fail-secure ceiling).
//! 4. **Length prefix zero** → [`InvalidFramingReason::LengthZero`].
//! 5. **Premature EOF mid-record** (length prefix complete but
//!    payload short) → [`InvalidFramingReason::Truncated`].
//!
//! Clean EOF (zero bytes available at the start of the next record)
//! returns `Ok(None)` — distinguishable from torn headers via a
//! single-byte probe before committing to the full 8-byte read.
//!
//! # Bridge to integration round-trip tests
//!
//! The sibling `round_trip_tests` module's `parse_stream` test helper
//! duplicates the framing logic to keep that module independent of
//! this reader API; this module hosts the production-grade equivalent
//! for non-test callers.

use std::io::{ErrorKind, Read};

use super::{InvalidFramingReason, StreamMagic, WalExportError, MAX_RECORD_BYTES};

/// Reader-side trait — `next_record` plus `cumulative_position`.
///
/// The `next_record` lifetime tie (`&mut self` borrow → `&[u8]`
/// borrow on the return) makes this trait a *streaming iterator*
/// rather than a `std::iter::Iterator`. Callers iterate via:
///
/// ```ignore
/// while let Some(payload) = reader.next_record()? {
///     // decode `payload` here; the slice expires next iteration
/// }
/// ```
pub trait WalStreamReader {
    /// Read the next record's payload bytes.
    ///
    /// Returns:
    /// - `Ok(Some(payload))` — a borrow into the reader's internal
    ///   buffer, valid until the next call.
    /// - `Ok(None)` — clean EOF, no more records.
    /// - `Err(WalExportError::InvalidFraming(...))` — framing reject
    ///   per the five fail-secure paths documented above.
    /// - `Err(WalExportError::Io(...))` — underlying I/O failure.
    fn next_record(&mut self) -> Result<Option<&[u8]>, WalExportError>;

    /// Cumulative byte count consumed from the underlying reader,
    /// including the 8-byte stream header magic + each record's
    /// `[8 byte length prefix][payload]` frame. Useful for forensic
    /// "where did the parse fail" reporting and for operator metrics
    /// (bytes-processed throughput).
    fn cumulative_position(&self) -> u64;
}

/// Concrete `WalStreamReader` impl over an arbitrary `std::io::Read`.
///
/// Typical instantiations:
/// - `StreamingWalReader<std::fs::File>` — on-disk archive reader
/// - `StreamingWalReader<&[u8]>` — in-memory test fixture (the common
///   case in this module's own test suite)
#[derive(Debug)]
pub struct StreamingWalReader<R: Read> {
    reader: R,
    /// Internal buffer reused across `next_record` calls. Sized up
    /// to fit each record's payload; capacity grows monotonically
    /// (no shrink) so steady-state throughput avoids reallocation
    /// once the largest record so far has been seen.
    buffer: Vec<u8>,
    /// Cumulative bytes consumed from `reader`.
    cumulative_pos: u64,
    /// The recognised stream magic (always `V1` currently; future
    /// versions add variants without breaking the reader's frame
    /// loop, which is version-agnostic at the framing layer).
    magic: StreamMagic,
}

impl<R: Read> StreamingWalReader<R> {
    /// Open a reader by consuming + dispatching the 8-byte stream
    /// header magic.
    ///
    /// **Fail-fast posture**: the 8-byte header is read into a stack
    /// array; an unrecognised magic yields
    /// [`WalExportError::UnsupportedStreamVersion`] with no heap
    /// allocation pre-rejection. A truncated header (fewer than 8
    /// bytes) yields [`InvalidFramingReason::HeaderMissing`].
    pub fn open_v1(mut reader: R) -> Result<Self, WalExportError> {
        let mut magic_bytes = [0u8; 8];
        match reader.read_exact(&mut magic_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Err(WalExportError::InvalidFraming(
                    InvalidFramingReason::HeaderMissing,
                ));
            }
            Err(e) => return Err(WalExportError::Io(e)),
        }
        let magic = StreamMagic::recognize(&magic_bytes)
            .ok_or(WalExportError::UnsupportedStreamVersion { magic: magic_bytes })?;
        Ok(Self {
            reader,
            buffer: Vec::new(),
            cumulative_pos: 8,
            magic,
        })
    }

    /// Recognised stream magic version. Currently always
    /// [`StreamMagic::V1`].
    #[must_use]
    pub fn magic(&self) -> StreamMagic {
        self.magic
    }
}

impl<R: Read> WalStreamReader for StreamingWalReader<R> {
    fn next_record(&mut self) -> Result<Option<&[u8]>, WalExportError> {
        // Step 1: probe one byte to distinguish clean EOF (Ok(0))
        // from a torn length prefix (UnexpectedEof on the remaining
        // 7 bytes). `read_exact` would conflate the two.
        let mut first_byte = [0u8; 1];
        let n = self
            .reader
            .read(&mut first_byte)
            .map_err(WalExportError::Io)?;
        if n == 0 {
            return Ok(None);
        }

        // Step 2: read the remaining 7 bytes of the length prefix.
        // A short read here = torn frame = `Truncated`.
        let mut rest = [0u8; 7];
        self.reader.read_exact(&mut rest).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                WalExportError::InvalidFraming(InvalidFramingReason::Truncated)
            } else {
                WalExportError::Io(e)
            }
        })?;

        // Step 3: assemble + validate the length.
        let mut len_bytes = [0u8; 8];
        len_bytes[0] = first_byte[0];
        len_bytes[1..].copy_from_slice(&rest);
        let len = u64::from_be_bytes(len_bytes);
        self.cumulative_pos += 8;

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

        // Step 4: read the payload BEFORE returning a borrow.
        // `len` already validated above so the `as usize` is safe on
        // any 64-bit (or smaller) platform: 16 MiB fits in usize on
        // every supported target.
        self.buffer.resize(len as usize, 0);
        self.reader.read_exact(&mut self.buffer).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                WalExportError::InvalidFraming(InvalidFramingReason::Truncated)
            } else {
                WalExportError::Io(e)
            }
        })?;
        self.cumulative_pos += len;

        Ok(Some(&self.buffer))
    }

    fn cumulative_position(&self) -> u64 {
        self.cumulative_pos
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::buffered_sink::BufferedWalSink;
    use super::super::{InvalidFramingReason, StreamMagic, WalExportError, WalRecordSink};
    use super::*;
    use std::io::Cursor;

    /// Build a synthetic record: postcard-encoded `seq: u64` followed
    /// by `padding` zero bytes. Mirrors the `synth_record` helper in
    /// `buffered_sink.rs` tests.
    fn synth_record(seq: u64, padding: usize) -> Vec<u8> {
        let mut bytes = postcard::to_stdvec(&seq).unwrap();
        bytes.extend(std::iter::repeat_n(0u8, padding));
        bytes
    }

    /// Encode `n` records via `BufferedWalSink<Vec<u8>>` and return the
    /// flushed byte stream.
    fn build_stream(n: u64) -> Vec<u8> {
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        for i in 0..n {
            let rec = synth_record(i, 4);
            sink.append_record(&rec).expect("append OK");
        }
        sink.flush().expect("flush OK");
        sink.into_writer_for_test()
    }

    /// Round-trip: writer-emitted stream parses back to the original
    /// record sequence via `StreamingWalReader::open_v1` +
    /// `next_record`.
    #[test]
    fn writer_to_reader_round_trip_three_records() {
        let stream = build_stream(3);
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");
        assert_eq!(reader.magic(), StreamMagic::V1);

        let mut decoded_seqs = Vec::new();
        while let Some(payload) = reader.next_record().expect("next OK") {
            let seq: u64 = postcard::from_bytes(payload).expect("postcard OK");
            decoded_seqs.push(seq);
        }
        assert_eq!(decoded_seqs, vec![0, 1, 2]);
        // Header + 3 frames each = (8 + N) bytes.
        let header_len = 8u64;
        let per_record_len = 8 + synth_record(0, 4).len() as u64;
        assert_eq!(
            reader.cumulative_position(),
            header_len + 3 * per_record_len
        );
    }

    /// `open_v1` on an empty stream returns `HeaderMissing` —
    /// 0-byte input cannot satisfy the 8-byte magic read.
    #[test]
    fn open_v1_empty_stream_rejected_with_header_missing() {
        let result = StreamingWalReader::open_v1(Cursor::new(Vec::<u8>::new()));
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::HeaderMissing
            ))
        ));
    }

    /// `open_v1` on a 7-byte truncated header returns `HeaderMissing`.
    #[test]
    fn open_v1_truncated_header_rejected_with_header_missing() {
        let truncated: &[u8] = b"ARKHEXP"; // 7 bytes, missing trailing '1'
        let result = StreamingWalReader::open_v1(Cursor::new(truncated));
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::HeaderMissing
            ))
        ));
    }

    /// `open_v1` on an unrecognised magic returns
    /// `UnsupportedStreamVersion` with the offending bytes carried.
    #[test]
    fn open_v1_unknown_magic_rejected_with_unsupported_version() {
        let unknown: &[u8] = b"ARKHEXP9"; // unrecognised version tag
        let result = StreamingWalReader::open_v1(Cursor::new(unknown));
        match result {
            Err(WalExportError::UnsupportedStreamVersion { magic }) => {
                assert_eq!(&magic, b"ARKHEXP9");
            }
            other => panic!("expected UnsupportedStreamVersion, got {other:?}"),
        }
    }

    /// L0 WAL magic (`ARKHEWAL`) misfed to the stream reader is
    /// rejected as `UnsupportedStreamVersion` (transport mismatch
    /// defence).
    #[test]
    fn open_v1_l0_wal_magic_rejected_with_unsupported_version() {
        let l0_magic = arkhe_kernel::persist::WalHeader::MAGIC;
        let result = StreamingWalReader::open_v1(Cursor::new(&l0_magic[..]));
        assert!(matches!(
            result,
            Err(WalExportError::UnsupportedStreamVersion { .. })
        ));
    }

    /// `next_record` on a stream with header but zero records returns
    /// `Ok(None)` — clean EOF.
    #[test]
    fn next_record_after_header_only_returns_none_clean_eof() {
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        // No appends; flush also a no-op since header is emitted only on
        // first append. So zero-record case = stream is just empty bytes.
        sink.flush().expect("flush OK");
        let stream = sink.into_writer_for_test();
        // Without any records, the stream has 0 bytes (header is
        // emitted only on first append). A reader cannot open it.
        // Build a *header-only* stream by appending and then truncating
        // back to the magic bytes.
        if !stream.is_empty() {
            // Defensive: should be empty in current sink semantics.
            return;
        }
        // Construct header-only stream manually.
        let mut hdr_only = Vec::new();
        hdr_only.extend_from_slice(StreamMagic::V1.bytes());
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&hdr_only)).expect("open OK");
        assert!(matches!(reader.next_record(), Ok(None)));
        assert_eq!(reader.cumulative_position(), 8);
    }

    /// Length prefix zero rejected with `LengthZero` (mid-stream).
    #[test]
    fn next_record_length_zero_rejected() {
        let mut stream = Vec::new();
        stream.extend_from_slice(StreamMagic::V1.bytes());
        stream.extend_from_slice(&0u64.to_be_bytes()); // explicit length-zero frame
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");
        assert!(matches!(
            reader.next_record(),
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::LengthZero
            ))
        ));
    }

    /// Length prefix exceeding `MAX_RECORD_BYTES` rejected with
    /// `LengthExceedsMax` (no payload alloc attempted — the bound
    /// check fires before `Vec::resize`).
    #[test]
    fn next_record_length_exceeds_max_rejected_pre_alloc() {
        let mut stream = Vec::new();
        stream.extend_from_slice(StreamMagic::V1.bytes());
        // 17 MiB length prefix — exceeds 16 MiB ceiling.
        let oversize = MAX_RECORD_BYTES + 1;
        stream.extend_from_slice(&oversize.to_be_bytes());
        // Note: NO payload bytes follow — the reader must reject on
        // length prefix alone, never reach `read_exact(&mut buffer)`.
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");
        match reader.next_record() {
            Err(WalExportError::InvalidFraming(InvalidFramingReason::LengthExceedsMax {
                prefix,
                max,
            })) => {
                assert_eq!(prefix, oversize);
                assert_eq!(max, MAX_RECORD_BYTES);
            }
            other => panic!("expected LengthExceedsMax, got {other:?}"),
        }
    }

    /// Truncated mid-length-prefix (4 of 8 bytes available) rejected
    /// with `Truncated`.
    #[test]
    fn next_record_truncated_mid_length_prefix_rejected() {
        let mut stream = Vec::new();
        stream.extend_from_slice(StreamMagic::V1.bytes());
        stream.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // only 4 of 8 length bytes
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");
        assert!(matches!(
            reader.next_record(),
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::Truncated
            ))
        ));
    }

    /// Truncated mid-payload (length says N bytes but only N-3
    /// available) rejected with `Truncated`.
    #[test]
    fn next_record_truncated_mid_payload_rejected() {
        let mut stream = Vec::new();
        stream.extend_from_slice(StreamMagic::V1.bytes());
        // Length prefix = 10 bytes; supply only 6.
        stream.extend_from_slice(&10u64.to_be_bytes());
        stream.extend_from_slice(&[0u8; 6]);
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");
        assert!(matches!(
            reader.next_record(),
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::Truncated
            ))
        ));
    }

    /// Reader resumes correctly across multiple successful records,
    /// and `cumulative_position` tracks total bytes consumed.
    #[test]
    fn cumulative_position_tracks_per_record_advance() {
        let stream = build_stream(2);
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");
        let header = 8u64;
        let frame = 8u64 + synth_record(0, 4).len() as u64;
        assert_eq!(reader.cumulative_position(), header);

        let _ = reader.next_record().expect("rec0").expect("Some");
        assert_eq!(reader.cumulative_position(), header + frame);

        let _ = reader.next_record().expect("rec1").expect("Some");
        assert_eq!(reader.cumulative_position(), header + 2 * frame);

        assert!(matches!(reader.next_record(), Ok(None)));
        assert_eq!(reader.cumulative_position(), header + 2 * frame);
    }

    /// Multiple sequential `next_record` calls correctly invalidate
    /// the previous borrow: each call returns a fresh slice into the
    /// reused internal buffer. (Compile-fail behaviour around
    /// retaining an old borrow across a call is the point of the
    /// streaming-iterator pattern; this test exercises the runtime
    /// behaviour.)
    #[test]
    fn next_record_borrow_refreshes_on_each_call() {
        let stream = build_stream(3);
        let mut reader = StreamingWalReader::open_v1(Cursor::new(&stream)).expect("open OK");

        // Iterate; each call replaces the buffer contents with the new
        // record's payload. We capture decoded values into owned data
        // (Vec<u64>) to release the borrow before the next call.
        let mut seqs = Vec::new();
        while let Some(payload) = reader.next_record().expect("next OK") {
            let s: u64 = postcard::from_bytes(payload).expect("decode");
            seqs.push(s);
        }
        assert_eq!(seqs, vec![0u64, 1, 2]);
    }

    /// `WalStreamReader` dyn-trait object usability check (Send +
    /// concrete-type erasure for higher-order callers).
    #[test]
    fn wal_stream_reader_trait_object_usable() {
        let stream = build_stream(1);
        let cursor = Cursor::new(stream);
        let reader = StreamingWalReader::open_v1(cursor).expect("open OK");
        let mut boxed: Box<dyn WalStreamReader> = Box::new(reader);
        let payload = boxed.next_record().expect("next").expect("Some");
        let seq: u64 = postcard::from_bytes(payload).expect("decode");
        assert_eq!(seq, 0);
    }
}
