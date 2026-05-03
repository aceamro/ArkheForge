//! Wire-stability tests — DO NOT TOUCH #8 invariant + stream framing
//! format pinning (Track F.3).
//!
//! Two independent invariants pinned per cryptographer Q3 split:
//!
//! 1. **`postcard_record_bytes_preserved_bit_exact`** — the record
//!    section inside a streamed export equals the input bytes
//!    byte-for-byte. The streaming format wraps unmodified L0
//!    `WalRecord` postcard bytes; any field-order rewrite or
//!    silent re-encoding would break this.
//! 2. **`streaming_header_byte_pattern_golden`** — the leading
//!    [`STREAM_HEADER_MAGIC`] bytes match a pinned hex pattern.
//!    This is a *format* invariant (separate from the cryptographic
//!    record invariant), guarding against accidental constant
//!    edits and serving as the wire-format anchor for downstream
//!    consumers.
//!
//! And one combined test pinning the entire stream layout end-to-end
//! (auditor F.3 Q2-1 firm gate — golden hex vector covering
//! header + length prefix + record section).
//!
//! All tests use synthetic record bytes — a postcard-encoded `seq:
//! u64` followed by deterministic padding. Real WAL round-trip
//! lives in F.4 (Kernel-driven WAL bytes).

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use crate::wal_export::{
        buffered_sink::BufferedWalSink, WalRecordSink, MAX_RECORD_BYTES, STREAM_HEADER_MAGIC,
    };

    /// Synthesize record bytes (postcard `seq: u64` + deterministic
    /// padding). Matches the helper in [`buffered_sink::tests`].
    fn synth_record(seq: u64, padding: usize) -> Vec<u8> {
        let mut bytes = postcard::to_allocvec(&seq).unwrap();
        bytes.extend(std::iter::repeat(0u8).take(padding));
        bytes
    }

    /// Run a single-record export and return the writer's bytes.
    fn export_one_record(record: &[u8]) -> Vec<u8> {
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        sink.append_record(record).expect("append OK");
        sink.flush().expect("flush OK");
        sink.into_writer_for_test()
    }

    /// Run an N-record export and return the writer's bytes.
    fn export_records(records: &[Vec<u8>]) -> Vec<u8> {
        let mut sink = BufferedWalSink::new(Vec::<u8>::new());
        for r in records {
            sink.append_record(r).expect("append OK");
        }
        sink.flush().expect("flush OK");
        sink.into_writer_for_test()
    }

    /// **Invariant #1 (cryptographic, DO NOT TOUCH #8 projection)**:
    /// the record section inside a streamed export equals the input
    /// bytes byte-for-byte. Stream layout:
    ///
    /// ```text
    /// [STREAM_HEADER_MAGIC: 8B] [u64 BE length: 8B] [record bytes: N bytes]
    /// ```
    ///
    /// The slice `output[16..16+N]` must equal `input[..N]` bit-exact
    /// — no field reordering, no re-encoding, no transformation
    /// inside the streaming layer. This is the runtime-side
    /// projection of L0 DO NOT TOUCH #8 (postcard field order on
    /// `WalRecord`).
    #[test]
    fn postcard_record_bytes_preserved_bit_exact() {
        let input = synth_record(0xABCD_1234, 64);
        let output = export_one_record(&input);
        let header_end = STREAM_HEADER_MAGIC.len();
        let prefix_end = header_end + 8;
        let record_section = &output[prefix_end..prefix_end + input.len()];
        assert_eq!(
            record_section, input,
            "record section in streamed output must equal input bytes bit-exact"
        );
    }

    /// **Invariant #1 across multi-record streams**: concatenated
    /// record sections preserve order + byte content. Frames are
    /// `[u64 BE length][payload]` per record, so the total layout is
    /// `[magic][len₁][bytes₁][len₂][bytes₂]…[lenₙ][bytesₙ]`.
    #[test]
    fn multi_record_sections_preserved_bit_exact_in_order() {
        let r1 = synth_record(1, 8);
        let r2 = synth_record(2, 16);
        let r3 = synth_record(3, 12);
        let output = export_records(&[r1.clone(), r2.clone(), r3.clone()]);

        // Walk the framed layout and verify each record section.
        let mut cursor = STREAM_HEADER_MAGIC.len();
        for expected in [&r1, &r2, &r3] {
            let len_bytes: [u8; 8] = output[cursor..cursor + 8]
                .try_into()
                .expect("8 bytes for length prefix");
            let len = u64::from_be_bytes(len_bytes) as usize;
            assert_eq!(len, expected.len(), "framed length matches input length");
            cursor += 8;
            let section = &output[cursor..cursor + len];
            assert_eq!(
                section, expected,
                "record section preserved bit-exact at frame boundary"
            );
            cursor += len;
        }
        assert_eq!(cursor, output.len(), "no trailing bytes after records");
    }

    /// **Invariant #2 (format, separate from cryptographic invariant)**:
    /// the leading bytes of any non-empty stream match the pinned
    /// hex pattern for [`STREAM_HEADER_MAGIC`]. This guards against
    /// accidental constant edits — if someone changes
    /// `STREAM_HEADER_MAGIC` from `b"ARKHEXP1"` to anything else,
    /// this test catches the wire-format break before merge.
    ///
    /// Matches the F.1 `stream_header_magic_is_arkhexp1` test at the
    /// constant level, but here we verify the bytes appear at offset
    /// 0 of an actual stream (end-to-end format anchor).
    #[test]
    fn streaming_header_byte_pattern_golden() {
        let input = synth_record(1, 8);
        let output = export_one_record(&input);
        let header_section = &output[..STREAM_HEADER_MAGIC.len()];
        // Hex-pinned bytes for "ARKHEXP1" — wire-stable.
        assert_eq!(
            header_section,
            &[0x41, 0x52, 0x4B, 0x48, 0x45, 0x58, 0x50, 0x31][..],
            "header magic at offset 0 matches pinned hex (ARKHEXP1)"
        );
    }

    /// **Length prefix encoding**: u64 big-endian. Verifies the
    /// stream framing's prefix encoding mechanically — high-order
    /// byte first, low-order byte last.
    #[test]
    fn length_prefix_uses_u64_big_endian_encoding() {
        // Choose payload with a non-trivial byte pattern: postcard
        // varint of seq=1 = 1 byte (`0x01`) + 257 padding zeros = 258
        // total bytes. BE prefix: [00 00 00 00 00 00 01 02] (= 0x0102).
        let input = synth_record(1, 257);
        assert_eq!(
            input.len(),
            258,
            "synthetic record = postcard(1) [1B] + 257 padding [257B] = 258B"
        );
        let output = export_one_record(&input);
        let prefix_section = &output[STREAM_HEADER_MAGIC.len()..STREAM_HEADER_MAGIC.len() + 8];
        // 258 = 0x0102 → big-endian: 00 00 00 00 00 00 01 02
        assert_eq!(
            prefix_section,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02][..],
            "u64 BE length prefix encodes high-order byte first"
        );
    }

    /// **Wire-stability golden vector (auditor F.3 Q2-1 firm gate)**:
    /// pin the *entire* stream output for a deterministic input.
    /// Catches any drift in derive-macro output, postcard varint
    /// encoding, framing layout, or constant values.
    ///
    /// Input: synthetic 4-byte record `[seq=1 (postcard varint),
    /// 0xAB, 0xCD, 0xEF]` (1-byte varint for u64=1 + 3 padding
    /// bytes).
    ///
    /// Expected stream: 8B header + 8B BE length + 4B payload = 20B.
    #[test]
    fn stream_framing_golden_vector() {
        // Hand-construct the input: postcard u64 varint encoding of
        // seq=1 is a single byte (0x01); pad with 3 deterministic
        // bytes to reach a known total length.
        let mut input = postcard::to_allocvec(&1u64).unwrap();
        input.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        assert_eq!(input.len(), 4, "synthetic input is 4 bytes");
        assert_eq!(
            input.as_slice(),
            &[0x01, 0xAB, 0xCD, 0xEF][..],
            "postcard varint(1) = 0x01"
        );

        let output = export_one_record(&input);

        // Expected output, byte-pinned:
        //   [8B header   ] [8B u64 BE length=4 ] [4B payload    ]
        //   41 52 4B 48 45 58 50 31  00 00 00 00 00 00 00 04  01 AB CD EF
        let expected: &[u8] = &[
            0x41, 0x52, 0x4B, 0x48, 0x45, 0x58, 0x50, 0x31, // "ARKHEXP1"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // BE u64 = 4
            0x01, 0xAB, 0xCD, 0xEF, // payload: postcard(1) + 0xAB 0xCD 0xEF
        ];
        assert_eq!(
            output.as_slice(),
            expected,
            "entire stream output matches pinned wire-format hex vector"
        );
    }

    /// **Sanity**: `MAX_RECORD_BYTES` constant remains
    /// `1 << 24` (16 MiB) at the wire-format layer — would be
    /// caught by F.1's `max_record_bytes_is_sixteen_mib` too,
    /// but pinning at this layer surfaces the link between
    /// the type-level constant and the streaming framing.
    #[test]
    fn max_record_bytes_constant_anchored_at_sixteen_mib() {
        assert_eq!(MAX_RECORD_BYTES, 1 << 24);
        assert_eq!(MAX_RECORD_BYTES, 16_777_216);
    }
}
