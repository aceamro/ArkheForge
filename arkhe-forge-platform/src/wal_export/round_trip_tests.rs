//! Round-trip + replay determinism integration tests.
//!
//! End-to-end coverage of the streaming export pipeline:
//!
//! ```text
//! Kernel::step → WAL records → BufferedWalSink → byte stream
//!     → parse_stream (consumer-side reconstruction) → Wal::verify_chain
//! ```
//!
//! Six integration coverage areas:
//!
//! 1. **consumer-side replay verification** — chain integrity preserved
//!    through round-trip (`round_trip_real_wal_records_verify_chain`).
//! 2. **stream `ARKHEXP1` + invalid prefix bytes reject scenarios** —
//!    `parse_stream` rejects malformed framing with the correct
//!    [`InvalidFramingReason`] variant.
//! 3. **truncation/corruption robustness** — clipped streams trip
//!    `Truncated`; tampered record bytes break `verify_chain`.
//! 4. **real WAL round-trip (Kernel-driven WAL bytes)** — production
//!    code path exercised end-to-end via `Kernel::new_with_wal` +
//!    `register_action::<TestAction>` + `submit` + `step` flow.
//! 5. **Record duplication (replay-attack) detection** — duplicate
//!    record bytes break `verify_chain` (chain prev-hash mismatch).
//! 6. **Mid-stream magic insertion detection** — inserting
//!    [`STREAM_HEADER_MAGIC`] bytes mid-stream produces an oversized
//!    length prefix that trips
//!    [`InvalidFramingReason::LengthExceedsMax`].

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::wal_export::{
        buffered_sink::BufferedWalSink, InvalidFramingReason, WalExportError, WalRecordSink,
        MAX_RECORD_BYTES, STREAM_HEADER_MAGIC,
    };
    use arkhe_forge_core::arkhe_pure;
    use arkhe_kernel::abi::{CapabilityMask, Principal, Tick};
    use arkhe_kernel::persist::{Wal, WalRecord};
    use arkhe_kernel::state::{
        Action, ActionCompute, ActionContext, ActionDeriv, InstanceConfig, Op,
    };
    use arkhe_kernel::{ArkheAction, Kernel};
    use serde::{Deserialize, Serialize};

    const WORLD_ID: [u8; 32] = [0x42u8; 32];
    const MANIFEST_DIGEST: [u8; 32] = [0x9Au8; 32];

    /// Minimal Action used to populate the WAL with real records.
    /// `ActionCompute::compute` returns no Ops so the WAL records are
    /// well-formed but carry empty staged-state — sufficient for chain
    /// integrity tests, doesn't add ledger / state mutations.
    #[derive(Debug, Serialize, Deserialize, Clone, ArkheAction)]
    #[arkhe(type_code = 7000, schema_version = 1)]
    struct TestAction {
        nonce: u64,
    }

    impl ActionCompute for TestAction {
        #[arkhe_pure]
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            Vec::new()
        }
    }

    /// Build a real WAL with `n` records appended via the production
    /// `Kernel::submit` + `Kernel::step` path. The returned `Wal` has a
    /// valid chain hash — `Wal::verify_chain(WORLD_ID)` must succeed.
    fn build_wal_with_records(n: u64) -> Wal {
        let mut kernel = Kernel::new_with_wal(WORLD_ID, MANIFEST_DIGEST);
        kernel.register_action::<TestAction>();
        let inst = kernel.create_instance(InstanceConfig::default());
        for i in 0..n {
            let action = TestAction { nonce: i };
            let bytes = Action::canonical_bytes(&action);
            let at = Tick(i);
            kernel
                .submit(
                    inst,
                    Principal::System,
                    None,
                    at,
                    TestAction::TYPE_CODE,
                    bytes,
                )
                .expect("submit OK");
            let _ = kernel.step(at, CapabilityMask::SYSTEM);
        }
        kernel.export_wal().expect("WAL attached")
    }

    /// Stream the WAL records through `BufferedWalSink<&mut Vec<u8>>`
    /// and return the framed bytes.
    fn export_records_to_stream(records: &[WalRecord]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut sink = BufferedWalSink::new(&mut buf);
            for r in records {
                let bytes = postcard::to_allocvec(r).expect("postcard OK");
                sink.append_record(&bytes).expect("append OK");
            }
            sink.flush().expect("flush OK");
        }
        buf
    }

    /// Consumer-side stream parser — validates framing + reconstructs
    /// per-record byte slices. Mirrors the producer-side `BufferedWalSink`
    /// invariants (length-prefix bounds, header pin, append-only).
    ///
    /// **Test-only** — duplicates the framing logic of the production
    /// `super::reader::StreamingWalReader` so this test module stays
    /// independent of the reader API.
    fn parse_stream(stream: &[u8]) -> Result<Vec<Vec<u8>>, WalExportError> {
        // Stream header — exactly 8 bytes matching STREAM_HEADER_MAGIC.
        if stream.len() < STREAM_HEADER_MAGIC.len() {
            return Err(WalExportError::InvalidFraming(
                InvalidFramingReason::Truncated,
            ));
        }
        if stream[..STREAM_HEADER_MAGIC.len()] != STREAM_HEADER_MAGIC {
            return Err(WalExportError::InvalidFraming(
                InvalidFramingReason::HeaderMissing,
            ));
        }

        let mut cursor = STREAM_HEADER_MAGIC.len();
        let mut records = Vec::new();
        while cursor < stream.len() {
            // Length prefix (8 bytes, BE).
            if stream.len() - cursor < 8 {
                return Err(WalExportError::InvalidFraming(
                    InvalidFramingReason::Truncated,
                ));
            }
            let len_bytes: [u8; 8] = stream[cursor..cursor + 8].try_into().expect("8-byte slice");
            let len = u64::from_be_bytes(len_bytes);

            // Bounds check (mirror producer-side firm req #2).
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

            cursor += 8;
            let len_usize = len as usize;
            if stream.len() - cursor < len_usize {
                return Err(WalExportError::InvalidFraming(
                    InvalidFramingReason::Truncated,
                ));
            }
            records.push(stream[cursor..cursor + len_usize].to_vec());
            cursor += len_usize;
        }
        Ok(records)
    }

    /// Reconstruct a `Wal` from the original header and the parsed
    /// per-record byte slices.
    fn reconstruct_wal(
        header: arkhe_kernel::persist::WalHeader,
        record_byte_slices: Vec<Vec<u8>>,
    ) -> Wal {
        let records: Vec<WalRecord> = record_byte_slices
            .iter()
            .map(|bytes| postcard::from_bytes(bytes).expect("postcard decode OK"))
            .collect();
        Wal { header, records }
    }

    // -------------------------------------------------------------------
    // Round-trip + replay determinism + chain integrity
    // -------------------------------------------------------------------

    /// Stream a real Kernel-driven WAL through the sink, parse it back,
    /// and confirm `Wal::verify_chain` still passes.
    /// Demonstrates end-to-end chain integrity preservation through the
    /// streaming export pipeline.
    #[test]
    fn round_trip_real_wal_records_verify_chain() {
        let original = build_wal_with_records(5);
        original
            .verify_chain(WORLD_ID)
            .expect("baseline WAL chain valid");

        let stream = export_records_to_stream(&original.records);
        let parsed = parse_stream(&stream).expect("parse OK");
        assert_eq!(
            parsed.len(),
            original.records.len(),
            "round-trip preserves record count"
        );

        let reconstructed = reconstruct_wal(original.header.clone(), parsed);
        reconstructed
            .verify_chain(WORLD_ID)
            .expect("round-trip WAL chain still valid");
    }

    /// Reconstructed records equal originals byte-for-byte (postcard
    /// re-encoding produces identical bytes via Serialize).
    #[test]
    fn round_trip_records_byte_identical_to_originals() {
        let original = build_wal_with_records(3);
        let stream = export_records_to_stream(&original.records);
        let parsed = parse_stream(&stream).expect("parse OK");

        for (i, parsed_bytes) in parsed.iter().enumerate() {
            let original_bytes = postcard::to_allocvec(&original.records[i]).expect("postcard OK");
            assert_eq!(
                parsed_bytes, &original_bytes,
                "record {i} parsed bytes equal original postcard encoding"
            );
        }
    }

    // -------------------------------------------------------------------
    // Stream header / invalid prefix reject scenarios
    // -------------------------------------------------------------------

    /// Empty stream → `Truncated` (header section missing).
    #[test]
    fn empty_stream_rejected_with_truncated() {
        let result = parse_stream(&[]);
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::Truncated
            ))
        ));
    }

    /// Stream without header magic → `HeaderMissing`.
    #[test]
    fn invalid_header_magic_rejected_with_header_missing() {
        let mut bogus = vec![0xFFu8; 8];
        bogus.extend_from_slice(&[0u8; 16]);
        let result = parse_stream(&bogus);
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::HeaderMissing
            ))
        ));
    }

    /// Stream with header but truncated mid-length-prefix → `Truncated`.
    #[test]
    fn truncated_in_length_prefix_rejected_with_truncated() {
        let mut stream = STREAM_HEADER_MAGIC.to_vec();
        stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // partial 4 bytes only
        let result = parse_stream(&stream);
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::Truncated
            ))
        ));
    }

    /// Zero-length prefix → `LengthZero`.
    #[test]
    fn zero_length_prefix_rejected_with_length_zero() {
        let mut stream = STREAM_HEADER_MAGIC.to_vec();
        stream.extend_from_slice(&0u64.to_be_bytes());
        let result = parse_stream(&stream);
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::LengthZero
            ))
        ));
    }

    /// Oversized length prefix → `LengthExceedsMax`.
    #[test]
    fn oversized_length_prefix_rejected_with_length_exceeds_max() {
        let mut stream = STREAM_HEADER_MAGIC.to_vec();
        stream.extend_from_slice(&(MAX_RECORD_BYTES + 1).to_be_bytes());
        let result = parse_stream(&stream);
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

    /// Stream truncated mid-payload → `Truncated`.
    #[test]
    fn truncated_in_payload_rejected_with_truncated() {
        let original = build_wal_with_records(2);
        let stream = export_records_to_stream(&original.records);
        let mut stream = stream;
        // Drop the last 4 bytes — payload truncated mid-record.
        stream.truncate(stream.len() - 4);
        let result = parse_stream(&stream);
        assert!(matches!(
            result,
            Err(WalExportError::InvalidFraming(
                InvalidFramingReason::Truncated
            ))
        ));
    }

    // -------------------------------------------------------------------
    // Tamper detection
    // -------------------------------------------------------------------

    /// Tampering a record's chain hash bytes mid-stream breaks
    /// `verify_chain`. The framing layer (parse_stream) accepts the
    /// bytes as well-formed, but downstream chain verification catches
    /// the integrity break.
    #[test]
    fn tampered_record_section_breaks_verify_chain() {
        let original = build_wal_with_records(3);
        let mut stream = export_records_to_stream(&original.records);

        // Locate a record's payload section and flip a byte. The
        // streamed layout starts with [magic 8B][len 8B], so byte 16+
        // is into the first record's bytes. Flip a byte deep inside
        // the record (after seq + tick + instance + principal) so we
        // perturb a chain-hash-relevant field.
        //
        // **Note**: perturb_offset = 32 assumes byte 32 within record
        // 0 lands in the chain-hashed payload region. If a future
        // WalRecord schema migration shifts the layout, this offset
        // may need re-tuning to stay inside the hashed region.
        let perturb_offset = STREAM_HEADER_MAGIC.len() + 8 + 32; // ~ middle of record 0
        stream[perturb_offset] ^= 0x01;

        let parsed = parse_stream(&stream).expect("framing still valid");
        let reconstructed = reconstruct_wal(original.header.clone(), parsed);
        let result = reconstructed.verify_chain(WORLD_ID);
        assert!(
            result.is_err(),
            "tampered record bytes break chain verification"
        );
    }

    // -------------------------------------------------------------------
    // Replay-attack (record duplication) detection
    // -------------------------------------------------------------------

    /// Producer-side rejection — `BufferedWalSink::append_record`
    /// rejects a duplicate `seq` with `AppendOnlyViolation`.
    #[test]
    fn record_duplication_rejected_at_sink_with_append_only_violation() {
        let original = build_wal_with_records(2);
        let mut buf = Vec::<u8>::new();
        {
            let mut sink = BufferedWalSink::new(&mut buf);
            let bytes = postcard::to_allocvec(&original.records[0]).expect("postcard OK");
            sink.append_record(&bytes).expect("first append OK");
            // Re-submit the same record (duplicate seq=1).
            let result = sink.append_record(&bytes);
            assert!(matches!(
                result,
                Err(WalExportError::AppendOnlyViolation {
                    expected_seq: 2,
                    got_seq: 1,
                    previous_seq: Some(1),
                })
            ));
        }
    }

    /// Consumer-side: a duplicated record in the parsed stream
    /// (constructed manually here) breaks `verify_chain` — the
    /// duplicate's `prev_chain_hash` won't match the running expected
    /// hash. Demonstrates the chain-level defence against replay
    /// attacks even if a malicious actor bypasses the producer.
    #[test]
    fn duplicated_record_in_parsed_stream_breaks_verify_chain() {
        let original = build_wal_with_records(3);

        // Manually construct a record list with seq 1, 2, 2 (record 2
        // duplicated in place of record 3). The duplicate's prev_chain_hash
        // and this_chain_hash were computed for position 2; at position 3
        // the running hash differs → ChainBroken or HashMismatch.
        let mut tampered_records = original.records.clone();
        tampered_records[2] = tampered_records[1].clone();

        let tampered_wal = Wal {
            header: original.header.clone(),
            records: tampered_records,
        };
        let result = tampered_wal.verify_chain(WORLD_ID);
        assert!(
            result.is_err(),
            "duplicated record breaks verify_chain (replay-attack defence)"
        );
    }

    // -------------------------------------------------------------------
    // Mid-stream magic insertion detection
    // -------------------------------------------------------------------

    /// Inserting [`STREAM_HEADER_MAGIC`] bytes mid-stream produces a
    /// bogus length prefix that exceeds `MAX_RECORD_BYTES`. The 8-byte
    /// magic `ARKHEXP1` decoded as u64 BE is `0x4152_4B48_4558_5031` ≈
    /// 4.7 quintillion — far above `MAX_RECORD_BYTES = 1 << 24`. Parser
    /// rejects with `LengthExceedsMax`, defending against split-stream
    /// concatenation attacks.
    ///
    /// **Defence-in-depth split**:
    /// - **Case (a)** — inserted 8 bytes decode as `> MAX_RECORD_BYTES`:
    ///   parser rejects mechanically with `LengthExceedsMax` (this test).
    /// - **Case (b)** — inserted 8 bytes decode as `≤ MAX_RECORD_BYTES`:
    ///   parser accepts the framing, payload extraction proceeds, but
    ///   the bytes that follow are mis-aligned vs the original chain
    ///   hashes → covered by
    ///   [`tampered_record_section_breaks_verify_chain`].
    ///
    /// Together the two tests cover the full attack surface.
    #[test]
    fn mid_stream_magic_insertion_caught_by_length_exceeds_max() {
        let original = build_wal_with_records(2);
        let stream = export_records_to_stream(&original.records);

        // Find the boundary between record 0 and record 1, insert
        // STREAM_HEADER_MAGIC bytes there. The next "length prefix"
        // the parser sees will be the magic bytes interpreted as a
        // huge u64.
        let header_end = STREAM_HEADER_MAGIC.len();
        let len_bytes: [u8; 8] = stream[header_end..header_end + 8]
            .try_into()
            .expect("8 bytes");
        let rec0_len = u64::from_be_bytes(len_bytes) as usize;
        let insert_at = header_end + 8 + rec0_len; // start of record 1's length prefix

        let mut tampered = stream[..insert_at].to_vec();
        tampered.extend_from_slice(&STREAM_HEADER_MAGIC);
        tampered.extend_from_slice(&stream[insert_at..]);

        let result = parse_stream(&tampered);
        match result {
            Err(WalExportError::InvalidFraming(InvalidFramingReason::LengthExceedsMax {
                prefix,
                max,
            })) => {
                // Magic "ARKHEXP1" interpreted as u64 BE.
                let expected_prefix = u64::from_be_bytes(STREAM_HEADER_MAGIC);
                assert_eq!(prefix, expected_prefix);
                assert_eq!(max, MAX_RECORD_BYTES);
            }
            other => panic!("expected LengthExceedsMax (mid-stream magic), got: {other:?}"),
        }
    }

    /// Replay determinism baseline check: build the same WAL twice —
    /// the streamed export bytes are byte-identical. Demonstrates the
    /// streaming layer is itself deterministic (no timestamps, no
    /// random salt, no allocator-order leak).
    ///
    /// **Combined determinism coverage matrix**: the wire-format
    /// `stream_framing_golden_vector` (in `super::wire_stability`) pins
    /// a fixed input → fixed hex output (catches compiler / library /
    /// allocator drift), and this test catches Runtime-level
    /// non-determinism (same-run twice-build). The two together form
    /// comprehensive determinism coverage at the wire-format and
    /// Runtime layers.
    #[test]
    fn streaming_export_is_byte_deterministic_across_runs() {
        let wal1 = build_wal_with_records(3);
        let wal2 = build_wal_with_records(3);
        let s1 = export_records_to_stream(&wal1.records);
        let s2 = export_records_to_stream(&wal2.records);
        assert_eq!(s1, s2, "streamed export bytes match across runs");
    }

    /// Bridge test verifying `BufferedWalSink::extract_seq` tracks the
    /// L0 `WalRecord` schema's leading `seq: u64` field (DO NOT TOUCH
    /// #7 sentinel — post-`8bf62eb` Layer A 8→7 renumber, ex-#8).
    ///
    /// Path:
    /// 1. Build a real `Wal` with N records via the Kernel pipeline
    ///    (the only public path, since `WalRecord.stage` is
    ///    `pub(crate)` to `arkhe_kernel`).
    /// 2. For each record, postcard-encode it via `to_allocvec`.
    /// 3. Call `BufferedWalSink::extract_seq` directly on the encoded
    ///    bytes.
    /// 4. Assert the extracted seq matches the original record's
    ///    `seq` field byte-equal.
    ///
    /// **Failure mode**: if a future schema migration reorders
    /// `WalRecord` fields (placing some other field before `seq`),
    /// `extract_seq` would parse the wrong leading value and the
    /// assertion would fail. This catches the schema drift before
    /// any production wire damage occurs — the L0 invariant is
    /// `arkhe_kernel`'s "DO NOT TOUCH #7" anchor, and the Runtime
    /// layer holds this bridging test as the cross-layer sentinel.
    ///
    #[test]
    fn walrecord_leading_seq_invariant_bridge() {
        let wal = build_wal_with_records(3);
        assert_eq!(
            wal.records.len(),
            3,
            "Kernel pipeline must produce 3 records"
        );

        for (idx, record) in wal.records.iter().enumerate() {
            let bytes = postcard::to_allocvec(record).expect("postcard encode OK");
            let extracted = BufferedWalSink::<Vec<u8>>::extract_seq(&bytes)
                .expect("extract_seq decodes leading seq u64");
            assert_eq!(
                extracted, record.seq,
                "record #{idx}: extract_seq must equal record.seq (L0 schema coupling)"
            );
        }
    }
}
