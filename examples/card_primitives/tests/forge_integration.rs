//! Forge L1 integration tests — drive `RecordHandShowdown` through
//! `pipeline::process_action` and assert the deterministic-replay +
//! tamper-rejection properties the framework integration must hold.
//!
//! These tests prove the framework "works" from a consumer-crate
//! perspective: the `#[derive(ArkheAction)]` / `#[derive(ArkheEvent)]`
//! macros expand cleanly in `card-primitives` (an external crate),
//! the sealed-trait pattern admits the derive-emitted impls, and the
//! L1 dispatch surface delivers byte-identical event payloads on
//! repeat runs (a prerequisite for L0 A1 D1-Total replay determinism).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_forge_core::context::{ActionContext, ActionError};
use arkhe_forge_core::event::ArkheEvent as _;
use arkhe_forge_core::pipeline::process_action;
use arkhe_forge_platform::dispatcher::{wal_to_sink, RuntimeService};
use arkhe_forge_platform::wal_export::{BufferedWalSink, StreamingWalReader, WalStreamReader};
use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal, Tick};
use arkhe_kernel::state::InstanceConfig;

use card_primitives::card::Rank;
use card_primitives::deck::Deck;
use card_primitives::forge_integration::{DeckOrderBytes, HandShowdownLanded, RecordHandShowdown};
use card_primitives::hand_eval::HandRank;
use card_primitives::shuffle_proof::{ProofRng, ShowdownReceipt, ShuffleCommitment};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic 32-byte seed for test fixtures. The integration tests
/// run on a single canonical seed; richer property coverage lives in
/// `tests/statistical_rng_suite.rs`.
fn fixture_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    s
}

/// Shuffle a fresh deck under `seed` and capture the canonical 52-byte
/// order. Mirrors the helper used by the `shuffle_proof` test suite.
fn shuffled_order(seed: [u8; 32]) -> [u8; 52] {
    let mut deck = Deck::standard();
    let mut rng = ProofRng::from_seed(seed);
    deck.shuffle(&mut rng);
    let mut order = [0u8; 52];
    for (i, c) in deck.cards().iter().enumerate() {
        order[i] = c.to_byte();
    }
    order
}

/// Build a fresh `ActionContext` with `CapabilityMask::SYSTEM` so the
/// pipeline's L1 capability gate passes.
fn fixture_ctx() -> ActionContext<'static> {
    ActionContext::new(
        [0x11u8; 32],
        InstanceId::new(1).expect("InstanceId 1 is non-zero"),
        Tick(0),
        Principal::System,
        CapabilityMask::SYSTEM,
    )
}

/// Build a canonical `RecordHandShowdown` for the fixture seed. The
/// hand_rank_bytes field uses an arbitrary but deterministic
/// `HandRank` value (`Straight(Ten)`) — the test does not depend on
/// the rank's specific semantics, only on byte-identical replay.
fn fixture_action() -> RecordHandShowdown {
    let seed = fixture_seed();
    let commitment = ShuffleCommitment::from_seed(&seed);
    let order = shuffled_order(seed);
    RecordHandShowdown {
        schema_version: 1,
        commitment: *commitment.as_bytes(),
        seed,
        deck_order: DeckOrderBytes::from_array(order),
        hand_rank_bytes: HandRank::Straight(Rank::Ten).to_chain_hash_bytes(),
    }
}

// ===========================================================================
// Test 1 — Replay determinism: byte-identical event payload
// ===========================================================================
//
// Same `(action, ctx-fixture)` pair, two independent `process_action`
// runs → drained `EventRecord.payload` must be byte-identical. This is
// the consumer-side proof of the L0 A1 D1-Total replay-determinism
// property: a ProofRng / blake3-keyed-PRF / Lemire-rejection-shuffle
// pipeline produces wire output that does not vary between runs.

#[test]
fn replay_determinism_event_payload_byte_identical() {
    let action = fixture_action();

    let mut ctx_a = fixture_ctx();
    let events_a = process_action(&action, &mut ctx_a).expect("first run must succeed");
    assert_eq!(events_a.len(), 1);

    let mut ctx_b = fixture_ctx();
    let events_b = process_action(&action, &mut ctx_b).expect("second run must succeed");
    assert_eq!(events_b.len(), 1);

    // Header equality.
    assert_eq!(events_a[0].type_code, events_b[0].type_code);
    assert_eq!(events_a[0].sequence, events_b[0].sequence);
    assert_eq!(events_a[0].tick, events_b[0].tick);

    // Payload byte-identical equality — the substantive property.
    assert_eq!(
        events_a[0].payload, events_b[0].payload,
        "two process_action runs must produce byte-identical payloads",
    );

    // Sanity — type_code matches the derived const.
    assert_eq!(events_a[0].type_code, HandShowdownLanded::TYPE_CODE);
}

// ===========================================================================
// Test 2 — Commitment mismatch rejection
// ===========================================================================
//
// Tamper the revealed seed by 1 bit; the commitment recomputation
// inside `compute()` produces a different digest, so the Action must
// reject with `ActionError::InvalidInput("commitment mismatch")`.

#[test]
fn commitment_mismatch_returns_invalid_input() {
    let mut action = fixture_action();
    // Flip bit 0 of seed byte 0 — the broadcast commitment no longer
    // matches the revealed seed under the BLAKE3 keyed-PRF domain tag.
    action.seed[0] ^= 0x01;

    let mut ctx = fixture_ctx();
    let err = process_action(&action, &mut ctx).expect_err("commitment mismatch must reject");

    match err {
        ActionError::InvalidInput(msg) => {
            assert_eq!(msg, "commitment mismatch", "error message pinned");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

// ===========================================================================
// Test 3 — Deck-order tamper rejection
// ===========================================================================
//
// Honest commitment + revealed seed, but the broadcast deck_order has
// two cards swapped. The pipeline must reject with
// `ActionError::InvalidInput("shuffle order invalid")` — the
// commitment binding stage 1 passes (seed/commitment unchanged), so
// the rejection comes from the `verify_shuffle_order` replay-mismatch
// in stage 2.

#[test]
fn deck_order_tamper_returns_invalid_input() {
    let action_clean = fixture_action();

    // Swap two adjacent bytes in the deck_order to break the canonical
    // shuffle reproduction without changing the seed.
    let mut tampered_order = action_clean.deck_order.as_array();
    tampered_order.swap(0, 1);
    let action_tampered = RecordHandShowdown {
        deck_order: DeckOrderBytes::from_array(tampered_order),
        ..action_clean.clone()
    };

    let mut ctx = fixture_ctx();
    let err =
        process_action(&action_tampered, &mut ctx).expect_err("deck_order tamper must reject");

    match err {
        ActionError::InvalidInput(msg) => {
            assert_eq!(msg, "shuffle order invalid", "error message pinned");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

// ===========================================================================
// Test 4 — DOMAIN_SHOWDOWN duplication drift defense
// ===========================================================================
//
// `forge_integration::DOMAIN_SHOWDOWN` is a byte-identical duplicate of
// `shuffle_proof`'s private domain tag (the latter is intentionally
// not re-exported — see forge_integration.rs L45-49). Today the two
// constants match because architect / cryptographer review verified
// the byte sequence; if a future edit drifts one without the other,
// the chain-hash anchors emitted via `RecordHandShowdown` would no
// longer match the audience-side `ShowdownReceipt::chain_hash()`,
// silently invalidating downstream verification.
//
// This regression test pins the equality at the byte level: same
// `(deck_order, hand_rank)` → identical 32-byte chain-hash digest from
// both paths. A future drift in either DOMAIN_SHOWDOWN copy trips the
// assertion before the change reaches main.

#[test]
fn chain_hash_byte_identical_to_showdown_receipt() {
    let action = fixture_action();

    // Audience-side: ShowdownReceipt::chain_hash() over the same
    // (deck_order, hand_rank_bytes) — uses shuffle_proof's private
    // DOMAIN_SHOWDOWN constant.
    let receipt = ShowdownReceipt {
        deck_order: action.deck_order.as_array(),
        hand_rank: HandRank::Straight(Rank::Ten),
    };
    let audience_anchor = receipt.chain_hash();

    // Action-side: drive the Action through the pipeline and pull the
    // emitted HandShowdownLanded.chain_hash out of the event payload.
    let mut ctx = fixture_ctx();
    let events = process_action(&action, &mut ctx).expect("Action must succeed");
    let landed: HandShowdownLanded =
        postcard::from_bytes(&events[0].payload).expect("payload is a valid HandShowdownLanded");

    // Byte-identical equality. Any future drift in either of the two
    // DOMAIN_SHOWDOWN copies (forge_integration.rs L45-49 vs
    // shuffle_proof's private const) breaks this assertion before the
    // change reaches main.
    assert_eq!(
        landed.chain_hash, audience_anchor,
        "Action-emitted chain_hash must match ShowdownReceipt::chain_hash() \
         byte-by-byte — DOMAIN_SHOWDOWN drift regression defense",
    );
}

// ===========================================================================
// Test 5 — L2 RuntimeService end-to-end + WAL export round-trip
// ===========================================================================
//
// Drive `RecordHandShowdown` through the L2 service layer
// (`RuntimeService`), let the kernel run its full authorize →
// dispatch → WAL append loop, export the resulting `Wal`, stream
// it into a `BufferedWalSink<Vec<u8>>`, then re-read through
// `StreamingWalReader` and assert each recovered record matches the
// original byte-for-byte.
//
// This is the consumer-side proof that:
// - `arkhe-forge-macros::ArkheAction` derive emits the kernel-side
//   `Sealed + ActionDeriv + ActionCompute` stack (else
//   `Kernel::register_action::<RecordHandShowdown>` would not compile).
// - The forge → kernel `bridge::kernel_compute` correctly runs the
//   forge `compute()` body inside the kernel `step()` loop (else the
//   `effects_applied` count would not reflect the emit_event Op).
// - `wal_to_sink` preserves L0 `WalRecord` bytes through the streaming
//   sink format (firm requirements #1 magic + #2 length-prefix +
//   #3 bounds-check).

#[test]
fn runtime_service_dispatch_wal_export_round_trip() {
    let action = fixture_action();

    let mut service = RuntimeService::new([0x11u8; 32], [0x22u8; 32]);
    service.register_action::<RecordHandShowdown>();
    let instance = service.create_instance(InstanceConfig::default());

    let report = service
        .dispatch(
            instance,
            Principal::System,
            &action,
            Tick(1),
            CapabilityMask::SYSTEM,
        )
        .expect("dispatch must succeed");
    assert_eq!(report.actions_executed, 1, "single submit + step pair");
    assert_eq!(
        report.effects_applied, 1,
        "RecordHandShowdown emits exactly one event Op",
    );
    assert_eq!(
        report.effects_denied, 0,
        "System principal under SYSTEM caps"
    );

    let wal = service.export_wal().expect("WAL configured");
    assert_eq!(wal.records.len(), 1, "one dispatch → one WAL record");

    // The WAL record's `action_type_code` must equal RecordHandShowdown's
    // pinned TYPE_CODE — proving the kernel-side dispatch saw the
    // forge-side action through the macro-emitted bridge.
    use arkhe_kernel::abi::TypeCode;
    assert_eq!(
        wal.records[0].action_type_code,
        TypeCode(0x0100_0001),
        "WAL record carries RecordHandShowdown TYPE_CODE",
    );

    let mut buffer: Vec<u8> = Vec::new();
    {
        let mut sink = BufferedWalSink::new(&mut buffer);
        wal_to_sink(&wal, &mut sink).expect("wal_to_sink must succeed");
    }
    assert!(
        !buffer.is_empty(),
        "sink writer holds framed bytes after flush",
    );

    // Round-trip verify — re-read the sink bytes through the
    // streaming reader and assert byte-identical recovery against the
    // postcard re-encoding of the original record.
    let mut reader = StreamingWalReader::open_v1(&buffer[..]).expect("ARKHEXP1 magic must decode");
    let recovered = reader
        .next_record()
        .expect("frame must decode")
        .expect("one record present");
    let original_bytes =
        postcard::to_allocvec(&wal.records[0]).expect("re-encode original WalRecord");
    assert_eq!(
        recovered, original_bytes,
        "round-trip: recovered record bytes match the original",
    );
    assert!(
        reader.next_record().expect("post-record poll").is_none(),
        "exactly one record was framed",
    );
}
