//! `card_primitives` end-to-end demo — provably-fair Texas Hold'em.
//!
//! The four supporting modules (`card`, `deck`, `hand_eval`,
//! `shuffle_proof`) build up bottom-up to the demo run in this file.
//! `cargo run -p card-primitives` executes a single 2-player Texas
//! Hold'em hand where the dealer:
//!
//! 1. picks a 32-byte seed and broadcasts the BLAKE3 commitment,
//! 2. shuffles the deck deterministically from the seed,
//! 3. deals hole cards (2 each) + community board (flop/turn/river),
//! 4. reveals the seed and a `ShowdownReceipt`,
//! 5. lets the audience verify shuffle integrity via the pure
//!    [`verify_shuffle`] / [`verify_shuffle_order`] functions and pins
//!    the showdown into a 32-byte chain-hash anchor,
//! 6. records the showdown into the ArkheForge L1 event pipeline via
//!    the [`RecordHandShowdown`] Action, which emits a
//!    [`HandShowdownLanded`] Event whose payload pins the same
//!    chain-hash anchor,
//! 7. dispatches the same Action through the L2
//!    [`RuntimeService`](arkhe_forge_platform::dispatcher::RuntimeService)
//!    so the kernel runs its full authorize → dispatch → WAL append
//!    loop end-to-end,
//! 8. exports the kernel's internal WAL and streams every record into a
//!    [`BufferedWalSink`](arkhe_forge_platform::wal_export::BufferedWalSink) —
//!    answering "is the showdown actually written to a WAL?" with
//!    "yes, here are the framed bytes",
//! 9. re-reads those bytes through
//!    [`StreamingWalReader`](arkhe_forge_platform::wal_export::StreamingWalReader)
//!    and asserts the recovered records match the originals byte-for-byte
//!    — the consumer-side proof of WAL round-trip stability.
//!
//! Educational scope — `unwrap` / `expect` / `panic` are locally
//! relaxed in this binary for tutorial legibility (pattern alignment
//! with `ArkheKernel/examples/dice/`). The four supporting modules
//! carry the production-style panic-free discipline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arkhe_forge_core::context::ActionContext;
use arkhe_forge_core::event::ArkheEvent as _;
use arkhe_forge_core::pipeline::process_action;
use arkhe_forge_platform::dispatcher::{wal_to_sink, RuntimeService};
use arkhe_forge_platform::wal_export::{BufferedWalSink, StreamingWalReader, WalStreamReader};
use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal, Tick};
use arkhe_kernel::state::InstanceConfig;
use arkhe_rand::RngSource;
use card_primitives::card::Card;
use card_primitives::deck::Deck;
use card_primitives::forge_integration::{DeckOrderBytes, HandShowdownLanded, RecordHandShowdown};
use card_primitives::hand_eval::{compare_hands, evaluate_7};
use card_primitives::shuffle_proof::{
    verify_shuffle, verify_shuffle_order, ShowdownReceipt, ShuffleCommitment,
};

/// Render a 32-byte digest as lowercase hex via [`blake3::Hash`]'s
/// `Display` impl. Avoids ad-hoc hex formatting in the demo body.
fn hex32(bytes: &[u8; 32]) -> blake3::Hash {
    blake3::Hash::from(*bytes)
}

fn main() {
    println!("=== card_primitives end-to-end demo ===");
    println!();

    // -----------------------------------------------------------------
    // 1. Dealer commits to a seed
    // -----------------------------------------------------------------
    // Educational seed — deterministic to keep the demo output stable.
    // Production dealers would source 32 bytes from `getrandom` and
    // never reuse the same seed across hands.
    let seed: [u8; 32] = {
        let mut s = [0u8; 32];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        s
    };
    let commitment = ShuffleCommitment::from_seed(&seed);
    println!("[1/9] Dealer broadcasts commitment (BLAKE3 of seed):");
    println!("      {}", hex32(commitment.as_bytes()));
    println!();

    // -----------------------------------------------------------------
    // 2. Dealer shuffles deterministically + deals
    // -----------------------------------------------------------------
    let mut rng = RngSource::from_seed(&seed);
    let mut deck = Deck::standard();
    deck.shuffle(&mut rng);

    // Texas Hold'em deal sequence:
    //   - 2 hole cards × 2 players (interleaved as in real play)
    //   - Burn 1 + Flop 3
    //   - Burn 1 + Turn 1
    //   - Burn 1 + River 1
    let p1_card_1 = deck.draw().unwrap();
    let p2_card_1 = deck.draw().unwrap();
    let p1_card_2 = deck.draw().unwrap();
    let p2_card_2 = deck.draw().unwrap();
    let p1_hole = [p1_card_1, p1_card_2];
    let p2_hole = [p2_card_1, p2_card_2];

    let _ = deck.draw().expect("burn slot 1");
    let flop = [
        deck.draw().unwrap(),
        deck.draw().unwrap(),
        deck.draw().unwrap(),
    ];
    let _ = deck.draw().expect("burn slot 2");
    let turn = deck.draw().unwrap();
    let _ = deck.draw().expect("burn slot 3");
    let river = deck.draw().unwrap();

    println!("[2/9] Deal sequence (after Fisher-Yates shuffle):");
    println!("      Player 1 hole: {} {}", p1_hole[0], p1_hole[1]);
    println!("      Player 2 hole: {} {}", p2_hole[0], p2_hole[1]);
    println!("      Flop : {} {} {}", flop[0], flop[1], flop[2]);
    println!("      Turn : {}", turn);
    println!("      River: {}", river);
    println!();

    // -----------------------------------------------------------------
    // 3. Showdown evaluation
    // -----------------------------------------------------------------
    let p1_seven: [Card; 7] = [
        p1_hole[0], p1_hole[1], flop[0], flop[1], flop[2], turn, river,
    ];
    let p2_seven: [Card; 7] = [
        p2_hole[0], p2_hole[1], flop[0], flop[1], flop[2], turn, river,
    ];
    let p1_rank = evaluate_7(&p1_seven);
    let p2_rank = evaluate_7(&p2_seven);

    println!("[3/9] Showdown best-5-of-7 evaluation:");
    println!("      Player 1: {}", p1_rank);
    println!("      Player 2: {}", p2_rank);
    // Tie is a distinct render — Player 1 / Player 2 are wins, Tie is a
    // separate outcome. `winner_rank` carries the canonical hand
    // strength regardless (both ranks are equal in the tie branch).
    let winner_rank = match compare_hands(&p1_rank, &p2_rank) {
        core::cmp::Ordering::Greater => {
            println!("      Winner  : Player 1 ({})", p1_rank);
            p1_rank
        }
        core::cmp::Ordering::Less => {
            println!("      Winner  : Player 2 ({})", p2_rank);
            p2_rank
        }
        core::cmp::Ordering::Equal => {
            println!("      Result  : Tie — both have {}", p1_rank);
            p1_rank
        }
    };
    println!(
        "      Deck state: cursor at {} of 52 ({} remaining)",
        deck.cursor(),
        deck.remaining()
    );
    println!();

    // -----------------------------------------------------------------
    // 4. Showdown receipt + chain-hash anchor
    // -----------------------------------------------------------------
    let receipt = ShowdownReceipt::from_deck_and_hand(&deck, winner_rank);
    println!("[4/9] Showdown receipt chain-hash anchor:");
    println!("      {}", hex32(&receipt.chain_hash()));
    println!("      (BLAKE3 over domain || deck_order || hand_rank_bytes)");
    println!();

    // -----------------------------------------------------------------
    // 5. Audience verification — anyone-runnable
    // -----------------------------------------------------------------
    println!("[5/9] Audience-side verification (pure functions):");

    // Path A — verify_shuffle_order: cursor-agnostic, ShowdownReceipt-facing.
    match verify_shuffle_order(&commitment, &seed, &receipt.deck_order) {
        Ok(()) => println!("      OK  verify_shuffle_order: receipt order valid"),
        Err(e) => println!("      ERR verify_shuffle_order: {e}"),
    }

    // Path B — verify_shuffle on the audience's local replay. Stage 1
    // (commitment binding) is the meaningful check; Stage 2 is a
    // deterministic-replay sanity check (we compare our replay against
    // itself). For protocols that broadcast a pre-deal Deck snapshot,
    // Path B audits that snapshot directly.
    let mut replay = Deck::standard();
    let mut replay_rng = RngSource::from_seed(&seed);
    replay.shuffle(&mut replay_rng);
    match verify_shuffle(&commitment, &seed, &replay) {
        Ok(()) => println!("      OK  verify_shuffle: pre-deal Deck reproducible"),
        Err(e) => println!("      ERR verify_shuffle: {e}"),
    }

    println!();

    // -----------------------------------------------------------------
    // 6. ArkheForge L1 integration — Action + Event pipeline
    // -----------------------------------------------------------------
    // The audience verification above is pure / off-runtime. Stage 6
    // demonstrates the *framework-side* path: the same showdown receipt
    // is fed into a `RecordHandShowdown` Action whose `compute()` body
    // re-runs the verification, recomputes the chain-hash, and emits a
    // `HandShowdownLanded` Event into the runtime pipeline. The drained
    // `EventRecord` carries the canonical chain-hash anchor that
    // downstream WAL append + observer pipelines pin verbatim.
    println!("[6/9] ArkheForge L1 integration:");

    let action = RecordHandShowdown {
        schema_version: 1,
        commitment: *commitment.as_bytes(),
        seed,
        deck_order: DeckOrderBytes::from_array(receipt.deck_order),
        hand_rank_bytes: winner_rank.to_chain_hash_bytes(),
    };

    // Educational fixture — a real shell layers manifest-driven authz +
    // idempotency dedup on top; here we just need a non-empty mask so
    // the L1 capability gate passes.
    let mut ctx = ActionContext::new(
        [0x11u8; 32],
        InstanceId::new(1).expect("InstanceId 1 is non-zero"),
        Tick(0),
        Principal::System,
        CapabilityMask::SYSTEM,
    );

    let l1_chain_hash = match process_action(&action, &mut ctx) {
        Ok(events) => {
            assert_eq!(events.len(), 1, "exactly one HandShowdownLanded expected");
            assert_eq!(
                events[0].type_code,
                HandShowdownLanded::TYPE_CODE,
                "drained Event must be HandShowdownLanded",
            );
            let landed: HandShowdownLanded = postcard::from_bytes(&events[0].payload)
                .expect("payload is a valid HandShowdownLanded");
            assert_eq!(
                landed.chain_hash,
                receipt.chain_hash(),
                "Action-emitted chain_hash must match audience-side ShowdownReceipt::chain_hash()",
            );
            println!("      OK  process_action: HandShowdownLanded event emitted");
            println!("          type_code  : 0x{:08X}", events[0].type_code);
            println!("          chain_hash : {}", hex32(&landed.chain_hash));
            Some(landed.chain_hash)
        }
        Err(e) => {
            println!("      ERR process_action: {e}");
            None
        }
    };

    println!();

    // -----------------------------------------------------------------
    // 7. ArkheForge L2 dispatch — RuntimeService end-to-end
    // -----------------------------------------------------------------
    // Stage 6 ran the L1 event-only pipeline. Stage 7 drives the same
    // Action through the L2 service layer: the `RuntimeService` wraps
    // an `arkhe_kernel::Kernel`, registers the Action, schedules a
    // submission, and steps the kernel once. The kernel's authorize →
    // dispatch → WAL append loop runs internally; the `StepReport`
    // confirms the action executed end-to-end.
    println!("[7/9] ArkheForge L2 RuntimeService dispatch:");

    let world_id = [0x11u8; 32];
    let manifest_digest = [0x22u8; 32];
    let mut service = RuntimeService::new(world_id, manifest_digest);
    service.register_action::<RecordHandShowdown>();
    let instance = service.create_instance(InstanceConfig::default());
    let report = service
        .dispatch(
            instance,
            Principal::System,
            &action,
            Tick(1),
            CapabilityMask::SYSTEM,
            // `RecordHandShowdown` is system-scoped (it never reads
            // `ctx.acting_actor`), so the system caller injects no actor.
            None,
        )
        .expect("dispatch must succeed");
    println!(
        "      StepReport: actions_executed={}, effects_applied={}, effects_denied={}",
        report.actions_executed, report.effects_applied, report.effects_denied,
    );
    assert_eq!(
        report.actions_executed, 1,
        "exactly one action executes per submit+step pair",
    );
    println!();

    // -----------------------------------------------------------------
    // 8. WAL export — answer "is the showdown actually written?"
    // -----------------------------------------------------------------
    // `RuntimeService::export_wal` consumes the service and returns the
    // kernel's internal `Wal`. Each `WalRecord` is then framed into a
    // `BufferedWalSink<Vec<u8>>` via `wal_to_sink` — the same streaming
    // sink that operator-side backup pipelines use for durable storage.
    // After flush the writer holds a self-describing byte stream
    // (magic `ARKHEXP1` + length-prefixed records).
    println!("[8/9] WAL export → BufferedWalSink:");

    let wal = service.export_wal().expect("WAL is configured");
    assert_eq!(wal.records.len(), 1, "one dispatch → one WAL record");
    let chain_tip = wal
        .records
        .last()
        .map(|r| r.this_chain_hash)
        .unwrap_or([0u8; 32]);
    println!(
        "      WAL: {} record(s), chain_tip = {}",
        wal.records.len(),
        hex32(&chain_tip),
    );

    let mut wal_buffer: Vec<u8> = Vec::new();
    {
        let mut sink = BufferedWalSink::new(&mut wal_buffer);
        wal_to_sink(&wal, &mut sink).expect("wal_to_sink must succeed");
    }
    println!(
        "      Sink: {} bytes appended (header `ARKHEXP1` + {} framed record(s))",
        wal_buffer.len(),
        wal.records.len(),
    );
    println!();

    // -----------------------------------------------------------------
    // 9. Streaming reader replay — round-trip verify
    // -----------------------------------------------------------------
    // The bytes from Stage 8 are read back through `StreamingWalReader`,
    // which de-frames the magic + length-prefixed payloads. Each
    // recovered record must postcard-decode to the same `WalRecord`
    // bytes the kernel originally emitted — the consumer-side proof of
    // the wire-format round-trip.
    println!("[9/9] Streaming WAL reader round-trip verify:");

    let mut reader =
        StreamingWalReader::open_v1(&wal_buffer[..]).expect("stream header `ARKHEXP1` must decode");
    let mut recovered: Vec<Vec<u8>> = Vec::new();
    while let Some(bytes) = reader.next_record().expect("framed record must decode") {
        recovered.push(bytes.to_vec());
    }
    assert_eq!(
        recovered.len(),
        wal.records.len(),
        "reader recovered the same record count",
    );
    for (i, (orig, back)) in wal.records.iter().zip(recovered.iter()).enumerate() {
        let orig_bytes = postcard::to_allocvec(orig).expect("re-encode original");
        assert_eq!(
            *back, orig_bytes,
            "record {i} must round-trip byte-identical",
        );
    }
    if let Some(landed_hash) = l1_chain_hash {
        // The L1-emitted chain_hash anchor and the L2 WAL chain are two
        // different cryptographic objects (BLAKE3 over distinct
        // domains), so byte equality is *not* expected. The continuity
        // we care about is that *both* paths anchor the same showdown:
        // anyone who sees Stage 6's chain_hash + Stage 8's WAL bytes
        // can reconstruct the receipt without trusting the dealer.
        println!("      L1 chain_hash anchor : {}", hex32(&landed_hash),);
    }
    println!("      L2 WAL chain tip      : {}", hex32(&chain_tip),);
    println!(
        "      OK  round-trip: {} record(s) recovered byte-identical",
        recovered.len()
    );
    println!();

    println!("Demo complete — the hand was provably fair: any audience");
    println!("member who saw the commitment up front can recompute every");
    println!("step from the revealed seed and confirm that the dealer");
    println!("could not have substituted a different shuffle after the");
    println!("commitment was broadcast. Stages 6-9 show the same anchor");
    println!("flowing through the runtime: L1 event pipeline (Stage 6),");
    println!("L2 RuntimeService kernel dispatch (Stage 7), WAL bytes");
    println!("durably framed (Stage 8), and round-trip-verified through");
    println!("the streaming reader (Stage 9).");
}
