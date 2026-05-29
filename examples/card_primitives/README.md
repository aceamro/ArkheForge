# card-primitives

A reference example showing how a domain-specific consumer crate plugs
into the ArkheForge framework. The Hold'em-side primitives (packed
`Card` byte form, cursor-based `Deck`, 9-category `HandRank`
evaluator, BLAKE3 commit-reveal) are the demo vehicle; the
forge-integration glue (`#[derive(ArkheAction)]` /
`#[derive(ArkheEvent)]`, `RuntimeService::dispatch`, `BufferedWalSink`
+ `StreamingWalReader` round-trip) is what the example actually
proves.

A single launch runs nine numbered stages end-to-end: dealer commits
to a shuffle seed, deals a 2-player hand, reveals the seed, the
audience-side `verify_shuffle` / `verify_shuffle_order` functions
recompute every step, and the same showdown then flows through the
forge L1 event pipeline (Stage 6), the L2 `RuntimeService` kernel
dispatch loop (Stage 7), the framed `BufferedWalSink` byte stream
(Stage 8), and a streaming reader round-trip that asserts each
record decodes byte-identical to the original (Stage 9).

## Run

```sh
cargo run -p card-primitives
```

Each stage prints its own `[N/9]` banner with the relevant artefacts
(commitment hash, deal sequence, hand-rank verdict, chain-hash
anchor, L1 event payload, L2 `StepReport`, WAL framing bytes,
round-trip diff). The demo body is non-interactive — it executes a
deterministic 2-player hand from a fixed seed so the output is
reproducible launch-to-launch.

## Modules

The five supporting modules build bottom-up to `main.rs`:

- **`card`** — `Card(u8)` packed byte form (4-bit `Suit` + 4-bit `Rank`
  in a single byte) plus the `Rank` / `Suit` enums and the `CardError`
  taxonomy that `Card::from_byte` returns when the byte is not in the
  canonical 0..=51 range.
- **`deck`** — `Deck { cards: [Card; 52], cursor: usize }`. The
  `shuffle(&mut self, rng: &mut RngSource)` method runs in-place
  Fisher-Yates against `arkhe-rand`'s unbiased
  `gen_range_inclusive`, so the post-shuffle order is fully
  determined by the `RngSource` seed. `draw()` advances the cursor
  rather than reallocating the underlying array.
- **`hand_eval`** — `HandRank` is a 9-variant enum (Royal Flush, Straight
  Flush, Four of a Kind, … High Card). `evaluate_5` and `evaluate_7`
  compute the best rank from a pocket+board view and `compare_hands`
  gives a total order.
- **`shuffle_proof`** — the commit-reveal core. `ShuffleCommitment::from_seed`
  computes `BLAKE3(DOMAIN_COMMIT || seed)`; `verify_shuffle` /
  `verify_shuffle_order` re-derive the post-shuffle deck from the
  revealed seed and check it against the audience-visible deal;
  `ShowdownReceipt::chain_hash` pins
  `BLAKE3(DOMAIN_SHOWDOWN || deck_order || hand_rank.to_chain_hash_bytes())`
  as a 32-byte anchor for the whole hand.
- **`forge_integration`** — defines `RecordHandShowdown`
  (`#[derive(ArkheAction)]`) and `HandShowdownLanded`
  (`#[derive(ArkheEvent)]`). The action's `compute()` re-runs Stage 1
  (commitment binding), Stage 2 (replay reproducibility), Stage 3
  (chain-hash recomputation) inside the runtime so the L1 event
  payload anchors the same byte-for-byte digest the audience
  computed off-runtime.

## How it works

Stage-by-stage breakdown, anchored to `main.rs:79..344`:

1. **Dealer broadcast** — pick a 32-byte seed, compute
   `ShuffleCommitment::from_seed(&seed)`, broadcast the 32-byte
   commitment hash. Players act on the commitment alone.
2. **Deal sequence** — `Deck::standard().shuffle(&mut RngSource::from_seed(&seed))`
   followed by `draw()` for the two pocket pairs, the flop, turn,
   and river. The cursor-based deck means the deal is just five
   sequential cursor advances.
3. **Showdown evaluation** — `evaluate_7` runs against each player's
   `[2 pocket; 5 board]` view; `compare_hands` decides the winner.
4. **Receipt + chain-hash anchor** — `ShowdownReceipt::from_deck_and_hand`
   captures the canonical 52-byte deck order plus the winner's
   `HandRank`; `chain_hash()` pins the 32-byte anchor.
5. **Audience verify** — `verify_shuffle` (deck-aware) and
   `verify_shuffle_order` (byte-array aware) recompute the
   post-shuffle order from the revealed seed and confirm it matches
   the deal anybody saw. These are pure functions — no kernel, no
   I/O.
6. **Forge L1 integration** — `RecordHandShowdown::compute` re-runs
   Stages 1+2+3 inside the L1 pipeline via
   `arkhe_forge_core::pipeline::process_action`; the emitted
   `HandShowdownLanded` event payload contains the same
   `chain_hash` the audience computed off-runtime.
7. **Forge L2 dispatch** — the same `RecordHandShowdown` action goes
   through `RuntimeService::dispatch`, which submits it to the
   kernel, runs the `step()` authorize → execute → WAL append loop,
   and returns a `StepReport` (`actions_executed=1`,
   `effects_applied=1`).
8. **WAL export** — `service.export_wal()` consumes the kernel and
   yields a `Wal` value; `wal_to_sink(&wal, &mut BufferedWalSink::new(&mut Vec<u8>))`
   writes the canonical `ARKHEXP1` framed stream into a byte buffer.
9. **Streaming round-trip** — those bytes are read back through
   `StreamingWalReader::open_v1`; each recovered `WalRecord`
   postcard-decodes to byte-identical bytes against the original.

## Provably-fair shuffle

The commit-reveal protocol is the audit anchor. Because the dealer
broadcasts `BLAKE3(DOMAIN_COMMIT || seed)` *before* the deal, and
the seed is revealed only post-deal, BLAKE3 collision resistance
binds the dealer to the seed they actually used: any after-the-fact
seed substitution would yield a different commitment, which audience
members already hold. The `verify_shuffle_order` routine then runs
the same in-place Fisher-Yates against the revealed seed, and
byte-equal output proves the deal was not re-ordered.

## ArkheForge framework integration

The example demonstrates four distinct framework surfaces:

- **Sealed traits.** `ArkheAction` / `ArkheEvent` are sealed —
  `__Sealed`-bound — so only types produced by `#[derive(...)]`
  satisfy the bound. A consumer crate (this example) producing such
  impls confirms the derive-from-external-crate path is open.
- **L1 pipeline determinism.** `process_action` runs
  `compute()` and drains the per-tick `EventRecord` buffer; the
  same `(action, ctx)` produces byte-identical event payloads.
  Verified by the `replay_determinism_event_payload_byte_identical`
  integration test under `tests/`.
- **L2 dispatch loop.** `RuntimeService::dispatch` wraps the kernel's
  `submit` → `step` cycle behind a forge-shaped API; the same
  Action that drove the L1 pipeline also drives the kernel's WAL
  append.
- **WAL round-trip.** `BufferedWalSink` (the sole `pub` write path)
  pairs with `StreamingWalReader` to give the audience a portable
  byte stream to verify against. The append-only invariant is
  enforced inside the sink.

## BLAKE3 mode disclosure

Two BLAKE3 modes appear:

- **Generic mode** (`Hasher::new` + `update`) for the public bindings:
  `ShuffleCommitment::from_seed`, `ShowdownReceipt::chain_hash`, and
  the `RecordHandShowdown::compute` body. Generic mode is the right
  primitive for public commitments — they are not key-derivation
  material.
- **KDF mode** (`Hasher::new_derive_key("arkhe-rand stream")`)
  is used internally by `arkhe-rand::RngSource::from_seed`. The
  context string is version-pinned; any later stream-format change
  surfaces as an explicit version bump rather than a silent break in
  shuffle determinism.

## Tests

- **`tests/forge_integration.rs`** — covers the L1 pipeline
  end-to-end: replay determinism, event payload byte-identity,
  chain-hash continuity between `ShowdownReceipt::chain_hash()` and
  the emitted `HandShowdownLanded.chain_hash`.
- **`tests/statistical_rng_suite.rs`** — runs a 14-test NIST
  SP 800-22 subset against the shuffle bit stream as an end-to-end
  check that the `arkhe-rand` integration carries the expected
  uniformity through the deck shuffle path.

```sh
cargo test -p card-primitives
```

## See also

- [`arkhe-rand`](../../arkhe-rand/) — the BLAKE3-keyed PRNG that
  drives the shuffle. Its `from_seed`/`gen_range_inclusive`/`shuffle`
  surface is the only RNG entry point used here.
- [`examples/dice`](../dice/) — a smaller sibling demo (3D6
  provably-fair dice) that uses the same `RngSource` plus a single
  `RecordDiceRoll` Action, with persistent multi-run history in
  `dice.wal`.
- [`arkhe-forge`](../../arkhe-forge/) — the umbrella crate that
  re-exports the L1 + L2 surface this example consumes.
