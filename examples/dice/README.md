# dice-forge

A provably-fair 3D6 dice example built on the ArkheForge L1 + L2 stack.
Each launch reads any prior `dice.wal`, prompts for a user seed, mixes
it with a fresh server seed via BLAKE3, rolls three dice through
`arkhe-rand::RngSource`, dispatches the result through
`arkhe-forge-platform::RuntimeService`, exports the WAL back to disk,
and prints the most recent five rolls in chronological order.

## Run

```sh
cargo run -p dice-forge
```

The binary prompts:

```
Commitment (server-side, broadcast pre-roll): <64 hex chars>
Enter your seed: Happy
```

Type any non-empty UTF-8 string up to 256 bytes (the cap keeps the
postcard payload size predictable). The roll is dispatched through the
forge runtime, the WAL is rewritten with the full canonical history,
and a table of the most recent five rolls prints to stdout:

```
─── Recent history (top 5) ─────────────────────────────────────
┌──────┬────────────────┬─────────────┬─────┬────────────┐
│  #   │ user_input     │ dice        │ sum │ chain_hash │
├──────┼────────────────┼─────────────┼─────┼────────────┤
│    1 │ Lucky          │ [3,5,2]     │  10 │ b13a8e51… │
│    2 │ Yolo           │ [6,6,3]     │  15 │ c24b9f62… │
│    3 │ Test           │ [2,4,5]     │  11 │ d35cab73… │
│    4 │ ABCabc         │ [5,3,1]     │   9 │ e46eaaf4… │
│    5 │ Happy          │ [4,1,6]     │  11 │ a02f9da8… │  ← NEW
└──────┴────────────────┴─────────────┴─────┴────────────┘
```

The `#` column is a 1-indexed display counter. The kernel-side `tick`
field is preserved in the WAL but hidden from this view; `--verify`
reports it in addition to the byte-equality check.

## Reset

```sh
cargo run -p dice-forge -- --reset
```

Deletes `examples/dice/dice.wal` (no-op if absent). The next launch
starts with an empty history.

## Verify

```sh
cargo run -p dice-forge -- --verify
```

Reads every record from `dice.wal`, re-dispatches them through a fresh
`RuntimeService`, exports the resulting WAL back into a buffer, and
asserts byte-equality against the on-disk file. A mismatch exits with
status 1; the chain-hash invariant catches in-record tampering during
the per-record dispatch (Stage 2 verify), and the byte-equality check
catches framing-layer tampering.

## How it works

1. **Server commit** — 32 OS-entropy bytes via direct
   `getrandom::getrandom`. The server broadcasts
   `BLAKE3(domain || server_seed)` *before* reading user input.
2. **User input** — interactive stdin, ≤256 bytes UTF-8 verbatim.
3. **Combined seed** — `BLAKE3(domain || server_seed ||
   user_input.as_bytes() || nonce.to_le_bytes())` where
   `nonce = history.len() as u64`. The PRF mixes both contributions
   so neither party alone can drive the dice.
4. **Roll** — `arkhe_rand::RngSource::from_seed(&combined_seed)`
   followed by three `gen_range_inclusive(rng, 1u32..=6)` calls.
5. **Reveal + verify** — the server seed lands in the WAL during
   dispatch, so an audience holding `dice.wal` can recompute the
   commitment, re-derive the combined seed, and replay the dice. The
   action body itself runs all four checks (commitment match,
   combined-seed match, dice match, chain-hash anchor) before emitting
   the `DiceRollLanded` event.

## Provably-fair pattern

Standard online-casino convention (Stake / BC.Game lineage): the
server commits to its seed before seeing the user input (so it cannot
adapt the seed to a known input), and the user provides their input
before the server reveals its seed (so they cannot predict the
combined seed). Because the combined seed is a function of both
contributions through a PRF, neither party alone determines the dice,
and any audience can verify both bindings from the WAL stream.

## BLAKE3 mode disclosure

Two BLAKE3 modes are used:

- **Generic mode** (`Hasher::new` + `update`) for the public binding
  hashes: `commitment_server`, `combined_seed`, and `chain_hash`.
  Generic mode is the right primitive for public commitments — they
  are not key-derivation material.
- **KDF mode** (`Hasher::new_derive_key("arkhe-rand stream v0.13")`)
  is used internally by `arkhe-rand::RngSource::from_seed`. The
  context string is version-pinned so any later stream-format change
  surfaces as an explicit version bump rather than a silent break in
  replay determinism.

Replay equivalence is **internal** to forge dice — same combined seed
under the same KDF mode produces byte-identical dice. Cross-impl
byte-identity with `ArkheKernel/examples/dice` (which uses an inline
generic-mode hash directly, no KDF) is **N/A by construction**: the
two implementations are structurally distinct PRFs even when their
input bytes happen to match.

## WAL tampering transparency

`dice.wal` is a local educational artifact. Tampering detection
inherits from the forge L1 chain-hash invariant — modified entries
break Stage 2 verify on the next replay (the dispatched action body
recomputes commitment + combined seed + dice and rejects mismatch).
This is example scope: production deployments would add (a) signed
entries via an operator-controlled key, (b) encryption at rest via a
KMS-managed DEK, and (c) filesystem-level integrity such as dm-verity
or sealed enclave storage. The commit-reveal protocol protects
against dealer-side seed substitution; it does **not** protect against
post-write file modification by parties with filesystem write access.

## UTF-8 handling

User input is captured as a Rust `String` (canonical UTF-8 byte view
via `String::as_bytes()`). The 256-byte cap operates on
`String::len()` (byte length, not character count) and rejects
oversize input rather than truncating, so the user always sees the
cap surface explicitly.

Note: `user_input` bytes are taken verbatim (no NFC normalization).
Visually-identical inputs with different Unicode encodings (e.g.,
precomposed "é" U+00E9 vs decomposed "e" + combining acute U+0301)
produce different `combined_seed` and therefore different dice. For
canonical user-input handling, normalize via the
`unicode-normalization` crate before passing to commit-binding.

## See also

- [`examples/card_primitives`](../card_primitives/) — richer
  commit-reveal context with a 52-card shuffle, 9-category Hold'em
  hand-rank evaluator, and a forge L1 integration showing the
  `RecordHandShowdown` Action / `HandShowdownLanded` Event pair.
- [`arkhe-rand`](../../arkhe-rand/) — the `RngSource` PRNG library
  that drives the dice roll under the hood.
