# arkhe-rand

BLAKE3-keyed PRNG with `split()` determinism — Lemire unbiased range +
Fisher-Yates shuffle. Shell-side use (kernel/runtime forbids RNG for
deterministic replay).

## Layer scope

`arkhe-rand` is an **L3 Library** tier crate per the ArkheForge layer
model (L0 Kernel / L1 Runtime Primitives / L2 Runtime Services /
L3 Library / L4-L6 Shell). The kernel and forge runtime forbid RNG to
preserve deterministic WAL replay; this crate is consumed only by
shell-side code (BBS, examples, downstream applications).

## Cryptographic core

Each `RngSource` wraps a BLAKE3 XOF stream constructed via the KDF
mode `Hasher::new_derive_key("arkhe-rand stream").update(seed)`. The
context string is a version-agnostic domain-separation tag: it scopes
the stream away from other BLAKE3 uses of the same seed, and is held
stable so stored seeds replay byte-identically.

XOF reader monotonic property is inherited from the `blake3` crate
spec, audited via the workspace `supply-chain/audits.toml` entry.

## API

| Surface | Role |
| :-- | :-- |
| `RngSource::from_seed(&[u8; 32])` | Deterministic constructor (KDF mode). |
| `RngSource::from_os_entropy()` | OS CSPRNG seeding via `getrandom` (default-on `os-entropy` feature). Returns `Result` — never panics. |
| `RngSource::split()` | Derive an independent child RNG; parent + child remain deterministic given the original seed. |
| `RngSource::fill_bytes(&mut [u8])` | Single entropy-consumption surface; monotonic stream advance. |
| `gen_range(rng, Range<T>)` | Lemire unbiased range over `T ∈ {u8, u16, u32, u64, usize}`. |
| `gen_range_inclusive(rng, RangeInclusive<T>)` | Inclusive variant; sources Fisher-Yates `[0, i]` samples. |
| `shuffle(rng, &mut [T])` | In-place Fisher-Yates; allocation 0. |

## Cross-platform determinism

Byte-to-integer conversions use explicit little-endian (`from_le_bytes`)
regardless of host endianness, so the same seed produces byte-identical
streams on x86_64 / aarch64 / wasm32. Two enforcement layers:

- **Golden-vector fixture** at `tests/golden/proof_rng_canonical_seq_v1.bin`
  (4 KiB). Version-pinned reproducibility anchor — byte-compared in
  `tests/golden_vector.rs`. CI re-runs this test under
  `--target {x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, wasm32-unknown-unknown}`.
- **Repository self-grep** that forbids native-endian conversion
  helpers in `arkhe-rand/src/` — expected 0 hits, run as part of the
  workflow-3 step 9.5 PCRE gate.

To regenerate the golden vector after a KDF context rotation:

```bash
ARKHE_RAND_REGEN_GOLDEN=1 cargo test -p arkhe-rand --test golden_vector
```

## Cargo features

| Flag | Pulls in | Role |
| :-- | :-- | :-- |
| `os-entropy` *(default)* | `getrandom` | Enables `RngSource::from_os_entropy()`. Disable for fully `#![no_std]` / no-`getrandom` targets that supply seeds externally. |

## Compile constraints

- `#![no_std]` + no `alloc` — runs on bare-metal and `wasm32-unknown-unknown`.
- `#![forbid(unsafe_code)]` — strictly stronger than `deny`. Audit
  surface is safe-Rust only.
- `Zeroize` + `ZeroizeOnDrop` — seed bytes are wiped on drop.
- Single-version pin `0.13.0` per the workspace policy.

## License

Dual MIT / Apache-2.0.
