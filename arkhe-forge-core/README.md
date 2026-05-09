# arkhe-forge-core

**L1 primitives for [ArkheForge Runtime](../arkhe-forge).**

Core 5 primitive types (User / Actor / Space / Entry / Activity), sealed
`ArkheComponent` / `ArkheAction` / `ArkheEvent` traits, `ShellBrand<'s>`
invariant-lifetime isolation, deterministic entity-id derivation. Pure compute —
no I/O, no time, no randomness.

## Layer

L1 of the Arkhe stack. Depends on `arkhe-kernel` (L0) and
`arkhe-macros` (derive provider). Does not depend on L2 `arkhe-forge-platform`
(layer-independence directive). Shell authors typically consume it through the
[`arkhe-forge`](../arkhe-forge) umbrella crate rather than directly.

## Core 5 primitives

- `User` — end-user identity (ActivityPub-hybrid).
- `Actor<'s, S>` — addressable runtime actor, tagged by `ShellBrand<'s>`.
- `Space` — bounded region with policy / membership.
- `Entry` — content-addressed post / object.
- `Activity` — verb record in the Activity pipeline.

## Quick start

```rust
use arkhe_forge_core::{derive_entity_id, MAX_ID_DERIVE_RETRIES};
use arkhe_kernel::abi::{InstanceId, Tick, TypeCode};

let world_seed = [0x42u8; 32];
let instance = InstanceId::new(1).unwrap();
let id = derive_entity_id(
    &world_seed,
    instance,
    TypeCode(0x0001_0001),
    Tick(42),
    0,
)
.expect("non-zero digest within MAX_ID_DERIVE_RETRIES");
```

## Key concepts

- **3-band determinism** — Core (L0 bit-identical) / Projection (eventually
  consistent) / Protocol-Correctness (shell-level).
- **Invariant-lifetime shell brand** — `Actor<'s, S>` types of two shells never
  unify; cross-shell contamination fails to compile.
- **TypeCode allocation** — 32-bit range partitioned into Core / Shell / Debug
  scopes; shell ranges isolated from upstream churn.
- **Axioms** — E1–E13 plus 30 per-primitive invariants enforced by
  `arkhe-runtime-testkit` property tests.
- **Sealed derives** — `#[derive(ArkheAction | ArkheComponent | ArkheEvent)]`
  from [`arkhe-forge-macros`](../arkhe-forge-macros); re-exported here.

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
