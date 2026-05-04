# arkhe-forge-macros

**Runtime-layer derive macros for [ArkheForge Runtime](../arkhe-forge).**

Three procedural derives targeting the L1 traits in
[`arkhe-forge-core`](../arkhe-forge-core): `ArkheComponent`, `ArkheAction`,
`ArkheEvent`. Do not confuse with [`arkhe-macros`](../arkhe-macros), which
targets the L0 kernel traits.

## Layer

Companion proc-macro crate for `arkhe-forge-core`. Consumers normally pull the
derives through the core crate's re-export; direct use is reserved for
compile-fail tests and advanced shell authors.

## Derives

- `#[derive(ArkheComponent)]` — emits the sealed impl and pins
  `TYPE_CODE` / `SCHEMA_VERSION`.
- `#[derive(ArkheAction)]` — additionally pins `BAND ∈ {1, 2, 3}` and
  `IDEMPOTENT` (opt-in).
- `#[derive(ArkheEvent)]` — same shape as Component.

Compile-time validation enforces:

- `#[arkhe(type_code = N)]` sits in the correct spec §3.2 sub-range.
- First named field is `schema_version: u16` (wire version tag).
- `#[arkhe(band = K)]` present for `ArkheAction`, `K ∈ {1, 2, 3}`.
- `#[arkhe(idempotent)]` requires an `idempotency_key` field.
- `#[arkhe(canonical_sort)]` is allowed only on `Vec<T>` / `BTreeSet<T>` fields.

## Quick start

```rust
use arkhe_forge_core::ArkheComponent;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0001_0002)]
struct UserProfile {
    schema_version: u16,
    display_name: String,
}
```

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- API reference: <https://docs.rs/arkhe-forge-macros>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
