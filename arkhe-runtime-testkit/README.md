# arkhe-runtime-testkit

**Property-based testing harness for [ArkheForge Runtime](../arkhe-forge).**

`proptest::Arbitrary` implementations plus a scope-based shrinker for the L1
primitives (`ShellId`, `TypeCode`, `Tick`, `EntityId`, …). Used by the Runtime
axiom tests (E1–E13 + per-primitive invariants).

## Layer

Dev-support crate. Consumed as a `[dev-dependencies]` entry by
`arkhe-forge-core` and shell test suites. Not intended for production code
paths.

## Why scope-based shrinking

TypeCode partitions the id space into Core / Shell / Debug scopes. A failure
near a scope boundary shrinks within its own scope so the minimal
counterexample keeps the original boundary, exposing the scope that actually
regressed. Naive range shrinking collapses the distinction.

## Quick start

```rust
use arkhe_runtime_testkit::arbitrary::ArbitraryTypeCode;
use proptest::prelude::*;

proptest! {
    #[test]
    fn typecode_roundtrip(tc in ArbitraryTypeCode::core_range()) {
        let bytes = postcard::to_allocvec(&tc).unwrap();
        let back: arkhe_kernel::abi::TypeCode = postcard::from_bytes(&bytes).unwrap();
        prop_assert_eq!(tc, back);
    }
}
```

## What's inside

- `arbitrary` — `Arbitrary` impls for Runtime primitives, plus scope-restricted
  strategies (`core_range`, `shell_range`, `debug_range`).
- `shrink` — structural shrinkers that preserve scope tags and field
  relationships.

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- API reference: <https://docs.rs/arkhe-runtime-testkit>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
