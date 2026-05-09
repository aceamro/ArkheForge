# arkhe-trait-default-check

**Trait default-body fingerprint lint for [ArkheForge Runtime](../arkhe-forge).**

Enforces the "Minor-1 breaking change" rule: a semantic change to a
trait's default method body is a breaking change, even when the signature is
unchanged. This crate detects such changes in CI by hashing the AST of each
default body and comparing against a baseline.

## Layer

CI-support crate. Not consumed by runtime code paths.

## How it works

1. Parse the target crate's `impl` items with `syn`.
2. Extract each default method body, normalize whitespace / comments.
3. BLAKE3-hash the canonical byte sequence — the **body fingerprint**.
4. Diff against `ci/trait-default-fingerprints.txt`. A mismatch fails CI.

## Architecture

Regular `lib` crate exposing `TraitDefaultFingerprint` + `hash_default_body`
on the workspace stable toolchain pin. The dylint cdylib + driver
alternative (adopt `dylint_linting::declare_late_lint!`, integrate the
`rustc_lint` API, invoke via `cargo dylint`) is recorded in `src/lib.rs`
rustdoc as an alternative architecture; the regular lib path is preferred
here because dylint requires nightly and the workspace toolchain is
pinned to stable.

## Quick start

```rust
use arkhe_trait_default_check::hash_default_body;
use syn::parse_quote;

let item: syn::ItemImpl = parse_quote! {
    impl MyTrait for MyType {
        fn canonical_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).unwrap() }
    }
};
let fps = hash_default_body(&item);
assert_eq!(fps[0].method_name, "canonical_bytes");
assert_eq!(fps[0].body_hash.len(), 64); // BLAKE3 hex
```

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
