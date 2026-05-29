# arkhe-subset-rust-check

**Subset-Rust purity lint for [ArkheForge Runtime](../arkhe-forge).**

Enforces the **E14.L1 Compute Determinism Closure** axiom: `Action::compute`
bodies must not call clock / RNG / file / network / FFI APIs. This crate is
the build-time AST checker that backs the `#[arkhe_pure]` attribute macro
shipped from `arkhe-forge-macros`.

## Layer

CI-support crate. Not consumed by runtime code paths.

## How it works

1. The shell author annotates `Action::compute` with `#[arkhe_pure]`.
2. The proc-macro receives the function token stream + parses with `syn`.
3. It calls `arkhe_subset_rust_check::check_purity(&item_fn, &policy)`.
4. The visitor walks every `ExprPath` / `ExprMethodCall` against the deny-list.
5. Each violation is emitted as a `compile_error!` at the source span.

## Default deny list

| Category | Paths |
|---|---|
| Clock | `std::time::Instant::now`, `std::time::SystemTime::now`, `std::time::UNIX_EPOCH`, `chrono::Utc::now`, `chrono::Local::now`, plus the `minstant` / `quanta` / `coarsetime` / `instant` / `tokio::time` clock-crate extensions |
| RNG | `rand::random`, `rand::thread_rng`, `rand::rngs::OsRng`, `rand::rngs::ThreadRng`, `getrandom::getrandom`, `getrandom::fill`, `rdrand::RdRand` |
| I/O + FFI | path-prefix bans + `unsafe`-block ban |

Threading + sync / atomic surfaces, replay hazards, and gray-area cases
are out of scope for the current deny-list — they surface as proptest
regressions that callers add to their own crate's test suites when
they hit them.

## Known limitation — single-ident suffix-match false-positive

The visitor matches a single-segment path (e.g. `thread_rng()`) by
scanning the deny-list for any entry ending in `::<ident>`. This catches
the common use-import escape (`use rand::thread_rng; thread_rng()`) but
also collides with a user-defined local fn of the same name. Mitigation:
use a fully-qualified path in shell code (`my_crate::random()` instead
of bare `random()`), or apply `Policy::empty()` and rely on a downstream
lint. Receiver-type aware HIR resolution would require the
`dylint_linting` cdylib alternative described below.

## Architecture

Regular `lib` crate exposing `Policy` / `PurityViolation` / `check_purity`,
called by the `#[arkhe_pure]` attribute macro at compile time. Pairs with
`arkhe-trait-default-check` on the same regular-lib pattern. The dylint
cdylib + driver alternative (adopt `dylint_linting::declare_late_lint!`,
integrate the `rustc_lint` API for HIR-level name resolution) is documented
in `src/lib.rs` rustdoc; the regular lib path is preferred here because
dylint requires nightly while the workspace toolchain is pinned to stable.

## Quick start

```rust
use arkhe_subset_rust_check::{check_purity_default, Policy};
use syn::parse_quote;

let f: syn::ItemFn = parse_quote! {
    fn compute(input: &[u8]) -> [u8; 32] {
        let now = std::time::Instant::now();        // <-- E14.L1 violation
        *blake3::hash(input).as_bytes()
    }
};
let violations = check_purity_default(&f);
assert_eq!(violations.len(), 1);
assert!(violations[0].denied_path.contains("Instant::now"));
```

## Spec anchor

- E14 Compute Determinism Closure (MC) — Runtime axiom layer.
- **`Policy::deny_compute_impurity` ↔ E14.L1-Deny** (spec canonical name) —
  the build-time AST deny-list this crate enforces.
- Pair crate: `arkhe-trait-default-check` (default-body fingerprint).

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
