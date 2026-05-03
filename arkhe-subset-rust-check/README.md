# arkhe-subset-rust-check

**R4-J Subset-Rust purity lint for [ArkheForge Runtime](../arkhe-forge).**

Enforces the **E14.L1 Compute Determinism Closure** axiom (v0.12 introduction):
`Action::compute` bodies must not call clock / RNG / file / network / FFI APIs.
This crate is the build-time AST checker that backs the `#[arkhe_pure]`
attribute macro shipped from `arkhe-forge-macros`.

## Layer

CI-support crate. Not consumed by runtime code paths.

## How it works

1. The shell author annotates `Action::compute` with `#[arkhe_pure]`.
2. The proc-macro receives the function token stream + parses with `syn`.
3. It calls `arkhe_subset_rust_check::check_purity(&item_fn, &policy)`.
4. The visitor walks every `ExprPath` / `ExprMethodCall` against the deny-list.
5. Each violation is emitted as a `compile_error!` at the source span.

## v0.12 first-cut deny list

| Category | Paths |
|---|---|
| Clock | `std::time::Instant::now`, `std::time::SystemTime::now`, `std::time::UNIX_EPOCH`, `chrono::Utc::now`, `chrono::Local::now` |
| RNG | `rand::random`, `rand::thread_rng`, `rand::rngs::OsRng`, `rand::rngs::ThreadRng`, `getrandom::getrandom` |

Cryptographer cross-review absorbed (Track A.1, 2026-04-25): I/O + FFI
prefix bans + `unsafe`-block ban shipped, plus `getrandom::fill` (0.3+
API), `rdrand::RdRand`, and the `minstant` / `quanta` / `coarsetime` /
`instant` / `tokio::time` clock-crate extensions. Round 2 (threading +
sync/atomic), Round 3 (replay hazards), and Round 4 (gray-area
re-examination) are non-breaking additive expansions tracked in
`test-corpus/e-axiom/e14-compute-determinism/INDEX.md`.

## Known limitation — single-ident suffix-match false-positive

The visitor matches a single-segment path (e.g. `thread_rng()`) by
scanning the deny-list for any entry ending in `::<ident>`. This catches
the common use-import escape (`use rand::thread_rng; thread_rng()`) but
also collides with a user-defined local fn of the same name. Mitigation:
use a fully-qualified path in shell code (`my_crate::random()` instead
of bare `random()`), or apply `Policy::empty()` and rely on a downstream
lint. Long-term — receiver-type aware HIR resolution lands with the
`dylint_linting` cdylib migration.

## Status

- **Current** — regular `lib` crate (sibling-pattern with `arkhe-trait-default-check`).
  `Policy`, `PurityViolation`, `check_purity` exposed; called by the
  `#[arkhe_pure]` attribute macro at compile time.
- **Planned** — switch to `cdylib`, adopt `dylint_linting::declare_late_lint!`,
  integrate the `rustc_lint` API for HIR-level name resolution. Same trajectory
  as `arkhe-trait-default-check`. Held until the workspace toolchain pin can
  be bifurcated (current pin = stable 1.80; dylint requires nightly).

## Quick start

```rust
use arkhe_subset_rust_check::{check_purity_v0_12, Policy};
use syn::parse_quote;

let f: syn::ItemFn = parse_quote! {
    fn compute(input: &[u8]) -> [u8; 32] {
        let now = std::time::Instant::now();        // <-- E14.L1 violation
        *blake3::hash(input).as_bytes()
    }
};
let violations = check_purity_v0_12(&f);
assert_eq!(violations.len(), 1);
assert!(violations[0].denied_path.contains("Instant::now"));
```

## Spec anchor

- E14 Compute Determinism Closure (v0.12 도입, MC) — Runtime axiom layer.
- **`Policy::v0_12_first_cut` ↔ E14.L1-Deny-v0_12** (spec canonical name).
- **WASM capability table ↔ E14.L2-Allow-v0_12** (Track B Hook host v2,
  paired enforcement of the E14 determinism contract).
- Sibling: `arkhe-trait-default-check` (theorist M7, default-body fingerprint).

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheKernel/runtime-book/>
- API reference: <https://docs.rs/arkhe-subset-rust-check>
- Repository: <https://github.com/aceamro/ArkheKernel>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
