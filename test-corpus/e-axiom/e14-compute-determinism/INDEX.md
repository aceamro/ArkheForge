# E14 Compute Determinism Closure — R4-J Subset-Rust cross-ref

**Spec**: §11.x E14 (v0.12 도입, MC). Two realisations:

- **E14.L1-Deny** — build-time AST deny-list (`arkhe-subset-rust-check`,
  Track A.1). This INDEX maps the v0.12 first-cut deny-list categories
  to the AST-visitor unit tests inside the crate.
- **E14.L2-Allow** — runtime host-import allow-list (WASM capability
  table, Track B). v0.12 Hook host v2 — separate INDEX.

Auditor cross-review (Track A.1 verification design) requested this
single source of truth so axiom auditors find the test→rule mapping in
one place; the actual test bodies live with the crate (ecosystem
convention) rather than duplicated under `test-corpus/`.

---

## E14.L1-Deny — v0.12 first cut (4-rule MVP)

Crate: [`arkhe-subset-rust-check`](../../../arkhe-subset-rust-check) — embedded
unit tests in `src/lib.rs` mod `tests`. Run via `cargo test -p
arkhe-subset-rust-check`.

| Category | Rule scope | Test names (positive + negative) |
|---|---|---|
| **Clock** | `std::time::*::now`, `std::time::UNIX_EPOCH`, `chrono::*::now`, `minstant::*::now`, `quanta::Clock::now`, `coarsetime::*::now`, `instant::Instant::now`, `tokio::time::*` | `instant_now_full_path_rejected`, `unix_epoch_constant_access_rejected`, `tokio_time_prefix_rejected`, `pure_compute_passes_v0_12` (negative-only check), `type_position_path_does_not_match`, `shell_defined_now_method_does_not_match` |
| **RNG** | `rand::random`, `rand::thread_rng`, `rand::rngs::{OsRng,ThreadRng}`, `getrandom::getrandom`, `rdrand::RdRand` | `os_rng_full_path_rejected`, `use_imported_thread_rng_single_ident_rejected` |
| **I/O** | namespace prefixes — `std::{fs,net,process,env,io::stdin/out/err}`, `tokio::{fs,net,io,time}`, `async_std::{fs,net,io,task}`, `mio`, `socket2` | `fs_namespace_prefix_rejected`, `net_namespace_prefix_rejected`, `process_namespace_prefix_rejected`, `env_namespace_prefix_rejected` |
| **FFI** | namespace prefix `libc` + `unsafe { ... }` block ban | `libc_namespace_prefix_rejected`, `unsafe_block_rejected` |

Plus harness tests: `pure_with_blake3_passes` (deterministic crypto must
NOT trigger), `empty_policy_accepts_anything` (Policy::empty escape
hatch), `classify_reason_categorises_correctly` (reason category
mapping).

End-to-end via `#[arkhe_pure]` proc-macro (`arkhe-forge-macros`):
`pure_add_smoke`, `pure_array_smoke`, `pure_with_blake3_smoke` in
`arkhe-forge-macros/tests/pure_macro.rs`.

---

## Round expansion roadmap (cryptographer Round 2 / 3 / 4)

Non-breaking additions to `Policy::v0_12_first_cut`:

| Round | Rules |
|---|---|
| **MVP (v0.12)** | Clock + RNG + I/O + FFI — landed |
| Round 2 | Threading (`std::thread::*`, `tokio::spawn`, `rayon::*`, `crossbeam::scope`), Sync/atomic (`std::sync::*`, `std::sync::atomic::*`) |
| Round 3 | Replay hazards (`Box::leak`, `std::panic::catch_unwind`, `backtrace::*`), `unsafe` escape-hatch attribute (`#[arkhe(unsafe_audit_cleared = "ticket-id")]`) |
| Round 4 | Gray-area re-examination (`lazy_static!`, `once_cell::*`, `OnceCell`) — first-call timing hazard inside `Action::compute` |

---

## Coverage assertion at sealing-cut

Per auditor cross-review (Option γ, leader retroactive adoption): a
workspace-wide scan extends `arkhe-trait-default-check` with a second
visitor — every `impl ActionCompute for T { fn compute(...) }` block in
the workspace must carry `#[arkhe_pure]` on the compute method. CI-red
on miss. Co-resident with the trait-default-body fingerprint scan since
both are workspace-wide MC structural-invariant scans on the same
dimension (D-USER-4 reframed).

Test entry: `arkhe-trait-default-check/tests/action_compute_coverage.rs`
(`all_action_compute_impls_have_arkhe_pure`). Sealed-trait closure
(`ActionCompute: __Sealed + ArkheAction`) means hand-rolled trait impls
outside the workspace cannot exist — coverage is total over the trait's
extension surface.

Forward note (auditor): macro-expanded `ActionCompute` impls are not
visible to the source-level syn scan. None exist today; if a future
derive emits compute bodies, either the new derive must auto-emit
`#[arkhe_pure]` on the compute method or the scanner needs cargo-expand
integration. v0.13+ candidate.

---

## Convention

This INDEX is read-only metadata. The test sources of truth are:

- `arkhe-subset-rust-check/src/lib.rs` — AST-visitor unit tests
- `arkhe-forge-macros/tests/pure_macro.rs` — `#[arkhe_pure]` smoke tests

Failure cases discovered during proptest fuzzing (v0.13+ candidate per
auditor) will land here as standard `.case` files following the
top-level `test-corpus/README.md` convention.
