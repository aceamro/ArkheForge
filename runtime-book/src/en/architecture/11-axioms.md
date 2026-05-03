## §11. Axiom E-series — inheriting L0 A1-A24

### §11.1 Foundation

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E1** | Runtime core primitive set = {User, Actor, Space, Entry, Activity}. Additions require the §7.4 gate + a Runtime semver bump. | A15 | MACHINE-CHECKED |
| **E2** | Every Runtime Action `compute` inherits A11 pure. No I/O/rand/time. Hooks are pre-submit 1-shot + fold into canonical_bytes → the kernel never re-runs them + post-hook policy re-validation (§9.1). | A11 | MACHINE-CHECKED |
| **E3** | Runtime → L0 is strictly downward, one-way. L1 → L2 import is forbidden. | L0 R4-X | MACHINE-CHECKED |

### §11.2 Identity & multi-shell isolation (E7 dual-tier — B1)

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E4** | UserId is globally unique across the Runtime. ActorId is `(shell, handle)`, shell-unique. | A6 | TYPE-PROVEN |
| **E5** | Actor.user_id **and** Actor.shell_id are immutable after creation. SetComponent modifications are rejected. | A17 | MACHINE-CHECKED |
| **E6** | `Actor<_, Authenticated>` requires `UserBinding`. No `Actor<_, Anonymous>` exists. Typestate. | A11 | TYPE-PROVEN |
| **E7** | Shell isolation: an Activity `(actor, target)` / Entry `(author, space)` share the same shell. **Dual-tier**: (a) submit-site `ShellBrand<'s>` compile-time (TYPE-PROVEN). (b) Replay/admin compute `ctx.authenticated_actor_shell(actor) == target.shell_id` MC (RUNTIME-ASSERTED fallback). | A3, A19 | **TYPE-PROVEN (submit) + RUNTIME-ASSERTED (replay)** |

### §11.3 DAG integrity

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E8** | `Entry.parent_entry` / `Space.parent_space` are cycle-free **and depth ≤ 64**. O(1) via a depth Component cache. Parent is immutable after creation (P5). | A11 | MACHINE-CHECKED |
| **E9** | Activity self-loop is blocked + meta-verb depth ≤ `manifest.moderation.appeal_max_depth` (1..=8, default 2). Runtime hard cap 8. L1 compute MC. | A11 | MACHINE-CHECKED |

### §11.4 Federation-ready ID & cascade

| ID | Axiom | L0 lineage | Tier |
|---|---|---|---|
| **E10** | `ArkheUri<K: EntityKind>` is a 3-tuple `(instance, shell, local)` — only kind is phantom; the rest is runtime data. In a single instance, instance defaults. | A14 | TYPE-ADJACENT |
| **E11** | L2 post-event cascade re-submit uses `Op::ScheduleAction { at: Tick(t+1) }` bound to the original tick `t`. L0 scheduler imposes a deterministic order. | A23 | MACHINE-CHECKED |
| **E12** | The Runtime's `(runtime_semver, manifest_digest)` is chain-anchored via an in-band `RuntimeBootstrap` event in the WAL. On replay, a mismatch between the bootstrap event and the current load → `ReplayError::ManifestDrift` reject. The sidecar approach is retired — L0 chain-hash integrity is inherited to block backup-rewrite attacks (C2). | A1, A13 | MACHINE-CHECKED |
| **E13** | A shell's `[audit.signature_class]` is chain-anchored via an in-band `SignatureClassPolicy` event in the WAL. Audit receipts issued after the tick at which a given shell declared Hybrid must be Hybrid-signed — Ed25519-only receipts are rejected (blocks PQC Hybrid downgrade attacks, FG5). The verifier judges the message tag based on the shell-per-tick **sticky snapshot** of `SignatureClassPolicy` (monotone: once a shell declares Hybrid at tick T, all receipts at ticks ≥ T must be Hybrid-signed; the snapshot never reverts). | A13, A14 | MACHINE-CHECKED |
| **E14** | Every compute path contributing to the L0 chain hash — L1 `Action::compute()` and L2 Hook host v2 invocations — produces bit-identical output across replay on any conformant Runtime instance. Realisations: **E14.L1-Deny** = Subset-Rust 4-rule MVP deny-list (clock / RNG / I/O / FFI — the `unsafe` block ban is the FFI-rule mechanism that closes the `extern "C"` / raw-pointer / `transmute` escape route) enforced at build time via `arkhe-subset-rust-check` (deny-list mechanism) + `arkhe-forge-macros::arkhe_pure` (attribute policy) + `arkhe-trait-default-check` (MC coverage gate — workspace-wide scan asserting every `compute` impl carries the attribute, sharing the trait-default-body fingerprint scaffold per D-USER-4); **E14.L2-Allow** = host-import allow-list enforced at runtime via the wasmtime sandbox (NaN canonicalisation + SIMD opt-out + IEEE-754 strict + fuel-metering bounded execution). Violation surface is layer-specific: L1-Deny = `compile_error!` at build-time (no replay artifact); L2-Allow = `ReplayError::DeterminismViolation` at runtime + compute-path quarantine (L0 A22 inheritance). | A1, A11, A22 | **MACHINE-CHECKED (build-time L1) + MACHINE-CHECKED (runtime L2)** |
| **E15** | L2 observer sinks execute in a capability-bounded sandbox such that: **(a)** observer panic is contained at the sandbox boundary — the host catches the trap and emits an `ObserverQuarantine` event (TypeCode `0x0003_0F0C`); no native unwind reaches the L0 chain (L0 A22 strengthening). **(b)** Observer side-effects route exclusively through host-declared capability tokens (`ObserverCapToken` `#[non_exhaustive]` enum, v0.12 first variant `PgWrite`); direct syscalls and `wasi-{fs, sockets, clocks, random, io, cli, http}` are rejected at module-load. **Chain-non-affecting invariant (4-clause)**: (1) `arkhe:observer/*` host-fn bindings never call chain-mutation primitives; (2) every `ObserverCapability::execute` impl carries a `&[u8]` payload only — chain-orthogonal at type-level; (3) `ObserverQuarantine` emission is host-supervised — observer triggers via trap, host generates the receipt; (4) panic isolation preserves chain progression — next-tick chain hash is unaffected by observer existence or panic state. Violation surface = host-fn dispatch trap → `ObserverQuarantine` chain-anchored receipt + per-host trap counter increment. Detail surface: §14.5.2 Observer host v2. | A22 | **MACHINE-CHECKED (runtime sandbox-boundary)** |

**C3 vs C2 role separation (R5 NF9)**:
- **C2 (E12 WAL-level)** — **in-band events** such as `RuntimeBootstrap` / `SignatureClassPolicy` / `UserErasureCompleted` are included in the L0 chain hash (A13). Responsible for the integrity / anti-rewrite of the WAL itself. Tampering is detected by recomputing the chain during replay.
- **C3 (§12.4 projection-level)** — `kernel_projection_state.chain_tip_signature` signs **L2 projection rows** with Ed25519. Separate from the WAL, this detects tampering of the projection snapshot stored in PG. On restart/restore, MC compares the projection chain_tip against the L0 InstanceView chain tip.

The two paths are orthogonal: C2 is WAL bit-stream integrity, C3 is projection value integrity. Compromise scenarios separate — if only C2 breaks, chain hash mismatch is detected immediately; if only C3 breaks, recover by rebuilding the projection (the WAL is intact); if both break, restore from a backup snapshot.

### §11.5 Enforcement Tier distribution (recomputed at R5.1 / maintained through R5.2 / R5.3 / R5.4 — includes E13, includes E-act-7)

**Counting convention (R5 NF1, extended v0.12 cycle)**: `E1-E15` are 15 distinct axiom IDs — `E7` (dual-tier) / `E-act-2` (dual-tier) / `E14` (dual-realisation L1-Deny + L2-Allow) are **counted as 1 axiom each**, but the enforcement tier table records them as **two slots each** (submit/replay or build-time/runtime). Therefore the total slot count in the tier table exceeds the axiom count.

**Runtime E-axioms (E1-E15, 15 items)**:

| Tier | Slots | Members |
|---|---:|---|
| MACHINE-CHECKED | **12** | E1, E2, E3, E5, E8, E9, E11, E12, E13, E14-L1-Deny, E14-L2-Allow, E15 |
| TYPE-PROVEN | **3** | E4, E6, E7-submit |
| TYPE-ADJACENT | **1** | E10 |
| RUNTIME-ASSERTED | **1** | E7-replay (dual-tier fallback) |
| SOCIAL-CONTRACT | **0** | — |

Total slots 17 = 15 axioms + 1 extra dual-tier slot (E7) + 1 extra dual-realisation slot (E14).

**E7 change (R3 → R4')**: single MC → dual-tier (TP submit + RA replay). Removing the `SubmitActivity<'s>` lifetime lost the compile-time guarantee on the storage path; the compute MC double-defense compensates. Submit remains TP (ShellBrand). Extension targets gain compute MC (R4'.1 C1).

**E12 introduced (R4'.1 cryptographer C2)**: the sidecar-metadata approach is retired — on backup compromise, rewriting the sidecar could keep the chain hash while swapping `manifest_digest` → tampering with `SpaceKind::Extension` semantics. Instead, record `RuntimeBootstrap` as an in-band `Op::EmitEvent` → it is automatically included in the L0 chain hash. Respects DO NOT TOUCH #8 (WalRecord postcard field order) — integrity without modifying L0.

**E13 introduced (R5.1 cryptographer FG5)**: blocks `SignatureClass` downgrade attacks. An MC gate refuses Ed25519-only receipts after the tick at which a shell declared Hybrid — verifiers reconstruct a shell-per-tick snapshot from the `SignatureClassPolicy` events in the WAL and trust only the **chain-anchored policy**, not the message tag.

**E14 introduced (v0.12 sealing cycle — Track A.1 + Track B)**: Compute Determinism Closure axiom paired with L0 A1 (bit-identical replay). Single declarative axiom + two realisation slots (E14.L1-Deny build-time + E14.L2-Allow runtime). The two layers paired enforce the **dual contract** — non-deterministic *inputs* are rejected at L1 (clock / RNG / I/O / FFI / `unsafe`), non-deterministic *operations* at L2 (FP / SIMD / wasm-side threading).

**E15 introduced (v0.12 sealing cycle — Track A.2)**: Observer Capability Confinement axiom paired with L0 A22 (panic quarantine). Targets Adversary B (observer compromise spreading via native panic + uncontrolled syscall egress). E15 closes both vectors:
- **E15.a panic close** strengthens A22 — pre-E15, A22 quarantines AFTER native unwind; E15.a contains the trap at the wasmtime sandbox boundary BEFORE side-effects propagate, then host-supervised emission generates `ObserverQuarantine` (TypeCode `0x0003_0F0C`).
- **E15.b capability confinement** rejects unauthorised egress at module-load. Concrete `ObserverCapToken` set in v0.12 = `{PgWrite}`. Expansion is non-breaking per `implementation-plan.md` §6 (additive token enum). Future ecosystem-driven additions (KMS / metric / etc.) wait for BBS-dogfood evidence per the validated-repetition directive.

**Adversary B residual reduction (E14 dual)**: pre-E15, observer compromise spreads through native panic (A22 quarantines AFTER unwind, not BEFORE side-effects) and uncontrolled egress via direct syscalls. E15.a closes the native-crash channel; E15.b closes uncontrolled egress. Residual surface = (i) host-call API implementation defects (cryptographer + veteran scope — covered by the Track A.2 chain-non-affecting 4-clause invariant: no chain-mutation host-fn / chain-orthogonal trait signature / host-supervised emission / panic isolation preserves chain progression), (ii) wasmtime engine zero-day (out-of-scope per `implementation-plan.md` §19 — same exclusion as E14.L2). The reduction is conservative: any adversary path not in (i)/(ii) is closed by E15. Symmetric with Adversary A reduction under E14 — together E14 + E15 close the chain-affecting compute axis (Adversary A) and the chain-non-affecting observer axis (Adversary B) at the v0.12 cut.

- **E14.L1-Deny** (Track A.1) — build-time AST deny-list. Three-crate single-responsibility split (D-USER-4): `arkhe-subset-rust-check` (deny-list mechanism — `Policy::v0_12_first_cut` + AST visitor with `denied_paths` exact-match + `denied_prefixes` namespace match + `deny_unsafe` block ban) / `arkhe-forge-macros::arkhe_pure` (attribute policy — proc-macro that calls `check_purity_v0_12` and emits `compile_error!` per violation site, re-emitting the original fn unchanged on success) / `arkhe-trait-default-check` (MC coverage gate — workspace-wide syn-AST scan asserting every `impl ActionCompute for T { fn compute }` carries `#[arkhe_pure]`; failure is CI-red with the offending file + type printed; co-resident with the trait-default-body fingerprint scan since both are workspace-wide MC structural-invariant scans on the same dimension). Stable-toolchain syn-based path; the `dylint_linting` cdylib migration is documented as future-extension in the crate rustdoc, deferred because a nightly pin would conflict with the workspace stable rust-version 1.80 and the dual-feature gate.
- **E14.L2-Allow** (Track B) — runtime WASM sandbox. Hook host v2 wasmtime configuration: `cranelift_nan_canonicalization(true)` + `wasm_simd(false)` + IEEE-754 strict (Cranelift default) + fuel-metering bounded execution (per-invocation budget via `WasmtimeEngineConfig::fuel_budget`, default 10⁷ ≈ 10 ms; 1 M–100 M envelope; **fail-secure direction**) + host-import whitelist (`arkhe:hook/{state.{read,write}, emit.extra_bytes, fuel.consumed}` only — non-whitelisted imports rejected at module-load via three-layer defense: pre-scan + link-time deny-by-default + call-time capability check). Memory bounds-check on `(ptr, len)` host-fn deref via `read_caller_memory` helper (cryptographer-anchored sandbox-escape defense). 3-tier ingestion via `WasmtimeHookHost::register_module(bytes, expected_digest)`: Tier 1 BLAKE3 digest pin active in v0.12; Tier 2 sigstore + Tier 3 cargo-vet scaffolded via `HookAttestationVerifier` trait, default `Tier1OnlyVerifier` loud-rejects Tier 2/3 payloads to prevent confused-deputy migrations; `HookModuleRegister` chain event (TypeCode `0x0003_0F0B`) anchors per-registration receipts. Detail surface: §14.5.1 Hook host v2.

E14.L1-Deny v0.12 first-cut deny-list (4-rule MVP per cryptographer cross-review):
- Clock — `std::time::{Instant,SystemTime}::now`, `std::time::UNIX_EPOCH`, `chrono::{Utc,Local}::now`, `minstant::Instant::now`, `quanta::Clock::now`, `coarsetime::Instant::now`, `instant::Instant::now`, `tokio::time` (prefix).
- RNG — `rand::random`, `rand::thread_rng`, `rand::rngs::{OsRng,ThreadRng}`, `getrandom::{getrandom,fill}`, `rdrand::RdRand`.
- I/O — namespace prefixes `std::{fs,net,process,env}` plus the `std::io::{stdin,stdout,stderr}` exact entries, `tokio::{fs,net,io}`, `async_std::{fs,net,io,task}`, `mio`, `socket2`.
- FFI — namespace prefix `libc` plus an `unsafe { ... }` block ban that closes the `extern "C"` / raw-pointer / `transmute` escape route.

Round 2/3/4 expansions (threading + sync/atomic + replay hazards + gray-area `lazy_static!`/`OnceCell`) are non-breaking additive entries tracked in `test-corpus/e-axiom/e14-compute-determinism/INDEX.md`.

**Per-primitive invariants** (E-user-* 4 + E-actor-* 5 + E-space-* 7 + E-entry-* 7 + E-act-* 7 = **30 items**):

| Tier | Slots | Members |
|---|---:|---|
| MACHINE-CHECKED | **25** | E-user-1/2, E-actor-1/3/5, E-space-1~7, E-entry-1~7, E-act-1/4/5/6/7, E-act-2-Extension-submit (NF2 dual-tier submit slot) |
| TYPE-PROVEN | **3** | E-user-4 (A6 NonZeroU64), E-actor-2 (typestate), E-actor-4 (`'s` brand) |
| TYPE-ADJACENT | **1** | E-act-3 (extra_bytes opaque) |
| RUNTIME-ASSERTED | **2** | E-user-3 (GDPR cascade SLA §14.9), E-act-2-replay (dual-tier fallback) |
| SOCIAL-CONTRACT | 0 | — |

Total slots 31 = 30 invariants + 1 extra dual-tier slot (E-act-2 Extension submit MC + replay RA, per NF2 counting convention).

**Total 44 Runtime axioms/invariants** (E1-E14 + per-primitive 30). Progression R2 → R3 → R4' → R4'.1 → R5.1 → R5.2 → R5.3 → R5.4 → v0.12 sealing cycle:
- R2→R3: E7 MC → dual-tier (honesty).
- R3→R4': E9 parametric (I3) / E-act-1 C2 re-statement / E-user-3 compute gate C3 / E-space/entry 7-7 extension P5.
- R4'→R4'.1: E12 introduced (in-band RuntimeBootstrap, sidecar retired) / E-act-2 Extension MC extended (C1, dual-tier retained) / E-user-3 crypto-erasure SLA extended (M5).
- R4'.1→R5.1: **E13 introduced** (SignatureClassPolicy chain-anchored, blocks PQC downgrade) / **E-act-7 introduced** (EntityShellId immutable, R5-r1) / `RuntimeSignatureClass` kept as a separate Runtime enum to protect L0 DO NOT TOUCH #3 (M-R5-1).
- **R5.1→R5.2**: **no change** to axiom / invariant counts. Existing tier slots retained. Additions are at the level of policy / runbook / type traits (sealed PiiType) / event structs (`PerRegionErasureProgress` 0x0003_0F08) / manifest validation — no axiom expansion. `E-user-3` RA's SLA scope is made concrete for multi-region 2PC (GF4) but the tier stays RA. `E13`'s MC enforcement scope extends to the `aead_kind` + `pii_cipher` manifest-anchored check (GF2) — tier stays MC.
- **R5.2→R5.3**: **no change** to axiom / invariant counts. 43 items / 45 slots unchanged. Reflects R7 Major 3 + Minor 12 at the level of policy (`alpha_credential_rotation_required` / auto_promote trust model) / trait sealed (`ArkheEvent` made explicit) / derive attribute opt-in (`#[arkhe(canonical_sort)]`) / metrics (`arkhe_runtime_event_total` / `kms_health_channels`) / event struct wire refinement (`PerRegionErasureProgress.scope: ProgressScope`, N=64) / runbook deliverables. Tier slots and axiom statements are unchanged. Minor 3 deferred (see §1.5 R7 section).
- **R5.3→R5.4**: **no change** to axiom / invariant counts. 43 items / 45 slots unchanged. After R8 verification (Critical 0 / Major 0 / 5 new Minor), a leader-housekeeping micro-patch — L0 version notation consistency (§14.8 `L0 v0.12+` → `L0 v0.13+`) / 2 SLO table rows (GdprPolicyViolation rate + kms_health_channels N-of-M) / alpha-to-beta-promote runbook deliverable registration / new v0.12 implementation tracking table (HF1 platform abstraction + HF4 manifest bypass audit). No impact on spec body structure / axioms / the 8 DO NOT TOUCH items. N=2 consecutive clean achieved.
- **R5.4→v0.12 sealing cycle (Track A.1 + Track B)**: **E14 introduced** (Compute Determinism Closure, dual-realisation L1-Deny + L2-Allow, both MC). +1 axiom / +2 slots. 44 items / 47 slots. Track A.1 ships E14.L1-Deny via the 3-crate D-USER-4 split (`arkhe-subset-rust-check` + `arkhe-forge-macros::arkhe_pure` + `arkhe-trait-default-check`); Track B ships E14.L2-Allow via the wasmtime Hook host v2 sandbox in a subsequent commit batch. Per-primitive invariants unchanged (30 items / 31 slots).
- **v0.12 cycle (Track A.2)**: **E15 introduced** (Observer Capability Confinement, single MC slot — no dual-realisation). +1 axiom / +1 slot. 45 items / 48 slots. Track A.2 ships E15.a (panic close — observer trap → host-supervised `ObserverQuarantine` chain-anchored receipt) + E15.b (capability-token interface — `ObserverCapToken` enum + `ObserverCapability` trait, v0.12 single concrete impl `PgWriteCapability`) via the wasmtime Observer host v2 sandbox in `arkhe-forge-platform/src/observer_host/`. Per-primitive invariants unchanged (30 items / 31 slots).

### §11.6 "Non-axioms" — intentional blanks

- No Band 2/3 axiom — policy / marker attribute (§9).
- No Actor signature axiom — shell choice.
- No rate-limit axiom — L2 policy.
- No federation protocol axiom — E10 is an ID structure.
- No MMORPG tick-sync state axiom — scope refusal.

---

