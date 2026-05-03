# Runtime sealing plan — v0.12 cut

**Status**: planning, pre-DIP. **Source session**: 2026-04-25. **Target cut**: `v0.12`. **L0 sealed at `v0.11` (`7d66c47`) — DO NOT TOUCH.**

This document defines what reaching **L0-grade sealed completeness for the Runtime** (L1 + L2) requires, organised as 8 work tracks (A-H) anchored on two new axioms (E14 + E15). After v0.12 is cut, the Runtime layer joins L0 in DO-NOT-TOUCH status; subsequent evolution happens in Shell ecosystems (separate repos) or in dev-tools / runtime-testkit / docs.

The plan input was a multi-axis review by the architect, auditor, and cryptographer. User decisions on three open questions are recorded in the [decision register](#decision-register).

---

## 1. Why v0.12

L0 reached its sealed cut at `v0.11` (axiom set A1-A24 + S1, dual-feature gate green, external Round R1-R5 + R4'.1 closed). The Runtime, however, ships at v0.11 with two acknowledged residuals on its design surface:

1. **`Action::compute()` determinism is SOCIAL-CONTRACT.** Rust cannot reject `std::time::Instant::now()` inside a trait impl body; the spec acknowledges this as Adversary A's *residual surface* (`book/src/en/architecture/threat-model.md`).
2. **L2 Hook host is OFF.** The `§5.3` dataflow diagram includes the box but spec `§14.5` declares all hooks disabled in v1 alpha, with v2 reintroduction conditioned on a WASI sandbox + budget + capability gating.

These two residuals, plus four drift-catalogued spec gaps, four forward-looking adversary surfaces, and a release-gate readiness deficit identified in this review, form the v0.12 sealing scope. The directive driving this scope is the user's 2026-04-25 statement: *"Runtime 도 커널처럼 완결성 있게 sealed 시키고 싶다."*

After v0.12 cut, the platform contract (Runtime invariants, ABI surface, host capability whitelist) is frozen. Shell authors gain a stable base on which BBS, Casino-style, federated-experience, or Roblox-style multi-experience hubs can all live without the Runtime ever changing under them.

---

## 2. Decision register

The user resolved three open scope decisions on 2026-04-25.

| ID | Question | Decision | Rationale |
|----|----------|----------|-----------|
| **D-USER-1** | Should the Runtime provide a `Room` primitive directly, or let each shell define its own `Room` type? | **(a) Runtime provides Room.** | Linus VFS pattern: a shared base interface enables composition (cross-shell friend / chat / asset transfer); per-shell reinvention rigidifies the platform. Spec `§14.1` R4' verdict already endorses *"Separate primitive, follow-up DIP"* — `follow-up DIP` only delays timing, not necessity. Layer-independence directive (third-party shell as first-class) reinforces (a). |
| **D-USER-3** | What level of formal verification gates the v0.12 cut? | **(c) TLA+ refinement + Kani implementation-level proofs.** | "L0처럼 sealed" interpreted as *"L0 보다 더 견고"*: the Runtime surface is larger than L0's (L1 + L2 vs L0's minimal core), so additional verification depth is warranted. Sealing forecloses post-cut additions, so under-investing carries no recourse. |
| **D-USER-4** | Where does the R4-J Subset-Rust dylint live — its own crate or inside `arkhe-trait-default-check`? | **(a) New crate `arkhe-subset-rust-check`.** | Linus *do one thing well*. Trait-fingerprint enforcement (publish-time, kernel-maintainer audience) and Action-purity enforcement (build-time, shell-author audience) are different concerns; bundling them couples opt-in. |
| **D-USER-5** | Track C Room evidence path — given Room is a distinct primitive but the workspace cannot manufacture in-tree shells, how does v0.12 satisfy the 2+ shell evidence gate? | **(iii) SHAPE-only spec declaration.** v0.12 ships TypeCode allocation + 4-gate compliance section + `RoomMarker: EntityKind` only — 0 Component / Action / VerbCode allocations. Implementation surface waits for v0.13 ecosystem-shell evidence. | Preserves D-USER-1 (a) intent (third-party shells land on a uniform Room shape from v0.12 — multi-experience-hub use cases stay viable). Validated-repetition partially honoured by deferring the implementation surface until ecosystem evidence arrives. Sealing-after-cut foreclosure risk minimised by locking only the shape, not the content. |

---

## 3. Sealing axioms

Two new MC (machine-checked) axioms enter the Runtime axiom series at v0.12. They live in the runtime-book E-series, **not** the L0 A-series (A1-A24 + S1 remain sealed under L0 DO NOT TOUCH #4).

### E14 — Compute Determinism Closure (MC, v0.12 도입)

> Every compute path contributing to the L0 chain hash — L1 `Action::compute()` and L2 Hook host v2 invocations — produces bit-identical output across replay on any conformant Runtime instance. Conformance:
> (a) host imports limited to the canonical whitelist; non-whitelisted imports are rejected at module-load;
> (b) numerical operations follow the FP / SIMD policy (NaN canonicalisation, SIMD opt-in policy, RNG / clock blocks);
> (c) bounded execution under a deterministic execution-cost measure: wasmtime fuel + instruction count. Wall-time forbidden.
>
> Realisations: **E14.L1** Subset-Rust dylint enforcement at build time / **E14.L2** WASM sandbox enforcement at runtime.
>
> E14 is the input-level guarantee that L0 A1 (bit-identical replay) requires when compute paths contain non-trivial logic. Violation surfaces as `ReplayError::DeterminismViolation` + compute-path quarantine (L0 A22 inheritance).

**Adversary A residual reduction**: pre-E14, an adversary injecting non-determinism via a malicious shell crate is constrained only by L0 A12 totality + Subset-Rust as a soft convention; the L2 Hook surface is uncovered, and L1 lacks compile-time enforcement beyond panic-rejection. E14 reduces the residual surface to (i) compromising the canonical host-import whitelist or (ii) breaking the underlying engine's determinism guarantees — both out-of-scope per `implementation-plan.md` §19 "zero-day in Rust compiler / WASM engine". The reduction is conservative: any adversary path not in (i)/(ii) is closed by E14.

**Host-import whitelist (canonical capability table)**:

| Namespace | v0.12 verdict | Rationale |
|---|---|---|
| `wasi:random/*`, `wasm-rand` | **DENY** | non-deterministic RNG |
| `wasi:clocks/wall-clock` | **DENY** | non-deterministic |
| `wasi:clocks/monotonic-clock` | **DENY** | timing oracle |
| `wasi:filesystem/*` | **DENY** | capability leak |
| `wasi:sockets/*` | **DENY** | exfiltration |
| `wasi:io/streams` | **DENY** by default (host-mediated only — Hook contract gates concrete ALLOW cases) | |
| `arkhe:hook/state` (read-only canonical snapshot) | **ALLOW** | host canonical-pin |
| `arkhe:hook/emit` (typed event) | **ALLOW** | post-hook re-validation target |
| `arkhe:hook/fuel` (fuel tick lookup) | **ALLOW** | clock substitute |

wasmtime configuration: AOT-compile + cranelift + `target_triple` pinned; `Config::wasm_threads(false)` + `wasm_simd(false)` (or `relaxed_simd(false)` + `cranelift_nan_canonicalization(true)`) + `consume_fuel(true)`. FP = strict IEEE 754 (Cranelift default, denormals preserved). Cross-host replay is out of axiom scope — operators run identical binaries.

### E15 — Observer Capability Confinement (MC, v0.12 도입)

> L2 observer sinks shall execute in a capability-bounded sandbox such that:
> (a) observer panic is contained at the sandbox boundary — the host catches the trap and emits an `ObserverQuarantine` event; no native unwind reaches the L0 chain (L0 A22 strengthening);
> (b) observer side-effects route exclusively through host-declared capability tokens; direct syscalls and `wasi-{fs,sockets,clocks,random}` are rejected at module-load. Concrete capability set in v0.12 = `{PgWrite}`. Expansion is non-breaking per `implementation-plan.md` §6 (additive token enum).

**Adversary B residual reduction**: pre-E15, observer compromise spreads through native panic (A22 quarantines AFTER unwind, not BEFORE side-effects) and uncontrolled egress via direct syscalls. E15.a closes the native-crash channel; E15.b closes uncontrolled egress. Residual surface = (i) host-call API implementation defects (cryptographer + veteran scope), (ii) wasmtime engine zero-day (out-of-scope).

---

## 4. Work tracks

Each track is a coherent sub-DIP scope. Tracks A-G are direct work; Track H is a forward-looking event surface that v0.12 reserves but does not activate.

| Track | Scope | Axiom anchor | Reviewer set |
|-------|-------|--------------|--------------|
| **A.1** | L1 `Action::compute()` Subset-Rust dylint — new crate `arkhe-subset-rust-check`. cdylib + dylint driver wiring. R4-J spec text. | E14.L1 | architect / theorist / dev-expert |
| **A.2** | L2 observer WASM sandbox — E15.a panic close + E15.b capability-token interface + 1 concrete impl (`PgWrite`). Additional host-call surface (KMS / metric / etc.) deferred to v0.12.x or v0.13 BBS-dogfood-driven (validated-repetition directive). | E15 | architect / cryptographer / auditor |
| **B** | Hook host v2 activation — wasmtime + WASI preview-2 (async); 10 ms wall + fuel limit; resource limits (16 MB memory cap, table size, instance count); post-hook policy re-validation on the **same canonical bytes** that gated admission (confused-deputy defense); 3-tier hook-bytes ingestion (BLAKE3 digest pin manifest-anchored + sigstore sign-before-load + provenance attestation). `HookModuleRegister { module_digest, wasm_size, operator_sig, sigstore_bundle, cargo_vet_attestation, effective_tick }` event. `HookLoadError::AttestationGap` if digest + sigstore + cargo-vet trio incomplete. | E14.L2 | architect / cryptographer / auditor |
| **C** | **Room primitive — SHAPE-only spec declaration (D-USER-5 (iii)).** v0.12 ships `RoomMarker: EntityKind` (ArkheUri §14.6 pattern) + TypeCode allocation (`0x0001_5001`, next free after ActivityMarker) + 4-gate compliance section (lifecycle ephemeral / auth Actor-bound / scale high-throughput WAL TTL / WAL policy TTL-based eviction distinct from Entry append-only). **Zero Component / Action / VerbCode allocations** — those wait for v0.13 ecosystem evidence. Architect V3 confirmed Room is distinct primitive; v0.12 freezes the shape, v0.13 fills the surface. ~2 architect-days. | (specialised under E1-E5) | architect / theorist / auditor / veteran |
| **D** | Spec drift correction (4 entries from `spec-drift-candidates.md`). Spec body fix only — code unchanged. v0.12 absorbs; the v0.11 tag is unaffected. Each correction clears the 4-person review prescribed in `spec-drift-candidates.md` working notes. | — | theorist / cryptographer / auditor / veteran |
| **E** | **TLA+ refinement (CR-1 / CR-2 / CR-3 + R4-I)** + **Kani implementation-level proofs** (authorize / dispatch / replay properties). CI auto model-check (TLC or Apalache); `cargo kani` regression hook; coverage report tied to release-gate. | covers E14 / E15 / chosen E1-E13 invariants | theorist / dev-expert / auditor |
| **F** | WAL streaming export — incremental fsync per record. A14 append-only and DO NOT TOUCH #8 postcard field order both invariant under the change. Adversary C (offline tamper) defense surface re-evaluated against streaming sink. | — | dev-expert / auditor |
| **G** | Sealing gate — Phase 6 release gates (9) + Phase 1 entry checkpoints (14) carry-over closure. Spec-sealing-DIP-scope additions (5): dylint cdylib activation, cargo-vet advisory→mandatory flip, HF4 manifest-bypass audit emission, three plan-mandated docstubs (`drift-log.md` / `threat-model-catalog.md` / `release-gate.md`), `cargo-public-api` baseline scaffold. **FG7 sealing-blocker fixes (3)**: define opaque `ReplayError` (Display + Debug = static "manifest mismatch — see operator log"), encapsulate `JournalEntry` + land WAL-backed-or-`0600`-perm journal access, replace `JournalError::BackendIo(String)` with payload-less variants. v0.12 cut writes the **Runtime DO NOT TOUCH list** (the L0-A-series analogue for E1-E15). | — | architect / dev-expert / auditor / cryptographer |
| **H** | **§14.7+ Forward-looking event class.** v0.12 reserves wire surface only — *define-only TypeCode reservation + schema freeze* + feature-gating. Activation is v0.99+ default (federation / long-term audit). Two events: `ReplicaIdAllocation { federation_id[16], replica_id u32, allocation_nonce u32, effective_tick, registry_attestation[64] }` (TypeCode `0x0003_0F09`, `feature="federation-v0_99"`); `AuditReceiptKeyPolicy { key_id[8], algorithm RuntimeSignatureClass, public_key Bytes(var), predecessor_key_id Option<[u8;8]>, effective_tick, retirement_tick Option<Tick>, attestation[64] }` (TypeCode `0x0003_0F0A`, `feature="audit-receipt-key-policy-v0_99"`). | reuses §14.7 SignatureClassPolicy MC pattern | cryptographer / auditor / theorist |

### Track A.2 capability-set deferral

Track A.2's E15.b interface ships with one concrete capability (`PgWrite`) at v0.12. Additional host-calls (KMS, metric, etc.) wait for BBS-dogfood evidence before joining — this respects the validated-repetition directive (R4' gate (b)) and keeps the v0.12 capability-token enum purely additive (non-breaking) for future Shell-side extensions. Architect V1 also flagged a Windows-side stretch goal: `ProcessMitigationPolicy::ProcessSignaturePolicy` (single Win32 call) closes the ptrace-deny asymmetry surfaced in HF1 and is a low-cost addition to Track A.2 for v0.12.

### 4.1 Track C evidence-path options

Architect V3 confirmed Room is a distinct primitive but flagged tension between two user directives at the evidence-path step:

- **Layer-independence directive** (third-party shell as first-class) and the user's D-USER-1 (a) decision favour shipping Room at v0.12 so any third-party shell — BBS, Casino-style, multi-experience hub — lands on a uniform Room base.
- **Validated-repetition directive** (`feedback_completeness_first.md` and R4' gate (b)) requires 2+ shell evidence in *code form*, not narrative form, before a Runtime primitive is sealed.
- **User directive on shell ownership**: *"BBS / Casino 를 우리가 안 만든다 — Runtime 이 받쳐주느냐가 관건."* The workspace cannot manufacture an in-tree shell to satisfy the gate.

Four evidence-path options surfaced:

| Option | Approach | v0.12 work | Trade-off |
|--------|----------|------------|-----------|
| (i) | Cite spec multi-shell narrative (BBS rooms + TubeLike live + GuildChat) and declare gate satisfied | spec text only | Violates validated-repetition (narrative ≠ evidence) |
| (ii) | Build BBS / Casino prototype in this workspace | full implementation, +1 shell | Violates Layer-independence + user shell-ownership directive |
| (iii) | Tighten the gate to "2+ **third-party** (ecosystem) shells" and ship SHAPE-only spec at v0.12 (TypeCode allocation + 4-gate compliance section, **0 Component / Action / VerbCode allocations**) | ~2 architect-days, spec text only | Layer-independence ✓, validated-repetition partial (shape declared, evidence deferred to v0.13 ecosystem code) |
| (iv) | Defer Room entirely to v0.13 — Track C OUT of v0.12 | 0 | Validated-repetition ✓, but D-USER-1 (a) intent partially deferred (Runtime ships v0.12 without Room base; ecosystem shells must each define their own until v0.13) |

**Architect recommendation: Option (iv).** Pre-declaring Room without 2+ shell evidence violates validated-repetition; minimum-churn path is leaving spec `§8.1 / §14.1 / §15.5` v0.13 row intact.

**Leader observation**: Option (iii) is a *spec-only SHAPE declaration* — `RoomMarker: EntityKind` + TypeCode allocation + 4-gate compliance section, with Component / Action / VerbCode entries waiting for v0.13 evidence. This preserves the platform-uniformity intent of D-USER-1 (third-party shells land on a known Room shape from v0.12) while honouring validated-repetition by not committing the implementation surface until evidence appears. (iv) yields a smaller v0.12 cut at the cost of post-cut shape evolution, which sealing forecloses.

**Decision: D-USER-5 = (iii) SHAPE-only.** Track C ships `RoomMarker: EntityKind` + TypeCode `0x0001_5001` + 4-gate compliance section at v0.12. Zero implementation allocations (Component / Action / VerbCode entries deferred to v0.13 evidence-driven addition). ~2 architect-days inside the v0.12 cut.

---

## 5. v0.11 residual obligations

Verification dispatched at session close (architect / cryptographer); results synthesised here.

### HF1 — Tier-0 process protection (architect V1)

Process protection 3-platform trace is asymmetric. Linux is fully wired; macOS and Windows have documented gaps that require *spec-level acknowledgement* rather than further code work.

| Platform | `lock_memory` | `disable_core_dump` | `disable_ptrace` | Status |
|----------|---------------|---------------------|------------------|--------|
| Linux | `mlockall(MCL_CURRENT \| MCL_FUTURE)` ✓ | `prctl(PR_SET_DUMPABLE, 0)` ✓ | `PR_SET_PTRACER, 0` + yama advisory ✓ | fully wired |
| macOS | **Unsupported** (Darwin lacks `mlockall`) | `setrlimit(RLIMIT_CORE, 0)` ✓ | `ptrace(PT_DENY_ATTACH)` self-apply ✓ | partial — Tier-0 KEK memory-residency unenforced |
| Windows | `SetProcessWorkingSetSizeEx + QUOTA_LIMITS_HARDWS_MIN_ENABLE` (closest analogue) | `SetErrorMode(SEM_FAILCRITICALERRORS \| SEM_NOGPFAULTERRORBOX)` | **Detect-only** via `IsDebuggerPresent + CheckRemoteDebuggerPresent` | partial — ptrace deny is detection, not denial |

**Sealing verdict — non-blocking with documentation requirement.** v0.12 cut absorbs the macOS / Windows gaps as a known-limitations table in spec `§14.9.1 §§12` (Track D micro-fix). Windows `ProcessMitigationPolicy::ProcessSignaturePolicy` is a low-cost stretch (single Win32 call, closes ptrace-deny asymmetry) — recommend Track A.2 stretch goal, not blocker.

### FG7 — Replay-error opacity + journal access control (architect V2)

**Sealing verdict — BLOCKING.** Three concrete gaps need closure inside Track G before v0.12 cut:

1. **`ReplayError` opaque type missing entirely.** Spec `§12.4 / §14.11.2` HF2 mandates an opaque "manifest mismatch (see operator log)" public surface; the type is not defined in code. Add as new error enum with both `Display` and `Debug` returning the static string, no `#[derive(Debug)]` defaults.
2. **`runtime_doctor_journal` access control absent in code.** `InMemoryJournal::entries() -> &[JournalEntry]` is public read; `JournalEntry` fields are all `pub`; `WalBackedJournal` trait is declared but unimplemented. Either land the WAL-backed implementation or filesystem-perm `0600` snapshot path; encapsulate `JournalEntry` so the public surface is `tip_hash() / len() / verify_chain()` only.
3. **`JournalError::BackendIo(String)` leaks paths / errno strings.** Replace with payload-less variants (`PermissionDenied`, `FilesystemError`) so opacity is structural rather than convention.

These three fixes land as Track G sub-scope items, gating the v0.12 cut.

### Archive-hardening (cryptographer V4)

Three items checked against `docs/release-keys.md`. All three are **partially met** — none catastrophically — and `AuditReceiptKeyPolicy` define-only reservation at v0.12 is sufficient. Emission activation stays at v0.99+. Four operator-side carry-overs extend the user's existing task (d):

- **(e)** `aceamro/arkhe-release-keys` repo: GitHub branch protection rule + 2-of-N commit-signature policy. Currently HW-signing co-custody is documented (§3) but archive-repo commit integrity policy is not.
- **(f)** Sigstore TUF mirror evaluation. Current cosign keyless + Rekor (§9 / §9.5) is strong for release artefacts; whether a TUF mirror adds material defence is a separate operator decision.
- **(g)** Audit-receipt key identity in `release-keys.md §1` inventory. Currently ambiguous whether receipt signing reuses the journal key or uses a separate L2 key. **Cryptographic prerequisite for emission activation** (not for v0.12 define-only).
- **(h)** `release-signing-v1` 1-year rotation manifest format (§5.2). Currently archive-only; recommend serialised rotation manifest with successor + retirement annotations (parallel to the journal key's in-band chain-of-trust at §5.1 step 5).

### Other obligations

| Obligation | Sealing-blocking? | Disposition |
|------------|-------------------|-------------|
| M-R6-4 software-kek → HSM migration runbook + test vectors | NO — defer ok | Required only at the alpha → beta promotion boundary. Out of v0.12 sealing scope. |
| Adversary D (multi-tenant WASM timing side-channel) | NO — defer ok | v0.11 is single-shell BBS — no multi-tenant surface. v0.13+ DIP open question. v0.12 records a placeholder in `book/src/en/architecture/threat-model.md` ("Adversary D — v0.12 N/A — single-shell BBS construction"). |

---

## 6. Spec drift fix mapping

`docs/spec-drift-candidates.md` lists four implementation-ahead drifts. All four are spec-body-only fixes — code is unchanged; the v0.11 tag `7d66c47` is unaffected. The fixes land **inside Track D as part of the v0.12 cut**, not as a v0.11 micro-patch (consistent with the user's single-cut versioning directive). Each fix clears the 4-person review (theorist / cryptographer / auditor / veteran) prescribed in the candidates document's working notes.

| Drift | Spec section | v0.12 disposition |
|-------|--------------|-------------------|
| #1 AES-GCM nonce invocation field | `runtime-spec.md §14.9.1 §§3` | text fix `random[4] → replica_id[4]`, single-writer invariant `replica_id ≡ 0`, F6 multi-region reservation note, forward-reference to Track H §14.X (federation policy). |
| #2 BLAKE3 domain string list | `runtime-spec.md §14.7 / §3.2` | append `arkhe-runtime-doctor-journal-chain` to the §3.2 domain separator table; cross-reference `§12.4` chain-hash definition. |
| #3 `UserSalt` typed anchor | `runtime-spec.md §14.9.1 §§4` | add typed-anchor note (Zeroize + non-Clone single-owner-per-fetch); state wire layout unchanged. |
| #4 `TIER0_DEV_DIGEST_V0_11` regression sentinel | `runtime-spec.md §5.6 / §14.7` | add manifest canonical-digest wire-stability invariant; document `toml` major-bump procedure. |

---

## 7. DIP cycle outline

Approximate breakdown — actual ordering depends on architect / dev-expert phasing during the next session.

| Cycle | Scope |
|-------|-------|
| DIP-N1 | Track A.1 (`arkhe-subset-rust-check` crate, dylint driver, R4-J spec text, E14.L1 strict-mode enforcement) + Track B (Hook host v2 activation + 3-tier ingestion). |
| DIP-N2 | Track A.2 (E15 + capability-token interface + `PgWrite` impl) + Track C (Room primitive introduction). |
| DIP-N3 | Track D (drift fixes) + Track F (WAL streaming) + Track H (forward-looking events define-only). |
| DIP-N4 | Track E (TLA+ refinement + Kani proofs). |
| DIP-N5 / Sealing | Track G — release-gate closure, R6+ external Round, Runtime DO NOT TOUCH list, v0.12 tag. |

---

## 8. Constraints

- **L0 unchanged.** `arkhe-kernel/src/**` and `arkhe-macros/src/**` keep `v0.11` source. DO NOT TOUCH 8 entries remain enforced. The `WalRecord` postcard field order (DO NOT TOUCH #8) is invariant.
- **v0.11 spec body unchanged.** Only Track D drift fixes touch spec text, and they land inside the v0.12 cut, not on the v0.11 tag.
- **Single-cut versioning.** v0.11 → v0.12 is a single bump; no `v0.11.1` / `v0.11-alpha` markers. CHANGELOG gets a fresh `[0.12.0]` section at cut.
- **1.0 forever-out-of-reach.** Pre-1.0 status preserved post-v0.12 to keep iteration room.
- **Layer independence.** Shell crates remain in separate repos (Layer-independence directive). The v0.12 cut explicitly does not introduce Casino, Forum, or any other shell into this workspace; the dice example is the only in-tree shell-shaped artefact and serves as the L1 deterministic-integrity demonstrator.
- **Linus single-path.** Where two viable approaches exist, the cut adopts one and removes the alternative path from the spec; ambiguity does not survive sealing.

---

## 9. Cross-references

- `docs/implementation-plan.md` — Phase 1 entry checkpoints (14) + Phase 6 release gates (9) feeding Track G.
- `docs/spec-drift-candidates.md` — input archeology for Track D.
- `docs/release-keys.md` — archive-hardening status fed into Track H emission verdict.
- `docs/alpha-release-schedule.md` — alpha-blocker doc deliverables outside v0.12 sealing scope.
- `runtime-book/src/en/architecture/14-open-questions.md` §14.5 (Hook v1 OFF) and `book/src/en/architecture/threat-model.md` (Adversary A / B residual surfaces) — direct anchors for E14 / E15 axioms.
- `book/src/en/roadmap.md` — original "WASM sandbox option for L1" + "R4-J Subset-Rust pure L1 checker" forward references that v0.12 closes.
