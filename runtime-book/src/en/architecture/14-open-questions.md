## §14. Open Questions — final verdicts + new sections

### §14.1 Room primitive — separate primitive (follow-up DIP)

(R2 auditor + team-lead). Withdraws the R1 "Entry(Ephemeral) + Activity(Say)" alternative (tuple idempotency). Gate §8.1. 2+ shell evidence satisfied. Runtime semver v0.12 → v0.13.

#### §14.1.1 Room primitive — SHAPE-only declaration (D-USER-5 (iii), Track C, v0.12 sealing cycle)

User decision **D-USER-5 = (iii) SHAPE-only** (recorded in `docs/runtime-sealing-plan.md` decision register): v0.12 ships the Room shape declaration without committing the implementation surface. The architect-V3 evidence-path tension between Layer-independence (third-party shell as first-class) and validated-repetition (R4' gate (b) — 2+ shell evidence in code form) resolves at the SHAPE level — third-party shells land on a uniform Room base from v0.12, while Component / Action / VerbCode allocations wait for v0.13 ecosystem evidence.

**Reserved type-level shape** (§14.6 ArkheUri pattern):

```rust
// Future v0.13 implementation surface — declared at v0.12 SHAPE only.
pub enum RoomMarker {}
impl kind_seal::Sealed for RoomMarker {}
impl EntityKind for RoomMarker {
    const TYPE_CODE: TypeCode = TypeCode(0x0001_5001);
}
```

The `RoomMarker` `EntityKind` impl follows the §14.6 pattern (`UserMarker` 0x0001_0001 / `ActorMarker` 0x0001_1001 / `SpaceMarker` 0x0001_2001 / `EntryMarker` 0x0001_3001 / `ActivityMarker` 0x0001_4001 / **`RoomMarker` 0x0001_5001** — next free in the `0x0001_X001` Core Entity sub-range progression). The TypeCode is doc-reserved at the code level via `arkhe_forge_core::typecode::ROOM_MARKER_RESERVED` (Track C.2) — the `EntityKind` trait + per-marker `impl` blocks themselves remain spec-text-only at v0.12, deferred to v0.13 alongside the §14.6 ArkheUri implementation surface.

**4-gate compliance section** (per `docs/runtime-sealing-plan.md` D-USER-5 (iii)):

| Gate | v0.12 SHAPE-only verdict | Significance |
|---|---|---|
| **Lifecycle** | Ephemeral (TTL-evicted, distinct from Entry's append-only) | Operational — lifecycle policy. WAL retention is a runbook concern; no chain-integrity coupling. |
| **Auth** | Actor-bound (Room membership requires Authenticated Actor) | **Cryptographic** — connects to E13 (`SignatureClassPolicy`). At v0.13 implementation time, Room operations must respect the shell-per-tick `auth.signature_class` manifest field; receipt class downgrade attacks are blocked by the same chain-anchored policy that protects Entry / Activity submissions. The cryptographic-significance flag pre-commits the v0.13 implementation gate. |
| **Scale** | High-throughput WAL TTL (sub-second latency tolerance, projection-side eviction) | Operational — SLO sizing. v0.12 reservation does not prescribe a specific TTL bound; v0.13 ecosystem evidence informs the operator-tunable default. |
| **WAL policy** | TTL-based eviction (distinct from Entry's append-only invariant — Room does not extend the `WalRecord` postcard field order under DO NOT TOUCH #8) | Operational — eviction integrates with the existing WAL streaming export (Track F). |

**Allocation freeze at v0.12** — by D-USER-5 (iii) decision:

- **0 Component allocations** — no `Room*` structs in the `arkhe-forge-core::component::*` registry. Per-shell Component sub-allocations (e.g., `RoomMembership`, `RoomBan`) wait for v0.13 ecosystem evidence.
- **0 Action allocations** — no `Room*` actions in the `arkhe-forge-core::action::*` registry. The verb set (`join` / `post` / `leave` / `kick` / etc.) is an ecosystem-driven extension at v0.13.
- **0 VerbCode allocations** — the `0x0002_0001..0x0002_03FF` canonical verb sub-range remains intact; Room-specific verbs land via the M-verbrange shell BLAKE3 sub-allocation pattern (§14.4) at v0.13, NOT as canonical verbs.

**v0.13+ cap-token family reservation note**: Room operations land alongside a dedicated capability-token family at v0.13 (e.g., `arkhe:room/{join, post, leave, ...}`) corresponding to the new Action verbs. v0.12 SHAPE does NOT include the cap-token reservation — `ObserverCapToken` (E15) and the future `RoomCapToken` family are independent dimensions; the deferral is structural, not scope creep.

**Sealed-completeness mutual lock** (cryptographer Q7 anchor): the SHAPE declaration is mirrored at code level by the doc-only `pub const ROOM_MARKER_RESERVED: u32 = 0x0001_5001;` constant in `arkhe-forge-core::typecode` (Track C.2). The two sources together (spec text + code constant) prevent v0.13 implementers from accidentally re-allocating `0x0001_5001` for a different EntityKind — sealing-cut foreclosure preserved without committing the implementation surface.

**Layer-independence rationale recap** (D-USER-1 (a) intent dispatch): the SHAPE declaration ensures third-party shells (BBS / Casino-style / federated-experience / Roblox-style multi-experience hubs) land on a uniform Room base from v0.12, even though the in-tree workspace ships zero shell artefacts. Each ecosystem shell consumes the spec's `RoomMarker: EntityKind` shape + 4-gate compliance section + TypeCode reservation as authoritative — the v0.13 evidence-driven implementation rolls out the Component / Action / VerbCode allocations once 2+ ecosystem shells demonstrate concrete need, satisfying the validated-repetition directive without serialising third-party shell development behind a single platform release.

### §14.2 Attachment — Axis 1 Component

`EntryAttachments { refs }` Component + `entry_attachment_refs` extension table. sha256 duplicate projection.

### §14.3 Session/Turn/Round — shell-scoped + Band attribute

Casino is shell-scoped. Band 3 uses the `#[arkhe(band = 3)]` Action attribute (NC3 integration).

### §14.4 VerbCode range — M-verbrange

Canonical 1023 / shell 64,512 via BLAKE3 deterministic sub-allocation. `runtime-typecode-allocations.toml` registry. const generic.

### §14.5 Hook v1-alpha OFF — confirmed

All hooks disabled in v1 alpha. Reasons: no hot-reload (C1), Send+Sync contradiction (M5), UnwindSafe not guaranteed (C3), dylint purity is build-time only (M2), confused-deputy risk (S1).

v1 scope: manifest policy only + single shell (BBS recommended). The range expressible by multi-shell manifest policy alone.

v2 reintroduction conditions: WASI sandbox + 10ms budget + resource limits + WASI async + post-hook policy re-validation (§5.3/§9.1).

**v1 flow note (auditor N2)**: the "Hook host" box in the §5.3 diagram is **pass-through (no-op)** in v1. Activated together with the post-hook re-validation step when v2 is enabled.

#### §14.5.1 Hook host v2 — v0.12 sealing-cycle realisation (Track B)

Tier-2 production opt-in via the `tier-2-hook-host-v2` Cargo feature on `arkhe-forge-platform`; Tier-0 / Tier-1 deployments continue to ship `NoopHookHost` (v1 alpha pass-through). Operators stating Tier-2 in the manifest pull in the wasmtime sandbox.

**Engine configuration (`WasmtimeEngineConfig`)** — pins the four E14.L2-Allow determinism axes:

| Axis | Field | v0.12 value | Effect |
|---|---|---|---|
| NaN canonicalisation | `nan_canonicalisation` | `true` | `cranelift_nan_canonicalization(true)` — defends replay against host-dependent NaN payload bits |
| SIMD opt-out | `wasm_simd_enabled` | `false` | `wasm_simd(false)` + `wasm_relaxed_simd(false)` — rejects SIMD instructions at module-load |
| Fuel metering | `fuel_metering` | `true` | `consume_fuel(true)` — enables per-invocation fuel ceiling |
| IEEE-754 strict | *(implicit)* | Cranelift default | No `Config` field; floating-point ops produce host-independent bits |
| Per-invocation budget | `fuel_budget` | `10_000_000` (1–100 M envelope) | `Store::set_fuel(...)` immediately before instantiation; ~10 ms wall-clock target on x64 server class. **Fail-secure direction** (under-budget → hook killed early; over-budget → DoS surface). |

**Capability-bounded `Linker` template** — three-layer defense:

1. **Pre-scan** (`scan_imports`) eager-rejects modules whose imports do not match the `arkhe:hook/*` allow-list, with explicit specific-error paths for the WASI deny-list (`wasi:random`, `wasi:clocks`, `wasi:filesystem`, `wasi:sockets`, `wasi:io`, `wasi:cli`, `wasi:http`). Boundary check confines deny-list matching to WIT package boundaries (`/`, `@`, end-of-string).
2. **Link-time deny-by-default** — `Linker::new` only `func_wrap`s the supported `arkhe:hook/*` host-fns; unknown imports fail at instantiation.
3. **Call-time capability check** — every host-fn body inspects `Caller::data().capabilities` and traps `CapabilityDenied` if the matching `CapToken` is absent.

**v0.12 host-fn allow set**:

| Import path | CapToken | Sig | Behaviour at v0.12 (Track B.5.b) |
|---|---|---|---|
| `arkhe:hook/state.read` | `StateRead` | `(key_ptr, key_len, val_ptr_out, val_buf_len) -> i32` | Reads `key` bytes from wasm memory, looks up `HookStoreData::scratchpad`, copies value to `val_ptr_out` (bounds-checked). Returns: `>=0` bytes copied / `-1` not found / `-2` buffer too small. |
| `arkhe:hook/state.write` | `StateWrite` | `(key_ptr, key_len, val_ptr, val_len)` | Reads key + value from wasm memory, inserts into `HookStoreData::scratchpad` (`BTreeMap<Vec<u8>, Vec<u8>>`). |
| `arkhe:hook/emit.extra_bytes` | `EmitExtraBytes` | `(ptr, len)` | Reads bytes from wasm memory, appends to `HookStoreData::extra` (the `ExtraBytesBuilder` moved in by `WasmtimeHookHost::invoke` from `HookContext::extra`). Traps if `extra` was not seeded (programmer-error guard). |
| `arkhe:hook/fuel.consumed` | `FuelConsumed` | `() -> i64` | Returns `initial_fuel - Caller::get_fuel()`. Saturating cast to `i64::MAX` for forward-compat. |

**Memory bounds-check contract** (`(ptr, len)` host-fn deref): all such inputs flow through `read_caller_memory` (input ranges) or `write_caller_memory` (output ranges). Both validate `len >= 0`, `ptr >= 0`, `ptr.checked_add(len)? <= Memory::data_size(&caller)`, and trap `OOB` with explicit reason on violation. Required to prevent FFI-shaped sandbox-escape primitives (cryptographer-anchored requirement, Track B.5.a + B.5.b).

**3-tier ingestion** (Track B.6) — `WasmtimeHookHost::register_module(bytes, expected_digest)` enforces:

- **Tier 1** (active in v0.12): BLAKE3 digest pin against operator-pinned `expected_digest` (typically sourced from manifest TOML). Mismatch → `DigestMismatch` at registration time, before any wasmtime engagement.
- **Tier 2** (sigstore sign-before-load) — scaffolded via `HookAttestationVerifier` trait; v0.13+ integration.
- **Tier 3** (cargo-vet provenance) — scaffolded; v0.13+.

The default `Tier1OnlyVerifier` **loud-rejects** any `(signature, vet_attestation)` payload supplied to `verify` (returns `UnexpectedTier23Payload`). This prevents confused-deputy migrations where a caller wires Tier 2/3 inputs believing they are validated while v0.12 only enforces Tier 1.

**Manifest signature scope** (cryptographer P2): manifest signature verification (operator key → manifest TOML signing) is outside the v0.12 hook host scope; `manifest_digest` is recorded as a chain-anchor for replay verification, and the operator-side trust establishment lands at the manifest layer integration (post-v0.12 DIP).

**Chain anchoring**: every successful `register_module` emits a `HookModuleRegister` event (TypeCode `0x0003_0F0B`) carrying `(manifest_digest, module_digest, register_tick, attestation_class)`. **Replay-side verification path** (cryptographer P1): on replay, the recorded `HookModuleRegister.module_digest` is matched against `blake3(registered_bytes)`; mismatch → `ReplayError::HookModuleDriftQuarantined` + compute-path quarantine (L0 A22 inheritance).

**Per-host trap counter**: `WasmtimeHookHost::trap_count` (`AtomicU64`, lock-free) increments on every `invoke()` Err. Operator telemetry surface; future `runtime_doctor_journal` integration routes per-trap entries chain-signed. **Era distinction** (cryptographer P3): Track B.5.b activated real wasm execution, so the counter narrows from "invoke() Err of any shape" to "actual wasm-execution traps" (`BudgetExceeded` from fuel exhaustion / `Trapped` from wasmtime trap propagation / capability-deny / OOB). The `AtomicU64` field shape is preserved across the era boundary; only the semantic narrows.

**Invoke pipeline (Track B.5.b)**: `WasmtimeHookHost::invoke(ctx)` builds a per-invocation `Store<HookStoreData>` seeded with `ctx.capabilities` + `fuel_budget` + the extra-bytes builder taken from `ctx.extra` via `std::mem::take`. Instantiates the registered module via the cached `Linker`, looks up the conventional `"hook"` export (signature `() -> ()`), seeds fuel via `Store::set_fuel(fuel_budget)`, and calls the entry point. After return — whether success or trap — the (possibly mutated) extra-bytes builder is moved back into `ctx.extra` so the post-hook policy re-validation step sees it. Wasmtime errors are translated coarsely: fuel exhaustion → `HookError::BudgetExceeded`; everything else → `HookError::Trapped` with a static reason tag (operator stderr + `runtime_doctor_journal` carry the rich detail).

**Post-hook policy re-validation** (spec §5.3 / cryptographer C8 confused-deputy defense): the submission pipeline re-runs the same policy predicates against the post-hook `extra_bytes` buffer. A hook that mutated the buffer to flip policy outcome is rejected at the re-validation step → `HookError::PolicyReValidationFailed`. The hook host exposes the post-hook builder; the pipeline owns the re-validation call.

#### §14.5.2 Observer host v2 — v0.12 sealing-cycle realisation (Track A.2)

Tier-2 production opt-in via the `tier-2-observer-host-v2` Cargo feature on `arkhe-forge-platform`; Tier-0 / Tier-1 deployments continue to ship `NoopObserverHost` (v1 alpha pass-through). The two wasmtime hosts (`tier-2-hook-host-v2` + `tier-2-observer-host-v2`) are **independent** — operators may enable just one, just the other, or both; Cargo dedups the shared `wasmtime` dep.

**E14.L2 vs E15 axis distinction**: hook host (E14.L2) is *chain-affecting* compute (`Action::compute` host hook on the submission hot path) — determinism axes pinned (NaN canonicalisation / SIMD off / IEEE-754 strict). Observer host (E15) is *chain-non-affecting* side-effect dispatch (post-commit projection / metric / vault sinks) — determinism axes deliberately UNPINNED (replay-determinism is unnecessary because observer execution does not contribute to the L0 chain hash). Shared mechanism (wasmtime engine + capability-bounded `Linker`) + branched invariant (chain-affecting determinism vs chain-non-affecting confinement).

**Engine configuration (`WasmtimeObserverEngineConfig`)** — pins the panic-close + fuel-metering axes only:

| Axis | Field | v0.12 value | Effect |
|---|---|---|---|
| Fuel metering | `fuel_metering` | `true` | `consume_fuel(true)` — required for fine-grained sandbox-boundary trap delivery (panic close E15.a) |
| Per-invocation budget | `fuel_budget` | `100_000_000` (1 M–1 G envelope) | `Store::set_fuel(...)` immediately before instantiation; ~100 ms wall-clock target on x64 server class. Generous vs hook's 10⁷ because observer is post-commit + tolerates PG round-trip latency. **Fail-secure direction** (under-budget kills observer early; over-budget DoS surface for projection pipeline). |
| NaN canonicalisation | *(not pinned)* | — | E15 chain-non-affecting → replay-determinism unnecessary. Operators may override per deployment policy. |
| SIMD opt-out | *(not pinned)* | — | Same rationale — chain-non-affecting. |

**Capability-bounded `Linker` template** — three-layer defense (mirrors hook host pattern):

1. **Pre-scan** (`scan_imports`) eager-rejects modules whose imports do not match the `arkhe:observer/*` allow-list, with explicit specific-error paths for the WASI deny-list (`wasi:random`, `wasi:clocks`, `wasi:filesystem`, `wasi:sockets`, `wasi:io`, `wasi:cli`, `wasi:http`). Boundary check confines deny-list matching to WIT package boundaries (`/`, `@`, end-of-string).
2. **Link-time deny-by-default** — `Linker::new` only `func_wrap`s the `arkhe:observer/pg.write` dispatch shim that routes through registered `ObserverCapability` impls. Unknown imports (typos within the allow-list, e.g. `arkhe:observer/pg.writeee`) fail at instantiation.
3. **Call-time capability check** — every dispatch shim inspects `Caller::data().capabilities` (the per-invocation `ObserverStoreData::capabilities` `BTreeSet<ObserverCapToken>`) and traps `CapabilityDenied` if the matching `ObserverCapToken` is absent.

**v0.12 host-fn allow set**:

| Import path | CapToken | Sig | Behaviour at v0.12 (Track A.2.3) |
|---|---|---|---|
| `arkhe:observer/pg.write` | `PgWrite` | `(ptr: i32, len: i32) -> ()` | Reads `len` bytes from wasm memory at `ptr` (bounds-checked via shared `read_caller_memory<ObserverStoreData>`), looks up the `PgWrite`-tagged `ObserverCapability` impl in the host's registry, calls `execute(&bytes)`. `CapabilityExecutionError` (e.g. PG unreachable) is silently swallowed at the wasm boundary — operational metric, NOT chain-anchored Quarantine. Future v0.13+ DIP routes operational failures to typed metric + `runtime_doctor_journal` entry. |

Additional capabilities (KMS / metric / etc.) wait for BBS-dogfood evidence per the validated-repetition directive — non-breaking additive expansion of the `ObserverCapToken` `#[non_exhaustive]` enum.

**`ObserverCapability` trait** (E15.b interface — host-side abstraction):

```rust
pub trait ObserverCapability: std::fmt::Debug + Send + Sync {
    fn token(&self) -> ObserverCapToken;
    fn execute(&self, bytes: &[u8]) -> Result<(), CapabilityExecutionError>;
}
```

The `&[u8]` payload-only signature enforces chain-non-affecting clause 2 at type-level — every impl carries its effect to a layer outside the chain (projection / metric / vault), with no chain reference reachable from the trait surface. v0.12 ships one concrete impl `PgWriteCapability` (unit struct, zero fields = trivially chain-orthogonal — verified by compile-time `size_of::<PgWriteCapability>() == 0` test) + `MockPgWriteCapability` (test helper recording bytes via `Arc<Mutex<Vec<Vec<u8>>>>`). Real PG connection wiring is deferred to v0.13+ shell-territory DIP — the v0.12 impl returns `Ok(())` unconditionally so operators can declare the cap-token before the shell-side integration lands.

**Memory bounds-check contract** (`(ptr, len)` host-fn deref): the `arkhe:observer/pg.write` dispatch shim flows through `read_caller_memory<ObserverStoreData>` — the same generic helper as the hook host's `read_caller_memory<HookStoreData>`. Both share the cryptographer-pinned B.5 invariant: `len >= 0`, `ptr >= 0`, `ptr.checked_add(len)? <= Memory::data_size(&caller)`, OOB trap on violation. Drift-avoidance: the helper is generic over the wasmtime Store data type `T` and lives in `arkhe-forge-platform/src/wasm_runtime_common/`, ensuring single source of truth.

**3-tier ingestion** (Track A.2.2) — `WasmtimeObserverHost::register_module(bytes, expected_digest)` enforces:

- **Tier 1** (active in v0.12): BLAKE3 digest pin against operator-pinned `expected_digest` (typically sourced from manifest TOML). Mismatch → `DigestMismatch` at registration time, before any wasmtime engagement.
- **Tier 2** (sigstore sign-before-load) — scaffolded via the `attestation_class` field on `ObserverQuarantine`; v0.13+ integration mirrors the hook host's `HookAttestationVerifier` pattern.
- **Tier 3** (cargo-vet provenance) — scaffolded; v0.13+.

**Chain anchoring** (cryptographer-anchored chain-non-affecting clause 3 — host-supervised emission): when an observer wasm execution trips a sandbox-boundary failure, the runtime supervisor generates an `ObserverQuarantine` event (TypeCode `0x0003_0F0C`) carrying `(observer_module_digest, quarantine_tick, trap_class, attestation_class)`. The observer *triggers* emission via its trap, but does NOT *generate* it — the cryptographic chain anchor is host-owned. **Replay-side verification path**: on replay, the recorded `ObserverQuarantine.observer_module_digest` is matched against `blake3(registered_bytes)`; mismatch indicates manifest tampering or operator mis-deployment.

**`attestation_class` semantics (cryptographer A.2.4 anchor)**: the `attestation_class: RuntimeSignatureClass` field records the *observer module ingestion* attestation tier (Tier 1 BLAKE3 digest pin only at v0.12 → typically `None`; Tier 2/3 future paths set Ed25519 / MlDsa65 / Hybrid). NOT the event-signing class — the `ObserverQuarantine` event itself is chain-anchored under the runtime's standard signing path (E13 shell-per-tick `SignatureClassPolicy`), independent of this field. Same `RuntimeSignatureClass` enum, context-specific reading (mirrors `HookModuleRegister.attestation_class` C14).

**Trap classification** (Track A.2.3 `run_wasm_invoke`): wasmtime errors are translated coarsely:
- Fuel exhaustion → `ObserverError::BudgetExceeded` → `ObserverTrapClass::BudgetExceeded` Quarantine
- "called without `<Token>` capability" trap → `ObserverError::CapabilityDenied(token)` → `ObserverTrapClass::CapabilityDenied` Quarantine
- Other (incl. operator-config error "no impl registered" + OOB bounds-check + module instantiation failure + wasm panic) → `ObserverError::Trapped(static reason)` → `ObserverTrapClass::Panic` or `ObserverTrapClass::Other` depending on root-cause classification at supervisor side

**Quarantine boundary (cryptographer A.2.4 anchor)**: `ObserverError` variants trigger Quarantine emission (chain-anchored). `CapabilityExecutionError` from the `ObserverCapability::execute` impl (e.g., PG connection broken, write conflict) is **operational, NOT chain-anchored** — surfaces via metric / `runtime_doctor_journal` instead (v0.13+ DIP candidate). The boundary preserves the sealed-completeness distinction between sandbox-boundary failures (cryptographic concern → chain anchor) and downstream destination failures (operational concern → operator alert).

**Chain-non-affecting invariant (cryptographer-anchored 4-clause firm contract)**:

1. **No chain-mutation host-fn** — every binding under `arkhe:observer/*` routes to a side-effect destination outside the chain (PG projection, metric sink, KMS rotation receipt). No binding calls `Op::EmitEvent`, `Op::SpawnEntity`, or any chain-head-write primitive.
2. **Effect signature is chain-orthogonal** — every `ObserverCapability::execute(&self, bytes: &[u8])` impl carries its effect to a layer outside the chain. Borrow checker enforces no chain reference at type-level.
3. **Quarantine emission is host-supervised** — observer triggers via trap, *host* generates the chain-anchored receipt. Cryptographic chain anchor is host-owned.
4. **Panic isolation preserves chain progression** — wasmtime trap caught at `WasmtimeObserverHost::invoke` boundary; chain progression continues independently. Next-tick chain hash is unaffected by observer existence or panic state.

The 4-clause invariant + compile-time `_OBSERVER_CONTEXT_SHAPE_CHECK` const sentinel (verifies `ObserverContext` carries only the capability slice — future field additions trip the build) form the structural enforcement of E15 at the v0.12 cut.

**Per-host trap counter**: `WasmtimeObserverHost::trap_count` (`AtomicU64`, lock-free) increments on every `invoke()` Err. Operator telemetry surface; future trap_count threshold + module digest blacklist policy is a v0.13+ operator-runbook scope (E15 axiom body declares the *mechanism* — invariant 3 host-supervised emission — without prescribing a *threshold*).

### §14.6 ArkheUri included from R3+ — partial type-level (theorist m3)

> **`RoomMarker` reserved at SHAPE-only level** (§14.1.1, Track C, v0.12 sealing cycle): `RoomMarker` is the next free slot in the `0x0001_X001` Core Entity sub-range progression (`0x0001_5001`). The `EntityKind` impl shape is declared at v0.12 as spec text only — code-side TypeCode reservation lives in `arkhe_forge_core::typecode::ROOM_MARKER_RESERVED`. Implementation surface (Component / Action / VerbCode allocations + the `EntityKind` trait + per-marker `impl` blocks themselves) is deferred to v0.13 ecosystem-driven addition per D-USER-5 (iii).

```rust
mod kind_seal { pub trait Sealed {} }
pub trait EntityKind: kind_seal::Sealed + 'static {
    const TYPE_CODE: TypeCode;
}

pub enum UserMarker {}       impl kind_seal::Sealed for UserMarker {}
                             impl EntityKind for UserMarker   { const TYPE_CODE: TypeCode = TypeCode(0x0001_0001); }
pub enum ActorMarker {}      impl kind_seal::Sealed for ActorMarker {}
                             impl EntityKind for ActorMarker  { const TYPE_CODE: TypeCode = TypeCode(0x0001_1001); }
pub enum SpaceMarker {}      impl kind_seal::Sealed for SpaceMarker {}
                             impl EntityKind for SpaceMarker  { const TYPE_CODE: TypeCode = TypeCode(0x0001_2001); }
pub enum EntryMarker {}      impl kind_seal::Sealed for EntryMarker {}
                             impl EntityKind for EntryMarker  { const TYPE_CODE: TypeCode = TypeCode(0x0001_3001); }
pub enum ActivityMarker {}   impl kind_seal::Sealed for ActivityMarker {}
                             impl EntityKind for ActivityMarker { const TYPE_CODE: TypeCode = TypeCode(0x0001_4001); }
// RoomMarker — SHAPE-only declaration at v0.12 (§14.1.1); v0.13 ecosystem-driven implementation.
// pub enum RoomMarker {}    impl kind_seal::Sealed for RoomMarker {}
//                            impl EntityKind for RoomMarker { const TYPE_CODE: TypeCode = TypeCode(0x0001_5001); }

pub struct ArkheUri<K: EntityKind> {
    instance: InstanceId,
    shell: ShellId,
    local: EntityId,
    _kind: PhantomData<K>,
}

impl<K: EntityKind> fmt::Display for ArkheUri<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "arkhe://{}/{}/{}/{}",
               self.instance.get(), self.shell, K::TYPE_CODE.0, self.local.get())
    }
}

impl<K: EntityKind> FromStr for ArkheUri<K> {
    /// M4 strictened — instance prefix required. If absent, reject.
    /// Blocks federation v0.99+ gateway confused-deputy.
    fn from_str(s: &str) -> Result<Self, UriError> { /* requires instance prefix */ }
}

impl<K: EntityKind> ArkheUri<K> {
    /// Context-aware parse. For URIs internal to the same instance (prefix omitted).
    pub fn parse_within(instance_id: InstanceId, s: &str) -> Result<Self, UriError> { /* ... */ }
    pub fn canonical_bytes(&self) -> Vec<u8> { /* instance always included */ }
}

// Reserved for federation v0.99+ — Ed25519 signed wrapper (cross-instance URI integrity).
pub struct SignedArkheUri<K: EntityKind> {
    pub uri: ArkheUri<K>,
    pub signature: [u8; 64],   // Ed25519 (or PQC, §14.7 M8)
    pub signer_instance: InstanceId,
}
```

For a single instance, an **externally-entering URI must carry an instance prefix** (M4). `parse_within` alone permits a default instance. Blocks gateway confused-deputy — even if an adversary assigns instance B the same `(shell_id, local)` as instance A, from_str distinguishes them.

### §14.7 Runtime semver upgrade path — R4'.1 extension (retires sidecar + moves to in-band event)

**R4' sidecar approach retired (cryptographer C2)**: the `{wal_path}.runtime_meta` sidecar proposed in R4' has an integrity gap — an adversary with backup access can rewrite only the sidecar to keep the original L0 chain hash while swapping manifest_digest → tamper with `SpaceKind::Extension` semantics + replay-with-rewrite attack. Bypasses chain immutability.

**R4'.1 in-band event approach (C2 / E12)**:

```rust
/// Runtime bootstrap event — included in-band in the L0 chain hash.
/// Respects DO NOT TOUCH #8 (WalRecord postcard field order) — no L0 modification required.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F01 /* R5 NF5 — core Event subrange allocation */, schema_version = 1)]
pub struct RuntimeBootstrap {
    pub runtime_semver: SemVer,          // Runtime-defined in §14.7 (NR6-6)
    pub manifest_digest: [u8; 32],        // canonical TOML BLAKE3 (C5)
    #[arkhe(canonical_sort)]             // R5.3 R7-NR3 — field attribute opt-in (§3.5)
    pub typecode_pins: Vec<TypeCode>,    // snapshot of active TypeCodes (the derive sorts before serialize)
    pub bootstrap_tick: Tick,
}

/// R5 FG5 — chain-anchor for a shell's signature_class.
/// Reject Ed25519-only audit receipts after the tick at which a shell declared Hybrid.
#[derive(ArkheEvent, serde::Serialize, serde::Deserialize)]
#[arkhe(type_code = 0x0003_0F06, schema_version = 1)]
pub struct SignatureClassPolicy {
    pub shell_id: ShellId,
    pub class: RuntimeSignatureClass,
    pub effective_tick: Tick,
}
```

**R5.2 NR6-5 / R5.3 R7-NR3 `typecode_pins` canonical-bytes stability**: declared via the `#[arkhe(canonical_sort)]` field attribute (§3.5) — the derive auto-injects `sort_unstable()` on ascending `TypeCode(u32)` just before serialize. E12 MC digest stability — if manifest_digest changes due to different insertion orders of the same set, replay drift false-positives follow. Opt-in preserves arrival-order semantics of other `Vec<T>` fields by default.

**R5.2 NR6-6 — Runtime-defined `SemVer`**:

The `semver` crate (SemVer 2.0 spec) has variable-length pre-release / build metadata strings — postcard canonical bytes are unstable. The Runtime adopts a minimal fixed-layout struct:

```rust
/// Runtime's own SemVer (R5.2 NR6-6). No pre-release / build metadata.
/// postcard canonical = u16 × 3 = 6 bytes. Inherits A17.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct SemVer {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl SemVer {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self { Self { major, minor, patch } }
    /// Used in manifest runtime_min / runtime_max comparison.
    pub fn lex_cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}
```

Manifest `runtime_min = "0.12"` is parsed by `parse_semver()` into `SemVer::new(0, 12, 0)`. Pre-release suffixes (`"0.12.0-rc.1"`) are rejected — SemVer 2.0 compatibility is sacrificed, canonical-bytes stability prioritized.

**R5 M-R5-1 / R5.2 NR6-4 — `RuntimeSignatureClass` (L0 DO NOT TOUCH #3 protection)**:

L0 `arkhe_kernel::SignatureClass` inspection (R5.2 NR6-4, as of 2026-04-24):

- **Visibility**: `pub enum SignatureClass` (arkhe-kernel/src/persist/signature.rs:28). Accessible to external crates.
- **Variants**: `None` (unit) + `Ed25519 { signing_key: SigningKey, verifying_key: VerifyingKey }` (struct variant, holds key material).
- **Attrs**: `#[non_exhaustive]`, `#[derive(Default)]`, **no `Serialize/Deserialize`** — because `SigningKey` must never be included in WAL bytes (operational configuration).

**Structural implications**:
- L0 `SignatureClass` is **operational runtime config** (holds keys).
- Runtime `RuntimeSignatureClass` is a **wire-format class tag** (receipt / policy event).
- Keep the two concepts distinct via a separate enum + explicit `From` path.

```rust
/// Runtime-only wire-format class tag — keeps L0 SignatureClass derive unchanged (DO NOT TOUCH #3).
/// postcard canonical = 1 byte (repr(u8)). Inherits A17.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RuntimeSignatureClass {
    None    = 0,
    Ed25519 = 1,
    MlDsa65 = 2,   // Dilithium (FIPS 204) — PQC
    Hybrid  = 3,   // Ed25519 + MlDsa65 dual-sign
}

/// L0 operational config → wire-format class tag. Drop keys, extract only the class.
impl From<&arkhe_kernel::SignatureClass> for RuntimeSignatureClass {
    fn from(k: &arkhe_kernel::SignatureClass) -> Self {
        use arkhe_kernel::SignatureClass as L0;
        match k {
            L0::None              => Self::None,
            L0::Ed25519 { .. }    => Self::Ed25519,
            L0::Hybrid { .. }     => Self::Hybrid,  // v0.12+ Hybrid (Ed25519 + ML-DSA 65)
        }
    }
}
```

Reference-based `From<&L0::SignatureClass>` — the L0 value must not have its key dropped, so borrow instead of move to copy only the class tag. **At v0.12 the L0 DIP is complete**: WAL postcard envelope provisioned (`verifying_key_pqc` field 11 + `signature_pqc` field 13) and Hybrid signing/verify path active per CNSA 2.0 transition spec. The Layer A item 8 escalation (envelope monotone append-only) preserves WalRecordBody chain-hash input bytes invariant — A1 bit-identical replay holds for all V99-1+ records.

**Type distinction along the audit receipt signing path**:
- L2 receipt issuers branch on `RuntimeSignatureClass` (including MlDsa65 / Hybrid).
- L0 WAL chain-hash signing uses the L0 `SignatureClass` value directly. **At v0.12+, Hybrid is the recommended class** for new WALs (write-side strict mode); Ed25519 stays sticky in WAL header for pre-Hybrid replay continuity (read-side backward-compat).

**§14.11 audit receipt path explicit**: the receipt issuer reads the manifest `[audit.signature_class]` value and signs with the corresponding key. Receipts issued after `SignatureClassPolicy` event's `effective_tick` enforce that class — the verifier cross-checks against the event snapshot.

**Emission times** (`RuntimeBootstrap`):
1. WAL first tick (instance initial start).
2. On every manifest change (first tick after runtime restart).
3. On Runtime semver bump.

**Emission times** (`SignatureClassPolicy`, R5 FG5):
1. On shell manifest `[audit.signature_class]` change (first tick after restart).
2. At completion of PQC migration (`arkhe-runtime-doctor pqc-reseal`) rewrite.

**Replay integrity (E12 MC + R5 FG7 ManifestDrift opacity)**:
- On replay init, MC-check that `manifest_digest` in the WAL's `RuntimeBootstrap` event matches the canonical digest of the currently-loaded manifest.
- Mismatch → `ReplayError::ManifestDrift` + replay reject.
- **Public error surface is opaque (R5 FG7)** — `ReplayError::ManifestDrift`'s Debug/Display is limited to "manifest mismatch (see operator log)". Expected digest / actual digest not exposed (blocks adversary oracle). Detailed values only recorded in `runtime_doctor_journal`.
- `runtime_semver` forward-compat rules retained below.

**Forward-compatible rules** (R4'/R5 integrated, R5 NF3 duplicate removal):
- Adding new TypeCodes OK.
- Removal of existing TypeCodes forbidden.
- Bumping schema_version of an existing TypeCode — on replay, existing records decode with the schema_version at that point.
- Adding a field to an existing TypeCode schema — only via `#[serde(default)]` or `Option<T>`. Field removal forbidden.

**Existing WAL migration** (R5 NF4 — "sidecar" wording substitution complete):
- WALs from before R4' using sidecar metadata have `RuntimeBootstrap` events retroactively prepended via the `runtime-doctor chain-prepend` command. Operator Ed25519 signs + `runtime_doctor_journal` append. Accompanied by a chain-tip change (explicit operator approval required).
- **R5 R5-r3 — transparency log verification recommendation**: the result of `chain-prepend` should be recorded in Sigstore/Rekor (or an in-house Merkle + periodic publish) as an entry with operator signature + new chain-tip digest. External auditors can independently verify prepend time · signer · before/after digest.

**Conclusion regarding the WAL header**: DO NOT TOUCH #8 (WalRecord postcard field order) is **immutable**. Modifying L0 `WalRecord` requires an L0 DIP first. R4'.1 / R5.1 solves the problem with an in-band event — zero L0 modification.

**Enum WAL compat (C10 / S3 / auditor N3)**:
- Every `#[non_exhaustive]` enum has `#[repr(u8)]` or serde `tag` explicit index.
- No reordering of existing variants, no removal.
- New variants appended only at the end.
- Extension variant is always last.
- Default reject on the compute path (§3.4 NC5).

**Replay upgrade** (R5 NF4 — RuntimeBootstrap-event based):
- `RuntimeBootstrap.runtime_semver` < current = forward replay OK.
- `RuntimeBootstrap.runtime_semver` > current (downgrade) = `ReplayError::RuntimeVersionTooNew` reject.
- `typecode_pins` superset OK, subset reject.

**Shell sunset policy (veteran N4)**:
- Shell uninstall = manifest `[deprecated]` flag.
- TypeCode pins retained; new Entity creation L2-gate rejected.
- Existing records replay-only.
- `arkhe-runtime-doctor sunset-audit` command — reports remaining record count + last-access for the deprecated shell.

**CI gate** (auditor N6 / S9):
- `arkhe-forge-abi-check` — build-time check that the currently-registered TypeCodes of the crate form a superset of the previous semver. CI fails on commits that remove a registered TypeCode. Build-time MC promotion.

**PQC migration path (M8 + R5 C-R5-5b timeline enforcement)**:

`RuntimeSignatureClass` is defined above as a Runtime-only enum separated from L0 `SignatureClass` — protects L0 DO NOT TOUCH #3.

- default = `Ed25519` (v0.11 compatible).
- Shells select via manifest `[audit.signature_class]`. Timeline validation (§5.6): Ed25519-only is rejected when `runtime_max ≥ "0.30"`.
- **2030 dual-signing recommended** (safety margin for CRQC, NIST recommendation).
- **2035 PQC-only target** (Ed25519-only audit records carry forgery risk).
- During 2027–2029, Ed25519-only shells carry a warning flag + marketplace UI exposure.
- `arkhe-runtime-doctor pqc-reseal` — rewrites existing Ed25519 records as Hybrid. Changes chain tip + mandatory operator Ed25519/MlDsa65 sign + `runtime_doctor_journal` record + emits `SignatureClassPolicy` event (FG5).
- `arkhe-runtime-doctor pqc-timeline-audit` — signature_class vs runtime_max timeline readiness dashboard for all shells.
- **BLAKE3 is Grover-resistant**: current 32-byte output = 128-bit post-quantum security (post-Grover). Consider `BLAKE3::extended` in v0.99+ if 512-bit output is required. Current safety margin explicit.

**R5.2 M-R6-4 — Alpha→beta crypto migration (software-kek → HSM)**:

Path to upgrade a WAL run under `software-kek` at `runtime_max ≤ "0.15"` to the `runtime_max ≥ "0.16"` HSM backend. The master key reference mismatch is the structural problem.

**R5.3 HF1 — Tier-0 software-kek process protection obligation (shared prerequisite for Options 1 / 2)**:

A software-kek-operating process is obliged at the operational stage to protect key-material memory residency:

1. **`mlock_all()`** — blocks paging / swap (no VM swap disk residue).
2. **`prctl(PR_SET_DUMPABLE, 0)`** — blocks core dump creation (blocks key-material dump on panic).
3. **ptrace-protection enabled** — setuid capability or `yama.ptrace_scope = 2` recommendation (restricts kernel-level root-account ptrace).
4. **Runtime startup capability check** — if any of the above 3 fails to activate, `RuntimeInitError::ProcessProtectionUnavailable` + startup reject (alpha but no protection bypass).

Threat model: assume the host-OS access holder is effectively the master-key holder. Internet isolation / air-gap operation recommended (reflected in §14.9.1 §§12 Tier-0 annotation).

**Option 1 (default, team-lead recommendation)**: full erasure of alpha data.
- Basis for "software-kek = **test-only assumption**". No real users (§14.9.1 Tier-0).
- `runtime-doctor wipe-alpha --confirm <phrase>` — deletes all of WAL + projection + tombstone_log (operator Ed25519 + journal append).
- Then HSM initialization + new WAL start. Minimum migration cost.
- With process protection active, wipe and restart the process — eliminates memory fragments at the source (R5.3 HF1).

**Option 2 (advanced, when data preservation is required)**: `runtime-doctor crypto-migrate-software-to-hsm` offline batch.
- Step 1: HSM generates a new per-user DEK + wrap (§14.9.1 §§2 envelope).
- Step 2: decrypt every `EncryptedPii<T>` ciphertext with the software-kek DEK → re-encrypt with the new HSM DEK.
- Step 3: emit `DekMigrationCompleted { old_dek_id, new_dek_id, user_id, migrated_tick }` event (new TypeCode 0x0003_0F09 reserved) + change chain tip.
- Step 4 (**R5.3 HF1 restated**): record the software-kek DEK in the tombstone log + **full process restart**. After migration completes, a runtime process restart is mandatory — since plaintext DEKs transiently reside in process memory during re-encryption, restart eliminates memory fragments at the source.
- Operator Ed25519 sign + `runtime_doctor_journal` append mandatory. External auditor confirms `DekMigrationCompleted` event count == user count.
- **Note**: during migration `observer_state='degraded'` — L2 new writes blocked, resume after migration + restart complete.
- Option 2 batch tool planned for v0.12+ (implementation scope is in the v0.12 implementation DIP).

`DekMigrationCompleted` Event TypeCode **0x0003_0F09** reserved (§3.2 table only marks R5.2 reservation; formal struct definition at v0.12).

**L2 serving disable during replay (m3)**: during replay, `AuthCredential`s whose `bound_tick` is future-dated may be temporarily invalid — L4 serving can respond with false negatives. Solution: **disable L2 serving entirely during replay** — when `kernel_projection_state.observer_state = 'replaying'`, L4 requests get 503 Service Unavailable + `Retry-After` header. Resume when replay finishes.

**Runtime BLAKE3 domain string list (m4)**:

| Domain string | Use | Location |
|---|---|---|
| `arkhe-forge-verb-alloc` | verb sub-range determination (shell_id BLAKE3) | §3.2 |
| `arkhe-forge-manifest-digest` | canonical TOML digest | §5.6 |
| `arkhe-forge-audit-receipt` | Ed25519/PQC audit receipt MAC | §5.2, §14.11 |
| `arkhe-forge-runtime-bootstrap` | RuntimeBootstrap event MAC | §14.7 |
| `arkhe-forge-signature-class-policy` | SignatureClassPolicy event MAC | §14.7 / E13 |
| `arkhe-forge-entity-id` | deterministic EntityId generation | §4.7 |
| `arkhe-runtime-doctor-journal-chain` | `runtime_doctor_journal` chain hash domain (HF2 audit-log tamper-resistance) | §12.4 / §14.11.2 |

CI (extension of `arkhe-forge-abi-check`) scans the entire source and fails on use of an unregistered domain string. List changes are accompanied by updates to this §14.7 document.

**Offline migration tool — `arkhe-runtime-doctor`** (veteran N3 / S5):
- `manifest-digest-recompute` — recompute canonical TOML (C5).
- Prints WAL header `runtime_semver` / `manifest_digest`.
- TypeCode-range record statistics.
- Snapshot rebuild.
- `sunset-audit` — residual records of a deprecated shell.
- schema_version bump rewrite of legacy records (optional, accompanied by chain-tip change — explicit operator consent).
- **Operator authentication + audit**: every rewrite command requires an Ed25519 signature (reusing A16). `runtime_doctor_journal` table is append-only (§12.4). Public chain-tip publish (GitHub release or internal transparency log).

### §14.8 Multi-L2 model — extension (X6 + C6 idempotency)

**R4' operational model**: **active-passive 1+N** + **client-supplied idempotency key**.

- Only the active L2 calls kernel `submit`.
- Passive L2 is read-only via WAL projection, synchronized.
- Failover: active failure → passive promotion (operator or lease expiry).

**Idempotency key (C6 / veteran N2 / R5 Axis 3 PG-only primary + FG6 WAL anchor)**:
- The L4 request header `X-Arkhe-Idempotency-Key: <UUID v4>` is mandatory. L2 pass-through via the `idempotency_key: Option<[u8; 16]>` field of an **`#[arkhe(idempotent)]` opt-in L1 Action** — the Action body is included as postcard-encoded inside the WAL record payload (no impact on L0 WalRecord field order DO NOT TOUCH #8).
- **Primary dedup (R5 Axis 3)**: PG `UNIQUE INDEX (idempotency_key) + INSERT ON CONFLICT DO NOTHING + expires_at TIMESTAMPTZ` + background TTL cleanup (partition drop, default 10min retention). 5–10min dedup window.
- **Redis `SETNX` alternative**: activated only in production with < 5ms SLA requirement. Selected via manifest `[quota.storage_backend = "redis"]`.
- During failover, client retry with the same key → duplicate response (returns prior submit_result) — PG row or Redis key hit.
- Metric `arkhe_runtime_idempotency_duplicate_total`.

**R5 FG6 — blocks active-passive failover idempotency race (aligned with Axis 3 PG-only)**:

A two-phase race (SETNX pending → submit → SET result) allows the active to crash right after SETNX — after passive promote, the same key can be resubmitted → duplicate Op emission. R5.1 / R5.2 solution:

1. **Opt-in `idempotency_key: Option<[u8; 16]>` field on the L1 Action body** — only Actions declared with the `#[arkhe(idempotent)]` attribute (R5.2 NR6-2) get the derive compile-time assert. Non-idempotent Actions keep the existing structure. `#[derive(ArkheAction)]` verifies the field's presence.
2. **compute-internal scan** — call `ctx.idempotency_lookup(&self.idempotency_key)` (R5.2 NR6-3 / §3.3). On hit return the existing `(entity_id, tick)` → deterministic noop (no Op regeneration). On miss process as new.
3. **Crash recovery** — on passive promotion, catch-up replay from `kernel_projection_state.last_applied_tick`. `idempotency_lookup` finds the same key → skips already-applied Actions + returns the stored response.
4. **Redis not required**: the WAL chain alone shrinks the race window (single primary) + backup replay is consistent. Satisfies the alpha/beta PG-only environment.

**2-layer dedup structure (R5.2 mNF-A)**: the §5.2 table makes this explicit — L2 PG `UNIQUE INDEX` fast pre-filter (5–10min window, absorbs normal traffic) + L1 WAL scan via `idempotency_lookup` crash-recovery backstop (scenario: passive promote + simultaneous PG/Redis loss). The two paths are orthogonal — on L2 fail-open, L1 is the backstop; the L1 scan cost is not on the hot path.

Metric `arkhe_runtime_idempotency_wal_scan_ms` histogram (scan cost monitoring, target: N-tick scan < 5ms p99).

**R5.2 m-R6-1 — L0 `SubmitAction` extension boundary**: R5.1 wording said "Runtime-owned", but in reality L0 `SubmitAction` (and the `WalRecord` postcard field order, DO NOT TOUCH #8) are kernel-defined. **Adding an `idempotency_key` field is a precondition for an L0 v0.12 DIP**. Within the scope of this DIP (v0.12 Runtime):

- Operate the **PG `UNIQUE INDEX` path** (§5.2 table / §14.8 primary dedup) as the sole channel.
- The `idempotency_lookup` trait method activates once L0 v0.13+ provides a WAL auxiliary index (R5.4 theorist L0 version notation consistency — aligned with the §5.2 R7-NR4 footnote). At Runtime v0.12 implementation time, only L0 v0.11 is available, so this is a **no-op stub** (always returns `None`) — functionally depends only on the PG UNIQUE INDEX.
- An Action declared `#[arkhe(idempotent)]` may still be defined in v0.12 Runtime, but is **ineffective because the stub returns None**. Actual WAL scan activation after L0 v0.12 DIP completion.

This separation respects "L0 DO NOT TOUCH" while fixing the Runtime API surface in advance — Runtime client code needs no modification when L0 is extended.

**Active writer same-tick ordering (M1)**:
- When multiple L4 Actions arrive on the same tick, **L4 arrival-timestamp strict FIFO** + order preservation within the same L4 connection.
- Timing-critical shells (Casino etc.) declare `manifest [shell.ordering_policy = "commit_reveal"]` — the active writer applies commit/reveal phase-based reordering (Band 3 shell responsibility).
- Front-running defense by network latency advantage: because FIFO-by-arrival depends on net latency, **publishing the low-latency peer connection topology** is recommended. Truly fair ordering requires shell-level commit-reveal.

**Mutex race cannot arise** (single active → manifest mutex validation sequential).

**Multi-active is a separate DIP**. Candidate solutions:
- Promote mutex groups to L1 kernel state → extension of Band 1 invariants (high cost).
- L2 distributed lock (Redis RedLock) — determinism contamination risk.
- Active shard split (active L2 per shell_id) — split-brain management on redistribution.

R1-R4' scope is single-active.

### §14.9 GDPR cascade policy — extension (X1 / C3 / P3)

**Problem**: 10^8 Ops in a single compute stops the L0 single-thread.

**Solution** (lease + L2 background):
1. `GdprEraseUser::compute` → `[SetComponent(UserProfile{gdpr_status: ErasurePending}), EmitEvent(UserErasureScheduled)]` only.
2. L2 erasure-cascade observer → per-tick bounded batch (config default 1,000 Op/tick):
   - From tick T+1: Actor lookup (user_id=target), per tick despawn N actors + EntryBody removal + Activity retract.
   - Each batch `Op::ScheduleAction` re-submitted at tick+1 (E11).
3. Completion condition: remaining Actor/Activity = 0 → `SetComponent(UserProfile{gdpr_status: Erased}) + EmitEvent(UserErasureCompleted)`.

**L1 compute MC gate (C3 / B3 resolution)**:
- gdpr_status check on every actor-originated compute (§3.3).
- Any Action from an actor with `gdpr_status == ErasurePending` is rejected.
- The L2 gate is a pre-filter, but L1 compute is the final defense — a double MC barrier.
- `GdprPolicyViolation` event recorded in the kernel WAL (audit trail).

**Tick-scoped gdpr cache (P3)**:
- Within the same tick, gdpr_status reads for the same user_id share a single lookup.
- Reuses L0 InstanceView's tick-scoped cache (P2).
- Metric `arkhe_runtime_gdpr_cache_hit_ratio{shell_id}`.

**SLA (E-user-3 RA)**:
- p95 completion < 24h.
- p99 < 72h (power user: 30 shells × 10^6 entries).
- Beyond 72h → operator alert.

**Safeguards**:
- Per-user Op ceiling 10^7 (config). Exceed = operator confirmation.
- Mid-cascade failure → resume from the projection.
- Progress via Prometheus `arkhe_runtime_gdpr_cascade_remaining_ops`.

#### §14.9.1 Crypto-erasure policy — R5.1 rewrite (M5 / GDPR Art. 17 + R5 C-R5-1/3/4 + FG3/FG4 + M-R5-2/3 + NF8)

**Reading order (R5.3 m-R7-2)**: determine your environment by §§12 Compliance Tier → §§1 EncryptedPii wire → §§10 (§14.9.1.1) Operator runbook → rest of the deep material. Subsection order is not by importance — deep-read only the subsections for your chosen tier.

**Problem**: the §14.9 cascade is Component-level `RemoveComponent(EntryBody)` only. The original WAL `SubmitEntry` permanently preserves `handle`, `body_hash`, `extra_bytes` (L0 A14 chain immutability). `body_hash` is PII under rainbow-table pre-image (GDPR Recital 26). During regulatory audit, residual WAL PII → up to 4% annual revenue fine risk.

**Solution (Envelope-based crypto-erasure)**:

##### 1. `EncryptedPii<T>` — type-safe wire format (R5 C-R5-4)

R4'.1 `EncryptedPii<T>` lacked a T bound + T information on the wire → **type confused-deputy** (decrypting the same ciphertext as a different T could leak handle as body). R5.1 redesign:

```rust
/// PII payload trait — wire-embedded code + canonical encode.
/// R5.2 NR6-7 — sealed. Only the Runtime crate may impl (PII_CODE 0x0001..=0x00FF).
/// Shell-scoped PII uses a separate `ShellPiiType` wrapper + manifest registration path (see below).
pub trait PiiType: CanonicalEncode + pii_seal::Sealed {
    /// `PII_CODE` is fixed at 2B on the wire — blocks the type confused-deputy.
    /// Runtime canonical: 0x0001..=0x00FF. Shell-scoped: 0x0100..=0xFFFF.
    const PII_CODE: u16;
}

mod pii_seal { pub trait Sealed {} }

/// Wrapper holding a PII encrypted under the per-user DEK.
/// canonical_bytes = (dek_id, pii_code, aead_kind, nonce, ciphertext).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct EncryptedPii<T: PiiType> {
    pub dek_id: DekId,              // HSM/KMS key reference (per-user)
    pub pii_code: u16,              // R5 C-R5-4 included on wire (2B) — cross-checked with T::PII_CODE
    pub aead_kind: AeadKind,        // R5 C-R5-1 — AEAD choice on the wire (misuse-resistant)
    pub nonce: NonceBytes,          // 12B (AES-GCM) / 24B (XChaCha20) / 12B (AES-GCM-SIV)
    pub ciphertext: bytes::Bytes,   // AEAD tag included (last 16B)
    _marker: PhantomData<T>,
}

#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AeadKind {
    XChaCha20Poly1305 = 0,   // default — 192-bit nonce, misuse-resistant
    Aes256Gcm         = 1,   // hardware acceleration
    Aes256GcmSiv      = 2,   // RFC 8452 — nonce-reuse resistance
}

impl<T: PiiType> EncryptedPii<T> {
    /// R5.2 NR6-1 — AEAD AAD = dek_id || pii_code.to_be_bytes() || (aead_kind as u8).
    /// Tampering with the wrap fields fails AEAD tag verification → `PiiError::AadMismatch`.
    fn compute_aad(dek_id: &DekId, pii_code: u16, kind: AeadKind) -> [u8; 19] {
        let mut aad = [0u8; 19];
        aad[..16].copy_from_slice(&dek_id.0);
        aad[16..18].copy_from_slice(&pii_code.to_be_bytes());
        aad[18] = kind as u8;
        aad
    }

    pub fn encrypt(
        dek: &[u8],
        dek_id: DekId,
        kind: AeadKind,
        plaintext: &T,
    ) -> Self {
        let aad = Self::compute_aad(&dek_id, T::PII_CODE, kind);
        let nonce = gen_nonce(kind);                          // kind-specific nonce generation
        let pt_bytes = plaintext.canonical_bytes();
        let ciphertext = aead_encrypt(kind, dek, &nonce, &aad, &pt_bytes);
        Self {
            dek_id,
            pii_code: T::PII_CODE,
            aead_kind: kind,
            nonce,
            ciphertext,
            _marker: PhantomData,
        }
    }

    pub fn decrypt(
        self,
        dek: &[u8],
        manifest_cipher: AeadKind,   // R5.2 GF2 — manifest `[audit.pii_cipher]` injected
    ) -> Result<T, PiiError> {
        // R5 C-R5-4 — blocks the type confused-deputy
        if self.pii_code != T::PII_CODE {
            return Err(PiiError::TypeMismatch);
        }
        // R5.2 GF2 — AeadKind downgrade block (manifest-anchored check)
        // mismatch between current manifest pii_cipher and the record's aead_kind → reject.
        // Exception path — when a manifest bump (§9.1 GF2) permits the old cipher by policy,
        // verify the record's pii_cipher at the time of creation from the shell manifest history table.
        if self.aead_kind != manifest_cipher {
            return Err(PiiError::CipherDowngrade);
        }
        // R5.2 NR6-1 — recompute AAD then AEAD verify
        let aad = Self::compute_aad(&self.dek_id, self.pii_code, self.aead_kind);
        let pt_bytes = aead_decrypt(self.aead_kind, dek, &self.nonce, &aad, &self.ciphertext)
            .map_err(|_| PiiError::AadMismatch)?;
        T::from_canonical_bytes(&pt_bytes).map_err(PiiError::DecodeFailed)
    }
}

/// `DekId` is an HSM/KMS key reference — the Runtime holds only the id, no plaintext key.
pub struct DekId(pub [u8; 16]);

/// Shell-scoped PII wrapper (R5.2 NR6-7). 0x0100..=0xFFFF.
/// Shell crate extends via `impl ShellPiiType for MyShellPayload`.
/// The Runtime pins per-shell ranges via manifest `[audit.shell_pii_code_range = { from, to }]`
/// + prevents overlap. Shell PII is shell-owned — the Runtime keeps only PII_CODE range separation.
pub trait ShellPiiType: CanonicalEncode {
    const PII_CODE: u16;      // within the manifest-registered range
}
```

**PII_CODE allocation convention (R5.2 NR6-7)**:

| Range | Owner | Reservation |
|---|---|---|
| `0x0001..=0x00FF` | **Runtime canonical** — `PiiType` sealed, only Runtime-internal impls allowed | Currently 4 (ActorHandle=0x0001 / EntryBody=0x0002 / ActivityExtraBytes=0x0003 / AuthCredentialSecret=0x0004). A new allocation = Runtime DIP. |
| `0x0100..=0xFFFF` | **Shell-scoped** — `ShellPiiType` wrapper trait, usable after shell manifest `[audit.shell_pii_code_range]` registration | Runtime rejects per-shell duplicate registration (registry). Shell owns PII definition + wire format. |
| `0x0000` | **reserved** (wire-level tombstone — do not use) | — |

**PII_CODE reservation (R5.1 C-R5-4)**:

| PII type | `PII_CODE` | Applied Component |
|---|---|---|
| `ActorHandle` | `0x0001` | `ActorProfile.handle` |
| `EntryBody` | `0x0002` | `EntryBody.body_plaintext` (optional) |
| `ActivityExtraBytes` | `0x0003` | `ActivityRecord.extra_bytes` (shell discretion) |
| `AuthCredentialSecret` | `0x0004` | auxiliary credential secret (the default KDF salt is already per-credential random) |

Allocation of a new PII type requires updating this table + a schema_version bump.

##### 2. Envelope encryption — HSM-generated DEK (R5 C-R5-3)

R4'.1 had two simultaneously-true propositions that were **impossible**: the `blake3::derive_key("arkhe-forge-user-dek", master_kms_key || user_id_bytes)` derivation and the statement "DEK exists only in HSM/KMS" (all DEKs recoverable once the master key leaks). R5.1 solution — **envelope encryption redesign**:

1. **The HSM generates the per-user DEK with its own randomness** — the Runtime does not derive it. The derivation formula is removed.
2. **The HSM master wraps the DEK** → the Runtime stores only `DekId` + `wrapped_dek: Bytes` (plaintext DEK remains inside the HSM).
3. **Encryption** — when the Runtime writes a PII field, it requests the HSM `Decrypt(wrapped_dek) → plaintext_dek` (fast inside HSM), then AEAD encrypts with the result. The plaintext DEK is zeroized and discarded from Runtime process memory.
4. **Erasure** — HSM `delete_key(dek_id)` → plaintext DEK removed. The `wrapped_dek` becomes permanently unwrappable → ciphertext undecryptable.
5. **HSM master rotation (FIPS 140-3 recommends 1 year)** — envelope re-wrap (fast inside HSM; no ciphertext re-encryption).

##### 3. AEAD choice (R5 C-R5-1) — nonce reuse / 2^32 message limit

AES-GCM, per NIST SP 800-38D, carries a birthday bound of ~2^32 messages with random 96-bit nonces — across 10 years × 10^6 entries/user × 30 shells, cumulative collision is possible. On collision, GCM integrity is destroyed globally + plaintext leaks.

**R5.1 policy**:
- **Default = XChaCha20-Poly1305** (192-bit nonce, misuse-resistant). Default when shell manifest `[audit.pii_cipher]` is omitted.
- When choosing `AeadKind::Aes256Gcm`, **deterministic counter nonce** is mandatory — `nonce = counter_be_bytes[8] ++ random[4]`. DEK rotation right before counter overflow.
- `AeadKind::Aes256GcmSiv` (RFC 8452) — hybrid option (HW acceleration + nonce-reuse resistance).
- **DEK rotation trigger**: track per-DEK message count (metric `arkhe_runtime_dek_message_count{user_id}`).
  - Warn at 2^30 messages.
  - **Force rotation + envelope re-wrap** before 2^32. HSM generates a new DEK → existing ciphertext remains decryptable only by the former DEK (keep both wrapped_deks for a short window).

##### 4. PII scope + body_hash salt (R5 NF8)

- `ActorProfile.handle` — the handle itself is an identifier → `EncryptedPii<ActorHandle>` (PII_CODE 0x0001).
- `EntryBody.body_hash` — **per-user + per-record nonce** (R5 NF8 linkability block):
  ```
  body_hash = BLAKE3(body || user_salt || entry_nonce)
  ```
  - `user_salt`: per-user 128-bit HSM-held. **R5.2 mNF-C — immutable**: generated by the HSM at user creation, unchangeable until `GdprEraseUser` cascade DEK shred. `user_salt` rotation requires **full re-write of the user's PII** — operationally disallowed. On shred, all entries become undecryptable.
  - `entry_nonce`: per-record 128-bit, a plaintext field of `EntryBody` (replay-deterministic).
  - **Responsibility boundary**: L2 reads `user_salt` from the HSM + pre-computes `body_hash` → L1 only stores the finished `body_hash`. HSM calls are forbidden inside L1 compute (inheriting A11 pure).
- `AuthCredential.credential_hash` — already salted Argon2id/Scrypt (§4.1). Extra encryption unnecessary.
- `ActivityRecord.extra_bytes` — shell discretion (per-user encrypt recommended). Uses PII_CODE 0x0003.
- `SpaceConfig.slug` — public identifier (not an encryption target).

##### 5. DEK lifecycle + shred receipt

1. At user creation, the HSM generates a DEK + wraps with the master → Runtime stores `(DekId, wrapped_dek)`.
2. Per-user PII writes go through the envelope path above.
3. On `GdprEraseUser` cascade completion, HSM `delete_key(dek_id)` → plaintext DEK removed.
4. Subsequent ciphertext is undecryptable = effective erasure.
5. Shred evidence: `Op::EmitEvent(UserErasureCompleted { user, dek_shred_tick, attestation })` — `attestation` = HSM "key destruction attestation" serialized bytes (Ed25519 or PQC signature, §14.7 M8).

**SLA**:
- p95 DEK shred < 24h.
- p99 < 72h.
- Beyond 72h → operator alert + regulator notification preparation.

##### 6. HSM SPOF + degraded mode (R5 C-R5-5a)

**HSM/KMS required** by default. Exception (team-lead directive 2026-04-24):
- `[audit.dek_backend = "software-kek"]` is valid only in the `runtime_max ≤ "0.15"` alpha milestone (§5.6). Replaced by process-memory master key + audit log, for ≤1k-user test environments only. Permanent warning tag on dashboards/logs (`arkhe_runtime_software_kek_alpha_mode=1`).

**On HSM outage (R5 R5-r4 degraded mode + R5.2 M-R6-2 threshold concretization)**:
- **Degraded mode trigger** (R5.2 M-R6-2): transition to `observer_state='degraded'` when any of the following holds.
  - **5 consecutive HSM timeouts** (per-request timeout default 2s), or
  - **Error rate ≥ 50% within a 60s window** (sum of HTTP 5xx / network error / auth failure).
  - Transition is automatic — no manual operator intervention required. Recovery is automatic when **error rate ≤ 5% for 30 consecutive seconds** is reached.
- `observer_state='degraded'` → L2 new writes **blocked** (PII writes impossible), read path retained (decryption after HSM recovery).
- `arkhe_runtime_hsm_unavailable_total{region}` counter + PagerDuty Critical (§12.4.1 SLO table).
- `runtime-doctor hsm-health` command — current error rate / consecutive timeout count / fallback-active dashboard.
- Multi-KMS primary/secondary pattern (§14.11.2) — on primary outage, operator-initiated promote to secondary (automatic fallback only when m-R6-2 `[audit.kms_auto_promote = "after_60min"]` is selected).

##### 7. DEK replication policy (R5 M-R5-3)

Manifest `[audit.dek_replication]`:

| Value | Meaning | Applicability |
|---|---|---|
| `global-hsm` (default) | Global replication by a single HSM vendor (e.g. AWS KMS multi-region key). All-or-nothing shred, SLO lag < 5min. | General deployments |
| `per-region` | Separate DEK per region. Cross-region access via re-encryption. For jurisdictions with strict per-jurisdiction data residency (EU / SG / KR). | Regulatory-sensitive |

##### 8. HSM insider threat mitigation (R5 FG3)

An HSM root operator can forge attestations → risk of issuing a "destroyed" receipt without actual destruction. R5.1 defenses:

1. **Multi-party threshold HSM (t-of-n Shamir)** — the master key permits export/destroy only with `t` approvers. Recommended: `t=3, n=5`. A single operator cannot tamper with keys.
2. **Public transparency log** — register `UserErasureCompleted` event hash + HSM attestation in **Sigstore/Rekor** (or an in-house Merkle + periodic publish). External auditors verify independently.
3. **Tamper-evident counter** — include the destruction log sequence number (monotonic counter) in HSM attestation. Detect gap / rewind.
4. **§14.11 runbook items** (below) — procedures for periodic attestation verification.

##### 9. GDPR precedent / regulatory citations (R5 FG4)

Legal basis that crypto-erasure satisfies GDPR Art. 17 "effective erasure":

- **EDPB Guidelines 04/2019** (Controller/Processor) — rendering data into an irrecoverable state.
- **EDPB Opinion 04/2022 on Transfers** — pseudonymisation → anonymisation via key destruction.
- **Article 29 WP Opinion 05/2014 on Anonymisation Techniques** — irreversibility criteria + crypto-erasure path.
- **ICO Anonymisation guidance (2023)** — key destruction recognized as "unrecoverable".
- **UK DPA 2018 Schedule 3** — cryptographic erasure as part of technical measures.

Detailed evidence is in `docs/Legal/gdpr-crypto-erasure.md` (separate doc accompanied by legal review). §14.9.1 covers operational policy only.

##### 10. §14.9.1.1 Operator runbook (R5 M-R5-2)

GDPR erasure request processing sequence:

1. L2 UI submits a `GdprEraseUser` Action → `UserErasureScheduled` event recorded in the WAL.
2. L2 erasure-cascade observer starts Component-level removal batches (§14.9).
3. On completion of all Component removal, L2 calls HSM `delete_key(dek_id)`.
4. The HSM's returned attestation → emit `UserErasureCompleted` event (in WAL).
5. `BackupErasurePropagated` event — after per-region tombstone apply (§14.11.1).

**HSM call failure handling (exp backoff ×3)**:

| Attempt | Wait | Action |
|---|---|---|
| 1 | Immediate | HSM `delete_key` call |
| 2 | 1 min | Retry |
| 3 | 5 min | Retry |
| 4 | 30 min | Retry + operator PagerDuty |
| >4 | — | `observer_state='degraded'` + regulator notification preparation |

**Receipt re-verification path**: `runtime-doctor erasure-verify --user <id>` — re-verifies the attestation of the `UserErasureCompleted` event in the WAL against the HSM public attestation key.

Detailed runbook (command sequence / rollback rule / cross-region propagation verification) is in `docs/runbook/crypto-erasure.md` (separate doc planned).

##### 11. Coexistence basis: L0 A14 vs GDPR Art. 17

L0 A14 guarantees "WAL bit-identical replay"; GDPR Art. 17 demands "personal data erasure". Crypto-erasure makes both principles coexist:
- WAL ciphertext preserved permanently (L0 A14 maintained).
- Plaintext irrecoverable via DEK shred — GDPR "effective erasure" (formally acknowledged by ICO/EDPB).
- Replay is bit-identical at the ciphertext level — L0 A1 maintained.
- Plaintext-level replay is impossible for erased users (interprets the L0 A14 scope at the ciphertext level).

**E-user-3 extension**: retains RUNTIME-ASSERTED (SLA-based). Crypto-shred completion is anchored by the L0 WAL `UserErasureCompleted` event, externally verifiable via HSM attestation + transparency log.

##### 12. Compliance Tier — R5.2 C-R6-1 introduced

BBS minimal shell (nickname + post password + telnet) illustrates a small-scale deployment with real users that cannot roll out alpha under an HSM-only cost structure. Three tiers make operating cost vs compliance requirements explicit — resolves the mismatch between spec and realistic operators.

| Tier | Condition | DEK backend | GDPR response | Monthly KMS cost (2026 baseline) | Target |
|---|---|---|---|---|---|
| **Tier-0** (dev/alpha) | `runtime_current ≤ "0.15"` + `runtime_max ≤ "0.15"` (GF1 cross-check) | `software-kek` | **Not guaranteed** — real users forbidden | $0 (process memory) | Dev/integration tests, private staging |
| **Tier-1** (small shell) | production runtime + AWS KMS free-tier (monthly 20,000 requests free) or GCP Cloud KMS free-tier | `kms` (vendor managed) | **Compliant** — Art. 17 crypto-erasure possible | $0–$50 (1–10k users, using the monthly DEK round-trip ≤ 20k req) | **BBS reference shell realistic alpha/beta path**, individual developers / small communities |
| **Tier-2** (production) | 10k+ users + high-throughput + strict regulation | `hsm` + Multi-KMS (§14.11.2) + threshold HSM (§14.11.3) + transparency log (§14.11.4) | **Enterprise-compliant** — full-stack audit / regulator response | $500+ (Multi-region HSM + transparency) | Commercial services, regulated industries |

**Tier migration paths**:
- **Tier-0 → Tier-1**: full erasure (§14.7 Option 1 default). No real user data, no loss.
- **Tier-1 → Tier-2**: live migration — re-wrap DEK envelopes to a new Multi-KMS environment (HSM-to-HSM exchange) + activate transparency log. `runtime-doctor tier-upgrade --to 2` command (v0.13+ implementation). During migration not in `observer_state='degraded'` — re-wrap is an HSM-internal operation; the Runtime only updates the wrapped_dek pointer.

**AWS KMS free-tier deployment guide** (Tier-1): `docs/guide/kms-free-tier.md` as a separate document — AWS KMS symmetric key + GenerateDataKey API + per-user DEK envelope + DEK round-trip pattern within the monthly 20k req. Linked from §15.5 roadmap v0.13 BBS deployment guide.

**Tier declaration** (manifest):
```toml
[audit]
compliance_tier = 1     # 0 | 1 | 2 — operator declaration; validation cross-checks against the above conditions
```
`compliance_tier = 0` parses successfully only in alpha-only manifests. `compliance_tier = 2` forces the Multi-KMS + transparency log manifest blocks.

**R5.3 mR7-α — tier ↔ backend cross-check**: `compliance_tier` is an operational policy declaration; `dek_backend` is a technical choice. Validation cross-checks their consistency — both values are required manifest fields. Example: `compliance_tier = 0` + `dek_backend = "hsm"` is inconsistent (Tier-0 is software-kek only) → `ManifestError::TierBackendMismatch`. Conversely `compliance_tier = 2` + `dek_backend = "software-kek"` is also rejected.

**R5.3 HF1 Tier-0 threat model annotation**: Tier-0 (software-kek) assumes a holder of host-OS access is **effectively a master-key holder**. Internet isolation + air-gap operation recommended. Process protection (§14.7 M-R6-4 HF1) offers only capability / dump / ptrace-level protection — cannot defend against a host-root attacker. Do not introduce real-user PII into a Tier-0 environment.

##### 13. Multi-region atomic shred — R5.2 GF4 / 2PC

GDPR erasure must achieve DEK deletion across all regions **all-or-nothing**. If only some regions delete + other regions retain independent DEKs, an adversary can restore the incomplete-region backup + HSM unwrap → decrypt PII.

**2PC procedure**:

1. **Phase 1 (prepare)**: L2 erasure-cascade fans out `delete_key(dek_id)` to every region HSM (concurrent). Wait for each region's response.
2. **Per-region progress event**: on receiving each region's attestation, emit `Op::EmitEvent(PerRegionErasureProgress { user, region, shred_tick, attestation_class, attestation_bytes })` (§3.2 TypeCode 0x0003_0F08). WAL chain-anchored.
3. **Phase 2 (commit)**: emit `UserErasureCompleted` **only after every region's PerRegionErasureProgress has been received**. Concatenate every region's attestation into `UserErasureCompleted.attestation_bytes`, or include as a separate multi-region attestation structure.
4. **Retry + SLA**: on individual region failure, apply the §14.9.1.1 runbook backoff (1m/5m/30m ×3). If not all regions complete **within SLA (p95 < 24h)** → operator alert + regulator notification preparation. `PerRegionErasureProgress` emits only for partially-complete regions — `UserErasureCompleted` is held.

   **R5.3 mR7-β — auto resume on L2 passive promotion**: during failover, when a passive L2 transitions to `observer_state='active'`, `runtime-doctor per-region-erasure-audit` auto-pushes users who emitted `PerRegionErasureProgress` without a final `UserErasureCompleted` onto a resume queue. Runbook backoff retry applied sequentially; operator intervention only on SLA miss. The transition itself is a path that restarts user-visible behavior — recommended to always execute promote and audit together.
5. **Restore flow (§14.11.1 integration)**: on restore, cross-check the tombstone_log + WAL `PerRegionErasureProgress`. Missing a region's tombstone = restore refuse. Partial progress existing for all regions + no final `UserErasureCompleted` = **incomplete erasure state** — skip/delete all that user's region ciphertext on restore (fail-safe).

**Operator tools**:
- `runtime-doctor per-region-erasure-audit --user <hashed-id>` — dashboard of each region's `PerRegionErasureProgress` status + `UserErasureCompleted` emission.
- Partial-completion user list + SLA monitoring.

**Single-region environment**: with `[audit.dek_replication = "global-hsm"]` + the vendor's own multi-region replication, 2PC degenerates to unary (region count = 1). Single `PerRegionErasureProgress` event + immediate `UserErasureCompleted`.

### §14.10 Scaling Path — new section (veteran m2)

**Current upper bound**: single instance ~200 Action/sec (§10.4).

**Scaling options**:

**Option A — shell-per-instance sharding** (connects to v0.99+ federation)
- Each shell gets its own kernel instance.
- Cross-shell User via the identity federation layer (v0.99+) → projection.
- Pros: per-instance load reduced. Cons: User cascade distributed, cross-shell query needs a per-adapter layer.
- Out of R1-R4' scope — requires federation DIP first.

**Option B — user-range sharding** (production candidate)
- Instance per user-ID range (e.g. user_id mod 16 = instance index).
- Pros: distributes a single shell's high load. Cons: user migration cost, cross-instance Activity required (inverse of Option A).
- Out of R1-R4' scope.

**Option C — L2 read-replica + PG-only tiered** (realistic for alpha/beta, integrates R5 Axis 3)
- Single active L2 writer, N passive readers.
- Read path distributed via PostgreSQL read replicas (+ Redis cache in production).
- Write path still a single kernel instance (inherits A2 determinism).
- Pros: read 10–100x scale. Cons: write-side upper bound unchanged.
- **Within R1-R5.1 scope. Default deployment model for alpha/beta.**

**Explicit storage tier (R5 Axis 3 — team-lead directive 2026-04-24, unanimous among 4)**:

| Tier | User scale | req/s | Primary store | Redis |
|---|---|---|---|---|
| alpha | < 1k | < 100 | PG-only (UNLOGGED idempotency/rate-limit + LISTEN/NOTIFY fanout) | **Not required** |
| beta | 1–10k | < 1k | PG primary | optional (dedicated idempotency/rate-limit) |
| production | > 10k | > 1k | PG + Redis required | **Required** (cache/queue, bypasses PG lock contention) |

- alpha / beta use the PG-only path to ease operator learning + reduce security surface (cryptographer recommendation — Redis CVE-2022-0543 RCE, Sentinel master election race, RedLock critique, ACL misconfiguration).
- Production transition requires Redis — absorbs the §10.4 single-thread ceiling.

**Production-verdict path**:
- alpha (< 1k users) / beta (< 10k users): Option C PG-only / PG+optional-Redis.
- Production (> 10k users): Option C PG+Redis → at v0.99+, re-evaluate Option A and introduce federation.
- MMORPG-scale demand is refused in §1.2 + separate DIP in §8.4.

### §14.11 Backup & Disaster Recovery — new section (C7 / N5 / P4 / S6)

**Policy summary**:
- **WAL-first strategy**: L0 WAL is the primary backup. Inherits append-only + fsync ordering.
- **Projection = re-derived by WAL replay**: on corruption, reconstruct via §12.5 partial replay.
- **Multi-region WAL streaming replication**: async (non-blocking for the critical path). primary region → secondary region replicates fsync'd WAL appends.
- **RPO target** < 1 min (WAL streaming lag bound).
- **RTO target** < 30 min (cold start + WAL replay + projection rebuild).

**Backup digest verification** (3-tuple, R5 NF4 — "sidecar" wording substitution):
```
(manifest_digest, chain_tip, runtime_semver)
```
- `manifest_digest` canonical TOML BLAKE3 (C5).
- `chain_tip` L0 WAL BLAKE3 chain tip (A13).
- `runtime_semver` in-band `RuntimeBootstrap` event in the WAL (§14.7 / E12).
- On backup restore, verify the 3-tuple — mismatch = corruption.

**Offsite at-rest encryption** (S6):
- Backup storage encryption **mandatory**.
- HSM/KMS recommended (concrete deployment at discretion — AWS KMS / GCP Cloud KMS / on-prem HSM).
- Key-rotation policy annotation (e.g. 90d cadence).
- Backup key separated from the WAL key — backup compromise independent from live WAL compromise.

**Weekly backup integrity audit**:
- `arkhe-runtime-doctor backup-verify` — random-sample WAL slice replay + 3-tuple re-verification.
- On audit failure → PagerDuty + operator intervention.

**Snapshot rotation (P4)**:
- Daily snapshot + 7-day retention (hot).
- Weekly snapshot + 12-week retention (warm).
- Monthly snapshot + 5-year retention (cold archive, offsite).
- A snapshot is L0 `KernelSnapshot` + L2 projection digest.
- `arkhe-runtime-doctor snapshot-rotate` command.

**WAL retention**:
- 90-day hot (replay RTO bound — a 10-yr WAL implies replay RTO hours~days → infeasible).
- > 90d archived (offsite cold storage, encrypted).
- Snapshot + most-recent 90d WAL achieves RTO < 30min.
- On replay, start from a snapshot (inherits L0 snapshot support).

**Runbook**:
- **Primary region outage** → secondary region promote (passive → active) + redirect WAL streaming source.
- **Projection corruption** → `runtime-doctor reset-projection` + WAL replay.
- **WAL corruption** (chain tip mismatch) → restore backup snapshot + replay to the verified last-known-good.
- **Silent data corruption** → weekly audit catches it → restore backup + re-review the changed delta.

**Multi-region setup (recommended for v1 alpha/beta)**:
- Primary: single region active.
- Secondary: 1–2 regions passive (WAL streaming).
- On disaster, operator-initiated promotion.
- Full multi-master is the same as §14.8 multi-active — separate DIP.

#### §14.11.1 Erasure propagation to offsite backup — new section (M6)

**Problem**: the leader S6 backup encryption is at-rest only. During a backup rotation cycle (e.g. 30 days), erased-user PII remains as ciphertext. On restore, deleted records resurface → GDPR violation.

**Solution (integrated with M5 crypto-erasure)**:
1. **Per-user DEK deletion = simultaneous invalidation of all backup-replica ciphertext**. Since the DEK exists only in HSM/KMS, post-shred no backup can decrypt the ciphertext.
2. **Tombstone log**: write a separate `tombstone_log` to backup storage — `TombstoneForUser { user_id, erased_tick, receipt_class: RuntimeSignatureClass, receipt_bytes: Bytes }`. Propagate to every offsite replica. The receipt is signed with the key corresponding to manifest `[audit.signature_class]` (§14.7 / E13).
3. **Per-region tombstone (R5.2 GF4)**: under multi-region deployment (`dek_replication = "per-region"`), write a `tombstone_log` per region. Include a `region` field in `TombstoneForUser`. **Restore flow**: on restore, cross-check every region's tombstone + WAL `PerRegionErasureProgress` events. Missing a region's tombstone → **restore refuse** (`RestoreError::MissingRegionTombstone`). For users in partially-complete state, restore skips/deletes the ciphertext (fail-safe).
4. **Restore consistency**: apply tombstones first → skip/delete ciphertext of users without a DEK. Post-restore verify `UserErasureCompleted` event count == tombstone count (refuse restart on mismatch).
5. **Propagation SLA**: offsite backup tombstone apply **p99 < 7 days** (meets regional legal requirements).
6. **Evidence log**: `Op::EmitEvent(BackupErasurePropagated { user, region, applied_tick, receipt_class, receipt_bytes })` — per-region apply evidence. Permanently anchored in the WAL chain. See §3.2 Event struct definitions.
7. `arkhe-runtime-doctor backup-erasure-audit` command — dashboard of every region's tombstone-apply status + `PerRegionErasureProgress` completion status.

#### §14.11.2 Multi-KMS primary/secondary — R5 C-R5-5a / FG2 runbook

**Purpose**: eliminate HSM/KMS single-vendor SPOF. On primary KMS outage, auto-fallback to secondary.

**Composition**:
- Primary KMS (e.g. AWS KMS multi-region key, globally-replicated DEK) — normal path.
- Secondary KMS (e.g. GCP Cloud KMS or on-prem HSM) — fallback path.
- The DEK envelope is **wrapped on both KMS and each wrapped copy is retained** — `wrapped_dek_primary` + `wrapped_dek_secondary` Runtime state. Decryption possible with whichever is live.

**Fallback procedure**:
1. Repeated primary KMS timeout / 5xx (§14.9.1 §§6 threshold) → L2 health check fails → `observer_state='degraded'`.
2. **R5.2 m-R6-2 — operator 60-min SLA**: after degraded transition, the operator is obligated to decide on promotion within 60 min. Manifest `[audit.kms_auto_promote]`:
   - `"manual"` (default) — operator manual promote. PagerDuty escalation after 60 min.
   - `"after_60min"` — automatic fallback (accepts split-brain risk). After 60 min, secondary auto-promoted + audit log.
3. Promote command: `runtime-doctor kms-promote --to secondary --reason <incident-id>` — mandatory operator Ed25519 sign + `runtime_doctor_journal` append. In auto mode, the runtime signs with a substitute (system key) + journal record.
4. Post-promote, secondary takes primary's role. New DEKs are created on secondary + re-wrapped after primary recovers.
5. After primary recovers: `runtime-doctor kms-rewrap-all` — regenerate primary wrapped copies for all active DEKs.

**DEK sync SLA**: Primary→Secondary wrap synchronization p99 < 60s (HSM vendor cross-region replication). Sync lag warning metric `arkhe_runtime_kms_sync_lag_seconds`.

**R5.2 GF6 — Multi-KMS shred path unified**: on `GdprEraseUser` cascade, **operator-issued single command** concurrently fans out `delete_key(dek_id)` to primary + secondary KMS. `UserErasureCompleted` **must never** be emitted before attestations from both are received — same principle as §14.9.1 §§13 GF4 2PC, extended to the KMS layer. Restoring a backup while one KMS is shred-complete and the other is not + unwrapping via the remaining KMS = PII decryptable — this path is blocked. Per-KMS progress is emitted explicitly via the `KmsIdentifier` variant of `PerRegionErasureProgress.scope` (R5.3 mR7-γ).

#### §14.11.2.1 Auto Promote Trust Model (R5.3 HF2)

The manifest `[audit.kms_auto_promote]` default remains `"manual"` — only opt-in to `"after_60min"` in production is recommended. The auto-promote path is a security-critical trust shift; explicitly acknowledge the following model:

**Split-brain risk acknowledgement**:
- Via BGP hijack / DNS poisoning / TLS mis-issuance, an adversary can selectively block the primary KMS → after the 60-min timer, **auto-fallback to an adversary-controlled secondary** may occur.
- Distinguishing whether a timeout is a network-level attack or a genuine KMS outage — not possible with a single-channel health check.

**Mitigations (mandatory when auto-promote is enabled)**:
1. **Multi-channel health check** — the `arkhe_runtime_kms_health_channels{channel, region}` metric (§12.4) runs health checks **in parallel** via DNS-over-HTTPS (DoH) / alternate region path / static-IP fallback. Do not trigger auto-promote on a single-channel failure — only on simultaneous failure of N-of-M channels (recommended 2-of-3).
2. **Require threshold-HSM operator pre-sign (t-of-n Shamir)** — auto-promote must not be signed by the system key alone (restricts the system-key path in §14.11.2 existing fallback procedure §3). Distribute `t=2 of 3` operator pre-signed authorization tokens in advance + consume them on use. When auto-promote fires, record the consumed token in `runtime_doctor_journal` — an external auditor can see operator-approval evidence.
3. **Explicit admin-UI enablement recommended** — a path enabled by manifest edits alone carries silent-enable risk on deployment-pipeline leak. Recommend a 2-step: explicit activation in the admin UI (separate ACL + MFA), then manifest reflection. Scope of the v0.13 admin dashboard.

**Default retention**: `"manual"` — operator manual promote is the safest path. Auto-promote should be opt-in only in environments with high availability demand + all 3 mitigations in place.

#### §14.11.3 HSM attestation public transparency log — R5 FG3

**Purpose**: defense against HSM insider threat + attestation forgery.

**Composition**:
- Register every `UserErasureCompleted` event's `attestation` + HSM destruction log sequence number in **Sigstore/Rekor** (recommended) or an in-house Merkle log + periodic publish.
- In-house Merkle log path: Runtime inserts tick-level attestation hash batches into `transparency_log_entries(log_index BIGSERIAL, attestation_hash BYTEA, published_tick BIGINT)` + publicly publishes the log root as a weekly GitHub release / internal publish.
- External auditors cross-check the `/erasure-receipt/{user_id}` endpoint (§14.11.4) with the transparency log index — independently verify that the HSM attestation was logged.

**Tamper-evident counter**:
- HSM attestation payload includes a destruction log sequence number (monotonic counter).
- Gap / rewind detection: the transparency log verifies counter continuity (missing seq → alert).

**Periodic audit**:
- Weekly `runtime-doctor transparency-verify` command — cross-checks the last 100 attestations against the transparency log; any mismatch → PagerDuty + regulator notification preparation.

#### §14.11.4 Public erasure receipt endpoint — R5 veteran m-R5-1

**Purpose**: GDPR regulators / users / external auditors independently confirm erasure evidence.

**Endpoint**: `GET /erasure-receipt/{user_id}` (L2 public HTTP).

**Response (JWT-signed)**:
```json
{
  "user_id": "<hash-of-user-id>",         // privacy: raw user_id not exposed
  "erased_tick": 1234567,
  "dek_shred_tick": 1234580,
  "hsm_attestation": "<base64>",
  "transparency_log_index": 9876543,
  "signature_class": "Hybrid",
  "jwt_signature": "<Ed25519 or MlDsa65 over above fields>"
}
```

**Signer key** = Runtime `chain_tip_signature` key (§12.4). Rotation 90d + grace (FG8).

**Regulator public key whitelist**: manifest `[audit.regulator_verify_keys]` lists GDPR regulator public keys — on JWT verification, confirm the signature is verifiable under one of these keys, then trust.

**CLI helper**: `arkhe-verify erasure-receipt --user <hashed-id> --endpoint https://...` — JWT + transparency log independent verification.

**R5.3 HF3 — direct WAL chain-tip re-verification (fail-close)**: the public endpoint responds only after **re-verification against the WAL chain tip**, not the `kernel_projection_state` row cache. The projection row is a read cache — to forge a row an adversary would have to also forge the Ed25519/PQC signature (requires HSM key possession) — but this blocks the cache-staleness / compromise path at the source. Fail-close policy: **on WAL re-verification failure return endpoint 5xx; cache response is forbidden**. Re-verification directly queries L0 `InstanceView.current_chain_tip()` + verifies `chain_tip_signature` / `signature_class` (§12.4 GF5) under the corresponding key. Implementation cost adds ~10–30ms to the read path — acceptable given the nature of a public endpoint.

---

