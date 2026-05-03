## §10. Rust type system limits

### §10.1 Compile-time invariants preserved

| L0 invariant | Runtime application |
|---|---|
| A2 `Kernel: !Sync` | Runtime dispatcher is `!Sync`. |
| A3/A19 `Effect<'i>` | L1 Action signatures thread `'i`. |
| A4 `#![forbid(unsafe_code)]` | Inherited by the Runtime crate. |
| A5 BTreeMap only | L1 `BTreeMap<TypeCode, ...>`. |
| A6 NonZeroU64 IDs | Every Id wraps it (private field). |
| A7 Principal exhaustive | L2 match is exhaustive. |
| A9 CapabilityMask | L2 manifest → caps. |
| A11 pure | `ActionCompute::compute` + `#[kernel_pure]`. |
| A15 TypeCode × schema_hash | WAL header `type_registry_pins` + `manifest_digest` + `runtime_semver`. |
| A17 postcard canonical | Runtime Component/Event/Action. |
| A20 StepStage | multi-Op atomic. |
| **Runtime new** | ShellBrand `'s` invariant-variance — multi-shell isolation (submit-site compile-time, replay/admin double-defense). |

### §10.2 Points where guarantees weaken

#### §10.2.1 Verb / shell-scoped dispatch

There is no verb-specific logic at L1. Policy lives in the L2 manifest + hooks. **L1 is fully static**.

#### §10.2.2 L2 Hook dispatch — M-hook-traitbound / C8

```rust
pub trait ShellHook: 'static {
    /// Extra-bytes only. Policy-invariant fields cannot be modified.
    /// 10ms CPU budget hard timeout. No blocking/async.
    /// Send + Sync removed — aligned with L0 A2 single-thread.
    fn pre_submit_activity(
        &self,
        req: &SubmitActivityReq,          // read-only view of policy-invariant fields
        builder: &mut ExtraBytesBuilder,  // only mutable surface
    ) -> Result<(), HookError>;

    fn pre_submit_entry(
        &self,
        req: &SubmitEntryReq,
        builder: &mut ExtraBytesBuilder,
    ) -> Result<(), HookError>;
}

/// The extra_bytes builder a hook appends to.
pub struct ExtraBytesBuilder {
    buffer: Vec<u8>,
    max_bytes: usize,                     // manifest extra_bytes_max_bytes
}
impl ExtraBytesBuilder {
    pub fn append_canonical<T: CanonicalEncode>(&mut self, value: &T) -> Result<(), HookError>;
}
```

**v1 alpha: all hooks OFF** (§14.5). v2 uses WASI.

#### §10.2.3 Shell Manifest runtime on/off

Core 5 are all registered with the kernel at compile time. on/off is L2 policy (reject at submit). L1 is always active. No dyn dispatch.

#### §10.2.4 Multi-shell brand operation (integrates I1 ergonomics)

`ShellBrand<'s>` provides submit-site compile-time isolation. Per-path handling is specified in §3.7.

**Multi-shell entry-point example** (representative boilerplate):
```rust
fn run_shell_bbs<F>(f: F) where F: for<'s> FnOnce(ShellBrand<'s>) {
    let brand = ShellBrand::<'_>::__new();
    f(brand);
}

// Usage:
run_shell_bbs(|brand_bbs| {
    let alice = Actor::<'_, Authenticated>::fetch(brand_bbs, alice_id);
    let entry = Entry::<'_>::fetch(brand_bbs, entry_id);
    let activity = Activity::new(brand_bbs, ActivityRecord { ... });
    submit(SubmitActivity::from_branded(activity));
});
```

Same pattern as L0 R5-T1 brand — boilerplate is absorbed by an HRTB closure wrapper. `arkhe-runtime-admin::BrandedAccess::enter` provides the standardized wrapper.

### §10.3 Summary of Rust type limits

| Point | Static? | Basis |
|---|---|---|
| L0 Kernel surface | ✓ | Unchanged |
| L1 `ActionCompute::compute` | ✓ | sealed + derive + `'i`/`'s` |
| L1 Component canonical_bytes | ✓ | ArkheComponent sealed + postcard |
| L1 Activity verb dispatch | ✓ | No verb-specific logic |
| L1 VerbCode range | ✓ | const generic `CanonicalVerb<C>` / `ShellVerb<C>` |
| L1 TypeCode registry | Partial | runtime BTreeMap, A15 structure determinism |
| L2 Shell Hook dispatch (v2+) | ✗ `dyn` | manifest runtime registration |
| L2 Projection writer | ✗ `dyn` | observer trait object + catch_unwind |
| L2 Manifest loader | ✓ | TOML strict + canonical digest |
| Submit-site Actor/Entry/Activity isolation | ✓ | ShellBrand compile-time |
| Replay/admin Actor/Entry/Activity isolation | Partial | compute MC double-check |

### §10.4 Throughput estimate — M-throughput / m2 context

- Upper bound for a single Runtime instance (L0 A2 single-thread): **p99 < 5ms/Action → ~200 Action/sec/instance**.
- Capacity: 1k active users × avg 0.2 Action/sec → ~1k users / instance.
- **The single-thread constraint is the cost of inheriting L0 A2 determinism**. Alternatives:
  - (a) Shard by shell_id — separate kernel instances (§14.10 Option A).
  - (b) Split stateless reads into L2 (§14.10 Option C).
  - Multi-thread primitive dispatch abandons determinism — out of Runtime scope.
- 10k+ concurrent users: see §14.10 Scaling Path.
- Prometheus `arkhe_runtime_action_duration_seconds` histogram (§12.4).

---

