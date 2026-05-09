# arkhe-forge

**ArkheForge Runtime — umbrella crate (L1 + L2 re-export).**

The single entry point shell authors depend on. Re-exports
[`arkhe-forge-core`](../arkhe-forge-core) as `core` and
[`arkhe-forge-platform`](../arkhe-forge-platform) as `platform`; compliance-tier
features proxy through to the platform crate.

## Layer

L1 + L2 facade. Do not mix-and-match `arkhe-forge-core` and
`arkhe-forge-platform` directly in shell code — depend on this umbrella so
version alignment and feature gating stay coherent.

## Quick start

```toml
[dependencies]
arkhe-forge = { version = "0.13", features = ["tier-1-kms"] }
```

```rust
use arkhe_forge::{core, platform};

// L1 primitive helper.
let _ = core::RUNTIME_SEMVER;

// L2 service namespace.
let _ = platform::PLATFORM_SEMVER;
```

## Feature flags

- `default` — Tier-0 dev only.
- `tier-1-kms` — proxy to `arkhe-forge-platform/tier-1-kms`.
- `tier-2-multi-kms` — proxy to `arkhe-forge-platform/tier-2-multi-kms`.
- `pqc-hybrid` — preview proxy to `arkhe-forge-platform/pqc-hybrid` (MlDsa65 + hybrid attestation scaffolding).
- `unstable` — proxy to `arkhe-forge-platform/unstable`.

## Stability

The public API follows an asymptotic-minor versioning scheme: 1.0 is
intentionally never reached so semantic breaks always land on a minor
bump.

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- API reference: <https://docs.rs/arkhe-forge>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
