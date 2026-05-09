# arkhe-forge-platform

**L2 services for [ArkheForge Runtime](../arkhe-forge).**

Projection observer, manifest loader, policy engine, rate limiter, audit
receipts, crypto-erasure coordinator, process-protection shim. Builds on
`arkhe-kernel` (L0) plus [`arkhe-forge-core`](../arkhe-forge-core) (L1).

## Layer

L2 of the Arkhe stack. Depends upward on L0 + L1; never on shell crates
(layer-independence directive). Shell authors typically consume L2 via the
[`arkhe-forge`](../arkhe-forge) umbrella rather than directly.

## Compliance tiers

Feature flags gate the compliance tier:

- **Tier-0 `default`** — software-only KEK, development only.
- **Tier-1 `tier-1-kms`** — KMS free-tier: Argon2 + XChaCha20-Poly1305.
- **Tier-2 `tier-2-multi-kms`** — production Multi-KMS + threshold HSM with
  t-of-n Shamir split; adds AES-GCM / AES-GCM-SIV.
- **`pqc-hybrid`** — L2 attestation Cargo feature flag. The L0 kernel
  WAL chain signing inherits Hybrid Ed25519 + ML-DSA 65 transitively
  via `arkhe-kernel` regardless of this flag.

## Key services

- `projection` — L2 projection observer; derives eventually-consistent views
  from the L0 WAL.
- `manifest` — domain manifest loader (TOML) with deterministic digest.
- `crypto` — HSM-generated DEK + envelope encryption, tombstone semantics,
  19-byte AEAD AAD.
- `hf2_kms` — auto-promote trust model: multi-channel health check (DoH /
  alternate region / static-IP) gated by threshold HSM.
- `process_protection` — platform shim: Linux (`mlock_all` + `PR_SET_DUMPABLE`
  + ptrace filter), macOS (`PT_DENY_ATTACH`), Windows
  (`SetProcessMitigationPolicy`).
- `observer`, `verifier` — audit trail emitters.

## Quick start

```toml
[dependencies]
arkhe-forge-platform = { version = "0.13", features = ["tier-1-kms"] }
```

```rust
use arkhe_forge_platform::PLATFORM_SEMVER;
assert_eq!(PLATFORM_SEMVER, (0, 13, 0));
```

## Documentation

- Runtime book: <https://aceamro.github.io/ArkheForge/>
- Repository: <https://github.com/aceamro/ArkheForge>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
