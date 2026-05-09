//! # ArkheForge Runtime — L2 Services / Platform (`arkhe-forge-platform`)
//!
//! Spec §5.2 surface — Manifest loader, L2 projection observer, Policy,
//! Rate limit, Audit receipt issuance, Cascade scheduler, Idempotency dedup,
//! GDPR erasure-cascade service, DR coordinator. Depends on L0
//! `arkhe-kernel` plus L1 `arkhe-forge-core` only — no upward edge
//! into shell crates (layer-independence directive).
//!
//! # Feature flags
//!
//! | Flag                       | Pulls in | Role |
//! | :------------------------- | :------- | :--- |
//! | *(none — default)*         | —        | Tier-0 dev: `MockKmsBackend` + in-memory crypto-erasure + `NoopHookHost` + `NoopObserverHost`. |
//! | `tier-1-kms`               | `argon2`, `chacha20poly1305` | Tier-1 KMS free-tier — `XChaCha20-Poly1305` AEAD. |
//! | `tier-2-multi-kms`         | `tier-1-kms` + `aes-gcm` + `aes-gcm-siv` | Tier-2 production AEAD surface (implies `tier-1-kms`). |
//! | `tier-2-aws-kms`           | `aws-sdk-kms`, `aws-config`, `tokio` | Orthogonal AWS KMS backend opt-in — `AwsKmsBackend` impl of [`hf2_kms::KmsBackend`]. |
//! | `tier-2-hook-host-v2`      | `wasmtime`, `wasmtime-wasi` | Hook host v2 wasmtime sandbox — chain-affecting compute path (spec §14.5 / E14.L2-Allow). |
//! | `tier-2-observer-host-v2`  | `wasmtime`, `wasmtime-wasi` | Observer host v2 wasmtime sandbox — chain-non-affecting side-effect path (spec §14.5.1 / E15). |
//! | `pqc-hybrid`               | — | Reserved for L2 MlDsa65 + hybrid attestation (preview scaffolding — no direct `ml-dsa` dep yet; L0 kernel WAL chain signing is unaffected). |
//! | `unstable`                 | — | Opt-in for items outside the stable surface. |
//!
//! Cloud KMS backends are orthogonal to the AEAD tiering — a deployment can
//! run `tier-1-kms` AEAD with `tier-2-aws-kms` key storage, or any other
//! mix. GCP / Azure backends land as their own `tier-2-<vendor>-kms` flags
//! in future releases. The two wasmtime hosts (`tier-2-hook-host-v2` /
//! `tier-2-observer-host-v2`) are independent — a deployment may enable
//! just one, the other, or both; Cargo dedups the shared `wasmtime` dep.

// `unsafe_code` is `deny` (not `forbid`) because `process_protection` must call
// platform FFI (mlockall / prctl / setrlimit / ptrace / VirtualLock / ...) —
// every other module keeps the safe-only invariant through the crate-wide deny
// plus the `#[deny(unsafe_code)]` attribute inherited below. The per-target
// FFI files opt in with a scoped `#![allow(unsafe_code)]` and document each
// `unsafe` block with SAFETY notes.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod crypto_erasure;
pub mod dedup;
pub mod dispatcher;
pub mod hf2_kms;
pub mod hook_host;
pub mod manifest;
pub mod observer_host;
pub mod process_protection;
pub mod projection;
pub mod verifier;
pub mod wal_export;

// Shared wasmtime-sandbox helpers — used by `hook_host/` and
// `observer_host/`. Compiled only when at least one wasmtime feature is
// enabled. `pub(crate)` visibility — sandbox-implementation detail.
#[cfg(any(feature = "tier-2-hook-host-v2", feature = "tier-2-observer-host-v2"))]
pub(crate) mod wasm_runtime_common;

/// ArkheForge Runtime Platform semver — matches the repo release.
pub const PLATFORM_SEMVER: (u16, u16, u16) = (0, 13, 0);
