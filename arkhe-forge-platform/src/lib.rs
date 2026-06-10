//! # ArkheForge Runtime — L2 Services / Platform (`arkhe-forge-platform`)
//!
//! L2 services surface — Manifest loader, L2 projection observer, Policy,
//! Rate limit, Audit receipt issuance, Cascade scheduler, Idempotency dedup,
//! GDPR erasure-cascade service, DR coordinator. Depends on L0
//! `arkhe-kernel` plus L1 `arkhe-forge-core` only — no upward edge
//! into shell crates (layer-independence directive).
//!
//! # Feature flags
//!
//! | Flag                       | Pulls in | Role |
//! | :------------------------- | :------- | :--- |
//! | *(none — default)*         | —        | Tier-0 dev: `MockKmsBackend` + in-memory crypto-erasure. |
//! | `tier-1-kms`               | `argon2`, `chacha20poly1305` | Tier-1 KMS free-tier — `XChaCha20-Poly1305` AEAD. |
//! | `tier-2-multi-kms`         | `tier-1-kms` + `aes-gcm` + `aes-gcm-siv` | Tier-2 production AEAD surface (implies `tier-1-kms`). |
//! | `tier-2-aws-kms`           | `aws-sdk-kms`, `aws-config`, `tokio` | Orthogonal AWS KMS backend opt-in — `AwsKmsBackend` impl of [`hf2_kms::KmsBackend`]. |
//!
//! The L0 kernel WAL chain signing inherits Hybrid Ed25519 + ML-DSA 65
//! transitively via `arkhe-kernel`. Forge L2 attestation surfaces emit
//! Ed25519.
//!
//! Cloud KMS backends are orthogonal to the AEAD tiering — a deployment can
//! run `tier-1-kms` AEAD with `tier-2-aws-kms` key storage, or any other
//! mix. GCP / Azure backends land as their own `tier-2-<vendor>-kms` flags
//! in future releases.

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
pub mod manifest;
pub mod process_protection;
pub mod projection;
pub mod verifier;
pub mod wal_export;

/// ArkheForge Runtime Platform semver — matches the repo release.
pub const PLATFORM_SEMVER: (u16, u16, u16) = (0, 15, 0);
