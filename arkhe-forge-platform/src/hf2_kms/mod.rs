//! HF2 Multi-KMS infrastructure — health + threshold HSM + KMS abstraction.
//!
//! Mitigates spec §14.11.2 / §14.11.3 HF2 actor 5 (HSM operator collusion).
//! Submodules:
//!
//! - [`health`] — multi-channel health check (DoH / alternate region /
//!   static-IP, N-of-M quorum).
//! - `threshold` (feature `tier-2-multi-kms`) — byte-level GF(256) Shamir
//!   `t-of-n` secret sharing for the auto_promote authorization token.
//! - [`journal`] — consumed-token audit journal (in-memory dev impl;
//!   production wires a chain-signed persistent backend on top).
//! - [`kms_backend`] — `KmsBackend` trait + [`MockKmsBackend`] Tier-0 impl.
//!
//! Real KMS-specific implementations (AWS, GCP, Azure) sit behind feature
//! gates — see the `tier-2-aws-kms` feature in `Cargo.toml`.

pub mod health;
pub mod journal;
pub mod kms_backend;

// Threshold HSM is a Tier-2 feature: shells that never run multi-KMS HA
// (Tier-0 dev, Tier-1 free-tier KMS) do not need the Shamir surface and
// would otherwise pay the `getrandom` link cost.
#[cfg(feature = "tier-2-multi-kms")]
pub mod threshold;

#[cfg(feature = "tier-2-aws-kms")]
pub mod aws_kms;

pub use kms_backend::{KekRef, KeyDeletionAttestation, KmsBackend, KmsError, MockKmsBackend};

#[cfg(feature = "tier-2-aws-kms")]
pub use aws_kms::AwsKmsBackend;
