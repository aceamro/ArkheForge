# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — v0.13 is a single fixed pre-public version.
Subsequent corrections land on the same v0.13 line. Version 1.0 is
intentionally never reached (parity with ArkheKernel).

## [0.13.0] — Initial release

ArkheForge L1+L2 runtime substrate built on the ArkheKernel L0 sealed
deterministic microkernel. Layered architecture: kernel inherit + L1
primitives (sealed `ArkheAction` / `ArkheEvent` traits, compute
pipeline) + L2 services (`RuntimeService` dispatcher, multi-tier KMS
AEAD, wasmtime-sandboxed hook host v2 and observer host v2, WAL
export reader+writer) + L3 utility (`arkhe-rand` BLAKE3-keyed PRNG) +
examples. Cryptographic primitives include BLAKE3 (hashing + KDF),
Ed25519 (Forge L2 attestations), multi-tier KMS AEAD (ChaCha20-Poly1305
/ AES-GCM / AES-GCM-SIV) with Argon2 KDF, and post-quantum signing
inherited transitively from the kernel (Hybrid Ed25519 + ML-DSA 65,
NIST FIPS 204). Provably-fair commit-reveal patterns demonstrated in
`examples/dice` (3D6 with WAL multi-run history) and
`examples/card_primitives` (Hold'em with end-to-end framework
integration). Engineering discipline: workflow-3 9-step gate + 4-axis
cross-review + workspace single-version pin. See [`README.md`](README.md)
for the crate enumeration and `Cargo.toml` for dependency pins.

### Licensing

Dual-licensed under MIT OR Apache-2.0.
