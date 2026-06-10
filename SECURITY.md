# Security policy

ArkheForge is the L1+L2 runtime substrate built on the ArkheKernel L0
deterministic microkernel. Cryptographic surfaces include the L2
dispatch + WAL append loop, the multi-tier KMS / AEAD stack, and the
audit attestation pipeline. Vulnerabilities affecting any of these
surfaces are treated as security issues.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to:

- **Email**: aceamro@gmail.com

Encrypt sensitive payloads if you have a public key for the maintainer;
an unencrypted initial contact requesting a key is also acceptable.

Please include:

1. The affected version (commit hash or crates.io version) and target
   triple.
2. A minimal reproduction (test, snippet, or repro project).
3. The observed vs. expected behaviour, and the security impact you
   believe applies.
4. Optional: a suggested remediation or patch.

Please **do not** open a public GitHub issue, pull request, or
discussion thread for an unfixed vulnerability.

## Response expectations

- **Acknowledgement**: within 5 business days.
- **Triage**: within 14 days the report is either confirmed, declined,
  or marked needing-more-info.
- **Fix window**: severity- and surface-dependent. Capability
  bypasses, KMS-tier AEAD downgrades, WAL chain-integrity breaks,
  sealed-trait escapes, replay non-determinism, and signature
  forgeries are prioritised. Coordinated public disclosure is agreed
  with the reporter once a fix is ready.

## Scope

In-scope: every crate in this repository (`arkhe-forge`,
`arkhe-forge-core`, `arkhe-forge-platform`, `arkhe-forge-macros`,
`arkhe-rand`, the test/lint helpers, `arkhe-runtime-proofs`, and the
`examples/`).

Out of scope: the ArkheKernel L0 sibling repository (own
`SECURITY.md`) and downstream domain shells (own policies).

## Versioning

ArkheForge's version tracks the ArkheKernel epoch (currently v0.15).
Security fixes land on the published version. Version 1.0 is
intentionally never reached (parity with ArkheKernel).

## Cryptographic acknowledgements

Primitives in use: BLAKE3 (hashing, KDF), Ed25519 (classical
signatures), ChaCha20-Poly1305 / AES-GCM / AES-GCM-SIV (KMS AEAD),
Argon2 (KDF), `getrandom` (OS CSPRNG), and Hybrid Ed25519 + ML-DSA 65
(NIST FIPS 204) inherited transitively via ArkheKernel. Specific
crate versions live in `Cargo.toml`. Reports about upstream defects
belong with the upstream maintainers; reports about how ArkheForge
uses them belong here.
