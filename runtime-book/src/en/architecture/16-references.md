## §16. References

- `arkhe-kernel` v0.11 — `/arkhe-kernel/`.
- `book/src/architecture/invariants.md` — L0 A1-A24 + S1.
- `book/src/architecture/threat-model.md` — L0 AI-adversary.
- `book/src/architecture/domain-spec.md` — L0 L1 boundary.
- `book/src/architecture/overview.md` — L0 overview.
- Shell requirements catalogs — maintained per shell repository (e.g., `arkhe-shell-bbs`). This repo houses only L0 + Runtime.
- **`docs/Review/r2-findings-2026-04-24.md`** — R2 cold-read archive (basis for R3 integration).
- **`docs/Review/r4-findings-2026-04-24.md`** — R4 cold-read archive + leader performance/security (basis for R4' integration).
- **`docs/Review/bounded-string-analysis-2026-04-24.md`** — `BoundedString<N>` crate selection analysis (basis for §3.4).
- **`docs/Review/r4-cryptographer-findings-2026-04-24.md`** — R4 cryptographer cold-read (basis for R4'.1 micro-revision). 17 items: Critical 4 / Major 9 / Minor 4.
- **`docs/Review/r5-findings-2026-04-24.md`** — R5 4-person cold-read (basis for R5.1 micro-revision). Critical 5 / Major 12 / Minor 15+ + Axis 3 PG-only tiered (unanimous among 4) + HSM fallback (team-lead directive 2026-04-24).
- **`docs/Review/r6-findings-2026-04-24.md`** — R6 4-person full clean round (basis for R5.2 micro-revision). Critical 1 / Major 11 / Minor 13. Team-lead option 2 confirmed.
- **`docs/Review/r7-findings-2026-04-24.md`** — R7 4-person clean round (basis for R5.3 micro-revision). Critical 0 / Major 3 / Minor 15 (12 reflected, 3 deferred). Team-lead option B confirmed.
- **R8 verification round** (2026-04-24, basis for R5.4 micro-patch) — Critical 0 / Major 0 / 5 new Minor (3 reflected in spec + 2 handed off to v0.12 implementation). N=2 consecutive clean achieved. Team-lead decision: skip R9 + close via leader self-review → enter v0.12 implementation DIP.
- **`docs/runbook/crypto-erasure.md`** — operator runbook (v0.12 alpha blocker, see §14.9.1.1 / §15.5).
- **`docs/Legal/gdpr-crypto-erasure.md`** — GDPR crypto-erasure legal basis (v0.12 alpha blocker, see §14.9.1 §§9 / §15.5).
- **`docs/guide/kms-free-tier.md`** — Tier-1 AWS KMS free-tier deployment (v0.12 alpha blocker, see §14.9.1 §§12 / §15.5).
- **`docs/runbook/hsm-degraded-mode.md`** — HSM outage runbook (v0.12 alpha blocker, see §14.9.1 §§6 / §15.5).
- **`docs/guide/bbs-deployment.md`** — BBS reference shell deployment (v0.13 target, see §15.5).
- L0 DO NOT TOUCH: `DOMAIN_CTX`, `InvariantLifetime`, `Principal`/`KernelEvent`/`StepStage` derives (including L0 `SignatureClass` — per R5.2 NR6-4 inspection, the Runtime extends this with `RuntimeSignatureClass`, §14.7), A11 MC tag, ROADMAP v0.99+ Deferred, R4-X DAG, `EventMask` bit allocation, `WalRecord` postcard field order.
- Runtime dylint CI gate: `#[arkhe_runtime_forbidden_modifier]` (§2.3).
- Runtime ABI CI gate: `arkhe-forge-abi-check` (§14.7).

**End of Runtime Spec.**
