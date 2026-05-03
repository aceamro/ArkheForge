# ArkheForge Runtime Spec

> **Scope**: the canonical design document for the **L1 Primitives + L2 Services/Platform** of the Runtime sitting on ArkheKernel v0.11 (L0). On par with KERNEL_SPEC.md / INVARIANTS.md.
>
> **Runtime codename**: **ArkheForge Runtime** (§15). A forge metaphor — shells are manufactured by repeatedly hammering primitive raw materials.
>
> **What this document defines**: the Runtime primitive set, trait signatures, extension axes, determinism boundaries, inheritance of L0 axioms, multi-shell isolation, operational SLOs, upgrade paths, and backup/DR. Implementation chunk guidance, crate partitioning, and milestones are not here.

---

## §1. Identity — "Promise to minimize duplication, refuse generality"

**ArkheForge Runtime is a reuse substrate that absorbs only empirically demonstrated duplication across shells. Features that only one shell needs stay outside the Runtime, at the shell level. Speculative generalization is the path that failed Rails/Meteor.**

### §1.1 What the Runtime promises

1. **Core 5 primitives** — User, Actor, Space, Entry, Activity. Absorbed only when duplicated across 2+ shells.
2. **Four extension axes** — Component / TypeCode / Subtype / New-Primitive gate. Extension without modifying the Runtime core.
3. **Determinism inheritance** — Inherits L0 A1 (bit-identical replay), A2 (single-thread), A11 (pure compute), A13-A17 (crypto). Runtime axioms E1-E11 layer on top.
4. **Multi-shell isolation** — dual defense of User/Actor 2-tier + `ShellBrand<'s>` invariant variance + L1 compute `shell_id` (§11.2 E7 dual-tier). Compile-time at submit site + runtime MC on the replay/admin path.

### §1.2 What the Runtime does not promise (scope refusals)

| Refusal | Reason |
|---|---|
| "All social / media / game platforms in one Runtime" | The Rails/Meteor lesson. |
| Media byte storage / transport (blob storage) | Floats, huge bytes, non-determinism. Outside CDN/S3. |
| DRM key management / payments / AI recommendation algorithms | External KMS/billing/ML. Receipts/commitments only. |
| WebRTC SFU / real-time streaming substance | A separate system. Runtime only holds session metadata. |
| Federation content pull | v0.99+ later. |
| **Real-time tick-synchronized state** (position, health, movement) | MMORPG / FPS. Departs from L0 single-thread + tick-atomic commit. A separate DIP in §8.4 "game-kernel overlay". |
| State-machine game Runtime integration | Casino / boardgame shells implement Session/Turn/Round primitives (§8.3) themselves. |

### §1.3 Criterion for inclusion in Core

Restricted to **"empirically demonstrated duplication across 2 or more shells"**. Predictive/speculative grounds are rejected. Decision details in §4 (Core 5) / §8 (later candidates) / §7.4 (New-Primitive gate).

### §1.4 engine.md §E.12 self-review reflection

S2/S5/S8/S9/S10 all reflected (§7 extension axes, §9 3-band, §11 E10/E14.6 ArkheUri, §4 Core 5, §1.2 scope). S1/S3/S4/S6/S7 are carried to R5+.

### §1.5 Summary of R4 / R5 / R6 / R7 / R8 findings reflection

- **R4** (auditor/veteran/theorist + leader) — Critical 10 / Major 19 / Minor 11 all reflected in R4'. Source: `docs/Review/r4-findings-2026-04-24.md`.
- **R4'.1** (cryptographer R4 cold-read) — Critical 4 / Major 9 / Minor 4 all reflected. Source: `docs/Review/r4-cryptographer-findings-2026-04-24.md`.
- **R5** (4-person cold-read) — Critical 5 / Major 12 / Minor 15+ + Axis-3 Storage plurality PG-only tiered (unanimous among 4) + HSM fallback (team-lead directive 2026-04-24) all reflected in R5.1. Source: `docs/Review/r5-findings-2026-04-24.md`.
- **R6** (4-person full clean round) — Critical 1 (BBS compliance tier) / Major 11 (4 ops + 3 types + 4 security) / Minor 13 all reflected in R5.2. Team-lead option 2 confirmed (2026-04-24): R7 + R8 consecutive clean path. Source: `docs/Review/r6-findings-2026-04-24.md`.
- **R7** (4-person clean round) — Critical 0 / Major 3 (HF1 software-kek memory residual / HF2 auto_promote split-brain / M-R7-1 BBS telnet TLS wrap matrix) / Minor 15 of which **12 reflected, 3 deferred**. Team-lead option B confirmed (2026-04-24): R5.3 micro-revision ~60-100 LoC, no structural change. Source: `docs/Review/r7-findings-2026-04-24.md`.

**R7 deferrals (v0.12 implementation DIP / v0.13+)**:
- cryptographer R7-r1 — `EncryptedPii<T>::decrypt()` record-time manifest resolution (tick-anchored manifest lookup) → concretized in v0.12 implementation DIP.
- cryptographer R5-r5 — standard trait for shell verifier chain-attestation → already previewed in §9.3 / §15.4, promoted to v0.13 DIP proper.
- theorist R7-NR5/6/7 — Rust stable limits / over-engineering verdict: pass.
- veteran m-R7-1 — Grafana dashboard JSON template → §15.5 v0.13 nice-to-have row.
- auditor mR7-δ — `ComplianceTierChange` event → §15.5 v0.13 DIP candidate (TypeCode `0x0003_0F0A` reserved).

- **R8** (4-person verification round) — Critical 0 / Major 0 / 5 new Minor. **Achieved N=2 consecutive clean (R7 + R8)**. Team-lead decision (2026-04-24): skip R9 → close this R5.4 micro-patch → enter v0.12 implementation DIP. Of the 5 R8 Minors, 3 reflected in spec (theorist L0 version notation / veteran R8-m1 SLO 2 rows / veteran R8-m2 alpha→beta runbook) + 2 handed off to v0.12 implementation (cryptographer HF1 platform abstraction / HF4 manifest bypass audit). Source: R8 reviewer session records.

---

