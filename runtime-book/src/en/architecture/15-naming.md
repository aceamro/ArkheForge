## §15. ArkheForge Runtime naming decision

**Confirmed**: **ArkheForge Runtime** (team-lead 2026-04-24).

### §15.1 Linux kernel / userland analogy

L0 ArkheKernel = Linux kernel — resource allocation, deterministic state, WAL, single-thread scheduling. On top of L0, L1 (primitive + compute) + L2 (policy / projection / manifest / hook host) = Linux userland runtime services: just as glibc + systemd + D-Bus sustain the process ecosystem above the kernel, ArkheForge Runtime sustains the primitive-execution ecosystem above ArkheKernel.

R1's "Engine" risked conflict with the L0 kernel category, carrying the "core itself" image of browser/game engines. "Runtime" makes transparent that L0 is already the kernel position.

### §15.2 "Forge" choice

- R1 alternatives "Stage / Loom / Axis" are outcome-oriented, weaker on the production-process image.
- "Forge" implies a repetitive hammering production process. The opposite axis to the Rails/Meteor failure — forging empirically demonstrated duplication.
- Pronounces cleanly across languages.
- A smithy metaphor — hammering primitive raw materials to manufacture shells.

### §15.3 Full naming

| Component | Name |
|---|---|
| Microkernel | ArkheKernel |
| Runtime | **ArkheForge Runtime** |
| Runtime crate | `arkhe-forge` |
| L1 primitive crate | `arkhe-forge-core` |
| L2 platform crate | `arkhe-forge-platform` |
| Offline migration tool | `arkhe-runtime-doctor` |
| ABI compat CI gate | `arkhe-forge-abi-check` |
| Admin access | `arkhe-runtime-admin` |
| Reference shell 1 | ArkheNet BBS |
| Reference shell 2 | ArkheCasino |
| Reference shell 3 (planned) | GuildChat |
| Audit verifier | `arkhe-verify` (shared L0) |
| Casino verifier | `arkhe-casino-verify` (shell-provided) |

The "Engine" / "engine-*" prefix is **retired entirely** after R4'.

### §15.4 v0.13 DIP candidate roadmap (C4 Band 3 primitive official registration)

In R4'.1 cryptographer C4, Band 3 engine support was confirmed as option B (scope refusal). The future entry path is officially registered as the following roadmap:

**v0.13 DIP candidate — Band 3 primitive promotion**:
- **Prerequisite**: completion of empirical evidence from **3 or more shells** among E2E DM / threshold vote / Casino.
- **Promotion content**:
  - `BandThreePhase` Component (phase FSM state).
  - `Band3Action::required_phase()` compile-time enforcement — R5 m-R5-1 preview:
    ```rust
    // v0.13 preview — per-Action phase compile-time enforcement via associated const
    pub trait Band3Action {
        const REQUIRED_PHASE: Phase;
    }
    // compute compares the phase Component against Self::REQUIRED_PHASE → mismatch rejects.
    // May be further promoted via a typestate wrapper (BandThreePhase<Expected>).
    ```
  - Standardization of `arkhe-<shell>-verify` tool interface (common trait `Band3VerifierAdapter`) + shell binary chain-attestation (R5 R5-r5) — binary BLAKE3 digest + Ed25519/PQC operator signature + Sigstore/Rekor transparency log entry. Manifest `[shell.verifier_attestation]` pins digest + log index.
- **Refusal conditions** (re-review gate):
  - If 2+ of the 3 shells prove "sufficient" via a shell-scoped implementation, refuse primitive promotion.
  - If the Runtime semver impact breaks 2+ shells, split into a derivative DIP (v0.13.1).
- **Tier goal**: promote Band 3 phase ordering to **TYPE-PROVEN** (typestate `BandThreePhase<Expected>`).

Current scope remains **Runtime core Band 3 non-commitment** — the shell is responsible for its own FSM + audit tool (§9.3 scope refusal).

### §15.5 Runtime semver roadmap — R5 M-R5-5 introduced

Officially registers future DIP candidates for the ArkheForge Runtime. Each DIP carries gate criteria + dependencies + target semver. Versioning increments as integers 0.11 → 0.12 → ... → 0.99 → 0.100 (1.0 is never reached).

| DIP candidate | Target semver | Gate criteria | Dependency |
|---|---|---|---|
| **Room primitive** | v0.13 | 2+ shell evidence (2 of BBS conversation rooms / TubeLike live / GuildChat) | — |
| **Band 3 primitive (`BandThreePhase`)** | v0.13 | 2+ shell evidence (Casino + one of E2E DM / threshold vote) + agreement on the `Band3VerifierAdapter` standard trait | (optional) Room — may be included together |
| **SpaceMembership primitive** | v0.14 | 3-shell evidence (BBS / Guild permissioning / DM) + completion of Room membership-absorption analysis | Room |
| **Attachment → dedicated primitive promotion** | v0.14+ | Currently judged sufficient as Axis 1 Component (§8.2). Re-evaluate only with 5-shell evidence + blob scale pressure. | — |
| **Active-multi L2** | v0.15+ | 10k+ user deployment + empirical limits of PG-only resolution for mutex races. Distributed lock design without determinism contamination must precede. | — |
| **Multi-instance active federation** | v0.16+ | User-range or shell-per-instance sharding evidence (§14.10 Option A/B) | — |
| **Federation (cross-instance)** | v0.99+ | `SignedArkheUri` + protocol spec + identity federation layer completion | ArkheUri E10 + SignedArkheUri + completed PQC transition |

**v0.12 alpha blocker docs (R5.2 M-R6-3 / R5.4 R8-m2 extension)** — must be completed before alpha release:

| Document | Path | Owner | Purpose |
|---|---|---|---|
| Operator runbook (crypto-erasure) | `docs/runbook/crypto-erasure.md` | veteran + cryptographer | §14.9.1.1 HSM call sequence + backoff + re-verification |
| GDPR legal basis | `docs/Legal/gdpr-crypto-erasure.md` | legal reviewer (external) + cryptographer | §14.9.1 §§9 precedent-based documentation |
| AWS KMS free-tier guide | `docs/guide/kms-free-tier.md` | veteran + BBS maintainer | Tier-1 (§14.9.1 §§12) deployment instructions, monthly 20k req free path |
| HSM degraded mode runbook | `docs/runbook/hsm-degraded-mode.md` | veteran | §14.9.1 §§6 threshold + fallback + recovery |
| Alpha → beta promote runbook | `docs/runbook/alpha-to-beta-promote.md` | veteran + BBS maintainer | R5.4 R8-m2 — (a) `AuthCredential` rotation procedure (`bound_tick` promote + `expires_tick` grace window) (b) user notification template (email / in-session notice) (c) non-rotated users blocked from login (`alpha_credential_rotation_required = true` enforcement) (d) rollback path (emergency `bound_tick` revert) |

Entering the v0.12 implementation DIP requires all 5 drafts complete. Final review before alpha release.

**v0.12 implementation tracking (R5.4 R8 handoff, 2 items)** — spec-level decisions are done; resolved in the implementation DIP:

| Item | Source | Owner | Implementation scope |
|---|---|---|---|
| Process protection platform abstraction | R5.4 cryptographer HF1 handoff | cryptographer + veteran | Abstract Linux (`mlock_all()` + `prctl(PR_SET_DUMPABLE, 0)` + `yama.ptrace_scope=2` or setuid) / macOS (`PT_DENY_ATTACH` + `VM_MAKE_NOMAP`) / Windows (`SetProcessMitigationPolicy(ProcessDynamicCodePolicy + ProcessExtensionPolicyInformation)` + `DebugSetProcessKillOnExit`) behind a `trait ProcessProtection`. Runtime startup selects the platform impl. Flattens §14.7 M-R6-4 HF1 3-part requirements. |
| Manifest bypass audit | R5.4 cryptographer HF4 handoff | cryptographer | The combination `[frontend.alpha_credential_rotation_required = false]` + `runtime_max ≥ "0.16"` produces a **WARN** (not a reject) + prints deployment guide notice. Appends to `runtime_doctor_journal` (operator identity + timestamp + bypass reason — manifest comment required). Leaves the operator's bypass declaration accountability in the audit trail. |

**v0.13 BBS reference shell deployment guide (R5.2 C-R6-1 / R5.3 M-R7-1 / HF4)**:
- `docs/guide/bbs-deployment.md` — nickname + post password + telnet-over-TLS (RFC 2946) + stunnel configuration + AWS KMS free-tier connection.
- Demonstrates that a BBS shell's minimal scope (1 board + 1 chat room) can be deployed at Tier-1 — aligning spec with operator reality.
- **Telnet client TLS wrap matrix (R5.3 M-R7-1)** — client configuration range per platform:
  - **macOS**: `stunnel` (brew install stunnel) + example config.
  - **Windows**: PuTTY + TLS-Telnet plugin, or the Windows stunnel binary.
  - **Linux**: `stunnel` or `socat` (openssl-wrapper).
  - **Mobile (iOS / Android)**: native telnet clients lack TLS support — **recommend the WebSocket-over-TLS alternative**. The BBS reference shell plans to provide a `telnet-ws` adapter (WebSocket frame ↔ Telnet NVT variant) (v0.13 scope).
  - Setup scripts as per-platform deliverables (`docs/guide/bbs-telnet-tls-<platform>.sh`).
- **Alpha → beta credential rotation (R5.3 HF4)**: `AuthCredential`s created during the alpha period (Tier-0 software-kek) **must** be rotated + session tokens invalidated on beta promote. Default: manifest `[frontend.alpha_credential_rotation_required = true]`. Rotation procedure: ask every user to re-register credentials → set existing AuthCredentials' `expires_tick` to the promote tick → non-rotated users are blocked from login in the beta environment.

**v0.13 nice-to-have docs (R5.3 veteran m-R7-1 carryover)**:
- `docs/guide/grafana-dashboard-templates.md` — Grafana dashboard JSON templates based on §12.4 metrics + §12.4.1 SLO table. Includes `arkhe_runtime_event_total{event_type, shell_id}` / `_projection_lag_seconds` / `_hsm_unavailable_total` / `_dek_message_count` / `_kms_sync_lag_seconds`. v0.13 deliverable; v0.12 alpha leaves operators to configure themselves.

**v0.13 DIP candidate (R5.3 auditor mR7-δ carryover)**:
- `ComplianceTierChange` event — records tier transitions (Tier-0 → Tier-1 etc.) chain-anchored. TypeCode `0x0003_0F0A` reserved. Necessity: a tier change is a runtime operations policy change, subject to external audit — currently only logged in the operator journal; v0.13 considers event promotion.

**Common gate requirements**:
- 1 of the §7.4 4 gates + 2+ shell evidence (for New-Primitive).
- Runtime semver impact assessment — split into derivative DIP on 2+ shell breakage.
- Confirm no impact on the 8 L0 DO NOT TOUCH items + BoundedString sealed wrapper.

**Consistency when running concurrently**:
- When multiple DIPs target the same semver (e.g. v0.13) — the leader decides on integration. Integrated: single clean-round cycle; split: each DIP proceeds independently.
- Federation (v0.99+) depends on results from other DIPs — cannot be pursued standalone.

**Refusal / deferred**:
- MMORPG tick-sync state primitive — rejected in §1.2, scoped out via the separate DIP "game-kernel overlay" in §8.4.
- Active-master Sync primitive — cannot inherit determinism; out of Runtime scope.

---

