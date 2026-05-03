## §9. Determinism boundaries — 3-band

### §9.1 Band 1 — Core Deterministic (direct L0 A1 lineage) + reinforced hook principles

**Guarantee**: the same config + postcard-canonical Action sequence + manifest → bit-identical WAL + snapshot.

**Scope**: all Core 5 Actions, all compute `Vec<Op<'i>>`, Component canonical_bytes, L0 Event emission.

**External input**: time/random/network must not enter Band 1 compute. L2 normalizes canonical bytes and folds them into the Action body before submit.

**Hook principles** (X2 / C8 / S1 reinforcement):
1. A hook is **1-shot pre-submit**. It may only modify `&mut ExtraBytesBuilder` (policy-invariant fields are immutable).
2. The result is folded into canonical bytes and submitted to the kernel as a single Action.
3. The kernel never re-executes the hook. Replay determinism preserved.
4. After hook execution, **policy re-validation** rechecks manifest rules (confused-deputy defense).
5. Hook failure = L2 submit rejection + audit log.
6. v1 alpha: all hooks OFF (§14.5).

**Cascade tick** (M-tick / E11 MC): L2 post-event cascade is an `Op::ScheduleAction { at: Tick(t+1), ... }` bound to the original Action's tick `t`. L0 scheduler imposes a deterministic order.

**Shell manifest change principle (R5.2 GF2 extension)**: changes to `[audit.pii_cipher]` / `[audit.signature_class]` / `[audit.dek_backend]` **require a VerbCode-level schema_version bump** — existing ciphertext/receipts remain under the old value (dispatched via wire tag); only new writes use the new value. Hot-swap is forbidden. The time of change is recorded with a chain-anchored event each (`SignatureClassPolicy` §14.7 E13 / consider introducing a similar PolicyEvent). Verifiers trust the chain-anchored policy, not the message tag.

### §9.2 Band 2 — L2 Projection (non-deterministic derivation)

Given the WAL, the L2 projection is reconstructed eventually consistent. Not bit-identical.

Scope: PostgreSQL, Redis, WebSocket fan-out, rate-limit counters. On projection corruption, re-derive from the WAL.

### §9.3 Band 3 — Protocol-Correctness Only (shell-level)

The kernel WAL is a valid protocol message sequence. State values cannot be bit-identically replayed.

Scope: Casino Mental Poker, E2E DM plaintext, threshold commit/reveal vote.

**Runtime core scope refusal (C4 team-lead option B 2026-04-24)**:

> **The Runtime core does not guarantee phase ordering / correctness / collusion resistance of Band 3 protocols. A Band 3 shell takes 100% responsibility for its own phase FSM, `arkhe-<shell>-verify` audit tool, and L2 active writer strict FIFO. The `Band3Message` marker trait (now replaced by the `#[arkhe(band = 3)]` attribute — NC3) is merely a type-level hint for routing.**

Rationale: enforcing phase ordering in a commit-reveal protocol (e.g. requiring Bob Commit to precede Alice Reveal) at L1 compute would require adding a "phase Component" + "action sequence guard" at the core primitive level. Insufficient 2+ shell evidence (Casino only) + conflict with §1 "refuse generality" principle. Therefore currently out of scope.

Officially registered as a **v0.13 DIP candidate** in §14 / §15.3 — once E2E DM, threshold vote, and Casino each have 3-shell evidence, a core promotion DIP for `BandThreePhase` Component + `Band3Action::required_phase()` compile-time enforcement will proceed.

**Band 3 shell audit checklist (C4 / §8.5 linkage)**: shell implementers own the defense against the following violation categories.

| Violation type | Description | Shell defense |
|---|---|---|
| commit-before-reveal | Reveal occurs before the counterpart's commit | Phase Component FSM — state transition guard |
| late reveal | Reveal after the deadline | Deadline tick cap + expiry Action |
| player collusion | Out-of-band collusion | Protocol design responsibility (outside engine scope) |
| phase skip / double-commit | Skipping FSM steps | Action guard: `if phase != Expected { reject }` |
| threshold cutoff manipulation | Threshold recomputation attack | Merkle-pinned threshold + commit-phase lock |

The Casino shell (`arkhe-casino`) provides its own `CasinoPhase` Component + `arkhe-casino-verify` audit tool — shell-scoped (§7.1 Axis 1).

**R5 R5-r5 — shell verifier chain-attestation requirement**: a Band 3 shell's audit tool (`arkhe-casino-verify` etc.) binary must itself ship as **chain-attestation**: (a) binary BLAKE3 digest + (b) Ed25519 / PQC operator signature + (c) transparency log (Sigstore/Rekor, or an in-house Merkle + periodic publish) entry. The Runtime manifest `[shell.verifier_attestation]` pins the digest + log index → only approved verifiers may produce trusted audit output. This blocks the path where an adversary ships a malicious verifier to forge a "pass" result. When §15.4 v0.13 DIP is promoted, the `Band3VerifierAdapter` trait interface will include an attestation verification API.

**Band attribute (NC3 adopted)**:
```rust
// A band attribute on Action derive — one Band per Action.
#[derive(ArkheAction)]
#[arkhe(type_code = ..., schema_version = 1, band = 1)]     // Band 1 (default)
pub struct SubmitActivity { ... }

#[derive(ArkheAction)]
#[arkhe(type_code = ..., schema_version = 1, band = 3)]     // Band 3
pub struct CasinoShuffleMessage { ... }
```

The ArkheAction derive reads the band attribute and auto-attaches the appropriate sealed marker trait. The standalone `Band3Message` trait is removed (NC3 integration).

### §9.4 Band-boundary red alerts

| Signal | Meaning |
|---|---|
| Core primitive Action uses rand/time | Band 1 violation of A11. |
| L2 projection bypasses WAL and writes | Band 2 → 1 contamination. |
| Shell Band 3 protocol injected into core primitive | Band boundary collapse. |
| Replay depends on PostgreSQL state | DAG inversion. |

### §9.5 Band summary (reflecting NC3 attribute)

| Band | Guarantee | Storage | Examples | Action attribute |
|---|---|---|---|---|
| 1 Core Deterministic | bit-identical replay | Kernel WAL | RegisterUser, SubmitActivity | `#[arkhe(band = 1)]` (default) |
| 2 L2 Projection | eventually consistent | PostgreSQL, Redis | reaction_count, timeline cache | (observer, not Action) |
| 3 Protocol-Correctness | protocol validity only | Kernel WAL (message bytes) | Mental Poker, E2E DM | `#[arkhe(band = 3)]` |

---

