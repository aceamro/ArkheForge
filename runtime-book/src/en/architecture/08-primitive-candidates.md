## §8. Follow-up primitive candidates — Gate analysis

### §8.1 Room — real-time chat

Gates (a, c, d) — 3. Evidence from 2+ shells (BBS conversation rooms + TubeLike live + GuildChat). **R4' verdict**: **Separate primitive, follow-up DIP** (held since R3). The R1 draft "Entry(Ephemeral) + Activity(Say)" alternative is withdrawn (tuple idempotency collision). Runtime semver v0.12 → v0.13.

### §8.2 Attachment — Axis 1 Component

Gate (c) — 1. **Retained as Axis 1**. `EntryAttachments { refs }` + `entry_attachment_refs` extension table. sha256-based duplicate detection projection.

### §8.3 Session/Turn/Round — shell-scoped + Band 3

Gates (a, b, d) — 3. Insufficient 2+ shell evidence (Casino only). **Shell-scoped own implementation** permitted. A Band 3 `Band3Message` marker trait (§9.3) — no axiom promotion. Re-evaluate once a second game shell provides evidence.

### §8.4 MMORPG / real-time games — rejected

Gates (c, d). **Rejected from the Runtime core** (§1.2). Separate DIP: "game-kernel overlay" architecture. Consider ArkheForge + game-kernel side-car in v0.99+. Currently the Runtime makes no promise in this area.

### §8.5 SpaceMembership primitive gate — auditor N5

**Identity**: the set of actors participating in a Space. In R4' §4.3 it is retained as a Component accompanying SpaceConfig.

**Gate**:
- (a) Lifecycle — same persistence as Space. Fail.
- (b) Auth — existing cap is sufficient. Fail.
- (c) Scale — in a single space where member count reaches critical scale (e.g. 10k+ public groups), the BTreeSet may explode. Partial (depends on shell policy).
- (d) WAL — existing SetComponent suffices. Fail.

**Verdict**: Axis 1 Component retained. Not a follow-up primitive candidate. When the Room primitive follow-up DIP proceeds, re-evaluate whether to absorb membership into Room (Room is likely to include membership itself).

### §8.6 Summary of follow-up candidates

| Candidate | Gate | Evidence | R4' verdict |
|---|---|---|---|
| Room | a, c, d (3) | 3 shells | Separate primitive, follow-up DIP |
| Attachment | c (1) | 3 shells | Axis 1 retained |
| Session/Turn/Round | a, b, d (3) | 1 shell | shell-scoped + Band 3 marker |
| MMORPG tick-sync | c, d | — | Scope rejected, separate DIP overlay |
| SpaceMembership | — | 1 shell (R3 correction) | Axis 1 retained, re-evaluate together with Room |

---

