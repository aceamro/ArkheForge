## §13. Multi-shell hybrid proof

### §13.1 Scenario

```
users [user_id=1 Alice | user_id=2 Bob]
actors
  actor=10 (shell=bbs,    user_id=1)   actor=11 (shell=bbs,    user_id=2)
  actor=20 (shell=guild,  user_id=1)   actor=21 (shell=guild,  user_id=2)
  actor=30 (shell=casino, user_id=1)   actor=31 (shell=casino, user_id=2)
spaces  (space=100 bbs, space=200 guild, space=300 casino)
entries (entry=1000 bbs, entry=2000 guild, entry=3000 casino)
activities (A1 Like→1000, A2 Follow→21, A3 Pin→3000)
```

### §13.2 Structural guarantees (reflecting E7 dual-tier)

**Isolation 1 — Cross-shell Activity submit-site** (E7 TP):
```
Can Alice's BBS Actor<'s1>(10) Follow Guild Bob Actor<'s2>(21)?
→ SubmitActivity::from_branded(Activity { brand: 's1, inner: { target: Actor(21) } })
  Here `'s1` is bbs; at runtime the target Actor(21) resolves to guild, but at the submit site
  the call `Activity::new(brand_bbs, record)` itself requires Bob actor's brand → compile error.
```

**Isolation 2 — Replay/admin double-check** (E7 RA):
```
Scenario where an adversarial or corrupted WAL contains a cross-shell ActivityRecord:
→ SubmitActivity::compute compares ctx.read::<ActorProfile>(actor).shell_id
  against ctx.read::<ActorProfile|EntryCore|SpaceConfig|ActivityRecord>(target).shell_id
  and rejects (B1 dual-check MC).
→ No Op is produced; a CrossShellActivity event is emitted.
```

**Isolation 3 — Entry parent/relay** (E7 + E-entry-2 + P5):
Is an Entry<'s_bbs>'s parent an Entry<'s_casino>? Type mismatch compile error + compute MC double-check.

**Integration 1 — GDPR lease + L1 MC (C3)**:
```
Alice GdprEraseUser(user_id=1):
→ compute: [SetComponent(ErasurePending), EmitEvent(UserErasureScheduled)]
→ L2 erasure-cascade observer → tick+1 bounded batch:
   per-shell Actor despawn, EntryBody removal, Activity retract.
→ During the ErasurePending window, all of Alice's Actors are rejected at L1 compute
   (gdpr_status check) — no new Activity/Entry creation.
→ §14.9 SLA p95 < 24h.
```

**Integration 2 — User-level audit**:
```sql
SELECT a.*, act.*
FROM actors a
JOIN activities act ON act.actor_id = a.actor_id
WHERE a.user_id = 1 AND act.at_tick > (now_tick - 24*3600*10)
  AND act.status = 'active'                    -- C2
ORDER BY act.at_tick DESC;
```

### §13.3 Kernel perspective + throughput

- All shell Actions within a single InstanceId share one WAL (A23).
- Shell distinction is a Component field.
- Single-thread serial (A2). ~200 Action/sec/instance (§10.4).
- 10k+ user scaling: §14.10.
- Projection shell_id filter.

### §13.4 Coexistence with shell-scoped primitives

Casino Session/Turn/Round is shell-scoped (`0x0201_XXXX`):
- A Casino hook (planned from v2+) submits `SubmitEntry` + `CasinoPlayerAction`.
- BBS/Guild are unaware — projection silent-skips unknown TypeCodes + shell_id filter.

### §13.5 Structural proof (5 lines)

1. **User/Actor 2-tier** — User is shared, Actor is isolated.
2. **ShellBrand `'s` submit-site** — cross-shell is a compile error (E7 TP).
3. **L1 compute shell_id dual-check** — MC double-defense on the replay/admin path (E7 RA).
4. **Core 5 + 4 extension axes** — absorbs shell specifics without modifying core.
5. **Active-passive L2 + idempotency key** — blocks multi-L2 races (§14.8).

Running BBS + GuildChat + Casino concurrently is **structurally sound**.

---

