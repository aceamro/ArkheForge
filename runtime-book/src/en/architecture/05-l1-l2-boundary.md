## §5. L1 ↔ L2 boundary

### §5.1 Inside L1

L1 only: Core 5 primitive Rust types, L0 TypeCode registration, `ActionCompute::compute` pure, referential integrity between primitives, ID generation, ShellBrand distribution.

Strictly forbidden in L1: HTTP/WebSocket/gRPC, PostgreSQL/Redis/S3/CDN, manifest parsing, rate limiting, `std::time::now`, `async`, `tokio`, `unsafe`.

### §5.2 Inside L2

L2 only: manifest TOML load + validation (§5.6), Hook host (v2 WASI — v1 alpha OFF), L4 request → caps → L1 Action → `Kernel::submit`, L0 observer registration → projection (§12.4 SLO), rate limit / quota, audit receipt, cascade scheduler (E11), **idempotency dedup (§14.8)**, GDPR erasure-cascade service (§14.9), DR coordinator (§14.11).

**R4' operational model**: active-passive L2 only + client-supplied idempotency key. Multi-active is a separate DIP.

Forbidden in L2: direct mutation of Kernel state, name-based dispatch, kernel re-execution of hook-originated cascades (§9.1).

**Primary backing store (R5 Axis 3 — team-lead directive 2026-04-24, unanimous among 4)**: **PostgreSQL**. Redis is an optional cache/queue at production scale.

| Function | PG primary | Redis fallback condition |
|---|---|---|
| Idempotency dedup | **2-layer (R5.2 mNF-A)**: (1) L2 PG `UNIQUE INDEX (idempotency_key) + INSERT ON CONFLICT DO NOTHING + expires_at TIMESTAMPTZ` + background TTL cleanup (partition drop) — fast pre-filter. (2) L1 WAL scan via `ctx.idempotency_lookup` (§3.3 / §14.8 FG6) — crash-recovery backstop (PG Redis loss scenario after passive promote). *R5.3 R7-NR4 footnote: the L1 path activates the tick-scoped auxiliary index only under L0 v0.13+. During Runtime v0.12 the PG UNIQUE INDEX is the single dedup path — the crash-recovery gap is covered by `docs/runbook/crypto-erasure.md` and the operator runbook.* | `SETNX` alternative when < 5ms SLA required. |
| Rate limit counter | `UNLOGGED TABLE` (restart loss permitted) + atomic `UPDATE ... RETURNING`. | Under production 10k+ user PG lock contention → Redis `INCR`. |
| Observer fanout | `LISTEN / NOTIFY` (payload ≤ 8KB, scales to hundreds of connections). | For beta+ multi-region pub-sub → Redis Streams. |
| Queue worker | `SELECT ... FOR UPDATE SKIP LOCKED`. | Redis Lists optional in production. |

**L4 adapter TLS obligation (R5.2 GF3)**: L2 verifies transport-layer security when registering an L4 adapter. Plaintext protocols (raw Telnet, plaintext HTTP, MQTT without TLS, etc.) are rejected by default — `L4AdapterError::TlsRequired`. Fine control via shell manifest `[frontend.tls_required]` (default `true`). Permitted bypass = dev/alpha `runtime_max ≤ "0.15"` + `tls_required = false` + permanent admin-dashboard warning (production reject). The BBS reference shell requires **Telnet-over-TLS (RFC 2946)** or stunnel wrap — see example in §15.5 deployment guide.

**Tiered deployment (aligned with §14.10)**:
- alpha (< 1k users, < 100 req/s): **PG-only recommended**. UNLOGGED + LISTEN/NOTIFY + single-DB operator learning curve.
- beta (1–10k users, < 1k req/s): PG primary + optional Redis (dedicated to idempotency/rate-limit).
- production (10k+ users, > 1k req/s): PG + Redis (cache/queue required, bypasses the §10.4 single-thread ceiling).

Basis for the cryptographer R5 recommendation: Redis CVE-2022-0543 RCE, Sentinel master election race, RedLock Kleppmann 2016 critique, ACL misconfiguration — PG `INSERT ON CONFLICT` is single-primary ACID with no split-brain. Reduced alpha security surface.

#### §5.2.1 Rate limit model — 3-axis token bucket (R5 veteran m-R5-2)

The Runtime rate limit composes three-axis token buckets:

| Axis | Key | Purpose | Default capacity / refill |
|---|---|---|---|
| per-actor | `(shell_id, actor_id)` | per-actor abuse defense | 60 tok / 60s |
| per-shell | `shell_id` | shell-wide throttle (DoS response) | manifest `[quota.shell_rps]` |
| per-IP | `client_ip` (L4 adapter provided) | anonymous-scrape defense | 30 tok / 60s |

Before compute entry, L2 must allow on all 3 axes to submit. Any reject → `429 Too Many Requests` + `arkhe_runtime_rate_limit_reject_total{axis, shell_id}` counter.

**Leak semantics**: tokens are a leaky bucket — fixed refill per second. Burst capacity is derivable from the expiry tick (L0 ticks are integers → deterministically computable).

**Storage tier** (aligned with PG-only tiered):
- alpha: `UNLOGGED rate_limit_bucket(key BYTEA PRIMARY KEY, tokens INT, last_refill_tick BIGINT)` table + atomic `UPDATE ... RETURNING`. Capacity loss on restart permitted (alpha SLA).
- beta+: keep the same table, or switch to Redis `INCR` + `EXPIRE` (manifest `[quota.storage_backend = "pg" | "redis"]`).
- production: Redis required — PG row lock contention absorbs the §10.4 single-thread ceiling.

**Cross-axis composition** (NC3 style): all 3 axes allow → 1-submit; any reject → full reject. Per-stage reject reasons are recorded in the audit log (operator diagnosis).

### §5.3 Data flow — hook confused-deputy defense (C8/S1/I2)

```
[Frontend/Client]
      │  X-Arkhe-Idempotency-Key: <UUID v4> (C6)
      ▼
[L4 Protocol Adapter]  ─ decode ─▶ [L2 Service API DTO]
                                         │
                                         ▼
                        [L2 Idempotency dedup (PG UNIQUE INDEX primary §14.8)]
                                         │  duplicate → return prior response
                                         ▼
                        [L2 Auth & Quota check]  ◄── caps resolve
                                         │  fail → reject
                                         ▼
                [L2 Hook host (extra_bytes only, v2+, OFF in v1)]
                                         │  hook result: modifies only &mut ExtraBytesBuilder
                                         │  (policy-invariant fields cannot be modified)
                                         ▼
                [L2 Policy re-validation]   ◄── re-validates after hook execution (C8 confused-deputy defense)
                                         │  rechecks manifest rule / mutex / visibility
                                         │  fail → reject + audit log
                                         ▼
                [L1 Action body build (with hook-appended extra_bytes)]
                                         │
                                         ▼
                        Kernel::submit(inst, principal, caps, ...)
                                         │
                                         ▼
                   ┌──────────── L0 Kernel ────────────────┐
                   │ authorize → Action::compute → Ops     │
                   │ → StepStage commit → WAL chain        │
                   └──────────────────┬─────────────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
            [WAL fsync]     [Observer fanout (shell_id filter S7)]  [InstanceView read]
                 │                    │
                 │                    ▼
                 │   [L2 Projection writer  (Prometheus SLO)]
                 │       ─ auto-restart (exp backoff 3×)
                 │       ─ catch_unwind + pool regen
                 │                    │
                 │                    ▼
                 │           [PostgreSQL primary + Redis optional (§5.2)]
                 │                    │
                 │                    ▼
                 │           [L4 Frontend push]
                 │
                 └──► [L2 cascade scheduler — tick+1 re-submit (E11)]
                 └──► [L2 GDPR erasure-cascade (§14.9)]
                 └──► [L2 Audit receipt issuance]
                 └──► [L2 DR coordinator — WAL streaming replication (§14.11)]
```

**Hook contract** (C8 / S1):
1. Hook execution order: Auth & Quota → **Hook (extra_bytes only)** → **Policy re-validation (rerun)** → Build → Submit.
2. A hook **cannot modify** policy-invariant fields (actor / verb / target / shell_id / principal). Only `&mut ExtraBytesBuilder` is exposed.
3. The hook result is folded into canonical bytes and submitted to the kernel as a single Action. The kernel never re-runs hooks. Replay determinism preserved.
4. After hook execution, policy re-validation rechecks the same manifest rules. If a hook inflates extra_bytes without bound, the size cap rejects.
5. Hook failure = L2 submit rejection + audit log.
6. v1 alpha: **all OFF** (§14.5).

### §5.4 L1-L2 mutual prohibitions

| Prohibition | Reason |
|---|---|
| L1 → L2 import | Strictly downward DAG (E3). |
| L1 → std::fs / net / time | A11 pure. |
| L2 → kernel state (submit bypass) | Disables A18/A20. |
| L2 → Component private field | A17 bypass. |
| L1 compute → HTTP/DB | A11. |
| L2 → shell-specific hardcode | Manifest + hook only. |
| Hook → policy-invariant field mutation | §9.1 / C8 confused deputy. |
| Hook → multiple submit | 1-shot + fold-in only. |
| Observer → bypass shell_id filter | S7 cross-shell metadata leak. |

### §5.5 Observer path — X5 / M-slo / S7 / P2

- L2 Projection writer = L0 observer, `OBSERVER_REGISTER` cap, `DOMAIN_EVENT_EMITTED` + `ACTION_EXECUTED` mask.
- **Shell filter obligation (S7)**: observer registration must specify `shell_id_filter: BTreeSet<ShellId>`. Events of shells outside the interest set are not dispatched. A single observer may subscribe to multiple shells, but the filter mask is declared publicly.
- L0 A18: observer drain after WAL fsync.
- L0 A22: an observer panic causes immediate eviction.

**Operational contract** (X5 + M9 per-tick atomic):
1. SLO `NOW() - last_applied_at < 30s` p99.
2. Auto-restart with exp backoff (2s / 8s / 32s) × 3. Three failures → operator page + `observer_dead=true`.
3. UnwindSafe: PG/Redis connections are not UnwindSafe → after `catch_unwind`, replace the entire connection pool. Hold only `Arc<Mutex<Pool>>`.
4. Cascade tick (E11 MC): L2 post-event cascade uses `Op::ScheduleAction { at: Tick(t+1), ... }` bound to the original Action tick `t`. L0 scheduler imposes a deterministic order.
5. **Per-tick atomic PG transaction (M9 / R5 NF7 replay inheritance)**: `BEGIN` at tick start, `COMMIT` at tick end. On panic → PG rollback → idempotent restart. `kernel_projection_state.last_applied_tick` is updated only at committed ticks (single transaction together with C3 chain_tip signature). Extension TypeCode validation runs as a validator **before** the projection write — on failure log+skip, never panic. Blocks the adversary path where malformed Extension bytes induce a writer panic → partial-state oracle. **The replay path inherits the same contract**: the tick stream supplied by L0 `replay_into` is wrapped in tick-level BEGIN/COMMIT by the L2 projection. Failed-validator records are explicitly inserted into the `unknown_variants` staging table (§12.4) + audit log — silent skip forbidden. Both replay/live paths are per-tick atomic: no "half-applied tick" state is permitted.

**Tick-scoped Component read cache (P2)**:
```rust
// L1 wrapper over the L0 InstanceView — within the same tick, identical (entity, TypeCode) reads share a single underlying lookup.
// BTreeMap<(EntityId, TypeCode), Arc<Bytes>> per-tick.
// Invalidated at tick boundaries (step boundary).
// Metric: arkhe_runtime_component_read_cache_hit_ratio.
```

For N=10^7 entities, `BTreeMap::get` O(log n) ≈ 23 — amortized to 1 by the cache.

### §5.6 Manifest Schema v1 — extensions (C5 / I3 / P1 / C2)

**Purpose**: the official schema for shell manifest TOML. unknown-key reject + schema_version required + **canonical TOML digest** pinned in the WAL header.

```toml
schema_version = 1                               # only value=1
shell_id       = "bbs"                           # [a-z0-9][a-z0-9_-]{1,30}
display_name   = "ArkheNet BBS"
version        = "0.1.0"
runtime_min    = "0.12"
runtime_max    = "0.x"

[typecode_allocation]
entity_range    = { from = 0x0100_0000, to = 0x0100_FFFF }
component_range = { from = 0x0101_0000, to = 0x0101_FFFF }
verb_sub_range  = "auto"                         # BLAKE3(shell_id) deterministic 256-verb
verb_range_nonce = 0                             # R5 NF10 — bump on collision (§3.2)

[actor]
naming_regex   = "^[a-z0-9_]{3,20}$"
handle_change_cooldown_days = 30
allow_anonymous = false

[space]
kinds_enabled  = ["Flat"]
tree_max_depth = 0
creation_policy= "AdminApprove"                  # AdminApprove | UserFree | InviteOnly

[entry]
title         = "Required"                       # Required | Optional | Disabled
body_max      = 65536
edit_grace_seconds = 600
attachment_max = 4
tags_max      = 5

[activity]
verbs_enabled = ["Like", "Follow"]
extra_bytes_max_bytes = 4096                     # P1 required, hard cap 65536
verb_cooldown_seconds = 10                       # C2 default, prevents retract abuse

[[activity.mutex_group]]
verbs         = ["Like", "Dislike"]

[activity.visibility]
Like     = "Public"
Bookmark = "Private"

[activity.notify_policy]
Follow   = "Push"                                # Push | Digest | None

[moderation]
scope             = "SpaceScoped"                # Global | SpaceScoped
appeal_sla_days   = 7
appeal_max_depth  = 2                            # I3 parametric (1..=8, default 2)

[hook]
enabled = false                                  # §14.5 v1 alpha OFF

# R5.2 GF3 — L4 frontend security requirements
[frontend]
tls_required     = true                          # default true. false only allowed when runtime_max ≤ "0.15"
alpha_credential_rotation_required = true        # R5.3 HF4 — AuthCredentials created during alpha must be rotated + sessions invalidated on beta promote

# R5 C-R5-5 — audit / crypto-erasure backend composition
[audit]
signature_class  = "Ed25519"                     # "Ed25519" | "MlDsa65" | "Hybrid"
dek_backend      = "hsm"                         # "hsm" | "kms" | "software-kek"
dek_replication  = "global-hsm"                  # "global-hsm" | "per-region"
pii_cipher       = "xchacha20-poly1305"          # "xchacha20-poly1305" (default) | "aes256-gcm" | "aes256-gcm-siv"
kms_auto_promote = "manual"                      # "manual" (default) | "after_60min" (R5.2 m-R6-2)

# R5 Axis 3 — storage tier
[quota]
shell_rps        = 200                           # per-shell token bucket capacity
storage_backend  = "pg"                          # "pg" (default alpha/beta) | "redis" (beta+/production)

# M1 — L2 active writer same-tick ordering. Timing-critical shells use "commit_reveal".
[shell]
ordering_policy = "fifo"                         # "fifo" (default) | "commit_reveal"

# M3 — Tick-timing cross-shell covert channel defense.
[projection]
tick_visibility = "precise"                      # "precise" (default) | "coarse" | "none"
# coarse: 1000-tick bucket + internal order shuffle (exposed values only; WAL origin stays precise)
# none:   Band 3 sessions expose only in bulk after session close
# precise: existing scheme (default for public shells)

# optional shell deprecation marker (veteran N4 / §14.7 shell sunset)
# [deprecated]
# at_tick     = 123456789
# reason      = "superseded by bbs-v2"
```

**Validation**:
- `schema_version` required; only `1` currently valid.
- Unknown top-level / section key → reject (strict parser).
- Values outside the canonical enum → reject.
- Regex validity.
- Cross-reference: `[activity.mutex_group]` verbs ⊆ `verbs_enabled`.
- `extra_bytes_max_bytes` ≤ Runtime hard cap 65536 (P1).
- `appeal_max_depth` ∈ [1, 8] (I3).
- `ordering_policy` ∈ {"fifo", "commit_reveal"} (M1).
- `tick_visibility` ∈ {"precise", "coarse", "none"} (M3).
- **R5 PQC timeline enforcement (C-R5-5b)**: when `runtime_max ≥ "0.30"`, `[audit.signature_class] ∈ {MlDsa65, Hybrid}` is enforced. Ed25519-only → `ManifestError::PqcTimelineViolation` parse error. During the 2027–2029 transition (`0.16 ≤ runtime_max < 0.30`), Ed25519-only shells carry a **warning flag** + marketplace UI exposure. The `arkhe-runtime-doctor pqc-timeline-audit` command produces a PQC-readiness dashboard across all shells.
- **R5 software-kek constraint (C-R5-5a — team-lead directive 2026-04-24, strengthened by R5.2 GF1)**: `[audit.dek_backend = "software-kek"]` is valid only when **both** conditions hold:
  1. Shell manifest `runtime_max ≤ "0.15"` (alpha milestone).
  2. **Runtime binary `runtime_current` version ≤ "0.15"** (R5.2 GF1 blocks production leak).
  When a production runtime binary (`runtime_current ≥ "0.16"`) encounters a manifest declaring `dek_backend = "software-kek"` → LOAD stage `ManifestError::SoftwareKekProductionRefused` parse error. Even if an adversary selectively declares a shell manifest's `runtime_max = "0.15"`, the production runtime rejects. On successful declaration, publish a permanent warning tag `arkhe_runtime_software_kek_alpha_mode=true` metric to dashboards/audit logs. Not a ≤1k-user / GDPR Art.17 empirically-validated environment.
- **R5.2 GF2 AeadKind downgrade defense**: changes to shell manifest `[audit.pii_cipher]` **require a VerbCode-level schema_version bump**. Existing ciphertexts are kept under the old cipher (dispatched via wire `aead_kind` field); only new writes use the new cipher. `EncryptedPii<T>::decrypt()` verifies that the ciphertext's `aead_kind` matches the manifest `pii_cipher` at the time the record was created — mismatch → `PiiError::CipherDowngrade`. Same rule wired to §9.1 hook principle.
- **R5 verb_range_nonce (NF10)**: `[typecode_allocation.verb_range_nonce]` is `u32` (default `0`). `blake3::derive_key("arkhe-forge-verb-alloc", shell_id_bytes || nonce.to_be_bytes())` deterministic retry (§3.2). On collision detection, bump the nonce — the registry pin (A15) uses the confirmed nonce value.
- **shell_id homograph phishing defense (m1)**: when registering a new shell_id, Levenshtein distance ≥ 2 against already-registered shell_ids is a soft guideline (warning, not forced reject). `display_name` is a separate field — UI confusion is first defended by display_name uniqueness.

**Canonical TOML digest (C5)**:
- BLAKE3 over raw TOML bytes is **forbidden** (comment/whitespace drift).
- Approach: use the `toml_edit` crate or an in-house canonicalizer to parse → canonical serialize (sorted keys, normalized whitespace, comments removed) → BLAKE3 over canonical bytes.
- Result: pinned in WAL header as `manifest_digest: [u8; 32]` (A14 extension).
- Replay mismatch → `ReplayError::ManifestDigestMismatch`.
- `arkhe-runtime-doctor` provides a `manifest-digest-recompute` command (§14.7).

**Hot-reload not supported in v1** (veteran C1). Change = process restart + WAL resume. Lifecycle: `LOADING → VALIDATED → ACTIVE → DRAINING → UNLOADED`.

---

