## §12. PostgreSQL projection schema overview

### §12.1 Design principles

1. Core tables carry generic names.
2. Multi-tenant `shell_id TEXT NOT NULL`.
3. Shell extensions: `shell_payload JSONB` (top-level key == shell_id) or a `<shell_id>_<entity>_ext` table.
4. Kernel entity id → BIGINT PK.
5. Partial index for active rows.
6. Beware JSONB GIN index write amplification (~20% throughput drop) — move large fields to separate tables.

### §12.2 Core 5 table summary

```sql
CREATE TABLE users (
    user_id           BIGINT PRIMARY KEY,
    gdpr_status       TEXT NOT NULL DEFAULT 'active',
    primary_auth_kind TEXT NOT NULL,
    created_tick      BIGINT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth_credentials (
    credential_id     BIGINT PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES users(user_id),
    kind              TEXT NOT NULL,
    kdf               TEXT NOT NULL CHECK (kdf IN ('argon2id','scrypt')),  -- C9/S2
    salt              BYTEA NOT NULL CHECK (octet_length(salt) = 16),
    credential_hash   BYTEA NOT NULL CHECK (octet_length(credential_hash) = 32),
    kdf_params        JSONB NOT NULL,                                       -- { m_cost, t_cost, p_cost }
    expires_tick      BIGINT,                                               -- S8 rotation
    bound_tick        BIGINT NOT NULL
);

CREATE TABLE actors (
    actor_id      BIGINT PRIMARY KEY,
    user_id       BIGINT REFERENCES users(user_id),
    shell_id      TEXT NOT NULL,
    handle        CITEXT NOT NULL,
    kind          TEXT NOT NULL,
    created_tick  BIGINT NOT NULL,
    shell_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (shell_id, handle)
);

CREATE TABLE spaces (
    space_id         BIGINT PRIMARY KEY,
    shell_id         TEXT NOT NULL,
    slug             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    visibility       TEXT NOT NULL,
    creator_id       BIGINT NOT NULL REFERENCES actors(actor_id),
    parent_space_id  BIGINT REFERENCES spaces(space_id),                    -- P5 immutable
    parent_depth     SMALLINT NOT NULL DEFAULT 0 CHECK (parent_depth <= 64),
    created_tick     BIGINT NOT NULL,
    shell_payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (shell_id, slug)
);

CREATE TABLE entries (
    entry_id           BIGINT PRIMARY KEY,
    shell_id           TEXT NOT NULL,
    space_id           BIGINT NOT NULL REFERENCES spaces(space_id),
    author_id          BIGINT NOT NULL REFERENCES actors(actor_id),
    parent_entry_id    BIGINT REFERENCES entries(entry_id),                 -- P5 immutable
    parent_depth       SMALLINT NOT NULL DEFAULT 0 CHECK (parent_depth <= 64),
    relay_of_entry_id  BIGINT REFERENCES entries(entry_id),                 -- P5 immutable
    relay_kind         TEXT,
    title              TEXT,
    body_hash          BYTEA NOT NULL CHECK (octet_length(body_hash) = 32),
    body_cache         TEXT,
    status             TEXT NOT NULL DEFAULT 'live',
    edit_seq           INT NOT NULL DEFAULT 0,
    created_tick       BIGINT NOT NULL,
    shell_payload      JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- DM (X3)
CREATE TABLE space_memberships (
    space_id    BIGINT NOT NULL REFERENCES spaces(space_id),
    actor_id    BIGINT NOT NULL REFERENCES actors(actor_id),
    joined_tick BIGINT NOT NULL,
    PRIMARY KEY (space_id, actor_id)
);

-- Activity with status (C2)
CREATE TABLE activities (
    activity_id               BIGINT PRIMARY KEY,
    shell_id                  TEXT NOT NULL,
    actor_id                  BIGINT NOT NULL REFERENCES actors(actor_id),
    verb_typecode             BIGINT NOT NULL,                              -- u32 widened
    target_kind               TEXT NOT NULL,                                -- 'entry'|'actor'|'space'|'activity'|'extension'
    target_id                 BIGINT NOT NULL,
    target_extension_typecode BIGINT,                                       -- NULL unless 'extension'
    target_shell_id           TEXT NOT NULL,                                -- C1 — shell-scoped idempotency
    at_tick                   BIGINT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'active'                -- C2 'active' | 'retracted'
                              CHECK (status IN ('active','retracted')),
    retracted_at_tick         BIGINT,                                       -- NULL if active
    extra_bytes               BYTEA,
    CHECK (target_shell_id = shell_id),                                     -- C1 cross-shell block
    UNIQUE (actor_id, verb_typecode, target_kind, target_id, status)        -- C2 unique on active only
);
-- Partial unique: active only — a new row on re-submit; previous becomes retracted tombstone
CREATE UNIQUE INDEX idx_activities_active_unique
    ON activities(actor_id, verb_typecode, target_kind, target_id)
    WHERE status = 'active';
CREATE INDEX idx_activities_target ON activities(target_kind, target_id, verb_typecode, at_tick DESC);
CREATE INDEX idx_activities_actor  ON activities(actor_id, verb_typecode, at_tick DESC);
```

### §12.3 Shell extension

BBS uses `shell_payload ->> 'is_concept'`. Separate tables: `bbs_board_creation_requests`, `casino_tables`, `casino_hands(transcript_url)`.

### §12.4 Kernel projection state + SLO (M-slo-metric)

```sql
CREATE TABLE kernel_projection_state (
    instance_id                   BIGINT PRIMARY KEY,
    last_applied_tick             BIGINT NOT NULL,
    last_applied_seq              BIGINT NOT NULL,
    chain_tip                     BYTEA NOT NULL CHECK (octet_length(chain_tip) = 32),
    chain_tip_signature           BYTEA NOT NULL CHECK (octet_length(chain_tip_signature) IN (64, 128)),  -- C3 Ed25519(64) or Hybrid(64+64)
    chain_tip_signature_key_id    BYTEA NOT NULL CHECK (octet_length(chain_tip_signature_key_id) = 32),   -- R5 M-R5-4 HSM key fingerprint
    signature_class               TEXT NOT NULL                                                           -- R5.2 GF5 — blocks type confusion
                                      CHECK (signature_class IN ('Ed25519','MlDsa65','Hybrid')),
    runtime_semver                TEXT NOT NULL,
    manifest_digest               BYTEA NOT NULL CHECK (octet_length(manifest_digest) = 32),
    observer_state                TEXT NOT NULL DEFAULT 'active'
        CHECK (observer_state IN ('active','degraded','replaying','dead')),
    last_applied_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    restart_attempts              INT NOT NULL DEFAULT 0
);
-- C3 read/write verifies chain_tip_signature. Key in HSM/KMS.
-- On restart, MC-check that the L0 InstanceView current tick matches last_applied_tick + chain_tip.
-- Mismatch → observer_state='dead' + operator alert + rollback blocked.
-- R5 M-R5-4 chain_tip_signature_key_id — HSM key fingerprint. On rotation, the old key is kept
--   verification-only (historical signature verification). Rotate via `runtime-doctor key-rotate`.
-- R5 FG8 — Ed25519 chain_tip key rotation 90d cadence + grace-period (90d+30d overlap verification window).
-- R5 R5-r4 — On HSM unavailable, switch observer_state='degraded' (new writes blocked, reads retained).
-- R5.2 GF5 — the signature_class column distinguishes Ed25519(64B) vs Hybrid(128B) vs MlDsa65(64B).
--   Verifier MC-branches on signature_class + key_id and cross-checks the WAL `SignatureClassPolicy` (§14.7 E13).

-- m2 unknown variant staging — replaces forward-version silent-skip with explicit staging.
CREATE TABLE unknown_variants (
    staging_id     BIGSERIAL PRIMARY KEY,
    wal_seq        BIGINT NOT NULL,
    type_code      BIGINT NOT NULL,
    variant_index  SMALLINT NOT NULL,
    raw_bytes      BYTEA NOT NULL,
    staged_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    replayed       BOOLEAN NOT NULL DEFAULT FALSE
);
-- On manifest update (Runtime/shell semver bump), `runtime-doctor replay-unknown-variants`
-- replays staged records with the new variant interpretation → projection.

-- S5 / veteran N3 doctor audit
-- BLAKE3 chain hash domain `arkhe-runtime-doctor-journal-chain` (§14.7 m4 / §3.2 / impl `arkhe-forge-platform/src/hf2_kms/journal.rs::JOURNAL_CHAIN_DOMAIN`).
CREATE TABLE runtime_doctor_journal (
    journal_id       BIGSERIAL PRIMARY KEY,
    operator_pubkey  BYTEA NOT NULL,
    ed25519_sig      BYTEA NOT NULL,
    command          TEXT NOT NULL,
    reason           TEXT NOT NULL,
    before_digest    BYTEA NOT NULL,
    after_digest     BYTEA,
    executed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- append-only (trigger / partition / revoke UPDATE,DELETE)
```

**Prometheus / OpenTelemetry metrics** (M-slo / P2 / P3 + R5 veteran m-R5-2):

Runtime default export = **OpenTelemetry v1.30+ (2025)**. Prometheus scrape is kept compatible via OTel Collector passthrough. R5.1 recommendation: **OpenTelemetry v2** (2026+) — exemplar trace correlation + native histogram support, switch as soon as the SDK is ready.

- `arkhe_runtime_projection_lag_seconds{shell_id="..."}` gauge.
- `arkhe_runtime_action_duration_seconds` histogram.
- `arkhe_runtime_observer_restart_total{shell_id="..."}` counter.
- `arkhe_runtime_hook_timeout_total{shell_id="..."}` counter.
- `arkhe_runtime_gdpr_cascade_remaining_ops{user_id="..."}` gauge.
- `arkhe_runtime_component_read_cache_hit_ratio` gauge (P2).
- `arkhe_runtime_gdpr_cache_hit_ratio{shell_id="..."}` gauge (P3).
- `arkhe_runtime_wal_growth_bytes_per_sec{shell_id="..."}` gauge (P1 extra_bytes monitoring).
- `arkhe_runtime_idempotency_duplicate_total{shell_id="..."}` counter (C6).
- `arkhe_runtime_rate_limit_reject_total{axis, shell_id}` counter (R5 veteran m-R5-2, §5.2.1).
- `arkhe_runtime_dek_message_count{user_id}` gauge (R5 FG1, DEK rotation trigger 2^30 warn / 2^32 force).
- `arkhe_runtime_software_kek_alpha_mode` gauge (R5 FG5a — 0/1 permanent warning tag).
- `arkhe_runtime_hsm_unavailable_total{region}` counter (R5 FG2 degraded-mode trigger).
- `arkhe_runtime_event_total{event_type, shell_id}` counter (R5.3 m-R7-1, tracks core Event emit). Grafana dashboard template: see §15.5 v0.13 nice-to-have.
- `arkhe_runtime_kms_health_channels{channel, region}` gauge (R5.3 HF2 — mandatory parallel health checks via DNS-over-HTTPS / alternate region path).

**SLO**: projection_lag_seconds p99 < 30s. Violation → PagerDuty.

#### §12.4.1 SLO / alert policy table (R5.2 M-R6-1)

Per-metric threshold / severity / action / runbook — operators can copy directly into alerting rules:

| Metric | Threshold | Severity | Action | Runbook |
|---|---|---|---|---|
| `arkhe_runtime_projection_lag_seconds` | p99 > 30s for 5min | **High** | PagerDuty page | `docs/runbook/projection-lag.md` |
| `arkhe_runtime_projection_lag_seconds` | p99 > 120s for 10min | **Critical** | PagerDuty + on-call escalation | `docs/runbook/projection-lag.md` |
| `arkhe_runtime_action_duration_seconds` | p99 > 10ms for 15min | Warning | Slack `#runtime-ops` | — |
| `arkhe_runtime_observer_restart_total` | rate > 3/hour | **High** | PagerDuty page | `docs/runbook/observer-restart.md` |
| `arkhe_runtime_hook_timeout_total` | any increase (should be v1 OFF) | **High** | Urgent investigation (hook active is not allowed) | — |
| `arkhe_runtime_gdpr_cascade_remaining_ops` | > 1000 for 48h | Warning | Operator review + SLA check | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_gdpr_cascade_remaining_ops` | > 0 for 72h | **High** | Prepare regulator notification | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_component_read_cache_hit_ratio` | < 0.7 for 30min | Warning | Review cache sizing | — |
| `arkhe_runtime_gdpr_cache_hit_ratio` | < 0.8 for 30min | Warning | Review §14.9 tick cache | — |
| `arkhe_runtime_wal_growth_bytes_per_sec` | > 10MB/s for 15min | Warning | Check for shell extra_bytes abuse | — |
| `arkhe_runtime_idempotency_duplicate_total` | rate > 5/s for 10min | Warning | Check for L4 retry storm | — |
| `arkhe_runtime_idempotency_wal_scan_ms` | p99 > 5ms for 15min | Warning | Review §14.8 FG6 scan N tick reduction | — |
| `arkhe_runtime_rate_limit_reject_total` | rate > 100/s for 15min | Warning | Attack / legitimate burst analysis | — |
| `arkhe_runtime_dek_message_count` | value > 2^30 (warn) | Warning | Prepare §14.9.1 DEK rotation | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_dek_message_count` | forced rotation fails before reaching 2^32 | **Critical** | PagerDuty + write block | `docs/runbook/crypto-erasure.md` |
| `arkhe_runtime_software_kek_alpha_mode` | value == 1 (permanent) | **Info (permanent warning)** | Confirm production deployment is blocked | — |
| `arkhe_runtime_hsm_unavailable_total` | > 0 (any) | **Critical** | PagerDuty + confirm degraded mode | `docs/runbook/hsm-degraded-mode.md` |
| `arkhe_runtime_kms_sync_lag_seconds` | p99 > 60s for 10min | **High** | Review §14.11.2 Multi-KMS sync | `docs/runbook/hsm-degraded-mode.md` |
| `arkhe_runtime_event_total{event_type="GdprPolicyViolation"}` | rate > 5/s for 10min | Warning | Check attack or deployment bug (expected near-zero in normal ops) | `docs/runbook/gdpr-violation.md` (v0.13) |
| `arkhe_runtime_kms_health_channels{channel, region}` | value < 2 (of 3) for 60s | **High** | Multi-channel N-of-M verdict — warns just before HF2 auto_promote trigger | `docs/runbook/hsm-degraded-mode.md` |

**Alertmanager routing recommendation**:
- Severity `Critical` → PagerDuty primary + SMS.
- Severity `High` → PagerDuty secondary.
- Severity `Warning` → Slack / email digest.
- Severity `Info` → dashboard only.

Severity / action combinations are alpha-calibrated. Re-evaluate thresholds at production transition (depending on user scale / tick rate).

### §12.5 Partial replay + observer shell filter

1. L0 `replay_into` re-validates the chain tip.
2. Reset `kernel_projection_state` → re-execute the WAL → reconstruct the projection.
3. **Observer shell_id filter (S7)**: each observer declares `shell_id_filter: BTreeSet<ShellId>`. Events outside the interest set are skipped — blocks cross-shell metadata leak. A cross-shell projection node also registers an explicit multi-shell filter.
4. Unknown TypeCode / variant handling (m2 revisited): **silent-skip retired**. Instead, record explicitly in the `unknown_variants` staging table (§12.4) — after a manifest/Runtime update, `runtime-doctor replay-unknown-variants` re-interprets them. Blocks WAL/projection consistency collapse. On shell removal (shell sunset §14.7), staging is skipped + audit logged.
5. **Replay path per-tick atomic inheritance (R5 NF7)**: the §5.5 contract (tick-level BEGIN/COMMIT) applies identically on replay. Failed-validator records are inserted into the `unknown_variants` staging table + audit log and the tick still COMMITs — no "half-applied tick". During `observer_state='replaying'`, L4 serving is disabled (§14.7 m3).

---

