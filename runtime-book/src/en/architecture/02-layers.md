## §2. Layer system

### §2.1 L0 = Kernel as the baseline

```
┌──────────────────────────────────────────────────────────┐
│  L6  Shell Package                                        │
│      (Manifest + Hooks + Frontends + Migrations bundle)   │
│      e.g. ArkheNet BBS, ArkheCasino, GuildChat            │
├──────────────────────────────────────────────────────────┤
│  L5  Frontend                                             │
│      ANSI Telnet · Web · Mobile · CLI · Bot · IRC         │
├──────────────────────────────────────────────────────────┤
│  L4  Protocol Adapter                                     │
│      WebSocket · HTTP/gRPC · SSH · Telnet session         │
├──────────────────────────────────────────────────────────┤
│  L3  Library (shell-common utilities)                     │
│      Rate limiter · JWT verifier · S3 client · search    │
├──────────────────────────────────────────────────────────┤
│  L2  Runtime Services / Platform    ◄── this DIP scope    │
│      Policy · Quota · Projection · Manifest · Hook host  │
├──────────────────────────────────────────────────────────┤
│  L1  Runtime Primitives             ◄── this DIP scope    │
│      Core 5 traits · TypeCode registry · Action dispatch │
├──────────────────────────────────────────────────────────┤
│  L0  ArkheKernel v0.11                              │
│      WAL · deterministic state · authz · scheduler        │
└──────────────────────────────────────────────────────────┘
```

### §2.2 Per-layer responsibility

| Layer | Responsibility | This DIP |
|---|---|---|
| **L0 Kernel** | Bit-identical replay, single-thread state, `Effect<'i, S>`/`Op`, TypeCode registry, WAL, observer, scheduler. A1-A24 + S1. | Fixed (v0.11) |
| **L1 Runtime Primitives** | Core 5 primitive Rust types, TypeCode allocation, `ActionCompute` pure, dependency DAG, ShellBrand. | R1-R4' design |
| **L2 Runtime Services/Platform** | Policy, Manifest loader, Projection, Hook host (v2 WASI), Rate limit, Audit receipt, cascade scheduler, idempotency dedup. | R1-R4' design |
| L3 Library | shell-common utilities. | Out of scope |
| L4 Protocol Adapter | Session, encoding, idempotency key passthrough. | Out of scope |
| L5 Frontend | I/O rendering. | Out of scope |
| L6 Shell Package | Logical bundle of a single product. | Out of scope |

### §2.3 Dependency direction

- **Strictly downward DAG**: L_n → L_{n-1} or below only. L1 → L2 **forbidden** (cargo CI).
- **L6 Shell is a cross-cutting package** — physically distributed, logically grouped.
- **DO NOT TOUCH propagation**: propagate the L0 `#[arkhe_runtime_forbidden_modifier]` dylint CI gate to L1/L2. In particular, the `WalRecord` postcard field order (DO NOT TOUCH #8) must **never be modified** in the Runtime — §14.7 runtime information uses only the `RuntimeBootstrap` in-band event and the L0 `WalRecord.reserved` field path (sidecar metadata is retired, §14.7 / E12).

### §2.4 L1/L2 separation principle (details in §5)

- L1: semantic-level primitive. Knows nothing about PostgreSQL/HTTP/Manifest. Pure compute.
- L2: policy, projection, ingress. L0 observer, L4 request, manifest/quota validation → kernel submit.

---

