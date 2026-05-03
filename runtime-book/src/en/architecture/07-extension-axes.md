## §7. Four extension axes

### §7.1 Axis 1 — Component

`#[derive(ArkheComponent)]` + shell-scoped TypeCode (manifest `[typecode_allocation.component_range]`). Inherits: A1, A11, A15, A17.

### §7.2 Axis 2 — TypeCode (verb / event / action)

`ArkheAction` / `ArkheEvent` derive over a shell-scoped range. A verb uses `ShellVerb<const C>` const assertion. A change to the extra_bytes format requires a new VerbCode. Inherits: A9, A11, A15, A17.

### §7.3 Axis 3 — Subtype

Variants of the `Extension { type_code: TypeCode, ... }` enum inside a primitive. Manifest load precedes use + A15 pin. Semantic validation is L2's responsibility. Runtime invariants default to safe.

### §7.4 Axis 4 — New-Primitive gate

One of 4 gates + evidence from 2+ shells:

| Gate | Question |
|---|---|
| (a) Lifecycle | Is the existing primitive lifecycle insufficient? |
| (b) Auth model | Is the existing Principal/Capability insufficient? |
| (c) Scale/query | Table explosion in the existing model? |
| (d) WAL policy | Fundamentally different recording policy? |

Procedure: RFC → Runtime semver bump → DIP R1-R4' → clean rounds → core addition.

**R4' currently adds none**. See §8 analysis.

### §7.5 Extension axis selection flowchart

```
 New feature request
       │
       ▼
 Existing primitive Component field? ──────── YES ─▶ Axis 1
       │ NO
       ▼
 Existing primitive extra_bytes + L2 hook? ── YES ─▶ Axis 2 (schema pin)
       │ NO
       ▼
 New verb/event/action type? ──────────────── YES ─▶ Axis 2
       │ NO
       ▼
 Extension variant of a primitive enum? ───── YES ─▶ Axis 3
       │ NO
       ▼
 4-gate + 2+ shell evidence? ──────────────── YES ─▶ Axis 4 RFC
       │ NO
       ▼
 Reject from Runtime core — shell-level
```

### §7.6 Anti-patterns

- "Might be useful in the future" — gate not met, rejected.
- "One shell wants it" — fails the 2+ shell rule, rejected.
- "Cannot attach a field to an existing primitive" — Axis 1 not considered, rejected.

---

