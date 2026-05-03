## §6. Activity generalization design

### §6.1 verb = TypeCode

A naive `enum Verb` is rejected (Open-Closed violation). Adopted: `VerbCode(TypeCode)` + const generic range partitioning. Type-erased `VerbCode` for storage.

### §6.2 verb range (M-verbrange final)

- Canonical: `0x0002_0001..=0x0002_03FF` (1023). 8 currently in use.
- Shell: `0x0002_0400..=0x0002_FFFF` (64,512). Deterministic BLAKE3-derived 256-verb sub-range per shell.
- Central registry `runtime-typecode-allocations.toml` (distributed with the Runtime crate).
- A change to the `extra_bytes` format obligates a new VerbCode allocation (M-schemaver-verb). Existing VerbCodes are schema_hash-pinned.

### §6.3 Reaction / Subscription / Follow / Report unification

| Original concept | Activity representation | Rationale |
|---|---|---|
| Reaction | verb=Like/... target=Entry | storage/query identical |
| Subscription | verb=Follow target=Actor/Space/Activity | WAL pattern identical |
| Follow | verb=Follow target=Actor | — |
| Report | verb=Report extra_bytes=reason_hash | workflow = verb + appeal chain |
| Bookmark | verb=Bookmark private | — |
| Mute/Block | verb=Mute/Block actor scope | — |
| Appeal | verb=Report target=Activity meta-verb | depth ≤ manifest (E9) |

### §6.4 Mapping to engine.md 13-primitives (X3 DM correction)

| engine.md primitive | R4' decision |
|---|---|
| Identity (User) | Core 5 #1 |
| Actor | Core 5 #2 |
| Space | Core 5 #3 |
| Entry | Core 5 #4 |
| Reaction / Subscription / Follow / Report | Activity verb |
| Relay | Entry variant (relay_of) |
| DirectMessage | `Space(kind=Flat, visibility=PrivateInvite, creator=sender) + SpaceMembership{members: {sender, recipient}} + Entry`. Primitive promotion only after 3-shell empirical evidence. |
| Room | **Separate primitive (follow-up DIP)** — §8.1 / §14.1 |
| Attachment/Media | Axis 1 Component — §8.2 |
| Playback | Activity verb(PlaybackCheckpoint) + scale issue deferred to R5 |
| Collection | Space.kind=Collection + Activity(Pin) |
| Moderation | Activity(Report) + meta-verb appeal + L2 ModerationAction |
| Gateway | Outside the Runtime — L4 proxy |
| AuditReceipt | L2 service (`RuntimeSignatureClass` §14.7) |

### §6.5 Mutex / visibility / notify / cooldown

Shell manifest `[activity.*]` (§5.6). L2 policy validation then kernel submit. The kernel sees only `SubmitActivity`.

---

