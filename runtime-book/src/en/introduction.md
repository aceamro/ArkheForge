# ArkheForge Runtime — Introduction

**ArkheForge Runtime** is the **L1 Primitives + L2 Services/Platform** layer that sits on top of [ArkheKernel](https://github.com/aceamro/ArkheKernel) v0.11.

## Relationship to the L0 Kernel

Mapped onto a Linux analogy:

| Linux world | ArkheKernel / ArkheForge |
|---|---|
| Linux kernel | **ArkheKernel** (L0, standalone crate) |
| glibc + systemd + D-Bus | **ArkheForge Runtime** (L1+L2, this book) |
| Debian / RedHat distribution | Shell Package (L6, separate project) |

**The L0 kernel is usable on its own without the Runtime**. Users who only need the kernel can use the [`arkhe-kernel`](../book/) crate directly. The Runtime is an optional upper layer that promises to absorb only **empirically demonstrated duplication**.

## Identity

> "ArkheForge Runtime is a reuse substrate that absorbs **only empirically demonstrated duplication** across shells. Features that only one shell needs stay outside the Runtime, at the shell level. Speculative generalization is the path that failed Rails/Meteor."

## Core features

- **Core 5 primitives** — User / Actor / Space / Entry / Activity (ActivityPub hybrid).
- **Four extension axes** — Component / TypeCode / Subtype / New-Primitive gate.
- **Determinism 3-band** — Band 1 Core (L0 bit-identical) / Band 2 Projection (eventually consistent) / Band 3 Protocol-Correctness (shell level).
- **Multi-shell isolation** — compile-time shell boundaries via `ShellBrand<'s>` invariant variance.
- **Determinism inheritance** — fully inherits L0 A1-A24 + S1, plus the Runtime's own E1-E13 axioms.

## Structure of this book

`architecture/runtime-spec.md` is the canonical design document.

## Official documentation layout

- `book/` — ArkheKernel L0 kernel official documentation (independent)
- **`runtime-book/`** (this document) — Runtime L1+L2 design specification
- `docs/` — Runtime implementation plan / policy / schedule
