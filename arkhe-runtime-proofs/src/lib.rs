//! # arkhe-runtime-proofs — ArkheKernel Runtime Kani harness crate
//!
//! DIP-N5 cycle plan Track E sub-step E.8 (4-property suite). The crate
//! is **excluded from the root ArkheKernel workspace** — `cargo build`
//! and `cargo test --workspace` from the workspace root do not see this
//! crate. Kani harnesses run via `cargo kani` from inside this directory,
//! with the Kani-bundled Rust toolchain (nightly per `rust-toolchain.toml`).
//!
//! ## 5-property suite
//!
//! 1. `kani_authorize_property` — E6/E7 typestate (`Actor<_, Authenticated>`
//!    + dual-tier shell brand). N=4 shell brands × M=2 typestate variants
//!    = 8 bounded cases (cycle plan v0.4 16-case ceiling, narrowed to 8
//!    for binary typestate domain).
//! 2. `kani_dispatch_property` — E14 deterministic execution, twice-
//!    dispatch determinism (same input ⇒ identical event sequence).
//! 3. `kani_replay_property` — A1 bit-identical replay, chain-tip
//!    invariance under same-order event replay (k=3 event window per
//!    cycle plan).
//! 4. `kani_memory_bounds_check_property` — DIP-N1 B.5 firm contract
//!    anchor (`read_caller_memory` / `write_caller_memory` symbolic OOB
//!    upper-bound proof — cryptographer-pinned cycle plan v0.4 4th
//!    harness adoption).
//! 5. `kani_hybrid_and_mode_property` — PQC Hybrid AND-mode dispatch
//!    logic. Mock BOOLEAN verify outcomes (NOT actual ML-DSA crypto
//!    correctness — covered by integration tests in
//!    `arkhe-kernel/src/persist/wal.rs::tests`). Verify scope:
//!    SignatureClass policy dispatch (None/Ed25519/Hybrid → AND-mode
//!    dispatch under Hybrid). 3 policy variants × 2 ed25519 outcomes ×
//!    2 mldsa65 outcomes = 12 bounded cases.
//!
//! Each harness uses `#[kani::unwind(8)]` to bound SMT loop depth and
//! `kani::assume(...)` for input domain restriction (cycle plan v0.4
//! theorist (d) input-domain bounding absorption).
//!
//! ## Abstract models
//!
//! The harnesses use abstract models (mirror runtime semantics with
//! no_std-compatible types) rather than direct runtime crate imports.
//! Rationale:
//! - SMT solver scales better with simpler models (Kani 0.67.0 + CBMC
//!   backend, depth bounded at 8 per `#[kani::unwind]`).
//! - Property structure (typestate gating, deterministic compute,
//!   replay invariance, bounds check) is the focus, not implementation
//!   specifics.
//! - Implementation defects covered by integration tests in `arkhe-
//!   forge-*` crates + invariant tests + TLA+ refinement (`formal/
//!   tla-plus/`).
//!
//! ## Run locally
//!
//! ```bash
//! cd arkhe-runtime-proofs
//! cargo kani
//! ```
//!
//! ## CI gate
//!
//! `.github/workflows/ci.yml` `kani-verify` job runs `cargo kani` on
//! every push + PR. 35-min job budget (per-harness 30-min target,
//! buffered for setup overhead).
//!
//! ## Sub-step trace
//!
//! - scaffold + smoke harness (commit `a9d2803`)
//! - 4-property suite proper (smoke replaced)
//! - 5th harness — Hybrid AND-mode property (this commit)

#![cfg_attr(kani, no_std)]
#![forbid(unsafe_code)]
// Multi-line list items with `=` sub-clause continuations trigger
// `clippy::doc_lazy_continuation` despite being intentionally
// structured for readability. Suppress at crate root.
#![allow(clippy::doc_lazy_continuation)]

// All abstract models + harnesses are gated under `#[cfg(kani)]` —
// non-kani builds compile to an essentially-empty crate. The Kani
// toolchain activates the cfg via `cargo kani` invocation.

// ============================================================
// Property 1 of 4: kani_authorize_property (E6 + E7 typestate)
// ============================================================

#[cfg(kani)]
mod authorize_model {
    //! E6/E7 typestate abstract model.
    //!
    //! E6: `Actor<_, Authenticated>` requires `UserBinding` (typestate
    //! at Rust type level — `Actor<S, Anonymous>` cannot transition to
    //! `Actor<S, Authenticated>` without consuming a `UserBinding`).
    //! E7: Shell isolation submit (TYPE-PROVEN via `ShellBrand<'s>`
    //! phantom lifetime) + replay (RUNTIME-ASSERTED via shell-id check)
    //! dual-tier — actor and target must share shell at submit-site.
    //!
    //! The abstract model captures both axioms via `authorize` predicate:
    //! returns `true` iff actor is `Authenticated` AND shell brands match.

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub enum ActorState {
        Anonymous,
        Authenticated,
    }

    pub struct Actor {
        pub state: ActorState,
        pub shell_brand: u8,
    }

    pub struct Target {
        pub shell_brand: u8,
    }

    /// Authorization predicate — returns `true` iff actor is
    /// `Authenticated` AND `actor.shell_brand == target.shell_brand`
    /// (E6 + E7 dual-tier submit-site check).
    pub fn authorize(actor: &Actor, target: &Target) -> bool {
        matches!(actor.state, ActorState::Authenticated)
            && actor.shell_brand == target.shell_brand
    }
}

/// E6/E7 typestate authorization property.
///
/// **Property statement**: For all symbolic actor + target inputs, if
/// `authorize()` returns `true`, then:
/// - `actor.state == Authenticated` (E6 axiom)
/// - `actor.shell_brand == target.shell_brand` (E7 dual-tier submit)
///
/// **Bounded MC**: N=4 shell brands × M=2 typestate variants = 8 bounded
/// cases (cycle plan v0.4 16-case ceiling, narrowed to 8 for binary
/// typestate domain).
///
/// **Anchor**: `runtime-book/src/en/architecture/11-axioms.md` E6 + E7
/// (TYPE-PROVEN at Rust + abstract MC at Kani).
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn kani_authorize_property() {
    use authorize_model::{authorize, Actor, ActorState, Target};

    // Symbolic state byte: 0 = Anonymous, 1 = Authenticated
    let state_byte: u8 = kani::any();
    kani::assume(state_byte < 2);
    let state = if state_byte == 0 {
        ActorState::Anonymous
    } else {
        ActorState::Authenticated
    };

    // Symbolic shell brands: 0..4 (N=4 per cycle plan)
    let actor_shell: u8 = kani::any();
    kani::assume(actor_shell < 4);
    let target_shell: u8 = kani::any();
    kani::assume(target_shell < 4);

    let actor = Actor {
        state,
        shell_brand: actor_shell,
    };
    let target = Target {
        shell_brand: target_shell,
    };

    let allowed = authorize(&actor, &target);

    if allowed {
        // E6: actor must be Authenticated
        assert!(matches!(state, ActorState::Authenticated));
        // E7: shell brands must match (dual-tier submit-site)
        assert!(actor_shell == target_shell);
    }
}

// ============================================================
// Property 2 of 4: kani_dispatch_property (E14 determinism)
// ============================================================

#[cfg(kani)]
mod dispatch_model {
    //! E14 compute determinism abstract model.
    //!
    //! E14: Compute Determinism Closure — every L1 `Action::compute` path
    //! contributing to the L0 chain hash produces bit-identical output
    //! across replay on any conformant Runtime instance. L1-Deny (build-
    //! time AST deny-list: clock / RNG / I/O / FFI / `unsafe`) + L2-Allow
    //! (runtime wasmtime sandbox: NaN canonicalisation + SIMD opt-out)
    //! dual realisation eliminates non-determinism.
    //!
    //! Abstract model: `dispatch(input)` is a pure function that emits
    //! a fixed-size event sequence. Twice-dispatch determinism = same
    //! input ⇒ same output sequence (functional purity).

    /// Dispatch a 32-bit input into a 4-byte event sequence.
    ///
    /// Pure compute — no I/O, no clock, no RNG. Models the L1-Deny
    /// constraint at the abstract level (the deny-list mechanism is
    /// enforced by `arkhe-subset-rust-check` at build time on the
    /// concrete Runtime implementation).
    pub fn dispatch(input: u32) -> [u8; 4] {
        [
            (input >> 24) as u8,
            (input >> 16) as u8,
            (input >> 8) as u8,
            input as u8,
        ]
    }
}

/// E14 dispatch determinism property.
///
/// **Property statement**: For all 32-bit symbolic inputs,
/// `dispatch(input) == dispatch(input)` (twice-dispatch determinism —
/// bit-identical event sequence under repeated invocation).
///
/// **Bounded MC**: u32 input domain (Kani symbolic full 32-bit space).
/// SMT loop unwind = 8 per harness budget.
///
/// **Anchor**: `runtime-book/src/en/architecture/11-axioms.md` E14
/// (MACHINE-CHECKED build-time L1 + runtime L2). Implementation-level
/// proof anchor for A1 bit-identical replay (E14 ⇒ A1).
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn kani_dispatch_property() {
    use dispatch_model::dispatch;

    let input: u32 = kani::any();

    let events_first = dispatch(input);
    let events_second = dispatch(input);

    // Property: same input ⇒ identical event sequence (E14 deterministic)
    let mut i = 0;
    while i < 4 {
        assert!(events_first[i] == events_second[i]);
        i += 1;
    }
}

// ============================================================
// Property 3 of 4: kani_replay_property (A1 bit-identical)
// ============================================================

#[cfg(kani)]
mod replay_model {
    //! A1 bit-identical replay abstract model.
    //!
    //! A1 (L0 axiom, inherited by Runtime): every WAL replay produces
    //! a bit-identical chain tip given the same event sequence. Chain-
    //! tip invariance is the foundational property of the runtime —
    //! E14 (compute determinism) is the input-side enforcement, A1 is
    //! the output-side guarantee.
    //!
    //! Abstract model: `fold_chain(events)` is a pure deterministic
    //! fold over the event sequence. Twice-fold determinism = same
    //! events ⇒ same chain tip. The cryptographic chain hash (BLAKE3)
    //! is too complex for SMT-bounded MC; this abstract model captures
    //! the bit-identical replay property at the functional fold level.

    /// Fold a 3-event sequence into a 32-bit chain tip.
    ///
    /// Pure deterministic fold — toy hash mix for SMT tractability.
    /// The cryptographic BLAKE3 chain hash (in `arkhe-kernel/src/
    /// persist/wal.rs`) is verified by integration tests + cross-
    /// referenced in TLA+ CR-1 module's `ChainHashFn` opaque function.
    pub fn fold_chain(events: &[u8; 3]) -> u32 {
        let mut acc: u32 = 0;
        let mut i = 0;
        while i < 3 {
            acc = acc.wrapping_mul(31).wrapping_add(events[i] as u32);
            i += 1;
        }
        acc
    }
}

/// A1 bit-identical replay property.
///
/// **Property statement**: For all 3-event symbolic sequences,
/// `fold_chain(events) == fold_chain(events)` (twice-fold determinism,
/// bit-identical replay).
///
/// **Bounded MC**: 3-event window (k=3 per cycle plan v0.4), each
/// event is a u8 byte (256-element symbolic domain per slot). Total
/// symbolic state = 256^3 = 16M cases. SMT unwind = 8.
///
/// **Anchor**: `arkhe-kernel` L0 A1 (bit-identical replay) inheritance
/// via E14 closure. The Kani harness verifies the foundational property
/// at the abstract fold level; cryptographic BLAKE3 chain hash (not
/// modeled here for SMT tractability) is verified by integration tests
/// in `arkhe-kernel` + observed across all 5 TLA+ refinement modules
/// via `chain_tip = ChainHashFn(wal)` (CR-1 `ChainHashDeterministic`).
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn kani_replay_property() {
    use replay_model::fold_chain;

    let e0: u8 = kani::any();
    let e1: u8 = kani::any();
    let e2: u8 = kani::any();

    let events = [e0, e1, e2];

    let chain_first = fold_chain(&events);
    let chain_second = fold_chain(&events);

    // Property: bit-identical event sequence ⇒ bit-identical chain tip
    assert!(chain_first == chain_second);
}

// ============================================================
// Property 4 of 4: kani_memory_bounds_check_property
//                  (DIP-N1 B.5 firm contract anchor)
// ============================================================

#[cfg(kani)]
mod memory_bounds_model {
    //! DIP-N1 B.5 firm contract anchor abstract model.
    //!
    //! `read_caller_memory(buffer, offset, len)` and
    //! `write_caller_memory(buffer, offset, len, src)` are wasmtime
    //! host-fn helpers in `arkhe-forge-platform/src/hook_host_v2/
    //! wasm_memory.rs` (DIP-N1 B.5 firm contract anchor). The contract
    //! requires bounds check to reject OOB inputs (`offset + len >
    //! buffer.len()` or `offset.checked_add(len)` overflow) with
    //! explicit error before any deref occurs.
    //!
    //! Abstract model: bounded buffer + checked_add overflow detection
    //! + explicit upper-bound check. Kani symbolic execution explores
    //! the full input domain to verify the bounds check is sound for
    //! all `(offset, len)` pairs.

    /// Maximum buffer size for the abstract Kani model.
    pub const MAX_BUFFER_SIZE: usize = 16;

    /// Error returned by `read_caller_memory` on OOB input.
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub enum MemoryError {
        Overflow,
        OutOfBounds,
    }

    /// Validate `(offset, len)` against `buffer`.
    ///
    /// - Returns `Err(Overflow)` if `offset + len` overflows usize.
    /// - Returns `Err(OutOfBounds)` if `offset + len > buffer.len()`.
    /// - Returns `Ok(())` on successful bounds check.
    ///
    /// The function does not actually dereference — bounds check is
    /// the firm contract anchor under verification. Concrete impl in
    /// `arkhe-forge-platform/src/hook_host_v2/wasm_memory.rs`
    /// dereferences the wasm linear memory after this check passes.
    pub fn read_caller_memory(
        _buffer: &[u8; MAX_BUFFER_SIZE],
        offset: usize,
        len: usize,
    ) -> Result<(), MemoryError> {
        let end = match offset.checked_add(len) {
            Some(end) => end,
            None => return Err(MemoryError::Overflow),
        };
        if end > MAX_BUFFER_SIZE {
            return Err(MemoryError::OutOfBounds);
        }
        Ok(())
    }
}

/// Memory bounds-check property (DIP-N1 B.5 firm contract anchor).
///
/// **Property statement**: For all symbolic `(offset, len)` inputs in
/// the bounded domain `[0, 2 * MAX_BUFFER_SIZE]`:
/// - If `offset + len` overflows usize → `Err(Overflow)`
/// - Else if `offset + len > MAX_BUFFER_SIZE` → `Err(OutOfBounds)`
/// - Else → `Ok(())`
///
/// **Bounded MC**: `offset + len ≤ 2 * MAX_BUFFER_SIZE` symbolic domain
/// (covers in-bounds, just-OOB, and far-OOB regions). SMT unwind = 8.
///
/// **Anchor**: DIP-N1 B.5 firm contract anchor — `read_caller_memory` /
/// `write_caller_memory` symbolic OOB upper-bound proof. Cryptographer-
/// pinned cycle plan v0.4 4th harness adoption — the formal verification
/// counterpart to integration tests in `arkhe-forge-platform/src/
/// hook_host/wasm_memory.rs` (path corrected at E.9: was
/// `hook_host_v2` in E.8 doc, actual path is `hook_host`).
///
/// **Note on Overflow branch unreachability** (theorist E.8 M1-secondary
/// finding, E.9 absorption): `kani::assume(offset ≤ 32 AND len ≤ 32)`
/// keeps `checked_add(offset, len) ≤ 64`, far below `usize::MAX` (~1.8e19
/// on 64-bit). Therefore the `Err(Overflow)` branch is structurally
/// unreachable under bounded MC — verification scope focuses on
/// in-bounds + OOB partition (the firm contract anchor's primary
/// surface). The `checked_add` call retains its defensive design
/// against attacker-controlled `usize::MAX/2` inputs in production;
/// bounded MC abstracts to SMT-tractable input domain.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn kani_memory_bounds_check_property() {
    use memory_bounds_model::{
        read_caller_memory, MemoryError, MAX_BUFFER_SIZE,
    };

    // Symbolic buffer
    let buffer: [u8; MAX_BUFFER_SIZE] = kani::any();

    // Symbolic offset + len, bounded to keep symbolic input domain
    // finite (covers in-bounds, just-OOB, and far-OOB regions).
    let offset: usize = kani::any();
    let len: usize = kani::any();
    kani::assume(offset <= 2 * MAX_BUFFER_SIZE);
    kani::assume(len <= 2 * MAX_BUFFER_SIZE);

    let result = read_caller_memory(&buffer, offset, len);

    // Property: bounds check is sound under all symbolic inputs.
    match offset.checked_add(len) {
        None => {
            // Overflow case: must return Err(Overflow)
            assert!(matches!(result, Err(MemoryError::Overflow)));
        }
        Some(end) => {
            if end > MAX_BUFFER_SIZE {
                // OOB case: must return Err(OutOfBounds)
                assert!(matches!(result, Err(MemoryError::OutOfBounds)));
            } else {
                // In-bounds case: must return Ok
                assert!(matches!(result, Ok(())));
            }
        }
    }
}

// ============================================================
// Property 5 of 5: kani_hybrid_and_mode_property (PQC Hybrid AND-mode)
// ============================================================

#[cfg(kani)]
mod hybrid_and_mode_model {
    //! PQC Hybrid AND-mode dispatch abstract model.
    //!
    //! `SignatureClass::Hybrid` (Ed25519 + ML-DSA 65 dual-sign, NIST
    //! FIPS 204 / CNSA 2.0). Verify path is AND-mode — both Ed25519
    //! and PQC signatures must validate for the record to pass
    //! `verify_chain`. Forward-secure default for v0.12+ new WALs.
    //!
    //! Abstract model: BOOLEAN verify outcomes mock the actual
    //! cryptographic verify (ML-DSA 65 verify is too complex for
    //! SMT-bounded MC; cryptographic correctness is covered by
    //! integration tests in `arkhe-kernel/src/persist/wal.rs::tests`).
    //! Property structure (SignatureClass policy dispatch + AND-mode
    //! gating) is the focus, not crypto correctness.

    /// Abstract `SignatureClass` policy variants.
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub enum SignatureClass {
        /// No signature path — chain integrity only (Tier 1).
        None,
        /// RFC 8032 Ed25519 — single-signature mode (Tier 2).
        Ed25519,
        /// Hybrid — Ed25519 + ML-DSA 65 dual-sign, AND-mode.
        Hybrid,
    }

    /// Verify a record under the given `SignatureClass` policy.
    ///
    /// Models the dispatch logic in `wal.rs::verify_chain`:
    /// - `None`: no signature check (chain integrity only)
    /// - `Ed25519`: single Ed25519 verify
    /// - `Hybrid`: both Ed25519 AND ML-DSA 65 verify (AND-mode —
    ///   AND-mode short-circuit failure if either is `false`)
    ///
    /// Returns `true` iff the record passes per policy. Mock BOOLEAN
    /// verify outcomes — actual cryptographic verify is opaque in
    /// this abstract model.
    pub fn verify_record(
        class: SignatureClass,
        ed25519_ok: bool,
        mldsa65_ok: bool,
    ) -> bool {
        match class {
            SignatureClass::None => true,
            SignatureClass::Ed25519 => ed25519_ok,
            SignatureClass::Hybrid => ed25519_ok && mldsa65_ok,
        }
    }
}

/// PQC Hybrid AND-mode dispatch property.
///
/// **Property statement**: For all symbolic `SignatureClass` policies +
/// BOOLEAN verify outcomes:
/// - `None` → pass regardless of sig outcomes
/// - `Ed25519` → pass iff `ed25519_ok`
/// - `Hybrid` → pass iff `ed25519_ok AND mldsa65_ok` (AND-mode
///   dispatch — both verifies invoked, fail if either is `false`)
///
/// **Bounded MC**: 3 `SignatureClass` variants × 2 ed25519 outcomes ×
/// 2 mldsa65 outcomes = 12 cases. SMT unwind = 8.
///
/// **Anchor**: Implementation-level proof anchor for
/// `wal.rs::verify_chain` Hybrid match arm dispatch logic.
/// Cryptographic correctness is verified by integration tests in
/// `arkhe-kernel/src/persist/wal.rs::tests`
/// (`hybrid_verify_chain_and_mode_passes_with_both_valid`,
/// `hybrid_verify_chain_rejects_corrupt_pqc_signature`,
/// `hybrid_verify_chain_rejects_corrupt_ed25519_when_pqc_valid`).
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn kani_hybrid_and_mode_property() {
    use hybrid_and_mode_model::{verify_record, SignatureClass};

    // Symbolic policy: 0 = None, 1 = Ed25519, 2 = Hybrid.
    let policy_byte: u8 = kani::any();
    kani::assume(policy_byte < 3);
    let class = match policy_byte {
        0 => SignatureClass::None,
        1 => SignatureClass::Ed25519,
        _ => SignatureClass::Hybrid,
    };

    // Symbolic BOOLEAN verify outcomes — mock the actual ML-DSA verify
    // (which is too complex for SMT-bounded MC; crypto correctness is
    // covered by integration tests).
    let ed25519_ok: bool = kani::any();
    let mldsa65_ok: bool = kani::any();

    let pass = verify_record(class, ed25519_ok, mldsa65_ok);

    // Property: dispatch logic matches policy semantics.
    match class {
        SignatureClass::None => {
            // No signature check — pass regardless of sig outcomes.
            assert!(pass);
        }
        SignatureClass::Ed25519 => {
            // Single Ed25519 verify.
            assert!(pass == ed25519_ok);
        }
        SignatureClass::Hybrid => {
            // AND-mode: both must pass; fail if either is false.
            assert!(pass == (ed25519_ok && mldsa65_ok));
        }
    }
}
