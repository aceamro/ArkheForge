//! Forward-looking event 3-layer 0-emission defense Layer (d) **mechanical proof**.
//!
//! Asserts that production runtime code never references the
//! forward-looking event types `ReplicaIdAllocation` /
//! `AuditReceiptKeyPolicy` outside of their **definition site** and
//! the **TypeCode reservation site** in `arkhe-forge-core`.
//!
//! # Defense layers
//!
//! - **Layer (a)** — `emit_event::<…>` not defined for these types in
//!   any production code path. Verified structurally by absence of
//!   call sites (this scanner).
//! - **Layer (b)** — `#[cfg(feature = "…")]` on type definitions →
//!   default builds skip compiling the types entirely.
//! - **Layer (d)** — workspace scan (this test) catches anyone who
//!   tries to introduce a type reference in a non-allowed location
//!   (e.g., a `Op::EmitEvent { … ReplicaIdAllocation … }` snippet
//!   sneaking into a non-test runtime module).
//!
//! Layers (a) + (b) + (d) together guarantee **zero production
//! emission**, with mechanical evidence at all three layers.
//!
//! # Failure mode
//!
//! If a future PR introduces a production reference to either
//! forward-looking event type outside the two allowed files, this
//! test fails with a punch-list of offending file paths so the
//! reviewer can either:
//!
//! - move the reference into one of the allowed files (if it's part
//!   of the type's own definition / surface), or
//! - cfg-gate the new module behind `federation-archive-hardened` or
//!   `audit-receipt-key-identified` and update [`ALLOWED_FILES`] to
//!   include it (with a peer-review approval recorded in the test
//!   commit message).
//!
//! # Why this scanner lives here
//!
//! `arkhe-trait-default-check` already ships as the workspace's MC
//! structural-invariant `syn` scaffolding. The "do one thing well"
//! framing reads workspace-wide structural invariant scan as a single
//! dimension covering trait-default-body fingerprint (E14.L1),
//! Action-compute coverage (E14.L1 lint trip), and forward-looking
//! 0-emission Layer (d).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// Workspace runtime crates scanned for forward-looking event type
/// references. Adding a new Runtime-layer crate requires updating
/// this list (and confirming the new crate cannot legitimately
/// reference the forward-looking types in production).
const RUNTIME_CRATES: &[&str] = &["arkhe-forge-core", "arkhe-forge-platform", "arkhe-forge"];

/// Files where the forward-looking event types may legitimately
/// appear. Exhaustive list — anything outside trips the Layer (d)
/// scanner.
///
/// - `arkhe-forge-core/src/event.rs` — type definitions + tests.
/// - `arkhe-forge-core/src/typecode.rs` — TypeCode reservation
///   constants + reservation tests (constants reference the type
///   names in rustdoc comments).
const ALLOWED_FILES: &[&str] = &[
    "arkhe-forge-core/src/event.rs",
    "arkhe-forge-core/src/typecode.rs",
];

/// Type names the scanner forbids in non-allowed files. Any literal
/// occurrence in a non-allowed runtime crate source file trips the
/// scanner. Substring match is intentional — we want to catch
/// `ReplicaIdAllocation::TYPE_CODE`, `&ReplicaIdAllocation { … }`,
/// `<ReplicaIdAllocation>`, and `// …ReplicaIdAllocation…` rustdoc
/// references all the same.
const FORBIDDEN_TYPES: &[&str] = &["ReplicaIdAllocation", "AuditReceiptKeyPolicy"];

#[test]
fn forward_looking_events_have_zero_production_emit_sites() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let mut scanned = 0usize;

    for crate_dir in RUNTIME_CRATES {
        let src = root.join(crate_dir).join("src");
        if !src.exists() {
            continue;
        }
        scan_dir(&src, &root, &mut violations, &mut scanned);
    }

    assert!(
        scanned > 0,
        "scanner did not encounter any source file — workspace layout assumption broken"
    );
    assert!(
        violations.is_empty(),
        "Layer (d) — forward-looking event types referenced outside the \
         allowed two files (event.rs + typecode.rs):\n  {}",
        violations.join("\n  ")
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn scan_dir(dir: &Path, root: &Path, violations: &mut Vec<String>, scanned: &mut usize) {
    let entries = std::fs::read_dir(dir).expect("read_dir");
    for entry in entries {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, root, violations, scanned);
        } else if path.extension().is_some_and(|e| e == "rs") {
            *scanned += 1;
            scan_file(&path, root, violations);
        }
    }
}

fn scan_file(path: &Path, root: &Path, violations: &mut Vec<String>) {
    // Compute the relative path against the workspace root so the
    // ALLOWED_FILES check is portable.
    let rel = path.strip_prefix(root).unwrap_or(path);
    let rel_str = rel.to_string_lossy();

    // Allowed files may legitimately reference the forbidden names.
    if ALLOWED_FILES.iter().any(|allowed| rel_str == *allowed) {
        return;
    }

    // Fail loudly on an unreadable file — a silent skip would let a
    // forbidden reference hide behind a permissions/encoding error.
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("zero-emission scan cannot read {rel_str}: {e}"));

    for ty in FORBIDDEN_TYPES {
        if let Some(line_no) = src.lines().position(|l| l.contains(ty)) {
            violations.push(format!(
                "{rel_str}:{}: contains forbidden reference to `{ty}`",
                line_no + 1
            ));
        }
    }
}
