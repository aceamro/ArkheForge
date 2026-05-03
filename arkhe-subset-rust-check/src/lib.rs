//! # arkhe-subset-rust-check — R4-J Subset-Rust Purity Lint (E14.L1-Deny)
//!
//! AST-level purity check for `Action::compute` bodies (E14.L1 — Compute
//! Determinism Closure, L1 realisation, v0.12 도입). Detects determinism-
//! breaking calls — clock / RNG / I/O / FFI — and bans `unsafe` blocks
//! inside the scanned function. Returns a list of [`PurityViolation`]s.
//!
//! ## Cross-link to E14.L2-Allow (cryptographer naming convention)
//!
//! Spec body terminology (cryptographer cross-review):
//!
//! - **E14.L1-Deny** — build-time AST deny-list (this crate).
//! - **E14.L2-Allow** — runtime host-import allow-list (WASM capability
//!   table, `arkhe:hook/{state, emit, fuel, ...}`). The L2 allow-list is
//!   the inverse of this L1 deny-list — compute-internal → external
//!   communication has exactly one channel (the host imports).
//!
//! The two layers paired is the **dual enforcement of E14 determinism
//! contract** — non-deterministic *inputs* are rejected at L1
//! (clock / RNG / I/O / FFI / threading), non-deterministic *operations*
//! at L2 (FP / SIMD / wasm-side threading).
//!
//! ## Current shape vs the dylint cdylib path
//!
//! Mirrors the [`arkhe-trait-default-check`] precedent: today a regular
//! syn-based lib that runs on stable Rust, integrated via the
//! `#[arkhe_pure]` attribute macro shipped from `arkhe-forge-macros`. A
//! future release migrates to `dylint_linting::declare_late_lint!` +
//! cdylib for HIR-level name resolution; this skeleton nails down the
//! policy + visitor concept first.
//!
//! Stable-toolchain compatibility is the deciding factor — going dylint-
//! native would force a nightly pin on the entire workspace, conflicting
//! with the dual-feature gate. The `#[arkhe_pure]` macro path catches
//! violations at every `cargo check`, which is the strongest enforcement
//! posture available without bifurcating the toolchain. Coverage assertion
//! ("every `Action::compute` has the attribute") is delegated to a
//! separate workspace-wide scan tracked in DIP-N1 (auditor cross-review).
//!
//! [`arkhe-trait-default-check`]: https://docs.rs/arkhe-trait-default-check
//!
//! ## Spec anchor
//!
//! - E14 Compute Determinism Closure (v0.12 도입, MC) — Runtime axiom layer.
//! - E14.L1-Deny — L1 `Action::compute` realisation (this crate + `#[arkhe_pure]`).
//! - Track A.1 (DIP-N1) — `arkhe-subset-rust-check` crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use syn::{visit::Visit, ExprPath, ExprUnsafe, ItemFn, Path};

/// Purity policy — exact path deny, namespace prefix deny, and an
/// `unsafe`-block ban. The default `v0_12_first_cut` policy covers the
/// 4-rule MVP (Clock + RNG + I/O + FFI per cryptographer cross-review).
///
/// ## Known limitation: single-ident suffix-match false-positive
///
/// The visitor matches a single-segment path (e.g. `thread_rng()`) by
/// scanning the deny-list for any entry ending in `::<ident>`. This
/// catches the common use-import escape (`use rand::thread_rng;
/// thread_rng()`) but also collides with **user-defined local fn of the
/// same name** (e.g. a shell crate defining `fn random() -> u32` would
/// have its calls to `random()` falsely flagged as `rand::random`).
///
/// Mitigation:
/// - Use full-qualified path in shell code (`my_crate::random()` instead
///   of `random()`).
/// - Or apply `Policy::empty()` and rely on a downstream lint.
/// - Long-term — receiver-type aware HIR resolution lands when the
///   crate migrates to the `dylint_linting` cdylib (documented in the
///   crate-level rustdoc).
#[derive(Debug, Clone)]
pub struct Policy {
    /// Fully-qualified path strings that must not appear as call targets
    /// or constant accesses. Match heuristics:
    /// - exact full-path equality (e.g. `std::time::Instant::now` vs the
    ///   path string of the visited `ExprPath`),
    /// - `use rand::thread_rng; thread_rng()` style — the bare ident
    ///   `thread_rng` matches the entry `rand::thread_rng` because the
    ///   entry's last segment equals the visited path's last segment AND
    ///   the visited path is a single ident.
    pub denied_paths: BTreeSet<String>,
    /// Namespace prefixes that ban every `prefix::*` call site in
    /// expression position. Use for whole-module bans (`std::fs`,
    /// `std::net`, `libc`, ...). A bare visited path `P` matches the
    /// prefix `P` exactly OR `P::*`. Type-position paths are skipped
    /// because the visitor only overrides `visit_expr_path`.
    pub denied_prefixes: BTreeSet<String>,
    /// When true, every `unsafe { ... }` block inside the scanned
    /// function triggers a violation. Closes the FFI escape route
    /// (raw `extern "C"` calls always require unsafe) plus
    /// `transmute` / raw-pointer dereferences.
    pub deny_unsafe: bool,
}

impl Policy {
    /// Empty policy — accepts every function. Useful for tests.
    pub fn empty() -> Self {
        Self {
            denied_paths: BTreeSet::new(),
            denied_prefixes: BTreeSet::new(),
            deny_unsafe: false,
        }
    }

    /// v0.12 first-cut deny list (4-rule MVP per cryptographer cross-
    /// review): Clock + RNG + I/O + FFI plus `unsafe` block ban.
    /// Subsequent rounds may add Threading + Sync/atomic + replay
    /// hazards (cryptographer Round 2/3) — non-breaking additions.
    pub fn v0_12_first_cut() -> Self {
        // Exact path entries — clock / RNG / specific I/O.
        let mut denied_paths = BTreeSet::new();
        for p in [
            // Clock crates — chain replay must not depend on wall-clock.
            "std::time::Instant::now",
            "std::time::SystemTime::now",
            "std::time::UNIX_EPOCH",
            "chrono::Utc::now",
            "chrono::Local::now",
            "minstant::Instant::now",
            "quanta::Clock::now",
            "coarsetime::Instant::now",
            "instant::Instant::now",
            // RNG OS-entropy paths — deterministic seeded RNGs
            // (e.g. `rand_chacha::ChaCha20Rng::seed_from_u64(42)`) are
            // intentionally NOT banned in v0.12; cryptographer Round 2
            // may add `from_entropy` / `from_os_rng` constructor bans
            // once HIR-level method-call resolution lands.
            "rand::random",
            "rand::thread_rng",
            "rand::rngs::OsRng",
            "rand::rngs::ThreadRng",
            "getrandom::getrandom",
            "getrandom::fill", // 0.3+ API; 0.2 / 0.3 dual-pin coverage.
            "rdrand::RdRand",
            // Specific I/O — chain replay must not read stdin / OS state.
            "std::io::stdin",
            "std::io::stdout",
            "std::io::stderr",
        ] {
            denied_paths.insert(p.to_string());
        }
        // Namespace prefixes — entire I/O / FFI modules.
        let mut denied_prefixes = BTreeSet::new();
        for p in [
            // I/O — filesystem / network / process / env.
            "std::fs",
            "std::net",
            "std::process",
            "std::env",
            "tokio::fs",
            "tokio::net",
            "tokio::io",
            "tokio::time",
            "async_std::fs",
            "async_std::net",
            "async_std::io",
            "async_std::task",
            "mio",
            "socket2",
            // FFI — libc.
            "libc",
        ] {
            denied_prefixes.insert(p.to_string());
        }
        Self {
            denied_paths,
            denied_prefixes,
            // Bans `extern "C"` calls (always behind unsafe), raw-pointer
            // deref, transmute, and other dangerous primitives. Escape
            // hatch via a `#[arkhe(unsafe_audit_cleared = "ticket-id")]`
            // attribute is a Round-3 candidate (cryptographer dispatch).
            deny_unsafe: true,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::v0_12_first_cut()
    }
}

/// One purity violation — a forbidden call site, prefix-matched namespace
/// access, or `unsafe` block inside the scanned function. Carries the
/// matching deny-list entry plus a span label for diagnostic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurityViolation {
    /// The deny-list entry (path or prefix) that matched, or
    /// `"unsafe-block"` for the unsafe ban.
    pub denied_path: String,
    /// Human-readable form of the offending site.
    pub site: String,
    /// Reason category — `clock`, `rng`, `io`, `ffi`, `unsafe`, `other`.
    pub reason: &'static str,
}

/// Scan a function for E14.L1-Deny purity violations under `policy`.
pub fn check_purity(item: &ItemFn, policy: &Policy) -> Vec<PurityViolation> {
    let mut visitor = PurityVisitor {
        policy,
        violations: Vec::new(),
    };
    visitor.visit_item_fn(item);
    visitor.violations
}

/// Convenience wrapper — scan with the v0.12 first-cut policy.
pub fn check_purity_v0_12(item: &ItemFn) -> Vec<PurityViolation> {
    check_purity(item, &Policy::v0_12_first_cut())
}

struct PurityVisitor<'p> {
    policy: &'p Policy,
    violations: Vec<PurityViolation>,
}

impl<'ast, 'p> Visit<'ast> for PurityVisitor<'p> {
    /// Match path expressions like `std::time::Instant::now` (when used
    /// as a function reference) and `std::time::UNIX_EPOCH` (constant
    /// access). Method-call form (`receiver.method()`) is intentionally
    /// not handled in the v0.12 first cut — it would require HIR-level
    /// receiver-type resolution to avoid colliding with shell-defined
    /// methods of the same name (e.g. a shell type with its own `.now()`).
    /// Cryptographer review may extend the visitor with `*::method`
    /// pattern entries once a precise receiver-type heuristic is agreed.
    ///
    /// Default visitor recursion is preserved for child nodes; we never
    /// override `visit_path` so generic / type-position paths are skipped.
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let path_str = path_to_string(&node.path);
        if let Some((denied, kind)) = self.match_against_deny_list(&node.path, &path_str) {
            self.violations.push(PurityViolation {
                denied_path: denied.to_string(),
                site: format!("{} ({kind})", path_str),
                reason: classify_reason(denied),
            });
        }
        syn::visit::visit_expr_path(self, node);
    }

    /// Ban `unsafe { ... }` blocks inside the scanned function. Closes the
    /// FFI / raw-pointer / transmute attack surface for E14.L1-Deny when
    /// `policy.deny_unsafe` is true.
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        if self.policy.deny_unsafe {
            self.violations.push(PurityViolation {
                denied_path: "unsafe-block".to_string(),
                site: "unsafe { ... }".to_string(),
                reason: "unsafe",
            });
        }
        syn::visit::visit_expr_unsafe(self, node);
    }
}

#[derive(Copy, Clone)]
enum MatchKind {
    Exact,
    SingleIdentSuffix,
    Prefix,
}

impl core::fmt::Display for MatchKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            MatchKind::Exact => "exact",
            MatchKind::SingleIdentSuffix => "imported-ident",
            MatchKind::Prefix => "prefix",
        })
    }
}

impl<'p> PurityVisitor<'p> {
    /// Return the matching deny-list entry plus the match kind, if any.
    ///
    /// Match order:
    /// 1. Exact full-path equality against `denied_paths`.
    /// 2. Single-ident form (`use rand::thread_rng; thread_rng()`) —
    ///    matches when the visited path is a single segment AND a
    ///    `denied_paths` entry ends with `::<that_ident>`.
    /// 3. Namespace prefix match against `denied_prefixes` —
    ///    `path == prefix` or `path` starts with `prefix::`.
    fn match_against_deny_list<'d>(
        &'d self,
        path: &Path,
        path_str: &str,
    ) -> Option<(&'d str, MatchKind)> {
        if let Some(entry) = self.policy.denied_paths.get(path_str) {
            return Some((entry.as_str(), MatchKind::Exact));
        }
        if path.segments.len() == 1 {
            let ident = &path.segments[0].ident;
            let needle = format!("::{ident}");
            for denied in &self.policy.denied_paths {
                if denied.ends_with(&needle) {
                    return Some((denied.as_str(), MatchKind::SingleIdentSuffix));
                }
            }
        }
        for prefix in &self.policy.denied_prefixes {
            if path_str == prefix.as_str() || path_str.starts_with(&format!("{prefix}::")) {
                return Some((prefix.as_str(), MatchKind::Prefix));
            }
        }
        None
    }
}

fn path_to_string(path: &Path) -> String {
    let mut out = String::new();
    if path.leading_colon.is_some() {
        out.push_str("::");
    }
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    out.push_str(&segs.join("::"));
    out
}

fn classify_reason(denied: &str) -> &'static str {
    if denied == "unsafe-block" {
        return "unsafe";
    }
    if denied.contains("time::")
        || denied.contains("chrono::")
        || denied.contains("minstant::")
        || denied.contains("quanta::")
        || denied.contains("coarsetime::")
        || denied.contains("instant::Instant")
        || denied == "tokio::time"
    {
        "clock"
    } else if denied.contains("rand")
        || denied.contains("OsRng")
        || denied.contains("getrandom")
        || denied.contains("rdrand")
    {
        "rng"
    } else if denied.contains("fs")
        || denied.contains("net")
        || denied.contains("io::")
        || denied.ends_with("::io")
        || denied.contains("process")
        || denied.contains("env")
        || denied == "mio"
        || denied == "socket2"
        || denied.contains("async_std::task")
    {
        "io"
    } else if denied == "libc" || denied.contains("libc::") {
        "ffi"
    } else {
        "other"
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn pure_compute_passes_v0_12() {
        let f: ItemFn = parse_quote! {
            fn compute(a: u32, b: u32) -> u32 {
                a.wrapping_add(b).wrapping_mul(2)
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations.is_empty(),
            "pure compute must not trigger violations: {violations:?}"
        );
    }

    #[test]
    fn instant_now_full_path_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u128 {
                let _now = std::time::Instant::now();
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].denied_path, "std::time::Instant::now");
        assert_eq!(violations[0].reason, "clock");
    }

    #[test]
    fn use_imported_thread_rng_single_ident_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _r = thread_rng();
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].denied_path, "rand::thread_rng");
        assert_eq!(violations[0].reason, "rng");
    }

    #[test]
    fn os_rng_full_path_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = rand::rngs::OsRng;
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations
            .iter()
            .any(|v| v.denied_path == "rand::rngs::OsRng"));
    }

    #[test]
    fn unix_epoch_constant_access_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u128 {
                let _ = std::time::UNIX_EPOCH;
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations
            .iter()
            .any(|v| v.denied_path == "std::time::UNIX_EPOCH"));
    }

    #[test]
    fn type_position_path_does_not_match() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _x: Option<std::time::Instant> = None;
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations.is_empty(),
            "type-position path must not match: {violations:?}"
        );
    }

    #[test]
    fn shell_defined_now_method_does_not_match() {
        let f: ItemFn = parse_quote! {
            fn compute(s: ShellState) -> u32 {
                let _ = s.now();
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations.is_empty(),
            "shell .now() method must not falsely trigger: {violations:?}"
        );
    }

    #[test]
    fn fs_namespace_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = std::fs::read_to_string("/etc/passwd");
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "std::fs"),
            "std::fs::* prefix must trigger: {violations:?}"
        );
        assert!(violations.iter().any(|v| v.reason == "io"));
    }

    #[test]
    fn net_namespace_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = std::net::TcpStream::connect("0.0.0.0:1");
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations.iter().any(|v| v.denied_path == "std::net"));
    }

    #[test]
    fn process_namespace_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = std::process::id();
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations.iter().any(|v| v.denied_path == "std::process"));
    }

    #[test]
    fn env_namespace_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = std::env::var("HOME");
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations.iter().any(|v| v.denied_path == "std::env"));
    }

    #[test]
    fn libc_namespace_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = libc::getpid();
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations.iter().any(|v| v.denied_path == "libc"));
        assert!(violations.iter().any(|v| v.reason == "ffi"));
    }

    #[test]
    fn unsafe_block_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute(x: u32) -> u32 {
                unsafe {
                    let p = &x as *const u32;
                    *p
                }
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "unsafe-block"),
            "unsafe block must trigger: {violations:?}"
        );
        assert!(violations.iter().any(|v| v.reason == "unsafe"));
    }

    #[test]
    fn tokio_time_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = tokio::time::Instant::now();
                0
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "tokio::time" && v.reason == "clock"),
            "tokio::time::* must trigger as clock: {violations:?}"
        );
    }

    #[test]
    fn tokio_io_prefix_classified_as_io() {
        // B1 — `tokio::io` / `async_std::io` previously fell through to
        // "other" because the `denied.contains("io::")` branch missed
        // tail-only matches (`tokio::io` has no trailing `::`).
        // `denied.ends_with("::io")` closes the gap (cryptographer Round 1).
        assert_eq!(classify_reason("tokio::io"), "io");
        assert_eq!(classify_reason("async_std::io"), "io");
    }

    #[test]
    fn classify_reason_categorises_correctly() {
        assert_eq!(classify_reason("std::time::Instant::now"), "clock");
        assert_eq!(classify_reason("rand::thread_rng"), "rng");
        assert_eq!(classify_reason("std::fs"), "io");
        assert_eq!(classify_reason("libc"), "ffi");
        assert_eq!(classify_reason("unsafe-block"), "unsafe");
        assert_eq!(classify_reason("blake3::hash"), "other");
    }

    #[test]
    fn empty_policy_accepts_anything() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = std::time::Instant::now();
                let _ = rand::thread_rng();
                let _ = std::fs::read_to_string("/etc/passwd");
                unsafe { let _: u8 = 1; }
                0
            }
        };
        let violations = check_purity(&f, &Policy::empty());
        assert!(violations.is_empty());
    }

    #[test]
    fn local_fn_named_random_currently_false_positives() {
        // Demonstrates the documented suffix-match limitation: a
        // user-defined local fn named `random` is flagged as
        // `rand::random` because the visitor cannot resolve receiver /
        // module without HIR. Once the crate migrates to the dylint
        // cdylib path, this test inverts (the local fn becomes correctly
        // allowed). Tracked in `Policy` rustdoc + crate-level rustdoc.
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                fn random() -> u32 { 42 }
                random()
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "rand::random"),
            "v0.12 first cut: bare-ident `random()` is a known false positive"
        );
    }

    #[test]
    fn getrandom_fill_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute(buf: &mut [u8]) -> () {
                let _ = getrandom::fill(buf);
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations
            .iter()
            .any(|v| v.denied_path == "getrandom::fill"));
    }

    #[test]
    fn pure_with_blake3_passes() {
        let f: ItemFn = parse_quote! {
            fn compute(input: &[u8]) -> [u8; 32] {
                let mut h = blake3::Hasher::new();
                h.update(input);
                *h.finalize().as_bytes()
            }
        };
        let violations = check_purity_v0_12(&f);
        assert!(violations.is_empty());
    }
}
