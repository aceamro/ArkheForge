//! # arkhe-subset-rust-check — Subset-Rust Purity Lint (E14.L1-Deny)
//!
//! AST-level purity check for `Action::compute` bodies (E14.L1 — Compute
//! Determinism Closure, L1 realisation). Detects determinism-
//! breaking calls — clock / RNG / I/O / FFI — and bans `unsafe` blocks
//! and `unsafe fn` signatures inside the scanned function. Returns a
//! list of [`PurityViolation`]s.
//!
//! Macro arguments are scanned best-effort: each invocation's tokens are
//! parsed as a comma-separated expression list and visited; when that
//! parse fails (non-expression DSLs), raw token trees are scanned for
//! `::`-joined ident sequences against the same deny rules. Ident
//! sequences directly after `.` are skipped, mirroring the AST visitor's
//! method-call exclusion.
//!
//! ## Crate shape
//!
//! Mirrors the `arkhe-trait-default-check` precedent: a syn-based lib
//! that runs on stable Rust, integrated via the `#[arkhe_pure]`
//! attribute macro shipped from `arkhe-forge-macros`. The macro path
//! catches violations at every `cargo check`. Coverage assertion
//! ("every `Action::compute` has the attribute") is delegated to a
//! separate workspace-wide scan in `arkhe-trait-default-check`.
//!
//!
//! ## Spec anchor
//!
//! - E14 Compute Determinism Closure (MC) — Runtime axiom layer.
//! - E14.L1-Deny — L1 `Action::compute` realisation (this crate + `#[arkhe_pure]`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use proc_macro2::{Spacing, TokenStream, TokenTree};
use std::collections::BTreeSet;
use syn::punctuated::Punctuated;
use syn::{visit::Visit, Expr, ExprPath, ExprUnsafe, ItemFn, Macro, Path, Signature, Token};

/// Purity policy — exact path deny, namespace prefix deny, macro-name
/// deny, and an `unsafe` ban (blocks + `unsafe fn` signatures). The
/// default `deny_compute_impurity` policy covers the 4-rule deny scope
/// (Clock + RNG + I/O + FFI).
///
/// Leading-colon paths (`::std::time::Instant::now`) are normalised
/// (the `::` is stripped) before matching; diagnostics keep the raw form.
///
/// ## Known limitation: suffix-match false-positives
///
/// The visitor matches a visited path by scanning the deny-list for any
/// entry ending in `::<visited path>`. This catches the use-import
/// escapes (`use rand::thread_rng; thread_rng()` and `use
/// std::time::Instant; Instant::now()`) but also collides with
/// **user-defined items whose trailing path coincides with a deny
/// entry** (e.g. a shell crate defining `fn random() -> u32`, or a shell
/// type named `Instant` with its own `now()` associated fn, would have
/// its calls falsely flagged).
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
    ///   normalised path string of the visited `ExprPath`),
    /// - suffix rule — the visited path `P` matches an entry `D` when
    ///   `D` ends with `::P`. Covers use-imports of the terminal item
    ///   (`use rand::thread_rng; thread_rng()`) and of an intermediate
    ///   segment (`use std::time::Instant; Instant::now()`). See the
    ///   struct-level docs for the accepted false-positive surface.
    pub denied_paths: BTreeSet<String>,
    /// Namespace prefixes that ban every `prefix::*` call site in
    /// expression position. Use for whole-module bans (`std::fs`,
    /// `std::net`, `libc`, ...). A bare visited path `P` matches the
    /// prefix `P` exactly OR `P::*`. Type-position paths are skipped
    /// because the visitor only overrides `visit_expr_path`.
    pub denied_prefixes: BTreeSet<String>,
    /// Macro names (terminal path segment, without `!`) whose invocation
    /// is denied outright. Covers stdout / stderr I/O macros
    /// (`println!`, `dbg!`, ...) that perform I/O without any deniable
    /// path appearing in argument position. Matched against the last
    /// segment of the macro path, so `std::println!` and `println!`
    /// both hit a `println` entry; a user-defined macro of the same
    /// name is falsely flagged (same trade-off as the suffix rule).
    pub denied_macros: BTreeSet<String>,
    /// When true, every `unsafe { ... }` block and every `unsafe fn`
    /// signature inside the scanned function (including the checked fn
    /// itself) triggers a violation. Closes the FFI escape route
    /// (raw `extern "C"` calls always require unsafe) plus
    /// `transmute` / raw-pointer dereferences — the signature check
    /// covers edition-2021 implicit-unsafe bodies that need no
    /// `unsafe` block.
    pub deny_unsafe: bool,
}

impl Policy {
    /// Empty policy — accepts every function. Useful for tests.
    pub fn empty() -> Self {
        Self {
            denied_paths: BTreeSet::new(),
            denied_prefixes: BTreeSet::new(),
            denied_macros: BTreeSet::new(),
            deny_unsafe: false,
        }
    }

    /// Default deny list (4 categories): Clock + RNG + I/O + FFI plus
    /// the `unsafe` ban (blocks and `unsafe fn` signatures) and the
    /// stdout / stderr I/O macros. Future rounds may add Threading +
    /// Sync/atomic + replay hazards — non-breaking additions.
    pub fn deny_compute_impurity() -> Self {
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
            // intentionally NOT banned (cryptographer review).
            // `from_entropy` / `from_os_rng` constructor bans depend on
            // HIR-level method-call resolution.
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
        // I/O macros — expand to stdout / stderr writes with no
        // deniable path in expression position.
        let mut denied_macros = BTreeSet::new();
        for m in ["println", "print", "eprintln", "eprint", "dbg"] {
            denied_macros.insert(m.to_string());
        }
        Self {
            denied_paths,
            denied_prefixes,
            denied_macros,
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
        Self::deny_compute_impurity()
    }
}

/// One purity violation — a forbidden call site, prefix-matched namespace
/// access, denied macro invocation, or `unsafe` block / `unsafe fn`
/// signature inside the scanned function. Carries the matching deny-list
/// entry plus a span label for diagnostic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurityViolation {
    /// The deny-list entry (path, prefix, or macro name) that matched,
    /// or `"unsafe-block"` / `"unsafe-fn"` for the unsafe ban.
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

/// Convenience wrapper — scan with the default `deny_compute_impurity` policy.
pub fn check_purity_default(item: &ItemFn) -> Vec<PurityViolation> {
    check_purity(item, &Policy::deny_compute_impurity())
}

struct PurityVisitor<'p> {
    policy: &'p Policy,
    violations: Vec<PurityViolation>,
}

impl<'ast, 'p> Visit<'ast> for PurityVisitor<'p> {
    /// Match path expressions like `std::time::Instant::now` (when used
    /// as a function reference) and `std::time::UNIX_EPOCH` (constant
    /// access). Method-call form (`receiver.method()`) is intentionally
    /// not handled in this implementation — it would require HIR-level
    /// receiver-type resolution to avoid colliding with shell-defined
    /// methods of the same name (e.g. a shell type with its own `.now()`).
    /// Cryptographer review may extend the visitor with `*::method`
    /// pattern entries once a precise receiver-type heuristic is agreed.
    ///
    /// Default visitor recursion is preserved for child nodes; we never
    /// override `visit_path` so generic / type-position paths are skipped.
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let raw = path_to_string(&node.path);
        // Leading-colon form (`::std::time::Instant::now`) resolves to
        // the same item — normalise for matching, keep the raw form for
        // the diagnostic site.
        let normalized = raw.strip_prefix("::").unwrap_or(&raw);
        if let Some((denied, kind)) =
            self.match_against_deny_list(normalized, node.path.segments.len())
        {
            self.violations.push(PurityViolation {
                denied_path: denied.to_string(),
                site: format!("{raw} ({kind})"),
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

    /// Ban `unsafe fn` signatures — the checked fn itself and any nested
    /// fn-like item. An `unsafe fn` body is an implicit unsafe context
    /// (edition 2021), so the block ban alone never fires for it.
    fn visit_signature(&mut self, node: &'ast Signature) {
        if self.policy.deny_unsafe && node.unsafety.is_some() {
            self.violations.push(PurityViolation {
                denied_path: "unsafe-fn".to_string(),
                site: format!("unsafe fn {}", node.ident),
                reason: "unsafe",
            });
        }
        syn::visit::visit_signature(self, node);
    }

    /// Scan macro invocations (expression, statement, and item position
    /// all funnel through this node). Two layers: (a) the macro name is
    /// checked against `denied_macros`; (b) arguments are scanned
    /// best-effort — parsed as a comma-separated expression list and
    /// visited, falling back to a raw token-tree scan when the parse
    /// fails (non-expression DSLs).
    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(seg) = node.path.segments.last() {
            let name = seg.ident.to_string();
            if let Some(entry) = self.policy.denied_macros.get(&name) {
                self.violations.push(PurityViolation {
                    denied_path: entry.clone(),
                    site: format!("{}! (macro)", path_to_string(&node.path)),
                    reason: classify_reason(entry),
                });
            }
        }
        match node.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            Ok(args) => {
                // Fresh visitor: the parsed expressions are local, so they
                // cannot be visited under the outer `'ast` lifetime.
                let mut inner = PurityVisitor {
                    policy: self.policy,
                    violations: Vec::new(),
                };
                for expr in &args {
                    inner.visit_expr(expr);
                }
                self.violations.append(&mut inner.violations);
            }
            Err(_) => self.scan_token_trees(node.tokens.clone()),
        }
        syn::visit::visit_macro(self, node);
    }
}

#[derive(Copy, Clone)]
enum MatchKind {
    Exact,
    SingleIdentSuffix,
    PathSuffix,
    Prefix,
}

impl core::fmt::Display for MatchKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            MatchKind::Exact => "exact",
            MatchKind::SingleIdentSuffix => "imported-ident",
            MatchKind::PathSuffix => "imported-path",
            MatchKind::Prefix => "prefix",
        })
    }
}

impl<'p> PurityVisitor<'p> {
    /// Return the matching deny-list entry plus the match kind, if any.
    /// `path_str` must be the normalised path (leading `::` stripped).
    ///
    /// Match order:
    /// 1. Exact full-path equality against `denied_paths`.
    /// 2. Suffix rule — a `denied_paths` entry ends with `::<path_str>`.
    ///    Catches use-imports of the terminal item (`use
    ///    rand::thread_rng; thread_rng()`) and of an intermediate
    ///    segment (`use std::time::Instant; Instant::now()`). When
    ///    several entries share the suffix, the lexicographically first
    ///    one is reported.
    /// 3. Namespace prefix match against `denied_prefixes` —
    ///    `path == prefix` or `path` starts with `prefix::`.
    fn match_against_deny_list<'d>(
        &'d self,
        path_str: &str,
        num_segments: usize,
    ) -> Option<(&'d str, MatchKind)> {
        if let Some(entry) = self.policy.denied_paths.get(path_str) {
            return Some((entry.as_str(), MatchKind::Exact));
        }
        let needle = format!("::{path_str}");
        for denied in &self.policy.denied_paths {
            if denied.ends_with(&needle) {
                let kind = if num_segments == 1 {
                    MatchKind::SingleIdentSuffix
                } else {
                    MatchKind::PathSuffix
                };
                return Some((denied.as_str(), kind));
            }
        }
        for prefix in &self.policy.denied_prefixes {
            if path_str == prefix.as_str() || path_str.starts_with(&format!("{prefix}::")) {
                return Some((prefix.as_str(), MatchKind::Prefix));
            }
        }
        None
    }

    /// Raw token-tree fallback for macro arguments that do not parse as
    /// a comma-separated expression list. Collects `::`-joined ident
    /// sequences and runs them through the same deny rules; sequences
    /// directly after `.` are skipped (method / field names, mirroring
    /// the AST visitor's method-call exclusion).
    fn scan_token_trees(&mut self, stream: TokenStream) {
        let mut iter = stream.into_iter().peekable();
        let mut segs: Vec<String> = Vec::new();
        let mut seq_after_dot = false;
        let mut prev_dot = false;
        let mut expect_segment = false;
        while let Some(tt) = iter.next() {
            match tt {
                TokenTree::Ident(id) => {
                    if !segs.is_empty() && !expect_segment {
                        self.check_token_path(&mut segs, seq_after_dot);
                    }
                    if segs.is_empty() {
                        seq_after_dot = prev_dot;
                    }
                    segs.push(id.to_string());
                    expect_segment = false;
                    prev_dot = false;
                }
                TokenTree::Punct(p)
                    if p.as_char() == ':'
                        && p.spacing() == Spacing::Joint
                        && matches!(
                            iter.peek(),
                            Some(TokenTree::Punct(q)) if q.as_char() == ':'
                        ) =>
                {
                    iter.next();
                    expect_segment = !segs.is_empty();
                    prev_dot = false;
                }
                TokenTree::Group(group) => {
                    self.check_token_path(&mut segs, seq_after_dot);
                    expect_segment = false;
                    prev_dot = false;
                    self.scan_token_trees(group.stream());
                }
                TokenTree::Punct(p) => {
                    self.check_token_path(&mut segs, seq_after_dot);
                    expect_segment = false;
                    prev_dot = p.as_char() == '.';
                }
                TokenTree::Literal(_) => {
                    self.check_token_path(&mut segs, seq_after_dot);
                    expect_segment = false;
                    prev_dot = false;
                }
            }
        }
        self.check_token_path(&mut segs, seq_after_dot);
    }

    fn check_token_path(&mut self, segs: &mut Vec<String>, after_dot: bool) {
        if segs.is_empty() {
            return;
        }
        if !after_dot {
            let path_str = segs.join("::");
            if let Some((denied, kind)) = self.match_against_deny_list(&path_str, segs.len()) {
                self.violations.push(PurityViolation {
                    denied_path: denied.to_string(),
                    site: format!("{path_str} ({kind}, macro tokens)"),
                    reason: classify_reason(denied),
                });
            }
        }
        segs.clear();
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
    if denied == "unsafe-block" || denied == "unsafe-fn" {
        return "unsafe";
    }
    if matches!(denied, "println" | "print" | "eprintln" | "eprint" | "dbg") {
        return "io";
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
    fn pure_compute_passes() {
        let f: ItemFn = parse_quote! {
            fn compute(a: u32, b: u32) -> u32 {
                a.wrapping_add(b).wrapping_mul(2)
            }
        };
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
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
            unsafe fn compute() -> u32 {
                let _ = std::time::Instant::now();
                let _ = ::std::time::Instant::now();
                let _ = Instant::now();
                let _ = rand::thread_rng();
                let _ = std::fs::read_to_string("/etc/passwd");
                println!("io");
                let _v = vec![std::time::SystemTime::now()];
                unsafe { let _: u8 = 1; }
                unsafe fn helper() {}
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
        let violations = check_purity_default(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "rand::random"),
            "bare-ident `random()` is a known false positive"
        );
    }

    #[test]
    fn getrandom_fill_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute(buf: &mut [u8]) -> () {
                let _ = getrandom::fill(buf);
            }
        };
        let violations = check_purity_default(&f);
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
        let violations = check_purity_default(&f);
        assert!(violations.is_empty());
    }

    #[test]
    fn seeded_chacha_rng_passes() {
        let f: ItemFn = parse_quote! {
            fn compute(seed: u64) -> u32 {
                let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
                rng.next_u32()
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations.is_empty(),
            "seeded deterministic RNG must pass: {violations:?}"
        );
    }

    #[test]
    fn use_imported_instant_now_two_segments_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u128 {
                let _now = Instant::now();
                0
            }
        };
        let violations = check_purity_default(&f);
        assert_eq!(violations.len(), 1, "{violations:?}");
        // Several deny entries share the `::Instant::now` suffix; the
        // lexicographically first one is reported — any of them is a
        // correct clock violation.
        assert!(violations[0].denied_path.ends_with("::Instant::now"));
        assert_eq!(violations[0].reason, "clock");
    }

    #[test]
    fn use_imported_time_module_three_segments_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u128 {
                let _now = time::Instant::now();
                0
            }
        };
        let violations = check_purity_default(&f);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].denied_path, "std::time::Instant::now");
        assert_eq!(violations[0].reason, "clock");
    }

    #[test]
    fn leading_colon_path_rejected_with_raw_site() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u128 {
                let _now = ::std::time::Instant::now();
                0
            }
        };
        let violations = check_purity_default(&f);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].denied_path, "std::time::Instant::now");
        assert!(
            violations[0].site.starts_with("::std::time::Instant::now"),
            "diagnostic site keeps the raw leading-colon form: {}",
            violations[0].site
        );
    }

    #[test]
    fn leading_colon_prefix_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _ = ::std::fs::read_to_string("/etc/passwd");
                0
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "std::fs"),
            "leading-colon prefix path must trigger: {violations:?}"
        );
    }

    #[test]
    fn vec_macro_argument_scanned() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _v = vec![std::time::Instant::now()];
                0
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "std::time::Instant::now" && v.reason == "clock"),
            "macro arguments must be scanned: {violations:?}"
        );
    }

    #[test]
    fn format_macro_argument_scanned() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                let _s = format!("{:?}", std::time::SystemTime::now());
                0
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "std::time::SystemTime::now"),
            "format! arguments must be scanned: {violations:?}"
        );
    }

    #[test]
    fn format_macro_with_pure_args_passes() {
        let f: ItemFn = parse_quote! {
            fn compute(a: u32, b: u32) -> String {
                format!("{}-{}", a, b)
            }
        };
        let violations = check_purity_default(&f);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn stdout_and_dbg_macros_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute(x: u32) -> u32 {
                println!("hello");
                let _ = dbg!(x);
                x
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "println" && v.reason == "io"),
            "println! must trigger: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "dbg" && v.reason == "io"),
            "dbg! must trigger: {violations:?}"
        );
    }

    #[test]
    fn full_path_io_macro_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                std::println!("hello");
                0
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "println"),
            "std::println! must hit the println entry: {violations:?}"
        );
    }

    #[test]
    fn macro_token_fallback_scans_non_expr_args() {
        // `x => ...` does not parse as a comma-separated expression list,
        // so the raw token-tree scan must catch the denied path.
        let f: ItemFn = parse_quote! {
            fn compute() -> u32 {
                custom_dsl!(x => std::time::Instant::now());
                0
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "std::time::Instant::now"),
            "token fallback must scan macro args: {violations:?}"
        );
    }

    #[test]
    fn macro_token_fallback_skips_method_names() {
        // `.fill(...)` is a method call — the fallback must not confuse
        // the method name with the `getrandom::fill` deny entry.
        let f: ItemFn = parse_quote! {
            fn compute(buf: &mut [u8]) -> u32 {
                custom_dsl!(x => buf.fill(0));
                0
            }
        };
        let violations = check_purity_default(&f);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn unsafe_fn_signature_rejected() {
        let f: ItemFn = parse_quote! {
            unsafe fn compute(p: *const u32) -> u32 {
                *p
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations
                .iter()
                .any(|v| v.denied_path == "unsafe-fn" && v.reason == "unsafe"),
            "unsafe fn signature must trigger: {violations:?}"
        );
    }

    #[test]
    fn nested_unsafe_fn_rejected() {
        let f: ItemFn = parse_quote! {
            fn compute(x: u32) -> u32 {
                unsafe fn helper(p: *const u32) -> u32 {
                    *p
                }
                x
            }
        };
        let violations = check_purity_default(&f);
        assert!(
            violations.iter().any(|v| v.denied_path == "unsafe-fn"),
            "nested unsafe fn must trigger: {violations:?}"
        );
    }
}
