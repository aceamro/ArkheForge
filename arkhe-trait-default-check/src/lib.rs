//! # arkhe-trait-default-check — Trait Default Body Semantic Change Detector
//!
//! Lint crate that enforces the Minor-1 breaking-change rule —
//! "a semantic change to a default-impl body is a breaking change" — in CI.
//!
//! ## How it works
//!
//! 1. Extract the default-impl body AST of each trait with `cargo expand` /
//!    `syn`.
//! 2. Normalize the body AST to a canonical form (whitespace collapse,
//!    comment strip).
//! 3. Produce a BLAKE3 hash — the **body fingerprint**.
//! 4. Compare against the baseline (`ci/trait-default-fingerprints.txt`).
//!    Any mismatch is treated as breaking.
//!
//! ## Crate shape
//!
//! A regular library crate that exposes the `TraitDefaultFingerprint`
//! struct and `hash_default_body` function. AST fingerprint generation
//! is consumed from proc-macro tests. Stable-toolchain compatible — no
//! rustc-driver dependency.
//!
//! ## Single-point-of-failure (SPOF) analysis
//!
//! This crate hosts three workspace-wide structural invariants, all
//! surfaced through integration tests under `tests/`:
//!
//! 1. **Trait default-body fingerprint** — `TraitDefaultFingerprint`
//!    types here in `src/lib.rs` plus the proc-macro tests that
//!    exercise them. Anchors the Minor-1 rule ("a semantic change to
//!    a default-impl body is a breaking change").
//! 2. **`ActionCompute` workspace coverage** —
//!    `tests/action_compute_coverage.rs` scans every workspace crate
//!    for `impl ActionCompute for T` blocks and asserts the
//!    `#[arkhe_pure]` attribute is present on `compute()`. Realises the
//!    E14.L1 Subset-Rust purity invariant at workspace scope.
//! 3. **Forward-looking event 0-emission** —
//!    `tests/forward_looking_event_zero_emission.rs` scans Runtime
//!    production source for any reference to `ReplicaIdAllocation` /
//!    `AuditReceiptKeyPolicy` outside the two allowed files. Mechanical
//!    proof that the sealed cut emits these define-only events from
//!    zero production sites.
//!
//! ### SPOF risk
//!
//! A bug or accidental delete in any of those three test files would
//! silently drop floor on the corresponding workspace invariant. The
//! crate is the *single point of mechanical enforcement* for all three —
//! a maintainer who edits `tests/forward_looking_event_zero_emission.rs`
//! by mistake (e.g. trimming "stale comments") might inadvertently
//! disable the 0-emission proof.
//!
//! ### Mitigation — count-gate sentinel
//!
//! The workspace's default test count gate (`cargo test --workspace`)
//! acts as the implicit meta-check: disabling or deleting any of the
//! three invariant tests trips the workflow-3 default test count
//! delta — peer reviewers flag the count decrease, and the architect /
//! auditor / cryptographer cycle catches the regression before merge.
//! **Test count gate IS the mechanical sentinel for the SPOF**.
//!
//! Cross-checks (independent verification axes pointing back at this
//! crate's invariants):
//!
//! - Workflow-3 7-config cargo test matrix (default + 2 feature
//!   single + combined + tier-2 hook + tier-2 observer + all-features)
//!   runs the three invariant tests in every config; a feature-gated
//!   regression on any one trips the matrix.
//! - CI `cargo test --workspace` (`.github/workflows/ci.yml`) — external
//!   CI runs the same matrix, providing a third-party (CI runner)
//!   execution trace in the PR review surface.
//! - Per-feature `cargo deny` — supply-chain regression would be caught
//!   at deny time, independent of the test layer.
//!
//! ### Migration-path note
//!
//! Adding a fourth or further workspace-wide invariant to this crate
//! evaluates the split decision:
//!
//! - **Stay consolidated** (cheap): the new invariant fits the
//!   "structural-invariant scan" axis. Continue to host here.
//! - **Split** (heavier): the new invariant is on a different axis
//!   (e.g. timing / runtime profiling / property-based correctness).
//!   Spin a peer crate alongside `arkhe-subset-rust-check`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use blake3::Hasher;
use syn::{ImplItem, ItemImpl};

/// Default body fingerprint of a trait impl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraitDefaultFingerprint {
    /// Trait name (e.g. `"ArkheComponent"`).
    pub trait_name: String,
    /// Impl target type (e.g. `"UserProfile"`).
    pub impl_for: String,
    /// Method name (e.g. `"canonical_bytes"`).
    pub method_name: String,
    /// BLAKE3 hash of canonical body bytes (32 bytes hex).
    pub body_hash: String,
}

/// Compute default body fingerprint from `ItemImpl` AST.
///
/// Normalizes the body by canonicalizing the token stream's `to_string()`
/// output (collapse runs of whitespace, strip comments).
pub fn hash_default_body(item: &ItemImpl) -> Vec<TraitDefaultFingerprint> {
    let trait_name = item
        .trait_
        .as_ref()
        .map(|(_, path, _)| path_ident_last(path))
        .unwrap_or_else(|| String::from("<inherent>"));
    let impl_for = type_ident_last(&item.self_ty);

    let mut out = Vec::new();
    for ii in &item.items {
        if let ImplItem::Fn(func) = ii {
            let method_name = func.sig.ident.to_string();
            let body_tokens = quote::quote! { #func }.to_string();
            let canonical = normalize(&body_tokens);
            let mut hasher = Hasher::new();
            hasher.update(canonical.as_bytes());
            out.push(TraitDefaultFingerprint {
                trait_name: trait_name.clone(),
                impl_for: impl_for.clone(),
                method_name,
                body_hash: hasher.finalize().to_hex().to_string(),
            });
        }
    }
    out
}

/// Canonical form — consecutive whitespace → single space, leading/trailing strip.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_ws = true; // strip leading
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

fn path_ident_last(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn type_ident_last(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(tp) => path_ident_last(&tp.path),
        _ => String::from("<complex>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn fingerprint_stable_across_whitespace() {
        let a: ItemImpl = parse_quote! {
            impl MyTrait for MyType {
                fn hello(&self) -> u32 { 42 }
            }
        };
        let b: ItemImpl = parse_quote! {
            impl    MyTrait   for    MyType   {
                fn    hello(&self)   ->   u32   {    42    }
            }
        };
        let fa = hash_default_body(&a);
        let fb = hash_default_body(&b);
        assert_eq!(fa[0].body_hash, fb[0].body_hash);
    }

    #[test]
    fn fingerprint_differs_on_return_value_change() {
        let a: ItemImpl = parse_quote! {
            impl MyTrait for MyType {
                fn hello(&self) -> u32 { 42 }
            }
        };
        let b: ItemImpl = parse_quote! {
            impl MyTrait for MyType {
                fn hello(&self) -> u32 { 43 }
            }
        };
        let fa = hash_default_body(&a);
        let fb = hash_default_body(&b);
        assert_ne!(fa[0].body_hash, fb[0].body_hash);
    }
}
