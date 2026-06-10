//! E14.L1 coverage assertion — every `impl ActionCompute for T { fn compute }`
//! in the workspace must carry the `#[arkhe_pure]` attribute on the compute
//! method.
//!
//! This is the build-time MC invariant — if the lint mechanism (`#[arkhe_pure]`
//! macro + `arkhe-subset-rust-check` policy) ships but no compute method ever
//! invokes it, the lint is silently neutered. This test scans every
//! Runtime-crate source file with `syn`, locates every `impl ActionCompute for
//! T` block at **any nesting depth** (including impls declared inside fn
//! bodies), and asserts the compute method has `#[arkhe_pure]`. Failure prints
//! the offending file + type so an operator can patch the missing attribute.
//!
//! # `#[cfg(test)]` exemption
//!
//! Items lexically under a `#[cfg(test)]` module are exempt: they never
//! compile into production builds, and test fixtures legitimately impl the
//! kernel `ActionCompute` trait directly without the purity lint. Only the
//! exact `#[cfg(test)]` form is recognized — `#[cfg(not(test))]`,
//! `#[cfg(feature = "…")]`, and compound predicates stay in scope, so the
//! exemption cannot be widened by accident.
//!
//! Why here (vs a separate sibling crate): `arkhe-trait-default-check` already
//! ships as the workspace's MC structural-invariant syn scaffolding; the
//! "do one thing well" framing reads workspace-wide structural invariant scan
//! as a single dimension covering both trait-default-body fingerprint and
//! compute coverage.
//!
//! Sealed-trait note: `ActionCompute` is bound `__Sealed + ArkheAction`
//! (`arkhe-forge-core::action`), so only types deriving `#[derive(ArkheAction)]`
//! can impl the trait — there is no escape via hand-rolled trait impl
//! reachable from outside the workspace.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use syn::{Attribute, ImplItem, ItemImpl, ItemMod, Meta};

/// The set of workspace crates that may contain `impl ActionCompute for T`
/// blocks. `examples/dice` is excluded — its `RollAction::compute` uses a
/// different (demo-only) signature and does not impl the `ActionCompute`
/// trait. Add a new crate here when a new Runtime-layer crate joins the
/// workspace.
const RUNTIME_CRATES: &[&str] = &["arkhe-forge-core", "arkhe-forge-platform", "arkhe-forge"];

#[test]
fn all_action_compute_impls_have_arkhe_pure() {
    let root = workspace_root();
    let mut missing = Vec::new();
    let mut scanned = 0usize;

    for crate_dir in RUNTIME_CRATES {
        let src = root.join(crate_dir).join("src");
        if !src.exists() {
            continue;
        }
        scan_dir(&src, &mut missing, &mut scanned);
    }

    assert!(
        scanned > 0,
        "scanner did not encounter any source file — workspace layout assumption broken"
    );
    assert!(
        missing.is_empty(),
        "E14.L1 coverage gap — `impl ActionCompute for T` missing `#[arkhe_pure]`:\n  {}",
        missing.join("\n  ")
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn scan_dir(dir: &Path, missing: &mut Vec<String>, scanned: &mut usize) {
    let entries = std::fs::read_dir(dir).expect("read_dir");
    for entry in entries {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, missing, scanned);
        } else if path.extension().is_some_and(|e| e == "rs") {
            *scanned += 1;
            scan_file(&path, missing);
        }
    }
}

fn scan_file(path: &Path, missing: &mut Vec<String>) {
    // A file the scanner cannot read or parse is a coverage hole, not a
    // skippable entry — fail loudly instead of silently narrowing the scan.
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("scanner failed to read {}: {e}", path.display()));
    let file = syn::parse_file(&src)
        .unwrap_or_else(|e| panic!("scanner failed to parse {}: {e}", path.display()));
    scan_syntax_tree(&file, path, missing);
}

fn scan_syntax_tree(file: &syn::File, path: &Path, missing: &mut Vec<String>) {
    let mut visitor = ComputeCoverageVisitor { path, missing };
    visitor.visit_file(file);
}

/// AST visitor that reaches `impl ActionCompute` blocks at any nesting depth
/// (module bodies, fn bodies, blocks) and skips `#[cfg(test)]` module
/// subtrees entirely.
struct ComputeCoverageVisitor<'a> {
    path: &'a Path,
    missing: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for ComputeCoverageVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        check_impl(node, self.path, self.missing);
        visit::visit_item_impl(self, node);
    }
}

/// Recognizes the exact `#[cfg(test)]` attribute form. Compound or negated
/// predicates (`not(test)`, `any(test, …)`, `feature = "test"`) do not parse
/// as a bare path and are intentionally not exempt.
fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        match &attr.meta {
            Meta::List(list) => list
                .parse_args::<syn::Path>()
                .is_ok_and(|p| p.is_ident("test")),
            _ => false,
        }
    })
}

fn check_impl(item: &ItemImpl, path: &Path, missing: &mut Vec<String>) {
    let Some((_, trait_path, _)) = &item.trait_ else {
        return;
    };
    let Some(last) = trait_path.segments.last() else {
        return;
    };
    if last.ident != "ActionCompute" {
        return;
    }
    for ii in &item.items {
        let ImplItem::Fn(func) = ii else { continue };
        if func.sig.ident != "compute" {
            continue;
        }
        let has_pure = func.attrs.iter().any(|a| {
            a.path()
                .segments
                .last()
                .is_some_and(|s| s.ident == "arkhe_pure")
        });
        if !has_pure {
            missing.push(format!(
                "{}: impl ActionCompute for {}::compute()",
                path.display(),
                type_to_string(&item.self_ty)
            ));
        }
    }
}

fn type_to_string(ty: &syn::Type) -> String {
    if let syn::Type::Path(tp) = ty {
        tp.path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_else(|| "<complex>".into())
    } else {
        "<complex>".into()
    }
}

fn scan_str(src: &str) -> Vec<String> {
    let file = syn::parse_str::<syn::File>(src).expect("fixture source parses");
    let mut missing = Vec::new();
    scan_syntax_tree(&file, Path::new("inline-fixture.rs"), &mut missing);
    missing
}

#[test]
fn detects_unannotated_impl_nested_in_fn_body() {
    let missing = scan_str(
        r#"
        mod production {
            fn build() {
                struct Hidden;
                impl ActionCompute for Hidden {
                    fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                        Vec::new()
                    }
                }
            }
        }
        "#,
    );
    assert_eq!(missing.len(), 1, "fn-body-nested impl must be detected");
    assert!(missing[0].contains("Hidden"), "got: {missing:?}");
}

#[test]
fn accepts_annotated_impl_nested_in_fn_body() {
    let missing = scan_str(
        r#"
        fn build() {
            struct Covered;
            impl ActionCompute for Covered {
                #[arkhe_pure]
                fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                    Vec::new()
                }
            }
        }
        "#,
    );
    assert!(missing.is_empty(), "got: {missing:?}");
}

#[test]
fn exempts_impl_under_cfg_test_module() {
    let missing = scan_str(
        r#"
        #[cfg(test)]
        mod tests {
            fn fixture() {
                struct Fixture;
                impl ActionCompute for Fixture {
                    fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                        Vec::new()
                    }
                }
            }
        }
        "#,
    );
    assert!(
        missing.is_empty(),
        "cfg(test) subtree must be exempt: {missing:?}"
    );
}

#[test]
fn cfg_exemption_requires_exact_test_predicate() {
    let missing = scan_str(
        r#"
        #[cfg(not(test))]
        mod negated {
            struct A;
            impl ActionCompute for A {
                fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> { Vec::new() }
            }
        }

        #[cfg(feature = "test")]
        mod featured {
            struct B;
            impl ActionCompute for B {
                fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> { Vec::new() }
            }
        }
        "#,
    );
    assert_eq!(
        missing.len(),
        2,
        "non-exact cfg predicates must stay in scope: {missing:?}"
    );
}
