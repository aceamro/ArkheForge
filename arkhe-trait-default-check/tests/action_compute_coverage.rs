//! E14.L1 coverage assertion — every `impl ActionCompute for T { fn compute }`
//! in the workspace must carry the `#[arkhe_pure]` attribute on the compute
//! method.
//!
//! This is the build-time MC invariant — if the lint mechanism (`#[arkhe_pure]`
//! macro + `arkhe-subset-rust-check` policy) ships but no compute method ever
//! invokes it, the lint is silently neutered. This test scans every
//! Runtime-crate source file with `syn`, locates every `impl ActionCompute for
//! T` block, and asserts the compute method has `#[arkhe_pure]`. Failure prints
//! the offending file + type so an operator can patch the missing attribute.
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

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use syn::{ImplItem, Item, ItemImpl};

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
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(file) = syn::parse_file(&src) else {
        return;
    };
    visit_items(&file.items, path, missing);
}

fn visit_items(items: &[Item], path: &Path, missing: &mut Vec<String>) {
    for item in items {
        match item {
            Item::Impl(item_impl) => check_impl(item_impl, path, missing),
            Item::Mod(item_mod) => {
                if let Some((_, mod_items)) = &item_mod.content {
                    visit_items(mod_items, path, missing);
                }
            }
            _ => {}
        }
    }
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
