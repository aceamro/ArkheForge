//! Compile-fail suite for `arkhe-forge-macros` derives.
//!
//! Each `tests/ui/*.rs` file is a standalone crate that must fail to compile;
//! trybuild compares the actual error output against the paired `*.stderr`
//! snapshot.

#[test]
fn derive_compile_fail() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
