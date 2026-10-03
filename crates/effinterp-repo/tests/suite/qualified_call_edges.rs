//! Package/path-qualified cross-file call edges reach effects across files.
//!
//! A Go `pkg.Func()` call on an imported package and a Rust `module::func()`
//! path-qualified call are recorded as call edges by the frontends, so building
//! the repo index and reaching the entrypoint traces INTO the callee's file.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

#[test]
fn go_package_qualified_call_reaches_cross_package_delete() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qce-go",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/util\"\nfunc main() { util.Wipe(\"/x\") }\n",
            ),
            (
                "util/util.go",
                "package util\nimport \"os\"\nfunc Wipe(p string) { os.RemoveAll(p) }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &ResourceSelector::parse("fs:/x").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "main.go"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "main.go's util.Wipe(\"/x\") reaches the cross-package delete: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

#[test]
fn rust_path_qualified_call_reaches_cross_file_delete() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qce-rust",
        &[
            ("app.rs", "fn main() { util::wipe() }\n"),
            (
                "util.rs",
                "pub fn wipe() { std::fs::remove_dir_all(\"/x\").ok(); }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &ResourceSelector::parse("fs:/x").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "app.rs"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "app.rs's util::wipe() reaches the cross-file delete: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}
