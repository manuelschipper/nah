//! Test-layout gate: each workspace member links its integration tests as one
//! `tests/suite/main.rs` binary. A new top-level `tests/*.rs` file silently
//! links another binary into every worktree's `target/`, the build-size cost
//! the "Build and test layout" rule in `AGENTS.md` exists to prevent.

use gates::workspace_test_binaries;
use std::path::Path;

#[test]
fn integration_tests_link_one_suite_binary_per_package() {
    let binaries = workspace_test_binaries();
    assert!(
        binaries
            .iter()
            .any(|path| path == Path::new("tools/gates/tests/suite/main.rs")),
        "gates' own suite binary is missing from {binaries:?}; the gate would be vacuous"
    );
    let stray = binaries
        .iter()
        .filter(|path| !path.ends_with("tests/suite/main.rs"))
        .collect::<Vec<_>>();
    assert!(
        stray.is_empty(),
        "test-layout gate failed: move each file into its package's tests/suite/ as a module:\n{stray:#?}"
    );
}
