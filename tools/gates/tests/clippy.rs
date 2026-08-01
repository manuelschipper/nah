#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Compiler-level seeded-red proof for purity checks that lexical matching
//! cannot resolve, such as a renamed `std` crate.

use gates::workspace_root;
use std::process::Command;

#[test]
fn aliased_io_and_global_state_fail_clippy() {
    let root = workspace_root();
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--locked",
            "--offline",
            "--manifest-path",
            "tools/gates/fixtures/impure-alias/Cargo.toml",
            "--target-dir",
            "target/gate-fixtures",
            "--",
            "-Dwarnings",
        ])
        .env("CLIPPY_CONF_DIR", &root)
        .current_dir(&root)
        .output()
        .expect("run seeded Clippy fixture");

    assert!(!output.status.success(), "impure fixture passed Clippy");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for path in [
        "std::os::unix::net::UnixStream",
        "std::sync::Once",
        "std::thread::Builder",
    ] {
        assert!(
            stderr.contains(path),
            "Clippy did not reject {path}:\n{stderr}"
        );
    }
}
