//! Prerelease packaging commitments that must remain explicit.

#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::process::Command;

use gates::workspace_root;

#[test]
fn every_workspace_package_is_private_and_mit_licensed() {
    let root = workspace_root();
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata");
    for package in metadata["packages"].as_array().expect("packages") {
        let name = package["name"].as_str().expect("package name");
        assert_eq!(
            package["publish"],
            serde_json::json!([]),
            "{name} is publishable"
        );
        assert_eq!(package["license"], "MIT", "{name} license metadata");
    }

    let license = std::fs::read_to_string(root.join("LICENSE")).expect("read LICENSE");
    assert!(license.starts_with("MIT License\n"));
    assert!(license.contains("Permission is hereby granted"));
    let security = std::fs::read_to_string(root.join("SECURITY.md")).expect("read SECURITY.md");
    assert!(security.contains("/security/advisories/new"));
}
