#![allow(clippy::disallowed_methods)]

//! Purity gate: pure crates contain no I/O, env, clock, process, or thread
//! tokens in their `src/` trees and no build scripts (a build.rs would run
//! arbitrary code outside the scanned tree).

use gates::{
    impure_source_violations, pure_crates, rust_files, workspace_packages, workspace_root,
};

#[test]
fn pure_crates_have_no_impure_tokens() {
    let root = workspace_root();
    let mut violations = Vec::new();

    for krate in pure_crates() {
        let src = root.join("crates").join(krate).join("src");
        let files = rust_files(&src).unwrap_or_else(|e| panic!("{krate}: {e}"));
        assert!(
            !files.is_empty(),
            "{krate}: no source files found under {} — gate would be vacuous",
            src.display()
        );
        for file in files {
            let text = std::fs::read_to_string(&file).expect("read source file");
            violations.extend(impure_source_violations(krate, &file, &text));
        }
    }

    assert!(
        violations.is_empty(),
        "purity gate failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pure_crates_are_all_workspace_members() {
    let root = workspace_root();
    for krate in pure_crates() {
        assert!(
            root.join("crates").join(krate).join("Cargo.toml").exists(),
            "{krate} listed as pure but missing from crates/"
        );
    }
}

#[test]
fn pure_crate_targets_cannot_escape_the_scanned_source_tree() {
    let root = workspace_root();
    let packages = workspace_packages();
    for krate in pure_crates() {
        let src = root.join("crates").join(krate).join("src");
        let package = packages
            .iter()
            .find(|package| package.name == krate)
            .unwrap_or_else(|| panic!("{krate} is not a workspace package"));
        assert!(!package.source_paths.is_empty(), "{krate} has no target");
        for target in &package.source_paths {
            assert!(
                target.starts_with(&src),
                "{krate} target {} escapes scanned source tree {}",
                target.display(),
                src.display()
            );
        }
    }
}

#[test]
fn evidence_graph_and_bridge_keep_their_pure_boundaries() {
    let root = workspace_root();
    let evidence_graph =
        std::fs::read_to_string(root.join("crates/nah-proto/src/effects.rs")).unwrap();
    // Every production module of the bridge; its tests read the engine's
    // sources from disk.
    let bridge = std::fs::read_dir(root.join("crates/nah-effinterp/src/bridge"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| !path.ends_with("tests.rs"))
        .map(|path| std::fs::read_to_string(path).unwrap())
        .collect::<String>();
    assert!(gates::evidence_boundary_violations(&evidence_graph, &bridge).is_empty());
    assert_eq!(
        gates::evidence_boundary_violations(
            "use effinterp_proto::Plan; use effinterp_engine::Engine;",
            "Engine::new().with_resolver(resolver)"
        )
        .len(),
        2
    );
}
