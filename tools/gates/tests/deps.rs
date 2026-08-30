//! Dependency-direction gate: the documented architecture is CI-checked
//! against `cargo metadata` (so table-form and renamed dependencies, and
//! members outside crates/, are all seen). Pure crates additionally may only
//! use allowlisted external crates — impurity can't arrive via a dependency.

use gates::{
    PackageDeps, allowed_nah_deps, dependency_direction_violations, pure_dependency_violations,
    workspace_packages,
};

/// Workspace tooling outside the decision pipeline, exempt from layering.
const TOOLING: &[&str] = &["gates"];

#[test]
fn dependency_direction_is_enforced() {
    let packages = workspace_packages();
    let names = packages
        .iter()
        .map(|pkg| pkg.name.as_str())
        .collect::<Vec<_>>();
    let violations = dependency_direction_violations(&packages, TOOLING, &names);
    assert!(
        violations.is_empty(),
        "dependency-direction gate failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pure_crates_have_only_allowed_dependencies_and_no_build_scripts() {
    let violations = pure_dependency_violations(&workspace_packages());
    assert!(
        violations.is_empty(),
        "pure-crate dependency gate failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn seeded_forbidden_edges_are_rejected_by_live_validators() {
    let packages = vec![PackageDeps {
        name: "nah-policy".into(),
        normal_deps: vec!["nah-observe".into()],
        build_deps: vec!["cc".into()],
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: vec!["custom.rs".into()],
    }];

    let direction =
        dependency_direction_violations(&packages, TOOLING, &["nah-policy", "nah-observe"]);
    assert_eq!(direction.len(), 1);
    assert!(direction[0].contains("forbidden dependency nah-observe"));

    let purity = pure_dependency_violations(&packages);
    assert_eq!(purity.len(), 3);
    assert!(purity.iter().any(|v| v.contains("nah-observe")));
    assert!(purity.iter().any(|v| v.contains("build-dependencies")));
    assert!(purity.iter().any(|v| v.contains("build scripts")));
}

#[test]
fn proto_allows_only_its_reviewed_contract_dependencies() {
    let allowed = PackageDeps {
        name: "nah-proto".into(),
        normal_deps: vec!["serde".into(), "serde_json".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    assert!(pure_dependency_violations(&[allowed]).is_empty());

    let forbidden = PackageDeps {
        name: "nah-proto".into(),
        normal_deps: vec!["indexmap".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    let violations = pure_dependency_violations(&[forbidden]);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("indexmap"));
}

#[test]
fn parser_allows_only_the_reviewed_tree_sitter_dependencies() {
    let allowed = PackageDeps {
        name: "nah-parse".into(),
        normal_deps: vec!["tree-sitter".into(), "tree-sitter-bash".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    assert!(pure_dependency_violations(&[allowed]).is_empty());

    let forbidden = PackageDeps {
        name: "nah-parse".into(),
        normal_deps: vec!["shell-words".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    let violations = pure_dependency_violations(&[forbidden]);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("shell-words"));
}

#[test]
fn inline_allows_only_the_reviewed_tree_sitter_dependencies() {
    let allowed = PackageDeps {
        name: "nah-inline".into(),
        normal_deps: vec![
            "tree-sitter".into(),
            "tree-sitter-javascript".into(),
            "tree-sitter-python".into(),
            "tree-sitter-typescript".into(),
        ],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    assert!(pure_dependency_violations(&[allowed]).is_empty());

    let forbidden = PackageDeps {
        name: "nah-inline".into(),
        normal_deps: vec!["swc_ecma_parser".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    let violations = pure_dependency_violations(&[forbidden]);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("swc_ecma_parser"));
}

#[test]
fn actions_allows_only_the_reviewed_idna_dependency() {
    let allowed = PackageDeps {
        name: "nah-actions".into(),
        normal_deps: vec!["idna".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    assert!(pure_dependency_violations(&[allowed]).is_empty());

    let forbidden = PackageDeps {
        name: "nah-actions".into(),
        normal_deps: vec!["url".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    };
    let violations = pure_dependency_violations(&[forbidden]);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("url"));
}

#[test]
fn composition_roots_reject_forbidden_edges() {
    let packages = vec![
        PackageDeps {
            name: "nah-cli".into(),
            normal_deps: vec!["nah-corpus".into(), "gates".into()],
            build_deps: Vec::new(),
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
        PackageDeps {
            name: "nah-corpus".into(),
            normal_deps: vec!["nah-cli".into(), "nah-actions".into(), "nah-observe".into()],
            build_deps: Vec::new(),
            dev_deps: vec!["nah-policy".into(), "gates".into()],
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
    ];

    let violations = dependency_direction_violations(
        &packages,
        TOOLING,
        &[
            "nah-cli",
            "nah-corpus",
            "nah-actions",
            "nah-observe",
            "nah-policy",
            "gates",
        ],
    );
    assert_eq!(violations.len(), 6);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("nah-cli has forbidden dependency nah-corpus"))
    );
    for dependency in ["nah-actions", "nah-observe"] {
        assert!(violations.iter().any(|violation| {
            violation.contains(&format!("nah-corpus has forbidden dependency {dependency}"))
        }));
    }
    assert!(violations.iter().any(|violation| {
        violation.contains("nah-corpus has forbidden dev-dependency nah-policy")
    }));
    assert!(
        violations
            .iter()
            .any(|violation| { violation.contains("nah-cli has forbidden dependency gates") })
    );
    assert!(
        violations.iter().any(|violation| {
            violation.contains("nah-corpus has forbidden dev-dependency gates")
        })
    );
    assert!(
        !violations
            .iter()
            .any(|violation| violation.contains("nah-corpus has forbidden dependency nah-cli"))
    );
}

#[test]
fn non_nah_workspace_dependencies_are_still_internal_edges() {
    let packages = vec![PackageDeps {
        name: "nah-cli".into(),
        normal_deps: vec!["adapter-codex".into()],
        build_deps: Vec::new(),
        dev_deps: Vec::new(),
        source_paths: Vec::new(),
        build_scripts: Vec::new(),
    }];
    let violations =
        dependency_direction_violations(&packages, TOOLING, &["nah-cli", "adapter-codex"]);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("adapter-codex"));
}

#[test]
fn every_workspace_member_is_classified() {
    // A member added anywhere in the workspace (crates/, adapters/, …) must
    // be known to the gate: pipeline crate, composition root, or named
    // tooling. allowed_nah_deps panics on names it has never heard of.
    for pkg in workspace_packages() {
        if TOOLING.contains(&pkg.name.as_str()) {
            continue;
        }
        let _ = allowed_nah_deps(&pkg.name);
    }
}
