//! Dependency-direction gate: the documented architecture is CI-checked
//! against `cargo metadata` (so table-form and renamed dependencies, and
//! members outside crates/, are all seen). Pure crates additionally may only
//! use allowlisted external crates — impurity can't arrive via a dependency.

use gates::{
    ENGINE_PACKAGES, PackageDeps, PathDependency, ResolvedPackage, allowed_nah_deps,
    dependency_direction_violations, effinterp_linkage_violations, engine_source_violations,
    path_dependency_violations, pure_dependency_violations, resolved_packages, workspace_packages,
    workspace_path_dependencies, workspace_root,
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
fn effinterp_linkage_is_confined_to_the_bridge() {
    let violations = effinterp_linkage_violations(&workspace_packages());
    assert!(
        violations.is_empty(),
        "effinterp linkage gate failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn seeded_effinterp_linkage_is_rejected() {
    let packages = vec![
        // Policy links the pure matcher and protocol, never engine analysis.
        PackageDeps {
            name: "nah-policy".into(),
            normal_deps: vec![
                "effinterp-matcher".into(),
                "effinterp-proto".into(),
                "effinterp-repo".into(),
            ],
            build_deps: vec!["effinterp-engine".into()],
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
        PackageDeps {
            name: "nah-effinterp".into(),
            normal_deps: vec!["effinterp-proto".into()],
            build_deps: vec!["effinterp-engine".into()],
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
        // The CLI never drives the engine; it reaches it through the bridge.
        PackageDeps {
            name: "nah-cli".into(),
            normal_deps: vec!["effinterp-engine".into()],
            build_deps: Vec::new(),
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
        PackageDeps {
            name: "effinterp-repo".into(),
            normal_deps: vec!["effinterp-engine".into()],
            build_deps: Vec::new(),
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
    ];
    let violations = effinterp_linkage_violations(&packages);
    assert_eq!(violations.len(), 3, "{violations:?}");
    assert!(
        violations.iter().any(
            |violation| violation.contains("nah-cli has forbidden dependency effinterp-engine")
        )
    );
}

#[test]
fn workspace_path_dependencies_stay_inside_the_workspace() {
    let root = workspace_root();
    let violations = path_dependency_violations(&workspace_path_dependencies(), &root);
    assert!(
        violations.is_empty(),
        "workspace path dependency gate failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn seeded_external_path_dependency_is_rejected() {
    let root = workspace_root();
    let dependencies = [PathDependency {
        package: "nah-cli".into(),
        dependency: "outside".into(),
        path: root.parent().unwrap().to_owned(),
    }];
    assert_eq!(path_dependency_violations(&dependencies, &root).len(), 1);
}

#[test]
fn engine_packages_resolve_once_from_the_workspace() {
    let root = workspace_root();
    let violations = engine_source_violations(&resolved_packages(), &root);
    assert!(
        violations.is_empty(),
        "engine source gate failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn seeded_remote_duplicate_and_missing_engine_sources_are_rejected() {
    let root = workspace_root();
    let local = |name: &str| ResolvedPackage {
        name: name.into(),
        source: None,
        manifest_path: root.join("crates").join(name).join("Cargo.toml"),
    };
    let mut packages: Vec<_> = ENGINE_PACKAGES
        .iter()
        .filter(|name| !matches!(**name, "effinterp-repo" | "effinterp-proto"))
        .map(|name| local(name))
        .collect();
    packages.push(local("effinterp-engine"));
    packages.push(ResolvedPackage {
        source: Some("git+https://example.invalid/engine.git#0000".into()),
        ..local("effinterp-proto")
    });
    let violations = engine_source_violations(&packages, &root);
    assert_eq!(violations.len(), 3, "{violations:?}");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("effinterp-repo is missing"))
    );
    assert!(
        violations
            .iter()
            .any(|v| v.contains("effinterp-engine resolves 2 times"))
    );
    assert!(
        violations
            .iter()
            .any(|v| v.contains("effinterp-proto resolves from git+"))
    );
}

#[test]
fn seeded_forbidden_edges_are_rejected_by_live_validators() {
    let packages = vec![
        PackageDeps {
            name: "nah-policy".into(),
            normal_deps: vec!["nah-observe".into()],
            build_deps: vec!["cc".into()],
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: vec!["custom.rs".into()],
        },
        PackageDeps {
            // The pure engine subset may not reach engine analysis or the network.
            name: "effinterp-matcher".into(),
            normal_deps: vec!["effinterp-engine".into(), "reqwest".into()],
            build_deps: Vec::new(),
            dev_deps: Vec::new(),
            source_paths: Vec::new(),
            build_scripts: Vec::new(),
        },
    ];

    let direction =
        dependency_direction_violations(&packages, TOOLING, &["nah-policy", "nah-observe"]);
    assert_eq!(direction.len(), 1);
    assert!(direction[0].contains("forbidden dependency nah-observe"));

    let purity = pure_dependency_violations(&packages);
    assert_eq!(purity.len(), 5, "{purity:?}");
    assert!(purity.iter().any(|v| v.contains("nah-observe")));
    for dependency in ["effinterp-engine", "reqwest"] {
        assert!(
            purity
                .iter()
                .any(|v| v.contains(&format!("effinterp-matcher: dependency {dependency}")))
        );
    }
    assert!(purity.iter().any(|v| v.contains("build-dependencies")));
    assert!(purity.iter().any(|v| v.contains("build scripts")));
}

#[test]
fn proto_allows_only_its_reviewed_contract_dependencies() {
    let allowed = PackageDeps {
        name: "nah-proto".into(),
        normal_deps: vec![
            "effinterp-proto".into(),
            "serde".into(),
            "serde_json".into(),
        ],
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
            normal_deps: vec!["nah-cli".into(), "nah-observe".into()],
            build_deps: Vec::new(),
            dev_deps: vec!["nah-policy".into(), "nah-extensions".into(), "gates".into()],
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
            "nah-extensions",
            "nah-observe",
            "nah-policy",
            "gates",
        ],
    );
    assert_eq!(violations.len(), 5, "{violations:?}");
    for dependency in ["nah-corpus", "gates"] {
        assert!(violations.iter().any(|violation| {
            violation.contains(&format!("nah-cli has forbidden dependency {dependency}"))
        }));
    }
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("nah-corpus has forbidden dependency nah-observe"))
    );
    for dependency in ["nah-extensions", "gates"] {
        assert!(violations.iter().any(|violation| {
            violation.contains(&format!(
                "nah-corpus has forbidden dev-dependency {dependency}"
            ))
        }));
    }
    // The corpus harness drives the application seam and reads shipped policy.
    for edge in [
        "nah-corpus has forbidden dependency nah-cli",
        "nah-corpus has forbidden dev-dependency nah-policy",
    ] {
        assert!(
            !violations.iter().any(|violation| violation.contains(edge)),
            "{edge}"
        );
    }
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
