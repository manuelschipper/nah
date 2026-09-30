#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_proto::{AnalysisStatus, PartialReason};
use effinterp_repo::{
    DependencyKind, IndexLimits, InvalidationAction, RepoChange, UpdateFailure, UpdateOutcome,
    apply_changes, build_index, effects_of, invalidation_action, save_index,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

#[test]
fn dependency_graph_binds_inputs_identities_limits_and_derived_outputs() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-dependency-graph",
        &[
            ("package.json", r#"{"scripts":{"run":"node app.js"}}"#),
            (
                "app.js",
                "#!/usr/bin/env node\nrequire('fs').unlinkSync('/a')\n",
            ),
            ("tsconfig.json", "{}\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for key in [
        "source:app.js",
        "discovery:package.json",
        "resolver:package.json",
        "resolver:tsconfig.json",
        "frontend:javascript",
        "analyzer",
        "model-set",
        "limit:crawl.max_files",
        "limit:engine.max_effects",
    ] {
        assert!(
            index.dependency_manifest.get(key).is_some(),
            "missing {key}"
        );
    }
    assert!(index.derived_dependencies.contains_key("module:app.js"));
    assert!(
        index.derived_dependencies["module:app.js"]
            .iter()
            .any(|key| key == "limit:crawl.max_files")
    );
    assert!(
        index
            .derived_dependencies
            .keys()
            .any(|key| key.starts_with("entrypoint:"))
    );
    assert_eq!(
        index.derived_dependencies["query-snapshot"],
        index
            .dependency_manifest
            .keys()
            .map(str::to_string)
            .collect::<Vec<_>>()
    );
}

#[test]
fn launch_and_entrypoint_compositions_keep_distinct_dependencies() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-composition-dependency-identity",
        &[
            ("package.json", r#"{"scripts":{"run":"python3 tool.py"}}"#),
            (
                "tool.py",
                "#!/usr/bin/env python3\nfrom helper import wipe\nwipe()\n",
            ),
            ("helper.py", "import os\ndef wipe(): os.remove('/target')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.composed.contains_key("tool.py"));
    assert!(index.composed.contains_key("\0launch:tool.py"));
    assert!(
        index
            .derived_dependencies
            .contains_key("composition:tool.py")
    );
    assert!(
        index
            .derived_dependencies
            .contains_key("launch-composition:tool.py")
    );
}

#[test]
fn failed_updates_leave_prior_snapshot_byte_identical() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-transactional-update",
        &[(
            "app.py",
            "#!/usr/bin/env python3\nimport os\nos.remove('/before')\n",
        )],
    );
    let mut index = build_index(&root, IndexLimits::default());
    let prior = save_index(&index);

    std::fs::write(root.join("app.py"), [0xff, 0xfe]).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("app.py".into())],
    );
    assert!(matches!(
        report.outcome,
        UpdateOutcome::Failed {
            failure: UpdateFailure::Read { .. }
        }
    ));
    assert_eq!(save_index(&index), prior);

    std::fs::write(
        root.join("app.py"),
        "#!/usr/bin/env python3\ndef broken(:\n",
    )
    .unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("app.py".into())],
    );
    assert!(matches!(
        report.outcome,
        UpdateOutcome::Failed {
            failure: UpdateFailure::Parse { .. }
        }
    ));
    assert_eq!(save_index(&index), prior);

    std::fs::write(
        root.join("app.py"),
        "#!/usr/bin/env python3\nimport os\nos.remove('/after')\n",
    )
    .unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("app.py".into())],
    );
    assert_eq!(report.outcome, UpdateOutcome::Published);
    assert_ne!(save_index(&index), prior);
}

#[test]
fn invalid_effect_resources_do_not_abort_the_index() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "untyped-resource-index",
        &[
            ("a.rb", "File.exist?(ENV['X'])\n"),
            (
                "b.py",
                "#!/usr/bin/env python3\nimport os\nos.remove('/before')\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    for source_file in ["a.rb", "b.py"] {
        let plan = index
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.entrypoint.source_file == source_file)
            .and_then(|entrypoint| entrypoint.plan())
            .unwrap();
        effinterp_proto::validate_plan(plan).unwrap();
    }
    if let AnalysisStatus::Partial { reasons } = &index.snapshot_state {
        assert!(
            reasons
                .iter()
                .all(|reason| !matches!(reason, PartialReason::AnalysisFailure { .. }))
        );
    }

    std::fs::write(root.join("a.rb"), "File.exist?(ENV['Y'])\n").unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("a.rb".into())],
    );
    assert_eq!(report.outcome, UpdateOutcome::Published);
}

#[test]
fn full_rebuild_accepts_prior_partial_evidence_and_matches_clean_build() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-partial-full-rebuild",
        &[
            ("app.sh", "#!/bin/sh\nrm /stable\n"),
            ("package.json", r#"{"name":"before"}"#),
        ],
    );
    std::fs::write(root.join("junk.py"), [0xff, 0xfe, 0x00]).unwrap();
    let mut index = build_index(&root, IndexLimits::default());
    assert!(matches!(
        index.snapshot_state,
        AnalysisStatus::Partial { .. }
    ));

    std::fs::write(root.join("package.json"), r#"{"name":"after"}"#).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("package.json".into())],
    );
    assert_eq!(report.outcome, UpdateOutcome::Published);
    assert_eq!(
        save_index(&index),
        save_index(&build_index(&root, IndexLimits::default()))
    );

    let prior = save_index(&index);
    std::fs::write(root.join("new.py"), [0xff, 0xfe]).unwrap();
    std::fs::write(root.join("package.json"), r#"{"name":"again"}"#).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("package.json".into())],
    );
    assert_eq!(
        report.outcome,
        UpdateOutcome::Failed {
            failure: UpdateFailure::Read {
                path: "new.py".into()
            }
        }
    );
    assert_eq!(save_index(&index), prior);
}

#[test]
fn full_rebuild_accepts_an_unchanged_prior_parse_failure() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-partial-parse-rebuild",
        &[
            ("app.py", "#!/usr/bin/env python3\ndef broken(:\n"),
            ("package.json", r#"{"name":"before"}"#),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    std::fs::write(root.join("package.json"), r#"{"name":"after"}"#).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("package.json".into())],
    );
    assert_eq!(report.outcome, UpdateOutcome::Published);
    assert_eq!(
        save_index(&index),
        save_index(&build_index(&root, IndexLimits::default()))
    );
}

#[test]
fn invalidation_policy_fails_closed_for_configs_identities_and_unknown_events() {
    assert_eq!(
        invalidation_action(&RepoChange::Modified("app.py".into())),
        InvalidationAction::Reextract
    );
    assert_eq!(
        invalidation_action(&RepoChange::Modified("package.json".into())),
        InvalidationAction::Rebuild
    );
    assert_eq!(
        invalidation_action(&RepoChange::Modified("bin/tool".into())),
        InvalidationAction::Rediscover
    );
    assert_eq!(
        invalidation_action(&RepoChange::IdentityChanged {
            kind: DependencyKind::ParserFrontend,
            key: "frontend:python".into(),
        }),
        InvalidationAction::Rebuild
    );
    assert_eq!(
        invalidation_action(&RepoChange::Unknown("future-event".into())),
        InvalidationAction::Rebuild
    );
}

#[test]
fn high_module_count_keeps_only_the_reachable_python_summaries() {
    let files = [
        (
            "app.py",
            "#!/usr/bin/env python3\nfrom reachable import run\nrun()\n",
        ),
        (
            "reachable.py",
            "import os\ndef run(): os.remove('/reachable')\n",
        ),
    ];
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "python-demand-driven-index",
        &files,
    );
    for module in 0..512 {
        std::fs::write(
            root.join(format!("unused_{module}.py")),
            "def value(): return 1\n",
        )
        .unwrap();
    }

    let index = build_index(&root, IndexLimits::default());
    assert!(index.registry.files.contains_key("app.py"));
    assert!(index.registry.files.contains_key("reachable.py"));
    assert!(
        index
            .registry
            .files
            .keys()
            .all(|path| !path.starts_with("unused_"))
    );
    assert_eq!(
        index
            .dependency_manifest
            .source_paths()
            .filter(|path| path.ends_with(".py"))
            .count(),
        514
    );
    let report = effects_of(&index, "app.py").expect("entry analyzed");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == "reachable.py"
            })
    );
    let closure = build_index(
        &repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            "python-reachable-closure",
            &files,
        ),
        IndexLimits::default(),
    );
    let effect_shape = |index: &effinterp_repo::RepoIndex| {
        effects_of(index, "app.py")
            .expect("entry analyzed")
            .payload
            .into_effects()
            .unwrap()
            .effects
            .into_iter()
            .map(|effect| {
                (
                    effect.operation,
                    effect.resource,
                    effect.origin.expect("effect origin").source_file,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(effect_shape(&index), effect_shape(&closure));
}

#[test]
fn source_patterns_record_only_matched_file_dependencies() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "source-pattern-dependencies",
        &[
            (
                "bin/dispatch.sh",
                "source \"${LIB}/lib/cmd/${CMD}.sh\"; deploy",
            ),
            ("lib/cmd/a.sh", "deploy(){ touch /a; }"),
            ("lib/cmd/b.sh", "deploy(){ touch /b; }"),
            ("lib/cmd/deep/c.sh", "deploy(){ touch /wrong; }"),
            (
                "scripts/e2e.sh",
                "SRC=$(cd $(dirname \"$0\"); pwd); source \"${SRC}/e2e/include.sh\"; runTest ./x.sh",
            ),
            ("scripts/e2e/include.sh", "runTest(){ bash \"$1\"; }"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let dependencies = &index.derived_dependencies["entrypoint:bin/dispatch.sh"];
    assert!(dependencies.contains(&"source:lib/cmd/a.sh".to_string()));
    assert!(dependencies.contains(&"source:lib/cmd/b.sh".to_string()));
    assert!(!dependencies.contains(&"source:lib/cmd/deep/c.sh".to_string()));
    for name in ["bin/dispatch.sh", "scripts/e2e.sh"] {
        let entry = index
            .entrypoints
            .iter()
            .find(|entry| entry.entrypoint.id == name)
            .unwrap();
        let effinterp_repo::EntrypointOutcome::Analyzed { plan } = &entry.outcome else {
            panic!("{:?}", entry.outcome)
        };
        assert!(
            !plan.boundaries.iter().any(|boundary| matches!(
                boundary.reason.as_str(),
                "unresolved_source" | "unmodeled_command"
            )),
            "{name}: {:?}",
            plan.boundaries
        );
        if name == "bin/dispatch.sh" {
            for path in ["/a", "/b"] {
                assert!(
                    plan.effects
                        .iter()
                        .any(|effect| effect.operation.0 == "filesystem.metadata"
                            && effinterp_proto::display_resource(&effect.resource).contains(path)
                            && effect.condition.is_some())
                );
            }
            assert_eq!(
                plan.execution_graph
                    .nodes
                    .iter()
                    .filter(
                        |node| node.input.as_ref().is_some_and(|input| input.assurance
                            == effinterp_proto::ExecutionAssurance::Alternatives)
                    )
                    .count(),
                2
            );
        }
    }
}
