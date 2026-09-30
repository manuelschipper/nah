//! The forward and reverse query surface: effect origins and provenance paths,
//! operation-filtered reverse queries, boundaries, and the status and coverage
//! each answer carries. Each result carries evidence (entrypoints, provenance
//! paths), never a bare verdict.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_proto::{
    AnalysisStatus, BoundaryReason, CoverageLevel, PartialReason, display_resource,
};
use effinterp_repo::{IndexLimits, Selector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn build(root: &Path) -> effinterp_repo::RepoIndex {
    build_index(root, IndexLimits::default())
}

const UTIL_PY: &str = "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n";
const APP_PY: &str = "#!/usr/bin/env python\nfrom util import wipe\nwipe(\"/data/cache\")\n";

/// Whether the envelope graph records a call crossing into `target`. The
/// composed call step lives in the node's evidence, not in its origin file.
fn crosses_into(dag: &effinterp_proto::ProvenanceDag, target: &str) -> bool {
    dag.nodes.iter().any(|node| {
        matches!(
            &node.evidence,
            effinterp_proto::ProtocolProvenanceKind::CrossFileCall { into, .. } if into == target
        )
    })
}

fn antecedent_call_sites(
    dag: &effinterp_proto::ProvenanceDag,
    roots: &[effinterp_proto::OccurrenceId],
) -> std::collections::BTreeSet<String> {
    let mut seen: std::collections::BTreeSet<_> = roots.iter().cloned().collect();
    let mut pending = roots.to_vec();
    while let Some(id) = pending.pop() {
        for edge in dag.edges.iter().filter(|edge| edge.to == id) {
            if seen.insert(edge.from.clone()) {
                pending.push(edge.from.clone());
            }
        }
    }
    dag.nodes
        .iter()
        .filter(|node| seen.contains(&node.id))
        .filter_map(|node| match &node.evidence {
            effinterp_proto::ProtocolProvenanceKind::CrossFileCall { from, .. } => {
                Some(from.clone())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn cross_file_effect_names_its_origin_and_call_chain() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-origins",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let idx = build(&root);

    // The delete originates in util.py and is reached from app.py.
    let report = effects_of(&idx, "app.py").unwrap();
    let row = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|r| r.operation.as_str() == "filesystem.delete")
        .expect("app.py reaches the delete");
    assert_eq!(row.origin.as_ref().unwrap().source_file, "util.py");
    assert_eq!(row.entrypoint, "app.py");
    assert!(row.operation.is_destructive());
    assert!(
        antecedent_call_sites(&report.provenance, &row.provenance_roots)
            .iter()
            .any(|call| call.starts_with("app.py"))
    );
    assert!(
        crosses_into(&report.provenance, "util.py:wipe"),
        "evidence names the origin function: {:?}",
        report.provenance
    );
    assert_eq!(report.snapshot_id, idx.fingerprint);
}

#[test]
fn provenance_roots_distinguish_converging_entrypoint_chains() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-converging-origins",
        &[
            (
                "app1.py",
                "#!/usr/bin/env python\nfrom mid import go\ngo()\n",
            ),
            (
                "app2.py",
                "#!/usr/bin/env python\nfrom mid import go\ngo()\n",
            ),
            ("mid.py", "from util import wipe\ndef go():\n    wipe()\n"),
            (
                "util.py",
                "import shutil\ndef wipe():\n    shutil.rmtree('/data/cache')\n",
            ),
        ],
    );
    let idx = build(&root);
    let reach_report = reach(&idx, &Selector::parse("fs:/data/cache").unwrap(), None);
    let dag = &reach_report.provenance;
    let facts = reach_report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .map(|hit| &hit.fact)
        .collect::<Vec<_>>();
    for entrypoint in ["app1.py", "app2.py"] {
        let fact = facts
            .iter()
            .find(|fact| fact.entrypoint == entrypoint)
            .expect("entrypoint reaches the shared effect");
        let call_sites = antecedent_call_sites(dag, &fact.provenance_roots);
        let other = if entrypoint == "app1.py" {
            "app2.py"
        } else {
            "app1.py"
        };
        assert!(call_sites.iter().any(|call| call.starts_with(entrypoint)));
        assert!(!call_sites.iter().any(|call| call.starts_with(other)));
    }
}

#[test]
fn reach_supports_operation_filtered_reverse_queries() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-reach-op",
        &[(
            "run.sh",
            "#!/bin/sh\necho started > /opt/data/log\nrm -rf /opt/data\n",
        )],
    );
    let idx = build(&root);
    let sel = Selector::parse("fs:/opt/data").unwrap();

    let deletes = reach(&idx, &sel, Some("delete"));
    assert_eq!(
        deletes.payload.as_reach().unwrap().operation.as_deref(),
        Some("delete")
    );
    assert!(
        deletes
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.operation.as_str() == "filesystem.delete"),
        "delete-only query finds the delete: {:?}",
        deletes.payload.as_reach().unwrap().matches
    );
    assert!(
        deletes.payload.as_reach().unwrap().matches.iter().all(|h| h
            .fact
            .operation
            .as_str()
            .ends_with(".delete")),
        "delete-only query excludes other operations: {:?}",
        deletes.payload.as_reach().unwrap().matches
    );

    let writes = reach(&idx, &sel, Some("write"));
    assert!(
        writes.payload.as_reach().unwrap().matches.iter().any(|h| h
            .fact
            .operation
            .as_str()
            .ends_with(".write")),
        "write-only query finds the redirect write: {:?}",
        writes.payload.as_reach().unwrap().matches
    );
    assert!(
        writes.payload.as_reach().unwrap().matches.iter().all(|h| h
            .fact
            .operation
            .as_str()
            .ends_with(".write"))
    );

    // The unfiltered query sees both.
    let both = reach(&idx, &sel, None);
    assert!(
        both.payload.as_reach().unwrap().matches.len()
            >= deletes.payload.as_reach().unwrap().matches.len()
                + writes.payload.as_reach().unwrap().matches.len()
    );
}

#[test]
fn composed_boundaries_keep_distinct_affected_resources() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-composed-boundary-resources",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom util import go\ngo()\n",
            ),
            (
                "util.py",
                "import subprocess\ndef go():\n    subprocess.run('alpha')\n    subprocess.run('beta')\n",
            ),
        ],
    );
    let idx = build(&root);
    let report = effects_of(&idx, "app.py").unwrap();
    let resources: std::collections::BTreeSet<_> = report
        .payload
        .as_effects()
        .unwrap()
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason == BoundaryReason::UNCOMPOSED_SUBPROCESS)
        .filter_map(|boundary| boundary.affected_resource.as_ref().map(display_resource))
        .collect();

    assert_eq!(
        resources,
        ["proc:alpha".to_string(), "proc:beta".to_string()].into()
    );
}

#[test]
fn boundary_query_keeps_distinct_affected_resources() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-direct-boundary-resources",
        &[(
            "app.py",
            "#!/usr/bin/env python\nimport subprocess\ndef one():\n    subprocess.run('alpha')\ndef two():\n    subprocess.run('beta')\none()\ntwo()\n",
        )],
    );
    let idx = build(&root);
    let report = effects_of(&idx, "app.py").unwrap();
    let resources: std::collections::BTreeSet<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "process.exec")
        .map(|effect| display_resource(&effect.resource))
        .collect();

    assert_eq!(
        resources,
        [
            "proc:alpha @ <cwd>".to_string(),
            "proc:beta @ <cwd>".to_string()
        ]
        .into()
    );
}

#[test]
fn reach_keeps_cross_domain_source_boundaries_without_effect_hits() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-reach-cross-domain-source",
        &[("Makefile", "all:\n\t@echo ready\n")],
    );
    let index = build(&root);
    let all: Vec<_> = index
        .entrypoints
        .iter()
        .filter_map(|analyzed| effects_of(&index, &analyzed.entrypoint.id))
        .flat_map(|report| {
            let entrypoint = report.payload.as_effects().unwrap().entrypoint.clone();
            report
                .payload
                .into_effects()
                .unwrap()
                .boundaries
                .into_iter()
                .map(move |boundary| (entrypoint.clone(), boundary))
        })
        .collect();
    for needle in ["db:public.users", "net:example.com", "env:HOME", "proc:rm"] {
        let selector = Selector::parse(needle).unwrap();
        let expected: Vec<_> = all
            .iter()
            .filter(|(_, boundary)| {
                boundary.reason == BoundaryReason::UNRECOVERABLE_SOURCE
                    && boundary
                        .domains
                        .iter()
                        .any(|domain| domain == selector.domain())
                    && boundary.affected_resource.as_ref().is_some_and(|resource| {
                        effinterp_proto::resource_domain(resource) == Some("filesystem")
                    })
            })
            .collect();
        assert!(!expected.is_empty(), "missing source evidence for {needle}");
        for operation in [None, Some("delete")] {
            let envelope = reach(&index, &selector, operation);
            effinterp_proto::validate_repo_query(&envelope).unwrap();
            let report = envelope.payload.as_reach().unwrap();
            assert!(report.matches.is_empty());
            for (entrypoint, boundary) in &expected {
                assert!(
                    report.indeterminate.iter().any(|row| matches!(
                        row,
                        effinterp_proto::Indeterminate::Boundary { evidence }
                            if evidence.boundary_id == boundary.boundary_id
                                && evidence.entrypoint == *entrypoint
                                && evidence.affected_resource == boundary.affected_resource
                                && evidence.provenance_roots == boundary.provenance_roots
                    )),
                    "source boundary omitted for {needle} with {operation:?}"
                );
                assert!(
                    envelope
                        .boundaries
                        .iter()
                        .any(|row| row.id == boundary.boundary_id.0)
                );
            }
            assert_ne!(
                envelope.coverage.domains[selector.domain()].level,
                CoverageLevel::Full
            );
        }
    }
}

#[test]
fn every_non_full_domain_is_explained_by_a_retained_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-nonredundant-reasons",
        &[(
            "app.py",
            "#!/usr/bin/env python\nimport socket\nsocket.create_connection((\"db\", 5432))\n",
        )],
    );
    let idx = build(&root);
    let envelope = effinterp_repo::effects_of(&idx, "app.py").expect("app.py analyzes");

    assert!(
        envelope
            .boundaries
            .iter()
            .any(|b| b.domains == vec!["network".to_string()]),
        "the socket call is a network-only boundary: {:?}",
        envelope.boundaries
    );
    let effinterp_proto::AnalysisStatus::Partial { reasons } = &envelope.status else {
        panic!("an unmodeled external call leaves the analysis partial");
    };
    assert!(!reasons.is_empty());
    let explained: std::collections::BTreeSet<&str> = envelope
        .boundaries
        .iter()
        .flat_map(|boundary| boundary.domains.iter().map(String::as_str))
        .collect();
    assert!(envelope.coverage.domains.iter().all(|(domain, level)| {
        level.level == effinterp_proto::CoverageLevel::Full || explained.contains(domain.as_str())
    }));
}

/// The status of a repository-wide reverse query, which answers for every
/// entrypoint and every skipped input that could be one.
fn repository_status(index: &effinterp_repo::RepoIndex) -> AnalysisStatus {
    reach(index, &Selector::parse("fs:/**").unwrap(), None).status
}

#[test]
fn skipped_source_uncertainty_only_reaches_semantic_dependents() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-scoped-skipped-source",
        &[
            (
                "main.py",
                "#!/usr/bin/env python3\nimport skipped\nprint('main')\n",
            ),
            ("independent.sh", "#!/bin/sh\necho independent\n"),
        ],
    );
    std::fs::write(root.join("skipped.py"), "#".repeat(256)).unwrap();
    std::fs::create_dir_all(root.join("tests/fixtures")).unwrap();
    std::fs::write(root.join("tests/fixtures/unrelated.py"), [0xff, 0xfe]).unwrap();
    let index = build_index(
        &root,
        IndexLimits {
            crawl: effinterp_repo::CrawlLimits {
                max_file_bytes: 128,
                ..Default::default()
            },
            ..IndexLimits::default()
        },
    );

    assert!(matches!(
        index.snapshot_state,
        AnalysisStatus::Partial { .. }
    ));
    assert!(
        index
            .dependency_manifest
            .get("skipped-source:skipped.py")
            .is_some()
    );
    assert_eq!(
        index.skipped_dependencies["skipped.py"],
        ["main.py".to_string()]
    );
    assert!(index.skipped_dependencies["tests/fixtures/unrelated.py"].is_empty());
    let skipped_reason = &index
        .skipped
        .iter()
        .find(|skip| skip.path == "skipped.py")
        .unwrap()
        .reason;

    let independent = effects_of(&index, "independent.sh").unwrap();
    assert!(matches!(independent.status, AnalysisStatus::Complete));

    let dependent = effects_of(&index, "main.py").unwrap();
    assert!(matches!(
        &dependent.status,
        AnalysisStatus::Partial { reasons }
            if reasons.iter().any(|reason| matches!(reason,
                PartialReason::LimitReached { limit, scope }
                    if limit == skipped_reason
                        && scope.entrypoints == ["main.py"]))
    ));
}

#[test]
fn repository_wide_query_stays_partial_when_a_skipped_source_could_be_an_entrypoint() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-skipped-possible-entrypoint",
        &[("independent.sh", "#!/bin/sh\necho independent\n")],
    );
    std::fs::write(root.join("hidden_entry.py"), [0xff, 0xfe]).unwrap();
    let index = build(&root);

    assert!(index.skipped_dependencies["hidden_entry.py"].is_empty());
    assert!(!index.skipped_roots.contains("hidden_entry.py"));
    assert!(matches!(
        repository_status(&index),
        AnalysisStatus::Partial { reasons }
            if reasons.iter().any(|reason| matches!(reason,
                PartialReason::UnanalyzedInput { path, .. } if path == "hidden_entry.py"))
    ));
    assert!(matches!(
        effects_of(&index, "independent.sh").unwrap().status,
        AnalysisStatus::Complete
    ));
    let no_hits = reach(
        &index,
        &Selector::parse("fs:/**").unwrap(),
        Some("database.delete"),
    );
    assert!(no_hits.payload.as_reach().unwrap().matches.is_empty());
    assert!(matches!(no_hits.status, AnalysisStatus::Partial { .. }));
    assert!(
        no_hits
            .coverage
            .domains
            .values()
            .all(|claim| claim.level != effinterp_proto::CoverageLevel::Full)
    );
}

#[test]
fn skipped_shell_source_uncertainty_reaches_its_dependent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-skipped-shell-source",
        &[
            ("app.sh", "#!/bin/sh\n. ./lib.sh\nhelper\n"),
            ("independent.sh", "#!/bin/sh\necho independent\n"),
        ],
    );
    std::fs::write(root.join("lib.sh"), [0xff, 0xfe]).unwrap();
    let mut index = build(&root);

    assert_eq!(index.skipped_dependencies["lib.sh"], ["app.sh".to_string()]);
    let dependent = effects_of(&index, "app.sh").unwrap();
    assert!(matches!(
        &dependent.status,
        AnalysisStatus::Partial { reasons }
            if reasons.iter().any(|reason| matches!(reason,
                PartialReason::UnanalyzedInput { path, scope }
                    if path == "lib.sh" && scope.entrypoints == ["app.sh"]))
    ));
    assert!(matches!(
        effects_of(&index, "independent.sh").unwrap().status,
        AnalysisStatus::Complete
    ));

    index
        .skipped
        .iter_mut()
        .find(|skip| skip.path == "lib.sh")
        .unwrap()
        .category = effinterp_repo::SkipCategory::Ignored;
    let ignored = effects_of(&index, "app.sh").unwrap();
    assert!(matches!(ignored.status, AnalysisStatus::Partial { .. }));
    assert!(
        ignored
            .coverage
            .domains
            .values()
            .all(|claim| claim.level != effinterp_proto::CoverageLevel::Full)
    );
    assert!(matches!(
        effects_of(&index, "independent.sh").unwrap().status,
        AnalysisStatus::Complete
    ));
}

#[test]
fn skipped_launch_alternative_taints_only_its_wrapper() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-scoped-skipped-launch",
        &[
            (
                "package.json",
                r#"{"bin":{"tool":"bad.js"},"scripts":{"run":"if [ \"$MODE\" = good ]; then SCRIPT=good.py; else SCRIPT=bad.py; fi; python3 \"$SCRIPT\""}}"#,
            ),
            ("good.py", "print('good')\n"),
            ("independent.sh", "#!/bin/sh\necho independent\n"),
        ],
    );
    std::fs::write(root.join("bad.py"), [0xff, 0xfe]).unwrap();
    std::fs::write(root.join("bad.js"), [0xff, 0xfe]).unwrap();
    let index = build(&root);

    assert_eq!(
        index.skipped_dependencies["bad.py"],
        ["package.json:scripts.run".to_string()]
    );
    assert!(index.skipped_roots.contains("bad.js"));
    assert!(matches!(
        effects_of(&index, "package.json:scripts.run")
            .unwrap()
            .status,
        AnalysisStatus::Partial { reasons }
            if reasons.iter().any(|reason| matches!(reason,
                PartialReason::UnanalyzedInput { path, .. } if path == "bad.py"))
    ));
    assert!(matches!(
        effects_of(&index, "independent.sh").unwrap().status,
        AnalysisStatus::Complete
    ));
    assert!(matches!(
        repository_status(&index),
        AnalysisStatus::Partial { reasons }
            if reasons.iter().any(|reason| matches!(reason,
                PartialReason::UnanalyzedInput { path, .. } if path == "bad.js"))
    ));
}

#[test]
fn full_zero_effects_requires_every_selected_root_to_claim_the_domain() {
    use effinterp_proto::{
        BoundaryClass, CoverageClaim, CoverageLevel, Domain, validate_repo_query,
    };
    use effinterp_repo::EntrypointOutcome;
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-contributing-claims",
        &[
            ("full.sh", "#!/bin/sh\n"),
            ("empty.sh", "#!/bin/sh\n"),
            ("failed.sh", "#!/bin/sh\n"),
        ],
    );
    let mut index = build(&root);
    for entry in &mut index.entrypoints {
        let EntrypointOutcome::Analyzed { plan } = &mut entry.outcome else {
            panic!("empty shell analyzes");
        };
        plan.coverage.0.clear();
        plan.boundaries.clear();
        plan.effects.clear();
        if entry.entrypoint.id == "full.sh" {
            plan.coverage.0.insert(
                Domain::new("filesystem"),
                CoverageClaim {
                    level: CoverageLevel::Full,
                    gaps: vec![],
                },
            );
        }
    }
    let full = effects_of(&index, "full.sh").unwrap();
    assert!(full.payload.as_effects().unwrap().effects.is_empty());
    assert_eq!(
        full.coverage.domains["filesystem"].level,
        CoverageLevel::Full
    );
    validate_repo_query(&full).unwrap();
    let empty = effects_of(&index, "empty.sh").unwrap();
    assert!(empty.coverage.domains.is_empty());
    validate_repo_query(&empty).unwrap();

    let all = reach(&index, &Selector::parse("fs:/**").unwrap(), None);
    assert_eq!(
        all.coverage.domains["filesystem"].level,
        CoverageLevel::Partial
    );
    assert!(!all.coverage.domains["filesystem"].gaps.is_empty());
    assert!(
        all.boundaries
            .iter()
            .any(|boundary| boundary.class == BoundaryClass::Unmodeled)
    );
    validate_repo_query(&all).unwrap();

    index
        .entrypoints
        .iter_mut()
        .find(|entry| entry.entrypoint.id == "failed.sh")
        .unwrap()
        .outcome = EntrypointOutcome::Failed {
        error: "parse failed".to_string(),
    };
    let independent = effects_of(&index, "full.sh").unwrap();
    assert_eq!(full.to_canonical_json(), independent.to_canonical_json());
    let all = reach(&index, &Selector::parse("fs:/**").unwrap(), None);
    assert!(
        all.boundaries
            .iter()
            .any(|boundary| boundary.class == BoundaryClass::ParseFailure)
    );
    validate_repo_query(&all).unwrap();
}

#[test]
fn causal_limit_gaps_preserve_independent_full_effect_coverage() {
    use effinterp_proto::{
        Boundary, BoundaryClass, BoundaryReason, BoundaryRef, CoverageClaim, CoverageLevel, Domain,
        validate_repo_query,
    };
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-causal-gap",
        &[("empty.sh", "#!/bin/sh\n")],
    );
    let mut index = build(&root);
    let effinterp_repo::EntrypointOutcome::Analyzed { plan } = &mut index.entrypoints[0].outcome
    else {
        panic!("shell analyzes");
    };
    plan.coverage.0.clear();
    plan.coverage.0.insert(
        Domain::new("filesystem"),
        CoverageClaim {
            level: CoverageLevel::Full,
            gaps: vec![],
        },
    );
    plan.boundaries = vec![Boundary {
        class: BoundaryClass::Limit,
        scope: effinterp_proto::BoundaryScope::Invocation,
        reason: BoundaryReason::LIMIT_SATURATED,
        domains: vec![Domain::new("dataflow")],
        affected_resource: None,
        callee: None,
        provenance: vec![],
        limit: Some("max_effects".to_string()),
        detail: Some("causal traversal exhausted".to_string()),
    }];
    plan.causality.coverage = CoverageClaim {
        level: CoverageLevel::Partial,
        gaps: vec![BoundaryRef(0)],
    };
    let answer = effects_of(&index, "empty.sh").unwrap();
    assert_eq!(
        answer.coverage.domains["filesystem"].level,
        CoverageLevel::Full
    );
    assert!(answer.coverage.domains["filesystem"].gaps.is_empty());
    assert_eq!(
        answer.coverage.causality.as_ref().unwrap().gaps,
        [answer.boundaries[0].id.clone()]
    );
    assert_eq!(answer.boundaries[0].class, BoundaryClass::Limit);
    validate_repo_query(&answer).unwrap();
}

#[test]
fn effects_identity_does_not_grow_with_unrelated_sources() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-scoped-identity",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let before = build(&root);
    let mut effects_before = effects_of(&before, "app.py").unwrap();
    for i in 0..20 {
        std::fs::write(
            root.join(format!("unrelated-{i}.py")),
            format!("print({i})\n"),
        )
        .unwrap();
    }
    let after = build(&root);
    let mut effects_after = effects_of(&after, "app.py").unwrap();
    for envelope in [&effects_before, &effects_after] {
        effinterp_proto::validate_repo_query(envelope).unwrap();
        assert_eq!(
            envelope.provenance.nodes.len(),
            envelope
                .provenance
                .reachable_nodes(&envelope.payload, &envelope.boundaries)
                .len()
        );
    }
    assert_ne!(effects_before.snapshot_id, effects_after.snapshot_id);
    effects_before.snapshot_id.clear();
    effects_before.content_hash.clear();
    effects_after.snapshot_id.clear();
    effects_after.content_hash.clear();
    assert_eq!(
        effects_before.to_canonical_json(),
        effects_after.to_canonical_json()
    );
}

#[test]
fn reach_effect_proofs_agree_with_proto_and_keep_unknown_effects_separate() {
    use effinterp_proto::{Bindings, EffectQuery, Indeterminate, Match, PathPlatform, Scope};
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-shared-match",
        &[(
            "run.sh",
            "#!/bin/sh\nrm -rf /tmp/output\nrm -rf \"$OUTPUT_DIR\"\nmystery-command\n",
        )],
    );
    let index = build(&root);
    let forward = effects_of(&index, "run.sh").unwrap();
    for needle in ["fs:/tmp/output/.hidden/nested", "fs:/outside"] {
        let selector = Selector::parse(needle).unwrap();
        let report = reach(&index, &selector, Some("filesystem.delete"));
        effinterp_proto::validate_repo_query(&report).unwrap();
        let rows = report.payload.as_reach().unwrap();
        for fact in &forward.payload.as_effects().unwrap().effects {
            if fact.operation.0 != "filesystem.delete" {
                continue;
            }
            let query = EffectQuery::Intersects {
                scope: Scope {
                    realm: None,
                    set: selector.scope_set().unwrap(),
                },
            };
            let expected = query.evaluate(fact.into(), &Bindings::none(PathPlatform::Posix));
            match &expected {
                Match::Satisfied { .. } => assert!(rows.matches.iter().any(|row| row.fact == *fact && row.matched == expected)),
                Match::Indeterminate { .. } => assert!(rows.indeterminate.iter().any(|row| matches!(row, Indeterminate::Effect { fact: actual, matched, .. } if actual == fact && matched == &expected))),
                Match::NotSatisfied => assert!(!rows.matches.iter().any(|row| row.fact == *fact)),
            }
        }
        assert!(
            rows.indeterminate
                .iter()
                .any(|row| matches!(row, Indeterminate::Boundary { .. }))
        );
        assert!(!report.boundaries.is_empty());
        let mut obsolete = serde_json::to_value(&report).unwrap();
        if let Some(row) = obsolete["payload"]["matches"]
            .as_array_mut()
            .unwrap()
            .first_mut()
        {
            row.as_object_mut().unwrap().remove("match");
            row["match_kind"] = "concrete".into();
            assert!(effinterp_proto::from_repo_query_json(&obsolete.to_string()).is_err());
        }
    }
}

#[test]
fn failed_limited_and_unclaimed_entrypoints_claim_no_coverage() {
    use effinterp_proto::validate_repo_query;
    use effinterp_repo::EntrypointOutcome;
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-entrypoint-inventory",
        &[
            ("direct.sh", "#!/bin/sh\nrm /direct\n"),
            ("opaque.sh", "#!/bin/sh\npython -m unknown_module\n"),
            ("failed.sh", "#!/bin/sh\ntrue\n"),
            ("limited.sh", "#!/bin/sh\ntrue\n"),
            ("unclaimed.sh", "#!/bin/sh\ntrue\n"),
        ],
    );
    let mut index = build(&root);
    for entry in &mut index.entrypoints {
        match entry.entrypoint.id.as_str() {
            "failed.sh" => {
                entry.outcome = EntrypointOutcome::Failed {
                    error: "parse failure".into(),
                }
            }
            "limited.sh" => {
                entry.outcome = EntrypointOutcome::LimitReached {
                    limit: "repository.max_work_units".into(),
                }
            }
            "unclaimed.sh" => {
                if let EntrypointOutcome::Analyzed { plan } = &mut entry.outcome {
                    plan.coverage.0.clear();
                }
            }
            _ => (),
        }
    }
    for analyzed in &index.entrypoints {
        let id = analyzed.entrypoint.id.as_str();
        let report = effects_of(&index, id);
        match id {
            "failed.sh" | "limited.sh" => assert!(report.is_none(), "{id}"),
            _ => {
                let report = report.unwrap();
                validate_repo_query(&report).unwrap();
                let levels: Vec<_> = report
                    .coverage
                    .domains
                    .values()
                    .map(|claim| claim.level)
                    .collect();
                match id {
                    "unclaimed.sh" => assert!(levels.is_empty()),
                    "direct.sh" => {
                        assert!(levels.iter().all(|level| *level == CoverageLevel::Full))
                    }
                    "opaque.sh" => assert!(levels.contains(&CoverageLevel::Partial)),
                    _ => unreachable!(),
                }
            }
        }
    }
    assert!(matches!(
        repository_status(&index),
        AnalysisStatus::Partial { .. }
    ));
}

#[test]
fn reach_compound_verbs_preserve_facts_and_collapse_boundary_reasons() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "qs-reach-compound",
        &[(
            "run.sh",
            "#!/bin/sh\ngit -C /repo config user.name one\n. ./helper.sh\ngit -C /repo add .\ngit -C /repo checkout main\ngit -C /repo reset --hard\nmystery-command\nmystery-command\n",
        )],
    );
    std::fs::write(
        root.join("helper.sh"),
        "#!/bin/sh\ngit -C /repo config user.name two\n",
    )
    .unwrap();

    let index = build(&root);
    let selector = Selector::parse("git:/repo").unwrap();
    let all = reach(&index, &selector, None);
    let writes = reach(&index, &selector, Some("write"));
    effinterp_proto::validate_repo_query(&writes).unwrap();
    let hits = &writes.payload.as_reach().unwrap().matches;
    for operation in ["git.config_write", "git.index_write", "git.worktree_write"] {
        assert!(
            hits.iter()
                .any(|hit| hit.fact.operation.as_str() == operation),
            "{operation}: {hits:?}"
        );
    }
    let configs = reach(&index, &selector, Some("config_write"));
    assert_eq!(
        configs.payload.as_reach().unwrap().matches,
        hits.iter()
            .filter(|hit| hit.fact.operation.as_str() == "git.config_write")
            .cloned()
            .collect::<Vec<_>>()
    );
    assert_eq!(
        configs
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .filter(|hit| hit.fact.entrypoint == "run.sh")
            .count(),
        2,
    );
    assert!(
        all.payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.operation.as_str() == "git.worktree_discard")
    );
    let deletes = reach(&index, &selector, Some("delete"));
    assert!(
        deletes
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .all(|hit| hit.fact.operation.as_str() != "git.worktree_discard")
    );
    assert_eq!(all.boundaries, writes.boundaries);
    let boundary_query = effects_of(&index, "run.sh").unwrap();
    let expected_ids: std::collections::BTreeSet<_> = boundary_query
        .boundaries
        .iter()
        .filter(|boundary| boundary.domains.iter().any(|domain| domain == "git"))
        .map(|boundary| &boundary.id)
        .collect();
    assert_eq!(
        all.boundaries
            .iter()
            .filter(|boundary| boundary.domains.iter().any(|domain| domain == "git"))
            .map(|boundary| &boundary.id)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_ids,
    );
    let report = all.payload.as_reach().unwrap();
    let rows: Vec<_> = report
        .indeterminate
        .iter()
        .filter_map(|row| match row {
            effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
            _ => None,
        })
        .collect();
    assert!(!rows.is_empty());
    let keys: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|row| {
            effinterp_proto::canonical_json(&(
                &row.entrypoint,
                &row.boundary_reason,
                &row.boundary_detail,
                &row.affected_resource,
            ))
        })
        .collect();
    assert_eq!(keys.len(), rows.len());
    assert!(
        all.boundaries.len() > rows.len(),
        "distinct provenance remains in the envelope"
    );
}
