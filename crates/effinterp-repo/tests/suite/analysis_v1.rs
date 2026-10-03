#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_proto::{
    AnalysisStatus, ExecutionAssurance, PartialReason, REPO_QUERY_SCHEMA_V1, RepoQueryEnvelope,
    RepoQueryValidationError, Subject, display_resource, from_repo_query_json, validate_repo_query,
};
use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::{origin_effects, plan_causality, plan_execution};

fn fixture(tag: &str) -> PathBuf {
    repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[
            ("run.sh", "#!/bin/sh\nprintf data | cat > /tmp/out\n"),
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom util import wipe\nwipe('/tmp/cache')\n",
            ),
            (
                "util.py",
                "import os\ndef wipe(path):\n    os.remove(path)\n",
            ),
            ("opaque.sh", "#!/bin/sh\nmystery-command --write /tmp/out\n"),
        ],
    )
}

fn checked(envelope: &RepoQueryEnvelope) -> String {
    assert_eq!(envelope.schema, REPO_QUERY_SCHEMA_V1);
    assert!(matches!(
        envelope.status,
        AnalysisStatus::Complete | AnalysisStatus::Partial { .. }
    ));
    validate_repo_query(envelope).unwrap();
    let text = envelope.to_canonical_json();
    assert!(text.ends_with('\n'));
    effinterp_conformance::validate_conformance_bytes(text.as_bytes()).unwrap();
    let parsed: RepoQueryEnvelope = from_repo_query_json(&text).unwrap();
    assert_eq!(parsed.to_canonical_json(), text);
    text
}

#[test]
fn a_narrowed_boundary_still_backs_the_coverage_it_reports() {
    // The only process-domain boundary here carries a typed resource, so a
    // reverse query for a different command narrows it out of the payload. The
    // coverage it caused is still reported, so it must remain envelope
    // evidence or the envelope contradicts itself.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-narrowed-boundary",
        &[(
            "app.js",
            "const { execSync } = require('child_process');\nfunction one() { execSync('git'); }\none();\n",
        )],
    );
    let live = build_index(&root, IndexLimits::default());
    let selector = ResourceSelector::parse("proc:beta").unwrap();
    let report = reach(&live, &selector, None);
    assert_ne!(
        report
            .coverage
            .domains
            .get("process")
            .map(|claim| &claim.level),
        Some(&effinterp_proto::CoverageLevel::Full),
        "the modeled command leaves the process domain non-full"
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.affected_resource.is_some()),
        "the narrowed boundary stays in the envelope: {:?}",
        report.boundaries
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .indeterminate
            .iter()
            .filter_map(|row| match row {
                effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
                _ => None,
            })
            .all(|hit| hit.affected_resource.is_none()),
        "a boundary for another command does not answer this selector: {:?}",
        report.payload.as_reach().unwrap().indeterminate
    );
    checked(&report);
}

#[test]
fn effects_coverage_agrees_with_composed_boundaries() {
    // effects_of reports the composed surface's boundaries, so it must report
    // that surface's coverage too: a boundary introduced by composition cannot
    // sit beside a Full domain.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-execution-coverage",
        &[(
            "app.js",
            "const { execSync } = require('child_process');\nfunction one() { execSync('git'); }\none();\n",
        )],
    );
    let live = build_index(&root, IndexLimits::default());
    let report = effects_of(&live, "app.js").unwrap();
    assert!(
        !report.boundaries.is_empty(),
        "the composed subprocess boundary reaches the entrypoint"
    );
    checked(&report);
}

#[test]
fn every_query_envelope_binds_the_index_snapshot() {
    let root = fixture("analysis-protocol-live-loaded");
    let live = build_index(&root, IndexLimits::default());

    for entrypoint in ["run.sh", "app.py", "opaque.sh"] {
        let report = effects_of(&live, entrypoint).unwrap();
        assert_eq!(report.snapshot_id, live.fingerprint);
        checked(&report);
    }
    let selector = ResourceSelector::parse("fs:/tmp/cache").unwrap();
    let report = reach(&live, &selector, Some("delete"));
    assert_eq!(report.snapshot_id, live.fingerprint);
    checked(&report);
}

#[test]
fn realistic_protocol_payloads_are_canonical_and_valid() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-realistic-payloads",
        &[
            ("local.sh", "#!/bin/sh\nprintf '%s\\n' \"$HOME\"\n"),
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom re import compile\ncompile('x')\n",
            ),
            (
                ".github/workflows/check.yml",
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          CURRENT_TAG: ${{ steps.current.outputs.tag }}\n          LATEST_TAG: ${{ steps.latest.outputs.tag }}\n        run: |\n          sed -i \"s/${CURRENT_TAG}/${LATEST_TAG}/\" target.txt\n          mdbook build book/en\n          mdbook build book/zh\n          printf '%s\\n' \"$HOME\"\n",
            ),
            (
                "quoted.sh",
                "#!/usr/bin/env bash\nargs=()\nif [ -n \"${TOKEN:-}\" ]; then\n  args+=(--header \"Authorization: Bearer $TOKEN\")\nfi\ncurl --proto =https --tlsv1.2 -sSfL ${args[@]+\"${args[@]}\"} \"$URL\" -o\"$OUTPUT\"\ncurl --proto =https --tlsv1.2 -sSfL \"https://example.com\" -o-\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let workflow = ".github/workflows/check.yml:run.1";

    let effects = effects_of(&index, workflow).unwrap();
    checked(&effects);
    assert_eq!(
        effects
            .payload.as_effects().unwrap()
            .boundaries
            .iter()
            .filter(|boundary| boundary.detail.as_deref() == Some("no model for command \"mdbook\""))
            .count(),
        2
    );

    let process_reach = reach(&index, &ResourceSelector::parse("proc:*").unwrap(), None);
    let reached_resources: Vec<_> = process_reach
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .filter(|hit| hit.fact.operation.0 == "process.exec")
        .map(|hit| display_resource(&hit.fact.resource))
        .collect();
    assert_eq!(reached_resources.len(), 2);
    let rows = &process_reach.payload.as_reach().unwrap().matches;
    assert!(effinterp_proto::canonical_json(&rows[0]) < effinterp_proto::canonical_json(&rows[1]));
    checked(&process_reach);

    let inert = effects_of(&index, "app.py").unwrap();
    checked(&inert);
    assert!(
        inert
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| !boundary.domains.is_empty())
    );
    assert!(
        inert
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "external_inert")
    );
}

#[test]
fn duplicate_subject_selection_is_insertion_order_independent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-duplicate-subjects",
        &[("run.sh", "#!/bin/sh\nprintf data > /dev/null\n")],
    );
    let mut first = build_index(&root, IndexLimits::default());
    let mut duplicate = first.entrypoints[0].clone();
    duplicate.entrypoint.subject = Subject::Shell {
        source: "printf different > /dev/null\n".to_string(),
        cwd: None,
        context: Default::default(),
    };
    first.entrypoints.push(duplicate);
    let mut second = first.clone();
    second.entrypoints.reverse();

    let first = effects_of(&first, "run.sh").unwrap();
    let second = effects_of(&second, "run.sh").unwrap();
    assert_eq!(first.subjects.len(), 1);
    assert_eq!(checked(&first), checked(&second));
}

#[test]
fn nondirectory_root_reports_a_canonical_partial_path() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-nondirectory-root",
        &[("not-a-repository", "plain file\n")],
    );
    let index = build_index(&root.join("not-a-repository"), IndexLimits::default());
    assert!(
        index
            .skipped
            .iter()
            .any(|skip| skip.path == ".effinterp-root")
    );

    let report = reach(&index, &ResourceSelector::parse("fs:/**").unwrap(), None);
    assert!(matches!(&report.status, AnalysisStatus::Partial { reasons }
        if reasons.iter().any(|reason| matches!(reason,
            PartialReason::UnanalyzedInput { path, .. } if path == ".effinterp-root"))));
    checked(&report);
}

#[test]
fn repeated_calls_tied_effects_and_widened_execution_conform() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-real-input-shapes",
        &[
            (
                "repeated.js",
                "const { execSync } = require('child_process');\nfunction main() { execSync('rm -f /tmp/stale.lock'); }\nmain();\nmain();\n",
            ),
            (
                "conditional.sh",
                "#!/bin/sh\nif test \"$MODE\" = one; then\n  printf one > /dev/null\nelse\n  printf two > /dev/null\nfi\n",
            ),
            ("cycle.sh", "#!/bin/sh\n. ./a.sh\n"),
            ("a.sh", ". ./b.sh\n"),
            ("b.sh", ". ./a.sh\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    let repeated = plan_causality(&index, "repeated.js").unwrap();
    let edge_ids: std::collections::BTreeSet<_> = repeated
        .edges
        .iter()
        .map(|edge| (&edge.from, &edge.to, edge.reason))
        .collect();
    assert_eq!(edge_ids.len(), repeated.edges.len());

    let conditional = effects_of(&index, "conditional.sh").unwrap();
    let tied: Vec<_> = conditional
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| {
            effect.operation.0 == "filesystem.write"
                && display_resource(&effect.resource) == "fs:/dev/null"
        })
        .collect();
    assert_eq!(tied.len(), 2);
    let legacy_keys: std::collections::BTreeSet<_> = tied
        .iter()
        .map(|effect| {
            serde_json::to_string(&serde_json::json!([
                effect.origin,
                effect.operation,
                effect.resource,
                effect.realm,
                effect.dispatch,
            ]))
            .unwrap()
        })
        .collect();
    assert_eq!(legacy_keys.len(), 1);
    assert_ne!(tied[0].fact_id, tied[1].fact_id);
    checked(&conditional);

    let widened = plan_execution(&index, "cycle.sh").unwrap();
    assert!(
        widened
            .graph
            .nodes
            .iter()
            .any(|node| node.assurance == ExecutionAssurance::Widened)
    );
}

#[test]
fn reach_retains_distinct_indeterminate_boundaries() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-distinct-indeterminate",
        &[(
            "run.sh",
            "#!/bin/sh\nunknown-alpha /tmp/target\nunknown-beta /tmp/target\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/tmp/target").unwrap(),
        None,
    );

    checked(&report);
    assert_eq!(report.payload.as_reach().unwrap().indeterminate.len(), 2);
    let boundaries: Vec<_> = report
        .payload
        .as_reach()
        .unwrap()
        .indeterminate
        .iter()
        .filter_map(|row| match row {
            effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
            _ => None,
        })
        .collect();
    assert_ne!(boundaries[0].boundary_id, boundaries[1].boundary_id);
    assert_ne!(boundaries[0].boundary_detail, boundaries[1].boundary_detail);
}

#[test]
fn indeterminate_entrypoints_use_compact_json_order() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-indeterminate-order",
        &[
            ("opaque\".sh", "#!/bin/sh\nunknown-alpha /tmp/target\n"),
            ("opaque<.sh", "#!/bin/sh\nunknown-beta /tmp/target\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/tmp/target").unwrap(),
        None,
    );
    let entrypoints: Vec<_> = report
        .payload
        .as_reach()
        .unwrap()
        .indeterminate
        .iter()
        .filter_map(|row| match row {
            effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
            _ => None,
        })
        .map(|row| row.entrypoint.as_str())
        .collect();

    assert_eq!(entrypoints.len(), 2);
    let rows = &report.payload.as_reach().unwrap().indeterminate;
    assert!(effinterp_proto::canonical_json(&rows[0]) < effinterp_proto::canonical_json(&rows[1]));
    checked(&report);
}

#[test]
fn identities_are_repeatable_and_semantic_changes_move_them() {
    let root = fixture("analysis-protocol-identities");
    let first = build_index(&root, IndexLimits::default());
    let second = build_index(&root, IndexLimits::default());
    let first_report = effects_of(&first, "app.py").unwrap();
    let second_report = effects_of(&second, "app.py").unwrap();
    assert_eq!(checked(&first_report), checked(&second_report));

    let mut tampered: RepoQueryEnvelope =
        serde_json::from_value(serde_json::to_value(&first_report).unwrap()).unwrap();
    let effinterp_proto::Payload::Effects(payload) = &mut tampered.payload else {
        panic!("effects report");
    };
    payload.effects[0].operation = effinterp_proto::Operation::new("filesystem.create");
    tampered.reseal();
    assert!(validate_repo_query(&tampered)
        .unwrap_err()
        .iter()
        .any(|error| matches!(error, RepoQueryValidationError::InvalidPayload { path } if path.ends_with(".fact_id"))));

    std::fs::write(
        root.join("util.py"),
        "import os\ndef wipe(path):\n    os.rmdir(path)\n",
    )
    .unwrap();
    let changed = build_index(&root, IndexLimits::default());
    let changed_report = effects_of(&changed, "app.py").unwrap();
    assert_ne!(first_report.snapshot_id, changed_report.snapshot_id);
    assert_ne!(first_report.content_hash, changed_report.content_hash);
    assert_ne!(
        first_report.payload.as_effects().unwrap().effects[0].fact_id,
        changed_report.payload.as_effects().unwrap().effects[0].fact_id
    );
}

/// Fact ids, not row positions, are the stable handle: forward and reverse
/// queries spell one fact the same way.
#[test]
fn fact_ids_are_the_stable_handle_across_query_families() {
    let root = fixture("analysis-protocol-fact-handles");
    std::fs::write(
        root.join("app.py"),
        "#!/usr/bin/env python3\nfrom util import wipe, clean\nwipe('/tmp/cache')\nclean('/tmp/cache')\n",
    )
    .unwrap();
    std::fs::write(
        root.join("util.py"),
        "import os\ndef wipe(path):\n    os.remove(path)\ndef clean(path):\n    os.remove(path)\n",
    )
    .unwrap();
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects;
    let delete = effects
        .iter()
        .find(|fact| fact.operation.0 == "filesystem.delete")
        .expect("app.py deletes through util.wipe");

    // Both helpers perform the same delete, so the row is one fact that
    // either function's origin selects.
    for function in ["wipe", "clean"] {
        assert_eq!(
            origin_effects(&index, "util.py", Some(function)),
            vec![delete.clone()]
        );
    }
    assert_eq!(delete.occurrences, 2);
    // Reach reuses the same fact rather than re-describing it.
    let reach_row = reach(
        &index,
        &ResourceSelector::parse("fs:/tmp/cache").unwrap(),
        None,
    )
    .payload
    .into_reach()
    .unwrap()
    .matches
    .into_iter()
    .find(|hit| hit.fact.fact_id == delete.fact_id)
    .expect("the reach match is the same fact");
    assert_eq!(&reach_row.fact, delete);
}

#[test]
fn relocation_insertion_order_and_configuration_have_explicit_v1_identity() {
    let files = [
        (
            "a.py",
            "#!/usr/bin/env python3\nfrom b import wipe\nwipe('/tmp/a')\n",
        ),
        ("b.py", "import os\ndef wipe(path):\n    os.remove(path)\n"),
    ];
    let relocated = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-v1-relocated-a",
        &files,
    );
    let reversed = [files[1], files[0]];
    let reordered = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-v1-relocated-b",
        &reversed,
    );
    let first = build_index(&relocated, IndexLimits::default());
    let second = build_index(&reordered, IndexLimits::default());
    let first_report = effects_of(&first, "a.py").unwrap();
    let second_report = effects_of(&second, "a.py").unwrap();

    assert_eq!(checked(&first_report), checked(&second_report));
    assert_eq!(
        first_report.identity.model_set_digest,
        first.model_set.strip_prefix("builtin:").unwrap()
    );
    assert!(
        first_report
            .identity
            .analyzer
            .build_digest
            .starts_with("blake3:")
    );
    assert_ne!(
        first_report.identity.analyzer.build_digest,
        format!(
            "blake3:{}",
            blake3::hash(first.analyzer.as_bytes()).to_hex()
        )
    );
    assert!(
        first_report
            .identity
            .dependencies
            .iter()
            .any(|dependency| dependency.key == "source:a.py")
    );
    assert_eq!(
        first_report
            .identity
            .dependencies
            .iter()
            .find(|dependency| dependency.key == "analyzer")
            .unwrap()
            .digest,
        first_report.identity.analyzer.build_digest
    );
    assert_eq!(
        first_report
            .identity
            .dependencies
            .iter()
            .find(|dependency| dependency.key == "model-set")
            .unwrap()
            .digest,
        first_report.identity.model_set_digest
    );
    assert!(
        first_report
            .subjects
            .iter()
            .any(|subject| subject.entrypoint == "a.py" && subject.source_path == "a.py")
    );

    let changed_limits = build_index(
        &relocated,
        IndexLimits {
            crawl: effinterp_repo::CrawlLimits {
                max_depth: effinterp_repo::CrawlLimits::default().max_depth - 1,
                ..Default::default()
            },
            ..IndexLimits::default()
        },
    );
    let changed_report = effects_of(&changed_limits, "a.py").unwrap();
    assert_ne!(
        first_report.identity.configuration_digest,
        changed_report.identity.configuration_digest
    );
    assert_ne!(first_report.snapshot_id, changed_report.snapshot_id);
}

#[cfg(unix)]
#[test]
fn noncanonical_repository_paths_fail_closed_without_shadowing_sources() {
    use std::collections::BTreeSet;

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-v1-path-collisions",
        &[("scripts/back/slash.sh", "#!/bin/sh\ncat /etc/passwd\n")],
    );
    std::fs::write(
        root.join("scripts/back\\slash.sh"),
        "#!/bin/sh\nrm -rf /tmp/shadowed\n",
    )
    .unwrap();
    // APFS refuses invalid UTF-8 filenames before the analyzer can observe them.
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        std::fs::write(
            root.join("scripts")
                .join(OsString::from_vec(b"invalid\xff.sh".to_vec())),
            "#!/bin/sh\nrm -rf /tmp/invalid\n",
        )
        .unwrap();
    }
    let rejected_count = 1 + usize::from(cfg!(target_os = "linux"));

    let index = build_index(&root, IndexLimits::default());
    assert_eq!(
        index
            .entrypoints
            .iter()
            .map(|entrypoint| entrypoint.entrypoint.id.as_str())
            .collect::<Vec<_>>(),
        ["scripts/back/slash.sh"]
    );
    let rejected: BTreeSet<_> = index
        .skipped
        .iter()
        .filter(|skip| skip.reason.contains("repository path"))
        .map(|skip| skip.path.as_str())
        .collect();
    assert_eq!(rejected.len(), rejected_count);
    assert!(
        rejected
            .iter()
            .all(|path| path.starts_with(".effinterp-invalid-path/"))
    );

    let report = effects_of(&index, "scripts/back/slash.sh").unwrap();
    assert!(matches!(&report.status, AnalysisStatus::Partial { reasons }
        if reasons.iter().filter(|reason| matches!(reason,
            PartialReason::UnanalyzedInput { path, .. }
                if path.starts_with(".effinterp-invalid-path/"))).count() == rejected_count));
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| {
                let resource = display_resource(&effect.resource);
                !resource.contains("shadowed") && !resource.contains("invalid")
            })
    );
    checked(&report);
}

#[test]
fn resource_display_expression_validates() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-nested-resource",
        &[(
            "app.js",
            "#!/usr/bin/env node\nconst fs = require('fs');\nconst path = require('path');\nconst root = path.resolve(__dirname, '..');\nfs.readFileSync(path.resolve(root, 'package.json'));\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    {
        let report = effects_of(&index, "app.js").unwrap();
        let effect = report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap();
        assert!(!display_resource(&effect.resource).is_empty());
        assert_eq!(effect.expected_fact_id(), effect.fact_id);
        checked(&report);
    }
}

#[test]
fn crawl_limits_bind_snapshot_and_skip_saturation_stays_partial() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "analysis-protocol-skip-saturation",
        &[("app.py", "#!/usr/bin/env python3\nprint('too large')\n")],
    );
    let retained_limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_file_bytes: 1,
            max_skips: 1,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let mut capped_limits = retained_limits.clone();
    capped_limits.crawl.max_skips = 0;
    let retained = build_index(&root, retained_limits);
    let capped = build_index(&root, capped_limits);
    assert_ne!(retained.fingerprint, capped.fingerprint);
    assert!(capped.skipped.is_empty());
    assert!(capped.skips_truncated);

    let report = reach(&capped, &ResourceSelector::parse("fs:/**").unwrap(), None);
    assert!(matches!(&report.status, AnalysisStatus::Partial { reasons }
        if reasons.iter().any(|reason| matches!(reason,
            PartialReason::LimitReached { limit, .. } if limit == "crawl.max_skips"))));
    checked(&report);
}

#[test]
fn cross_file_wipe_occurrences_survive_incremental_updates() {
    use effinterp_repo::{RepoChange, apply_changes};
    for (language, entrypoint, helper, source, body) in [
        (
            "js",
            "app.js",
            "util.js",
            "const { wipe } = require('./util');\nwipe('/tmp/cache');\nwipe('/tmp/cache');\nif (process.env.CLEAN) wipe('/tmp/guarded');\n",
            "const fs = require('fs');\nfunction wipe(path) { fs.rmSync(path); }\nmodule.exports = { wipe };\n",
        ),
        (
            "py",
            "app.py",
            "util.py",
            "#!/usr/bin/env python3\nfrom util import wipe\nwipe('/tmp/cache')\nwipe('/tmp/cache')\nif unknown:\n    wipe('/tmp/guarded')\n",
            "import os\ndef wipe(path):\n    os.remove(path)\n",
        ),
    ] {
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("causality-wipe-{language}"),
            &[(entrypoint, source), (helper, body)],
        );
        let live = build_index(&root, IndexLimits::default());
        let composition = live.composition(entrypoint).unwrap();
        let deletes: Vec<_> = composition
            .occurrence_effects
            .iter()
            .filter(|row| composition.effects[row.effect].effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(
            deletes.len(),
            3,
            "{language}: repeated calls must retain distinct delete occurrences"
        );
        for resource in ["fs:/tmp/cache", "fs:/tmp/guarded"] {
            assert!(
                deletes.iter().any(|row| display_resource(
                    &composition.effects[row.effect].effect.resource
                ) == resource),
                "{language}: missing {resource}"
            );
        }
        assert!(deletes.iter().any(|row| row.condition.is_some()));
        let mut incremental = live;
        std::fs::write(root.join(helper), format!("{body}\n")).unwrap();
        apply_changes(
            &mut incremental,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified(helper.into())],
        );
        let clean = build_index(&root, IndexLimits::default());
        assert_eq!(
            checked(&effects_of(&incremental, entrypoint).unwrap()),
            checked(&effects_of(&clean, entrypoint).unwrap())
        );
    }
}
