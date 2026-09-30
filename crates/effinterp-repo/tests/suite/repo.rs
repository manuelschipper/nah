#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_repo::{
    EntrypointKind, IndexLimits, Selector, SkipCategory, build_index, effects_of, reach,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn index(name: &str) -> effinterp_repo::RepoIndex {
    build_index(&fixture(name), IndexLimits::default())
}

/// Build a throwaway repo under the test tmp dir with the given (path, content)
/// files, returning its root. Deterministic path from `tag`.
#[test]
fn discovers_all_entrypoint_sources() {
    let idx = index("sample-repo");
    let ids: Vec<&str> = idx
        .entrypoints
        .iter()
        .map(|e| e.entrypoint.id.as_str())
        .collect();
    assert!(ids.contains(&"package.json:scripts.build"));
    assert!(ids.contains(&"package.json:scripts.migrate"));
    assert!(ids.contains(&"scripts/deploy.sh"));
    assert!(ids.contains(&"Makefile:wipe"));

    let kinds: Vec<EntrypointKind> = idx
        .entrypoints
        .iter()
        .map(|e| e.entrypoint.evidence.kind)
        .collect();
    assert!(kinds.contains(&EntrypointKind::PackageScript));
    assert!(kinds.contains(&EntrypointKind::ShellFile));
    assert!(kinds.contains(&EntrypointKind::MakefileTarget));

    assert!(idx.entrypoints.iter().all(|e| e.plan().is_some()));
}

#[test]
fn forward_query_includes_coverage_and_boundaries() {
    let idx = index("sample-repo");
    let report = effects_of(&idx, "scripts/deploy.sh").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|r| r.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&r.resource)
                    == "fs:/var/cache/app"
                && r.operation.is_destructive())
    );
    // A forward query reports coverage alongside effects, not effects alone.
    assert!(!report.payload.as_effects().unwrap().coverage.is_empty());
    assert!(effects_of(&idx, "does/not/exist").is_none());
}

#[test]
fn reverse_query_separates_proven_targets_from_unbound_cwd() {
    let idx = index("sample-repo");
    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "scripts/deploy.sh"
                && h.fact.operation.as_str() == "filesystem.delete"
                && matches!(h.matched, effinterp_proto::Match::Satisfied { .. }))
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .all(|h| !h.fact.provenance_roots.is_empty())
    );

    let build = reach(&idx, &Selector::parse("fs:build").unwrap(), None);
    assert!(
        build.payload.as_reach().unwrap().indeterminate.iter().filter_map(|row| match row { effinterp_proto::Indeterminate::Effect { fact, .. } => Some(fact), _ => None })
            .any(|h| h.entrypoint == "Makefile:wipe"
                && h.operation.as_str() == "filesystem.delete")
    );

    for row in &build.payload.as_reach().unwrap().indeterminate {
        if let effinterp_proto::Indeterminate::Effect { matched, .. } = row {
            assert_eq!(
                *matched,
                effinterp_proto::Match::Indeterminate {
                    reason: effinterp_proto::MatchReason::Unbound {
                        names: vec!["cwd".into()]
                    }
                }
            );
        }
    }
    effinterp_proto::validate_repo_query(&build).unwrap();

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "symbolic-reverse-query",
        &[("scripts/clean.sh", "#!/bin/sh\nrm -rf build\n")],
    );
    let symbolic = reach(
        &build_index(&root, IndexLimits::default()),
        &Selector::parse("fs:build").unwrap(),
        None,
    );
    assert!(
        symbolic
            .payload
            .as_reach()
            .unwrap()
            .indeterminate
            .iter()
            .filter_map(|row| match row {
                effinterp_proto::Indeterminate::Effect { fact, .. } => Some(fact),
                _ => None,
            })
            .any(|hit| {
                hit.entrypoint == "scripts/clean.sh"
                    && hit.operation.as_str() == "filesystem.delete"
            })
    );
}

/// Advisor acceptance test: an opaque boundary must leave a reverse query
/// indeterminate, never a clean empty result that reads as proof of safety.
#[test]
fn opaque_reverse_query_is_indeterminate_not_empty() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "opaque-repo",
        &[("run.sh", "#!/bin/sh\nmystery-command\n")],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/etc/passwd").unwrap(), None);

    // No concrete/symbolic effect matched...
    assert!(report.payload.as_reach().unwrap().matches.is_empty());
    // ...but the entrypoint went opaque in filesystem, so it is indeterminate.
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
            .any(|i| i.entrypoint == "run.sh" && i.domain == "filesystem"),
        "mystery-command must yield an indeterminate result for fs:/etc/passwd"
    );
}

/// Advisor acceptance test: the fingerprint's manifest lists analyzed inputs,
/// and changing an input changes the fingerprint.
#[test]
fn manifest_lists_inputs_and_fingerprint_tracks_changes() {
    let v1 = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "fp-1",
        &[("run.sh", "#!/bin/sh\nrm /a\n")],
    );
    let idx1 = build_index(&v1, IndexLimits::default());
    assert!(idx1.dependency_manifest.source_digest("run.sh").is_some());

    let v2 = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "fp-2",
        &[("run.sh", "#!/bin/sh\nrm /b\n")],
    );
    let idx2 = build_index(&v2, IndexLimits::default());
    assert_ne!(idx1.fingerprint, idx2.fingerprint);

    // Rebuilding identical inputs is stable.
    let idx1b = build_index(&v1, IndexLimits::default());
    assert_eq!(idx1.fingerprint, idx1b.fingerprint);
}

/// Advisor acceptance test: symlinks are never followed (no escape, no loops),
/// and hitting max_files yields one truncation record, not N skips.
#[test]
fn crawl_safety_symlinks_and_truncation() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "crawl-repo",
        &[
            ("a.sh", "#!/bin/sh\nrm /a\n"),
            ("b.sh", "#!/bin/sh\nrm /b\n"),
            ("c.sh", "#!/bin/sh\nrm /c\n"),
        ],
    );
    // A symlink pointing outside the repo root must not be followed.
    #[cfg(unix)]
    {
        let link = root.join("escape.sh");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
        std::fs::create_dir_all(root.join("lib/ansible/cli")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(
            root.join("lib/ansible/cli/adhoc.py"),
            "#!/usr/bin/env python\nimport os\nos.unlink('/linked')\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("../lib/ansible/cli/adhoc.py", root.join("bin/ansible"))
            .unwrap();
        std::fs::write(
            root.join("lib/ansible/cli/main.py"),
            "import helper\nif __name__ == '__main__': helper.wipe()\n",
        )
        .unwrap();
        std::fs::write(
            root.join("lib/ansible/cli/helper.py"),
            "import os\ndef wipe(): os.unlink('/linked-main')\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("../lib/ansible/cli/main.py", root.join("bin/main")).unwrap();
        std::os::unix::fs::symlink("../lib", root.join("bin/lib")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("bin/dangling")).unwrap();
        let idx = build_index(&root, IndexLimits::default());
        let linked = idx
            .entrypoints
            .iter()
            .find(|e| e.entrypoint.id == "bin/ansible")
            .unwrap();
        assert_eq!(linked.entrypoint.source_file, "lib/ansible/cli/adhoc.py");
        assert_eq!(
            linked.entrypoint.source_cwd.as_deref(),
            Some("lib/ansible/cli")
        );
        assert_eq!(linked.entrypoint.evidence.kind, EntrypointKind::ShebangFile);
        let main = idx
            .entrypoints
            .iter()
            .find(|e| e.entrypoint.id == "bin/main")
            .unwrap();
        assert_eq!(main.entrypoint.evidence.kind, EntrypointKind::MainFile);
        assert!(
            effects_of(&idx, "bin/main")
                .unwrap()
                .payload
                .as_effects()
                .unwrap()
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete")
        );
        let linked_effects = effects_of(&idx, "bin/ansible")
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        let target_effects = effects_of(&idx, "lib/ansible/cli/adhoc.py")
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        assert!(!linked_effects.is_empty());
        assert_eq!(
            linked_effects
                .iter()
                .map(|effect| &effect.fact_id)
                .collect::<Vec<_>>(),
            target_effects
                .iter()
                .map(|effect| &effect.fact_id)
                .collect::<Vec<_>>()
        );
        for path in ["bin/lib", "bin/dangling"] {
            assert!(idx.skipped.iter().any(|s| s.path == path
                && s.category == SkipCategory::Ignored
                && s.reason.contains("symlink")));
        }
        assert!(
            idx.dependency_manifest
                .source_paths()
                .any(|path| path == "lib/ansible/cli/adhoc.py")
        );
        assert!(
            idx.skipped.iter().any(|s| s.path == "escape.sh"
                && s.category == SkipCategory::Ignored
                && s.reason.contains("symlink")),
            "the escaping symlink must be recorded as an unfollowed symlink"
        );
        // /etc/passwd must not appear as an analyzed input.
        assert!(
            idx.dependency_manifest
                .source_paths()
                .all(|path| !path.contains("passwd"))
        );
    }

    // max_files stops the crawl with a single truncation record.
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_files: 1,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let idx = build_index(&root, limits);
    let truncations: Vec<_> = idx
        .skipped
        .iter()
        .filter(|s| s.reason.contains("truncated"))
        .collect();
    assert_eq!(truncations.len(), 1, "exactly one truncation record");
}

#[test]
fn fingerprint_is_stable_across_builds() {
    assert_eq!(
        index("sample-repo").fingerprint,
        index("sample-repo").fingerprint
    );
}

#[test]
fn added_destructive_effect_is_reachable_only_in_the_changed_repo() {
    let v1 = index("sample-repo");
    let v2 = index("sample-repo-v2");
    assert_ne!(v1.fingerprint, v2.fingerprint);
    assert_eq!(v1.fingerprint, index("sample-repo").fingerprint);
    let selector = Selector::parse("fs:/var/lib/data").unwrap();
    let deletes = |index: &effinterp_repo::RepoIndex| {
        let report = reach(index, &selector, Some("filesystem.delete"));
        effinterp_proto::validate_repo_query(&report).unwrap();
        effinterp_conformance::validate_conformance_bytes(report.to_canonical_json().as_bytes())
            .unwrap();
        report.payload.as_reach().unwrap().matches.len()
    };
    assert_eq!(deletes(&v1), 0);
    assert!(deletes(&v2) > 0);
}

#[test]
fn makefile_variables_fail_closed_in_the_shared_make_model() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "makefile-vars",
        &[(
            "Makefile",
            "prefix ?= /usr/local\ndatadir := ${prefix}/share\n\ninstall:\n\trm -rf ${datadir}/app\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "Makefile:install").unwrap();
    assert!(
        !report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|r| effinterp_proto::display_resource_with_scope(&r.resource) == "$datadir"),
        "make-defined variable read as environment: {:?}",
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .map(|r| (&r.operation, &r.resource))
            .collect::<Vec<_>>()
    );
    assert!(
        !report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|r| r.operation.as_str() == "filesystem.delete")
    );
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_build_target")
    );
}

#[test]
fn malformed_files_are_skipped_not_panicked() {
    let idx = index("broken-repo");
    assert!(
        idx.skipped
            .iter()
            .any(|s| s.path.contains("package.json") && s.category == SkipCategory::Failure)
    );
    assert!(idx.entrypoints.iter().any(|e| e.entrypoint.id == "ok.sh"));
    assert!(idx.entrypoints.iter().all(|e| e.plan().is_some()));
}

/// Spans of package scripts index the host file, covering the text that
/// produced them; a plain shell file keeps spans into its own content.
#[test]
fn embedded_script_spans_point_into_host_file() {
    let pkg = "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"clean\": \"rm -rf build\",\n    \"greet\": \"echo \\\"hi\\\" && rm -rf dist\"\n  }\n}\n";
    let mk = "wipe:\n\t@rm -rf cache\n";
    let sh = "#!/bin/sh\nrm -rf logs\n";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "span-host-repo",
        &[("package.json", pkg), ("Makefile", mk), ("clean.sh", sh)],
    );
    let idx = build_index(&root, IndexLimits::default());

    let span_texts = |id: &str, host: &str| -> Vec<String> {
        let plan = idx
            .entrypoints
            .iter()
            .find(|e| e.entrypoint.id == id)
            .unwrap_or_else(|| panic!("missing entrypoint {id}"))
            .plan()
            .unwrap();
        plan.provenance
            .iter()
            .filter_map(|n| match n.kind {
                effinterp_proto::ProvenanceKind::SourceSpan { start, end } => {
                    Some(host[start as usize..end as usize].to_string())
                }
                _ => None,
            })
            .collect()
    };

    let clean = span_texts("package.json:scripts.clean", pkg);
    assert!(clean.iter().any(|t| t == "rm -rf build"), "got {clean:?}");
    // Escaped quotes before the command shift raw offsets; the span still
    // covers the raw text of the command that produced the effect.
    let greet = span_texts("package.json:scripts.greet", pkg);
    assert!(greet.iter().any(|t| t == "rm -rf dist"), "got {greet:?}");
    let wipe = idx
        .entrypoints
        .iter()
        .find(|entry| entry.entrypoint.id == "Makefile:wipe")
        .unwrap()
        .plan()
        .unwrap();
    assert!(
        wipe.execution_graph
            .edges
            .iter()
            .any(|edge| { edge.kind == effinterp_proto::ExecutionEdgeKind::BuildTarget })
    );
    // A whole-file shell entrypoint has no map and spans its own source.
    let file = span_texts("clean.sh", sh);
    assert!(file.iter().any(|t| t == "rm -rf logs"), "got {file:?}");
}

#[test]
fn vendored_sources_remain_manifest_inputs_and_compose_when_reached() {
    let vendored = "src/pkg/_vendor/distro/distro.py";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "vendored-composition",
        &[
            ("src/pkg/__init__.py", ""),
            ("src/pkg/_vendor/__init__.py", ""),
            ("src/pkg/_vendor/distro/__init__.py", ""),
            (
                "src/pkg/__main__.py",
                "from pkg._vendor.distro.distro import main\nif __name__ == '__main__':\n    main()\n",
            ),
            (
                vendored,
                "import os\ndef main():\n    os.remove('/tmp/vendored')\nif __name__ == '__main__':\n    main()\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(idx.find(vendored).is_none());
    assert!(idx.dependency_manifest.source_digest(vendored).is_some());
    assert!(idx.skipped.iter().all(|skip| skip.path != vendored));
    let report = reach(&idx, &Selector::parse("fs:/tmp/vendored").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "src/pkg/__main__.py"
                    && hit.fact.operation.0 == "filesystem.delete"
            }),
        "{report:?}"
    );
}
