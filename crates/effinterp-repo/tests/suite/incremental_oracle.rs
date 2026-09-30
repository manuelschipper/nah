//! The strengthened incremental clean-rebuild oracle.
//!
//! For a battery of repositories, each test builds a clean index and reaches the
//! same on-disk file state incrementally through a sequence of Added/Modified/
//! Deleted events, then asserts that the two indexes produce a BYTE-IDENTICAL
//! normalized serialization of the entire public query surface (`normalize_surface`).
//! Unlike the effect-set comparison in `cross_module.rs`, this compares realms,
//! modalities, conditions, attributes, boundaries, coverage, structured
//! provenance (rendered to stable structural steps), origin files, skip/failure
//! records, the fingerprint, and the model manifest.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{
    DependencyKind, IndexLimits, InvalidationAction, RepoChange, apply_changes, build_index,
    effects_of, normalize_surface, save_index,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::plan_causality;

fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// The oracle: an index reached incrementally must serialize byte-for-byte the
/// same as a clean rebuild of the current on-disk state.
fn assert_full_surface_equivalent(incremental: &effinterp_repo::RepoIndex, root: &Path) {
    assert_surface_equivalent(incremental, root, &IndexLimits::default());
}

fn assert_surface_equivalent(
    incremental: &effinterp_repo::RepoIndex,
    root: &Path,
    limits: &IndexLimits,
) {
    let rebuilt = build_index(root, limits.clone());
    let got = normalize_surface(incremental);
    let want = normalize_surface(&rebuilt);
    if got != want {
        // Point at the first differing line to make a failure diagnosable.
        let first_diff = got
            .lines()
            .zip(want.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| format!("line {i}:\n  incremental: {a}\n  rebuilt:     {b}"))
            .unwrap_or_else(|| "(length differs)".to_string());
        panic!("normalized surface differs from clean rebuild:\n{first_diff}");
    }
    assert_eq!(
        save_index(incremental),
        save_index(&rebuilt),
        "persisted P10 snapshots differ"
    );
    for entrypoint in &rebuilt.entrypoints {
        let id = &entrypoint.entrypoint.id;
        assert_eq!(
            effinterp_proto::canonical_json(&effects_of(incremental, id)),
            effinterp_proto::canonical_json(&effects_of(&rebuilt, id)),
            "forward query for {id} differs from a clean rebuild"
        );
        assert_eq!(
            effinterp_proto::canonical_json(&plan_causality(incremental, id)),
            effinterp_proto::canonical_json(&plan_causality(&rebuilt, id)),
            "causality graph for {id} differs from a clean rebuild"
        );
    }
}

#[test]
fn dependency_graph_drives_extraction_analysis_and_composition() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-dependency-driven-reuse",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom helper import wipe\nwipe()\n",
            ),
            ("helper.py", "import os\ndef wipe(): os.remove('/before')\n"),
            ("unrelated.py", "def value(): return 1\n"),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());

    write_file(&root, "unrelated.py", "def value(): return 2\n");
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("unrelated.py".into())],
    );
    assert_eq!(report.invalidation, InvalidationAction::Reextract);
    assert_eq!(report.reextracted, ["unrelated.py"]);
    assert!(report.reanalyzed.is_empty());
    assert!(report.recomposed.is_empty());
    assert_full_surface_equivalent(&index, &root);

    write_file(
        &root,
        "helper.py",
        "import os\ndef wipe(): os.remove('/after')\n",
    );
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("helper.py".into())],
    );
    assert_eq!(report.invalidation, InvalidationAction::Recompose);
    assert_eq!(report.reextracted, ["helper.py"]);
    assert!(report.reanalyzed.is_empty());
    assert_eq!(report.recomposed, ["app.py"]);
    assert_full_surface_equivalent(&index, &root);

    write_file(
        &root,
        "app.py",
        "#!/usr/bin/env python3\nimport os\nos.remove('/direct')\n",
    );
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("app.py".into())],
    );
    assert_eq!(report.invalidation, InvalidationAction::Rediscover);
    assert_eq!(report.reextracted, ["app.py"]);
    assert_eq!(report.reanalyzed, ["app.py"]);
    assert_eq!(report.recomposed, ["app.py"]);
    assert_full_surface_equivalent(&index, &root);
}

#[test]
fn oversize_skip_evidence_tracks_add_and_delete_events() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-oversize-events",
        &[("app.sh", "#!/bin/sh\nrm /stable\n")],
    );
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_file_bytes: 64,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let mut index = build_index(&root, limits.clone());

    write_file(&root, "big.py", &"#".repeat(240));
    let report = apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Added("big.py".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_surface_equivalent(&index, &root, &limits);

    std::fs::remove_file(root.join("big.py")).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Deleted("big.py".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_surface_equivalent(&index, &root, &limits);
}

#[test]
fn max_depth_skip_evidence_tracks_add_and_delete_events() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-max-depth-events",
        &[("app.sh", "#!/bin/sh\nrm /stable\n")],
    );
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_depth: 0,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let mut index = build_index(&root, limits.clone());

    write_file(&root, "deep/app.py", "#!/usr/bin/env python3\n");
    let report = apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Added("deep/app.py".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_surface_equivalent(&index, &root, &limits);

    std::fs::remove_dir_all(root.join("deep")).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Deleted("deep/app.py".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_surface_equivalent(&index, &root, &limits);
}

#[test]
fn crawl_and_skip_truncation_track_add_and_delete_events() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-truncation-events",
        &[("app.sh", "#!/bin/sh\nrm /stable\n")],
    );
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_files: 1,
            max_skips: 0,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let mut index = build_index(&root, limits.clone());

    write_file(&root, "zz.py", "def helper(): pass\n");
    let report = apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Added("zz.py".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_surface_equivalent(&index, &root, &limits);

    std::fs::remove_file(root.join("zz.py")).unwrap();
    let report = apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Deleted("zz.py".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_surface_equivalent(&index, &root, &limits);
}

const APP_PY: &str = "#!/usr/bin/env python\nfrom util import wipe\ndef run():\n    wipe(\"/var/cache/app\", name)\nrun()\n";
const UTIL_PY: &str =
    "import os, shutil\ndef wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))\n";

/// Case 1: adding a new file that resolves a previously-external call.
#[test]
fn added_file_resolves_external_call() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-resolve",
        &[("app.py", APP_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    write_file(&root, "util.py", UTIL_PY);
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("util.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

/// Case 2: modifying a callee's effect (recursive delete of a joined path
/// becomes a plain delete of the root).
#[test]
fn modified_callee_effect() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-modify",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "util.py",
        "import shutil\ndef wipe(root, t):\n    shutil.rmtree(root)\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("util.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

/// Case 3: deleting a file (the callee), which turns a resolved cross-file
/// effect back into an unresolved boundary.
#[test]
fn deleted_file() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-delete",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    std::fs::remove_file(root.join("util.py")).unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("util.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

/// Case 4: a rename, expressed as delete + add. The import target moves, so the
/// composition must be recomputed against the new file name.
#[test]
fn renamed_file_delete_plus_add() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-rename",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    // Rename util.py -> helpers.py; app.py still imports `util`, so the call is
    // now external and the delete degrades to a boundary. The rebuild agrees.
    std::fs::rename(root.join("util.py"), root.join("helpers.py")).unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Deleted("util.py".into()),
            RepoChange::Added("helpers.py".into()),
        ],
    );
    assert_full_surface_equivalent(&idx, &root);

    // Rename again so the import resolves: point app.py at the new module.
    write_file(
        &root,
        "app.py",
        "#!/usr/bin/env python\nfrom helpers import wipe\ndef run():\n    wipe(\"/var/cache/app\", name)\nrun()\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("app.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

/// Case 5: a change that alters entrypoint discovery — adding a `func main`
/// promotes a Go source file to a MainFile entrypoint that did not exist before.
#[test]
fn change_alters_discovery_adding_main() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-discovery",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "lib.go",
                "package main\nimport \"os\"\nfunc Helper() { os.RemoveAll(\"/x\") }\n",
            ),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    // Add a main.go with `func main` — a new entrypoint appears in discovery.
    write_file(
        &root,
        "main.go",
        "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/tmp/build\") }\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("main.go".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

/// Config/resolver event: a `go.mod` change alters the Go module prefix and thus
/// which imports resolve across files. It cannot be applied per-source-file, so
/// `apply_changes` forces a full registry rebuild; the result must still match a
/// clean rebuild. (The engine's own analysis limits / model-set are not
/// reconfigurable through the public API, so those resolver-event variants are
/// out of scope here — see TODO below.)
#[test]
fn config_event_go_mod_change_forces_recomposition() {
    const MAIN_GO: &str =
        "package main\nimport \"example.com/app/util\"\nfunc main() { util.Wipe(\"/var/data\") }\n";
    const UTIL_GO: &str = "package util\nimport \"os\"\nfunc Wipe(p string) { os.RemoveAll(p) }\n";

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-gomod",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            ("main.go", MAIN_GO),
            ("util/util.go", UTIL_GO),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());

    // Change the module prefix so `example.com/app/util` no longer resolves; the
    // cross-file delete degrades to an unresolved boundary.
    write_file(&root, "go.mod", "module example.com/renamed\n\ngo 1.21\n");
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("go.mod".into())],
    );
    assert_full_surface_equivalent(&idx, &root);

    // Restore the prefix; resolution (and the cross-file effect) must come back.
    write_file(&root, "go.mod", "module example.com/app\n\ngo 1.21\n");
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("go.mod".into())],
    );
    assert_full_surface_equivalent(&idx, &root);

    // TODO(advisor): analysis-limit and model-set change events are not covered
    // here because the engine's limits and model-set identity are fixed by the
    // engine and not reconfigurable through effinterp-repo's public API; exercising
    // them would require threading a configurable model manifest through
    // build_index/apply_changes (out of scope for this oracle).
}

#[test]
fn nested_go_mod_change_forces_recomposition() {
    const MAIN_GO: &str = "package main\nimport \"example.com/tools/util\"\nfunc main() { util.Wipe(\"/var/data\") }\n";
    const UTIL_GO: &str = "package util\nimport \"os\"\nfunc Wipe(p string) { os.RemoveAll(p) }\n";

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-nested-gomod",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            ("tools/go.mod", "module example.com/tools\n\ngo 1.21\n"),
            ("tools/cmd/main.go", MAIN_GO),
            ("tools/util/util.go", UTIL_GO),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());

    write_file(
        &root,
        "tools/go.mod",
        "module example.com/renamed\n\ngo 1.21\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("tools/go.mod".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

#[test]
fn changed_launched_source_reanalyzes_its_wrapper() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-launched-source",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"cd scripts && ./run.sh"}}"#,
            ),
            ("scripts/run.sh", "#!/bin/sh\npython3 task.py\n"),
            (
                "scripts/task.py",
                "import os\nos.remove('/p7a/incremental-before')\n",
            ),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "scripts/task.py",
        "import os\nos.remove('/p7a/incremental-after')\n",
    );
    let report = apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("scripts/task.py".into())],
    );
    assert!(
        report
            .reanalyzed
            .iter()
            .any(|id| id == "package.json:scripts.run"),
        "wrapper plan retained an embedded stale source: {:?}",
        report.reanalyzed
    );
    assert_full_surface_equivalent(&idx, &root);
}

#[test]
fn crawl_admission_change_reanalyzes_a_launch_dependent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-launch-admission",
        &[
            ("00_run.sh", "#!/bin/sh\npython3 99_task.py\n"),
            (
                "99_task.py",
                "import os\nos.remove('/p7a/evicted-source')\n",
            ),
        ],
    );
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_files: 2,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let mut idx = build_index(&root, limits.clone());
    write_file(&root, "50_noise.txt", "crawl slot\n");
    let report = apply_changes(
        &mut idx,
        &root,
        &limits,
        &[RepoChange::Added("50_noise.txt".into())],
    );
    assert!(
        report.reanalyzed.iter().any(|id| id == "00_run.sh"),
        "wrapper plan retained a source evicted from the manifest: {:?}",
        report.reanalyzed
    );
    let rebuilt = build_index(&root, limits);
    assert_eq!(normalize_surface(&idx), normalize_surface(&rebuilt));
}

#[test]
fn changed_source_reanalyzes_a_non_shell_launcher() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-non-shell-launched-source",
        &[
            (
                "app.php",
                "#!/usr/bin/env php\n<?php passthru('python3 job.py');\n",
            ),
            ("job.py", "import os\nos.remove('/p7a/non-shell-before')\n"),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "job.py",
        "import os\nos.remove('/p7a/non-shell-after')\n",
    );
    let report = apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("job.py".into())],
    );
    assert!(
        report.reanalyzed.iter().any(|id| id == "app.php"),
        "non-shell launcher retained an embedded stale source: {:?}",
        report.reanalyzed
    );
    assert_full_surface_equivalent(&idx, &root);

    std::fs::remove_file(root.join("job.py")).unwrap();
    let report = apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("job.py".into())],
    );
    assert!(report.reanalyzed.iter().any(|id| id == "app.php"));
    assert_full_surface_equivalent(&idx, &root);

    write_file(
        &root,
        "job.py",
        "import os\nos.remove('/p7a/non-shell-added')\n",
    );
    let report = apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("job.py".into())],
    );
    assert!(report.reanalyzed.iter().any(|id| id == "app.php"));
    assert_full_surface_equivalent(&idx, &root);
}

#[test]
fn changed_launch_context_reanalyzes_the_launched_program() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-launch-context",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"cd a && tsx ../tests/task.ts"}}"#,
            ),
            ("a/keep.txt", "a\n"),
            ("c/keep.txt", "c\n"),
            (
                "tests/task.ts",
                "import { rmSync } from 'fs'\nrmSync('victim.txt')\n",
            ),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "package.json",
        r#"{"scripts":{"run":"cd c && tsx ../tests/task.ts"}}"#,
    );
    let report = apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("package.json".into())],
    );
    assert!(
        report
            .reanalyzed
            .iter()
            .any(|id| id == "tests/task.ts:launch@c"),
        "launched program retained its previous cwd: {:?}",
        report.reanalyzed
    );
    let effects = effects_of(&idx, "package.json:scripts.run")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects;
    assert!(
        effects.iter().any(|effect| {
            effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "tests/task.ts"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:c/victim.txt"
        }),
        "{effects:?}"
    );
    assert!(effects.iter().all(|effect| {
        effect
            .origin
            .as_ref()
            .expect("effect origin")
            .source_file
            .as_str()
            != "tests/task.ts"
            || effinterp_proto::display_resource_with_scope(&effect.resource) != "fs:a/victim.txt"
    }));
    assert_full_surface_equivalent(&idx, &root);
}

/// A longer sequence of mixed events on one index, asserting equivalence after
/// each step, to catch stale state that only a single event would not reveal.
#[test]
fn mixed_event_sequence_stays_equivalent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-sequence",
        &[("app.py", APP_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    assert_full_surface_equivalent(&idx, &root);

    // Resolve the external call.
    write_file(&root, "util.py", UTIL_PY);
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("util.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);

    // Add an unrelated entrypoint.
    write_file(
        &root,
        "extra.py",
        "#!/usr/bin/env python\nimport os\nos.remove(\"/tmp/z\")\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("extra.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);

    // Modify the callee.
    write_file(
        &root,
        "util.py",
        "import shutil\ndef wipe(root, t):\n    shutil.rmtree(root)\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("util.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);

    // Delete the extra entrypoint.
    std::fs::remove_file(root.join("extra.py")).unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("extra.py".into())],
    );
    assert_full_surface_equivalent(&idx, &root);
}

#[test]
fn representative_source_modification_matrix_covers_every_frontend() {
    let cases = [
        (
            "shell",
            "app.sh",
            "#!/bin/sh\nrm /before\n",
            "#!/bin/sh\nrm /after\n",
            None,
        ),
        (
            "python",
            "app.py",
            "#!/usr/bin/env python3\nimport os\nos.remove('/before')\n",
            "#!/usr/bin/env python3\nimport os\nos.remove('/after')\n",
            None,
        ),
        (
            "javascript",
            "app.js",
            "#!/usr/bin/env node\nrequire('fs').unlinkSync('/before')\n",
            "#!/usr/bin/env node\nrequire('fs').unlinkSync('/after')\n",
            None,
        ),
        (
            "typescript",
            "src/app.ts",
            "import { unlinkSync } from 'fs'; unlinkSync('/before')\n",
            "import { unlinkSync } from 'fs'; unlinkSync('/after')\n",
            Some(("package.json", r#"{"scripts":{"run":"tsx src/app.ts"}}"#)),
        ),
        (
            "go",
            "main.go",
            "package main\nimport \"os\"\nfunc main(){ os.Remove(\"/before\") }\n",
            "package main\nimport \"os\"\nfunc main(){ os.Remove(\"/after\") }\n",
            Some(("go.mod", "module example.test/app\n\ngo 1.21\n")),
        ),
        (
            "rust",
            "src/main.rs",
            "fn main(){ std::fs::remove_file(\"/before\").ok(); }\n",
            "fn main(){ std::fs::remove_file(\"/after\").ok(); }\n",
            Some(("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'\n")),
        ),
        (
            "ruby",
            "app.rb",
            "#!/usr/bin/env ruby\nFile.delete('/before')\n",
            "#!/usr/bin/env ruby\nFile.delete('/after')\n",
            None,
        ),
        (
            "php",
            "app.php",
            "#!/usr/bin/env php\n<?php unlink('/before');\n",
            "#!/usr/bin/env php\n<?php unlink('/after');\n",
            None,
        ),
        (
            "java",
            "Main.java",
            "class Main { public static void main(String[] a){ new java.io.File(\"/before\").delete(); } }\n",
            "class Main { public static void main(String[] a){ new java.io.File(\"/after\").delete(); } }\n",
            None,
        ),
    ];
    for (language, path, before, after, config) in cases {
        let mut files = vec![(path, before)];
        if let Some(config) = config {
            files.push(config);
        }
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("p10-source-{language}"),
            &files,
        );
        let mut index = build_index(&root, IndexLimits::default());
        write_file(&root, path, after);
        apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified(path.into())],
        );
        assert_full_surface_equivalent(&index, &root);
    }
}

#[test]
fn nine_frontend_call_target_updates_are_byte_identical_to_clean_rebuilds() {
    let cases = vec![
        (
            "shell",
            "app.sh",
            "app.sh",
            "#!/bin/sh\nerase() { rm -f -- /p13e/shell-before; }\nerase\n",
            "#!/bin/sh\nerase() { rm -f -- /p13e/shell-after; }\nerase\n",
            vec![],
        ),
        (
            "python",
            "app.py",
            "helper.py",
            "import os\ndef erase(): os.remove('/p13e/python-before')\n",
            "import os\ndef erase(): os.remove('/p13e/python-after')\n",
            vec![(
                "app.py",
                "#!/usr/bin/env python3\nfrom helper import erase\nerase()\n",
            )],
        ),
        (
            "javascript",
            "app.js",
            "helper.js",
            "import fs from 'node:fs'\nexport function erase() { fs.unlinkSync('/p13e/javascript-before') }\n",
            "import fs from 'node:fs'\nexport function erase() { fs.unlinkSync('/p13e/javascript-after') }\n",
            vec![(
                "app.js",
                "#!/usr/bin/env node\nimport { erase } from './helper.js'\nerase()\n",
            )],
        ),
        (
            "typescript",
            "package.json:scripts.parity",
            "src/helper.ts",
            "import fs from 'node:fs'\nexport function erase() { fs.unlinkSync('/p13e/typescript-before') }\n",
            "import fs from 'node:fs'\nexport function erase() { fs.unlinkSync('/p13e/typescript-after') }\n",
            vec![
                ("package.json", r#"{"scripts":{"parity":"tsx src/app.ts"}}"#),
                ("src/app.ts", "import { erase } from './helper'\nerase()\n"),
            ],
        ),
        (
            "go",
            "main.go",
            "helper/helper.go",
            "package helper\nimport \"os\"\nfunc Erase() { os.Remove(\"/p13e/go-before\") }\n",
            "package helper\nimport \"os\"\nfunc Erase() { os.Remove(\"/p13e/go-after\") }\n",
            vec![
                ("go.mod", "module example.test/p13e\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\nimport \"example.test/p13e/helper\"\nfunc main() { helper.Erase() }\n",
                ),
            ],
        ),
        (
            "rust",
            "src/main.rs",
            "src/helper.rs",
            "pub fn erase() { std::fs::remove_file(\"/p13e/rust-before\").ok(); }\n",
            "pub fn erase() { std::fs::remove_file(\"/p13e/rust-after\").ok(); }\n",
            vec![
                (
                    "Cargo.toml",
                    "[package]\nname = 'p13e'\nversion = '0.1.0'\n",
                ),
                (
                    "src/main.rs",
                    "mod helper;\nfn main() { helper::erase(); }\n",
                ),
            ],
        ),
        (
            "java",
            "src/p13e/App.java",
            "src/p13e/Helper.java",
            "package p13e;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\nclass Helper { static void erase() throws Exception { Files.delete(Path.of(\"/p13e/java-before\")); } }\n",
            "package p13e;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\nclass Helper { static void erase() throws Exception { Files.delete(Path.of(\"/p13e/java-after\")); } }\n",
            vec![(
                "src/p13e/App.java",
                "package p13e;\npublic class App { public static void main(String[] args) { Helper.erase(); } }\n",
            )],
        ),
        (
            "ruby",
            "app.rb",
            "helper.rb",
            "module Helper\n  def self.erase\n    File.delete('/p13e/ruby-before')\n  end\nend\n",
            "module Helper\n  def self.erase\n    File.delete('/p13e/ruby-after')\n  end\nend\n",
            vec![(
                "app.rb",
                "#!/usr/bin/env ruby\nrequire_relative 'helper'\nHelper.erase\n",
            )],
        ),
        (
            "php",
            "bin/app.php",
            "helper.php",
            "<?php function erase() { unlink('/p13e/php-before'); }\n",
            "<?php function erase() { unlink('/p13e/php-after'); }\n",
            vec![(
                "bin/app.php",
                "<?php require __DIR__ . '/../helper.php'; erase();\n",
            )],
        ),
    ];

    for (frontend, entrypoint, changed, before, after, mut stable) in cases {
        stable.push((changed, before));
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("p13e-call-target-{frontend}"),
            &stable,
        );
        let mut incremental = build_index(&root, IndexLimits::default());
        write_file(&root, changed, after);
        apply_changes(
            &mut incremental,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified(changed.into())],
        );
        assert_full_surface_equivalent(&incremental, &root);
        let surface = effects_of(&incremental, entrypoint)
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert!(
            surface
                .effects
                .iter()
                .any(
                    |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                        == format!("fs:/p13e/{frontend}-after")
                ),
            "{frontend} did not publish the changed call target: {:?}",
            surface.effects
        );
        assert!(
            surface
                .effects
                .iter()
                .all(
                    |effect| !effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("-before")
                ),
            "{frontend} retained stale call-target output: {:?}",
            surface.effects
        );
    }
}

#[test]
fn indirectly_reanalyzed_parse_failure_does_not_freeze_incremental_updates() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-prior-parse-incremental",
        &[
            ("app.php", "#!/usr/bin/env php\n<?php unlink('/before');\n"),
            (
                "broken.php",
                "#!/usr/bin/env php\n<?php function broken( {\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    assert!(
        index
            .find("broken.php")
            .unwrap()
            .plan()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "parse_error")
    );

    write_file(
        &root,
        "app.php",
        "#!/usr/bin/env php\n<?php unlink('/after');\n",
    );
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("app.php".into())],
    );
    assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Published);
    assert_full_surface_equivalent(&index, &root);
}

#[test]
fn add_delete_rename_matrix_covers_js_ts_python_go_and_rust() {
    for (language, extension, content) in [
        ("javascript", "js", "export function f() {}\n"),
        ("typescript", "ts", "export function f(): void {}\n"),
        ("python", "py", "def f(): pass\n"),
        ("go", "go", "package helper\nfunc F() {}\n"),
        ("rust", "rs", "pub fn f() {}\n"),
    ] {
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("p10-events-{language}"),
            &[("app.sh", "#!/bin/sh\nrm /stable\n")],
        );
        let mut index = build_index(&root, IndexLimits::default());
        let added = format!("src/added.{extension}");
        write_file(&root, &added, content);
        apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Added(added.clone())],
        );
        assert_full_surface_equivalent(&index, &root);

        let renamed = format!("src/renamed.{extension}");
        std::fs::rename(root.join(&added), root.join(&renamed)).unwrap();
        apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[
                RepoChange::Added(renamed.clone()),
                RepoChange::Deleted(added),
            ],
        );
        assert_full_surface_equivalent(&index, &root);

        std::fs::remove_file(root.join(&renamed)).unwrap();
        apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Deleted(renamed)],
        );
        assert_full_surface_equivalent(&index, &root);
    }
}

#[test]
fn resolver_discovery_and_identity_matrix_fails_closed_to_rebuild() {
    for (name, before, after) in [
        (
            "package.json",
            r#"{"scripts":{"run":"node app.js"},"exports":"./app.js"}"#,
            r#"{"scripts":{"run":"node next.js"},"exports":"./next.js"}"#,
        ),
        (
            "go.mod",
            "module old.example/app\n",
            "module new.example/app\n",
        ),
        ("go.work", "go 1.21\nuse ./old\n", "go 1.21\nuse ./new\n"),
        (
            "pyproject.toml",
            "[project]\nname='old'\n",
            "[project]\nname='new'\n",
        ),
        (
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            r#"{"autoload":{"psr-4":{"App\\":"lib/"}}}"#,
        ),
        (
            "Cargo.toml",
            "[workspace]\nmembers=['old']\n",
            "[workspace]\nmembers=['new']\n",
        ),
    ] {
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("p10-config-{}", name.replace('.', "-")),
            &[("app.sh", "#!/bin/sh\nrm /stable\n"), (name, before)],
        );
        let mut index = build_index(&root, IndexLimits::default());
        write_file(&root, name, after);
        let report = apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified(name.into())],
        );
        assert_eq!(report.invalidation, InvalidationAction::Rebuild, "{name}");
        assert_full_surface_equivalent(&index, &root);
    }

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-identity-events",
        &[("app.sh", "#!/bin/sh\nrm /x\n")],
    );
    let mut index = build_index(&root, IndexLimits::default());
    for (kind, key) in [
        (DependencyKind::ModelSet, "model-set"),
        (DependencyKind::ParserFrontend, "frontend:python"),
        (DependencyKind::Analyzer, "analyzer"),
    ] {
        let report = apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::IdentityChanged {
                kind,
                key: key.into(),
            }],
        );
        assert_eq!(report.invalidation, InvalidationAction::Rebuild);
        assert_full_surface_equivalent(&index, &root);
    }

    let changed_limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_files: effinterp_repo::CrawlLimits::default().max_files + 1,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let report = apply_changes(&mut index, &root, &changed_limits, &[]);
    assert_eq!(report.invalidation, InvalidationAction::Rebuild);
    let rebuilt = build_index(&root, changed_limits);
    assert_eq!(save_index(&index), save_index(&rebuilt));
}

#[test]
fn package_export_change_matches_a_clean_rebuild() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13b-package-export-incremental",
        &[
            ("package.json", r#"{"name":"app","bin":{"app":"bin.js"}}"#),
            ("bin.js", "import { run } from '@app/tool'\nrun()\n"),
            (
                "packages/tool/package.json",
                r#"{"name":"@app/tool","exports":"./src/before.ts"}"#,
            ),
            (
                "packages/tool/src/before.ts",
                "import { readFileSync } from 'fs'\nexport function run() { readFileSync('/before') }\n",
            ),
            (
                "packages/tool/src/after.ts",
                "import { readFileSync } from 'fs'\nexport function run() { readFileSync('/after') }\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "packages/tool/package.json",
        r#"{"name":"@app/tool","exports":"./src/after.ts"}"#,
    );
    let report = apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("packages/tool/package.json".into())],
    );
    assert_eq!(report.invalidation, InvalidationAction::Rebuild);
    assert_full_surface_equivalent(&index, &root);
    let effects = effects_of(&index, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap()
        .effects;
    assert!(effects.iter().any(|effect| {
        effinterp_proto::display_resource_with_scope(&effect.resource).contains("/after")
    }));
    assert!(effects.iter().all(|effect| {
        !effinterp_proto::display_resource_with_scope(&effect.resource).contains("/before")
    }));
}

#[test]
fn duplicate_and_out_of_order_events_reaching_one_tree_are_byte_stable() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-event-order",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom util import wipe\nwipe()\n",
            ),
            ("util.py", "import os\ndef wipe(): os.remove('/before')\n"),
        ],
    );
    let baseline = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "util.py",
        "import os\ndef wipe(): os.remove('/after')\n",
    );
    write_file(&root, "extra.py", "def helper(): pass\n");

    let mut ordered = baseline.clone();
    apply_changes(
        &mut ordered,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Modified("util.py".into()),
            RepoChange::Added("extra.py".into()),
        ],
    );
    let mut adversarial = baseline;
    apply_changes(
        &mut adversarial,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Added("extra.py".into()),
            RepoChange::Modified("util.py".into()),
            RepoChange::Modified("util.py".into()),
            RepoChange::Added("extra.py".into()),
        ],
    );
    assert_eq!(save_index(&ordered), save_index(&adversarial));
    assert_full_surface_equivalent(&ordered, &root);
}

#[test]
fn python_package_layout_changes_stay_equivalent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-python-package-layout",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom pkg import wipe\nwipe()\n",
            ),
            (
                "pkg/impl.py",
                "import os\ndef wipe(): os.remove('/package-layout')\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());

    write_file(&root, "pkg/__init__.py", "from .impl import wipe\n");
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("pkg/__init__.py".into())],
    );
    assert_full_surface_equivalent(&index, &root);

    std::fs::remove_file(root.join("pkg/__init__.py")).unwrap();
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("pkg/__init__.py".into())],
    );
    assert_full_surface_equivalent(&index, &root);

    std::fs::remove_file(root.join("pkg/impl.py")).unwrap();
    write_file(&root, "src/pkg/__init__.py", "from .impl import wipe\n");
    write_file(
        &root,
        "src/pkg/impl.py",
        "import os\ndef wipe(): os.remove('/src-layout')\n",
    );
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Added("src/pkg/impl.py".into()),
            RepoChange::Deleted("pkg/impl.py".into()),
            RepoChange::Added("src/pkg/__init__.py".into()),
        ],
    );
    assert_full_surface_equivalent(&index, &root);
}

#[test]
fn dependency_cycle_update_stays_equivalent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-dependency-cycle",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom a import alpha\nalpha()\n",
            ),
            ("a.py", "from b import beta\ndef alpha(): beta()\n"),
            (
                "b.py",
                "from a import alpha\nimport os\ndef beta():\n    os.remove('/before')\n    alpha()\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "b.py",
        "from a import alpha\nimport os\ndef beta():\n    os.remove('/after')\n    alpha()\n",
    );
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("b.py".into())],
    );
    assert_full_surface_equivalent(&index, &root);
}

#[test]
fn delete_then_readd_in_separate_updates_restores_snapshot_bytes() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-delete-then-readd",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let mut index = build_index(&root, IndexLimits::default());
    let original = save_index(&index);

    std::fs::remove_file(root.join("util.py")).unwrap();
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("util.py".into())],
    );
    assert_full_surface_equivalent(&index, &root);

    write_file(&root, "util.py", UTIL_PY);
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("util.py".into())],
    );
    assert_full_surface_equivalent(&index, &root);
    assert_eq!(save_index(&index), original);
}

#[test]
fn repeated_identical_content_updates_are_unchanged_and_byte_stable() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-identical-content",
        &[("app.py", APP_PY)],
    );
    let mut index = build_index(&root, IndexLimits::default());
    let original = save_index(&index);

    for _ in 0..2 {
        write_file(&root, "app.py", APP_PY);
        let report = apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified("app.py".into())],
        );
        assert_eq!(report.outcome, effinterp_repo::UpdateOutcome::Unchanged);
        assert_eq!(save_index(&index), original);
        assert_full_surface_equivalent(&index, &root);
    }
}

#[test]
fn go_generic_and_rust_async_updates_match_clean_results() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13c-go-rust-incremental",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc wipe[T ~string](path T) { os.RemoveAll(path) }\nfunc main() { wipe[string](\"/go-before\") }\n",
            ),
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/main.rs",
                "async fn wipe(path: &str) { std::fs::remove_file(path); }\nasync fn main() { wipe(\"/rust-before\").await; }\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "main.go",
        "package main\nimport \"os\"\nfunc wipe[T ~string](path T) { os.RemoveAll(path) }\nfunc main() { wipe[string](\"/go-after\") }\n",
    );
    write_file(
        &root,
        "src/main.rs",
        "async fn wipe(path: &str) { std::fs::remove_file(path); }\nasync fn main() { wipe(\"/rust-after\").await; }\n",
    );
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Modified("main.go".into()),
            RepoChange::Modified("src/main.rs".into()),
        ],
    );
    assert_full_surface_equivalent(&index, &root);
    let go = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let rust = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(go.effects.iter().any(|effect| {
        effinterp_proto::display_resource_with_scope(&effect.resource).contains("/go-after")
    }));
    assert!(rust.effects.iter().any(|effect| {
        effinterp_proto::display_resource_with_scope(&effect.resource).contains("/rust-after")
    }));
}

#[test]
fn java_ruby_and_php_callable_updates_match_clean_results() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13d-callable-incremental",
        &[
            (
                "Main.java",
                "public class Main {\npublic static void main(String[] a) { Runnable work = () -> new java.io.File(\"/java-before\").delete(); work.run(); }\n}\n",
            ),
            (
                "app.rb",
                "#!/usr/bin/env ruby\nwork = proc { File.delete('/ruby-before') }\nwork.call\n",
            ),
            (
                "bin/tool.php",
                "<?php $work = fn () => unlink('/php-before'); $work();\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "Main.java",
        "public class Main {\npublic static void main(String[] a) { Runnable work = () -> new java.io.File(\"/java-after\").delete(); work.run(); }\n}\n",
    );
    write_file(
        &root,
        "app.rb",
        "#!/usr/bin/env ruby\nwork = proc { File.delete('/ruby-after') }\nwork.call\n",
    );
    write_file(
        &root,
        "bin/tool.php",
        "<?php $work = fn () => unlink('/php-after'); $work();\n",
    );
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Modified("Main.java".into()),
            RepoChange::Modified("app.rb".into()),
            RepoChange::Modified("bin/tool.php".into()),
        ],
    );
    assert_full_surface_equivalent(&index, &root);
    for (entry, path) in [
        ("Main.java", "/java-after"),
        ("app.rb", "/ruby-after"),
        ("bin/tool.php", "/php-after"),
    ] {
        let report = effects_of(&index, entry)
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert!(
            report
                .effects
                .iter()
                .any(
                    |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains(path)
                ),
            "{entry} did not update to {path}: {:?}",
            report.effects
        );
        assert!(report.effects.iter().all(|effect| {
            !effinterp_proto::display_resource_with_scope(&effect.resource).contains("before")
        }));
    }
}

#[test]
fn infrastructure_supporting_inputs_invalidate_lifecycle_results() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "infrastructure-inputs",
        &[
            ("package.json", r#"{"scripts":{"deploy":"sh deploy.sh"}}"#),
            (
                "deploy.sh",
                "#!/bin/sh\nkubectl apply -f object.yaml\nkubectl delete -f later.yaml\nterraform apply\n",
            ),
            (
                "object.yaml",
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: before\n",
            ),
            ("main.tf", "resource \"aws_instance\" \"before\" {}"),
        ],
    );
    let limits = IndexLimits::default();
    let mut index = build_index(&root, limits.clone());
    let initial = effects_of(&index, "package.json:scripts.deploy").unwrap();
    assert!(initial.payload.as_effects().unwrap().effects.iter().any(|e| matches!(&e.resource, effinterp_proto::ResourceExpr::Concrete { identity: effinterp_proto::ResourceIdentity::ManagedInfrastructure { address, .. } } if address.as_deref() == Some("aws_instance.before"))), "{}", effinterp_proto::canonical_json(&initial));
    for (path, content, change) in [
        (
            "object.yaml",
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: after\n  namespace: other\n",
            RepoChange::Modified("object.yaml".into()),
        ),
        (
            "main.tf",
            "resource \"aws_instance\" \"after\" {}",
            RepoChange::Modified("main.tf".into()),
        ),
        (
            "extra.tf",
            "resource \"aws_s3_bucket\" \"extra\" {}",
            RepoChange::Added("extra.tf".into()),
        ),
        (
            "later.yaml",
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: later\n",
            RepoChange::Added("later.yaml".into()),
        ),
    ] {
        write_file(&root, path, content);
        apply_changes(&mut index, &root, &limits, &[change]);
        assert_full_surface_equivalent(&index, &root);
    }
    std::fs::remove_file(root.join("extra.tf")).unwrap();
    apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Deleted("extra.tf".into())],
    );
    assert_full_surface_equivalent(&index, &root);
}

#[test]
fn registration_only_modules_add_change_remove_match_clean_indexes() {
    let route = "from fastapi import FastAPI\nimport os\napp = FastAPI()\n@app.get('/one')\ndef one(): os.remove('/one')\n";
    let command = "package cmd\nimport (\"github.com/spf13/cobra\"; \"os\")\nvar cmd = &cobra.Command{Use: \"one args\", Run: func(cmd *cobra.Command, args []string) { os.Remove(\"/one\") }}\n";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p10-registration-only",
        &[
            ("api.py", "def unused(): pass\n"),
            ("cmd.go", "package cmd\n"),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    assert!(index.entrypoints.is_empty());
    for (file, source) in [
        ("api.py", route.to_string()),
        ("cmd.go", command.to_string()),
        ("api.py", route.replace("/one", "/two")),
        ("cmd.go", command.replace("one", "two")),
        (
            "api.py",
            route.replace(
                "@app.get",
                "app.state.ready = True\napp.dependency_overrides[object] = None\n@app.get",
            ),
        ),
        (
            "api.py",
            route.replace("@app.get", "app.prefix = unknown\n@app.get"),
        ),
        ("api.py", "def unused(): pass\n".into()),
        ("cmd.go", "package cmd\n".into()),
    ] {
        write_file(&root, file, &source);
        apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified(file.into())],
        );
        assert_full_surface_equivalent(&index, &root);
        index = build_index(&root, IndexLimits::default());
    }
    assert!(index.entrypoints.is_empty());
    write_file(&root, "new.py", route);
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("new.py".into())],
    );
    assert_eq!(index.entrypoints.len(), 1);
    assert_full_surface_equivalent(&index, &root);
    std::fs::remove_file(root.join("new.py")).unwrap();
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("new.py".into())],
    );
    assert!(index.entrypoints.is_empty());
    assert_full_surface_equivalent(&index, &root);
}

#[test]
fn ruby_load_paths_and_gem_metadata_match_clean_rebuilds() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "oracle-ruby-load-path",
        &[
            (
                "run.rb",
                "$LOAD_PATH.unshift(File.join(__dir__, 'core'))\nrequire 'feature'\nrequire 'nokogiri'\n",
            ),
            ("core/feature.rb", "X = File.delete('/core')\n"),
            ("other/feature.rb", "X = File.delete('/other')\n"),
            ("Gemfile.lock", "GEM\n  specs:\n    nokogiri (1.16.0)\n"),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    for (path, content) in [
        (
            "run.rb",
            "$LOAD_PATH.unshift(File.join(__dir__, 'other'))\nrequire 'feature'\nrequire 'nokogiri'\n",
        ),
        ("Gemfile.lock", "GEM\n  specs:\n    nokogiri (1.17.0)\n"),
        ("Gemfile.lock", "GEM\n  specs:\n"),
    ] {
        let before = index.fingerprint.clone();
        write_file(&root, path, content);
        apply_changes(
            &mut index,
            &root,
            &IndexLimits::default(),
            &[RepoChange::Modified(path.into())],
        );
        assert_ne!(index.fingerprint, before);
        assert_full_surface_equivalent(&index, &root);
    }
}
