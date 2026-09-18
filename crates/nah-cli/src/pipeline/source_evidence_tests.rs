//! Evidence for the scripts and imports an invocation is about to run.

use nah_effinterp::{EvidenceBudget, SelectedInput, SourceObservation};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::effects::{EffectGraph, FactPayload, FilesystemOperation, Knowledge};
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Appears in every helper body so a leak into evidence, provenance, or a bound
/// observation is unambiguous.
const HELPER_BODY_MARKER: &str = "helper-body-marker-8f21";

const WIPE_TARGET: &str = "/repo/data";

fn context() -> Ctx {
    Ctx::new(
        Platform::Linux,
        AbsolutePath::new(Platform::Linux, "/home/test").unwrap(),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap()
}

/// A budget long enough that these deterministic cases never race it.
fn budget() -> EvidenceBudget {
    EvidenceBudget::after(std::time::Duration::from_secs(30))
}

/// Temporary directories are symlinked on some hosts; analysis anchors on the
/// canonical cwd the invocation would actually run in.
fn workspace(files: &[(&str, String)]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    for (name, contents) in files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    (dir, root)
}

fn helper(body: &str) -> String {
    format!(
        "import shutil\n\n\n# {HELPER_BODY_MARKER}\ndef wipe():\n    shutil.rmtree('{WIPE_TARGET}')\n{body}"
    )
}

fn shell_input(cwd: &Path, command: &str) -> ToolCallInput {
    ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({ "command": command }),
        cwd.to_str().unwrap(),
        None,
    )
    .unwrap()
}

fn analyze(input: SelectedInput<'_>, budget: &EvidenceBudget) -> super::OptionalEvidenceAnalysis {
    super::analyze_optional_with(input, &context(), budget, |request| {
        nah_observe::fulfill(request).map_err(|_| "observation failed".to_owned())
    })
    .unwrap()
}

/// Whether the run would recursively delete `path` according to this evidence.
fn deletes_recursively(graph: &EffectGraph, path: &str) -> bool {
    graph.facts.iter().any(|fact| match &fact.payload {
        FactPayload::FilesystemAccess {
            operation: FilesystemOperation::Delete,
            target,
            recursive: Knowledge::Known(true),
            ..
        } => graph.resources.iter().any(|resource| {
            resource.id == *target && resource.identity.name == Knowledge::Known(path.into())
        }),
        _ => false,
    })
}

fn observed_paths(observations: &[SourceObservation]) -> BTreeSet<&str> {
    observations
        .iter()
        .filter_map(SourceObservation::observed_path)
        .collect()
}

fn unavailable_reasons(observations: &[SourceObservation]) -> BTreeSet<&str> {
    observations
        .iter()
        .filter_map(|observation| match observation {
            SourceObservation::Unavailable { reason, .. } => Some(*reason),
            SourceObservation::Observed { .. } => None,
        })
        .collect()
}

#[test]
fn inline_direct_and_imported_source_reach_the_same_destructive_evidence() {
    let inline = format!("import shutil\n\nshutil.rmtree('{WIPE_TARGET}')\n");
    let inline_input = ToolCallInput::new(
        SchemaVersion::V1,
        "execute_code",
        json!({"code": inline, "language": "python"}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(json!({ "code": inline }), true);
    let inline_evidence = analyze(
        SelectedInput::Source {
            input: &inline_input,
            source: &inline,
            language: nah_effinterp::SourceLanguage::Python,
        },
        &budget(),
    );
    assert!(deletes_recursively(
        inline_evidence.evidence.graph(),
        WIPE_TARGET
    ));

    let (_direct, direct_root) = workspace(&[(
        "cleanup.py",
        format!("import shutil\n\nshutil.rmtree('{WIPE_TARGET}')\n"),
    )]);
    let direct_input = shell_input(&direct_root, "python3 cleanup.py");
    let direct = analyze(SelectedInput::Shell(&direct_input), &budget());
    assert!(deletes_recursively(direct.evidence.graph(), WIPE_TARGET));
    assert_eq!(
        observed_paths(&direct.source_observations),
        BTreeSet::from([direct_root.join("cleanup.py").to_str().unwrap()])
    );

    let (_imported, imported_root) = workspace(&[
        ("cleanup.py", "import helper\n\nhelper.wipe()\n".to_owned()),
        ("helper.py", helper("")),
    ]);
    let imported_input = shell_input(&imported_root, "python3 cleanup.py");
    let imported = analyze(SelectedInput::Shell(&imported_input), &budget());
    assert!(deletes_recursively(imported.evidence.graph(), WIPE_TARGET));
    assert!(
        observed_paths(&imported.source_observations)
            .contains(imported_root.join("helper.py").to_str().unwrap())
    );
}

#[test]
fn a_dormant_helper_function_contributes_no_destructive_evidence() {
    let (_workspace, root) = workspace(&[
        ("cleanup.py", "import helper\n\nprint(helper)\n".to_owned()),
        ("helper.py", helper("")),
    ]);
    let input = shell_input(&root, "python3 cleanup.py");
    let analysis = analyze(SelectedInput::Shell(&input), &budget());
    assert!(
        observed_paths(&analysis.source_observations)
            .contains(root.join("helper.py").to_str().unwrap())
    );
    assert!(!deletes_recursively(analysis.evidence.graph(), WIPE_TARGET));
}

#[test]
fn edited_helper_bytes_produce_fresh_identity_and_fresh_evidence() {
    let (_workspace, root) = workspace(&[
        ("cleanup.py", "import helper\n\nhelper.wipe()\n".to_owned()),
        ("helper.py", helper("")),
    ]);
    let input = shell_input(&root, "python3 cleanup.py");
    let before = analyze(SelectedInput::Shell(&input), &budget());
    let unchanged = analyze(SelectedInput::Shell(&input), &budget());
    assert_eq!(
        before.provenance.input_fingerprint,
        unchanged.provenance.input_fingerprint
    );

    fs::write(
        root.join("helper.py"),
        helper("\n\ndef keep():\n    pass\n"),
    )
    .unwrap();
    let after = analyze(SelectedInput::Shell(&input), &budget());
    assert_ne!(
        before.provenance.input_fingerprint,
        after.provenance.input_fingerprint
    );
    assert_ne!(before.source_observations, after.source_observations);

    fs::write(root.join("helper.py"), "def wipe():\n    pass\n").unwrap();
    let dropped = analyze(SelectedInput::Shell(&input), &budget());
    assert!(!deletes_recursively(dropped.evidence.graph(), WIPE_TARGET));
}

#[test]
fn unresolvable_sources_stay_explicit_and_never_carry_their_bytes() {
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside.py"), helper("")).unwrap();
    let (_workspace, root) = workspace(&[
        (
            "cleanup.py",
            "import absent\nimport escape\nimport cycle_a\n".to_owned(),
        ),
        ("cycle_a.py", "import cycle_b\n".to_owned()),
        ("cycle_b.py", "import cycle_a\n".to_owned()),
        ("unrelated.py", helper("")),
    ]);
    std::os::unix::fs::symlink(outside.path().join("outside.py"), root.join("escape.py")).unwrap();
    let input = shell_input(&root, "python3 cleanup.py");
    let analysis = analyze(SelectedInput::Shell(&input), &budget());

    let reasons = unavailable_reasons(&analysis.source_observations);
    assert!(reasons.contains("missing"), "{reasons:?}");
    assert!(reasons.contains("escapes"), "{reasons:?}");
    // An import cycle terminates without re-reading either module.
    assert!(
        observed_paths(&analysis.source_observations)
            .contains(root.join("cycle_b.py").to_str().unwrap())
    );
    // Only demanded sources are read: nothing crawls the rest of the directory.
    assert!(
        !observed_paths(&analysis.source_observations)
            .contains(root.join("unrelated.py").to_str().unwrap())
    );
    assert!(!deletes_recursively(analysis.evidence.graph(), WIPE_TARGET));

    for projection in [
        format!("{:?}", analysis.evidence),
        serde_json::to_string(&analysis.observation).unwrap(),
        analysis.provenance.input_fingerprint.clone(),
        format!("{:?}", analysis.source_observations),
    ] {
        assert!(!projection.contains(HELPER_BODY_MARKER));
        assert!(!projection.contains("rmtree"));
    }
}

#[test]
fn an_expired_budget_stops_source_reads_and_leaves_the_gap_explicit() {
    let (_workspace, root) = workspace(&[
        ("cleanup.py", "import helper\n\nhelper.wipe()\n".to_owned()),
        ("helper.py", helper("")),
    ]);
    let input = shell_input(&root, "python3 cleanup.py");
    assert!(deletes_recursively(
        analyze(SelectedInput::Shell(&input), &budget())
            .evidence
            .graph(),
        WIPE_TARGET
    ));

    let budget = budget();
    budget.expire();
    let analysis = analyze(SelectedInput::Shell(&input), &budget);
    // No source read is issued once the budget is spent, and the unfinished
    // analysis stays explicit instead of claiming the run is harmless.
    assert!(observed_paths(&analysis.source_observations).is_empty());
    assert!(!deletes_recursively(analysis.evidence.graph(), WIPE_TARGET));
    assert!(!analysis.evidence.graph().gaps.is_empty());
}

#[test]
fn source_observation_writes_no_index_snapshot_or_daemon_state() {
    let (_workspace, root) = workspace(&[
        ("cleanup.py", "import helper\n\nhelper.wipe()\n".to_owned()),
        ("helper.py", helper("")),
    ]);
    let before = entries(&root);
    let input = shell_input(&root, "python3 cleanup.py");
    analyze(SelectedInput::Shell(&input), &budget());
    assert_eq!(entries(&root), before);
}

fn entries(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
        .collect()
}
