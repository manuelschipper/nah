//! Evidence for the scripts and imports an invocation is about to run.

use nah_effinterp::{
    DeclaredSourceObservations, EvidenceBudget, RefusalKind, SelectedInput, SourceObservation,
    SourceProvider,
};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::effects::{EffectGraph, FactPayload, FilesystemOperation, Knowledge};
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
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

fn analyze(input: SelectedInput<'_>, budget: &EvidenceBudget) -> super::EvidenceAnalysis {
    super::analyze_with(input, &context(), budget, |request| {
        nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
            .map_err(|_| "observation failed".to_owned())
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
            SourceObservation::Observed { .. } | SourceObservation::Listed { .. } => None,
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
fn an_expired_budget_stops_source_reads_and_returns_a_typed_refusal() {
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
    let sources = DeclaredSourceObservations::new(
        AbsolutePath::new(Platform::Linux, root.to_str().unwrap()).unwrap(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let refusal = super::analyze_observed(
        SelectedInput::Shell(&input),
        &context(),
        &budget,
        &nah_proto::runtime_protection::SelfProtectionProjection::default(),
        Some(&sources),
        &mut |_| panic!("an expired budget must not request observations"),
    )
    .unwrap_err();
    assert_eq!(refusal.kind, RefusalKind::DeadlineExceeded);
    assert_eq!(refusal.code, "deadline-exceeded");
    assert_eq!(refusal.component, "effinterp-engine");
    assert!(sources.observations().is_empty());

    // Once the observed host binds the plan, expiry stops re-planning but not
    // evaluation: the shipped guards still read the established deletion,
    // whether the budget runs out in the bound round's environment
    // observation or in its full observation.
    let input = shell_input(&root, "rm -rf ~");
    for environment_requests_before_expiry in [1, 2] {
        let late_budget = EvidenceBudget::after(std::time::Duration::from_secs(30));
        let mut environment_requests = 0;
        let late = super::analyze_with(
            SelectedInput::Shell(&input),
            &context(),
            &late_budget,
            |request| {
                let observation =
                    nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                        .map_err(|_| "observation failed".to_owned());
                if request.request_id() == "effinterp-environment-v1" {
                    environment_requests += 1;
                }
                if environment_requests > environment_requests_before_expiry
                    || request.request_id() != "effinterp-environment-v1"
                {
                    late_budget.expire();
                }
                observation
            },
        )
        .unwrap();
        assert!(late.guard_matches.matched("fs-outside-workspace-delete"));
        assert_eq!(
            late.evidence.evaluation(),
            nah_proto::effects::EvaluationStatus::Refused {
                component: "observation",
                code: "deadline-exceeded",
            }
        );
    }

    // A deadline that stops the engine's walk keeps what the walk established:
    // the deletion before it still blocks, and nothing after it is analyzed.
    let marker = root.join("walked-past-the-deletion");
    let input = shell_input(
        &root,
        &format!("rm -rf ~; cat {}; rm -rf /", marker.display()),
    );
    let environment_observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let walk_budget = std::sync::Arc::new(std::sync::OnceLock::<EvidenceBudget>::new());
    let resolver = ExpireOnPath {
        path: marker.to_str().unwrap().to_owned(),
        armed: environment_observed.clone(),
        budget: walk_budget.clone(),
    };
    let _ = walk_budget.set(
        EvidenceBudget::after(std::time::Duration::from_secs(30))
            .with_observations(std::sync::Arc::new(resolver)),
    );
    let walked = super::analyze_with(
        SelectedInput::Shell(&input),
        &context(),
        walk_budget.get().unwrap(),
        |request| {
            if request.request_id() == "effinterp-environment-v1" {
                environment_observed.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|_| "observation failed".to_owned())
        },
    )
    .unwrap();
    assert!(walked.guard_matches.matched("fs-outside-workspace-delete"));
    assert!(!walked.guard_matches.matched("fs-system-tree"));
    assert_eq!(
        walked.evidence.evaluation(),
        nah_proto::effects::EvaluationStatus::Refused {
            component: "effinterp-engine",
            code: "deadline-exceeded",
        }
    );
}

/// Answers no path fact, and expires `budget` when the engine asks for `path`
/// once `armed`: during the round planned with the observed host.
struct ExpireOnPath {
    path: String,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    budget: std::sync::Arc<std::sync::OnceLock<EvidenceBudget>>,
}

impl nah_effinterp::ObservationResolver for ExpireOnPath {
    fn observe(
        &self,
        query: &nah_proto::effinterp_proto::ObservationQuery,
        _budget: nah_effinterp::ObservationBudget,
    ) -> nah_proto::effinterp_proto::ObservationOutcome {
        if self.armed.load(std::sync::atomic::Ordering::Relaxed)
            && matches!(
                query,
                nah_proto::effinterp_proto::ObservationQuery::Path { path } if *path == self.path
            )
        {
            self.budget.get().unwrap().expire();
        }
        nah_proto::effinterp_proto::ObservationOutcome::Refused(
            nah_proto::effinterp_proto::ObservationRefusal::Unobserved,
        )
    }
}

/// A guard whose queries ran out of matcher work has not shown its danger
/// absent. The analysis names it and refuses the evaluation, which a
/// fail-closed hook blocks on, rather than reporting the guard as silent.
#[test]
fn exhausted_guard_work_refuses_the_evaluation() {
    let (_workspace, root) = workspace(&[]);
    let input = shell_input(&root, "rm -rf ~");
    let analysis = analyze(SelectedInput::Shell(&input), &budget());
    assert!(
        analysis
            .guard_matches
            .matched("fs-outside-workspace-delete")
    );
    assert!(analysis.evaluation_refusal.is_none());

    let starved = budget().with_guard_work(nah_policy::QueryLimits {
        max_steps: 0,
        own_steps: 0,
        shared_steps: 0,
        ..nah_policy::QueryLimits::default()
    });
    let analysis = analyze(SelectedInput::Shell(&input), &starved);
    assert!(
        !analysis
            .guard_matches
            .matched("fs-outside-workspace-delete")
    );
    assert!(
        analysis
            .guard_matches
            .exceeded
            .contains(&"fs-outside-workspace-delete")
    );
    let refusal = analysis.evaluation_refusal.expect("evaluation refusal");
    assert_eq!(
        (refusal.component, refusal.code),
        ("shipped-guards", "guard-work-limit")
    );
    assert_eq!(
        analysis.evidence.evaluation(),
        nah_proto::effects::EvaluationStatus::Refused {
            component: "shipped-guards",
            code: "guard-work-limit",
        }
    );
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

#[test]
fn lazy_path_evidence_survives_link_changes_and_same_call_aliases_resolve() {
    use nah_proto::effect_annotation::PathLabel;
    use nah_proto::effinterp_proto::{ObservationOutcome, ProvenanceKind};
    let (_workspace, root) = workspace(&[("first", "first".into()), ("second", "second".into())]);
    let link = root.join(".env");
    std::os::unix::fs::symlink(root.join("first"), &link).unwrap();
    let input = shell_input(&root, "cat .env");
    let initial = super::analyze_with(
        SelectedInput::Shell(&input), &context(), &budget(), |request| {
            // A later observation must not replace the fact used by the engine.
            assert!(!request.queries().iter().any(|query| matches!(query,
                nah_proto::observation::ObservationQuery::Path { requested, .. }
                    if requested == link.to_str().unwrap() || requested == root.join("first").to_str().unwrap()
            )));
            fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(root.join("second"), &link).unwrap();
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT).map_err(|error| error.to_string())
        },
    ).unwrap();
    assert!(initial.annotations.iter().any(|annotation| matches!(&annotation.path,
        Some(PathLabel::Resolved { path, sensitivity, .. }) if path.as_str() == root.join("first").to_str().unwrap() && *sensitivity != nah_proto::labels::Sensitivity::None
    )));
    assert!(initial.path_observations.iter().any(|record| matches!(record,
        ProvenanceKind::HostObservation { outcome: ObservationOutcome::Path(fact), .. }
            if fact.followed.known().is_some_and(|target| target.path == root.join("first").to_str().unwrap())
    )));
    let later = analyze(SelectedInput::Shell(&input), &budget());
    assert_ne!(
        initial.provenance.input_fingerprint,
        later.provenance.input_fingerprint
    );
    let redacted =
        serde_json::to_string(&nah_proto::effinterp_proto::redact_plan(&initial.plan)).unwrap();
    assert!(!redacted.contains(root.to_str().unwrap()));

    let input = shell_input(&root, "ln -s first alias && cat alias");
    let same_call = analyze(SelectedInput::Shell(&input), &budget());
    assert!(same_call.path_observations.iter().any(|record| matches!(
        record,
        ProvenanceKind::HostObservation {
            outcome: ObservationOutcome::Path(fact),
            ..
        } if fact.followed.known().is_some_and(|target| target.path == root.join("first").to_str().unwrap())
    )));
    assert!(
        same_call
            .plan
            .effects
            .iter()
            .zip(&same_call.annotations)
            .any(
                |(effect, annotation)| effect.operation.as_str() == "filesystem.read"
                    && matches!(&annotation.path,
                        Some(PathLabel::Resolved { path, .. })
                            if path.as_str() == root.join("first").to_str().unwrap())
            )
    );
}
