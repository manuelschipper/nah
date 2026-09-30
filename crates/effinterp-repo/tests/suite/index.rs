use effinterp_proto::CoverageLevel;
use effinterp_repo::{EntrypointOutcome, IndexLimits, build_index, effects_of, save_index};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use super::live;

/// The worst coverage level on each entrypoint's forward surface, with the
/// reasons of the boundaries that surface carries.
fn forward_coverage(root: &std::path::Path) -> Vec<(String, CoverageLevel, Vec<String>)> {
    let index = live(root);
    index
        .entrypoints
        .iter()
        .map(|analyzed| {
            let id = analyzed.entrypoint.id.clone();
            let report = effects_of(&index, &id)
                .unwrap()
                .payload
                .into_effects()
                .unwrap();
            let level = report
                .coverage
                .values()
                .map(|claim| claim.level)
                .max_by_key(|level| match level {
                    CoverageLevel::Full => 0,
                    CoverageLevel::Partial => 1,
                    CoverageLevel::None => 2,
                })
                .unwrap_or(CoverageLevel::None);
            let boundaries = report
                .boundaries
                .into_iter()
                .map(|boundary| boundary.reason.as_str().to_string())
                .collect();
            (id, level, boundaries)
        })
        .collect()
}

#[test]
fn opaque_python_module_launch_leaves_its_entrypoint_partial() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "repo-suite-index-semantic-partial",
        &[
            ("direct.sh", "#!/bin/sh\nrm -f /direct\n"),
            ("opaque.sh", "#!/bin/sh\npython -m meta_ads_mcp\n"),
        ],
    );
    let coverage = forward_coverage(&root);
    assert_eq!(coverage.len(), 2);
    let (_, direct, _) = coverage.iter().find(|(id, ..)| id == "direct.sh").unwrap();
    assert_eq!(*direct, CoverageLevel::Full);
    let (_, opaque, boundaries) = coverage.iter().find(|(id, ..)| id == "opaque.sh").unwrap();
    assert_eq!(*opaque, CoverageLevel::Partial);
    assert!(
        boundaries
            .iter()
            .any(|reason| reason == "unrecoverable_source"),
        "{boundaries:?}"
    );
}

#[test]
fn index_limit_overrides_reach_the_crawl_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "repo-suite-index-limit-overrides",
        &[
            ("one.sh", "#!/bin/sh\nrm /one\n"),
            ("two.sh", "#!/bin/sh\nrm /two\n"),
        ],
    );
    let limited = |name: &str, value: u64| {
        let mut limits = IndexLimits::default();
        limits.set(name, value).unwrap();
        build_index(&root, limits)
    };

    let index: serde_json::Value =
        serde_json::from_str(&save_index(&limited("crawl.max_files", 1))).unwrap();
    assert_eq!(index["limits"]["crawl"]["max_files"], 1);
    assert!(index["skipped"].as_array().unwrap().iter().any(|skip| {
        skip["category"] == "limit"
            && skip["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("max_files"))
    }));

    let index = limited("repository.max_repo_work_units", 3);
    assert_eq!(index.entrypoints.len(), 2);
    assert_ne!(
        index.snapshot_state,
        effinterp_proto::AnalysisStatus::Complete
    );
    let limited_ids: Vec<_> = index
        .entrypoints
        .iter()
        .filter(|analyzed| matches!(analyzed.outcome, EntrypointOutcome::LimitReached { .. }))
        .map(|analyzed| analyzed.entrypoint.id.clone())
        .collect();
    assert!(!limited_ids.is_empty());
    for id in limited_ids {
        assert!(
            effects_of(&index, &id).is_none(),
            "{id} has no analyzed surface"
        );
    }
}
