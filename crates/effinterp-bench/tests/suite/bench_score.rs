use std::collections::BTreeMap;

use effinterp_bench::invocation::corpus::BenchRow;
use effinterp_bench::invocation::judge::{Verdict, judge_plan};
use effinterp_bench::invocation::score::{
    AdversarialScore, Drop, ExeShare, Invocation, SCOREBOARD_SCHEMA, Scoreboard, SourceScore,
    score_source,
};
use effinterp_bench::invocation::tiers::{Bucket, bucket_plan};
use effinterp_bench::invocation::{Analyzed, FailureKind, SubjectOutcome};
use effinterp_bench::latency::{
    COLD_CATALOG_TARGET_US, ColdStart, LatencySection, NAH_P99_TARGET_US,
};
use effinterp_bench::nah::classify::ParityClass;
use effinterp_bench::nah::report::{Ceilings, Parity};
use effinterp_bench::repos::expectations::Matched;
use effinterp_bench::repos::isolate::IsolateStatus;
use effinterp_bench::repos::score::{EntryBuckets, RepoRow, ReposSection, ResourceMix};
use effinterp_bench::run::Plane;
use effinterp_bench::run::gate::check_gate_rules;
use effinterp_engine::Engine;
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Operation, Plan, ResourceExpr,
    ResourceIdentity, Subject,
};

fn delete_plan() -> Plan {
    Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "rm -rf /tmp/x".into(),
            cwd: Some("/corpus/test".into()),
            context: Default::default(),
        })
        .unwrap()
}

fn boundary(reason: BoundaryReason, domain: &str) -> Boundary {
    Boundary {
        reason,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        domains: vec![Domain::new(domain)],
        affected_resource: None,
        callee: None,
        provenance: Vec::new(),
        limit: None,
        detail: None,
    }
}

#[test]
fn plans_land_in_one_bucket() {
    let complete = delete_plan();
    assert!(complete.boundaries.is_empty());
    assert_eq!(bucket_plan(&complete), Bucket::Complete);

    let mut dynamic = complete.clone();
    dynamic
        .boundaries
        .push(boundary(BoundaryReason::DYNAMIC_CALL, "process"));
    dynamic
        .boundaries
        .push(boundary(BoundaryReason::REMOTE_COMMAND, "network"));
    assert_eq!(bucket_plan(&dynamic), Bucket::Dynamic);

    let mut unobservable = dynamic.clone();
    unobservable
        .boundaries
        .push(boundary(BoundaryReason::UNRESOLVED_SOURCE, "filesystem"));
    assert_eq!(bucket_plan(&unobservable), Bucket::Unobservable);

    let mut gap = unobservable.clone();
    gap.boundaries.push(boundary(
        BoundaryReason::new("never_seen_reason"),
        "process",
    ));
    assert_eq!(bucket_plan(&gap), Bucket::Gap);
}

/// The headline counts only rows that landed in a non-gap bucket: a failed
/// row was not understood, so the share is not `1 - gap`.
#[test]
fn understood_excludes_failed_rows() {
    let row = |weight| BenchRow {
        file: "f.jsonl".into(),
        id: format!("row-{weight}"),
        source: "swe".into(),
        kind: "shell".into(),
        weight,
        category: None,
        expected_effects: Vec::new(),
        subject: Subject::Shell {
            source: "true".into(),
            cwd: None,
            context: Default::default(),
        },
    };
    let analyzed = |reasons: &[&str]| SubjectOutcome {
        elapsed_ms: 0.0,
        result: Ok(Analyzed {
            reasons: reasons.iter().map(|r| r.to_string()).collect(),
            gap_classes: Default::default(),
            gap_commands: Default::default(),
            unmodeled: Default::default(),
            any_domain_none: false,
            all_full: false,
            only_process_exec: false,
            verdict: None,
            mutation: None,
        }),
    };
    let rows = [row(1), row(2), row(3), row(4)];
    let outcomes = [
        analyzed(&[]),
        analyzed(&["dynamic_source"]),
        analyzed(&["never_seen_reason"]),
        SubjectOutcome {
            elapsed_ms: 0.0,
            result: Err(FailureKind::Deadline),
        },
    ];
    let score = score_source(&rows, &outcomes);
    assert_eq!(score.buckets.gap.weighted_share, 0.3);
    assert_eq!(score.understood.unique, 2);
    assert_eq!(score.understood.weighted_share, 0.3);
}

#[test]
fn judge_yields_every_verdict() {
    let sound = delete_plan();
    let expected = ["filesystem.delete".to_string()];
    assert_eq!(judge_plan(&sound, &expected), Verdict::Sound);

    let mut boundary_only = sound.clone();
    boundary_only.effects.clear();
    boundary_only
        .boundaries
        .push(boundary(BoundaryReason::UNMODELED_COMMAND, "filesystem"));
    assert_eq!(judge_plan(&boundary_only, &expected), Verdict::BoundaryOnly);

    let mut silent = sound.clone();
    silent.effects.clear();
    assert!(silent.coverage.is_full(&Domain::new("filesystem")));
    assert_eq!(judge_plan(&silent, &expected), Verdict::SilentMiss);

    let mut wrong = sound.clone();
    wrong.subject = Subject::Shell {
        source: "cat < /dev/tcp/evil/80".into(),
        cwd: None,
        context: Default::default(),
    };
    wrong.effects[0].operation = Operation::new("filesystem.read");
    wrong.effects[0].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/dev/tcp/evil/80".into(),
        },
    };
    assert_eq!(
        judge_plan(&wrong, &["network.connect".to_string()]),
        Verdict::WrongResource
    );
}

fn board(edit: impl FnOnce(&mut Scoreboard)) -> Scoreboard {
    let mut source = SourceScore::default();
    source.buckets.complete.weighted_share = 0.5;
    source.buckets.gap.weighted_share = 0.5;
    source.top_unmodeled = (0..21)
        .map(|i| ExeShare {
            exe: format!("exe{i:02}"),
            any_share: 0.05,
            unique: 1,
            sole_share: 0.021 - 0.001 * i as f64,
        })
        .collect();
    // exe21 and exe22 sit outside the displayed ranking but keep measured
    // sole shares in the complete map.
    source.unmodeled_sole_shares = source
        .top_unmodeled
        .iter()
        .map(|e| (e.exe.clone(), e.sole_share))
        .chain([("exe21".to_string(), 0.0015), ("exe22".to_string(), 0.0)])
        .collect();
    let mut board = Scoreboard {
        schema: SCOREBOARD_SCHEMA.into(),
        correctness: effinterp_bench::invocation::score::Correctness {
            corpus_digest: "d".into(),
            semantic: Some(effinterp_bench::layered::SemanticScore {
                cases: 1,
                passed: 1,
                ..Default::default()
            }),
            adversarial: Some(AdversarialScore::default()),
            parity: Some(Parity::default()),
        },
        coverage: Invocation {
            corpus_digest: "d".into(),
            sources: BTreeMap::from([("swe".to_string(), source)]),
        },
        repos: Some(ReposSection {
            corpus_digest: "r".into(),
            selected: Vec::new(),
            repos: BTreeMap::from([(
                "owner/repo".to_string(),
                RepoRow {
                    status: IsolateStatus::Analyzed,
                    entrypoints: 2,
                    effects: 3,
                    diagnostics: Some(Default::default()),
                    real_entry_nonempty: true,
                    recall: Matched {
                        matched: 1,
                        total: 1,
                    },
                    facts: Matched {
                        matched: 1,
                        total: 2,
                    },
                    forbidden_hits: 0,
                    buckets: EntryBuckets::default(),
                    resource_mix: ResourceMix::default(),
                    wall_ms: 10,
                    peak_rss_kb: 10,
                },
            )]),
            understood_share: 0.0,
            strata: BTreeMap::new(),
            unlocked: None,
        }),
        performance: effinterp_bench::invocation::score::Performance {
            latency: Some(LatencySection {
                nah_p99_us: NAH_P99_TARGET_US,
                cold_start: Some(ColdStart {
                    cold_process_us: COLD_CATALOG_TARGET_US,
                    cold_catalog_us: COLD_CATALOG_TARGET_US,
                }),
                ..Default::default()
            }),
            host: BTreeMap::new(),
        },
        provenance: BTreeMap::new(),
    };
    edit(&mut board);
    board
}

fn ceilings() -> Ceilings {
    Ceilings {
        total: BTreeMap::from([("missing_effect".into(), 1)]),
        per_guard: BTreeMap::new(),
    }
}

fn parity(board: &mut Scoreboard) -> &mut Parity {
    board.correctness.parity.as_mut().unwrap()
}

fn repo(board: &mut Scoreboard) -> &mut RepoRow {
    board
        .repos
        .as_mut()
        .unwrap()
        .repos
        .get_mut("owner/repo")
        .unwrap()
}

fn swe(board: &mut Scoreboard) -> &mut SourceScore {
    board.coverage.sources.get_mut("swe").unwrap()
}

fn sole(board: &mut Scoreboard, exe: &str, share: f64) {
    swe(board)
        .unmodeled_sole_shares
        .insert(exe.to_string(), share);
}

fn drop() -> Drop {
    Drop {
        id: "swe-1".into(),
        word: "/tmp/x".into(),
        operation: "filesystem.delete".into(),
        domain: "filesystem".into(),
    }
}

#[test]
fn gate_rules_fail_and_pass() {
    let baseline = board(|_| {});
    // Each case is (rule, a board that must fail it, a board that must pass).
    let cases: Vec<(&str, Scoreboard, Scoreboard)> = vec![
        // understood drop > 0.5 pt / within 0.5 pt (gap rise mirrored).
        (
            "(a) ",
            board(|b| {
                swe(b).buckets.complete.weighted_share = 0.494;
                swe(b).buckets.gap.weighted_share = 0.506;
            }),
            board(|b| {
                swe(b).buckets.complete.weighted_share = 0.495;
                swe(b).buckets.gap.weighted_share = 0.505;
            }),
        ),
        // a panic above baseline / deadlines above baseline (never gated).
        (
            "(b) ",
            board(|b| swe(b).failures.panic = 1),
            board(|b| swe(b).failures.deadline = 7),
        ),
        // a new silent drop / one already in the baseline.
        (
            "(d) ",
            board(|b| swe(b).silent_drops.drops.push(drop())),
            board(|_| {}),
        ),
        // a new top-20 executable rising > 0.1 pt / an executable omitted
        // from the displayed ranking entering the top 20 with its measured
        // baseline share unchanged, because another one left.
        (
            "(e) ",
            board(|b| sole(b, "exe20", 0.0025)),
            board(|b| {
                sole(b, "exe00", 0.0);
                sole(b, "exe21", 0.0015);
            }),
        ),
        // a parity class above its ceiling / at it.
        (
            "(g) ",
            board(|b| {
                parity(b).classes.insert(ParityClass::MissingEffect, 2);
            }),
            board(|b| {
                parity(b).classes.insert(ParityClass::MissingEffect, 1);
            }),
        ),
        // a repo loses its real entry surface / improves on a slower host.
        (
            "(h) ",
            board(|b| repo(b).real_entry_nonempty = false),
            board(|b| {
                repo(b).facts.matched = 2;
                repo(b).wall_ms = 99;
            }),
        ),
        // nah p99 above the target / at it.
        (
            "(i) ",
            board(|b| b.performance.latency.as_mut().unwrap().nah_p99_us = NAH_P99_TARGET_US + 1),
            board(|_| {}),
        ),
        // a cold catalog measurement above the target / at it.
        (
            "(k) ",
            board(|b| {
                b.performance
                    .latency
                    .as_mut()
                    .unwrap()
                    .cold_start
                    .as_mut()
                    .unwrap()
                    .cold_catalog_us = COLD_CATALOG_TARGET_US + 1;
            }),
            board(|_| {}),
        ),
    ];
    for (name, failing, passing) in &cases {
        let results = check_gate_rules(&baseline, failing, &ceilings(), &Plane::ALL, &[]);
        let rule = results
            .iter()
            .position(|r| r.rule.starts_with(name))
            .unwrap();
        assert!(
            !results[rule].failures.is_empty(),
            "{}: {results:?}",
            results[rule].rule
        );
        assert!(
            results
                .iter()
                .all(|r| r.rule == results[rule].rule || r.failures.is_empty()),
            "{}: {results:?}",
            results[rule].rule
        );
        let results = check_gate_rules(&baseline, passing, &ceilings(), &Plane::ALL, &[]);
        assert!(
            results.iter().all(|r| r.failures.is_empty()),
            "{}: {results:?}",
            results[rule].rule
        );
    }
    // Removing fact-recall gates must not let newly silent analyses pass.
    let measured = board(|b| repo(b).diagnostics = Some(Default::default()));
    let silent = board(|b| {
        repo(b).diagnostics = Some(effinterp_bench::repos::score::CoverageDiagnostics {
            silent_entrypoints: 1,
            ..Default::default()
        });
    });
    assert!(
        check_gate_rules(&measured, &silent, &ceilings(), &[Plane::Repositories], &[])
            .iter()
            .any(|r| r.rule.starts_with("(h)") && !r.failures.is_empty())
    );
    // (e) a genuine rise of an executable the baseline measured at zero
    // outside the displayed ranking still fails once it enters the top 20.
    let rising = board(|b| sole(b, "exe22", 0.0025));
    assert!(
        !check_gate_rules(&baseline, &rising, &ceilings(), &Plane::ALL, &[])
            .into_iter()
            .find(|r| r.rule.starts_with("(e)"))
            .unwrap()
            .failures
            .is_empty()
    );
    // A silent drop already in the baseline passes (d); the shared-drop pair.
    let with_drop = board(|b| swe(b).silent_drops.drops.push(drop()));
    assert!(
        check_gate_rules(&with_drop, &with_drop, &ceilings(), &Plane::ALL, &[])
            .iter()
            .all(|r| r.failures.is_empty())
    );
    // Correctness failures cannot disappear behind a coverage-only pass, and
    // coverage gaps cannot turn an unmeasured correctness result into failure.
    let broken = board(|b| {
        b.correctness
            .semantic
            .as_mut()
            .unwrap()
            .failures
            .insert("wrong-resource".into(), "resource mismatch".into());
    });
    assert!(
        check_gate_rules(&baseline, &broken, &ceilings(), &[Plane::Correctness], &[])
            .iter()
            .any(|r| r.rule.starts_with("(j)") && !r.failures.is_empty())
    );
    assert!(
        check_gate_rules(&baseline, &broken, &ceilings(), &[Plane::Coverage], &[])
            .iter()
            .all(|r| r.failures.is_empty())
    );
    // An old performance record without the cold section is visibly skipped,
    // never reported as a passing cold-start measurement.
    let missing_cold = board(|b| {
        b.performance.latency.as_mut().unwrap().cold_start = None;
    });
    let results = check_gate_rules(
        &baseline,
        &missing_cold,
        &ceilings(),
        &[Plane::Performance],
        &[],
    );
    let cold = results.iter().find(|r| r.rule.starts_with("(k)")).unwrap();
    assert_eq!(cold.skipped, Some("cold start not measured"));
    assert!(cold.failures.is_empty());
    let failed_coverage = board(|b| swe(b).failures.panic = 1);
    assert!(
        check_gate_rules(
            &baseline,
            &failed_coverage,
            &ceilings(),
            &[Plane::Correctness],
            &[]
        )
        .iter()
        .all(|r| r.failures.is_empty())
    );
}
