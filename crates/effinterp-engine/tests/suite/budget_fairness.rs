//! Metamorphic budget-fairness tests: under deliberately small invocation
//! limits, semantically equivalent reordering of independent regions must
//! yield either the same set of effect domains or explicit starvation
//! boundaries covering the starved regions — never silently different
//! domains.
#![allow(clippy::disallowed_types)]

use std::collections::BTreeSet;

use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{Plan, ProvenanceKind, Subject, validate_plan};

fn analyze(source: &str, max_invocations: u64) -> Plan {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), max_invocations);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

/// Effect domains present in the plan (the operation's dotted prefix).
fn domains(plan: &Plan) -> BTreeSet<String> {
    plan.effects
        .iter()
        .filter_map(|e| e.operation.0.split('.').next().map(str::to_string))
        .collect()
}

/// Source spans of every invocation-budget starvation boundary.
fn starved_spans(plan: &Plan) -> Vec<(u32, u32)> {
    plan.boundaries
        .iter()
        .filter(|b| {
            b.reason.as_str() == "branch_starved"
                || b.reason.as_str() == "execution_limit"
                || (b.reason.as_str() == "limit_saturated"
                    && b.limit.as_deref() == Some("max_execution_nodes"))
        })
        .flat_map(|b| &b.provenance)
        .filter_map(|r| match plan.provenance.get(r.0 as usize)?.kind {
            ProvenanceKind::SourceSpan { start, end } => Some((start, end)),
            _ => None,
        })
        .collect()
}

/// Whether some starvation boundary's span covers `needle` in `source`.
fn starvation_covers(plan: &Plan, source: &str, needle: &str) -> bool {
    let offset = source.find(needle).expect("needle in source") as u32;
    starved_spans(plan)
        .iter()
        .any(|(start, end)| *start <= offset && offset < *end)
}

const CASE_ARMS: [&str; 3] = [
    "a) curl http://one/x; curl http://two/x; curl http://three/x ;;",
    "b) rm /tmp/a ;;",
    "c) git clone http://host/r /tmp/r ;;",
];

fn case_script(order: &[usize]) -> String {
    let arms: Vec<&str> = order.iter().map(|&i| CASE_ARMS[i]).collect();
    format!("case \"$1\" in\n{}\nesac\n", arms.join("\n"))
}

/// Reordering independent case arms under a small budget must not change
/// which effect domains are observed: each arm draws on its own fair share.
#[test]
fn case_arm_reordering_is_domain_stable() {
    let forward = analyze(&case_script(&[0, 1, 2]), 4);
    let reversed = analyze(&case_script(&[2, 1, 0]), 4);
    // Every analyzed command also emits process.exec.
    let expected: BTreeSet<String> = ["network", "filesystem", "git", "process"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(domains(&forward), expected);
    assert_eq!(domains(&reversed), expected);
    // The multi-command arm exceeded its water-fill allocation: starvation
    // is explicit. (The refusal reads branch_starved when the arm's window
    // is below the global limit, limit_saturated when it abuts it.)
    for plan in [&forward, &reversed] {
        assert!(!starved_spans(plan).is_empty());
    }
}

/// A budget too small for any arm's share still reports every arm as
/// starved rather than silently analyzing a source-order prefix.
#[test]
fn undersized_case_budget_starves_all_arms_explicitly() {
    let forward = analyze(&case_script(&[0, 1, 2]), 2);
    let reversed = analyze(&case_script(&[2, 1, 0]), 2);
    assert_eq!(domains(&forward), domains(&reversed));
    for (plan, source) in [
        (&forward, case_script(&[0, 1, 2])),
        (&reversed, case_script(&[2, 1, 0])),
    ] {
        for needle in ["curl", "rm /tmp/a", "git clone"] {
            assert!(
                starvation_covers(plan, &source, needle),
                "no starvation boundary covers {needle:?}"
            );
        }
    }
}

/// Work conservation: a frugal arm's unused share flows to a demanding
/// sibling. The three-curl arm needs 3 of the 4 available invocations —
/// more than an equal split would grant — and completes without any
/// starvation boundary, in either arm order.
#[test]
fn frugal_arm_surplus_lets_demanding_arm_finish() {
    let arms = [CASE_ARMS[0], CASE_ARMS[1]];
    let forward = format!("case \"$1\" in\n{}\n{}\nesac\n", arms[0], arms[1]);
    let reversed = format!("case \"$1\" in\n{}\n{}\nesac\n", arms[1], arms[0]);
    for source in [&forward, &reversed] {
        let plan = analyze(source, 4);
        let expected: BTreeSet<String> = ["network", "filesystem", "process"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(domains(&plan), expected);
        // All three curls were analyzed; nothing starved.
        assert_eq!(
            plan.effects
                .iter()
                .filter(|e| e.operation.0.starts_with("network."))
                .count(),
            3
        );
        assert!(starved_spans(&plan).is_empty(), "unexpected starvation");
    }
}

/// Reordering function definitions (not calls) never changes the analysis:
/// definitions cost no budget and calls run in call order.
#[test]
fn function_definition_reordering_is_domain_stable() {
    let a = "f() { curl http://host/x; }\ng() { rm /tmp/a; }\nf\ng\n";
    let b = "g() { rm /tmp/a; }\nf() { curl http://host/x; }\nf\ng\n";
    let plan_a = analyze(a, 1);
    let plan_b = analyze(b, 1);
    assert_eq!(domains(&plan_a), domains(&plan_b));
    // The starved second call is covered by an explicit boundary.
    assert!(starvation_covers(&plan_a, a, "rm /tmp/a"));
    assert!(starvation_covers(&plan_b, b, "rm /tmp/a"));
}

/// Moving an effectful call earlier or later in a sequential script may
/// change which commands fit the budget, but every command pushed out must
/// be covered by an explicit starvation boundary — never silently dropped.
#[test]
fn sequential_reordering_starves_explicitly() {
    let early = "curl http://host/x\nrm /tmp/a\ngit clone http://host/r /tmp/r\n";
    let late = "rm /tmp/a\ngit clone http://host/r /tmp/r\ncurl http://host/x\n";
    let plan_early = analyze(early, 2);
    let plan_late = analyze(late, 2);
    let commands = [
        ("network", "curl"),
        ("filesystem", "rm /tmp/a"),
        ("git", "git clone"),
    ];
    for (plan, source) in [(&plan_early, early), (&plan_late, late)] {
        for (domain, cmd) in commands {
            assert!(
                domains(plan).contains(domain) || starvation_covers(plan, source, cmd),
                "{cmd:?} neither analyzed nor covered by a starvation boundary"
            );
        }
    }
    // Sanity: the small limit really did cut different commands in the two
    // orderings, so the covering property above was exercised.
    assert_ne!(domains(&plan_early), domains(&plan_late));
}

/// Analyze under a whole-analysis step budget instead of an invocation cap.
fn analyze_with_steps(source: &str, max_analysis_steps: u64) -> Plan {
    let mut limits = default_limits();
    limits.insert("max_analysis_steps".to_string(), max_analysis_steps);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

fn step_saturated(plan: &Plan) -> bool {
    plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.limit.as_deref() == Some("max_analysis_steps")
    })
}

/// The step budget is a global pool, so a small one may cut a script short —
/// but reordering independent regions must then either leave the observed
/// domains unchanged or say plainly that the budget saturated, with every
/// domain partial. Silently different domains would let a reordering hide an
/// effect.
#[test]
fn step_budget_reordering_is_domain_stable_or_saturated() {
    let forward = "curl http://host/x\nrm /tmp/a\ngit clone http://host/r /tmp/r\n";
    let reversed = "git clone http://host/r /tmp/r\nrm /tmp/a\ncurl http://host/x\n";
    for steps in [8, 16, 32, 64, 128] {
        let plan_forward = analyze_with_steps(forward, steps);
        let plan_reversed = analyze_with_steps(reversed, steps);
        if domains(&plan_forward) == domains(&plan_reversed) {
            continue;
        }
        for plan in [&plan_forward, &plan_reversed] {
            assert!(
                step_saturated(plan),
                "reordering changed domains at {steps} steps without saturating"
            );
            assert!(
                plan.coverage
                    .0
                    .values()
                    .all(|level| level.level != effinterp_proto::CoverageLevel::Full),
                "saturated plan still reads complete in some domain"
            );
        }
    }
}

#[test]
fn invocation_deadline_before_work_and_nonexpiring_equivalence() {
    use effinterp_engine::InvocationDeadline;
    use std::time::Duration;
    let engine = Engine::new().with_causality_detail(true);
    for subject in [
        Subject::Shell {
            source: "rm /tmp/a; sh -c 'rm /tmp/b'".into(),
            cwd: None,
            context: Default::default(),
        },
        Subject::Source {
            language: "python".into(),
            dialect: None,
            source: "import os\nos.remove('/tmp/a')".into(),
            cwd: None,
            context: Default::default(),
        },
    ] {
        let unlimited = engine.analyze(&subject).unwrap();
        let deadline = InvocationDeadline::after(Duration::from_secs(60));
        let timed = engine
            .analyze_with_deadline(&subject, &deadline, None)
            .unwrap();
        assert_eq!(
            effinterp_proto::canonical_json(&timed),
            effinterp_proto::canonical_json(&unlimited)
        );
        deadline.expire();
        let cancelled = Engine::new().with_cancel_flag(std::sync::Arc::new(
            std::sync::atomic::AtomicBool::new(true),
        ));
        assert!(matches!(
            cancelled.analyze_with_deadline(&subject, &deadline, None),
            Err(effinterp_engine::EngineError::Cancelled)
        ));
        let partial = engine
            .analyze_with_deadline(&subject, &deadline, None)
            .unwrap();
        validate_plan(&partial).unwrap();
        assert!(partial.effects.is_empty());
        assert!(
            partial
                .boundaries
                .iter()
                .any(|b| b.limit.as_deref() == Some("invocation_deadline"))
        );
        assert!(
            partial
                .coverage
                .0
                .values()
                .all(|c| c.level != effinterp_proto::CoverageLevel::Full)
        );
    }
}

#[test]
fn deadline_evidence_survives_finalization_byte_limit() {
    let mut limits = default_limits();
    limits.insert("max_analysis_bytes".into(), 0);
    let subject = Subject::Shell {
        source: "rm /tmp/a".into(),
        cwd: None,
        context: Default::default(),
    };
    let deadline = effinterp_engine::InvocationDeadline::after(std::time::Duration::ZERO);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze_with_deadline(&subject, &deadline, None)
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("invocation_deadline"))
    );
}
