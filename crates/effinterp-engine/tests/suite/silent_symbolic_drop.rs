#![allow(clippy::disallowed_macros)]

use effinterp_engine::Engine;
use effinterp_engine::operand::{
    SYMBOLIC_OPERAND, operand_cites, shell_operand_slot, shell_operand_subject,
};
use effinterp_model_schema::FactAssertionFixture;
use effinterp_proto::{Effect, Plan, ResourceExpr, Subject};

const MUTATIONS_PER_SUBJECT: usize = 16;

fn analyze(subject: &Subject) -> Plan {
    let plan = Engine::new().analyze(subject).unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.limit.is_none())
    );
    plan
}

fn occurrence<'a>(plan: &'a Plan, operation: &str, span: (u32, u32)) -> Vec<&'a Effect> {
    plan.effects
        .iter()
        .filter(|effect| {
            effect.operation.as_str() == operation && operand_cites(plan, &effect.provenance, span)
        })
        .collect()
}

fn symbolic_target(resource: &ResourceExpr, domain: &str) -> bool {
    match resource {
        ResourceExpr::Environment { name } => name == SYMBOLIC_OPERAND,
        ResourceExpr::Unresolved { family } => {
            family.0 == domain || family.0 == "unknown" || family.0 == "value"
        }
        ResourceExpr::Join { parts } => parts.iter().any(|part| symbolic_target(part, domain)),
        ResourceExpr::Union { alternatives } => alternatives
            .iter()
            .any(|part| symbolic_target(part, domain)),
        _ => false,
    }
}

fn retained(plan: &Plan, original: &Effect, span: (u32, u32)) -> bool {
    let domain = original.operation.as_str().split('.').next().unwrap();
    occurrence(plan, original.operation.as_str(), span)
        .iter()
        .any(|effect| effect.realm == original.realm && symbolic_target(&effect.resource, domain))
        || plan.boundaries.iter().any(|boundary| {
            boundary.domains.iter().any(|d| d.0 == domain)
                && operand_cites(plan, &boundary.provenance, span)
        })
}

fn exercise(subject: &Subject, index: usize, operation: &str) -> Result<(), &'static str> {
    let mut baseline_subject = shell_operand_subject(subject);
    if let Subject::Shell { context, .. } = &mut baseline_subject {
        context
            .env
            .insert("ORACLE_CONTEXT".into(), "present".into());
    }
    let span = shell_operand_slot(&baseline_subject, index)?;
    let baseline = analyze(&baseline_subject);
    let originals = occurrence(&baseline, operation, span);
    assert!(
        !originals.is_empty(),
        "no baseline occurrence: {subject:?}, {index}, {operation}"
    );
    // The shell adapter must preserve the authored resource semantics before mutation.
    if matches!(subject, Subject::Exec { .. }) {
        let exec = analyze(subject);
        for effect in &originals {
            assert!(exec.effects.iter().any(|e| e.operation == effect.operation
                && e.resource == effect.resource
                && e.realm == effect.realm));
        }
    }
    let mut mutant = baseline_subject.clone();
    let Subject::Shell {
        source, context, ..
    } = &mut mutant
    else {
        unreachable!()
    };
    context.env.remove(SYMBOLIC_OPERAND);
    let expansion = format!("\"${SYMBOLIC_OPERAND}\"");
    source.replace_range(span.0 as usize..span.1 as usize, &expansion);
    let mutant_span = (span.0, span.0 + expansion.len() as u32);
    let plan = analyze(&mutant);
    for original in originals {
        assert!(
            retained(&plan, original, mutant_span),
            "silent drop: {mutant:?} {operation}: {:?}",
            plan.effects
        );
    }
    Ok(())
}

#[derive(Default)]
struct Coverage {
    exercised: usize,
    skipped: std::collections::BTreeMap<&'static str, usize>,
    exhausted: usize,
}

fn exercise_candidates(
    subject: &Subject,
    roles: &[(usize, &str)],
    coverage: &mut Coverage,
) -> usize {
    let mut candidates = roles.to_vec();
    candidates.sort_unstable();
    candidates.dedup();
    let mut exercised = 0;
    for (position, (index, operation)) in candidates.into_iter().enumerate() {
        if position >= MUTATIONS_PER_SUBJECT {
            coverage.exhausted += 1;
            continue;
        }
        match exercise(subject, index, operation) {
            Ok(()) => {
                exercised += 1;
                coverage.exercised += 1;
            }
            Err(reason) => *coverage.skipped.entry(reason).or_default() += 1,
        }
    }
    exercised
}

#[test]
fn fixture_operands_preserve_their_occurrence() {
    let fact_arrays = [
        (
            include_str!("../fixtures/model_equivalence/rm.json"),
            1,
            &[(2, "filesystem.delete")][..],
        ),
        (
            include_str!("../fixtures/model_equivalence/cp.json"),
            1,
            &[(2, "filesystem.read"), (3, "filesystem.read")][..],
        ),
    ];
    let mut coverage = Coverage::default();
    for (array, row, roles) in fact_arrays {
        let fixture: FactAssertionFixture = serde_json::from_str(array).unwrap();
        let subject = fixture.cases[row].subject.clone();
        assert!(exercise_candidates(&subject, roles, &mut coverage) > 0);
    }
    let fixture: FactAssertionFixture =
        serde_json::from_str(include_str!("../fixtures/model_tranche/strace.json")).unwrap();
    let subject = fixture.cases[0].subject.clone();
    assert!(exercise_candidates(&subject, &[(2, "filesystem.write")], &mut coverage) > 0);
    // These roles are absent from the promoted model arrays; serialize the same
    // subjects used by the focused shell/SQL regressions, without mutating programs.
    let subjects: Vec<Subject> = serde_json::from_str(
        r#"[
      {"kind":"shell","source":"curl -T /payload https://example.test"},
      {"kind":"shell","source":"psql -h production -d app -c 'DELETE FROM users'"},
      {"kind":"shell","source":"mysql -h production -D app -e 'DELETE FROM users'"},
      {"kind":"shell","source":"read FIRST SECOND"},
      {"kind":"shell","source":"rsync --recursive --delete /source /out/$DEST"}
    ]"#,
    )
    .unwrap();
    for (subject, index, operation) in [
        (&subjects[0], 2, "filesystem.read"),
        (&subjects[1], 2, "network.connect"),
        (&subjects[2], 2, "network.connect"),
        (&subjects[3], 1, "environment.write"),
        (&subjects[4], 4, "filesystem.delete"),
    ] {
        assert!(exercise_candidates(subject, &[(index, operation)], &mut coverage) > 0);
    }
    let unsupported = Subject::Shell {
        source: "rm x | cat".into(),
        cwd: None,
        context: Default::default(),
    };
    assert_eq!(
        exercise_candidates(&unsupported, &[(1, "filesystem.delete")], &mut coverage),
        0
    );
    assert_eq!(coverage.exercised, 9);
    assert_eq!(coverage.skipped.values().sum::<usize>(), 1);
    assert_eq!(coverage.exhausted, 0);
    eprintln!(
        "symbolic mutation coverage: exercised={}, skipped={:?}, exhausted={}; budget={MUTATIONS_PER_SUBJECT} per subject",
        coverage.exercised, coverage.skipped, coverage.exhausted
    );
}

#[test]
fn unrelated_occurrence_cannot_mask_a_seeded_drop() {
    let subject = Subject::Shell {
        source: "rm /first /second".into(),
        cwd: None,
        context: Default::default(),
    };
    let baseline = analyze(&subject);
    let span = shell_operand_slot(&subject, 1).unwrap();
    let original = occurrence(&baseline, "filesystem.delete", span)[0];
    let mutant = Subject::Shell {
        source: format!("rm \"${SYMBOLIC_OPERAND}\" /second"),
        cwd: None,
        context: Default::default(),
    };
    let mut plan = analyze(&mutant);
    let span = (3, 3 + SYMBOLIC_OPERAND.len() as u32 + 3);
    assert!(retained(&plan, original, span));
    let suppressed = occurrence(&plan, "filesystem.delete", span)
        .iter()
        .map(|e| e.id.clone())
        .collect::<Vec<_>>();
    plan.effects.retain(|e| !suppressed.contains(&e.id));
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete")
    );
    assert!(!retained(&plan, original, span));

    let literal = analyze(&Subject::Exec {
        argv: vec!["rm".into(), format!("${SYMBOLIC_OPERAND}")],
        cwd: Some("/work".into()),
        context: Default::default(),
    });
    assert!(
        literal
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"
                && matches!(e.resource, ResourceExpr::Concrete { .. }))
    );
}

#[test]
fn mutation_budget_reports_unexercised_candidates() {
    let subject = Subject::Exec {
        argv: std::iter::once("rm".into())
            .chain((0..=MUTATIONS_PER_SUBJECT).map(|index| format!("/file{index}")))
            .collect(),
        cwd: None,
        context: Default::default(),
    };
    let roles: Vec<_> = (1..=MUTATIONS_PER_SUBJECT + 1)
        .map(|index| (index, "filesystem.delete"))
        .collect();
    let mut coverage = Coverage::default();
    assert_eq!(
        exercise_candidates(&subject, &roles, &mut coverage),
        MUTATIONS_PER_SUBJECT
    );
    assert_eq!(coverage.exhausted, 1);
    assert!(coverage.skipped.is_empty());
}
