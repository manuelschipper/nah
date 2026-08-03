#![allow(clippy::disallowed_types)]

mod support;

use nah_inline::{Finding, FindingKind, InlineReport};
use nah_policy::EnforcementMode;
use nah_proto::action::{Coverage, Sensitivity};
use nah_proto::decision::Verdict;
use nah_proto::observation::ProjectGuardDeclaration;
use support::{context, project_scope, read_stream};

#[test]
fn exact_inline_findings_use_existing_guard_enablement() {
    let stream = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
    let mut report = InlineReport::default();
    report.push(Finding::exact(FindingKind::RootDestruction));

    for enabled in [true, false] {
        let (_, policy) = context(
            &[("fs-root", enabled)],
            vec![],
            ProjectGuardDeclaration::Absent,
        );
        let decision = nah_policy::decide_with_mode_and_inline(
            &stream,
            &report,
            &policy,
            &[],
            EnforcementMode::Normal,
        )
        .unwrap();
        assert_eq!(
            decision.verdict(),
            if enabled {
                Verdict::Block
            } else {
                Verdict::Delegate
            }
        );
    }
}

#[test]
fn multiple_inline_findings_keep_all_guard_attributions() {
    let stream = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
    let mut report = InlineReport::default();
    report.push(Finding::exact(FindingKind::RootDestruction));
    report.push(Finding::exact(FindingKind::DecodedExecution));
    let (_, policy) = context(
        &[("fs-root", true), ("exec-decoded", true)],
        vec![],
        ProjectGuardDeclaration::Absent,
    );

    let decision = nah_policy::decide_with_mode_and_inline(
        &stream,
        &report,
        &policy,
        &[],
        EnforcementMode::Normal,
    )
    .unwrap();

    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(
        decision
            .policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        ["exec-decoded", "fs-root"]
    );
}

#[test]
fn conservative_findings_never_reach_configurable_guards() {
    let stream = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
    let mut report = InlineReport::default();
    report.push(Finding::conservative(FindingKind::RootDestruction));
    let (_, policy) = context(
        &[("fs-root", true)],
        vec![],
        ProjectGuardDeclaration::Absent,
    );

    let decision = nah_policy::decide_with_mode_and_inline(
        &stream,
        &report,
        &policy,
        &[],
        EnforcementMode::Normal,
    )
    .unwrap();

    assert_eq!(decision.verdict(), Verdict::Delegate);
}

#[test]
fn conservative_nah_findings_are_structural_and_follow_nap_mode() {
    let stream = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
    let mut report = InlineReport::default();
    report.push(Finding::conservative(FindingKind::NahTampering));
    let (_, policy) = context(&[], vec![], ProjectGuardDeclaration::Absent);

    for (mode, expected) in [
        (EnforcementMode::Normal, Verdict::Block),
        (EnforcementMode::SelfProtectionPaused, Verdict::Delegate),
        (EnforcementMode::AllPaused, Verdict::Delegate),
    ] {
        let decision =
            nah_policy::decide_with_mode_and_inline(&stream, &report, &policy, &[], mode).unwrap();
        assert_eq!(decision.verdict(), expected, "{mode:?}");
    }
}
