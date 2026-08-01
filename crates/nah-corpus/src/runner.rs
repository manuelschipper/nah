//! Reconciles corpus expectations through the real decision seam; it does not reimplement policy.

use std::collections::BTreeSet;

use nah_cli::{DecisionResult, decide_with};
use nah_proto::action::Coverage;
use nah_proto::ctx::{AbsolutePath, Platform, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;

use crate::case::{CaseInput, CorpusCase, Expectation, ExpectedCoverage, ExpectedVerdict};
use crate::fixtures::FixtureRegistry;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Reconciliation {
    pub executed_green: Vec<String>,
    pub expected_failures: Vec<String>,
    pub unexpected_failures: Vec<String>,
    pub unexpected_passes: Vec<String>,
    pub ledger_errors: Vec<String>,
}

pub fn reconcile(cases: &[CorpusCase], fixtures: &FixtureRegistry, ledger: &str) -> Reconciliation {
    let (expected_fail, mut ledger_errors) = expected_fail_ids(ledger);
    let case_ids = cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    for id in expected_fail.difference(&case_ids) {
        ledger_errors.push(format!("stale expected-fail `{id}`"));
    }

    let mut result = Reconciliation {
        ledger_errors,
        ..Reconciliation::default()
    };
    for case in cases {
        let outcome = execute(case, fixtures);
        match (expected_fail.contains(case.id.as_str()), outcome) {
            (false, Ok(())) => result.executed_green.push(case.id.clone()),
            (true, Err(_)) => result.expected_failures.push(case.id.clone()),
            (false, Err(error)) => result
                .unexpected_failures
                .push(format!("{}: {error}", case.id)),
            (true, Ok(())) => result.unexpected_passes.push(case.id.clone()),
        }
    }
    result
}

fn execute(case: &CorpusCase, fixtures: &FixtureRegistry) -> Result<(), String> {
    let result = decide_case(case, fixtures)?;
    expectation_matches(&case.expected, &result)
}

pub(crate) fn decide_case(
    case: &CorpusCase,
    fixtures: &FixtureRegistry,
) -> Result<DecisionResult, String> {
    let ctx_fixture = fixtures
        .ctx_fixtures
        .get(&case.ctx_fixture)
        .ok_or_else(|| format!("unknown context fixture `{}`", case.ctx_fixture))?;
    let observation_fixture = fixtures
        .observation_fixtures
        .get(&case.observation_fixture)
        .ok_or_else(|| format!("unknown observation fixture `{}`", case.observation_fixture))?;
    let ctx = ctx_fixture.context()?;
    let input = tool_input(case, ctx.platform(), &observation_fixture.cwd)?;
    let result = decide_with(&input, &ctx, |request| {
        observation_fixture.observation(request)
    });
    require_healthy(result)
}

fn require_healthy(result: DecisionResult) -> Result<DecisionResult, String> {
    if let Some(failure) = result.failures().first() {
        Err(format!(
            "evaluation failed: {}/{}/{}",
            failure.source(),
            failure.component(),
            failure.code()
        ))
    } else {
        Ok(result)
    }
}

fn tool_input(case: &CorpusCase, platform: Platform, cwd: &str) -> Result<ToolCallInput, String> {
    let (tool, input) = match &case.input {
        CaseInput::Command(command) => ("Bash", serde_json::json!({"command": command})),
        CaseInput::Tool { tool, input } => (tool.as_str(), input.clone()),
    };
    AbsolutePath::new(platform, cwd).map_err(|error| error.to_string())?;
    ToolCallInput::new(SchemaVersion::V1, tool, input, cwd, None).map_err(|error| error.to_string())
}

fn expectation_matches(expected: &Expectation, result: &DecisionResult) -> Result<(), String> {
    match expected {
        Expectation::NoFlows => {
            if result.action_stream().flows().is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "expected no flows, got {:?}",
                    result.action_stream().flows()
                ))
            }
        }
        Expectation::Decision {
            verdict,
            guard,
            coverage,
        } => {
            let actual_verdict = result.core().verdict();
            let expected_verdict = match verdict {
                ExpectedVerdict::Block => Verdict::Block,
                ExpectedVerdict::Delegate => Verdict::Delegate,
            };
            if actual_verdict != expected_verdict {
                return Err(format!(
                    "expected {expected_verdict:?}, got {actual_verdict:?} ({}); warnings={:?}; action={}",
                    result.core().reason(),
                    result.warnings(),
                    result
                        .action_stream()
                        .canonical_json()
                        .unwrap_or_else(|error| format!("<invalid: {error}>"))
                ));
            }
            if let Some(coverage) = coverage {
                let expected_coverage = match coverage {
                    ExpectedCoverage::Full => Coverage::Full,
                    ExpectedCoverage::Partial => Coverage::Partial,
                };
                if result.core().coverage() != expected_coverage {
                    return Err(format!(
                        "expected {expected_coverage:?} coverage, got {:?}",
                        result.core().coverage()
                    ));
                }
            }
            if let Some(guard) = guard
                && !result
                    .core()
                    .policy_attributions()
                    .iter()
                    .any(|attribution| attribution.name() == guard)
            {
                return Err(format!("expected firing guard `{guard}`"));
            }
            if *verdict == ExpectedVerdict::Block
                && guard.is_none()
                && (!result.core().policy_attributions().is_empty()
                    || !matches!(
                        result.core().reason(),
                        "nah self-protection blocked a change to nah or its runtime wiring; do not retry through another tool; if intended, ask the operator to run `nah nap` in a separate terminal"
                            | "nah nap must be started by the operator in a separate terminal"
                    ))
            {
                return Err("expected structural block".into());
            }
            Ok(())
        }
    }
}

fn expected_fail_ids(ledger: &str) -> (BTreeSet<&str>, Vec<String>) {
    let mut in_expected_fail = false;
    let mut ids = BTreeSet::new();
    let mut errors = Vec::new();
    for line in ledger.lines() {
        if line == "## Expected-fail" {
            in_expected_fail = true;
            continue;
        }
        if in_expected_fail && line.starts_with("## ") {
            in_expected_fail = false;
        }
        let Some(id) = in_expected_fail
            .then_some(line)
            .and_then(|line| line.strip_prefix("- `"))
            .and_then(|line| line.split_once('`'))
            .map(|(id, _)| id)
            .filter(|id| id.starts_with("nah0."))
        else {
            continue;
        };
        if !ids.insert(id) {
            errors.push(format!("duplicate expected-fail `{id}`"));
        }
    }
    (ids, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_ledger_ids_are_reported() {
        let ledger = "## Expected-fail\n\n- `nah0.x`\n- `nah0.x`\n";
        let (_, errors) = expected_fail_ids(ledger);
        assert_eq!(errors, ["duplicate expected-fail `nah0.x`"]);
    }

    #[test]
    fn malformed_input_is_an_ordinary_delegate() {
        let home = AbsolutePath::new(Platform::Linux, "/repo").unwrap();
        let ctx = nah_proto::ctx::Ctx::new(
            SchemaVersion::V1,
            Platform::Linux,
            home,
            vec![],
            vec![],
            nah_proto::ctx::TrustProjection::new(vec![]).unwrap(),
            nah_proto::ctx::PolicyVersion::V1,
        )
        .unwrap();
        let input = ToolCallInput::new(
            SchemaVersion::V1,
            "Bash",
            serde_json::json!({}),
            "/repo",
            None,
        )
        .unwrap();
        let result = decide_with(&input, &ctx, |_| {
            unreachable!("malformed Bash input stops before observation")
        });

        let result = require_healthy(result).unwrap();
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert!(result.failures().is_empty());
    }
}
