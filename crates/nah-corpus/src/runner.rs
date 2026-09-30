//! Reconciles corpus expectations through the real decision seam; it does not reimplement policy.

use std::collections::{BTreeMap, BTreeSet};

use nah_cli::{DecisionResult, decide_replay, decide_replay_code};
use nah_proto::action::Coverage;
use nah_proto::ctx::{AbsolutePath, Platform, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::effects::{Certainty, GapCategory, GuardEvidence, RelationKind};
use nah_proto::tool::ToolCallInput;

use crate::fixtures::FixtureRegistry;
use nah_corpus_schema::{CaseInput, CorpusCase, Expectation, ExpectedCoverage, ExpectedVerdict};

/// Corpus rows sorted by how their engine decision met the expectation and the
/// `corpus/TRIAGE.md` Expected-fail list.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Reconciliation {
    pub executed_green: Vec<String>,
    pub expected_failures: Vec<String>,
    pub unexpected_failures: Vec<String>,
    pub unexpected_passes: Vec<String>,
    pub ledger_errors: Vec<String>,
    /// Rows whose replay exhausted the analysis budget. A timed-out analysis is
    /// never a corpus decision, expected failure or not.
    pub analysis_limits: Vec<String>,
    /// Every guard some row's engine decision attributed, whatever the row
    /// expected.
    pub exercised_guards: BTreeSet<String>,
    /// Per decided row id, the guards its engine decision attributed.
    pub firing_guards: BTreeMap<String, BTreeSet<String>>,
}

/// Decides every case through the production engine path and reconciles it
/// against the Expected-fail section of `ledger`, the text of `corpus/TRIAGE.md`.
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
        let outcome = match decide_case(case, fixtures) {
            Ok(decision) => {
                let firing = decision
                    .core()
                    .policy_attributions()
                    .iter()
                    .map(|guard| guard.name().to_owned())
                    .collect::<BTreeSet<_>>();
                result.exercised_guards.extend(firing.iter().cloned());
                result.firing_guards.insert(case.id.clone(), firing);
                expectation_matches(&case.expected, &decision)
            }
            Err(DecisionFailure::AnalysisLimit(code)) => {
                result.analysis_limits.push(format!(
                    "{}: replay hit the analysis budget ({code})",
                    case.id
                ));
                continue;
            }
            Err(DecisionFailure::Other(error)) => Err(error),
        };
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

pub(crate) enum DecisionFailure {
    AnalysisLimit(String),
    Other(String),
}

impl From<String> for DecisionFailure {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

/// Decide one row through the production engine path on the deterministic
/// replay seam: the fixture answers source, path and host observations, so the
/// replaying host's disk never reaches the decision, and the fixture budget
/// replaces the interactive production deadline.
pub(crate) fn decide_case(
    case: &CorpusCase,
    fixtures: &FixtureRegistry,
) -> Result<DecisionResult, DecisionFailure> {
    let ctx_fixture = fixtures
        .ctx_fixtures
        .get(&case.ctx_fixture)
        .ok_or_else(|| format!("unknown context fixture `{}`", case.ctx_fixture))?;
    let observation_fixture = fixtures
        .observation_fixtures
        .get(&case.observation_fixture)
        .ok_or_else(|| format!("unknown observation fixture `{}`", case.observation_fixture))?;
    if observation_fixture.platform() != ctx_fixture.platform() {
        return Err("context and observation fixture platforms differ"
            .to_owned()
            .into());
    }
    let ctx = ctx_fixture.context()?;
    let sources = observation_fixture.sources()?;
    let observe = |request: &_| observation_fixture.observation(request);
    // Code rows take the code hook's route; command and tool rows arrive as
    // one tool call.
    let result = match &case.input {
        CaseInput::Code { language, source } => {
            AbsolutePath::new(ctx.platform(), &observation_fixture.cwd)
                .map_err(|error| error.to_string())?;
            decide_replay_code(
                language.as_str(),
                source,
                &observation_fixture.cwd,
                &ctx,
                ctx_fixture.enforcement(),
                &sources,
                observation_fixture.observations(),
                observe,
            )?
        }
        CaseInput::Command(_) | CaseInput::Tool { .. } => decide_replay(
            &tool_input(case, ctx.platform(), &observation_fixture.cwd)?,
            &ctx,
            ctx_fixture.enforcement(),
            &sources,
            observation_fixture.observations(),
            observe,
        ),
    };
    if let Some(code) = analysis_limit(&result) {
        return Err(DecisionFailure::AnalysisLimit(code.to_owned()));
    }
    require_healthy(result)
}

/// The gap code when the engine ran out of budget instead of finishing.
pub(crate) fn analysis_limit(result: &DecisionResult) -> Option<&str> {
    result
        .guard_evidence()
        .and_then(Result::ok)
        .and_then(|evidence| {
            evidence
                .graph()
                .gaps
                .iter()
                .find(|gap| gap.category == GapCategory::Limit)
        })
        .map(|gap| gap.code.as_str())
}

fn require_healthy(result: DecisionResult) -> Result<DecisionResult, DecisionFailure> {
    if let Some(failure) = result.failures().first() {
        Err(format!(
            "evaluation failed: {}/{}/{}",
            failure.source(),
            failure.component(),
            failure.code()
        )
        .into())
    } else {
        Ok(result)
    }
}

pub(crate) fn tool_input(
    case: &CorpusCase,
    platform: Platform,
    cwd: &str,
) -> Result<ToolCallInput, String> {
    let (tool, input) = match &case.input {
        CaseInput::Command(command) => ("Bash", serde_json::json!({"command": command})),
        CaseInput::Tool { tool, input } => (tool.as_str(), input.clone()),
        CaseInput::Code { .. } => return Err("code rows replay through the code route".into()),
    };
    AbsolutePath::new(platform, cwd).map_err(|error| error.to_string())?;
    ToolCallInput::new(SchemaVersion::V1, tool, input, cwd, None).map_err(|error| error.to_string())
}

/// Hold an engine decision to the row's expectation. Structural expectations
/// are checked against typed guard evidence: a `NoFlows` row must show no exact
/// public transfer between payload groups, and a guardless block must be the
/// reducer's structural verdict rather than an attributed one.
pub(crate) fn expectation_matches(
    expected: &Expectation,
    result: &DecisionResult,
) -> Result<(), String> {
    match expected {
        Expectation::NoFlows => match result.guard_evidence() {
            Some(Ok(evidence)) if no_intergroup_public_transfer(evidence) => Ok(()),
            Some(Ok(_)) => Err("expected no public flows between payload groups".into()),
            Some(Err(error)) => Err(format!("guard evidence invalid: {error:?}")),
            None => Err("decided without guard evidence".into()),
        },
        Expectation::Decision {
            verdict,
            guard,
            coverage,
            guards,
        } => {
            let actual_verdict = result.core().verdict();
            let expected_verdict = match verdict {
                ExpectedVerdict::Block => Verdict::Block,
                ExpectedVerdict::Delegate => Verdict::Delegate,
            };
            if actual_verdict != expected_verdict {
                return Err(format!(
                    "expected {expected_verdict:?}, got {actual_verdict:?} ({}); guards={:?}; warnings={:?}; gaps={:?}",
                    result.core().reason(),
                    result
                        .core()
                        .policy_attributions()
                        .iter()
                        .map(nah_proto::decision::GuardAttribution::name)
                        .collect::<Vec<_>>(),
                    result.warnings(),
                    gap_codes(result),
                ));
            }
            if let Some(coverage) = coverage {
                let expected_coverage = match coverage {
                    ExpectedCoverage::Full => Coverage::Full,
                    ExpectedCoverage::Partial => Coverage::Partial,
                };
                if result.core().coverage() != expected_coverage
                    && !matches!(
                        (expected_coverage, result.core().coverage()),
                        (Coverage::Partial, Coverage::Full)
                    )
                {
                    return Err(format!(
                        "expected {expected_coverage:?} coverage, got {:?}; gaps={:?}",
                        result.core().coverage(),
                        gap_codes(result),
                    ));
                }
            }
            let firing = result
                .core()
                .policy_attributions()
                .iter()
                .map(nah_proto::decision::GuardAttribution::name)
                .collect::<BTreeSet<_>>();
            if let Some(guards) = guards
                && firing != guards.iter().map(String::as_str).collect()
            {
                return Err(format!(
                    "expected exactly firing guards {guards:?}, got {firing:?}"
                ));
            }
            if let Some(guard) = guard
                && !firing.contains(guard.as_str())
            {
                return Err(format!("expected firing guard `{guard}`, got {firing:?}"));
            }
            if *verdict == ExpectedVerdict::Block
                && guard.is_none()
                && !result.core().policy_attributions().is_empty()
            {
                return Err("expected structural block".into());
            }
            Ok(())
        }
    }
}

fn gap_codes(result: &DecisionResult) -> Vec<String> {
    result
        .guard_evidence()
        .and_then(Result::ok)
        .map(|evidence| {
            evidence
                .graph()
                .gaps
                .iter()
                .map(|gap| format!("{:?}/{}", gap.category, gap.code))
                .collect()
        })
        .unwrap_or_default()
}

/// No exact value or byte transfer connects two public occurrences of
/// different payload groups.
pub(crate) fn no_intergroup_public_transfer(evidence: &GuardEvidence) -> bool {
    let graph = evidence.graph();
    let public = evidence.public_selection();
    graph.relations.iter().all(|relation| {
        if relation.certainty != Certainty::Exact {
            return true;
        }
        if !matches!(
            relation.kind,
            RelationKind::ValueDependence
                | RelationKind::ByteTransfer
                | RelationKind::ContentPreservingTransfer
        ) {
            return true;
        }
        let Some(from) = graph
            .occurrences
            .iter()
            .find(|occurrence| occurrence.id == relation.from)
        else {
            return true;
        };
        let Some(to) = graph
            .occurrences
            .iter()
            .find(|occurrence| occurrence.id == relation.to)
        else {
            return true;
        };
        if !public.occurrences.contains(&from.id) || !public.occurrences.contains(&to.id) {
            return true;
        }
        let Some(from_call) = graph.calls.iter().find(|call| call.id == from.call) else {
            return true;
        };
        let Some(to_call) = graph.calls.iter().find(|call| call.id == to.call) else {
            return true;
        };
        match (&from_call.payload_group, &to_call.payload_group) {
            (
                nah_proto::effects::Knowledge::Known(from),
                nah_proto::effects::Knowledge::Known(to),
            ) => from == to,
            _ => false,
        }
    })
}

/// Case ids listed under `## Expected-fail` in `ledger`, the text of
/// `corpus/TRIAGE.md`, with a ledger error for each duplicate id.
pub fn expected_fail_ids(ledger: &str) -> (BTreeSet<&str>, Vec<String>) {
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
        let ledger = "## Expected-fail\n\n- `exec.x` — reason\n- `exec.x`\n";
        let (ids, errors) = expected_fail_ids(ledger);
        assert_eq!(ids.into_iter().collect::<Vec<_>>(), ["exec.x"]);
        assert_eq!(errors, ["duplicate expected-fail `exec.x`"]);
    }

    /// A PATH search reaches the basename model only when the host certifies
    /// the candidate executable, which no corpus fixture declares. Certifying
    /// the two `rm` files here shows that a PATH entry climbing out of a
    /// possible symlink (`link/..`) does not lend `/usr/local/bin` trust,
    /// while a system bin directory reached the same way keeps its guards.
    #[test]
    fn path_selected_executable_trust_reads_the_path_spelling() {
        use nah_proto::effinterp_proto::{
            Fact, ObservationOutcome, PathFact, PathKind, PathTarget,
        };

        struct Certified(std::sync::Arc<dyn nah_cli::ObservationResolver>);
        impl nah_cli::ObservationResolver for Certified {
            fn observe(
                &self,
                query: &nah_proto::effinterp_proto::ObservationQuery,
                budget: nah_cli::ObservationBudget,
            ) -> ObservationOutcome {
                if let nah_proto::effinterp_proto::ObservationQuery::Path { path } = query
                    && (path == "/usr/local/bin/rm" || path == "/usr/bin/rm")
                {
                    return ObservationOutcome::Path(PathFact {
                        entry: path.clone(),
                        kind: PathKind::File,
                        followed: Fact::Known(PathTarget {
                            path: path.clone(),
                            kind: Fact::Known(PathKind::File),
                        }),
                        executable: Some(true),
                    });
                }
                self.0.observe(query, budget)
            }
        }

        let fixtures = crate::load_fixtures(&crate::corpus_dir().join("FIXTURES.json")).unwrap();
        let ctx_fixture = &fixtures.ctx_fixtures["default-linux-v1"];
        let observation_fixture = &fixtures.observation_fixtures["filesystem-linux-v1"];
        let ctx = ctx_fixture.context().unwrap();
        let sources = observation_fixture.sources().unwrap();
        for (command, verdict) in [
            ("PATH=/usr/local/bin rm -rf /", Verdict::Block),
            ("PATH=/usr/bin/../bin rm -rf /", Verdict::Block),
            ("PATH=/usr/local/bin/link/.. rm -rf /", Verdict::Delegate),
            (
                "env PATH=/usr/local/bin/link/.. rm -rf /",
                Verdict::Delegate,
            ),
        ] {
            let input = ToolCallInput::new(
                SchemaVersion::V1,
                "Bash",
                serde_json::json!({ "command": command }),
                &observation_fixture.cwd,
                None,
            )
            .unwrap();
            let result = decide_replay(
                &input,
                &ctx,
                ctx_fixture.enforcement(),
                &sources,
                std::sync::Arc::new(Certified(observation_fixture.observations())),
                |request| observation_fixture.observation(request),
            );
            assert_eq!(result.core().verdict(), verdict, "{command}");
        }
    }

    #[test]
    fn malformed_input_is_an_ordinary_delegate() {
        let home = AbsolutePath::new(Platform::Linux, "/repo").unwrap();
        let ctx = nah_proto::ctx::Ctx::new(
            Platform::Linux,
            home,
            vec![],
            vec![],
            nah_proto::ctx::TrustProjection::new(vec![]).unwrap(),
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
        let result = nah_cli::decide_with(&input, &ctx, |_| {
            unreachable!("malformed Bash input stops before observation")
        });

        let Ok(result) = require_healthy(result) else {
            panic!("malformed input is not an evaluation failure");
        };
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert!(result.failures().is_empty());
    }
}
