use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use effinterp_engine::{Engine, ObservationResolver, SourceResolver};
use effinterp_proto::validate_plan;
use serde::{Deserialize, Serialize};

use crate::nah::classify::{ParityClass, classify_golden, classify_plan};
use crate::nah::corpus::{CaseLoad, FixtureObservations, FixtureResolver};
use crate::nah::flow::FlowMetric;
use crate::nah::goldens;
use crate::nah::guard_queries::{GuardQueryOutcome, load_guard_queries};
use crate::nah::normalize::normalize_plan;
use nah_corpus_schema::{CaseInput, Expectation};

#[derive(Debug)]
pub struct HarnessReport {
    pub unmodeled_commands: crate::unmodeled::UnmodeledCommands,
    pub corpus_digest: String,
    pub nah_commit: String,
    pub cases: Vec<CaseResult>,
    /// Causality-graph facts over the analyzed plans. Separate from each case's
    /// effect-domain `coverage`.
    pub flow: FlowMetric,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseResult {
    pub file: String,
    pub id: String,
    pub class: ParityClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_guard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_coverage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// True when an effect-level golden governed this case's class.
    #[serde(default, skip_serializing_if = "is_false")]
    pub golden: bool,
    /// Required effects or flows that the plan did not contain. Present on
    /// silent misses and on golden-backed, boundary-reported gaps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub coverage: BTreeMap<String, String>,
    /// Source paths the case's observation fixture does not declare. nah
    /// refuses such a row outright; here the path stays unobserved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undeclared: Vec<String>,
    pub mutation: crate::nah::mutate::MutationMeasurement,
    pub gaps: BTreeMap<String, Vec<effinterp_proto::BoundaryRef>>,
    /// How the expected guard's exported query answers this block row's plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_query: Option<GuardQueryOutcome>,
}

impl CaseResult {
    /// The golden passes, yet the guard it backs cannot fire on this plan.
    pub fn guard_silent(&self) -> bool {
        self.class == ParityClass::EffectMatch
            && self.guard_query == Some(GuardQueryOutcome::NoMatch)
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Run loaded cases through the engine and produce a deterministic report:
/// cases are sorted by (file, id), and nothing time- or host-dependent is
/// recorded.
pub fn run_corpus(
    engine: &Engine,
    cases: Vec<CaseLoad>,
    corpus_digest: String,
    nah_commit: String,
) -> HarnessReport {
    let goldens = goldens::load_goldens();
    let guard_queries = load_guard_queries();

    let mut flow = FlowMetric::default();
    let mut unmodeled_commands = crate::unmodeled::UnmodeledCommands::default();
    let mut results: Vec<CaseResult> = Vec::new();
    for load in cases {
        let result = match load {
            CaseLoad::Malformed { file, line, error } => CaseResult {
                file,
                id: format!("<line {line}>"),
                class: ParityClass::BaselineDefect,
                command: None,
                tool: None,
                cwd: None,
                expected_verdict: None,
                expected_guard: None,
                expected_coverage: None,
                error: Some(error),
                golden: false,
                missing: Vec::new(),
                effects: Vec::new(),
                boundaries: Vec::new(),
                coverage: BTreeMap::new(),
                undeclared: Vec::new(),
                gaps: BTreeMap::new(),
                guard_query: None,
                mutation: crate::nah::mutate::MutationMeasurement {
                    not_exercised: 1,
                    reasons: BTreeMap::from([("malformed_baseline".into(), 1)]),
                    ..Default::default()
                },
            },
            CaseLoad::Ok(case) => {
                let (expected_verdict, expected_guard, expected_coverage) = match &case.expected {
                    Expectation::Decision {
                        verdict,
                        guard,
                        coverage,
                        ..
                    } => (
                        Some(verdict.as_str().to_string()),
                        guard.clone(),
                        coverage.map(|coverage| coverage.as_str().to_string()),
                    ),
                    Expectation::NoFlows => (None, None, None),
                };
                let mut result = CaseResult {
                    file: case.file.clone(),
                    id: case.id.clone(),
                    class: ParityClass::Unsupported,
                    command: None,
                    tool: None,
                    cwd: case.cwd.clone(),
                    expected_verdict,
                    expected_guard,
                    expected_coverage,
                    error: None,
                    golden: false,
                    missing: Vec::new(),
                    effects: Vec::new(),
                    boundaries: Vec::new(),
                    coverage: BTreeMap::new(),
                    undeclared: Vec::new(),
                    gaps: BTreeMap::new(),
                    mutation: Default::default(),
                    guard_query: None,
                };
                match &case.input {
                    CaseInput::Tool { tool, .. } => {
                        result.tool = Some(tool.clone());
                    }
                    CaseInput::Command(command) => {
                        result.command = Some(command.clone());
                    }
                    CaseInput::Code { .. } => {}
                }
                let subject = case.analysis_subject();
                let resolver = case.observation.as_deref().map(FixtureResolver::new);
                // Both channels read the same fixture, so a case sees one world.
                let observations = case
                    .observation
                    .clone()
                    .map(|fixture| Arc::new(FixtureObservations::new(fixture)));
                let analyzed = engine.analyze_with_observations(
                    &subject,
                    None,
                    resolver
                        .as_ref()
                        .map(|resolver| resolver as &dyn SourceResolver),
                    observations
                        .clone()
                        .map(|observations| observations as Arc<dyn ObservationResolver>),
                );
                let mut undeclared = BTreeSet::new();
                if let Some(resolver) = &resolver {
                    undeclared.extend(resolver.undeclared());
                }
                if let Some(observations) = &observations {
                    undeclared.extend(observations.undeclared());
                }
                result.undeclared = undeclared.into_iter().collect();
                match analyzed {
                    Err(e) => {
                        result.class = ParityClass::EngineError;
                        result.error = Some(e.to_string());
                        result.mutation.skip("analysis_failed");
                    }
                    Ok(plan) => {
                        if let Err(errors) = validate_plan(&plan) {
                            result.class = ParityClass::EngineError;
                            result.mutation.skip("invalid_baseline");
                            result.error = Some(format!(
                                "engine produced an invalid plan: {}",
                                errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ")
                            ));
                        } else {
                            flow.observe(&plan);
                            unmodeled_commands.observe(&plan, "nah", &case.id);
                            let normalized = normalize_plan(&plan);
                            // An effect-level golden, when present,
                            // overrides the verdict-level heuristic.
                            if let Some(golden) = goldens.get(&case.id) {
                                let (class, missing) = classify_golden(&plan, golden);
                                result.class = class;
                                result.golden = true;
                                result.missing = missing;
                            } else {
                                result.class =
                                    classify_plan(&normalized, result.expected_verdict.as_deref());
                            }
                            result.mutation = crate::nah::mutate::measure_symbolic_mutations(
                                engine,
                                &plan,
                                goldens.get(&case.id).map_or(&[], |g| g.require.as_slice()),
                                resolver.as_ref().map(|r| r as &dyn SourceResolver),
                                observations.clone().map(|observations| {
                                    observations as Arc<dyn ObservationResolver>
                                }),
                            );
                            if !result.mutation.findings.is_empty() {
                                result.class = ParityClass::SilentSymbolicDrop;
                            }
                            if result.expected_verdict.as_deref() == Some("block") {
                                result.guard_query = result
                                    .expected_guard
                                    .as_deref()
                                    .and_then(|guard| guard_queries.evaluate(guard, &plan));
                            }
                            result.effects = normalized.effects;
                            result.boundaries = normalized.boundaries;
                            result.coverage = normalized.coverage;
                            result.gaps = normalized.gaps;
                        }
                    }
                }
                result
            }
        };
        results.push(result);
    }

    results.sort_by(|a, b| (&a.file, &a.id).cmp(&(&b.file, &b.id)));
    HarnessReport {
        unmodeled_commands,
        corpus_digest,
        nah_commit,
        cases: results,
        flow,
    }
}

/// The nah parity section of the bench scoreboard: source identity and
/// per-class counts overall, per corpus file, and per expected-block guard.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parity {
    pub nah_commit: String,
    pub corpus_digest: String,
    pub classes: BTreeMap<ParityClass, usize>,
    pub per_file: BTreeMap<String, BTreeMap<ParityClass, usize>>,
    pub per_guard: BTreeMap<String, BTreeMap<ParityClass, usize>>,
    /// Source paths the observation fixtures do not declare, each with the
    /// number of cases that asked for it. nah refuses such a row as
    /// `InvalidObservation`; here it stays unobserved and keeps a boundary,
    /// so this names exactly what a corpus owner would have to declare.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub undeclared_paths: BTreeMap<String, usize>,
    /// How each expected-block guard's exported query answers its rows' plans.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub guard_queries: BTreeMap<String, BTreeMap<GuardQueryOutcome, usize>>,
    /// Per guard, the block rows whose golden passes while the guard's query
    /// cannot fire.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub guard_silent: BTreeMap<String, Vec<String>>,
}

const CEILING_CLASSES: [ParityClass; 6] = [
    ParityClass::MissingEffect,
    ParityClass::MissingFlow,
    ParityClass::Regression,
    ParityClass::EngineError,
    ParityClass::BaselineDefect,
    ParityClass::Unsupported,
];
// per_guard contains only block cases; corpus_goldens checks that each has a reviewed golden.
const GUARD_CEILING_CLASSES: [ParityClass; 3] = [
    ParityClass::MissingEffect,
    ParityClass::MissingFlow,
    ParityClass::ExplainedPartial,
];

/// The ceiling key for block rows whose golden passes while their guard's
/// query cannot fire. Rule (l) gates it, naming the rows; rule (g) does not.
pub const GUARD_SILENT: &str = "guard_silent";

/// Maximum failures by metric and group; absent keys have zero allowance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceilings {
    pub total: BTreeMap<String, usize>,
    pub per_guard: BTreeMap<String, BTreeMap<String, usize>>,
}

/// Select only gated metrics, preserving the nah gate's class policy.
pub trait CeilingCounts {
    fn ceiling_counts(&self) -> Ceilings;
}

impl CeilingCounts for Ceilings {
    fn ceiling_counts(&self) -> Ceilings {
        self.clone()
    }
}

impl CeilingCounts for Parity {
    fn ceiling_counts(&self) -> Ceilings {
        Ceilings {
            total: CEILING_CLASSES
                .into_iter()
                .map(|class| {
                    (
                        class.as_str().into(),
                        self.classes.get(&class).copied().unwrap_or(0),
                    )
                })
                .chain([(
                    GUARD_SILENT.into(),
                    self.guard_silent.values().map(Vec::len).sum(),
                )])
                .collect(),
            per_guard: self
                .per_guard
                .iter()
                .map(|(guard, counts)| {
                    (
                        guard.clone(),
                        GUARD_CEILING_CLASSES
                            .into_iter()
                            .map(|class| {
                                (
                                    class.as_str().into(),
                                    counts.get(&class).copied().unwrap_or(0),
                                )
                            })
                            .chain(
                                self.guard_silent
                                    .get(guard)
                                    .map(|rows| (GUARD_SILENT.into(), rows.len())),
                            )
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

/// Return every exceeded metric and group ceiling, including newly observed
/// keys, except `GUARD_SILENT`, which `check_guard_silent` owns.
pub fn check_ceilings(counts: &impl CeilingCounts, ceilings: &Ceilings) -> Vec<String> {
    let counts = counts.ceiling_counts();
    let mut exceeded = Vec::new();
    for (key, count) in &counts.total {
        if key == GUARD_SILENT {
            continue;
        }
        let ceiling = ceilings.total.get(key).copied().unwrap_or(0);
        if *count > ceiling {
            exceeded.push(format!("ceiling exceeded: {key} count {count} > {ceiling}"));
        }
    }
    for (group, counts) in &counts.per_guard {
        for (key, count) in counts {
            if key == GUARD_SILENT {
                continue;
            }
            let ceiling = ceilings
                .per_guard
                .get(group)
                .and_then(|counts| counts.get(key))
                .copied()
                .unwrap_or(0);
            if *count > ceiling {
                exceeded.push(format!(
                    "ceiling exceeded: guard {group} {key} count {count} > {ceiling}"
                ));
            }
        }
    }
    exceeded
}

/// Return each guard, and the total, whose guard-silent rows exceed the
/// `GUARD_SILENT` ceiling; a guard's line names its rows.
pub fn check_guard_silent(parity: &Parity, ceilings: &Ceilings) -> Vec<String> {
    let mut exceeded = Vec::new();
    let total = parity.guard_silent.values().map(Vec::len).sum::<usize>();
    let ceiling = ceilings.total.get(GUARD_SILENT).copied().unwrap_or(0);
    if total > ceiling {
        exceeded.push(format!(
            "ceiling exceeded: {GUARD_SILENT} count {total} > {ceiling}"
        ));
    }
    for (guard, rows) in &parity.guard_silent {
        let ceiling = ceilings
            .per_guard
            .get(guard)
            .and_then(|counts| counts.get(GUARD_SILENT))
            .copied()
            .unwrap_or(0);
        if rows.len() > ceiling {
            exceeded.push(format!(
                "ceiling exceeded: guard {guard} {GUARD_SILENT} count {} > {ceiling}: {}",
                rows.len(),
                rows.join(", ")
            ));
        }
    }
    exceeded
}

/// Write ceilings after lowering them to live counts; never raise an allowance.
pub fn write_ratchet_ceilings(
    path: &Path,
    counts: &impl CeilingCounts,
    ceilings: &mut Ceilings,
) -> std::io::Result<()> {
    fn ratchet(limits: &mut BTreeMap<String, usize>, counts: &BTreeMap<String, usize>) {
        for key in counts.keys() {
            limits.entry(key.clone()).or_default();
        }
        for (key, limit) in limits {
            *limit = (*limit).min(counts.get(key).copied().unwrap_or(0));
        }
    }
    let counts = counts.ceiling_counts();
    ratchet(&mut ceilings.total, &counts.total);
    for group in counts.per_guard.keys() {
        ceilings.per_guard.entry(group.clone()).or_default();
    }
    for (group, limits) in &mut ceilings.per_guard {
        ratchet(
            limits,
            counts.per_guard.get(group).unwrap_or(&BTreeMap::new()),
        );
    }
    let mut json =
        serde_json::to_string_pretty(ceilings).expect("ceilings serialization cannot fail");
    json.push('\n');
    std::fs::write(path, json)
}

pub fn parity(report: &HarnessReport) -> Parity {
    let mut total: BTreeMap<ParityClass, usize> = BTreeMap::new();
    let mut per_file: BTreeMap<String, BTreeMap<ParityClass, usize>> = BTreeMap::new();
    let mut per_guard: BTreeMap<String, BTreeMap<ParityClass, usize>> = BTreeMap::new();
    let mut undeclared_paths: BTreeMap<String, usize> = BTreeMap::new();
    let mut guard_queries: BTreeMap<String, BTreeMap<GuardQueryOutcome, usize>> = BTreeMap::new();
    let mut guard_silent: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for case in &report.cases {
        if let (Some(guard), Some(outcome)) = (&case.expected_guard, case.guard_query) {
            *guard_queries
                .entry(guard.clone())
                .or_default()
                .entry(outcome)
                .or_default() += 1;
            if case.guard_silent() {
                guard_silent
                    .entry(guard.clone())
                    .or_default()
                    .push(case.id.clone());
            }
        }
        for path in &case.undeclared {
            *undeclared_paths.entry(path.clone()).or_default() += 1;
        }
        *total.entry(case.class).or_default() += 1;
        *per_file
            .entry(case.file.clone())
            .or_default()
            .entry(case.class)
            .or_default() += 1;
        if case.expected_verdict.as_deref() == Some("block") {
            *per_guard
                .entry(
                    case.expected_guard
                        .clone()
                        .unwrap_or_else(|| "(structural)".to_string()),
                )
                .or_default()
                .entry(case.class)
                .or_default() += 1;
        }
    }
    Parity {
        nah_commit: report.nah_commit.clone(),
        corpus_digest: report.corpus_digest.clone(),
        classes: total,
        per_file,
        per_guard,
        undeclared_paths,
        guard_queries,
        guard_silent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nah::corpus::LoadedCase;

    #[test]
    fn check_ceilings_reports_every_exceeded_class_and_guard() {
        let mut ceilings = Ceilings {
            total: CEILING_CLASSES
                .into_iter()
                .map(|class| (class.as_str().to_string(), 1))
                .collect(),
            per_guard: BTreeMap::from([(
                "guard".into(),
                GUARD_CEILING_CLASSES
                    .into_iter()
                    .map(|class| (class.as_str().to_string(), 1))
                    .collect(),
            )]),
        };
        let mut counts = Parity {
            classes: CEILING_CLASSES
                .into_iter()
                .map(|class| (class, 1))
                .collect(),
            per_guard: BTreeMap::from([(
                "guard".into(),
                GUARD_CEILING_CLASSES
                    .into_iter()
                    .map(|class| (class, 1))
                    .collect(),
            )]),
            ..Default::default()
        };
        assert!(check_ceilings(&counts, &ceilings).is_empty());
        for count in counts.classes.values_mut() {
            *count += 1;
        }
        for count in counts.per_guard.get_mut("guard").unwrap().values_mut() {
            *count += 1;
        }
        counts.per_guard.insert(
            "new-guard".into(),
            BTreeMap::from([(ParityClass::MissingFlow, 1)]),
        );
        assert_eq!(check_ceilings(&counts, &ceilings).len(), 10);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ceilings.json");
        write_ratchet_ceilings(&path, &counts, &mut ceilings).unwrap();
        assert_eq!(
            ceilings.per_guard["guard"][ParityClass::ExplainedPartial.as_str()],
            1
        );
        assert_eq!(
            ceilings.per_guard["new-guard"][ParityClass::ExplainedPartial.as_str()],
            0
        );
        counts.classes.clear();
        counts.per_guard.clear();
        assert!(check_ceilings(&counts, &ceilings).is_empty());
        write_ratchet_ceilings(&path, &counts, &mut ceilings).unwrap();
        let lowered: Ceilings = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        counts.per_guard.insert(
            "guard".into(),
            BTreeMap::from([(ParityClass::ExplainedPartial, 1)]),
        );
        assert_eq!(
            lowered.per_guard["guard"][ParityClass::ExplainedPartial.as_str()],
            0
        );
        assert_eq!(check_ceilings(&counts, &lowered).len(), 1);
    }

    fn shell_case(id: &str, command: &str) -> CaseLoad {
        CaseLoad::Ok(Box::new(LoadedCase {
            file: "test.jsonl".to_string(),
            id: id.to_string(),
            input: CaseInput::Command(command.to_string()),
            cwd: Some("/workspace/project".to_string()),
            context: Default::default(),
            expected: Expectation::Decision {
                verdict: nah_corpus_schema::ExpectedVerdict::Delegate,
                guard: None,
                coverage: None,
                guards: None,
            },
            observation: None,
        }))
    }

    #[test]
    fn shell_cases_are_analyzed() {
        let report = run_corpus(
            &Engine::new().with_causality_detail(true),
            vec![shell_case("a", "rm -rf /")],
            "test-corpus".to_string(),
            "test-nah".to_string(),
        );
        assert_eq!(report.cases.len(), 1);
        assert_eq!(report.cases[0].class, ParityClass::Covered);
        assert!(
            report.cases[0]
                .effects
                .iter()
                .any(|e| e == "filesystem.delete /")
        );
        assert_eq!(report.nah_commit, "test-nah");
    }

    #[test]
    fn report_is_deterministic_and_sorted() {
        let cases = || {
            vec![
                shell_case("b", "ls"),
                shell_case("a", "ls"),
                CaseLoad::Malformed {
                    file: "a.jsonl".to_string(),
                    line: 3,
                    error: "bad".to_string(),
                },
            ]
        };
        let engine = Engine::new().with_causality_detail(true);
        let cases_json = |report: HarnessReport| serde_json::to_string(&report.cases).unwrap();
        let one = cases_json(run_corpus(
            &engine,
            cases(),
            "test-corpus".to_string(),
            "test-nah".to_string(),
        ));
        let two = cases_json(run_corpus(
            &engine,
            cases(),
            "test-corpus".to_string(),
            "test-nah".to_string(),
        ));
        assert_eq!(one, two);
        let report = run_corpus(
            &engine,
            cases(),
            "test-corpus".to_string(),
            "test-nah".to_string(),
        );
        assert_eq!(report.cases[0].file, "a.jsonl");
        assert_eq!(report.cases[1].id, "a");
        assert_eq!(report.cases[2].id, "b");
    }

    #[test]
    fn causality_metric_counts_graphs_and_pairs_on_a_separate_axis() {
        let report = run_corpus(
            &Engine::new().with_causality_detail(true),
            vec![
                // A pipe wires two stages and a read reaches an upload.
                shell_case("pipe", "cat f | curl -d@- http://h"),
                // Sequencing and a lone command still carry occurrence nodes.
                shell_case("seq", "cat f; curl -d@- http://h"),
                shell_case("lone", "ls"),
            ],
            "test-corpus".to_string(),
            "test-nah".to_string(),
        );
        assert_eq!(report.flow.plans_with_graph, 3);
        assert_eq!(
            report.flow.full_coverage + report.flow.partial_coverage,
            report.flow.plans_with_graph
        );
        assert!(report.flow.stages >= 2, "pipe has two stages: {report:?}");
        assert!(report.flow.edges >= 1, "pipe has a pipe edge: {report:?}");
        assert!(
            report.flow.complete_reachable_pairs >= 1,
            "read reaches upload: {report:?}"
        );
        assert_eq!(report.flow.partial_reachable_pairs, 0);
        assert_eq!(report.flow.depth_saturated_plans, 0);
        assert_eq!(report.flow.pair_saturated_plans, 0);
        assert_eq!(report.flow.producer_saturated_plans, 0);
        // Flow facts stay off the effect-domain coverage map.
        assert!(
            report
                .cases
                .iter()
                .all(|c| !c.coverage.contains_key("flow"))
        );

        let mut limits = effinterp_engine::default_limits();
        limits.insert("max_causal_pairs".into(), 1);
        let saturated = run_corpus(
            &Engine::with_limits(limits)
                .unwrap()
                .with_causality_detail(true),
            vec![shell_case("pipe", "cat f | tee g | curl -d@- http://h")],
            "test-corpus".to_string(),
            "test-nah".to_string(),
        );
        assert_eq!(saturated.flow.complete_reachable_pairs, 0);
        assert_eq!(saturated.flow.partial_reachable_pairs, 1);
        assert_eq!(saturated.flow.pair_saturated_plans, 1);
        assert_eq!(saturated.flow.producer_saturated_plans, 1);
    }

    #[test]
    fn guard_tally_counts_only_blocks_and_preserves_structural_rows() {
        let mut report = run_corpus(
            &Engine::new().with_causality_detail(true),
            vec![
                shell_case("a", "true"),
                shell_case("b", "true"),
                shell_case("c", "true"),
            ],
            "test-corpus".to_string(),
            "test-nah".to_string(),
        );
        report.cases[0].expected_verdict = Some("block".to_string());
        report.cases[1].expected_verdict = Some("block".to_string());
        report.cases[1].expected_guard = Some("guard".to_string());
        report.cases[2].expected_verdict = Some("delegate".to_string());
        report.cases[2].expected_guard = Some("delegate-only".to_string());
        let parity = parity(&report);
        assert_eq!(parity.classes.values().sum::<usize>(), 3);
        assert_eq!(parity.per_file.len(), 1);
        assert_eq!(parity.per_guard.len(), 2);
        assert_eq!(parity.per_guard["(structural)"].values().sum::<usize>(), 1);
        assert_eq!(parity.per_guard["guard"].values().sum::<usize>(), 1);
    }
}
