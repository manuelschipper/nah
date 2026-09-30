//! Layered semantic evaluation corpus.
//!
//! Unlike the nah goldens (which key on a corpus id and a verdict-level
//! oracle), these cases carry their own input and exact expectation, so they
//! test the engine's semantics directly across three layers:
//!
//! - Layer 1: one modeled operation at a time — positive, negative-ownership,
//!   symbolic argument, malformed, and dynamic/unresolved cases.
//! - Layer 2: composition — within-file and cross-file calls, argument
//!   substitution, realm transitions, cross-language subprocess chains.
//! - Layer 3: repository fixtures — a small repo with an exact reverse-query
//!   answer, run through the real index.
//! - Layer 4: flow — producer→consumer reachability derived from the
//!   serialized plan alone through `effinterp_trace::reachable_pairs`
//!   (`goldens/flows.json`).
//!
//! A case may `require` effects (must be present), `forbid` effects (must be
//! absent — the false-positive guard for negative-ownership cases), and
//! `require_boundary` reasons (must be present — malformed/dynamic cases).
//! Flow cases add `require_flow` (a producer→consumer pair that must be
//! reachable, optionally with provenance on every stage of the connecting
//! path) and `forbid_flow` (a pair that must NOT be reachable — the
//! invented-edge guard). A requirement the engine does not yet meet is marked
//! `known_gap` with a note rather than silently dropped, so real gaps stay
//! visible.

use std::collections::BTreeMap;
use std::path::Path;

use effinterp_engine::Engine;
use effinterp_proto::{HostContext, Plan, SourceDialect, Subject, validate_plan};
use serde::Deserialize;

use crate::nah::goldens::{FlowReq, Req};
use crate::nah::normalize::{Normalized, normalize_plan};

const EVAL_JSON: &str = include_str!("../../../bench/nah/goldens/layered.json");
const FLOW_JSON: &str = include_str!("../../../bench/nah/goldens/flows.json");

#[derive(Debug, Deserialize)]
struct EvalFile {
    cases: Vec<LayeredCase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LayeredCase {
    pub id: String,
    pub layer: u8,
    #[serde(default)]
    pub note: Option<String>,
    pub input: LayeredInput,
    #[serde(default)]
    pub require: Vec<Req>,
    #[serde(default)]
    pub forbid: Vec<Req>,
    #[serde(default)]
    pub require_boundary: Vec<String>,
    #[serde(default)]
    pub forbid_boundary: Vec<String>,
    #[serde(default)]
    pub require_coverage: BTreeMap<String, String>,
    #[serde(default)]
    pub require_flow: Vec<FlowReq>,
    #[serde(default)]
    pub forbid_flow: Vec<FlowReq>,
    /// A requirement the engine does not yet satisfy: expected, tracked, not a
    /// test failure. The reason is surfaced in the summary.
    #[serde(default)]
    pub known_gap: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayeredInput {
    /// argv, no shell interpretation.
    Exec {
        argv: Vec<String>,
        cwd: Option<String>,
        #[serde(default)]
        source_root: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// shell source.
    Shell {
        source: String,
        cwd: Option<String>,
        #[serde(default)]
        source_root: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// language source: python/js/ts use their typed subjects, everything else
    /// the generic Source subject.
    Source {
        language: String,
        code: String,
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// A checked-in fixture repo plus a reverse query.
    Fixture {
        path: String,
        reach: String,
        #[serde(default)]
        entrypoint: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LayeredClass {
    Pass,
    MissingEffect,
    FalsePositive,
    BoundaryMissing,
    BoundaryPresent,
    CoverageMismatch,
    MissingFlow,
    IncompleteFlow,
    ForbiddenFlow,
    KnownGap,
    InvalidPlan,
    SilentSymbolicDrop,
    FixtureError,
}

impl LayeredClass {
    pub fn as_str(self) -> &'static str {
        match self {
            LayeredClass::Pass => "pass",
            LayeredClass::MissingEffect => "missing_effect",
            LayeredClass::FalsePositive => "false_positive",
            LayeredClass::BoundaryMissing => "boundary_missing",
            LayeredClass::BoundaryPresent => "boundary_present",
            LayeredClass::CoverageMismatch => "coverage_mismatch",
            LayeredClass::MissingFlow => "missing_flow",
            LayeredClass::IncompleteFlow => "incomplete_flow",
            LayeredClass::ForbiddenFlow => "forbidden_flow",
            LayeredClass::KnownGap => "known_gap",
            LayeredClass::SilentSymbolicDrop => "silent_symbolic_drop",
            LayeredClass::InvalidPlan => "invalid_plan",
            LayeredClass::FixtureError => "fixture_error",
        }
    }
}

pub struct LayeredOutcome {
    pub id: String,
    pub layer: u8,
    pub class: LayeredClass,
    pub detail: Option<String>,
    pub mutation: crate::nah::mutate::MutationMeasurement,
}

pub fn load_layered_cases() -> Vec<LayeredCase> {
    let mut file: EvalFile = serde_json::from_str(EVAL_JSON).expect("layered.json parses");
    let flows: EvalFile = serde_json::from_str(FLOW_JSON).expect("flows.json parses");
    file.cases.extend(flows.cases);
    file.cases
}

fn subject_of(input: &LayeredInput) -> Option<Subject> {
    Some(match input {
        LayeredInput::Exec { argv, cwd, env, .. } => Subject::Exec {
            argv: argv.clone(),
            cwd: cwd.clone(),
            context: HostContext {
                env: env.clone(),
                ..Default::default()
            },
        },
        LayeredInput::Shell {
            source, cwd, env, ..
        } => Subject::Shell {
            source: source.clone(),
            cwd: cwd.clone(),
            context: HostContext {
                env: env.clone(),
                ..Default::default()
            },
        },
        LayeredInput::Source {
            language,
            code,
            cwd,
            env,
        } => match language.as_str() {
            "python" => Subject::Source {
                dialect: None,
                language: "python".into(),
                source: code.clone(),
                cwd: cwd.clone(),
                context: HostContext {
                    env: env.clone(),
                    ..Default::default()
                },
            },
            "js" => Subject::Source {
                language: "js".into(),
                source: code.clone(),
                dialect: Some(SourceDialect::Js),
                cwd: cwd.clone(),
                context: HostContext {
                    env: env.clone(),
                    ..Default::default()
                },
            },
            "ts" => Subject::Source {
                language: "js".into(),
                source: code.clone(),
                dialect: Some(SourceDialect::Ts),
                cwd: cwd.clone(),
                context: HostContext {
                    env: env.clone(),
                    ..Default::default()
                },
            },
            other => Subject::Source {
                dialect: None,
                language: other.to_string(),
                source: code.clone(),
                cwd: cwd.clone(),
                context: HostContext {
                    env: env.clone(),
                    ..Default::default()
                },
            },
        },
        LayeredInput::Fixture { .. } => return None,
    })
}

/// Evaluate one case against the engine (or the repo index for a fixture).
/// `fixture_root` is the directory holding Layer-3 fixture repos.
pub fn evaluate_layered_case(
    case: &LayeredCase,
    engine: &Engine,
    fixture_root: &Path,
) -> LayeredOutcome {
    let mk = |class, detail| LayeredOutcome {
        id: case.id.clone(),
        layer: case.layer,
        class,
        detail,
        mutation: Default::default(),
    };

    let (normalized, plan) = match &case.input {
        LayeredInput::Fixture {
            path,
            reach,
            entrypoint,
        } => match fixture_reach(fixture_root, path, reach, entrypoint.as_deref()) {
            Ok(n) => (n, None),
            Err(e) => return mk(LayeredClass::FixtureError, Some(e)),
        },
        other => {
            let subject = subject_of(other).expect("non-fixture subject");
            let source = match other {
                LayeredInput::Exec {
                    cwd, source_root, ..
                }
                | LayeredInput::Shell {
                    cwd, source_root, ..
                } => source_root
                    .as_deref()
                    .map(|source_root| (source_root, cwd.as_deref())),
                _ => None,
            };
            let resolver = match source {
                Some((source_root, cwd)) => {
                    let root = fixture_root.join(source_root);
                    let anchor = cwd.map_or_else(String::new, |cwd| {
                        effinterp_proto::normalize_path(cwd, effinterp_proto::PathPlatform::Posix)
                    });
                    let resolver = match effinterp_repo::ShallowSourceResolver::new(
                        &root,
                        &anchor,
                        engine.limits().max_source_bytes,
                    ) {
                        Ok(resolver) => resolver,
                        Err(error) => {
                            return mk(LayeredClass::FixtureError, Some(error.to_string()));
                        }
                    };
                    Some(resolver)
                }
                None => None,
            };
            let analysis = match resolver {
                Some(resolver) => engine.analyze_with_resolver(&subject, &resolver),
                None => engine.analyze(&subject),
            };
            let plan = match analysis {
                Ok(p) => p,
                Err(e) => return mk(LayeredClass::FixtureError, Some(e.to_string())),
            };
            if let Err(errs) = validate_plan(&plan) {
                return mk(LayeredClass::InvalidPlan, Some(format!("{errs:?}")));
            }
            (normalize_plan(&plan), Some(plan))
        }
    };

    let mut outcome = classify(case, &normalized, plan.as_ref(), mk);
    if let Some(plan) = &plan {
        outcome.mutation =
            crate::nah::mutate::measure_symbolic_mutations(engine, plan, &case.require, None, None);
        if !outcome.mutation.findings.is_empty() {
            outcome.class = LayeredClass::SilentSymbolicDrop;
            outcome.detail = Some(format!("{:?}", outcome.mutation.findings));
        }
    } else {
        outcome.mutation.not_exercised = 1;
        outcome
            .mutation
            .reasons
            .insert("repository_transform_unsupported".into(), 1);
    }
    outcome
}

fn classify(
    case: &LayeredCase,
    n: &Normalized,
    plan: Option<&Plan>,
    mk: impl Fn(LayeredClass, Option<String>) -> LayeredOutcome,
) -> LayeredOutcome {
    if (!case.require_flow.is_empty() || !case.forbid_flow.is_empty())
        && plan.is_none_or(|plan| plan.causality.graph.is_none())
    {
        return mk(
            LayeredClass::IncompleteFlow,
            Some("causality detail unavailable".into()),
        );
    }

    // A forbidden effect present is a false positive, regardless of gap notes.
    for f in &case.forbid {
        if f.satisfied_by(&n.effects) {
            return mk(
                LayeredClass::FalsePositive,
                Some(format!("forbidden effect present: {}", f.describe())),
            );
        }
    }
    for req in &case.require {
        if !req.satisfied_by(&n.effects) {
            if let Some(reason) = &case.known_gap {
                return mk(
                    LayeredClass::KnownGap,
                    Some(format!("{}: {reason}", req.describe())),
                );
            }
            return mk(LayeredClass::MissingEffect, Some(req.describe()));
        }
    }
    for reason in &case.require_boundary {
        if !n.boundaries.iter().any(|b| b.starts_with(reason)) {
            if let Some(gap) = &case.known_gap {
                return mk(
                    LayeredClass::KnownGap,
                    Some(format!("boundary {reason}: {gap}")),
                );
            }
            return mk(LayeredClass::BoundaryMissing, Some(reason.clone()));
        }
    }
    for reason in &case.forbid_boundary {
        if n.boundaries
            .iter()
            .any(|boundary| boundary.starts_with(reason))
        {
            return mk(LayeredClass::BoundaryPresent, Some(reason.clone()));
        }
    }
    for (domain, expected) in &case.require_coverage {
        if n.coverage.get(domain) != Some(expected) {
            return mk(
                LayeredClass::CoverageMismatch,
                Some(format!(
                    "{domain}: expected {expected}, got {}",
                    n.coverage.get(domain).map_or("missing", String::as_str)
                )),
            );
        }
    }
    // Flow expectations are answered from the serialized plan alone, through
    // the same public consumer any external tool would use.
    if !case.require_flow.is_empty() || !case.forbid_flow.is_empty() {
        let evaluator = crate::nah::goldens::evaluator(plan.unwrap());
        let evaluate =
            |flow: &FlowReq| evaluator.evaluate(&flow.query().expect("flow requirement imports"));
        let forbidden: Vec<_> = case
            .forbid_flow
            .iter()
            .map(|flow| (flow, evaluate(flow)))
            .collect();
        if let Some((flow, _)) = forbidden
            .iter()
            .find(|(_, outcome)| matches!(outcome, effinterp_matcher::Outcome::Match(_)))
        {
            return mk(
                LayeredClass::ForbiddenFlow,
                Some(format!("forbidden flow present: {}", flow.describe())),
            );
        }
        let missing: Vec<_> = case
            .require_flow
            .iter()
            .map(|flow| (flow, evaluate(flow)))
            .filter(|(_, outcome)| !matches!(outcome, effinterp_matcher::Outcome::Match(_)))
            .collect();
        if !missing.is_empty() {
            if let Some(gap) = &case.known_gap {
                return mk(
                    LayeredClass::KnownGap,
                    Some(format!("{}: {gap}", missing[0].0.describe())),
                );
            }
            if let Some((flow, _)) = missing
                .iter()
                .find(|(_, outcome)| *outcome == effinterp_matcher::Outcome::NoMatch)
            {
                return mk(LayeredClass::MissingFlow, Some(flow.describe()));
            }
            return mk(
                LayeredClass::IncompleteFlow,
                Some(format!(
                    "required flow inconclusive: {}",
                    missing[0].0.describe()
                )),
            );
        }
        if let Some((flow, _)) = forbidden
            .iter()
            .find(|(_, outcome)| *outcome != effinterp_matcher::Outcome::NoMatch)
        {
            return mk(
                LayeredClass::IncompleteFlow,
                Some(format!("forbidden flow inconclusive: {}", flow.describe())),
            );
        }
    }
    mk(LayeredClass::Pass, None)
}

fn fixture_reach(
    root: &Path,
    path: &str,
    selector: &str,
    entrypoint: Option<&str>,
) -> Result<Normalized, String> {
    use effinterp_repo::{IndexLimits, Selector, build_index, effects_of, reach};
    let dir = root.join(path);
    let index = build_index(&dir, IndexLimits::default());
    let sel = Selector::parse(selector).map_err(|e| format!("bad selector {selector:?}: {e:?}"))?;
    let report = reach(&index, &sel, None);
    // Normalize retained effect evidence, including unresolved target relations.
    let effects = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .map(|hit| &hit.fact)
        .chain(
            report
                .payload
                .as_reach()
                .unwrap()
                .indeterminate
                .iter()
                .filter_map(|row| match row {
                    effinterp_proto::Indeterminate::Effect { fact, .. } => Some(fact),
                    effinterp_proto::Indeterminate::Boundary { .. } => None,
                }),
        )
        .map(|fact| {
            format!(
                "{} {}",
                fact.operation.0,
                effinterp_proto::display_resource(&fact.resource)
            )
        })
        .collect();
    let (boundaries, coverage) = if let Some(entrypoint) = entrypoint {
        let report = effects_of(&index, entrypoint)
            .ok_or_else(|| format!("missing fixture entrypoint {entrypoint:?}"))?
            .payload
            .into_effects()
            .unwrap();
        (
            report
                .boundaries
                .iter()
                .map(|boundary| {
                    format!(
                        "{} [{}]",
                        boundary.reason,
                        boundary.display_domains.join(", ")
                    )
                })
                .collect(),
            report
                .coverage
                .into_iter()
                .map(|(domain, claim)| {
                    (
                        domain,
                        match claim.level {
                            effinterp_proto::CoverageLevel::Full => "full",
                            effinterp_proto::CoverageLevel::Partial => "partial",
                            effinterp_proto::CoverageLevel::None => "none",
                        }
                        .to_string(),
                    )
                })
                .collect(),
        )
    } else {
        (Vec::new(), BTreeMap::new())
    };
    Ok(Normalized {
        gaps: BTreeMap::new(),
        effects,
        boundaries,
        coverage,
    })
}

/// Authored expectations, separate from the analyzer's own coverage claims.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SemanticScore {
    pub cases: usize,
    pub passed: usize,
    pub known_gaps: BTreeMap<String, String>,
    pub failures: BTreeMap<String, String>,
}

pub fn measure_semantic_score(engine: &Engine, fixtures: &Path) -> SemanticScore {
    let mut score = SemanticScore::default();
    for case in load_layered_cases() {
        let result = evaluate_layered_case(&case, engine, fixtures);
        score.cases += 1;
        match result.class {
            LayeredClass::Pass => score.passed += 1,
            LayeredClass::KnownGap => {
                score
                    .known_gaps
                    .insert(result.id, result.detail.unwrap_or_default());
            }
            _ => {
                score.failures.insert(
                    result.id,
                    format!(
                        "{}: {}",
                        result.class.as_str(),
                        result.detail.unwrap_or_default()
                    ),
                );
            }
        }
    }
    for case in effinterp_testkit::selected_code::selected_code_cases() {
        let (plan, requests) = effinterp_testkit::selected_code::analyze_selected_code(&case);
        score.cases += 1;
        match effinterp_testkit::selected_code::check_selected_code(&case, &plan, &requests) {
            Ok(()) => score.passed += 1,
            Err(error) => {
                score.failures.insert(case.id, error);
            }
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nah::goldens::ResourceMatch;
    use effinterp_engine::default_limits;
    use effinterp_matcher::render::rendered_resource;
    use effinterp_trace::reachable_pairs;

    fn any_resource(op: impl Into<String>) -> Req {
        Req {
            op: op.into(),
            resource: ResourceMatch::Any(true),
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn saturated_flow_keeps_present_violations_and_marks_absence_incomplete() {
        let source = "cat f | tee g | curl -d@- http://h";
        let mut limits = default_limits();
        limits.insert("max_causal_pairs".into(), 1);
        let engine = Engine::with_limits(limits)
            .unwrap()
            .with_causality_detail(true);
        let subject = Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        };
        let plan = engine.analyze(&subject).unwrap();
        let reachability = reachable_pairs(&plan).unwrap();
        let retained = &reachability.pairs()[0];
        let retained_flow = FlowReq {
            from: Req {
                op: retained.from.op.clone(),
                resource: ResourceMatch::Eq(rendered_resource(&retained.from.resource)),
                attributes: BTreeMap::new(),
            },
            to: Req {
                op: retained.to.op.clone(),
                resource: ResourceMatch::Eq(rendered_resource(&retained.to.resource)),
                attributes: BTreeMap::new(),
            },
            path_provenance: false,
        };
        let case = LayeredCase {
            id: "saturated-flow".into(),
            layer: 4,
            note: None,
            input: LayeredInput::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                source_root: None,
                env: BTreeMap::new(),
            },
            require: Vec::new(),
            forbid: Vec::new(),
            require_boundary: Vec::new(),
            forbid_boundary: Vec::new(),
            require_coverage: BTreeMap::new(),
            require_flow: Vec::new(),
            forbid_flow: vec![retained_flow.clone()],
            known_gap: None,
        };
        assert_eq!(
            evaluate_layered_case(&case, &engine, Path::new(".")).class,
            LayeredClass::ForbiddenFlow
        );

        let mut absent = case;
        absent.forbid_flow = vec![FlowReq {
            from: retained_flow.from,
            to: any_resource("database.write"),
            path_provenance: false,
        }];
        assert_eq!(
            evaluate_layered_case(&absent, &engine, Path::new(".")).class,
            LayeredClass::IncompleteFlow
        );
    }
}
