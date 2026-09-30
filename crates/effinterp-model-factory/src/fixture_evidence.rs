//! Fixture evidence: the projected whole-plan fixture format and its
//! migration to the current engine, the fact assertion fixture format, and
//! evaluating a fact assertion case against a plan.

use std::collections::BTreeSet;
use std::path::Path;

use effinterp_engine::Engine;
use effinterp_matcher::{Assertion, Evaluator, NO_LABELS, Outcome, Query, QueryLimits, Witness};
use effinterp_model_schema::{FactAssertionCase, FactAssertionFixture, SerializedMatcherQuery};
use effinterp_proto::{Bindings, Plan, Subject};

use crate::FactoryError;
use crate::model_directory::{read, write};

/// Re-analyze the subjects of a whole-plan fixture and write the projected
/// fixture the current engine produces for them.
pub fn migrate_fixture(input: &Path, output: &Path) -> Result<(), FactoryError> {
    let source = read(input)?;
    let prior: Vec<serde_json::Value> =
        serde_json::from_str(&source).map_err(|error| FactoryError::Json(error.to_string()))?;
    let engine = Engine::new().with_causality_detail(true);
    let plans = prior
        .into_iter()
        .enumerate()
        .map(|(case, value)| {
            let subject: Subject =
                serde_json::from_value(value.get("subject").cloned().ok_or_else(|| {
                    FactoryError::Validation(format!("fixture case {case} has no subject"))
                })?)
                .map_err(|error| FactoryError::Json(error.to_string()))?;
            engine
                .analyze(&subject)
                .map_err(|error| FactoryError::Validation(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source = projected_fixture_json(&plans)?;
    write(output, source.as_bytes())
}

pub(crate) fn read_projected_fixture(
    bytes: &[u8],
    model_set_id: &str,
) -> Result<Vec<Plan>, String> {
    let mut cases: Vec<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    cases
        .iter_mut()
        .enumerate()
        .map(|(case, value)| {
            let analysis = value
                .get_mut("analysis")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| format!("case {case} has no analysis object"))?;
            if analysis.contains_key("model_set") {
                return Err(format!(
                    "case {case} stores analysis.model_set instead of using the fixture projection"
                ));
            }
            analysis.insert(
                "model_set".to_string(),
                serde_json::Value::String(model_set_id.to_string()),
            );
            serde_json::from_value(value.take()).map_err(|error| format!("case {case}: {error}"))
        })
        .collect()
}

#[derive(serde::Serialize)]
struct ProjectedAnalysis<'a> {
    engine_version: &'a str,
    limits: &'a effinterp_proto::Limits,
}

// Keep Plan's serialized field order while omitting only the catalog-wide identity.
#[derive(serde::Serialize)]
struct ProjectedPlan<'a> {
    schema: &'a str,
    subject: &'a Subject,
    analysis: ProjectedAnalysis<'a>,
    effects: &'a [effinterp_proto::Effect],
    execution_graph: &'a effinterp_proto::ExecutionGraph,
    #[serde(skip_serializing_if = "projected_slice_is_empty")]
    provenance: &'a [effinterp_proto::ProvenanceNode],
    #[serde(skip_serializing_if = "projected_slice_is_empty")]
    boundaries: &'a [effinterp_proto::Boundary],
    coverage: &'a effinterp_proto::Coverage,
    causality: &'a effinterp_proto::Causality,
}

fn projected_slice_is_empty<T>(values: &&[T]) -> bool {
    values.is_empty()
}

pub(crate) fn projected_fixture_json(plans: &[Plan]) -> Result<String, FactoryError> {
    assert!(
        plans.iter().all(|plan| plan.causality.graph.is_some()),
        "causality detail required"
    );
    let projected = plans
        .iter()
        .map(|plan| ProjectedPlan {
            schema: &plan.schema,
            subject: &plan.subject,
            analysis: ProjectedAnalysis {
                engine_version: &plan.analysis.engine_version,
                limits: &plan.analysis.limits,
            },
            effects: &plan.effects,
            execution_graph: &plan.execution_graph,
            provenance: &plan.provenance,
            boundaries: &plan.boundaries,
            coverage: &plan.coverage,
            causality: &plan.causality,
        })
        .collect::<Vec<_>>();
    let mut source = serde_json::to_string_pretty(&projected)
        .map_err(|error| FactoryError::Json(error.to_string()))?;
    source.push('\n');
    Ok(source)
}

pub(crate) fn read_fact_assertion_fixture(bytes: &[u8]) -> Result<FactAssertionFixture, String> {
    let fixture: FactAssertionFixture =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    fixture.validate()?;
    for (case_index, case) in fixture.cases.iter().enumerate() {
        for required in &case.required_effects {
            matcher_query(
                &required.query,
                case_index,
                "required effect",
                |assertion| matches!(assertion, Assertion::Effect { .. }),
            )?;
        }
        for forbidden in &case.forbidden_effects {
            matcher_query(forbidden, case_index, "forbidden effect", |assertion| {
                matches!(assertion, Assertion::Effect { .. })
            })?;
        }
        for required in &case.required_boundaries {
            matcher_query(
                &required.query,
                case_index,
                "required boundary",
                |assertion| matches!(assertion, Assertion::Boundary { .. }),
            )?;
        }
    }
    Ok(fixture)
}

fn matcher_query(
    serialized: &SerializedMatcherQuery,
    case: usize,
    kind: &str,
    expected: impl FnOnce(&Assertion) -> bool,
) -> Result<Query, String> {
    let query: Query = serde_json::from_value(serialized.0.clone())
        .map_err(|error| format!("case {case} {kind}: {error}"))?;
    query
        .validate()
        .map_err(|error| format!("case {case} {kind} query is invalid: {error}"))?;
    if !expected(&query.assertion) {
        return Err(format!(
            "case {case} {kind} query has the wrong assertion kind"
        ));
    }
    Ok(query)
}

#[derive(Default)]
pub(crate) struct ReviewedFacts {
    pub(crate) operations: BTreeSet<String>,
    pub(crate) boundaries: BTreeSet<String>,
}

pub(crate) fn plan_evaluator(plan: &Plan) -> Evaluator<'_> {
    let bindings = Bindings::from_subject(&plan.subject);
    Evaluator::new(
        plan,
        plan.execution_graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, _)| {
                (
                    effinterp_proto::ExecutionNodeRef(index as u32),
                    bindings.clone(),
                )
            })
            .collect(),
        &NO_LABELS,
        QueryLimits::default(),
    )
}

pub(crate) fn evaluate_fact_case(
    plan: &Plan,
    case: &FactAssertionCase,
    case_index: usize,
) -> Result<ReviewedFacts, String> {
    if plan.coverage != case.coverage {
        return Err("coverage differs from the reviewed map".to_string());
    }
    let evaluator = plan_evaluator(plan);
    let mut facts = ReviewedFacts::default();
    for required in &case.required_effects {
        let query = matcher_query(
            &required.query,
            case_index,
            "required effect",
            |assertion| matches!(assertion, Assertion::Effect { .. }),
        )?;
        let outcome = evaluator.evaluate(&query);
        let Outcome::Match(Witness::Effect { effect }) = outcome else {
            return Err(format!(
                "required effect {query:?} did not match: {outcome:?}"
            ));
        };
        let effect = plan
            .effects
            .iter()
            .find(|candidate| candidate.id == effect)
            .ok_or_else(|| "matcher returned an absent effect witness".to_string())?;
        if effect.modality != required.modality {
            return Err(format!(
                "required effect modality is {}, expected {}",
                effect.modality.as_str(),
                required.modality.as_str()
            ));
        }
        facts.operations.insert(effect.operation.0.clone());
    }
    for forbidden in &case.forbidden_effects {
        let query = matcher_query(forbidden, case_index, "forbidden effect", |assertion| {
            matches!(assertion, Assertion::Effect { .. })
        })?;
        let outcome = evaluator.evaluate(&query);
        if outcome != Outcome::NoMatch {
            return Err(format!("forbidden effect was not disproved: {outcome:?}"));
        }
    }
    for required in &case.required_boundaries {
        let query = matcher_query(
            &required.query,
            case_index,
            "required boundary",
            |assertion| matches!(assertion, Assertion::Boundary { .. }),
        )?;
        let outcome = evaluator.evaluate(&query);
        let Outcome::Match(Witness::Boundary { boundary }) = outcome else {
            return Err(format!(
                "required boundary {query:?} did not match: {outcome:?}"
            ));
        };
        let boundary = plan
            .boundaries
            .get(boundary.0 as usize)
            .ok_or_else(|| "matcher returned an absent boundary witness".to_string())?;
        if boundary.class != required.class || boundary.domains != required.domains {
            return Err(format!(
                "required boundary metadata differs: class={}, domains={:?}",
                boundary.class, boundary.domains
            ));
        }
        facts.boundaries.insert(boundary.reason.to_string());
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{evaluate_fact_case, read_fact_assertion_fixture};
    use effinterp_engine::Engine;

    #[test]
    fn standalone_kubectl_fixture_matches_reviewed_facts() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../effinterp-engine/tests/fixtures/model_equivalence/kubectl_target.json");
        let fixture = read_fact_assertion_fixture(&fs::read(path).unwrap()).unwrap();
        assert_eq!(fixture.cases.len(), 34);
        let engine = Engine::new().with_causality_detail(true);
        for (case_index, case) in fixture.cases.iter().enumerate() {
            let plan = engine.analyze(&case.subject).unwrap();
            effinterp_proto::validate_plan(&plan).unwrap();
            evaluate_fact_case(&plan, case, case_index)
                .unwrap_or_else(|error| panic!("kubectl case {case_index}: {error}"));
        }
    }
}
