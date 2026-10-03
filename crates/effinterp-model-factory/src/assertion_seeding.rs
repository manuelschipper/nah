//! Assertion seeding: replace a whole-plan fixture with mechanically seeded
//! fact assertions (matcher queries) for a reviewer to prune.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use effinterp_matcher::{
    Assertion, AttributePredicate, AttributeTest, BoundaryDomainsPredicate,
    BoundaryProvenancePredicate, Closure, Evaluator, OperationMatch, Outcome, Projection, Query,
    ResourcePredicate, ResourceVariant, Selector, TextPredicate, Witness,
};
use effinterp_model_schema::{
    DeclarationDocument, FACT_ASSERTION_FIXTURE_SCHEMA_V1, FactAssertionCase, FactAssertionFixture,
    RequiredBoundaryAssertion, RequiredEffectAssertion, SerializedMatcherQuery,
};
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, validate_plan};

use crate::FactoryError;
use crate::fixture_evidence::{evaluate_fact_case, plan_evaluator, read_projected_fixture};
use crate::model_directory::{pretty_model_json, read, write};

/// Replace a whole-plan fixture with mechanically seeded fact assertions for review.
pub fn seed_assertions(fixture: &Path, document: Option<&Path>) -> Result<(), FactoryError> {
    let bytes = fs::read(fixture).map_err(|error| FactoryError::Io {
        path: fixture.to_path_buf(),
        detail: error.to_string(),
    })?;
    let document = document
        .map(|path| {
            serde_json::from_str::<DeclarationDocument>(&read(path)?)
                .map_err(|error| FactoryError::Json(format!("{}: {error}", path.display())))
        })
        .transpose()?;
    let source = seed_assertion_fixture_json(&bytes, document.as_ref())?;
    write(fixture, source.as_bytes())
}

fn seed_assertion_fixture_json(
    bytes: &[u8],
    document: Option<&DeclarationDocument>,
) -> Result<String, FactoryError> {
    let model_set_id = document.map_or("seed-assertions", |document| document.identity.as_str());
    let plans = read_projected_fixture(bytes, model_set_id).map_err(FactoryError::Validation)?;
    for plan in &plans {
        validate_plan(plan).map_err(|errors| FactoryError::Validation(format!("{errors:?}")))?;
    }

    let expected_operations = document
        .into_iter()
        .flat_map(|document| document.evidence.expected_facts.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_generic_operations = expected_operations
        .iter()
        .filter(|operation| is_generic_seed_operation(operation))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut retained_generic_operations = BTreeSet::new();
    let cases = plans
        .iter()
        .map(|plan| {
            let mut effect_keys = BTreeSet::new();
            let required_effects = plan
                .effects
                .iter()
                .filter(|effect| {
                    !is_generic_seed_operation(effect.operation.as_str())
                        || expected_generic_operations.contains(effect.operation.as_str())
                            && retained_generic_operations.insert(effect.operation.0.clone())
                })
                .map(seed_effect_assertion)
                .filter(|assertion| match assertion {
                    Ok(assertion) => effect_keys.insert(
                        serde_json::to_string(assertion)
                            .expect("seeded effect assertion serializes"),
                    ),
                    Err(_) => true,
                })
                .collect::<Result<Vec<_>, _>>()?;

            let evaluator = plan_evaluator(plan);
            let mut boundary_keys = BTreeSet::new();
            let required_boundaries = plan
                .boundaries
                .iter()
                .filter_map(|boundary| seed_boundary_assertion(plan, &evaluator, boundary))
                .filter(|assertion| match assertion {
                    Ok(assertion) => boundary_keys.insert(
                        serde_json::to_string(assertion)
                            .expect("seeded boundary assertion serializes"),
                    ),
                    Err(_) => true,
                })
                .collect::<Result<Vec<_>, _>>()?;
            let forbidden_effects = if required_effects.is_empty() && required_boundaries.is_empty()
            {
                expected_operations
                    .iter()
                    .filter(|operation| !is_generic_seed_operation(operation))
                    .map(|operation| seed_forbidden_effect_assertion(operation))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };

            Ok(FactAssertionCase {
                subject: plan.subject.clone(),
                required_effects,
                forbidden_effects,
                required_boundaries,
                coverage: plan.coverage.clone(),
            })
        })
        .collect::<Result<Vec<_>, FactoryError>>()?;
    let fixture = FactAssertionFixture {
        schema: FACT_ASSERTION_FIXTURE_SCHEMA_V1.to_string(),
        cases,
    };
    fixture.validate().map_err(FactoryError::Validation)?;
    for (case_index, (plan, case)) in plans.iter().zip(&fixture.cases).enumerate() {
        evaluate_fact_case(plan, case, case_index).map_err(|detail| FactoryError::Fixture {
            name: "seed-assertions".to_string(),
            detail: format!("case {case_index}: {detail}"),
        })?;
    }
    pretty_model_json(&fixture)
}

fn is_generic_seed_operation(operation: &str) -> bool {
    matches!(operation, "process.exec" | "environment.read")
}

fn seed_effect_assertion(
    effect: &effinterp_proto::Effect,
) -> Result<RequiredEffectAssertion, FactoryError> {
    let resource = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact { .. },
        } => ResourcePredicate::Variant {
            variant: ResourceVariant::Artifact,
        },
        ResourceExpr::Concrete {
            identity: ResourceIdentity::HostSystem {},
        } => ResourcePredicate::Variant {
            variant: ResourceVariant::HostSystem,
        },
        resource => {
            let (projection, text) = if effect.realm.is_host() {
                (
                    Projection::Resource,
                    effinterp_matcher::render::rendered_resource(resource),
                )
            } else {
                (
                    Projection::RealmScoped,
                    effinterp_matcher::render::rendered_resource_in_realm(&effect.realm, resource),
                )
            };
            ResourcePredicate::Rendered {
                projection,
                text: TextPredicate::Equals(text),
            }
        }
    };
    let query = Query {
        schema_version: effinterp_matcher::SCHEMA_VERSION,
        assertion: Assertion::Effect {
            selector: Selector {
                operation: OperationMatch::Exact(effect.operation.0.clone()),
                resource,
                attributes: effect
                    .attributes
                    .iter()
                    .map(|(name, value)| AttributePredicate {
                        name: name.clone(),
                        test: AttributeTest::Equals(value.clone()),
                    })
                    .collect(),
                request_assurance: None,
                condition: None,
                modality: None,
                execution_assurance: None,
                realm: None,
            },
            closure: Some(Closure::DomainFullOrBoundaryFree {
                domain: effect.operation.domain().to_string(),
            }),
        },
    };
    Ok(RequiredEffectAssertion {
        query: serialized_matcher_query(query)?,
        modality: effect.modality,
    })
}

/// Seed one boundary, or `None` when the matcher would witness a different
/// boundary for it. Domain selectors are all-of and an omitted detail matches
/// any detail, so a detail-less boundary whose domains are a subset of a
/// sibling with the same reason cannot be selected on its own.
fn seed_boundary_assertion(
    plan: &Plan,
    evaluator: &Evaluator<'_>,
    boundary: &effinterp_proto::Boundary,
) -> Option<Result<RequiredBoundaryAssertion, FactoryError>> {
    let query = Query {
        schema_version: effinterp_matcher::SCHEMA_VERSION,
        assertion: Assertion::Boundary {
            reason: boundary.reason.as_str().to_string(),
            class: Some(boundary.class),
            domains: Some(BoundaryDomainsPredicate::AllOf(boundary.domains.clone())),
            detail: boundary.detail.clone().map(TextPredicate::Equals),
            provenance: (!boundary.provenance.is_empty())
                .then_some(BoundaryProvenancePredicate::Nonempty),
        },
    };
    let Outcome::Match(Witness::Boundary { boundary: witness }) = evaluator.evaluate(&query) else {
        return None;
    };
    let witness = plan.boundaries.get(witness.0 as usize)?;
    if witness.class != boundary.class || witness.domains != boundary.domains {
        return None;
    }
    Some(
        serialized_matcher_query(query).map(|query| RequiredBoundaryAssertion {
            query,
            class: boundary.class,
            domains: boundary.domains.clone(),
        }),
    )
}

fn seed_forbidden_effect_assertion(
    operation: &str,
) -> Result<SerializedMatcherQuery, FactoryError> {
    serialized_matcher_query(Query {
        schema_version: effinterp_matcher::SCHEMA_VERSION,
        assertion: Assertion::Effect {
            selector: Selector {
                operation: OperationMatch::Exact(operation.to_string()),
                resource: ResourcePredicate::Any,
                attributes: Vec::new(),
                request_assurance: None,
                condition: None,
                modality: None,
                execution_assurance: None,
                realm: None,
            },
            closure: Some(Closure::DomainFullOrBoundaryFree {
                domain: operation.split('.').next().unwrap_or(operation).to_string(),
            }),
        },
    })
}

fn serialized_matcher_query(query: Query) -> Result<SerializedMatcherQuery, FactoryError> {
    serde_json::to_value(query)
        .map(SerializedMatcherQuery)
        .map_err(|error| FactoryError::Json(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::seed_assertion_fixture_json;
    use crate::fixture_evidence::{projected_fixture_json, read_fact_assertion_fixture};
    use effinterp_engine::Engine;
    use effinterp_proto::Subject;

    fn document(path: &str) -> effinterp_model_schema::DeclarationDocument {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../effinterp-engine/models/v1/tranche")
            .join(path);
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    // Seed from plans analyzed now, so the tests outlive the migration of
    // the whole-plan fixtures they were first written against.
    fn projected_plans(argvs: &[&[&str]]) -> Vec<u8> {
        let engine = Engine::new().with_causality_detail(true);
        let plans = argvs
            .iter()
            .map(|argv| {
                let subject: Subject = serde_json::from_value(
                    serde_json::json!({"kind": "exec", "argv": argv, "cwd": "/work"}),
                )
                .unwrap();
                engine.analyze(&subject).unwrap()
            })
            .collect::<Vec<_>>();
        projected_fixture_json(&plans).unwrap().into_bytes()
    }

    #[test]
    fn seeding_a_small_fixture_keeps_semantics_and_drops_generic_copies() {
        let plans = projected_plans(&[
            &["ansible-playbook", "/work/site.yml"],
            &["ansible-playbook", "--bad-option"],
        ]);
        let seeded =
            seed_assertion_fixture_json(&plans, Some(&document("cloud/ansible-playbook.json")))
                .unwrap();
        let fixture = read_fact_assertion_fixture(seeded.as_bytes()).unwrap();

        assert_eq!(fixture.cases.len(), 2);
        assert_eq!(fixture.cases[0].required_effects.len(), 1);
        assert_eq!(fixture.cases[1].required_effects.len(), 0);
        assert_eq!(fixture.cases[1].required_boundaries.len(), 2);
        assert!(!seeded.contains("process.exec"));
        assert!(!seeded.contains("environment.read"));
        assert!(seeded.contains("filesystem.read"));
        assert!(seeded.contains("unrecognized_arguments"));
        assert!(seeded.contains("\"class\": \"unmodeled\""));
        assert!(seeded.contains("\"all_of\""));
        assert!(seeded.contains("\"provenance\": \"nonempty\""));
    }

    #[test]
    fn seeding_an_inert_case_uses_the_owner_fact_inventory_as_negatives() {
        let plans = projected_plans(&[&["which", "cargo"]]);
        let seeded =
            seed_assertion_fixture_json(&plans, Some(&document("cloud/ansible-playbook.json")))
                .unwrap();
        let fixture = read_fact_assertion_fixture(seeded.as_bytes()).unwrap();

        assert_eq!(fixture.cases.len(), 1);
        assert!(fixture.cases[0].required_effects.is_empty());
        assert!(fixture.cases[0].required_boundaries.is_empty());
        assert_eq!(fixture.cases[0].forbidden_effects.len(), 1);
        assert!(!seeded.contains("process.exec"));
        assert!(seeded.contains("filesystem.read"));
    }

    #[test]
    fn seeding_skips_a_boundary_the_matcher_would_witness_with_a_sibling() {
        // `bunx npm publish` has a detailed package-scripts boundary and a
        // detail-less one over a subset of its domains; the second cannot be
        // selected without also matching the first.
        let plans = projected_plans(&[&["bunx", "npm", "publish"]]);
        let seeded =
            seed_assertion_fixture_json(&plans, Some(&document("package-build-vcs/npx.json")))
                .unwrap();
        let fixture = read_fact_assertion_fixture(seeded.as_bytes()).unwrap();

        let package_scripts = fixture.cases[0]
            .required_boundaries
            .iter()
            .filter(|boundary| {
                boundary.query.0["assertion"]["boundary"]["reason"] == "package_scripts"
            })
            .collect::<Vec<_>>();
        assert_eq!(package_scripts.len(), 1);
        assert_eq!(package_scripts[0].domains.len(), 4);
    }
}
