//! Versioned evidence fixtures that pin reviewed facts instead of whole plans.
//!
//! Matcher queries express the semantic claims. The adjacent metadata records
//! protocol fields that a matching query does not itself make reviewable, and
//! coverage remains an exact per-case contract.

use effinterp_proto::{BoundaryClass, Coverage, Domain, Modality, Subject};
use serde::{Deserialize, Serialize};

/// Schema tag of a fact-assertion fixture document.
pub const FACT_ASSERTION_FIXTURE_SCHEMA_V1: &str = "effinterp/fact-assertion-fixture/v1";

/// A fact-assertion fixture: reviewed claims about its subjects' plans, pinned
/// instead of whole plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactAssertionFixture {
    pub schema: String,
    pub cases: Vec<FactAssertionCase>,
}

/// One subject's reviewed claims: effects that must and must not appear,
/// boundaries that must appear, and its exact coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactAssertionCase {
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_effects: Vec<RequiredEffectAssertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_effects: Vec<SerializedMatcherQuery>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_boundaries: Vec<RequiredBoundaryAssertion>,
    pub coverage: Coverage,
}

/// An effect a case's plan must contain, selected by a matcher query, with its
/// expected modality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredEffectAssertion {
    pub query: SerializedMatcherQuery,
    pub modality: Modality,
}

/// A boundary a case's plan must contain, selected by a matcher query, with its
/// expected class and domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredBoundaryAssertion {
    pub query: SerializedMatcherQuery,
    pub class: BoundaryClass,
    pub domains: Vec<Domain>,
}

/// The exact JSON representation of an `effinterp_matcher::Query`.
///
/// The schema crate deliberately keeps this serialized to preserve dependency
/// direction. The model factory deserializes and validates it with the shared
/// matcher before evaluating the fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializedMatcherQuery(pub serde_json::Value);

impl FactAssertionFixture {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FACT_ASSERTION_FIXTURE_SCHEMA_V1 {
            return Err(format!(
                "unsupported fact-assertion fixture schema {:?}",
                self.schema
            ));
        }
        if self.cases.is_empty() {
            return Err("fact-assertion fixture contains no cases".to_string());
        }
        for (case_index, case) in self.cases.iter().enumerate() {
            if case.required_effects.is_empty()
                && case.forbidden_effects.is_empty()
                && case.required_boundaries.is_empty()
            {
                return Err(format!("case {case_index} contains no assertions"));
            }
            if case
                .required_boundaries
                .iter()
                .any(|required| required.domains.is_empty())
            {
                return Err(format!(
                    "case {case_index} required boundary has no affected domains"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use effinterp_proto::{CoverageClaim, CoverageLevel, Domain, HostContext};
    use serde_json::json;

    use super::*;

    fn effect_query() -> SerializedMatcherQuery {
        SerializedMatcherQuery(json!({
            "schema_version": 2,
            "assertion": {
                "effect": {
                    "selector": {
                        "operation": {"exact": "filesystem.read"},
                        "resource": "any"
                    },
                    "closure": {"domain_full_or_boundary_free": {"domain": "filesystem"}}
                }
            }
        }))
    }

    fn fixture() -> FactAssertionFixture {
        FactAssertionFixture {
            schema: FACT_ASSERTION_FIXTURE_SCHEMA_V1.to_string(),
            cases: vec![FactAssertionCase {
                subject: Subject::Exec {
                    argv: vec!["cat".to_string(), "/tmp/input".to_string()],
                    cwd: None,
                    context: HostContext::default(),
                },
                required_effects: vec![RequiredEffectAssertion {
                    query: effect_query(),
                    modality: Modality::MustOnSuccess,
                }],
                forbidden_effects: vec![],
                required_boundaries: vec![],
                coverage: Coverage(BTreeMap::from([(
                    Domain::new("filesystem"),
                    CoverageClaim {
                        level: CoverageLevel::Full,
                        gaps: vec![],
                    },
                )])),
            }],
        }
    }

    #[test]
    fn fixture_requires_its_version_and_nonempty_cases() {
        fixture().validate().unwrap();

        let mut wrong_version = fixture();
        wrong_version.schema = "effinterp/fact-assertion-fixture/v2".to_string();
        assert!(wrong_version.validate().is_err());

        let mut empty = fixture();
        empty.cases.clear();
        assert!(empty.validate().is_err());
    }
}
