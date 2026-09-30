//! Reduce an effect plan to compact, comparable conclusions.

use std::collections::BTreeMap;

use effinterp_matcher::render::rendered_resource_in_realm;
use effinterp_proto::{CoverageLevel, Plan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// "operation target" lines, in plan order.
    pub effects: Vec<String>,
    /// "reason [domain, ...]" lines, in plan order.
    pub boundaries: Vec<String>,
    /// domain -> full/partial/none.
    pub coverage: BTreeMap<String, String>,
    /// Domain to positional boundary references, preserving the explaining evidence.
    pub gaps: BTreeMap<String, Vec<effinterp_proto::BoundaryRef>>,
}

impl Normalized {
    pub fn is_full(&self, domain: &str) -> bool {
        self.coverage
            .get(domain)
            .is_some_and(|level| level == "full")
    }

    /// A silent plan draws no conclusions at all: no effects, no boundaries.
    pub fn silent(&self) -> bool {
        self.effects.is_empty() && self.boundaries.is_empty()
    }
}

pub fn normalize_plan(plan: &Plan) -> Normalized {
    Normalized {
        effects: plan.effects.iter().map(effect).collect(),
        boundaries: plan
            .boundaries
            .iter()
            .map(|boundary| {
                let domains: Vec<&str> = boundary.domains.iter().map(|d| d.0.as_str()).collect();
                format!("{} [{}]", boundary.reason.as_str(), domains.join(", "))
            })
            .collect(),
        gaps: plan
            .coverage
            .0
            .iter()
            .map(|(domain, claim)| (domain.0.clone(), claim.gaps.clone()))
            .chain(std::iter::once((
                "dataflow".to_string(),
                plan.causality.coverage.gaps.clone(),
            )))
            .collect(),
        coverage: plan
            .coverage
            .0
            .iter()
            .map(|(domain, level)| {
                let level = match level.level {
                    CoverageLevel::Full => "full",
                    CoverageLevel::Partial => "partial",
                    CoverageLevel::None => "none",
                };
                (domain.0.clone(), level.to_string())
            })
            .collect(),
    }
}

pub(crate) fn effect(effect: &effinterp_proto::Effect) -> String {
    format!(
        "{} {}",
        effect.operation.0,
        rendered_resource_in_realm(&effect.realm, &effect.resource)
    )
}
