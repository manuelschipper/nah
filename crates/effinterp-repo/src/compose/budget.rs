use super::accumulation::{push_composed_boundary, push_coverage};
use super::{BoundaryOccurrence, Composition};
use crate::index::RepositoryLimits;
use effinterp_proto::{BoundaryReason, CoverageLevel, ResourceExpr, ResourceFamily};

const MAX_RESOURCE_DEPTH: usize = 24;

/// Deterministic repository composition budget and what one walk spent.
#[derive(Debug, Clone)]
pub struct ComposeBudget {
    pub limits: RepositoryLimits,
    pub steps: u64,
    pub saturated: Option<&'static str>,
    pub(super) reported_limits: std::collections::HashSet<&'static str>,
}

fn saturate(out: &mut Composition, path: &[String], limit: &'static str) {
    if out.budget.saturated.is_some() {
        return;
    }
    out.budget.saturated = Some(limit);
    report_limit(out, path, limit);
}

pub(super) fn report_limit(out: &mut Composition, path: &[String], limit: &'static str) {
    if !out.budget.reported_limits.insert(limit) {
        return;
    }
    push_composed_boundary(
        out,
        BoundaryOccurrence {
            class: effinterp_proto::BoundaryClass::Limit,
            reason: BoundaryReason::LIMIT_SATURATED,
            detail: format!("{limit} reached"),
            source_file: None,
            callee: None,
            domains: all_domains(),
            affected_resource: None,
            limit: Some(limit.to_string()),
            path: path.to_vec(),
            via_dispatch: out.walk_via_dispatch.clone(),
        },
    );
    for domain in all_domains() {
        push_coverage(out, (domain, CoverageLevel::Partial));
    }
}

pub(super) fn charge_compose_step(out: &mut Composition, path: &[String]) -> bool {
    if out.budget.saturated.is_some() {
        return false;
    }
    if out.budget.steps >= out.budget.limits.max_compose_steps {
        saturate(out, path, "repository.max_compose_steps");
        return false;
    }
    out.budget.steps += 1;
    true
}

pub(super) fn reserve_effect(out: &mut Composition, _path: &[String]) -> bool {
    out.budget.saturated.is_none()
}

pub(super) fn reserve_new_effect(out: &mut Composition, path: &[String]) -> bool {
    if out.budget.saturated.is_some() {
        return false;
    }
    if out.effects.len() >= out.budget.limits.max_composed_effects {
        saturate(out, path, "repository.max_composed_effects");
        return false;
    }
    true
}

pub(super) fn check_composition_depth(out: &mut Composition, path: &[String]) -> bool {
    if out.budget.saturated.is_some() {
        return false;
    }
    if path.len() >= out.budget.limits.max_composition_depth {
        saturate(out, path, "repository.max_composition_depth");
        return false;
    }
    true
}

pub(super) fn widen(out: &mut Composition, path: &[String], reason: BoundaryReason, detail: &str) {
    if !charge_compose_step(out, path) {
        return;
    }
    push_composed_boundary(
        out,
        BoundaryOccurrence {
            class: effinterp_proto::BoundaryClass::Unmodeled,
            reason,
            detail: detail.to_string(),
            source_file: None,
            callee: None,
            domains: all_domains(),
            affected_resource: None,
            limit: None,
            path: path.to_vec(),
            via_dispatch: out.walk_via_dispatch.clone(),
        },
    );
    for d in all_domains() {
        push_coverage(out, (d, CoverageLevel::Partial));
    }
}

/// A classification's domain set as owned strings for the composed boundary.
pub(super) fn owned_domains(domains: effinterp_engine::Domains) -> Vec<String> {
    domains.iter().map(|d| (*d).to_string()).collect()
}

pub(super) fn all_domains() -> Vec<String> {
    effinterp_proto::DOMAINS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Widen a resource expression deeper than the cap to an unresolved family, so
/// deep cross-file recursion cannot grow an unbounded Join/Union tree.
pub(crate) fn cap_depth(expr: ResourceExpr) -> ResourceExpr {
    fn go(expr: ResourceExpr, remaining: usize) -> ResourceExpr {
        if remaining == 0 {
            return ResourceExpr::Unresolved {
                family: ResourceFamily::new("unknown"),
            };
        }
        match expr {
            ResourceExpr::Property { base, name } => ResourceExpr::Property {
                base: Box::new(go(*base, remaining - 1)),
                name,
            },
            ResourceExpr::Join { parts } => ResourceExpr::Join {
                parts: parts.into_iter().map(|p| go(p, remaining - 1)).collect(),
            },
            ResourceExpr::Union { alternatives } => ResourceExpr::Union {
                alternatives: alternatives
                    .into_iter()
                    .map(|a| go(a, remaining - 1))
                    .collect(),
            },
            other => other,
        }
    }
    go(expr, MAX_RESOURCE_DEPTH)
}
