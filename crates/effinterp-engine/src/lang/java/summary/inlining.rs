//! Inlines same-file Java summary effects while preserving effect slots.

use super::super::{JAVA_DOMAINS, MAX_SUMMARY_BOUNDARIES, MAX_SUMMARY_EFFECTS};
use super::JavaSummaryDraft;
use crate::SemanticValue;
use crate::control_flow::ControlFlow;
use crate::resource_transfer::TransferBinding;
use crate::summary::{bind_positional, substitute_resource_expr};
use crate::value::unresolved_resource;
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, ResourceExpr,
    ResourceIdentity,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A method's full effects/boundaries with same-file callees inlined
/// (arguments substituted), memoized, cycle-guarded, and capped.
pub(super) fn inline_java_summary(
    key: &str,
    raws: &BTreeMap<String, JavaSummaryDraft>,
    memo: &mut HashMap<String, JavaInlinedSummary>,
    visiting: &mut HashSet<String>,
) -> JavaInlinedSummary {
    if let Some(hit) = memo.get(key) {
        return hit.clone();
    }
    if visiting.len() >= 64 || !crate::limits::summary_step() {
        return JavaInlinedSummary {
            control_flow: ControlFlow::widened(),
            boundaries: vec![Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                domains: JAVA_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: Vec::new(),
                limit: Some("max_java_summary_inlining".to_string()),
                detail: Some("Java summary inlining depth or work budget exhausted".to_string()),
                affected_resource: None,
                callee: None,
            }],
            ..Default::default()
        };
    }
    if !visiting.insert(key.to_string()) {
        return JavaInlinedSummary::default();
    }
    let Some(raw) = raws.get(key) else {
        visiting.remove(key);
        return JavaInlinedSummary::default();
    };
    let mut effects = raw.effects.clone();
    let mut control_flow = raw.control_flow.clone();
    let mut transfers = raw.transfers.clone();
    let mut boundaries = raw.boundaries.clone();
    for (callee, args, call) in &raw.locals {
        let inlined = inline_java_summary(callee, raws, memo, visiting);
        let requirements =
            inlined
                .control_flow
                .requirements(&mut |_| false, &mut |_| None, &mut |_, _| {
                    crate::limits::summary_step()
                });
        let (ce, cb) = (inlined.effects, inlined.boundaries);
        let params = raws
            .get(callee)
            .map(|r| r.params.clone())
            .unwrap_or_default();
        let bindings = bind_positional(&params, args);
        // Keep a separate slot for each call occurrence, including equal
        // resources, so transfer pairings and control facts stay aligned.
        let mut slots: Vec<Option<u32>> = Vec::with_capacity(ce.len());
        for e in ce {
            let refused = if effects.len() >= MAX_SUMMARY_EFFECTS {
                Some("max_java_summary_effects")
            } else {
                crate::limits::summary_charge(1).err()
            };
            if let Some(limit) = refused {
                control_flow = ControlFlow::widened();
                boundaries.push(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    domains: JAVA_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: Vec::new(),
                    limit: Some(limit.to_string()),
                    detail: Some("Java summary effect inlining truncated".to_string()),
                    affected_resource: None,
                    callee: None,
                });
                break;
            }
            let mut specialized = e.clone();
            specialized.resource = substitute_resource_expr(&e.resource, &bindings);
            // A caller-resolved env-var name substitutes in as a concrete
            // string; keep the environment identity.
            if specialized.operation.0.starts_with("environment.") {
                specialized.resource = match &specialized.resource {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if !path.is_empty() => ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name: path.clone() },
                    },
                    resource @ ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { .. },
                    } => resource.clone(),
                    _ => unresolved_resource("environment"),
                };
            }
            let value = SemanticValue::from(&specialized.resource);
            crate::lower_effect_value(&mut specialized, &value);
            effects.push(specialized);
            slots.push(Some(effects.len() as u32 - 1));
        }
        control_flow.inline_call(*call, &requirements, &slots);
        for binding in inlined.transfers {
            let (Some(Some(source)), Some(Some(destination))) = (
                slots.get(binding.source as usize),
                slots.get(binding.destination as usize),
            ) else {
                continue;
            };
            let binding = TransferBinding::new(*source, *destination);
            if source != destination && !transfers.contains(&binding) {
                transfers.push(binding);
            }
        }
        for b in cb {
            if boundaries.len() >= MAX_SUMMARY_BOUNDARIES {
                break;
            }
            if !boundaries
                .iter()
                .any(|x| x.reason == b.reason && x.detail == b.detail)
            {
                boundaries.push(b);
            }
        }
    }
    visiting.remove(key);
    let inlined = JavaInlinedSummary {
        control_flow,
        effects,
        transfers,
        boundaries,
    };
    memo.insert(key.to_string(), inlined.clone());
    inlined
}

/// One method's effects with same-file callees inlined, and the transfer
/// pairings that survived that inlining.
#[derive(Clone, Default)]
pub(super) struct JavaInlinedSummary {
    pub(super) control_flow: ControlFlow,
    pub(super) effects: Vec<Effect>,
    pub(super) transfers: Vec<TransferBinding>,
    pub(super) boundaries: Vec<Boundary>,
}
