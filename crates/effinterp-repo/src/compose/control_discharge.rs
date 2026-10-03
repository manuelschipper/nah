//! Control discharge: what a file's retained control-flow graph guarantees
//! once unresolved import exits are discharged against the repository.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use effinterp_engine::{Assurance, Requirements};
use effinterp_proto::{BoundaryReason, CoverageLevel};

use super::accumulation::{push_composed_boundary, push_coverage};
use super::budget::charge_compose_step;
use super::{BoundaryOccurrence, Composition, module_receiver_targets};
use crate::linker::Resolution;
use crate::module::{ModuleFile, ModuleRegistry};

/// Which retained control-flow graph of a file owns an occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ControlOwner {
    Module,
    Main,
    Function(String),
}

/// Import chains deeper than this are not followed to discharge an import.
const MAX_DISCHARGE_DEPTH: usize = 8;

/// What a file's retained graph guarantees in this repository: an unresolved
/// import exit is discharged when the module it names resolves to a repo file
/// whose own top level always completes normally.
pub(super) fn control_requirements(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    owner: &ControlOwner,
    out: &mut Composition,
    path: &[String],
) -> Requirements {
    evaluate_control(registry, file, owner, out, path, &mut Vec::new())
}

fn evaluate_control(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    owner: &ControlOwner,
    out: &mut Composition,
    path: &[String],
    evaluating: &mut Vec<(String, ControlOwner)>,
) -> Requirements {
    let key = (file.path.clone(), owner.clone());
    if evaluating.contains(&key) || evaluating.len() >= MAX_DISCHARGE_DEPTH {
        return Requirements::unknown();
    }
    // A result cut short by an import cycle is only more conservative.
    if let Some(requirements) = out.control_requirements.get(&key) {
        return requirements.clone();
    }
    let flow = match owner {
        ControlOwner::Module => &file.summary.module_control_flow,
        ControlOwner::Main => &file.summary.main_control_flow,
        ControlOwner::Function(name) => match file.function(name) {
            Some(function) => &function.summary.control_flow,
            None => return Requirements::unknown(),
        },
    };
    if !charge_compose_step(out, path) {
        return Requirements::unknown();
    }
    let mut discharged = BTreeSet::new();
    let mut calls = BTreeMap::new();
    evaluating.push(key.clone());
    {
        for module in flow.imports() {
            let Some(target) = file
                .summary
                .imports
                .iter()
                .chain(&file.summary.scoped_imports)
                .filter(|binding| binding.module == module)
                .find_map(|binding| registry.resolve_import(file, binding))
            else {
                continue;
            };
            let imported = evaluate_control(
                registry,
                target,
                &ControlOwner::Module,
                out,
                path,
                evaluating,
            );
            if imported.succeeds && !imported.may_exit {
                discharged.insert(module.to_string());
            }
        }
    }
    let edges = match owner {
        ControlOwner::Module => &file.summary.module_calls,
        ControlOwner::Main => &file.summary.main_calls,
        ControlOwner::Function(name) => &file.function(name).unwrap().calls,
    };
    for slot in flow.unresolved_calls().collect::<BTreeSet<_>>() {
        if !charge_compose_step(out, path) {
            break;
        }
        let Some(edge) = edges.get(slot as usize) else {
            continue;
        };
        if edge.dynamic_target {
            continue;
        }
        let targets = if edge.receiver.is_some() {
            let Some(targets) = module_receiver_targets(registry, file, edge) else {
                continue;
            };
            targets
        } else {
            match registry
                .linker(file.lang)
                .resolve_callee(registry, file, &edge.callee)
            {
                Resolution::Local => vec![(file, edge.callee.clone(), Assurance::Exact)],
                Resolution::Targets(targets)
                    if !targets.is_empty()
                        && targets
                            .iter()
                            .all(|(_, _, assurance)| *assurance == Assurance::Exact) =>
                {
                    targets
                }
                _ => continue,
            }
        };
        let mut succeeds = false;
        let mut returns = false;
        let mut may_exit = false;
        let mut throws = false;
        let mut escaping = effinterp_engine::Exn::Unknown;
        let mut escaping_set = false;
        for (target, name, _) in targets {
            let Some(function) = target.function(&name) else {
                may_exit = true;
                throws = true;
                succeeds = true;
                returns = true;
                escaping = effinterp_engine::Exn::Unknown;
                escaping_set = true;
                continue;
            };
            if !function.decorator_gate.is_empty() || (function.is_async && !edge.awaited) {
                may_exit = true;
                throws = true;
                succeeds = true;
                returns = true;
                escaping = effinterp_engine::Exn::Unknown;
                escaping_set = true;
                continue;
            }
            let callee = evaluate_control(
                registry,
                target,
                &ControlOwner::Function(name),
                out,
                path,
                evaluating,
            );
            succeeds |= callee.succeeds;
            returns |= callee.succeeds || callee.may_return || callee.fails;
            may_exit |= callee.may_exit;
            if callee.throws {
                if throws && escaping_set {
                    escaping = escaping.join(callee.escaping);
                } else {
                    escaping = callee.escaping;
                    escaping_set = true;
                }
            }
            throws |= callee.throws;
        }
        calls.insert(
            slot,
            effinterp_engine::CallContract {
                returns,
                succeeds,
                may_exit,
                throws,
                escaping: if throws {
                    escaping
                } else {
                    effinterp_engine::Exn::Unknown
                },
            },
        );
    }
    evaluating.pop();
    let requirements = evaluate_flow(flow, &discharged, &calls, file, out, path);
    out.control_requirements.insert(key, requirements.clone());
    requirements
}

pub(super) fn evaluate_flow(
    flow: &effinterp_engine::ControlFlow,
    discharged: &BTreeSet<String>,
    calls: &BTreeMap<u32, effinterp_engine::CallContract>,
    file: &ModuleFile,
    out: &mut Composition,
    path: &[String],
) -> Requirements {
    // Necessity refines causal cardinality, so its fixpoint shares the causal
    // pair bound rather than the traversal budget effects need.
    let cap = effinterp_engine::AnalysisLimits::default().max_causal_pairs;
    let mut work = 0u64;
    let mut refused = false;
    let requirements = flow.requirements(
        &mut |module| discharged.contains(module),
        &mut |slot| calls.get(&slot).cloned(),
        &mut |steps, _| {
            if steps > cap - work {
                refused = true;
                return false;
            }
            work += steps;
            true
        },
    );
    if refused {
        push_composed_boundary(
            out,
            BoundaryOccurrence {
                class: effinterp_proto::BoundaryClass::Limit,
                reason: BoundaryReason::LIMIT_SATURATED,
                detail: "required-on-success reachability widened".to_string(),
                source_file: Some(file.path.clone()),
                callee: None,
                domains: vec!["dataflow".to_string()],
                affected_resource: None,
                limit: Some("max_causal_pairs".to_string()),
                path: path.to_vec(),
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
        push_coverage(out, ("dataflow".to_string(), CoverageLevel::Partial));
    }
    requirements
}
