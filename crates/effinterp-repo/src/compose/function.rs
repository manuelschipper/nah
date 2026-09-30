use super::budget::{all_domains, cap_depth, reserve_effect, widen};
use super::instance::{
    bind_constructor_results, bind_fn_args, bind_function_arguments, bound_callable, class_entry,
    function_parameter, instance_attrs, instance_values, parameter_allows_instance,
    resolve_instance, resolve_obj_args, resolve_runtime_value, resolved_object_value,
    returned_contract_instance, returned_instance,
};
use super::lifecycle::{module_binding_origin, rebase_lifecycle_origin};
use super::memo::{function_memo_key, memo_checkpoint, memoized_walk, replay_memoized_walk};
use super::{
    BoundCallable, BoundaryOccurrence, Composition, Dispatch, EffectOccurrence, Env, ResolvedCall,
    ResolvedDecorator, Walk, apply_external_resolution, dispatch_is_exhaustive,
    ensure_module_executed, follow, follow_dispatch, frontend_call_reference, is_constructor_fact,
    push_composed_boundary, push_composed_effect, push_composed_effect_slot, push_coverage,
    push_dependency, push_linker_boundary, push_specialized_process_effects, record_resolved_call,
    record_unresolved_call, replay_summary_transfers,
};
use crate::launch::is_process_template;
use crate::linker::Resolution;
use crate::module::{ModuleFile, Registry};
use effinterp_engine::{
    Assurance, CallEdge, CallableValue, ExternalCall, ResolvedObject, SemanticValue,
    SemanticValueKind, ValueArgument, scope_rust_branch_groups, substitute_value,
};
use effinterp_proto::{
    BoundaryReason, CalleeReference, PathPlatform, normalize_resource, resource_domain,
};
use std::collections::{BTreeMap, HashMap};

/// Descend into a resolved function: collect its specialized effects and follow
/// its call edges, binding any local functions this call passed as arguments
/// and typing its parameters from the call's instance-typed arguments. With
/// `inline_only` (a same-file method entered via dispatch) the effects are
/// already inlined into the caller's summary, so only the call edges are
/// walked. After the walk, locals the caller binds from this call's result are
/// typed via the callee's returned instances.
pub(super) fn enter_function(
    walk: &mut Walk<'_>,
    caller: &ModuleFile,
    target: &ModuleFile,
    fn_name: &str,
    edge: &CallEdge,
    dispatch: Dispatch,
    inline_only: bool,
) {
    enter_function_with_assurance(
        walk,
        caller,
        (target, fn_name),
        edge,
        dispatch,
        Assurance::Exact,
        inline_only,
    );
}

pub(super) fn enter_function_with_assurance(
    walk: &mut Walk<'_>,
    caller: &ModuleFile,
    destination: (&ModuleFile, &str),
    edge: &CallEdge,
    dispatch: Dispatch,
    assurance: Assurance,
    inline_only: bool,
) {
    let (target, fn_name) = destination;
    let previous = walk.assurance;
    walk.assurance = previous.max(assurance);
    walk.out.walk_assurance = walk.assurance;
    let required = walk.out.required;
    walk.out.required &= walk.assurance == Assurance::Exact;
    enter_function_inner(walk, caller, target, fn_name, edge, dispatch, inline_only);
    walk.out.required = required;
    walk.assurance = previous;
    walk.out.walk_assurance = previous;
}

// One active root owns its back-edges; nested activations are re-walked with it.
#[derive(Debug, Clone, Default)]
pub(super) struct RecursiveGroup {
    occurrence_start: usize,
    bindings: HashMap<String, SemanticValue>,
    effects: HashMap<super::EffectOccurrenceKey, EffectOccurrence>,
    back_edge_path: Option<Vec<String>>,
}

fn enter_function_inner(
    walk: &mut Walk<'_>,
    caller: &ModuleFile,
    target: &ModuleFile,
    fn_name: &str,
    edge: &CallEdge,
    dispatch: Dispatch,
    inline_only: bool,
) {
    use super::budget::{charge_compose_step, check_composition_depth};
    use effinterp_engine::join_branches;
    use effinterp_proto::{Condition, CoverageLevel, Modality};
    use std::collections::BTreeSet;

    if walk.out.budget.saturated.is_some() {
        return;
    }
    // Execute the imported module before the function memo checkpoint so its
    // one-time top-level effects are not replayed on later function calls.
    ensure_module_executed(walk.registry, target, &walk.path, &mut walk.stack, walk.out);
    // Scoped imports stay unresolved until a composed call executes their module.
    // Record each caller's binding even when another caller already ran the top level.
    for binding in caller
        .summary
        .imports
        .iter()
        .chain(&caller.summary.scoped_imports)
    {
        if walk
            .registry
            .resolve_import(caller, binding)
            .is_some_and(|module| module.path == target.path)
        {
            walk.out.resolved_calls.push(ResolvedCall {
                source_file: caller.path.clone(),
                callee: CalleeReference {
                    module: binding.module.clone(),
                    symbol: "__module_init__".to_string(),
                },
            });
        }
    }
    let key = (target.path.clone(), fn_name.to_string());
    let Some(func) = target
        .function(fn_name)
        .or_else(|| target.function(&format!("{fn_name}.__init__")))
    else {
        enter_function_round(
            walk,
            caller,
            target,
            fn_name,
            edge,
            dispatch,
            inline_only,
            &HashMap::new(),
        );
        return;
    };
    walk.out.processed_functions.insert(key.clone());
    if func.is_async && !edge.awaited {
        widen(
            walk.out,
            &walk.path,
            BoundaryReason::UNPOLLED_ASYNC,
            &format!("{fn_name} in {} is not known to be polled", target.path),
        );
        // Some runtimes start async calls eagerly. Retain their possible effects,
        // but only an awaited call can carry the callee's necessity proof.
        if !target.summary.linkage.eager_async_calls {
            return;
        }
        walk.out.required = false;
    }
    let mut bindings = bind_function_arguments(func, &edge.arguments);
    if let Some(receiver) = &dispatch.receiver {
        for (name, value) in receiver.values.clone() {
            if !func.summary.params.contains(&name) {
                bindings.insert(name, value);
            }
        }
    }
    for (name, value) in walk
        .registry
        .linker(target.lang)
        .package_bindings(walk.registry, target)
    {
        bindings.entry(name).or_insert(value);
    }

    if walk.out.recursive_groups.contains_key(&key) && !walk.out.recursive_dispatch_exhaustive {
        return;
    }
    if let Some(group) = walk.out.recursive_groups.get_mut(&key) {
        group
            .back_edge_path
            .get_or_insert_with(|| walk.path.clone());
        for (name, value) in bindings {
            let joined = match group.bindings.get(&name) {
                Some(previous) => {
                    join_branches([previous.clone(), value], walk.registry.value_limits())
                }
                None => value,
            };
            group.bindings.insert(name, joined);
        }
        let occurrence_start = group.occurrence_start;
        let mut effects = group.effects.values().cloned().collect::<Vec<_>>();
        effects.sort_by_key(|effect| {
            (
                effect.source_file.clone(),
                super::effect_evidence_key(&effect.effect),
                format!("{:?}", effect.via_dispatch),
            )
        });
        let path = walk.path.clone();
        for mut effect in effects {
            effect.path = path.iter().cloned().chain(effect.path).collect();
            // The cache is a set of known facts, not another call site. A
            // concrete walk may already have emitted this recursive path.
            let effect_key = super::EffectOccurrenceKey {
                source_file: effect.source_file.clone(),
                effect: super::composed_effect_id(&effect.effect),
                via_dispatch: effect.via_dispatch.clone(),
            };
            if let Some(index) = walk.out.effect_positions.get(&effect_key.effect)
                && walk.out.occurrence_effects[occurrence_start..]
                    .iter()
                    .any(|occurrence| {
                        occurrence.effect == *index
                            && occurrence.path == effect.path
                            && occurrence.assurance == effect.assurance
                    })
            {
                continue;
            }
            if !check_composition_depth(walk.out, &effect.path[..effect.path.len() - 1]) {
                break;
            }
            push_composed_effect(walk.out, effect);
        }
        return;
    }
    let memo_eligible = edge.result_bindings().next().is_none()
        && func.summary.returns.is_none()
        && class_entry(target, fn_name).is_none()
        && func.calls.iter().all(|call| !call.lifecycle_registration);
    let memo_key = memo_eligible
        .then(|| function_memo_key(walk, target, fn_name, &bindings, &dispatch, inline_only));
    if let Some(memo) = memo_key
        .as_ref()
        .and_then(|key| walk.out.memo.get(key))
        .cloned()
    {
        replay_memoized_walk(walk.out, &walk.path, &memo);
        return;
    }
    let checkpoint = memo_checkpoint(walk.out);
    walk.out.recursive_groups.insert(
        key.clone(),
        RecursiveGroup {
            occurrence_start: checkpoint.occurrences,
            bindings,
            ..RecursiveGroup::default()
        },
    );
    let previous_recursive_round = walk.out.recursive_round;
    let mut converged = false;
    let mut round_checkpoint = checkpoint;
    for round in 0..walk.out.budget.limits.max_recursion_rounds.max(1) {
        if !charge_compose_step(walk.out, &walk.path) {
            break;
        }
        let before = walk.out.recursive_groups[&key].clone();
        if round <= 1 {
            walk.out.memo_boundaries.truncate(checkpoint.boundaries + 1);
            round_checkpoint = memo_checkpoint(walk.out);
        }
        let occurrence_start = walk.out.occurrence_effects.len();
        walk.out.recursive_round = previous_recursive_round || round > 0;
        let previous_path = walk.path.clone();
        if round > 0 {
            walk.path = before.back_edge_path.clone().unwrap();
            if !check_composition_depth(walk.out, &walk.path) {
                walk.path = previous_path;
                break;
            }
        }
        if round > 0 {
            walk.out
                .recursive_occurrences
                .push(super::RecursiveOccurrences::new(
                    &walk.out.occurrence_effects[checkpoint.occurrences..],
                ));
        }
        enter_function_round(
            walk,
            caller,
            target,
            fn_name,
            edge,
            dispatch.clone(),
            inline_only,
            &before.bindings,
        );
        if round > 0 {
            walk.out.recursive_occurrences.pop();
        }
        walk.path = previous_path;
        let group = walk.out.recursive_groups.get_mut(&key).unwrap();
        if walk.out.budget.saturated.is_some() {
            break;
        }
        if group.back_edge_path.is_none() {
            converged = true;
            break;
        }
        let mut growing_domains = BTreeSet::new();
        for occurrence in &walk.out.occurrence_effects[occurrence_start..] {
            let mut effect = occurrence.evidence(&walk.out.effects);
            effect.effect.modality = Modality::May;
            effect.effect.condition = Some(Condition::Widened);
            effect.effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
            effect.path = occurrence
                .path
                .strip_prefix(walk.path.as_slice())
                .unwrap_or(&occurrence.path)
                .to_vec();
            effect.assurance = occurrence.assurance;
            effect.via_dispatch = occurrence.via_dispatch.clone();
            let effect_key = super::EffectOccurrenceKey {
                source_file: effect.source_file.clone(),
                effect: super::composed_effect_id(&effect.effect),
                via_dispatch: effect.via_dispatch.clone(),
            };
            if let Some(previous) = group.effects.get_mut(&effect_key) {
                previous.assurance = previous.assurance.max(effect.assurance);
            } else {
                growing_domains.insert(effect.effect.operation.domain().to_string());
                group.effects.insert(effect_key, effect);
            }
        }
        if group.bindings == before.bindings && group.effects.len() == before.effects.len() {
            converged = true;
            break;
        }
        if round + 1 >= walk.out.budget.limits.max_recursion_rounds {
            walk.out.recursion_truncations += 1;
            let domains: Vec<_> = growing_domains.into_iter().collect();
            if domains.is_empty() {
                // Argument growth alone has no effect domain to mark partial.
                break;
            }
            for domain in &domains {
                push_coverage(walk.out, (domain.clone(), CoverageLevel::Partial));
            }
            push_composed_boundary(
                walk.out,
                BoundaryOccurrence {
                    class: effinterp_proto::BoundaryClass::Unmodeled,
                    reason: BoundaryReason::RECURSIVE_CALL,
                    detail: format!("cross-file recursion at {}:{fn_name}", target.path),
                    source_file: Some(target.path.clone()),
                    callee: None,
                    domains,
                    affected_resource: None,
                    limit: None,
                    path: walk.path.clone(),
                    via_dispatch: walk.out.walk_via_dispatch.clone(),
                },
            );
        }
    }
    walk.out.recursive_round = previous_recursive_round;
    let group = walk.out.recursive_groups.remove(&key).unwrap();
    if converged
        && !walk
            .out
            .recursive_groups
            .values()
            .any(|group| group.back_edge_path.is_some())
        && walk.out.recursion_truncations == checkpoint.recursion_truncations
        && walk.out.occurrences - checkpoint.total_occurrences
            == walk.out.occurrence_effects.len() - checkpoint.occurrences
        && let Some(memo_key) = memo_key
    {
        let memo = memoized_walk(walk.out, checkpoint, &walk.path);
        let widened_key = function_memo_key(
            walk,
            target,
            fn_name,
            &group.bindings,
            &dispatch,
            inline_only,
        );
        // Widened callers replay the retained May rounds, excluding the original
        // invocation's MustOnSuccess effects for its narrower arguments.
        let widened_memo = memoized_walk(walk.out, round_checkpoint, &walk.path);
        walk.out.memo.insert(widened_key, widened_memo);
        walk.out.memo.insert(memo_key, memo);
    }
    walk.out.memo_boundaries.truncate(checkpoint.boundaries);
}

#[allow(clippy::too_many_arguments)]
fn enter_function_round(
    walk: &mut Walk<'_>,
    caller: &ModuleFile,
    target: &ModuleFile,
    fn_name: &str,
    edge: &CallEdge,
    dispatch: Dispatch,
    inline_only: bool,
    recursive_bindings: &HashMap<String, SemanticValue>,
) {
    if walk.out.budget.saturated.is_some() {
        return;
    }
    let key = (target.path.clone(), fn_name.to_string());
    let Some(func) = target
        .function(fn_name)
        .or_else(|| target.function(&format!("{fn_name}.__init__")))
    else {
        // A constructor of a class whose `__init__` is inherited: resolve it
        // through the class's declared bases.
        if let Some(class) = class_entry(target, fn_name) {
            let has_implicit_init = class.bases.is_empty();
            let inst = ResolvedObject {
                file: target.path.clone(),
                class_name: fn_name.to_string(),
                attrs: HashMap::new(),
                values: BTreeMap::new(),
                origin: None,
                ty: None,
            };
            match walk
                .registry
                .linker(target.lang)
                .resolve_method(walk.registry, &inst, "__init__")
            {
                Resolution::Targets(targets) => {
                    if dispatch_is_exhaustive(&targets) {
                        record_resolved_call(walk.registry, caller, edge, walk.out);
                    } else {
                        record_unresolved_call(walk.registry, caller, edge, walk.out);
                    }
                    let resolved =
                        resolve_obj_args(walk.registry, caller, &walk.env, &edge.arguments, 0);
                    let self_attrs = instance_attrs(walk.registry, &inst, &resolved);
                    let required = super::alternatives(walk.out, &targets);
                    for (init_file, init_name, assurance) in targets {
                        enter_function_with_assurance(
                            walk,
                            caller,
                            (init_file, &init_name),
                            edge,
                            Dispatch {
                                receiver: Some(inst.clone()),
                                self_attrs: self_attrs.clone(),
                            },
                            assurance,
                            false,
                        );
                    }
                    walk.out.required = required;
                    bind_constructor_results(
                        walk.registry,
                        target,
                        fn_name,
                        edge,
                        &mut walk.env,
                        walk.out,
                    );
                    return;
                }
                Resolution::Boundary { reason, detail } => {
                    record_unresolved_call(walk.registry, caller, edge, walk.out);
                    push_linker_boundary(walk.out, &walk.path, reason, detail);
                    return;
                }
                Resolution::External { module, member } => {
                    apply_external_resolution(walk, caller, edge, &module, &member);
                    record_resolved_call(walk.registry, caller, edge, walk.out);
                    bind_constructor_results(
                        walk.registry,
                        target,
                        fn_name,
                        edge,
                        &mut walk.env,
                        walk.out,
                    );
                    return;
                }
                Resolution::Local | Resolution::Unknown => {}
            }
            if has_implicit_init {
                bind_constructor_results(
                    walk.registry,
                    target,
                    fn_name,
                    edge,
                    &mut walk.env,
                    walk.out,
                );
                return;
            }
        }
        match walk
            .registry
            .linker(target.lang)
            .resolve_callee(walk.registry, target, fn_name)
        {
            Resolution::Targets(targets) => {
                if dispatch_is_exhaustive(&targets) {
                    record_resolved_call(walk.registry, caller, edge, walk.out);
                } else {
                    record_unresolved_call(walk.registry, caller, edge, walk.out);
                }
                let required = super::alternatives(walk.out, &targets);
                for (definition, function, assurance) in targets {
                    if definition.path == target.path && function == fn_name {
                        continue;
                    }
                    enter_function_with_assurance(
                        walk,
                        caller,
                        (definition, &function),
                        edge,
                        dispatch.clone(),
                        assurance,
                        false,
                    );
                }
                walk.out.required = required;
                return;
            }
            Resolution::External { module, member } => {
                if apply_external_resolution(walk, caller, edge, &module, &member) {
                    record_resolved_call(walk.registry, caller, edge, walk.out);
                } else {
                    record_unresolved_call(walk.registry, caller, edge, walk.out);
                }
                return;
            }
            Resolution::Boundary { reason, detail } => {
                record_unresolved_call(walk.registry, caller, edge, walk.out);
                push_linker_boundary(walk.out, &walk.path, reason, detail);
                return;
            }
            Resolution::Local | Resolution::Unknown => {}
        }
        // Anonymous callable names are file-local: follow the initializer
        // from its declaration, not the package's import target file.
        if let Some(value) =
            walk.registry
                .linker(target.lang)
                .package_value(walk.registry, target, fn_name)
            && let Some((declaration, _)) =
                walk.registry
                    .linker(target.lang)
                    .rebound_callee(walk.registry, target, fn_name)
        {
            // A frontend-only model cannot account for an indirect external call.
            let frontend_only = match bound_callable(walk.registry, declaration, &value) {
                Some(BoundCallable::External { module, member }) => {
                    matches!(
                        walk.registry.linker(target.lang).classify_external(
                            walk.registry,
                            &module,
                            &member,
                            Some(edge.positional_values().len())
                        ),
                        Some(ExternalCall::Modeled)
                    ) && walk
                        .registry
                        .linker(target.lang)
                        .semantic_external_effects(&module, &member, &edge.positional_values())
                        .is_none()
                        && walk
                            .registry
                            .linker(target.lang)
                            .external_effects(&module, &member, &edge.resource_arguments())
                            .is_none()
                }
                _ => false,
            };
            if !frontend_only && follow_callable_value(walk, declaration, edge, &value) {
                if !matches!(value.kind, SemanticValueKind::Union(_)) {
                    record_resolved_call(walk.registry, caller, edge, walk.out);
                }
                return;
            }
        }
        push_composed_boundary(
            walk.out,
            BoundaryOccurrence {
                class: effinterp_proto::BoundaryClass::Unresolved,
                reason: BoundaryReason::UNRESOLVED_CALL,
                detail: format!("{fn_name} not found in {}", target.path),
                source_file: Some(caller.path.clone()),
                callee: frontend_call_reference(walk.registry, caller, edge)
                    .map(|call| call.callee),
                domains: all_domains(),
                affected_resource: None,
                limit: None,
                path: walk.path.to_vec(),
                via_dispatch: walk.out.walk_via_dispatch.clone(),
            },
        );
        record_unresolved_call(walk.registry, caller, edge, walk.out);
        return;
    };
    push_dependency(walk.out, target.path.clone());
    let mut next_path = walk.path.to_vec();
    next_path.push(format!("{}:{fn_name}", target.path));

    if !func.decorator_gate.is_empty() {
        let open = func
            .decorator_gate
            .iter()
            .all(|callee| decorator_gate_opens(walk.registry, target, callee, walk.out));
        let resolved: Vec<_> = func
            .decorator_gate
            .iter()
            .map(|callee| ResolvedDecorator {
                source_file: target.path.clone(),
                callee: callee.clone(),
                function: func.name.clone(),
            })
            .collect();
        if !open {
            for boundary in func.summary.boundaries.iter().filter(|boundary| {
                boundary.reason == BoundaryReason::UNRESOLVED_DECORATOR
                    && resolved.iter().any(|resolved| {
                        resolved.matches_boundary(
                            &target.path,
                            boundary.callee.as_ref(),
                            boundary.detail.as_deref(),
                        )
                    })
            }) {
                push_composed_boundary(
                    walk.out,
                    BoundaryOccurrence {
                        class: boundary.class,
                        reason: boundary.reason.clone(),
                        detail: boundary.detail.clone().unwrap_or_default(),
                        source_file: Some(target.path.clone()),
                        callee: boundary.callee.clone(),
                        domains: boundary
                            .domains
                            .iter()
                            .map(|domain| domain.0.clone())
                            .collect(),
                        affected_resource: None,
                        limit: None,
                        path: next_path.clone(),
                        via_dispatch: walk.out.walk_via_dispatch.clone(),
                    },
                );
            }
            return;
        }
        walk.out.resolved_decorators.extend(resolved);
    }
    let inline_only = inline_only && func.decorator_gate.is_empty();
    let required = walk.out.required;
    let accepts_throw = walk.out.accepts_throw;
    let requirements = if required {
        super::control_requirements(
            walk.registry,
            target,
            &super::ControlOwner::Function(func.name.clone()),
            walk.out,
            &next_path,
        )
    } else {
        effinterp_engine::Requirements::unknown()
    };

    let mut guarantees = requirements.on_success;
    if accepts_throw && requirements.throws {
        if !requirements.succeeds
            && !requirements.fails
            && !requirements.may_exit
            && !requirements.may_return
        {
            guarantees = requirements.on_throw;
        } else {
            guarantees.retain(|fact| requirements.on_throw.contains(fact));
        }
    }
    let bindings = recursive_bindings.clone();
    // Frontend summary iteration can repeat the same provenance fact.
    // Separate call sites retain different provenance or separate walks.
    let summary_effects = {
        let mut seen = std::collections::HashSet::new();
        func.summary
            .effects
            .iter()
            .enumerate()
            .filter(|(_, effect)| seen.insert(super::effect_evidence_key(effect)))
            .collect::<Vec<_>>()
    };
    // The entrypoint's plan already carries this callable's effects, so no row
    // is pushed for them. Their necessity still belongs to this walk: the plan
    // could not discharge the imports the repository resolved. Record every
    // occurrence, optional ones included, so the surface can tell a proven
    // occurrence from a look-alike it must not promote.
    if inline_only && walk.path.first() == Some(&target.path) && !walk.out.recursive_round {
        for (slot, effect) in summary_effects.iter().copied() {
            if !super::charge_compose_step(walk.out, &next_path) {
                break;
            }
            let mut proven = effect.clone();
            proven.modality =
                if guarantees.contains(&effinterp_engine::ControlFact::Effect(slot as u32)) {
                    effinterp_proto::Modality::MustOnSuccess
                } else {
                    effinterp_proto::Modality::May
                };
            let value = SemanticValue::from(&effect.resource);
            let value = substitute_value(&value, &bindings, walk.registry.value_limits());
            effinterp_engine::lower_effect_value(&mut proven, &value);
            proven.resource = normalize_resource(cap_depth(proven.resource), PathPlatform::Posix);
            walk.out.local_necessity.push(proven);
        }
    }
    if !inline_only {
        // Where each summary effect slot landed among the composed occurrences,
        // so the callable's own transfer pairings survive substitution.
        let mut summary_slots: Vec<Option<usize>> = vec![None; func.summary.effects.len()];
        for (slot, effect) in summary_effects.iter().copied() {
            if is_process_template(effect) {
                continue;
            }
            if !reserve_effect(walk.out, &next_path) {
                break;
            }
            let mut specialized = effect.clone();
            specialized.modality =
                if guarantees.contains(&effinterp_engine::ControlFact::Effect(slot as u32)) {
                    effinterp_proto::Modality::MustOnSuccess
                } else {
                    effinterp_proto::Modality::May
                };
            let value = SemanticValue::from(&effect.resource);
            let value = substitute_value(&value, &bindings, walk.registry.value_limits());
            effinterp_engine::lower_effect_value(&mut specialized, &value);
            specialized.resource =
                normalize_resource(cap_depth(specialized.resource), PathPlatform::Posix);
            let (_, occurrence) = push_composed_effect_slot(
                walk.out,
                EffectOccurrence {
                    effect: specialized,
                    source_file: target.path.clone(),
                    path: next_path.clone(),
                    assurance: walk.out.walk_assurance,
                    via_dispatch: walk.out.walk_via_dispatch.clone(),
                },
            );
            summary_slots[slot] = occurrence;
        }
        replay_summary_transfers(walk.out, &func.summary.transfers, &summary_slots);
        for boundary in &func.summary.boundaries {
            if boundary.reason == BoundaryReason::UNRESOLVED_DECORATOR
                && walk.out.resolved_decorators.iter().any(|resolved| {
                    resolved.matches_boundary(
                        &target.path,
                        boundary.callee.as_ref(),
                        boundary.detail.as_deref(),
                    )
                })
            {
                continue;
            }
            push_composed_boundary(
                walk.out,
                BoundaryOccurrence {
                    class: boundary.class,
                    reason: boundary.reason.clone(),
                    detail: if boundary.reason == BoundaryReason::CROSS_MODULE {
                        boundary
                            .affected_resource
                            .as_ref()
                            .map(|resource| {
                                let value = substitute_value(
                                    &SemanticValue::from(resource),
                                    &bindings,
                                    walk.registry.value_limits(),
                                );
                                format!(
                                    "{}; recovered path {}",
                                    boundary
                                        .detail
                                        .as_deref()
                                        .unwrap_or_default()
                                        .split("; recovered path ")
                                        .next()
                                        .unwrap_or_default(),
                                    effinterp_engine::python_plugin_path_pattern(
                                        &value.lower_resource()
                                    )
                                    .unwrap_or_else(|| {
                                        effinterp_proto::display_resource_with_scope(
                                            &value.lower_resource(),
                                        )
                                    })
                                )
                            })
                            .unwrap_or_else(|| boundary.detail.clone().unwrap_or_default())
                    } else {
                        boundary.detail.clone().unwrap_or_default()
                    },
                    source_file: Some(target.path.clone()),
                    callee: boundary.callee.clone(),
                    domains: boundary.domains.iter().map(|d| d.0.clone()).collect(),
                    affected_resource: boundary.affected_resource.as_ref().and_then(|resource| {
                        let value = SemanticValue::from(resource);
                        let value =
                            substitute_value(&value, &bindings, walk.registry.value_limits());
                        let lowered = value.lower_resource();
                        let domain = resource_domain(&lowered)?;
                        boundary
                            .domains
                            .iter()
                            .any(|declared| declared.0 == domain)
                            .then(|| {
                                normalize_resource(
                                    value.lower_resource_for_domain(domain),
                                    PathPlatform::Posix,
                                )
                            })
                    }),
                    limit: boundary.limit.clone(),
                    path: next_path.clone(),
                    via_dispatch: walk.out.walk_via_dispatch.clone(),
                },
            );
        }
        let claims: Vec<_> = func
            .summary
            .coverage
            .iter()
            .map(|(domain, level)| (domain.0.clone(), *level))
            .collect();
        for claim in &claims {
            push_coverage(walk.out, claim.clone());
        }
        walk.out.coverage_segments.push((next_path.clone(), claims));
    }

    // Object parameters use the same argument vector as all other values.
    let mut child_env = Env {
        receiver: dispatch.receiver,
        self_attrs: dispatch.self_attrs,
        params: HashMap::new(),
        vars: HashMap::new(),
        values: bindings.clone(),
    };
    for (name, index, val) in resolve_obj_args(walk.registry, caller, &walk.env, &edge.arguments, 0)
    {
        let param = function_parameter(func, name.as_deref(), index).map(str::to_string);
        let param_index = param.as_ref().and_then(|param| {
            func.summary
                .params
                .iter()
                .position(|candidate| candidate == param)
        });
        if let Some(p) = param
            && func.summary.params.contains(&p)
        {
            let allowed = param_index
                .and_then(|index| func.parameter_type_narrowing.get(index))
                .map(Vec::as_slice)
                .unwrap_or_default();
            if !allowed.is_empty()
                && parameter_allows_instance(walk.registry, target, allowed, &val) == Some(false)
            {
                push_composed_boundary(
                    walk.out,
                    BoundaryOccurrence {
                        class: effinterp_proto::BoundaryClass::Unmodeled,
                        reason: BoundaryReason::TYPE_NARROWING,
                        detail: format!(
                            "runtime receiver {} is outside {}'s finite type set {}",
                            val.class_name,
                            p,
                            allowed.join(" | ")
                        ),
                        source_file: None,
                        callee: None,
                        domains: all_domains(),
                        affected_resource: None,
                        limit: None,
                        path: next_path.clone(),
                        via_dispatch: walk.out.walk_via_dispatch.clone(),
                    },
                );
                continue;
            }
            child_env.params.insert(p, val);
        }
    }

    let child = bind_fn_args(walk, caller, target, func, edge);
    walk.stack.push(key);
    for (index, inner) in func.calls.iter().enumerate() {
        walk.out.required =
            required && guarantees.contains(&effinterp_engine::ControlFact::Call(index as u32));
        walk.out.accepts_throw =
            !guarantees.contains(&effinterp_engine::ControlFact::CallSuccess(index as u32));
        let mut inner_bindings = bindings.clone();
        inner_bindings.extend(child_env.values.clone());
        let inner_edge = CallEdge {
            condition: inner.condition.clone(),
            call_site: inner.call_site.clone(),
            callee: inner.callee.clone(),
            arguments: inner
                .arguments
                .iter()
                .map(|argument| ValueArgument {
                    name: argument.name.clone(),
                    index: argument.index,
                    value: match &argument.value.kind {
                        SemanticValueKind::Parameter(name) | SemanticValueKind::Symbol(name) => {
                            child_env
                                .params
                                .get(name)
                                .or_else(|| child_env.vars.get(name))
                                .map(resolved_object_value)
                                .unwrap_or_else(|| {
                                    substitute_value(
                                        &argument.value,
                                        &inner_bindings,
                                        walk.registry.value_limits(),
                                    )
                                })
                        }
                        _ => substitute_value(
                            &argument.value,
                            &inner_bindings,
                            walk.registry.value_limits(),
                        ),
                    },
                })
                .collect(),
            effects_propagated: inner.effects_propagated,
            external_inert: inner.external_inert.clone(),
            lifecycle_registration: inner.lifecycle_registration,
            dynamic_target: inner.dynamic_target,
            callee_span: inner.callee_span,
            awaited: inner.awaited,
            receiver: inner.receiver.clone(),
            results: inner
                .results
                .iter()
                .cloned()
                .map(|mut result| {
                    result.value = substitute_value(
                        &result.value,
                        &inner_bindings,
                        walk.registry.value_limits(),
                    );
                    result
                })
                .collect(),
            writes: inner.writes.clone(),
        };
        let previous_path = std::mem::replace(&mut walk.path, next_path.clone());
        std::mem::swap(&mut walk.env, &mut child_env);
        let previous_linker =
            std::mem::replace(&mut walk.linker, walk.registry.linker(target.lang));
        follow(walk, target, &inner_edge, &child);
        walk.linker = previous_linker;
        std::mem::swap(&mut walk.env, &mut child_env);
        walk.path = previous_path;
    }
    walk.out.required = required;
    walk.stack.pop();
    walk.out.accepts_throw = accepts_throw;

    let mut completed_bindings = bindings.clone();
    completed_bindings.extend(child_env.values.clone());
    if !inline_only {
        for (_, effect) in summary_effects
            .iter()
            .copied()
            .filter(|(_, effect)| is_process_template(effect))
        {
            push_specialized_process_effects(
                effect,
                &completed_bindings,
                target,
                &next_path,
                walk.out,
                walk.registry.value_limits(),
            );
        }
    }
    if let Some(returned) = &func.summary.returns {
        let returned = edge
            .results
            .iter()
            .find_map(|result| match &result.value.kind {
                SemanticValueKind::Symbol(symbol)
                    if symbol.starts_with("__effinterp_rust_call:") =>
                {
                    Some(scope_rust_branch_groups(returned, symbol))
                }
                _ => None,
            })
            .unwrap_or_else(|| returned.clone());
        let returned = walk.registry.linker(target.lang).declared_result_value(
            substitute_value(&returned, &completed_bindings, walk.registry.value_limits()),
            walk.registry.value_limits(),
        );
        for (_, binding) in edge.result_bindings() {
            walk.env
                .values
                .insert(binding.to_string(), returned.clone());
        }
    }

    // A returned local keeps the lifecycle facts collected for it inside the
    // callee, but uses this call's result Site so separate factory calls remain
    // distinct dispatchers.
    for (i, var) in edge.result_bindings() {
        if let Some(Some(binding)) = func.return_bindings.get(i)
            && let Some(mut value) = child_env.vars.get(binding).cloned()
            && let (Some(old), Some(new)) = (
                value.origin.clone(),
                module_binding_origin(caller, edge, i).or_else(|| edge.origin_for_result(i)),
            )
        {
            if value.values.is_empty() && !value.class_name.is_empty() {
                let class_name = &value.class_name;
                let constructors: Vec<_> = func
                    .calls
                    .iter()
                    .filter(|call| {
                        call.callee.rsplit('.').next() == Some(class_name.as_str())
                            && call.result_bindings().any(|(_, name)| name == binding)
                    })
                    .collect();
                if let [constructor] = constructors.as_slice() {
                    let arguments: Vec<_> = constructor
                        .arguments
                        .iter()
                        .map(|argument| ValueArgument {
                            name: argument.name.clone(),
                            index: argument.index,
                            value: substitute_value(
                                &argument.value,
                                &bindings,
                                walk.registry.value_limits(),
                            ),
                        })
                        .collect();
                    let resolved =
                        resolve_obj_args(walk.registry, target, &child_env, &arguments, 0);
                    value.attrs = instance_attrs(walk.registry, &value, &resolved);
                    value.values = instance_values(walk.registry, &value, &arguments, 0);
                }
            }
            rebase_lifecycle_origin(&mut walk.out.lifecycle, &old, &new);
            if let Some(Some(ty)) = func.return_types.get(i)
                && let Some(declared) = returned_contract_instance(walk.registry, ty)
            {
                value = declared;
            } else if value.class_name.is_empty()
                && let Some(Some(cls)) = func.returns_instances.get(i)
                && let Some(typed) = returned_instance(
                    walk.registry,
                    target,
                    cls,
                    func.return_types.get(i).and_then(Option::as_ref),
                )
            {
                value = typed;
            }
            value.origin = Some(new);
            if let Some(origin) = &value.origin {
                walk.out
                    .lifecycle
                    .objects
                    .insert(origin.clone(), value.clone());
            }
            walk.env.vars.insert(var.to_string(), value);
            continue;
        }

        // Directly constructed returns have no local binding to carry. Their
        // class still types the caller result at its frontend-assigned Site.
        if let Some(Some(cls)) = func.returns_instances.get(i)
            && let Some(mut v) = returned_instance(
                walk.registry,
                target,
                cls,
                func.return_types.get(i).and_then(Option::as_ref),
            )
        {
            let constructors: Vec<_> = func
                .calls
                .iter()
                .filter(|call| {
                    is_constructor_fact(call)
                        && call.callee.rsplit('.').next() == Some(cls.as_str())
                })
                .collect();
            if let [constructor] = constructors.as_slice() {
                let arguments: Vec<_> = constructor
                    .arguments
                    .iter()
                    .map(|argument| ValueArgument {
                        name: argument.name.clone(),
                        index: argument.index,
                        value: substitute_value(
                            &argument.value,
                            &bindings,
                            walk.registry.value_limits(),
                        ),
                    })
                    .collect();
                let resolved = resolve_obj_args(walk.registry, target, &child_env, &arguments, 0);
                v.attrs = instance_attrs(walk.registry, &v, &resolved);
                v.values = instance_values(walk.registry, &v, &arguments, 0);
            }
            v.origin = edge.origin_for_result(i);
            if let Some(origin) = &v.origin {
                walk.out.lifecycle.objects.insert(origin.clone(), v.clone());
            }
            walk.env.vars.insert(var.to_string(), v);
        }
    }
    if walk
        .registry
        .linker(target.lang)
        .resolve_returned_instance()
        && let Some(returned) = &func.summary.returns
    {
        let returned = substitute_value(returned, &bindings, walk.registry.value_limits());
        let returned = resolve_runtime_value(walk.registry, target, &child_env, &returned);
        for (index, name) in edge.result_bindings() {
            if index != 0 {
                continue;
            }
            let returned = returned.clone().with_origin(edge.origin_for_result(index));
            walk.env.values.insert(name.to_string(), returned.clone());
            if let Some(mut instance) =
                resolve_instance(walk.registry, target, &child_env, &returned, 0)
            {
                instance.origin = edge.origin_for_result(index);
                if let Some(origin) = &instance.origin {
                    walk.out
                        .lifecycle
                        .objects
                        .insert(origin.clone(), instance.clone());
                }
                walk.env.vars.insert(name.to_string(), instance);
            }
        }
    }
    if class_entry(target, fn_name).is_some() {
        bind_constructor_results(
            walk.registry,
            target,
            fn_name,
            edge,
            &mut walk.env,
            walk.out,
        );
    }
}

fn decorator_gate_opens(
    registry: &Registry,
    target: &ModuleFile,
    callee: &CalleeReference,
    out: &mut Composition,
) -> bool {
    if callee.module.is_empty() {
        return false;
    }
    let symbol = callee.symbol.strip_suffix("()").unwrap_or(&callee.symbol);
    let canonical = format!("{}.{}", callee.module, symbol);
    // Recover the written import alias; the linker owns ambiguity and re-exports.
    let written = target
        .summary
        .imports
        .iter()
        .chain(&target.summary.scoped_imports)
        .find_map(|binding| {
            let base = match &binding.imported {
                Some(imported) => format!(
                    "{}{}{}",
                    binding.module,
                    if binding.module.ends_with('.') {
                        ""
                    } else {
                        "."
                    },
                    imported
                ),
                None => binding.module.clone(),
            };
            if canonical == base {
                Some(binding.local.clone())
            } else {
                canonical
                    .strip_prefix(&format!("{base}."))
                    .map(|member| format!("{}.{}", binding.local, member))
            }
        });
    let Some(written) = written else {
        return false;
    };
    let Resolution::Targets(targets) = registry
        .linker(target.lang)
        .resolve_callee(registry, target, &written)
    else {
        return false;
    };
    for (file, _, _) in &targets {
        push_dependency(out, file.path.clone());
    }
    let [(file, name, Assurance::Exact)] = targets.as_slice() else {
        return false;
    };
    let required = if callee.symbol.ends_with("()") {
        effinterp_engine::DecoratorShape::IdentityFactory
    } else {
        effinterp_engine::DecoratorShape::Identity
    };
    file.function(name)
        .is_some_and(|function| function.decorator_shape == required)
}

/// A call that resolved to no repo function may still invoke the local
/// functions it was handed as arguments (argparse's
/// `set_defaults(func=_cmd_x)`, `asyncio.run(main)`, an `atexit.register`):
/// enter each argument that names an unambiguous function of the calling file,
/// so the registered callback's effects surface instead of vanishing behind
/// the callee's boundary. Anything not a caller-local function never enters.
pub(super) fn enter_fn_args(walk: &mut Walk<'_>, importer: &ModuleFile, edge: &CallEdge) {
    if edge.lifecycle_registration || walk.registry.linker(importer.lang).callbacks_escape() {
        return;
    }
    // The callee decides whether and how often a callback runs.
    let required = std::mem::replace(&mut walk.out.required, false);
    enter_callback_args(walk, importer, edge);
    walk.out.required = required;
}

fn enter_callback_args(walk: &mut Walk<'_>, importer: &ModuleFile, edge: &CallEdge) {
    // Direct callback passing (`asyncio.run(main)`, `atexit.register(f)`)
    // is invoked by the callee itself. Registrars are handled in follow_inner.
    for (_, callback) in edge.callback_arguments() {
        if importer.function(callback).is_some() {
            let cb_edge = CallEdge {
                callee: callback.to_string(),
                ..Default::default()
            };
            enter_function(
                walk,
                importer,
                importer,
                callback,
                &cb_edge,
                Dispatch::default(),
                false,
            );
            continue;
        }
        // A name imported from another file (`cli.action(init)` where `init`
        // is `import { init } from './commands'`): enter that function.
        let Resolution::Targets(targets) =
            walk.registry
                .linker(importer.lang)
                .resolve_callee(walk.registry, importer, callback)
        else {
            continue;
        };
        for (target, function, assurance) in targets {
            if target.function(&function).is_none() {
                continue;
            }
            let cb_edge = CallEdge {
                callee: function.clone(),
                ..Default::default()
            };
            enter_function_with_assurance(
                walk,
                importer,
                (target, &function),
                &cb_edge,
                Dispatch::default(),
                assurance,
                false,
            );
        }
    }
}

pub(super) fn follow_callable_value(
    walk: &mut Walk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    value: &SemanticValue,
) -> bool {
    if matches!(value.kind, SemanticValueKind::Union(_)) {
        record_unresolved_call(walk.registry, importer, edge, walk.out);
        push_composed_boundary(
            walk.out,
            BoundaryOccurrence {
                class: effinterp_proto::BoundaryClass::Unresolved,
                reason: BoundaryReason::DYNAMIC_DISPATCH,
                detail: format!("callable {} has multiple possible values", edge.callee),
                source_file: None,
                callee: None,
                domains: all_domains(),
                affected_resource: None,
                limit: None,
                path: walk.path.to_vec(),
                via_dispatch: walk.out.walk_via_dispatch.clone(),
            },
        );
        return true;
    }
    let method = match &value.kind {
        SemanticValueKind::Property { base, name } => Some((base.as_ref(), name.as_str())),
        SemanticValueKind::Callable(CallableValue::BoundMethod { receiver, method }) => {
            Some((receiver.as_ref(), method.as_str()))
        }
        _ => None,
    };
    if let Some((receiver, method)) = method {
        let mut method_edge = edge.clone();
        method_edge.callee = format!("_.{method}");
        method_edge.effects_propagated = false;
        method_edge
            .arguments
            .retain(|argument| argument.name.as_deref() != Some("$callee"));
        return follow_dispatch(walk, importer, &method_edge, receiver, false);
    }
    match bound_callable(walk.registry, importer, value) {
        Some(BoundCallable::Function { file, function }) => {
            if let Some(target) = walk.registry.files.get(&file) {
                enter_function(
                    walk,
                    importer,
                    target,
                    &function,
                    edge,
                    Dispatch::default(),
                    false,
                );
                record_resolved_call(walk.registry, importer, edge, walk.out);
            }
            true
        }
        Some(BoundCallable::External { module, member }) => {
            if apply_external_resolution(walk, importer, edge, &module, &member) {
                record_resolved_call(walk.registry, importer, edge, walk.out);
            } else {
                record_unresolved_call(walk.registry, importer, edge, walk.out);
            }
            true
        }
        Some(BoundCallable::Class(instance)) => {
            let receiver = resolved_object_value(&instance);
            follow_dispatch(walk, importer, edge, &receiver, false);
            true
        }
        None => false,
    }
}
