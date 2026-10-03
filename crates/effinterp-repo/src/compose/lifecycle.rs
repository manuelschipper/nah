use super::accumulation::push_composed_boundary;
use super::budget::all_domains;
use super::function::enter_function_with_assurance;
use super::instance::{
    MAX_INSTANCE_DEPTH, callback_target, class_entry, imports_function, imports_type, instance_at,
    instance_attrs, receiver_matches_type, resolve_exact_class, type_ref_name, value_from_ref,
};
use super::{
    BoundaryOccurrence, Composition, Dispatch, Env, Walk, is_constructor_fact, push_linker_boundary,
};
use crate::dispatch::DispatchVia;
use crate::linker::Resolution;
use crate::module::{ModuleFile, ModuleRegistry};
use effinterp_engine::{
    Assurance, CallEdge, FrameworkLifecycle, LIFECYCLE_CATALOG, LifecycleSig, ObjectIdentity,
    ResolvedObject, SigEvidence, SigRole, TypeRef, ValueOrigin,
};
use effinterp_proto::BoundaryReason;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

const MAX_DISPATCH_ROUNDS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingId {
    pub(super) dispatcher: ValueOrigin,
    pub(super) registration_site: ValueOrigin,
    pub(super) registration_path: Vec<String>,
    pub(super) callback_file: String,
    pub(super) callback_function: String,
}

#[derive(Debug, Clone)]
struct Pending {
    pub(super) id: PendingId,
    pub(super) file: String,
    pub(super) function: String,
    pub(super) dispatch: Dispatch,
    pub(super) registration_path: Vec<String>,
    pub(super) model: &'static str,
    pub(super) assurance: Assurance,
    pub(super) may_dispatch: bool,
}

#[derive(Debug, Clone)]
struct Attachment {
    pub(super) child: ValueOrigin,
    pub(super) assurance: Assurance,
}

#[derive(Debug, Clone)]
struct DispatchEvent {
    pub(super) origin: ValueOrigin,
    pub(super) path: Vec<String>,
    pub(super) model: &'static str,
    pub(super) assurance: Assurance,
}

#[derive(Debug, Clone, Default)]
pub(super) struct LifecycleState {
    registered: HashMap<ValueOrigin, Vec<Pending>>,
    attached: HashMap<ValueOrigin, Vec<Attachment>>,
    dispatched: Vec<DispatchEvent>,
    activated: HashSet<PendingId>,
    pub(super) types: HashMap<ValueOrigin, TypeRef>,
    pub(super) objects: HashMap<ValueOrigin, ResolvedObject>,
}

pub(super) fn rebase_lifecycle_origin(
    state: &mut LifecycleState,
    old: &ValueOrigin,
    new: &ValueOrigin,
) {
    if old == new {
        return;
    }

    if let Some(mut pending) = state.registered.remove(old) {
        for item in &mut pending {
            item.id.dispatcher = new.clone();
        }
        let target = state.registered.entry(new.clone()).or_default();
        for item in pending {
            if let Some(existing) = target.iter_mut().find(|existing| existing.id == item.id) {
                existing.assurance = existing.assurance.max(item.assurance);
            } else {
                target.push(item);
            }
        }
    }

    if let Some(attachments) = state.attached.remove(old) {
        let target = state.attached.entry(new.clone()).or_default();
        for attachment in attachments {
            if let Some(existing) = target
                .iter_mut()
                .find(|existing| existing.child == attachment.child)
            {
                existing.assurance = existing.assurance.max(attachment.assurance);
            } else {
                target.push(attachment);
            }
        }
    }
    for attachments in state.attached.values_mut() {
        for attachment in attachments {
            if attachment.child == *old {
                attachment.child = new.clone();
            }
        }
    }
    for event in &mut state.dispatched {
        if event.origin == *old {
            event.origin = new.clone();
        }
    }
    state.activated = state
        .activated
        .drain()
        .map(|mut id| {
            if id.dispatcher == *old {
                id.dispatcher = new.clone();
            }
            id
        })
        .collect();
    if let Some(ty) = state.types.remove(old) {
        state.types.insert(new.clone(), ty);
    }
    if let Some(mut object) = state.objects.remove(old) {
        object.origin = Some(new.clone());
        state.objects.insert(new.clone(), object);
    }
}

#[derive(Clone, Copy)]
pub(super) struct LifecycleMatch {
    pub(super) model: &'static FrameworkLifecycle,
    pub(super) sig: &'static LifecycleSig,
    pub(super) assurance: Assurance,
}

pub(super) fn lifecycle_match(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
    receiver: Option<&ResolvedObject>,
    state: &LifecycleState,
) -> Option<LifecycleMatch> {
    let method = (!is_constructor_fact(edge))
        .then(|| edge.callee.rsplit('.').next().unwrap_or(&edge.callee));
    let ty = if method.is_none() {
        edge.result_type()
    } else {
        receiver.and_then(|value| {
            value.ty.as_ref().or_else(|| {
                value
                    .origin
                    .as_ref()
                    .and_then(|origin| state.types.get(origin))
            })
        })
    };
    let mut matches = Vec::new();
    for model in LIFECYCLE_CATALOG.iter() {
        if model.lang.is_some_and(|lang| lang != importer.lang) {
            continue;
        }
        for sig in model.sigs {
            if sig.method != method
                || sig
                    .max_args
                    .is_some_and(|max| edge.positional_values().len() > max)
            {
                continue;
            }
            let matched = match sig.evidence {
                SigEvidence::TypedReceiver => sig.receiver_type.is_some_and(|expected| {
                    ty.is_some_and(|actual| type_ref_name(actual) == expected)
                        || receiver.is_some_and(|value| {
                            receiver_matches_type(registry, value, expected, &mut HashSet::new())
                        })
                }),
                SigEvidence::NameAndImport => sig.receiver_type.is_some_and(|expected| {
                    imports_type(importer, expected)
                        || ty.is_some_and(|actual| type_ref_name(actual) == expected)
                }),
                SigEvidence::ExactImport => sig.import_path.is_some_and(|import_path| {
                    sig.method.is_some_and(|name| {
                        imports_function(importer, &edge.callee, import_path, name)
                    })
                }),
            };
            if matched {
                let assurance = match sig.evidence {
                    SigEvidence::TypedReceiver => Assurance::Exact,
                    SigEvidence::NameAndImport => Assurance::Heuristic,
                    SigEvidence::ExactImport => Assurance::Exact,
                };
                matches.push((evidence_rank(sig.evidence), model.id, model, sig, assurance));
            }
        }
    }
    matches.sort_by_key(|(rank, id, _, sig, _)| (*rank, *id, sig.role));
    matches
        .into_iter()
        .next()
        .map(|(_, _, model, sig, assurance)| LifecycleMatch {
            model,
            sig,
            assurance,
        })
}

fn evidence_rank(evidence: SigEvidence) -> u8 {
    match evidence {
        SigEvidence::TypedReceiver | SigEvidence::ExactImport => 0,
        SigEvidence::NameAndImport => 1,
    }
}

fn bind_edge_result(importer: &ModuleFile, edge: &CallEdge, env: &mut Env) {
    for (index, name) in edge.result_bindings() {
        if let Some(origin) = edge.origin_for_result(index) {
            env.vars.insert(
                name.to_string(),
                instance_at(importer, origin, edge.result_type().cloned()),
            );
        }
    }
}

pub(super) fn module_binding_origin(
    importer: &ModuleFile,
    edge: &CallEdge,
    result_index: usize,
) -> Option<ValueOrigin> {
    if !matches!(
        edge.origin_for_result(result_index),
        Some(ValueOrigin::Site { ref function, .. }) if function.is_empty()
    ) {
        return None;
    }
    let (_, name) = edge
        .result_bindings()
        .find(|(index, _)| *index == result_index)?;
    Some(ValueOrigin::Module {
        scope: importer.summary.linkage.scope.clone()?,
        name: name.to_string(),
    })
}

fn lifecycle_boundary(out: &mut Composition, path: &[String], detail: String) {
    push_composed_boundary(
        out,
        BoundaryOccurrence {
            class: effinterp_proto::BoundaryClass::Unresolved,
            reason: BoundaryReason::LIFECYCLE_UNBOUND,
            detail,
            source_file: None,
            callee: None,
            domains: all_domains(),
            affected_resource: None,
            limit: None,
            path: path.to_vec(),
            via_dispatch: out.walk_via_dispatch.clone(),
        },
    );
}

struct TaggedHook<'a> {
    pub(super) target: &'a ModuleFile,
    pub(super) function: String,
    pub(super) receiver: ResolvedObject,
    pub(super) registration_path: Vec<String>,
}

fn collect_tagged_hooks<'a>(
    registry: &'a ModuleRegistry,
    instance: &ResolvedObject,
    selectors: (&[&str], &[&str]),
    path: &[String],
    depth: usize,
    seen: &mut HashSet<(String, String)>,
    out: &mut Vec<TaggedHook<'a>>,
) {
    let (tags, hooks) = selectors;
    if depth >= MAX_INSTANCE_DEPTH {
        return;
    }
    let Some(file) = registry.files.get(&instance.file) else {
        return;
    };
    let Some(class) = class_entry(file, &instance.class_name).filter(|class| class.is_struct)
    else {
        return;
    };
    if !seen.insert((instance.file.clone(), instance.class_name.clone())) {
        return;
    }
    for field in &class.struct_fields {
        if !field.tags.iter().any(|tag| tags.contains(&tag.as_str())) {
            continue;
        }
        let Some(child) = resolve_exact_class(registry, file, &field.typ) else {
            continue;
        };
        let Some(child_file) = registry.files.get(&child.file) else {
            continue;
        };
        if !class_entry(child_file, &child.class_name).is_some_and(|class| class.is_struct) {
            continue;
        }
        let mut registration_path = path.to_vec();
        registration_path.push(format!("field:{}:{}.{}", file.path, class.name, field.name));
        for hook in hooks {
            let Resolution::Targets(targets) = registry
                .linker(file.lang)
                .resolve_method(registry, &child, hook)
            else {
                continue;
            };
            for (target, function, assurance) in targets {
                if assurance == Assurance::Exact {
                    out.push(TaggedHook {
                        target,
                        function,
                        receiver: child.clone(),
                        registration_path: registration_path.clone(),
                    });
                }
            }
        }
        collect_tagged_hooks(
            registry,
            &child,
            (tags, hooks),
            &registration_path,
            depth + 1,
            seen,
            out,
        );
    }
    seen.remove(&(instance.file.clone(), instance.class_name.clone()));
}

fn register_component(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
    path: &[String],
    out: &mut Composition,
    matched: LifecycleMatch,
    index: usize,
) -> bool {
    let Some(origin) = edge.origin_for_result(0) else {
        lifecycle_boundary(
            out,
            path,
            format!("{} component has no call Site", matched.model.id),
        );
        return true;
    };
    let argument = edge.arguments.iter().find(|arg| {
        arg.name.as_deref().map_or(arg.index == index, |name| {
            matched.sig.params.contains(&name)
        })
    });
    let mut targets = Vec::new();
    let mut alternatives = argument.is_none();
    if let Some(argument) = argument {
        match super::instance::bound_callable(registry, importer, &argument.value) {
            Some(super::BoundCallable::Function { file, function }) => {
                targets.push((file, function, Dispatch::default()))
            }
            Some(super::BoundCallable::Class(instance)) => {
                alternatives = true;
                if let Some(file) = registry.files.get(&instance.file) {
                    let prefix = format!("{}.", instance.class_name);
                    for function in &file.summary.functions {
                        if function
                            .name
                            .strip_prefix(&prefix)
                            .is_some_and(|method| !method.starts_with('_') && !method.contains('.'))
                        {
                            targets.push((
                                file.path.clone(),
                                function.name.clone(),
                                Dispatch {
                                    receiver: Some(instance.clone()),
                                    self_attrs: instance_attrs(registry, &instance, &[]),
                                },
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    } else {
        for value in importer.summary.module_values.values() {
            if let Some(effinterp_engine::CallableValue::Function { name }) = value.as_callable() {
                targets.push((importer.path.clone(), name.clone(), Dispatch::default()));
            }
        }
    }
    if argument.is_none() || targets.is_empty() {
        lifecycle_boundary(
            out,
            path,
            format!(
                "{} component dispatch: {} callable candidates",
                matched.model.id,
                targets.len()
            ),
        );
    }
    let assurance = out
        .walk_assurance
        .max(matched.assurance)
        .max(if alternatives {
            Assurance::Alternatives
        } else {
            Assurance::Exact
        });
    for (file, function, dispatch) in targets {
        let pending = Pending {
            id: PendingId {
                dispatcher: origin.clone(),
                registration_site: origin.clone(),
                registration_path: path.to_vec(),
                callback_file: file.clone(),
                callback_function: function.clone(),
            },
            file,
            function,
            dispatch,
            registration_path: path.to_vec(),
            model: matched.model.id,
            assurance,
            may_dispatch: alternatives,
        };
        let entries = out.lifecycle.registered.entry(origin.clone()).or_default();
        if !entries.iter().any(|existing| existing.id == pending.id) {
            entries.push(pending);
        }
    }
    if !out
        .lifecycle
        .dispatched
        .iter()
        .any(|event| event.origin == origin && event.path == path)
    {
        out.lifecycle.dispatched.push(DispatchEvent {
            origin,
            path: path.to_vec(),
            model: matched.model.id,
            assurance,
        });
    }
    true
}

pub(super) fn apply_lifecycle(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
    path: &[String],
    out: &mut Composition,
    env: &mut Env,
) -> bool {
    bind_edge_result(importer, edge, env);
    if is_constructor_fact(edge)
        && let Some(ty) = edge.result_type().cloned()
        && let Some(origin) =
            module_binding_origin(importer, edge, 0).or_else(|| edge.origin_for_result(0))
    {
        out.lifecycle.types.insert(origin, ty);
    }
    let mut receiver = edge
        .receiver
        .as_ref()
        .and_then(|value| value_from_ref(registry, importer, env, value));
    if let Some(value) = &mut receiver
        && let Some(origin) = &value.origin
        && let Some(carried) = out.lifecycle.objects.get(origin)
    {
        *value = carried.clone();
    }
    if let Some(value) = &receiver
        && let (Some(origin), Some(ty)) = (&value.origin, &value.ty)
    {
        out.lifecycle.types.insert(origin.clone(), ty.clone());
    }
    let Some(matched) =
        lifecycle_match(registry, importer, edge, receiver.as_ref(), &out.lifecycle)
    else {
        return false;
    };
    if let Some(result_type) = matched.sig.result_type
        && let Some(origin) = edge.origin_for_result(matched.sig.derive_result.unwrap_or(0))
    {
        let ty = TypeRef::External {
            path: result_type.to_string(),
        };
        out.lifecycle.types.insert(origin.clone(), ty.clone());
        for (index, name) in edge.result_bindings() {
            if index == matched.sig.derive_result.unwrap_or(0) {
                env.vars.insert(
                    name.to_string(),
                    instance_at(importer, origin.clone(), Some(ty.clone())),
                );
            }
        }
    }
    let assurance = out.walk_assurance.max(matched.assurance);
    let model = matched.model.id;
    if let Some(index) = matched.sig.component {
        return register_component(registry, importer, edge, path, out, matched, index);
    }
    match matched.sig.role {
        SigRole::Registers => {
            let Some(registration_site) = edge
                .origin_for_result(0)
                .filter(|origin| matches!(origin, ValueOrigin::Site { .. }))
            else {
                lifecycle_boundary(out, path, format!("{model} registration has no call Site"));
                return true;
            };
            let dispatcher = if matched.sig.import_path.is_some() {
                edge.origin_for_result(matched.sig.derive_result.unwrap_or(0))
            } else if matched.sig.method.is_none() {
                module_binding_origin(importer, edge, 0).or_else(|| edge.origin_for_result(0))
            } else {
                receiver.as_ref().and_then(|value| value.origin.clone())
            };
            let Some(dispatcher) = dispatcher else {
                lifecycle_boundary(
                    out,
                    path,
                    format!("{model} registration receiver has no origin"),
                );
                return true;
            };
            if !matched.sig.hooks.is_empty() && matched.sig.field_tags.is_empty() {
                let positional = edge.positional_values();
                let missing: Vec<_> = (0..positional.len())
                    .filter(|index| {
                        !edge
                            .object_arguments()
                            .any(|(argument, _)| argument.index == *index)
                    })
                    .collect();
                if !missing.is_empty() {
                    for index in missing {
                        lifecycle_boundary(
                            out,
                            path,
                            format!("{model} object argument {index} has no origin"),
                        );
                    }
                    return true;
                }
            }
            let mut pending = Vec::new();
            let positional_params = matched
                .sig
                .method
                .and_then(|method| {
                    let receiver = receiver.as_ref()?;
                    let Resolution::Targets(targets) = registry
                        .linker(importer.lang)
                        .resolve_method(registry, receiver, method)
                    else {
                        return None;
                    };
                    let [(target, function, _)] = targets.as_slice() else {
                        return None;
                    };
                    target
                        .function(function)
                        .map(|function| function.summary.params.clone())
                })
                .unwrap_or_default();
            for (argument, callback) in edge.callback_arguments() {
                let selected = if matched.sig.method.is_none() {
                    argument
                        .name
                        .as_deref()
                        .is_some_and(|name| matched.sig.fields.contains(&name))
                } else {
                    argument.name.as_deref().map_or_else(
                        || {
                            positional_params
                                .get(argument.index)
                                .is_some_and(|name| matched.sig.params.contains(&name.as_str()))
                        },
                        |name| matched.sig.params.contains(&name),
                    )
                };
                if !selected {
                    continue;
                }
                let Some((target, function)) = callback_target(registry, importer, callback) else {
                    continue;
                };
                let id = PendingId {
                    dispatcher: dispatcher.clone(),
                    registration_site: registration_site.clone(),
                    registration_path: path.to_vec(),
                    callback_file: target.path.clone(),
                    callback_function: function.clone(),
                };
                pending.push(Pending {
                    id,
                    file: target.path.clone(),
                    function,
                    dispatch: Dispatch::default(),
                    registration_path: path.to_vec(),
                    model,
                    assurance,
                    may_dispatch: false,
                });
            }
            let mut hook_pending = Vec::new();
            if !matched.sig.field_tags.is_empty() {
                let Some((argument, _)) = edge
                    .object_arguments()
                    .find(|(argument, _)| argument.index == 0)
                else {
                    lifecycle_boundary(
                        out,
                        path,
                        format!("{model} object argument 0 has no origin"),
                    );
                    return true;
                };
                let Some(root) = value_from_ref(registry, importer, env, &argument.value) else {
                    lifecycle_boundary(
                        out,
                        path,
                        format!("{model} object argument 0 has no origin"),
                    );
                    return true;
                };
                let mut hooks = Vec::new();
                collect_tagged_hooks(
                    registry,
                    &root,
                    (matched.sig.field_tags, matched.sig.hooks),
                    path,
                    0,
                    &mut HashSet::new(),
                    &mut hooks,
                );
                for hook in hooks {
                    let id = PendingId {
                        dispatcher: dispatcher.clone(),
                        registration_site: registration_site.clone(),
                        registration_path: hook.registration_path.clone(),
                        callback_file: hook.target.path.clone(),
                        callback_function: hook.function.clone(),
                    };
                    hook_pending.push(Pending {
                        id,
                        file: hook.target.path.clone(),
                        function: hook.function,
                        dispatch: Dispatch {
                            receiver: Some(hook.receiver.clone()),
                            self_attrs: instance_attrs(registry, &hook.receiver, &[]),
                        },
                        registration_path: hook.registration_path,
                        model,
                        assurance,
                        may_dispatch: true,
                    });
                }
            } else if !matched.sig.hooks.is_empty() {
                for (argument, _) in edge.object_arguments() {
                    let mut registration_path = path.to_vec();
                    registration_path.push(format!("argument:{}", argument.index));
                    let Some(instance) = value_from_ref(registry, importer, env, &argument.value)
                    else {
                        lifecycle_boundary(
                            out,
                            path,
                            format!("{model} object argument {} has no origin", argument.index),
                        );
                        continue;
                    };
                    let Some(origin) = instance.origin.clone() else {
                        lifecycle_boundary(
                            out,
                            path,
                            format!("{model} object argument {} has no origin", argument.index),
                        );
                        continue;
                    };
                    let mut resolved_hook = false;
                    for hook in matched.sig.hooks {
                        let Resolution::Targets(targets) = registry
                            .linker(importer.lang)
                            .resolve_method(registry, &instance, hook)
                        else {
                            continue;
                        };
                        resolved_hook = true;
                        for (target, function, target_assurance) in targets {
                            let id = PendingId {
                                dispatcher: dispatcher.clone(),
                                registration_site: registration_site.clone(),
                                registration_path: registration_path.clone(),
                                callback_file: target.path.clone(),
                                callback_function: function.clone(),
                            };
                            hook_pending.push(Pending {
                                id,
                                file: target.path.clone(),
                                function,
                                dispatch: Dispatch {
                                    receiver: Some(instance.clone()),
                                    self_attrs: instance.attrs.clone(),
                                },
                                registration_path: registration_path.clone(),
                                model,
                                assurance: assurance.max(target_assurance),
                                may_dispatch: false,
                            });
                        }
                        break;
                    }
                    if !resolved_hook {
                        lifecycle_boundary(
                            out,
                            &registration_path,
                            format!(
                                "{model} registered object has no resolvable {} hook",
                                matched.sig.hooks.join(" or ")
                            ),
                        );
                    }
                    let _ = origin;
                }
            }
            pending.extend(hook_pending);
            let entries = out.lifecycle.registered.entry(dispatcher).or_default();
            for item in pending {
                if let Some(existing) = entries.iter_mut().find(|existing| existing.id == item.id) {
                    existing.assurance = existing.assurance.max(item.assurance);
                } else {
                    entries.push(item);
                }
            }
            true
        }
        SigRole::Attaches => {
            let Some(parent) = receiver.as_ref().and_then(|value| value.origin.clone()) else {
                lifecycle_boundary(
                    out,
                    path,
                    format!("{model} attachment receiver has no origin"),
                );
                return false;
            };
            let positional = edge.positional_values();
            let missing: Vec<_> = (0..positional.len())
                .filter(|index| {
                    !edge
                        .object_arguments()
                        .any(|(argument, _)| argument.index == *index)
                })
                .collect();
            if !missing.is_empty() {
                for index in missing {
                    lifecycle_boundary(
                        out,
                        path,
                        format!("{model} object argument {index} has no origin"),
                    );
                }
                return false;
            }
            let mut children = Vec::new();
            for (argument, _) in edge.object_arguments() {
                let Some(child) = value_from_ref(registry, importer, env, &argument.value)
                    .and_then(|value| value.origin)
                else {
                    lifecycle_boundary(
                        out,
                        path,
                        format!("{model} object argument {} has no origin", argument.index),
                    );
                    return false;
                };
                children.push(child);
            }
            let entries = out.lifecycle.attached.entry(parent).or_default();
            for child in children {
                if let Some(existing) = entries.iter_mut().find(|entry| entry.child == child) {
                    existing.assurance = existing.assurance.max(assurance);
                } else {
                    entries.push(Attachment { child, assurance });
                }
            }
            false
        }
        SigRole::DerivesDispatcher => {
            let Some(parent) = receiver.as_ref().and_then(|value| value.origin.clone()) else {
                lifecycle_boundary(out, path, format!("{model} derive receiver has no origin"));
                return false;
            };
            let result_index = matched.sig.derive_result.unwrap_or(0);
            let Some(child) = edge.origin_for_result(result_index) else {
                lifecycle_boundary(out, path, format!("{model} derived result has no origin"));
                return false;
            };
            let ty = matched.sig.receiver_type.map(|path| TypeRef::External {
                path: path.to_string(),
            });
            for (index, name) in edge.result_bindings() {
                if index == result_index {
                    env.vars.insert(
                        name.to_string(),
                        instance_at(importer, child.clone(), ty.clone()),
                    );
                }
            }
            let entries = out.lifecycle.attached.entry(parent).or_default();
            if let Some(existing) = entries.iter_mut().find(|entry| entry.child == child) {
                existing.assurance = existing.assurance.max(assurance);
            } else {
                entries.push(Attachment { child, assurance });
            }
            false
        }
        SigRole::Dispatches => {
            let origin = receiver
                .as_ref()
                .and_then(|value| value.origin.clone())
                .or_else(|| {
                    matches!(edge.receiver_identity(), Some(ObjectIdentity::Class { .. }))
                        .then(|| env.receiver.as_ref().and_then(|value| value.origin.clone()))
                        .flatten()
                });
            let Some(origin) = origin else {
                lifecycle_boundary(
                    out,
                    path,
                    format!("{model} dispatch receiver has no origin"),
                );
                return false;
            };
            let event = DispatchEvent {
                origin,
                path: path.to_vec(),
                model,
                assurance,
            };
            if let Some(existing) = out.lifecycle.dispatched.iter_mut().find(|existing| {
                existing.origin == event.origin
                    && existing.path == event.path
                    && existing.model == event.model
            }) {
                existing.assurance = existing.assurance.max(event.assurance);
            } else {
                out.lifecycle.dispatched.push(event);
            }
            false
        }
    }
}

#[derive(Clone)]
struct Fired {
    pub(super) dispatch_path: Vec<String>,
    pub(super) assurance: Assurance,
}

fn fired_closure(state: &LifecycleState) -> HashMap<ValueOrigin, Fired> {
    let mut events = state.dispatched.clone();
    events.sort_by_key(|event| {
        (
            origin_key(&event.origin),
            event.path.clone(),
            event.model.to_string(),
        )
    });
    let mut fired = HashMap::new();
    let mut work = VecDeque::new();
    for event in events {
        if fired.contains_key(&event.origin) {
            continue;
        }
        fired.insert(
            event.origin.clone(),
            Fired {
                dispatch_path: event.path,
                assurance: event.assurance,
            },
        );
        work.push_back(event.origin);
    }
    while let Some(parent) = work.pop_front() {
        let Some(parent_fired) = fired.get(&parent).cloned() else {
            continue;
        };
        let mut attachments = state.attached.get(&parent).cloned().unwrap_or_default();
        attachments.sort_by_key(|attachment| origin_key(&attachment.child));
        for attachment in attachments {
            if fired.contains_key(&attachment.child) {
                continue;
            }
            let mut dispatch_path = parent_fired.dispatch_path.clone();
            dispatch_path.push(format!(
                "attach:{}->{}",
                origin_key(&parent),
                origin_key(&attachment.child)
            ));
            fired.insert(
                attachment.child.clone(),
                Fired {
                    dispatch_path,
                    assurance: parent_fired.assurance.max(attachment.assurance),
                },
            );
            work.push_back(attachment.child);
        }
    }
    fired
}

fn origin_key(origin: &ValueOrigin) -> String {
    format!("{origin:?}")
}

pub(super) fn activate_lifecycle(
    registry: &ModuleRegistry,
    stack: &mut Vec<(String, String)>,
    out: &mut Composition,
) {
    for _ in 0..MAX_DISPATCH_ROUNDS {
        let fired = fired_closure(&out.lifecycle);
        let mut todo: Vec<(Pending, Fired)> = Vec::new();
        for (origin, reached) in &fired {
            for pending in out.lifecycle.registered.get(origin).into_iter().flatten() {
                if !out.lifecycle.activated.contains(&pending.id) {
                    todo.push((pending.clone(), reached.clone()));
                }
            }
        }
        todo.sort_by_key(|(pending, _)| {
            (
                pending.file.clone(),
                pending.function.clone(),
                pending.registration_path.clone(),
                origin_key(&pending.id.dispatcher),
                origin_key(&pending.id.registration_site),
            )
        });
        if todo.is_empty() {
            return;
        }
        for (pending, fired) in todo {
            if !out.lifecycle.activated.insert(pending.id.clone()) {
                continue;
            }
            let Some(target) = registry.files.get(&pending.file) else {
                push_linker_boundary(
                    out,
                    &pending.registration_path,
                    BoundaryReason::CROSS_MODULE,
                    format!(
                        "registered callback {}:{} is unavailable",
                        pending.file, pending.function
                    ),
                );
                continue;
            };
            let via = DispatchVia {
                model: pending.model.to_string(),
                registration_path: pending.registration_path.clone(),
                dispatch_path: fired.dispatch_path.clone(),
            };
            let mut activation_path = pending.registration_path.clone();
            activation_path.push(format!(
                "dispatch:{}@{}",
                pending.model,
                origin_key(&pending.id.dispatcher)
            ));
            let previous_via = out.walk_via_dispatch.replace(via);
            let previous_force_may = out.force_may;
            out.force_may |= pending.may_dispatch;
            // A lifecycle framework decides when a registered hook runs.
            let previous_required = std::mem::replace(&mut out.required, false);
            let previous_condition = out.walk_condition.clone();
            if pending.may_dispatch {
                // This model knows selection is conditional but has no source predicate span.
                out.walk_condition = Some(effinterp_proto::Condition::Widened);
            }
            let edge = CallEdge {
                callee: pending.function.clone(),
                ..Default::default()
            };
            let mut env = Env::default();
            Walk::run(
                registry,
                target,
                out,
                (&activation_path, stack, &mut env),
                |walk| {
                    enter_function_with_assurance(
                        walk,
                        target,
                        (target, &pending.function),
                        &edge,
                        pending.dispatch,
                        pending.assurance.max(fired.assurance),
                        false,
                    )
                },
            );
            out.walk_condition = previous_condition;
            out.force_may = previous_force_may;
            out.required = previous_required;
            out.walk_via_dispatch = previous_via;
        }
    }

    let fired = fired_closure(&out.lifecycle);
    let mut remaining = Vec::new();
    for (origin, reached) in fired {
        for pending in out.lifecycle.registered.get(&origin).into_iter().flatten() {
            if !out.lifecycle.activated.contains(&pending.id) {
                remaining.push((pending.clone(), reached.clone()));
            }
        }
    }
    remaining.sort_by_key(|(pending, _)| {
        (
            pending.file.clone(),
            pending.function.clone(),
            pending.registration_path.clone(),
            origin_key(&pending.id.dispatcher),
            origin_key(&pending.id.registration_site),
        )
    });
    for (pending, reached) in remaining {
        push_composed_boundary(
            out,
            BoundaryOccurrence {
                class: effinterp_proto::BoundaryClass::Limit,
                reason: BoundaryReason::DISPATCH_ROUNDS_EXHAUSTED,
                detail: format!(
                    "{} callback {}:{} remains pending on {}",
                    pending.model,
                    pending.file,
                    pending.function,
                    origin_key(&pending.id.dispatcher)
                ),
                source_file: None,
                callee: None,
                domains: all_domains(),
                affected_resource: None,
                limit: None,
                path: reached.dispatch_path.clone(),
                via_dispatch: Some(DispatchVia {
                    model: pending.model.to_string(),
                    registration_path: pending.registration_path,
                    dispatch_path: reached.dispatch_path,
                }),
            },
        );
    }
}
