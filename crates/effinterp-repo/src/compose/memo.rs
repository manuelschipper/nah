use super::budget::{check_composition_depth, reserve_effect};
use super::{
    Composition, Dispatch, Walk, push_coalesced_boundary, push_coverage, push_dependency,
    replay_summary_transfers,
};
use crate::dispatch::DispatchVia;
use crate::module::ModuleFile;
use effinterp_engine::{
    Assurance, CallableValue, ObjectIdentity, ResolvedObject, SemanticValue, SemanticValueKind,
    TransferBinding, TypeRef, ValueOrigin,
};
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct MemoKey {
    pub(super) target_path: String,
    pub(super) function: String,
    pub(super) dispatch: [u8; 32],
    pub(super) arguments: [u8; 32],
    pub(super) assurance: u8,
    pub(super) via_dispatch: Option<DispatchVia>,
    pub(super) inline_only: bool,
    pub(super) force_may: bool,
    required: bool,
    accepts_throw: bool,
    recursive_round: bool,
    condition_context: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct MemoizedWalk {
    pub(super) base_path: Vec<String>,
    pub(super) occurrences: std::ops::Range<usize>,
    /// Transfer pairings recorded inside the memoized range, as slots relative
    /// to `occurrences.start` so a replay can rebase them.
    pub(super) transfers: Vec<TransferBinding>,
    pub(super) boundaries: Vec<(super::ComposedBoundary, Vec<Vec<String>>)>,
    pub(super) resolved_calls: std::ops::Range<usize>,
    pub(super) unresolved_calls: std::ops::Range<usize>,
    pub(super) coverage: std::ops::Range<usize>,
    pub(super) deps: std::ops::Range<usize>,
}

#[derive(Clone, Copy)]
pub(super) struct MemoCheckpoint {
    pub(super) occurrences: usize,
    pub(super) total_occurrences: usize,
    pub(super) boundaries: usize,
    pub(super) resolved_calls: usize,
    pub(super) unresolved_calls: usize,
    pub(super) coverage: usize,
    pub(super) deps: usize,
    pub(super) recursion_truncations: u64,
}

fn memo_field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

fn memo_string(bytes: &mut Vec<u8>, value: &str) {
    memo_field(bytes, value.as_bytes());
}

fn memo_option_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    bytes.push(value.is_some() as u8);
    if let Some(value) = value {
        memo_string(bytes, value);
    }
}

fn memo_origin(bytes: &mut Vec<u8>, origin: &ValueOrigin) {
    match origin {
        ValueOrigin::Module { scope, name } => {
            bytes.push(0);
            match scope {
                effinterp_engine::ScopeKey::Module { key } => {
                    bytes.push(0);
                    memo_string(bytes, key);
                }
                effinterp_engine::ScopeKey::GoPackage { key } => {
                    bytes.push(1);
                    memo_string(bytes, key);
                }
                effinterp_engine::ScopeKey::RustModule { key } => {
                    bytes.push(2);
                    memo_string(bytes, key);
                }
            }
            memo_string(bytes, name);
        }
        ValueOrigin::Local {
            file,
            function,
            name,
        } => {
            bytes.push(1);
            memo_string(bytes, file);
            memo_string(bytes, function);
            memo_string(bytes, name);
        }
        ValueOrigin::Site {
            file,
            function,
            ordinal,
            result_index,
        } => {
            bytes.push(2);
            memo_string(bytes, file);
            memo_string(bytes, function);
            bytes.extend_from_slice(&ordinal.to_le_bytes());
            bytes.extend_from_slice(&(*result_index as u64).to_le_bytes());
        }
    }
}

fn memo_type(bytes: &mut Vec<u8>, ty: &TypeRef) {
    match ty {
        TypeRef::Repo { file, name } => {
            bytes.push(0);
            memo_string(bytes, file);
            memo_string(bytes, name);
        }
        TypeRef::External { path } => {
            bytes.push(1);
            memo_string(bytes, path);
        }
    }
}

fn memo_object_identity(bytes: &mut Vec<u8>, identity: &ObjectIdentity) {
    match identity {
        ObjectIdentity::Class { name, constructor } => {
            bytes.push(0);
            memo_string(bytes, name);
            bytes.extend_from_slice(&(constructor.len() as u64).to_le_bytes());
            for argument in constructor {
                memo_option_string(bytes, argument.name.as_deref());
                bytes.extend_from_slice(&(argument.index as u64).to_le_bytes());
                memo_value(bytes, &argument.value);
            }
        }
        ObjectIdentity::ModuleBinding { scope, name } => {
            bytes.push(1);
            memo_origin(
                bytes,
                &ValueOrigin::Module {
                    scope: scope.clone(),
                    name: name.clone(),
                },
            );
        }
        ObjectIdentity::DynamicClass => bytes.push(2),
        ObjectIdentity::Receiver => bytes.push(3),
        ObjectIdentity::ReceiverProperty(name) => {
            bytes.push(4);
            memo_string(bytes, name);
        }
        ObjectIdentity::Parameter { name, fallback } => {
            bytes.push(5);
            memo_string(bytes, name);
            memo_option_string(bytes, fallback.as_deref());
        }
        ObjectIdentity::Local { name, fallback } => {
            bytes.push(6);
            memo_string(bytes, name);
            memo_option_string(bytes, fallback.as_deref());
        }
        ObjectIdentity::LocalProperty { name, property } => {
            bytes.push(7);
            memo_string(bytes, name);
            memo_string(bytes, property);
        }
        ObjectIdentity::Resolved { file, class_name } => {
            bytes.push(8);
            memo_string(bytes, file);
            memo_string(bytes, class_name);
        }
    }
}

fn memo_resolved_object(bytes: &mut Vec<u8>, object: &ResolvedObject) {
    memo_string(bytes, &object.file);
    memo_string(bytes, &object.class_name);
    let mut attrs = object.attrs.iter().collect::<Vec<_>>();
    attrs.sort_by_key(|(name, _)| *name);
    bytes.extend_from_slice(&(attrs.len() as u64).to_le_bytes());
    for (name, value) in attrs {
        memo_string(bytes, name);
        memo_resolved_object(bytes, value);
    }
    bytes.extend_from_slice(&(object.values.len() as u64).to_le_bytes());
    for (name, value) in &object.values {
        memo_string(bytes, name);
        memo_value(bytes, value);
    }
    bytes.push(object.origin.is_some() as u8);
    if let Some(origin) = &object.origin {
        memo_origin(bytes, origin);
    }
    bytes.push(object.ty.is_some() as u8);
    if let Some(ty) = &object.ty {
        memo_type(bytes, ty);
    }
}

fn memo_value(bytes: &mut Vec<u8>, value: &SemanticValue) {
    match &value.kind {
        SemanticValueKind::Literal(value) => {
            bytes.push(0);
            memo_string(bytes, value);
        }
        SemanticValueKind::Symbol(value) => {
            bytes.push(1);
            memo_string(bytes, value);
        }
        SemanticValueKind::Parameter(value) => {
            bytes.push(2);
            memo_string(bytes, value);
        }
        SemanticValueKind::Union(values) => {
            bytes.push(3);
            bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
            for value in values {
                memo_value(bytes, value);
            }
        }
        SemanticValueKind::Unresolved { family, widened_by } => {
            bytes.push(4);
            memo_string(bytes, family);
            bytes.push(match widened_by {
                None => 0,
                Some(effinterp_engine::WidenReason::Depth) => 1,
                Some(effinterp_engine::WidenReason::Cardinality) => 2,
            });
        }
        SemanticValueKind::Path { parts, source } => {
            bytes.push(5);
            bytes.extend_from_slice(&(parts.len() as u64).to_le_bytes());
            for part in parts {
                memo_value(bytes, part);
            }
            memo_option_string(bytes, source.as_deref());
        }
        SemanticValueKind::Endpoint {
            host,
            scheme,
            port,
            path,
        } => {
            bytes.push(6);
            memo_string(bytes, host);
            memo_option_string(bytes, scheme.as_deref());
            bytes.extend_from_slice(&port.unwrap_or_default().to_le_bytes());
            bytes.push(port.is_some() as u8);
            memo_option_string(bytes, path.as_deref());
        }
        SemanticValueKind::Executable(value) => {
            bytes.push(7);
            memo_string(bytes, value);
        }
        SemanticValueKind::Process {
            executable,
            path,
            argv,
            cwd,
        } => {
            bytes.push(8);
            memo_string(bytes, executable);
            memo_option_string(bytes, path.as_deref());
            bytes.extend_from_slice(&(argv.len() as u64).to_le_bytes());
            for value in argv {
                memo_value(bytes, value);
            }
            bytes.push(cwd.is_some() as u8);
            if let Some(cwd) = cwd {
                memo_value(bytes, cwd);
            }
        }
        SemanticValueKind::Cwd(value) => {
            bytes.push(9);
            memo_value(bytes, value);
        }
        SemanticValueKind::Environment(value) => {
            bytes.push(10);
            memo_string(bytes, value);
        }
        SemanticValueKind::Collection {
            elements,
            properties,
        } => {
            bytes.push(11);
            bytes.extend_from_slice(&(elements.len() as u64).to_le_bytes());
            for value in elements {
                memo_value(bytes, value);
            }
            bytes.extend_from_slice(&(properties.len() as u64).to_le_bytes());
            for (name, value) in properties {
                memo_string(bytes, name);
                memo_value(bytes, value);
            }
        }
        SemanticValueKind::Property { base, name } => {
            bytes.push(12);
            memo_value(bytes, base);
            memo_string(bytes, name);
        }
        SemanticValueKind::Object(object) => {
            bytes.push(13);
            memo_object_identity(bytes, &object.identity);
            bytes.extend_from_slice(&(object.properties.len() as u64).to_le_bytes());
            for (name, value) in &object.properties {
                memo_string(bytes, name);
                memo_value(bytes, value);
            }
        }
        SemanticValueKind::Callable(callable) => {
            bytes.push(14);
            match callable {
                CallableValue::Function { name } => {
                    bytes.push(0);
                    memo_string(bytes, name);
                }
                CallableValue::Closure { name, captures } => {
                    bytes.push(1);
                    memo_string(bytes, name);
                    bytes.extend_from_slice(&(captures.len() as u64).to_le_bytes());
                    for (name, value) in captures {
                        memo_string(bytes, name);
                        memo_value(bytes, value);
                    }
                }
                CallableValue::BoundMethod { receiver, method } => {
                    bytes.push(2);
                    memo_value(bytes, receiver);
                    memo_string(bytes, method);
                }
            }
        }
        SemanticValueKind::Alias { name, value } => {
            bytes.push(15);
            memo_string(bytes, name);
            memo_value(bytes, value);
        }
        SemanticValueKind::Join(values) => {
            bytes.push(16);
            bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
            for value in values {
                memo_value(bytes, value);
            }
        }
        SemanticValueKind::Pattern { pattern } => {
            bytes.push(17);
            memo_string(bytes, &effinterp_proto::canonical_json(pattern));
        }
        SemanticValueKind::Resource(identity) => {
            bytes.push(18);
            memo_string(bytes, &effinterp_proto::canonical_json(identity));
        }
        SemanticValueKind::Exception(value) => {
            bytes.push(19);
            memo_value(bytes, value);
        }
    }
    bytes.push(value.evidence.origin.is_some() as u8);
    if let Some(origin) = &value.evidence.origin {
        memo_origin(bytes, origin);
    }
    bytes.push(value.evidence.ty.is_some() as u8);
    if let Some(ty) = &value.evidence.ty {
        memo_type(bytes, ty);
    }
    memo_string(
        bytes,
        &effinterp_proto::canonical_json(&value.evidence.realm),
    );
    memo_string(bytes, value.evidence.modality.as_str());
    bytes.extend_from_slice(&(value.evidence.cardinality.min as u64).to_le_bytes());
    bytes.push(value.evidence.cardinality.max.is_some() as u8);
    if let Some(max) = value.evidence.cardinality.max {
        bytes.extend_from_slice(&(max as u64).to_le_bytes());
    }
}

pub(super) fn function_memo_key(
    walk: &Walk<'_>,
    target: &ModuleFile,
    fn_name: &str,
    bindings: &HashMap<String, SemanticValue>,
    dispatch: &Dispatch,
    inline_only: bool,
) -> MemoKey {
    let mut arguments = Vec::new();
    let mut ordered_bindings = bindings.iter().collect::<Vec<_>>();
    ordered_bindings.sort_by_key(|(name, _)| *name);
    for (name, value) in ordered_bindings {
        memo_string(&mut arguments, name);
        memo_value(&mut arguments, value);
    }
    let mut dispatch_bytes = Vec::new();
    dispatch_bytes.push(dispatch.receiver.is_some() as u8);
    if let Some(receiver) = &dispatch.receiver {
        memo_resolved_object(&mut dispatch_bytes, receiver);
    }
    let mut self_attrs = dispatch.self_attrs.iter().collect::<Vec<_>>();
    self_attrs.sort_by_key(|(name, _)| *name);
    for (name, value) in self_attrs {
        memo_string(&mut dispatch_bytes, name);
        memo_resolved_object(&mut dispatch_bytes, value);
    }
    let assurance = match walk.assurance {
        Assurance::Exact => 0,
        Assurance::Alternatives => 1,
        Assurance::Heuristic => 2,
    };
    MemoKey {
        target_path: target.path.clone(),
        function: fn_name.to_string(),
        dispatch: *blake3::hash(&dispatch_bytes).as_bytes(),
        arguments: *blake3::hash(&arguments).as_bytes(),
        assurance,
        via_dispatch: walk.out.walk_via_dispatch.clone(),
        inline_only,
        force_may: walk.out.force_may,
        required: walk.out.required,
        accepts_throw: walk.out.required && walk.out.accepts_throw,
        recursive_round: walk.out.recursive_round,
        condition_context: if walk.out.walk_condition.is_some()
            || target.function(fn_name).is_some_and(|f| {
                f.summary.effects.iter().any(|e| e.condition.is_some())
                    || f.calls
                        .iter()
                        .any(|edge| edge.condition.is_some() || edge.callee != fn_name)
            }) {
            Some(effinterp_proto::stable_hash(
                "effinterp/condition-memo/v1",
                &(
                    &walk.out.walk_call_instance,
                    walk.out
                        .walk_condition
                        .as_ref()
                        .map(effinterp_proto::Condition::identity),
                ),
            ))
        } else {
            None
        },
    }
}

pub(super) fn memo_checkpoint(out: &mut Composition) -> MemoCheckpoint {
    let boundaries = out.memo_boundaries.len();
    out.memo_boundaries
        .push(super::BoundaryCollection::default());
    MemoCheckpoint {
        total_occurrences: out.occurrences,
        occurrences: out.occurrence_effects.len(),
        boundaries,
        resolved_calls: out.resolved_calls.len(),
        unresolved_calls: out.unresolved_calls.len(),
        coverage: out.coverage.len(),
        deps: out.deps.len(),
        recursion_truncations: out.recursion_truncations,
    }
}

pub(super) fn memoized_walk(
    out: &Composition,
    checkpoint: MemoCheckpoint,
    base_path: &[String],
) -> MemoizedWalk {
    MemoizedWalk {
        base_path: base_path.to_vec(),
        occurrences: checkpoint.occurrences..out.occurrence_effects.len(),
        transfers: memoized_transfers(out, checkpoint.occurrences),
        boundaries: out.memo_boundaries[checkpoint.boundaries]
            .rows
            .iter()
            .map(|boundary| {
                let paths = out.memo_boundaries[checkpoint.boundaries].paths
                    [&super::boundary_key(boundary)]
                    .iter()
                    .cloned()
                    .collect();
                (boundary.clone(), paths)
            })
            .collect(),
        resolved_calls: checkpoint.resolved_calls..out.resolved_calls.len(),
        unresolved_calls: checkpoint.unresolved_calls..out.unresolved_calls.len(),
        coverage: checkpoint.coverage..out.coverage.len(),
        deps: checkpoint.deps..out.deps.len(),
    }
}

/// Pairings whose two endpoints both fall inside the memoized occurrence
/// range. A pairing reaching outside the range belongs to the caller's walk,
/// not to this callable, so replaying it elsewhere would state a transfer that
/// was never modeled.
fn memoized_transfers(out: &Composition, start: usize) -> Vec<TransferBinding> {
    let start = start as u32;
    out.transfers
        .iter()
        .filter(|binding| binding.source >= start && binding.destination >= start)
        .map(|binding| TransferBinding::new(binding.source - start, binding.destination - start))
        .collect()
}

fn rebase_memo_path(path: &[String], old_base: &[String], new_base: &[String]) -> Vec<String> {
    path.strip_prefix(old_base)
        .map(|suffix| {
            new_base
                .iter()
                .cloned()
                .chain(suffix.iter().cloned())
                .collect()
        })
        .unwrap_or_else(|| path.to_vec())
}

fn rebase_memo_dispatch(
    dispatch: &mut Option<DispatchVia>,
    old_base: &[String],
    new_base: &[String],
) {
    if let Some(dispatch) = dispatch {
        dispatch.registration_path =
            rebase_memo_path(&dispatch.registration_path, old_base, new_base);
        dispatch.dispatch_path = rebase_memo_path(&dispatch.dispatch_path, old_base, new_base);
    }
}

pub(super) fn replay_memoized_walk(out: &mut Composition, path: &[String], memo: &MemoizedWalk) {
    let effects = out.occurrence_effects[memo.occurrences.clone()]
        .iter()
        .map(|occurrence| occurrence.evidence(&out.effects))
        .collect::<Vec<_>>();
    let boundaries = memo.boundaries.clone();
    let resolved_calls = out.resolved_calls[memo.resolved_calls.clone()].to_vec();
    let unresolved_calls = out.unresolved_calls[memo.unresolved_calls.clone()].to_vec();
    let coverage = out.coverage[memo.coverage.clone()].to_vec();
    let deps = out.deps[memo.deps.clone()].to_vec();
    let mut slots: Vec<Option<usize>> = Vec::with_capacity(effects.len());
    let mut exhausted = false;
    for mut effect in effects {
        if !reserve_effect(out, path) {
            exhausted = true;
            break;
        }
        effect.path = rebase_memo_path(&effect.path, &memo.base_path, path);
        if !check_composition_depth(out, &effect.path[..effect.path.len() - 1]) {
            exhausted = true;
            break;
        }
        rebase_memo_dispatch(&mut effect.via_dispatch, &memo.base_path, path);
        let before = out.occurrence_effects.len();
        super::push_bound_composed_effect(out, effect);
        slots.push((out.occurrence_effects.len() > before).then_some(before));
    }
    replay_summary_transfers(out, &memo.transfers, &slots);
    if exhausted {
        return;
    }
    for (mut boundary, mut paths) in boundaries {
        for evidence in &mut paths {
            *evidence = rebase_memo_path(evidence, &memo.base_path, path);
        }
        rebase_memo_dispatch(&mut boundary.via_dispatch, &memo.base_path, path);
        push_coalesced_boundary(out, boundary, &paths);
    }
    out.resolved_calls.extend(resolved_calls);
    out.unresolved_calls.extend(unresolved_calls);
    for item in coverage {
        push_coverage(out, item);
    }
    for dependency in deps {
        push_dependency(out, dependency);
    }
}
