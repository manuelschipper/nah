use super::accumulation::push_dependency;
use super::{BoundCallable, Callbacks, Composition, Env, Walk, find_import};
use crate::linker::Resolution;
use crate::module::{ModuleFile, ModuleRegistry};
use effinterp_engine::{
    Assurance, CallEdge, CallableValue, ClassEntry, FunctionEntry, ObjectIdentity, ResolvedObject,
    SemanticValue, SemanticValueKind, TypeRef, ValueArgument, ValueOrigin, substitute_value,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Bound on nested constructor-argument typing when resolving instances.
pub(super) const MAX_INSTANCE_DEPTH: usize = 4;

pub(super) fn function_parameter<'a>(
    function: &'a FunctionEntry,
    name: Option<&str>,
    index: usize,
) -> Option<&'a str> {
    match name {
        Some(name) => function
            .summary
            .params
            .iter()
            .find(|param| param.as_str() == name)
            .map(String::as_str),
        None if function
            .positional_param_count
            .is_none_or(|count| index < count) =>
        {
            function.summary.params.get(index).map(String::as_str)
        }
        None => None,
    }
}

pub(super) fn bind_function_arguments(
    function: &FunctionEntry,
    arguments: &[ValueArgument],
) -> HashMap<String, SemanticValue> {
    arguments
        .iter()
        .filter_map(|argument| {
            function_parameter(function, argument.name.as_deref(), argument.index)
                .map(|param| (param.to_string(), argument.value.clone()))
        })
        .collect()
}

pub(super) fn class_entry<'a>(file: &'a ModuleFile, name: &str) -> Option<&'a ClassEntry> {
    file.summary.classes.iter().find(|c| c.name == name)
}

pub(super) fn resolve_exact_class(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
) -> Option<ResolvedObject> {
    registry
        .linker(file.lang)
        .class_candidates(registry, file, name)
        .into_iter()
        .find_map(|(instance, assurance)| (assurance == Assurance::Exact).then_some(instance))
}

pub(super) fn parameter_allows_instance(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    allowed: &[String],
    value: &ResolvedObject,
) -> Option<bool> {
    let candidates: Option<Vec<_>> = allowed
        .iter()
        .map(|name| resolve_exact_class(registry, file, name))
        .collect();
    Some(candidates?.iter().any(|candidate| {
        instance_is_class_or_subclass(registry, value, candidate, &mut HashSet::new())
    }))
}

fn instance_is_class_or_subclass(
    registry: &ModuleRegistry,
    value: &ResolvedObject,
    allowed: &ResolvedObject,
    seen: &mut HashSet<(String, String)>,
) -> bool {
    if value.file == allowed.file && value.class_name == allowed.class_name {
        return true;
    }
    if !seen.insert((value.file.clone(), value.class_name.clone())) {
        return false;
    }
    let Some(file) = registry.files.get(&value.file) else {
        return false;
    };
    let Some(class) = class_entry(file, &value.class_name) else {
        return false;
    };
    class.bases.iter().any(|base| {
        resolve_exact_class(registry, file, base)
            .is_some_and(|base| instance_is_class_or_subclass(registry, &base, allowed, seen))
    })
}

pub(super) fn returned_instance(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
    return_type: Option<&TypeRef>,
) -> Option<ResolvedObject> {
    resolve_exact_class(registry, file, name).or_else(|| {
        let ty = return_type?.clone();
        Some(ResolvedObject {
            file: file.path.clone(),
            class_name: name.to_string(),
            attrs: HashMap::new(),
            values: BTreeMap::new(),
            origin: None,
            ty: Some(ty),
        })
    })
}

pub(super) fn returned_contract_instance(
    registry: &ModuleRegistry,
    ty: &TypeRef,
) -> Option<ResolvedObject> {
    let TypeRef::Repo { file, name } = ty else {
        return None;
    };
    let definition = registry.files.get(file)?;
    definition
        .summary
        .dispatch_contracts
        .iter()
        .any(|contract| contract.name == *name)
        .then(|| ResolvedObject {
            file: file.clone(),
            class_name: name.clone(),
            attrs: HashMap::new(),
            values: BTreeMap::new(),
            origin: None,
            ty: Some(ty.clone()),
        })
}

/// Resolve an instance reference at a call site against the caller's context.
/// A constructor-typed reference also resolves its attribute classes (from the
/// constructor's instance-typed arguments), bounded by `depth`.
pub(super) fn resolve_instance(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    env: &Env,
    value: &SemanticValue,
    depth: usize,
) -> Option<ResolvedObject> {
    let object = value.as_object()?;
    match &object.identity {
        ObjectIdentity::Class { name, constructor } => {
            let mut inst = resolve_exact_class(registry, importer, name)?;
            inst.origin = value.evidence.origin.clone();
            inst.ty = value.evidence.ty.clone().or(inst.ty);
            if depth < MAX_INSTANCE_DEPTH {
                let resolved = resolve_obj_args(registry, importer, env, constructor, depth + 1);
                inst.attrs = instance_attrs(registry, &inst, &resolved);
                inst.values = instance_values(registry, &inst, constructor, depth + 1);
            }
            Some(inst)
        }
        // The carried type drives dispatch and the origin preserves lifecycle
        // identity. An external type keeps its full path as the class name so
        // it never collides with a same-named repo type in the importer's file.
        ObjectIdentity::ModuleBinding { scope, name } => {
            let exact = resolve_exact_class(registry, importer, name);
            let exact_untyped = exact.is_some() && value.evidence.ty.is_none();
            let mut instance = exact.unwrap_or_else(|| ResolvedObject {
                file: match &value.evidence.ty {
                    Some(effinterp_engine::TypeRef::Repo { file, .. }) => file.clone(),
                    _ => importer.path.clone(),
                },
                class_name: match &value.evidence.ty {
                    Some(effinterp_engine::TypeRef::Repo { name, .. }) => name.clone(),
                    Some(effinterp_engine::TypeRef::External { path }) => path.clone(),
                    None => String::new(),
                },
                attrs: HashMap::new(),
                values: BTreeMap::new(),
                origin: None,
                ty: value.evidence.ty.clone(),
            });
            instance.origin = Some(effinterp_engine::ValueOrigin::Module {
                scope: if exact_untyped {
                    effinterp_engine::ScopeKey::Module {
                        key: instance.file.clone(),
                    }
                } else {
                    scope.clone()
                },
                name: if exact_untyped {
                    instance.class_name.clone()
                } else {
                    name.clone()
                },
            });
            instance.ty = value.evidence.ty.clone().or(instance.ty);
            Some(instance)
        }
        ObjectIdentity::DynamicClass | ObjectIdentity::Receiver => env.receiver.clone(),
        ObjectIdentity::ReceiverProperty(attr) => {
            env.self_attrs.get(attr).cloned().map(|mut inst| {
                inst.ty = value.evidence.ty.clone().or(inst.ty);
                inst
            })
        }
        ObjectIdentity::Parameter { name, fallback } => {
            env.params.get(name).cloned().or_else(|| {
                fallback
                    .as_deref()
                    .and_then(|ty| resolve_exact_class(registry, importer, ty))
            })
        }
        ObjectIdentity::Local { name, fallback } => env
            .vars
            .get(name)
            .filter(|value| value.ty.is_some() || !value.class_name.is_empty())
            .cloned()
            .or_else(|| {
                fallback
                    .as_deref()
                    .and_then(|ty| resolve_exact_class(registry, importer, ty))
            }),
        // `<var>.<attr>` (Rust struct fields carry declared types): the typed
        // local's attribute classes, from its construction or its class's
        // field declarations.
        ObjectIdentity::LocalProperty { name, property } => {
            let inst = env.vars.get(name)?;
            inst.attrs
                .get(property)
                .cloned()
                .or_else(|| instance_attrs(registry, inst, &[]).get(property).cloned())
                .map(|mut inst| {
                    inst.ty = value.evidence.ty.clone().or(inst.ty);
                    inst
                })
        }
        ObjectIdentity::Resolved { file, class_name } => Some(ResolvedObject {
            file: file.clone(),
            class_name: class_name.clone(),
            attrs: if depth < MAX_INSTANCE_DEPTH {
                object
                    .properties
                    .iter()
                    .filter_map(|(name, value)| {
                        resolve_instance(registry, importer, env, value, depth + 1)
                            .map(|value| (name.clone(), value))
                    })
                    .collect()
            } else {
                HashMap::new()
            },
            values: object
                .properties
                .iter()
                .filter(|(_, value)| !matches!(value.kind, SemanticValueKind::Object(_)))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            origin: value.evidence.origin.clone(),
            ty: value.evidence.ty.clone(),
        }),
    }
}

/// Resolve a call's instance-typed arguments in the caller's context, keeping
/// their keyword-name/positional-index identification.
pub(super) fn resolve_obj_args(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    env: &Env,
    arguments: &[ValueArgument],
    depth: usize,
) -> Vec<(Option<String>, usize, ResolvedObject)> {
    if depth > MAX_INSTANCE_DEPTH {
        return Vec::new();
    }
    arguments
        .iter()
        .filter_map(|argument| {
            let resolved = match &argument.value.kind {
                SemanticValueKind::Object(_) => {
                    resolve_instance(registry, importer, env, &argument.value, depth)
                }
                SemanticValueKind::Parameter(name) | SemanticValueKind::Symbol(name) => {
                    env.params.get(name).or_else(|| env.vars.get(name)).cloned()
                }
                _ => None,
            };
            resolved.map(|value| (argument.name.clone(), argument.index, value))
        })
        .collect()
}

pub(super) fn resolved_object_value(value: &ResolvedObject) -> SemanticValue {
    let mut properties = value.values.clone();
    properties.extend(
        value
            .attrs
            .iter()
            .map(|(name, value)| (name.clone(), resolved_object_value(value))),
    );
    SemanticValue::new(SemanticValueKind::Object(effinterp_engine::ObjectValue {
        identity: ObjectIdentity::Resolved {
            file: value.file.clone(),
            class_name: value.class_name.clone(),
        },
        properties,
    }))
    .with_origin(value.origin.clone())
    .with_type(value.ty.clone())
}

pub(super) fn resolve_runtime_value(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    env: &Env,
    value: &SemanticValue,
) -> SemanticValue {
    let mut bindings = env.values.clone();
    bindings.extend(
        env.params
            .iter()
            .map(|(name, value)| (name.clone(), resolved_object_value(value))),
    );
    bindings.extend(
        env.vars
            .iter()
            .map(|(name, value)| (name.clone(), resolved_object_value(value))),
    );
    let value = substitute_value(value, &bindings, registry.value_limits());
    registry
        .linker(importer.lang)
        .resolve_package_value(registry, importer, &value)
}

/// The `self.<attr>` classes of an instance of `inst`: the resolved
/// `__init__`'s directly constructed attributes, plus parameter-stored
/// attributes bound from the constructor's instance-typed arguments.
pub(super) fn instance_attrs(
    registry: &ModuleRegistry,
    inst: &ResolvedObject,
    ctor: &[(Option<String>, usize, ResolvedObject)],
) -> HashMap<String, ResolvedObject> {
    let mut out = HashMap::new();
    let Some(inst_file) = registry.files.get(&inst.file) else {
        return out;
    };
    let Resolution::Targets(targets) = registry
        .linker(inst_file.lang)
        .resolve_method(registry, inst, "__init__")
    else {
        // No constructor def (a Rust struct): the class entry's declared field
        // types are the attribute classes, resolved in the defining file.
        if let Some(file) = registry.files.get(&inst.file)
            && let Some(entry) = class_entry(file, &inst.class_name)
        {
            for (attr, cls) in &entry.attr_classes {
                if let Some(v) = resolve_exact_class(registry, file, cls) {
                    out.insert(attr.clone(), v);
                }
            }
            for (attr, param) in &entry.attr_params {
                if let Some((_, _, value)) = ctor
                    .iter()
                    .find(|(name, _, _)| name.as_deref() == Some(param))
                {
                    out.insert(attr.clone(), value.clone());
                }
            }
        }
        return out;
    };
    let [(file, init_name, _)] = targets.as_slice() else {
        return out;
    };
    let init_class_name = init_name
        .split_once('.')
        .map(|(class, _)| class)
        .unwrap_or(init_name);
    let init_class = ResolvedObject {
        file: file.path.clone(),
        class_name: init_class_name.to_string(),
        attrs: HashMap::new(),
        values: BTreeMap::new(),
        origin: inst.origin.clone(),
        ty: inst.ty.clone(),
    };
    let Some(entry) = class_entry(file, &init_class.class_name) else {
        return out;
    };
    for (attr, cls) in &entry.attr_classes {
        if let Some(v) = resolve_exact_class(registry, file, cls) {
            out.insert(attr.clone(), v);
        }
    }
    let params = file
        .function(init_name)
        .map(|f| f.summary.params.clone())
        .unwrap_or_default();
    for (attr, param) in &entry.attr_params {
        let pos = params.iter().position(|p| p == param);
        let bound = ctor.iter().find(|(name, index, _)| match name {
            Some(n) => n == param,
            None => Some(*index) == pos,
        });
        if let Some((_, _, v)) = bound {
            out.insert(attr.clone(), v.clone());
        }
    }
    out
}

pub(super) fn instance_values(
    registry: &ModuleRegistry,
    inst: &ResolvedObject,
    ctor: &[ValueArgument],
    depth: usize,
) -> BTreeMap<String, SemanticValue> {
    if depth > MAX_INSTANCE_DEPTH {
        return BTreeMap::new();
    }
    if matches!(
        &inst.ty,
        Some(TypeRef::External { path }) if path == "pathlib.Path"
    ) {
        return ctor
            .iter()
            .find(|argument| argument.name.is_none() && argument.index == 0)
            .map(|argument| BTreeMap::from([("__resource__".to_string(), argument.value.clone())]))
            .unwrap_or_default();
    }
    let Some(inst_file) = registry.files.get(&inst.file) else {
        return BTreeMap::new();
    };
    let Resolution::Targets(targets) = registry
        .linker(inst_file.lang)
        .resolve_method(registry, inst, "__init__")
    else {
        if registry.linker(inst_file.lang).constructor_has_fields()
            && let Some(class) = class_entry(inst_file, &inst.class_name)
        {
            let mut values = BTreeMap::new();
            for (index, (field, _)) in class.attr_params.iter().enumerate() {
                if let Some(argument) = ctor.iter().find(|argument| {
                    argument.name.as_deref() == Some(field)
                        || (argument.name.is_none() && argument.index == index)
                }) {
                    values.insert(field.clone(), argument.value.clone());
                }
            }
            return values;
        }
        return BTreeMap::new();
    };
    let [(file, init_name, _)] = targets.as_slice() else {
        return BTreeMap::new();
    };
    let Some(function) = file.function(init_name) else {
        return BTreeMap::new();
    };
    let bindings = bind_function_arguments(function, ctor);
    let class_name = init_name
        .split_once('.')
        .map(|(class, _)| class)
        .unwrap_or(init_name);
    let mut values = BTreeMap::new();
    if let Some(class) = class_entry(file, class_name) {
        for (attr, param) in &class.attr_params {
            if let Some(value) = bindings.get(param) {
                let value = match value.as_object().map(|object| &object.identity) {
                    Some(ObjectIdentity::Class { constructor, .. })
                        if matches!(
                            &value.evidence.ty,
                            Some(TypeRef::External { path })
                                if matches!(path.as_str(), "pathlib.Path" | "pathlib.PosixPath" | "pathlib.WindowsPath")
                        ) =>
                    {
                        constructor
                            .iter()
                            .find(|argument| argument.name.is_none() && argument.index == 0)
                            .map(|argument| argument.value.clone())
                            .unwrap_or_else(|| value.clone())
                    }
                    _ => value.clone(),
                };
                values.insert(attr.clone(), value);
            }
        }
    }
    for call in &function.calls {
        let Some(receiver) = call.receiver.as_ref() else {
            continue;
        };
        if call.callee.rsplit('.').next() != Some("__init__") {
            continue;
        }
        let Some(base) = resolve_instance(registry, file, &Env::default(), receiver, depth + 1)
        else {
            continue;
        };
        let arguments: Vec<_> = call
            .arguments
            .iter()
            .map(|argument| ValueArgument {
                name: argument.name.clone(),
                index: argument.index,
                value: substitute_value(&argument.value, &bindings, registry.value_limits()),
            })
            .collect();
        values.extend(instance_values(registry, &base, &arguments, depth + 1));
    }
    values
}

pub(super) fn type_ref_name(ty: &TypeRef) -> &str {
    match ty {
        TypeRef::Repo { name, .. } => name,
        TypeRef::External { path } => path,
    }
}

pub(super) fn imports_type(importer: &ModuleFile, expected: &str) -> bool {
    let (module, name) = expected.rsplit_once('.').unwrap_or((expected, ""));
    importer
        .summary
        .imports
        .iter()
        .chain(&importer.summary.scoped_imports)
        .any(|binding| {
            binding.module == module
                && (binding.imported.is_none() || binding.imported.as_deref() == Some(name))
        })
}

pub(super) fn imports_function(
    importer: &ModuleFile,
    callee: &str,
    module: &str,
    name: &str,
) -> bool {
    let (local, member) = callee.split_once('.').unwrap_or((callee, name));
    member == name
        && importer
            .summary
            .imports
            .iter()
            .chain(&importer.summary.scoped_imports)
            .any(|binding| {
                binding.local == local
                    && binding.module == module
                    && binding
                        .imported
                        .as_deref()
                        .is_none_or(|imported| imported == name)
            })
}

pub(super) fn receiver_matches_type(
    registry: &ModuleRegistry,
    value: &ResolvedObject,
    expected: &str,
    seen: &mut HashSet<(String, String)>,
) -> bool {
    if value
        .ty
        .as_ref()
        .is_some_and(|actual| type_ref_name(actual) == expected)
    {
        return true;
    }
    if !seen.insert((value.file.clone(), value.class_name.clone())) {
        return false;
    }
    let Some(file) = registry.files.get(&value.file) else {
        return false;
    };
    let Some(class) = class_entry(file, &value.class_name) else {
        return false;
    };
    for base in &class.bases {
        if base == expected {
            return true;
        }
        let (expected_module, expected_name) =
            expected.rsplit_once(['.', '\\']).unwrap_or((expected, ""));
        if file
            .summary
            .imports
            .iter()
            .chain(&file.summary.scoped_imports)
            .filter(|binding| {
                binding.local == *base
                    || (binding.module == expected_module && expected_name == base)
            })
            .any(|binding| {
                let imported = binding.imported.as_deref().unwrap_or(base);
                format!("{}.{}", binding.module, imported) == expected || binding.module == expected
            })
        {
            return true;
        }
        if expected_name == base && loader_imports_external(registry, file, expected_module) {
            return true;
        }
        for (candidate, assurance) in registry
            .linker(file.lang)
            .class_candidates(registry, file, base)
        {
            if assurance == Assurance::Exact
                && receiver_matches_type(registry, &candidate, expected, seen)
            {
                return true;
            }
        }
    }
    false
}

fn loader_imports_external(
    registry: &ModuleRegistry,
    class_file: &ModuleFile,
    external: &str,
) -> bool {
    registry.files.values().any(|loader| {
        loader
            .summary
            .imports
            .iter()
            .any(|binding| binding.module == external)
            && loader.summary.imports.iter().any(|binding| {
                registry
                    .resolve_import(loader, binding)
                    .is_some_and(|target| target.path == class_file.path)
            })
    })
}

pub(super) fn value_from_ref(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    env: &Env,
    value: &SemanticValue,
) -> Option<ResolvedObject> {
    resolve_instance(registry, importer, env, value, 0).or_else(|| {
        let ObjectIdentity::Class { name, .. } = &value.as_object()?.identity else {
            return None;
        };
        let origin = value.evidence.origin.as_ref()?;
        Some(ResolvedObject {
            file: match &value.evidence.ty {
                Some(TypeRef::Repo { file, .. }) => file.clone(),
                _ => importer.path.clone(),
            },
            class_name: match &value.evidence.ty {
                Some(TypeRef::Repo { name, .. }) => name.clone(),
                Some(TypeRef::External { path }) => path.clone(),
                None => name.clone(),
            },
            attrs: HashMap::new(),
            values: BTreeMap::new(),
            origin: Some(origin.clone()),
            ty: value.evidence.ty.clone(),
        })
    })
}

pub(super) fn instance_at(
    importer: &ModuleFile,
    origin: ValueOrigin,
    ty: Option<TypeRef>,
) -> ResolvedObject {
    ResolvedObject {
        file: match &ty {
            Some(TypeRef::Repo { file, .. }) => file.clone(),
            _ => importer.path.clone(),
        },
        class_name: match &ty {
            Some(TypeRef::Repo { name, .. }) => name.clone(),
            Some(TypeRef::External { path }) => path.clone(),
            None => String::new(),
        },
        attrs: HashMap::new(),
        values: BTreeMap::new(),
        origin: Some(origin),
        ty,
    }
}

pub(super) fn callback_target<'a>(
    registry: &'a ModuleRegistry,
    importer: &'a ModuleFile,
    function: &str,
) -> Option<(&'a ModuleFile, String)> {
    if importer.function(function).is_some() {
        return Some((importer, function.to_string()));
    }
    match registry
        .linker(importer.lang)
        .resolve_callee(registry, importer, function)
    {
        Resolution::Targets(targets) => targets
            .into_iter()
            .find(|(target, name, _)| target.function(name).is_some())
            .map(|(target, name, _)| (target, name)),
        _ => None,
    }
}

pub(super) fn bound_callable(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    value: &SemanticValue,
) -> Option<BoundCallable> {
    let name = match &value.kind {
        SemanticValueKind::Callable(CallableValue::Function { name })
        | SemanticValueKind::Symbol(name) => Some(name.as_str()),
        _ => None,
    };
    if let Some(name) = name {
        if let Some(class) = resolve_exact_class(registry, importer, name) {
            return Some(BoundCallable::Class(class));
        }
        if let Some((file, function)) = callback_target(registry, importer, name) {
            return Some(BoundCallable::Function {
                file: file.path.clone(),
                function,
            });
        }
        if let Some((head, member)) = name.split_once('.')
            && let Some(binding) = find_import(&importer.summary, head)
        {
            return Some(BoundCallable::External {
                module: binding.module.clone(),
                member: member.to_string(),
            });
        }
    }
    let SemanticValueKind::Object(object) = &value.kind else {
        return None;
    };
    match &object.identity {
        ObjectIdentity::Class { name, .. } => {
            resolve_exact_class(registry, importer, name).map(BoundCallable::Class)
        }
        ObjectIdentity::ModuleBinding { scope, name } => {
            let mut candidates = Vec::new();
            for file in registry.files.values().filter(|file| {
                file.summary.linkage.scope.as_ref() == Some(scope)
                    && registry
                        .linker(importer.lang)
                        .module_binding_candidate(registry, importer, file)
            }) {
                if let Some(class) = resolve_exact_class(registry, file, name) {
                    candidates.push(BoundCallable::Class(class));
                } else if file.function(name).is_some() {
                    candidates.push(BoundCallable::Function {
                        file: file.path.clone(),
                        function: name.clone(),
                    });
                }
            }
            (candidates.len() == 1).then(|| candidates.pop().unwrap())
        }
        _ => None,
    }
}

pub(super) fn bind_constructor_results(
    registry: &ModuleRegistry,
    target: &ModuleFile,
    class_name: &str,
    edge: &CallEdge,
    env: &mut Env,
    out: &mut Composition,
) {
    let Some(value) = resolve_exact_class(registry, target, class_name) else {
        return;
    };
    bind_resolved_constructor(registry, target, value, edge, env, out);
}

pub(super) fn bind_resolved_constructor(
    registry: &ModuleRegistry,
    caller: &ModuleFile,
    mut value: ResolvedObject,
    edge: &CallEdge,
    env: &mut Env,
    out: &mut Composition,
) {
    push_dependency(out, value.file.clone());
    let resolved = resolve_obj_args(registry, caller, env, &edge.arguments, 0);
    value.attrs = instance_attrs(registry, &value, &resolved);
    value.values = instance_values(registry, &value, &edge.arguments, 0);
    for (index, name) in edge.result_bindings() {
        value.origin = edge.origin_for_result(index);
        if let Some(origin) = &value.origin {
            out.lifecycle.objects.insert(origin.clone(), value.clone());
        }
        env.vars.insert(name.to_string(), value.clone());
    }
}

/// Bind this call's exact function or class arguments to the callee's parameter names.
/// Positionals use the callee's declared parameter list; keywords use the
/// keyword name. Imported values must resolve to one repository module.
pub(super) fn bind_fn_args(
    walk: &mut Walk<'_>,
    caller: &ModuleFile,
    target: &ModuleFile,
    callee: &FunctionEntry,
    edge: &CallEdge,
) -> Callbacks {
    let mut map = HashMap::new();
    for argument in &edge.arguments {
        let Some(param) = function_parameter(callee, argument.name.as_deref(), argument.index)
        else {
            continue;
        };
        let callback = bound_callable(walk.registry, caller, &argument.value);
        if let Some(callback) = callback {
            map.insert(param.to_string(), callback);
        }
    }
    let supplied = bind_function_arguments(callee, &edge.arguments);
    for (index, default) in callee.callable_defaults.iter().enumerate() {
        let Some(param) = callee.summary.params.get(index) else {
            continue;
        };
        if supplied.contains_key(param) {
            continue;
        }
        let Some(default) = default else {
            continue;
        };
        if let Some(class) = resolve_exact_class(walk.registry, target, default) {
            map.insert(param.clone(), BoundCallable::Class(class));
        } else if let Some((file, function)) = callback_target(walk.registry, target, default) {
            map.insert(
                param.clone(),
                BoundCallable::Function {
                    file: file.path.clone(),
                    function,
                },
            );
        }
    }
    map
}
