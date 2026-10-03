use std::collections::{HashMap, HashSet};

use effinterp_engine::{
    Assurance, ExternalCall, ImportBinding, ObjectIdentity, ResolvedObject, SemanticValue,
    SemanticValueKind, property_access,
};
use effinterp_proto::{BoundaryReason, CalleeReference, Effect, ResourceExpr};

use crate::module::{ModuleFile, ModuleRegistry};

pub(crate) fn invalidation_for_path(
    path: &str,
) -> Option<crate::index::incremental_update::InvalidationAction> {
    matches!(
        std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path),
        "Cargo.toml"
            | "composer.json"
            | "go.mod"
            | "go.work"
            | "package.json"
            | "pyproject.toml"
            | "setup.cfg"
            | "tsconfig.json"
    )
    .then_some(crate::index::incremental_update::InvalidationAction::Rebuild)
}

pub(crate) const MAX_DISPATCH_CANDIDATES: usize = 4;
const MAX_MRO_CLASSES: usize = 16;
pub(crate) const MAX_EXPORT_CHASE: usize = 64;

pub(crate) trait Linker {
    /// The unambiguous declaration value of a package binding, excluding later writes.
    fn package_value(
        &self,
        _registry: &ModuleRegistry,
        _importer: &ModuleFile,
        _name: &str,
    ) -> Option<SemanticValue> {
        None
    }
    fn resolve_package_value(
        &self,
        registry: &ModuleRegistry,
        importer: &ModuleFile,
        value: &SemanticValue,
    ) -> SemanticValue {
        resolve_package_value_at(registry, importer, value, &mut HashSet::new(), 0)
    }
    /// Resolve a package binding in its recorded scope without restarting the recursion guard.
    fn package_value_in_scope(
        &self,
        _registry: &ModuleRegistry,
        _importer: &ModuleFile,
        _scope: &effinterp_engine::ScopeKey,
        _name: &str,
    ) -> Option<SemanticValue> {
        None
    }

    /// Bind package declarations under the names visible from this file.
    fn package_bindings(
        &self,
        _registry: &ModuleRegistry,
        _importer: &ModuleFile,
    ) -> HashMap<String, SemanticValue> {
        HashMap::new()
    }
    /// Whether a package callee can differ from its declaration initializer.
    fn callee_is_rebound(
        &self,
        _registry: &ModuleRegistry,
        _importer: &ModuleFile,
        _callee: &str,
    ) -> bool {
        false
    }
    /// Find the declaration file of an indirect package callee; anonymous callables are file-local.
    fn rebound_callee<'a>(
        &self,
        _registry: &'a ModuleRegistry,
        _importer: &'a ModuleFile,
        _callee: &str,
    ) -> Option<(&'a ModuleFile, String)> {
        None
    }
    /// Whether this file participates in the importer’s selected package build.
    fn module_binding_candidate(
        &self,
        _registry: &ModuleRegistry,
        _importer: &ModuleFile,
        _file: &ModuleFile,
    ) -> bool {
        true
    }
    /// Whether constructor arguments directly initialize declared fields without an initializer method.
    fn constructor_has_fields(&self) -> bool {
        false
    }
    /// Whether a resolved class call binds an instance without entering a constructor body.
    fn constructor_result_is_instance(&self, _edge: &effinterp_engine::CallEdge) -> bool {
        false
    }
    /// Whether passing a callable to an unknown callee leaves its execution unproven.
    fn callbacks_escape(&self) -> bool {
        false
    }
    /// Whether the first returned value carries runtime object identity back to the caller.
    fn resolve_returned_instance(&self) -> bool {
        false
    }
    /// Domains a spawned subprocess may affect when its execution is not composed.
    fn subprocess_boundary_domains(&self) -> Vec<String> {
        vec!["process".to_string()]
    }
    fn semantic_external_effects(
        &self,
        _module: &str,
        _member: &str,
        _values: &[SemanticValue],
    ) -> Option<Vec<Effect>> {
        None
    }
    /// Project a declared result to the value available along successful execution.
    fn declared_result_value(
        &self,
        value: SemanticValue,
        _value_limits: effinterp_engine::ValueLimits,
    ) -> SemanticValue {
        value
    }
    /// Translate the frontend import spelling into a query-visible callee reference.
    fn import_call_reference(
        &self,
        _importer: &ModuleFile,
        _edge: &effinterp_engine::CallEdge,
    ) -> Option<CalleeReference> {
        None
    }
    /// Recover the imported class reference after exact receiver dispatch.
    fn import_dispatch_reference(
        &self,
        _registry: &ModuleRegistry,
        _importer: &ModuleFile,
        _edge: &effinterp_engine::CallEdge,
        _instance: &ResolvedObject,
        _method: &str,
    ) -> Option<CalleeReference> {
        None
    }
    /// Whether a qualified class identity must survive method dispatch unchanged.
    fn qualified_class_dispatch(&self, _class_name: &str) -> bool {
        false
    }
    /// Whether an unresolved non-constructor call requires an explicit boundary.
    fn unresolved_call_is_boundary(&self) -> bool {
        false
    }
    /// Describe an unmodeled receiver method, or return no boundary for a proven inert method.
    fn unresolved_method_detail(
        &self,
        _insts: &[ResolvedObject],
        method: &str,
        _edge: &effinterp_engine::CallEdge,
        exact_repository_receivers: bool,
    ) -> Option<String> {
        exact_repository_receivers
            .then(|| format!("{method} not found on exact repository receiver"))
    }

    fn resolve_callee<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a>;

    fn class_candidates<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)>;

    fn resolve_method<'a>(
        &self,
        reg: &'a ModuleRegistry,
        inst: &ResolvedObject,
        method: &str,
    ) -> Resolution<'a>;

    /// Classify an external call. `arity` is the observed positional argument
    /// count when the call site knows it, so a curated entry naming a
    /// fixed-signature function is not inherited by a same-named call.
    fn classify_external(
        &self,
        reg: &ModuleRegistry,
        module: &str,
        member: &str,
        arity: Option<usize>,
    ) -> Option<ExternalCall>;

    fn classify_import(
        &self,
        reg: &ModuleRegistry,
        file: &ModuleFile,
        spec: &str,
    ) -> Option<ExternalCall>;

    fn external_import_label(
        &self,
        _reg: &ModuleRegistry,
        _file: &ModuleFile,
        spec: &str,
    ) -> String {
        format!("import {spec:?} is an unmodeled external library")
    }

    fn execution_roots<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
    ) -> Vec<(&'a ModuleFile, Option<&'a str>)>;

    fn external_effects(
        &self,
        _module: &str,
        _member: &str,
        _args: &[ResourceExpr],
    ) -> Option<Vec<Effect>> {
        None
    }

    fn unknown_import_is_boundary(&self) -> bool {
        false
    }

    fn is_constructor_fact(&self, _edge: &effinterp_engine::CallEdge) -> bool {
        false
    }
}

pub(crate) enum Resolution<'a> {
    Targets(Vec<(&'a ModuleFile, String, Assurance)>),
    Local,
    External {
        module: String,
        member: String,
    },
    Unknown,
    Boundary {
        reason: BoundaryReason,
        detail: String,
    },
}

mod go;
mod java;
mod js;
mod php;
mod python;
mod ruby;
mod rust;

use go::GoLinker;
use java::JavaLinker;
use js::JsLinker;
use php::PhpLinker;
use python::PythonLinker;
use ruby::RubyLinker;
use rust::RustLinker;

pub(crate) static PYTHON_LINKER: PythonLinker = PythonLinker;
pub(crate) static JS_LINKER: JsLinker = JsLinker;
pub(crate) static RUBY_LINKER: RubyLinker = RubyLinker;
pub(crate) static RUST_LINKER: RustLinker = RustLinker;
pub(crate) static GO_LINKER: GoLinker = GoLinker;
pub(crate) static JAVA_LINKER: JavaLinker = JavaLinker;
pub(crate) static PHP_LINKER: PhpLinker = PhpLinker;

fn instance(file: &ModuleFile, class_name: &str) -> ResolvedObject {
    ResolvedObject {
        file: file.path.clone(),
        class_name: class_name.to_string(),
        attrs: HashMap::new(),
        values: Default::default(),
        origin: None,
        ty: None,
    }
}

fn class_defined(file: &ModuleFile, name: &str) -> bool {
    file.summary.classes.iter().any(|class| class.name == name)
}

fn imported_function_name(file: &ModuleFile, name: &str) -> Option<String> {
    if file.summary.linkage.explicit_exports {
        file.summary
            .exported_definitions
            .iter()
            .find(|(exported, local)| exported == name && file.function(local).is_some())
            .map(|(_, local)| local.clone())
    } else {
        file.function(name).map(|_| name.to_string())
    }
}

fn imported_class_name(file: &ModuleFile, name: &str) -> Option<String> {
    if file.summary.linkage.explicit_exports {
        file.summary
            .exported_definitions
            .iter()
            .find(|(exported, local)| exported == name && class_defined(file, local))
            .map(|(_, local)| local.clone())
    } else {
        class_defined(file, name).then(|| name.to_string())
    }
}

fn find_import<'a>(file: &'a ModuleFile, local: &str) -> Option<&'a ImportBinding> {
    file.summary
        .imports
        .iter()
        .chain(&file.summary.scoped_imports)
        .find(|binding| binding.local == local)
}

fn wildcard_exports(file: &ModuleFile, name: &str) -> bool {
    !(file
        .summary
        .linkage
        .wildcard_excluded_names
        .iter()
        .any(|excluded| excluded == name)
        || (file.summary.linkage.wildcard_excludes_private && name.starts_with('_')))
}

/// The module path of `imported` under `module`; a relative module made only
/// of dots keeps its dots and takes the name directly.
pub(crate) fn join_module(module: &str, imported: &str) -> String {
    if module.chars().all(|c| c == '.') {
        format!("{module}{imported}")
    } else {
        format!("{module}.{imported}")
    }
}

fn member_after_module(module: &str, head: &str, member: &str) -> String {
    let full = format!("{head}.{member}");
    full.strip_prefix(module)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(member)
        .to_string()
}

fn one<'a>(file: &'a ModuleFile, name: String, assurance: Assurance) -> Resolution<'a> {
    Resolution::Targets(vec![(file, name, assurance)])
}

fn bounded_dispatch<'a>(
    mut targets: Vec<(&'a ModuleFile, String, Assurance)>,
    detail: impl FnOnce(usize) -> String,
) -> Resolution<'a> {
    dedup_targets(&mut targets);
    match targets.len() {
        0 => Resolution::Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            detail: detail(0),
        },
        1 => {
            targets[0].2 = Assurance::Heuristic;
            Resolution::Targets(targets)
        }
        2..=MAX_DISPATCH_CANDIDATES => {
            for target in &mut targets {
                target.2 = Assurance::Alternatives;
            }
            Resolution::Targets(targets)
        }
        count => Resolution::Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            detail: detail(count),
        },
    }
}

fn dispatch_contract<'a>(
    reg: &'a ModuleRegistry,
    inst: &ResolvedObject,
) -> Option<(&'a ModuleFile, &'a effinterp_engine::DispatchContract)> {
    let file = reg.files.get(&inst.file)?;
    let contract = file
        .summary
        .dispatch_contracts
        .iter()
        .find(|contract| contract.name == inst.class_name)?;
    Some((file, contract))
}

fn resolves_contract(
    linker: &dyn Linker,
    reg: &ModuleRegistry,
    file: &ModuleFile,
    written: &str,
    contract_file: &str,
    contract_name: &str,
) -> bool {
    linker
        .class_candidates(reg, file, written)
        .into_iter()
        .any(|(candidate, assurance)| {
            assurance == Assurance::Exact
                && candidate.file == contract_file
                && candidate.class_name == contract_name
        })
}

fn excluded_dispatch_file(path: &str) -> bool {
    path.starts_with("tests/")
        || path.contains("/tests/")
        || path.starts_with("examples/")
        || path.starts_with("benches/")
        || path.ends_with("_test.go")
        || path.ends_with("Test.java")
}

fn resolve_to<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    importer: &'a ModuleFile,
    binding: &ImportBinding,
    name: &str,
) -> Resolution<'a> {
    match reg.resolve_import(importer, binding) {
        Some(target) => {
            if let Some(local) = imported_function_name(target, name) {
                return one(target, local, Assurance::Exact);
            }
            if !name.contains('.') {
                let forwarded = resolve_export(reg, target, name);
                if !matches!(forwarded, Resolution::Unknown) {
                    return forwarded;
                }
                // Keep the imported module as the bounded unresolved target so
                // composition records that the requested definition is absent
                // there instead of silently dropping the call.
                return one(target, name.to_string(), Assurance::Exact);
            }
            if let Some(resolved) = resolve_through_submodule(linker, reg, importer, binding, name)
            {
                return resolved;
            }
            one(target, name.to_string(), Assurance::Exact)
        }
        None => {
            if let Some(resolved) = resolve_through_submodule(linker, reg, importer, binding, name)
            {
                return resolved;
            }
            Resolution::External {
                module: binding.module.clone(),
                member: name.to_string(),
            }
        }
    }
}

/// Follow only frontend-confirmed exports. Ordinary imports are deliberately
/// excluded: a dependency with a same-named definition is not a re-export.
fn resolve_export<'a>(reg: &'a ModuleRegistry, file: &'a ModuleFile, name: &str) -> Resolution<'a> {
    resolve_export_inner(reg, file, name, &mut Vec::new(), &mut HashMap::new())
}

fn resolve_export_inner<'a>(
    reg: &'a ModuleRegistry,
    file: &'a ModuleFile,
    name: &str,
    stack: &mut Vec<(String, String)>,
    best_depth: &mut HashMap<(String, String), usize>,
) -> Resolution<'a> {
    reg.note_export_visit();
    let key = (file.path.clone(), name.to_string());
    if stack.contains(&key) {
        return Resolution::Boundary {
            reason: BoundaryReason::REEXPORT_CYCLE,
            detail: format!("re-export cycle at {}:{name}", file.path),
        };
    }
    if stack.len() >= MAX_EXPORT_CHASE {
        return Resolution::Boundary {
            reason: BoundaryReason::REEXPORT_LIMIT,
            detail: format!(
                "re-export chase exceeded {MAX_EXPORT_CHASE} hops at {}:{name}",
                file.path
            ),
        };
    }
    let depth = stack.len();
    // A shorter route gets more of the hop budget; equal or longer routes
    // through a shared export node cannot discover anything new.
    if best_depth
        .get(&key)
        .is_some_and(|previous_depth| *previous_depth <= depth)
    {
        return Resolution::Unknown;
    }
    best_depth.insert(key.clone(), depth);
    if let Some(local) = imported_function_name(file, name) {
        return one(file, local, Assurance::Exact);
    }

    stack.push(key);
    let mut targets = Vec::new();
    let mut boundary = None;
    let matching_exports = file.summary.exports.iter().filter(|export| {
        export.local == name || (export.local == "*" && wildcard_exports(file, name))
    });
    let mut matching_exports: Vec<_> = matching_exports.collect();
    // Python applies unconditional imports in source order. An exact binding
    // after the last star wins; otherwise one unconditional star replaces an
    // earlier exact binding. Conditional stars are retained more than once by
    // the frontend and therefore stay on the ambiguity path below.
    if file.summary.linkage.ordered_wildcard_overrides
        && let Some(last_star) = matching_exports
            .iter()
            .rposition(|export| export.local == "*")
    {
        let exact_after = matching_exports[last_star + 1..]
            .iter()
            .any(|export| export.local == name);
        if exact_after {
            matching_exports = matching_exports[last_star + 1..]
                .iter()
                .copied()
                .filter(|export| export.local == name)
                .collect();
        } else if matching_exports
            .iter()
            .filter(|export| export.local == "*")
            .count()
            == 1
        {
            matching_exports = vec![matching_exports[last_star]];
        }
    }
    for export in matching_exports {
        let Some(target) = reg.resolve_import(file, export) else {
            continue;
        };
        let target_name = if export.local == "*" {
            name
        } else {
            export.imported.as_deref().unwrap_or(name)
        };
        match resolve_export_inner(reg, target, target_name, stack, best_depth) {
            Resolution::Targets(found) => targets.extend(found),
            Resolution::Boundary { reason, detail } => {
                boundary.get_or_insert((reason, detail));
            }
            Resolution::Local | Resolution::External { .. } | Resolution::Unknown => {}
        }
    }
    stack.pop();
    dedup_targets(&mut targets);
    match targets.len() {
        0 => boundary
            .map(|(reason, detail)| Resolution::Boundary { reason, detail })
            .unwrap_or(Resolution::Unknown),
        1 => Resolution::Targets(targets),
        count => Resolution::Boundary {
            reason: BoundaryReason::REEXPORT_AMBIGUOUS,
            detail: format!("export {name:?} from {} has {count} definitions", file.path),
        },
    }
}

fn resolve_export_class<'a>(
    reg: &'a ModuleRegistry,
    file: &'a ModuleFile,
    name: &str,
) -> Option<(&'a ModuleFile, String)> {
    resolve_export_class_inner(reg, file, name, &mut Vec::new(), &mut HashMap::new())
}

fn resolve_export_class_inner<'a>(
    reg: &'a ModuleRegistry,
    file: &'a ModuleFile,
    name: &str,
    stack: &mut Vec<(String, String)>,
    best_depth: &mut HashMap<(String, String), usize>,
) -> Option<(&'a ModuleFile, String)> {
    reg.note_export_visit();
    let key = (file.path.clone(), name.to_string());
    if stack.len() >= MAX_EXPORT_CHASE || stack.contains(&key) {
        return None;
    }
    let depth = stack.len();
    if best_depth
        .get(&key)
        .is_some_and(|previous_depth| *previous_depth <= depth)
    {
        return None;
    }
    best_depth.insert(key.clone(), depth);
    if let Some(local) = imported_class_name(file, name) {
        return Some((file, local));
    }

    stack.push(key);
    let mut targets = Vec::new();
    for export in file.summary.exports.iter().filter(|export| {
        export.local == name || (export.local == "*" && wildcard_exports(file, name))
    }) {
        let Some(target) = reg.resolve_import(file, export) else {
            continue;
        };
        let target_name = if export.local == "*" {
            name
        } else {
            export.imported.as_deref().unwrap_or(name)
        };
        if let Some(found) = resolve_export_class_inner(reg, target, target_name, stack, best_depth)
            && !targets.iter().any(|(file, class): &(&ModuleFile, String)| {
                file.path == found.0.path && class == &found.1
            })
        {
            targets.push(found);
        }
    }
    stack.pop();
    (targets.len() == 1).then(|| targets.pop().unwrap())
}

fn resolve_through_submodule<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    importer: &'a ModuleFile,
    binding: &ImportBinding,
    name: &str,
) -> Option<Resolution<'a>> {
    let (sub, rest) = name.split_once('.')?;
    let sub_binding = ImportBinding {
        local: sub.to_string(),
        module: join_module(&binding.module, sub),
        imported: None,
    };
    reg.resolve_import(importer, &sub_binding)
        .is_some()
        .then(|| resolve_to(linker, reg, importer, &sub_binding, rest))
}

fn module_singleton(
    linker: &dyn Linker,
    reg: &ModuleRegistry,
    target: &ModuleFile,
    name: &str,
) -> Option<ResolvedObject> {
    for edge in &target.summary.module_calls {
        if let Some((result_index, _)) = edge.result_bindings().find(|(_, var)| *var == name)
            && let Some((mut inst, _)) = linker
                .class_candidates(reg, target, &edge.callee)
                .into_iter()
                .find(|(_, assurance)| *assurance == Assurance::Exact)
        {
            inst.origin = edge.origin_for_result(result_index);
            inst.ty = edge.result_type().cloned().or(inst.ty);
            return Some(inst);
        }
    }
    None
}

fn resolve_standard_callee<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    file: &'a ModuleFile,
    callee: &str,
) -> Resolution<'a> {
    let (head, member) = match callee.split_once('.') {
        Some((head, member)) => (head, Some(member)),
        None => (callee, None),
    };
    if member.is_none() {
        if let Some(binding) = find_import(file, head) {
            if let Some(imported) = &binding.imported {
                return resolve_to(linker, reg, file, binding, imported);
            }
            return Resolution::Unknown;
        }
        return if file.function(head).is_some() {
            Resolution::Local
        } else {
            Resolution::Unknown
        };
    }

    let member = member.unwrap();
    let Some(binding) = find_import(file, head) else {
        return Resolution::Unknown;
    };
    match &binding.imported {
        None => resolve_to(
            linker,
            reg,
            file,
            binding,
            &member_after_module(&binding.module, head, member),
        ),
        Some(imported) => {
            let sub = ImportBinding {
                local: head.to_string(),
                module: join_module(&binding.module, imported),
                imported: None,
            };
            if reg.resolve_import(file, &sub).is_some() {
                return resolve_to(linker, reg, file, &sub, member);
            }
            if let Some(target) = reg.resolve_import(file, binding) {
                let qualified = format!("{imported}.{member}");
                if target.function(&qualified).is_some() {
                    return one(target, qualified, Assurance::Exact);
                }
                if let Some(inst) = module_singleton(linker, reg, target, imported) {
                    return linker.resolve_method(reg, &inst, member);
                }
            }
            Resolution::Unknown
        }
    }
}

fn standard_class_candidates(
    linker: &dyn Linker,
    reg: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
) -> Vec<(ResolvedObject, Assurance)> {
    if let Some((head, rest)) = name.split_once('.') {
        if rest.contains('.') {
            return Vec::new();
        }
        let Some(binding) = find_import(file, head) else {
            return Vec::new();
        };
        let target = match &binding.imported {
            None => reg.resolve_import(file, binding),
            Some(imported) => {
                let sub = ImportBinding {
                    local: head.to_string(),
                    module: join_module(&binding.module, imported),
                    imported: None,
                };
                reg.resolve_import(file, &sub)
            }
        };
        return target
            .and_then(|target| {
                imported_class_name(target, rest)
                    .map(|local| vec![(instance(target, &local), Assurance::Exact)])
            })
            .unwrap_or_default();
    }
    if class_defined(file, name) {
        return vec![(instance(file, name), Assurance::Exact)];
    }
    let Some(binding) = find_import(file, name) else {
        return Vec::new();
    };
    let Some(target) = reg.resolve_import(file, binding) else {
        return Vec::new();
    };
    let Some(imported) = &binding.imported else {
        return imported_class_name(target, name)
            .map(|local| vec![(instance(target, &local), Assurance::Exact)])
            .unwrap_or_default();
    };
    if let Some(local) = imported_class_name(target, imported) {
        vec![(instance(target, &local), Assurance::Exact)]
    } else if let Some((definition, local)) = resolve_export_class(reg, target, imported) {
        vec![(instance(definition, &local), Assurance::Exact)]
    } else if imported != name
        && let Some(local) = imported_class_name(target, name)
    {
        vec![(instance(target, &local), Assurance::Exact)]
    } else {
        let _ = linker;
        Vec::new()
    }
}

fn resolve_common_method<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    inst: &ResolvedObject,
    method: &str,
) -> Resolution<'a> {
    let Some(file) = reg.files.get(&inst.file) else {
        return Resolution::Unknown;
    };
    if class_defined(file, &inst.class_name) {
        return resolve_method_in_class(linker, reg, inst, method, &mut HashSet::new());
    }
    let mut targets = Vec::new();
    for (candidate, assurance) in linker.class_candidates(reg, file, &inst.class_name) {
        if let Resolution::Targets(found) =
            resolve_method_in_class(linker, reg, &candidate, method, &mut HashSet::new())
        {
            targets.extend(
                found
                    .into_iter()
                    .map(|(file, name, nested)| (file, name, assurance.max(nested))),
            );
        }
    }
    dedup_targets(&mut targets);
    if targets.is_empty() {
        Resolution::Unknown
    } else {
        Resolution::Targets(targets)
    }
}

fn resolve_method_in_class<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    inst: &ResolvedObject,
    method: &str,
    seen: &mut HashSet<(String, String)>,
) -> Resolution<'a> {
    if seen.len() >= MAX_MRO_CLASSES || !seen.insert((inst.file.clone(), inst.class_name.clone())) {
        return Resolution::Unknown;
    }
    let Some(file) = reg.files.get(&inst.file) else {
        return Resolution::Unknown;
    };
    let qualified = format!("{}.{method}", inst.class_name);
    if file.function(&qualified).is_some() {
        return one(file, qualified, Assurance::Exact);
    }
    if method == "__init__" && file.function(&inst.class_name).is_some() {
        return one(file, inst.class_name.clone(), Assurance::Exact);
    }
    let Some(class) = file
        .summary
        .classes
        .iter()
        .find(|class| class.name == inst.class_name)
    else {
        return Resolution::Unknown;
    };
    for base in &class.bases {
        for (base_inst, assurance) in linker.class_candidates(reg, file, base) {
            match resolve_method_in_class(linker, reg, &base_inst, method, seen) {
                Resolution::Targets(mut found) => {
                    for target in &mut found {
                        target.2 = target.2.max(assurance);
                    }
                    return Resolution::Targets(found);
                }
                external @ Resolution::External { .. } => return external,
                Resolution::Local | Resolution::Unknown | Resolution::Boundary { .. } => {}
            }
        }
        let (local, suffix) = base.split_once('.').unwrap_or((base, ""));
        let Some(binding) = find_import(file, local) else {
            continue;
        };
        if reg.resolve_import(file, binding).is_some() {
            continue;
        }
        let imported = match (binding.imported.as_deref(), suffix) {
            (Some(imported), "") => imported.to_string(),
            (Some(imported), suffix) => format!("{imported}.{suffix}"),
            (None, suffix) => suffix.to_string(),
        };
        if !imported.is_empty() {
            return Resolution::External {
                module: binding.module.clone(),
                member: format!("{imported}.{method}"),
            };
        }
    }
    Resolution::Unknown
}

fn dedup_targets(targets: &mut Vec<(&ModuleFile, String, Assurance)>) {
    targets
        .sort_by(|a, b| (a.0.path.as_str(), a.1.as_str()).cmp(&(b.0.path.as_str(), b.1.as_str())));
    let mut out: Vec<(&ModuleFile, String, Assurance)> = Vec::new();
    for (file, name, assurance) in targets.drain(..) {
        if let Some(existing) = out.iter_mut().find(|(existing_file, existing_name, _)| {
            existing_file.path == file.path && existing_name == &name
        }) {
            existing.2 = existing.2.max(assurance);
        } else {
            out.push((file, name, assurance));
        }
    }
    *targets = out;
}

const MAX_PACKAGE_VALUE_DEPTH: usize = 24;

fn resolve_package_value_at(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    value: &SemanticValue,
    seen: &mut HashSet<(effinterp_engine::ScopeKey, String)>,
    depth: usize,
) -> SemanticValue {
    if depth >= MAX_PACKAGE_VALUE_DEPTH {
        return SemanticValue::unresolved("value");
    }
    match &value.kind {
        SemanticValueKind::Object(object) => {
            if let ObjectIdentity::ModuleBinding { scope, name } = &object.identity {
                let key = (scope.clone(), name.clone());
                if seen.insert(key.clone()) {
                    let resolved = registry
                        .linker(importer.lang)
                        .package_value_in_scope(registry, importer, scope, name)
                        .map(|value| {
                            resolve_package_value_at(registry, importer, &value, seen, depth + 1)
                        });
                    seen.remove(&key);
                    if let Some(resolved) = resolved {
                        return resolved;
                    }
                }
            }
            let mut value = value.clone();
            if let SemanticValueKind::Object(object) = &mut value.kind {
                if let ObjectIdentity::Class { constructor, .. } = &mut object.identity {
                    for argument in constructor {
                        argument.value = resolve_package_value_at(
                            registry,
                            importer,
                            &argument.value,
                            seen,
                            depth + 1,
                        );
                    }
                }
                for property in object.properties.values_mut() {
                    *property =
                        resolve_package_value_at(registry, importer, property, seen, depth + 1);
                }
            }
            value
        }
        SemanticValueKind::Property { base, name } => {
            let base = resolve_package_value_at(registry, importer, base, seen, depth + 1);
            property_access(&base, name, registry.value_limits())
        }
        SemanticValueKind::Collection {
            elements,
            properties,
        } => SemanticValue::new(SemanticValueKind::Collection {
            elements: elements
                .iter()
                .map(|value| resolve_package_value_at(registry, importer, value, seen, depth + 1))
                .collect(),
            properties: properties
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        resolve_package_value_at(registry, importer, value, seen, depth + 1),
                    )
                })
                .collect(),
        }),
        SemanticValueKind::Union(values) => SemanticValue::new(SemanticValueKind::Union(
            values
                .iter()
                .map(|value| resolve_package_value_at(registry, importer, value, seen, depth + 1))
                .collect(),
        ))
        .canonicalize(registry.value_limits()),
        _ => value.clone(),
    }
}
