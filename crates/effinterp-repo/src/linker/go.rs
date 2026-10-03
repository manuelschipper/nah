use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use effinterp_engine::{
    Assurance, DispatchSignature, DispatchStyle, ExternalCall, ImportBinding, ResolvedObject,
    SemanticValue, TypeRef, classify_go_call,
};
use effinterp_proto::{CalleeReference, Effect};

use super::{
    Linker, Resolution, bounded_dispatch, class_defined, dispatch_contract, excluded_dispatch_file,
    find_import, instance, one, resolve_common_method, resolve_package_value_at,
    standard_class_candidates,
};
use crate::module::{ModuleFile, ModuleRegistry};

pub(crate) struct GoLinker;

fn go_dispatch_targets<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    inst: &ResolvedObject,
    method: &str,
) -> Resolution<'a> {
    let Some((_contract_file, contract)) = dispatch_contract(reg, inst) else {
        return Resolution::Unknown;
    };
    if !contract.methods.iter().any(|candidate| candidate == method) {
        return Resolution::Unknown;
    }
    let aliases = go_dispatch_aliases(reg);
    let mut targets = Vec::new();
    for file in reg.files.values().map(|file| file.as_ref()) {
        if file.summary.linkage.dispatch != DispatchStyle::Structural
            || excluded_dispatch_file(&file.path)
        {
            continue;
        }
        for class in &file.summary.classes {
            if file
                .summary
                .dispatch_contracts
                .iter()
                .any(|candidate| candidate.name == class.name)
            {
                continue;
            }
            let candidate = instance(file, &class.name);
            let implements = contract.methods.iter().all(|required| {
                let Some((_, signature)) = contract
                    .method_signatures
                    .iter()
                    .find(|(name, _)| name == required)
                else {
                    return false;
                };
                match linker.resolve_method(reg, &candidate, required) {
                    Resolution::Targets(targets) => targets.iter().all(|(file, name, _)| {
                        file.function(name)
                            .and_then(|function| function.dispatch_signature.as_ref())
                            .is_some_and(|candidate| {
                                go_dispatch_signatures_match(candidate, signature, &aliases)
                            })
                    }),
                    _ => false,
                }
            });
            if !implements {
                continue;
            }
            if let Resolution::Targets(found) = linker.resolve_method(reg, &candidate, method) {
                targets.extend(found);
            }
        }
    }
    bounded_dispatch(targets, |count| {
        format!(
            "interface {} method {method:?} has {count} typed candidates",
            contract.name
        )
    })
}

fn go_dispatch_aliases(reg: &ModuleRegistry) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for file in reg
        .files
        .values()
        .filter(|file| file.summary.linkage.dispatch == DispatchStyle::Structural)
    {
        for (name, target) in &file.summary.dispatch_type_aliases {
            aliases
                .entry(name.clone())
                .or_insert_with(|| target.clone());
        }
    }
    aliases
}

fn go_dispatch_signatures_match(
    left: &DispatchSignature,
    right: &DispatchSignature,
    aliases: &BTreeMap<String, String>,
) -> bool {
    left.params.len() == right.params.len()
        && left.results.len() == right.results.len()
        && left.params.iter().zip(&right.params).all(|(left, right)| {
            expand_go_type_aliases(left, aliases) == expand_go_type_aliases(right, aliases)
        })
        && left
            .results
            .iter()
            .zip(&right.results)
            .all(|(left, right)| {
                expand_go_type_aliases(left, aliases) == expand_go_type_aliases(right, aliases)
            })
}

fn expand_go_type_aliases(typ: &str, aliases: &BTreeMap<String, String>) -> String {
    let mut expanded = typ.to_string();
    let mut resolved = HashSet::new();
    for _ in 0..aliases.len() {
        let Some((alias, target)) = aliases.iter().find(|(alias, _)| {
            !resolved.contains(*alias) && contains_go_type_name(&expanded, alias)
        }) else {
            break;
        };
        resolved.insert(alias.clone());
        expanded = replace_go_type_name(&expanded, alias, target);
    }
    expanded
}

fn contains_go_type_name(typ: &str, name: &str) -> bool {
    let mut rest = typ;
    while let Some(index) = rest.find(name) {
        let before = &rest[..index];
        let after = &rest[index + name.len()..];
        if before
            .chars()
            .next_back()
            .is_none_or(|ch| !go_type_name_char(ch))
            && after.chars().next().is_none_or(|ch| !go_type_name_char(ch))
        {
            return true;
        }
        rest = after;
    }
    false
}

fn replace_go_type_name(typ: &str, name: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(typ.len());
    let mut rest = typ;
    while let Some(index) = rest.find(name) {
        let before = &rest[..index];
        let after = &rest[index + name.len()..];
        let left_bound = before
            .chars()
            .next_back()
            .is_none_or(|ch| !go_type_name_char(ch));
        let right_bound = after.chars().next().is_none_or(|ch| !go_type_name_char(ch));
        out.push_str(before);
        if left_bound && right_bound {
            out.push_str(replacement);
        } else {
            out.push_str(name);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn go_type_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/')
}

fn go_sibling<'a>(
    reg: &'a ModuleRegistry,
    file: &ModuleFile,
    function: &str,
) -> Option<&'a ModuleFile> {
    let package = reg.go_packages.get(&file.path);
    reg.files.values().map(|file| file.as_ref()).find(|target| {
        target.summary.linkage.scope == file.summary.linkage.scope
            && target.dir == file.dir
            && !target.path.ends_with("_test.go")
            && reg.go_packages.get(&target.path) == package
            && target.function(function).is_some()
    })
}

fn go_class<'a>(reg: &'a ModuleRegistry, file: &ModuleFile, name: &str) -> Option<&'a ModuleFile> {
    let package = reg.go_packages.get(&file.path);
    reg.files.values().map(|file| file.as_ref()).find(|target| {
        target.summary.linkage.scope == file.summary.linkage.scope
            && target.dir == file.dir
            && !target.path.ends_with("_test.go")
            && reg.go_packages.get(&target.path) == package
            && class_defined(target, name)
    })
}

fn go_resolve_to<'a>(
    reg: &'a ModuleRegistry,
    importer: &'a ModuleFile,
    binding: &ImportBinding,
    function: &str,
) -> Resolution<'a> {
    let Some(package_file) = reg.resolve_import(importer, binding).and_then(|file| {
        reg.files.values().map(|file| file.as_ref()).find(|target| {
            target.summary.linkage.scope == file.summary.linkage.scope
                && target.dir == file.dir
                && !target.path.ends_with("_test.go")
                && target.path.ends_with(".go")
        })
    }) else {
        return Resolution::External {
            module: binding.module.clone(),
            member: function.to_string(),
        };
    };
    match go_sibling(reg, package_file, function) {
        Some(target) => one(target, function.to_string(), Assurance::Exact),
        None => one(package_file, function.to_string(), Assurance::Exact),
    }
}
impl Linker for GoLinker {
    fn import_call_reference(
        &self,
        _importer: &ModuleFile,
        edge: &effinterp_engine::CallEdge,
    ) -> Option<CalleeReference> {
        let owner =
            edge.results
                .iter()
                .find_map(|result| match result.value.evidence.origin.as_ref() {
                    Some(effinterp_engine::ValueOrigin::Site { function, .. }) => {
                        Some(function.as_str())
                    }
                    _ => None,
                })?;
        let (module, symbol) = edge
            .callee
            .rsplit_once('.')
            .unwrap_or((owner, &edge.callee));
        Some(CalleeReference {
            module: module.to_string(),
            symbol: symbol.to_string(),
        })
    }

    fn package_value(
        &self,
        registry: &ModuleRegistry,
        importer: &ModuleFile,
        name: &str,
    ) -> Option<SemanticValue> {
        go_package_value(registry, importer, name)
    }
    fn package_value_in_scope(
        &self,
        registry: &ModuleRegistry,
        importer: &ModuleFile,
        scope: &effinterp_engine::ScopeKey,
        name: &str,
    ) -> Option<SemanticValue> {
        go_package_value_in_scope(registry, importer, scope, name)
    }

    fn package_bindings(
        &self,
        registry: &ModuleRegistry,
        importer: &ModuleFile,
    ) -> HashMap<String, SemanticValue> {
        go_package_bindings(registry, importer)
    }
    fn callee_is_rebound(
        &self,
        registry: &ModuleRegistry,
        importer: &ModuleFile,
        callee: &str,
    ) -> bool {
        go_rebound_callee(registry, importer, callee)
    }
    fn rebound_callee<'a>(
        &self,
        registry: &'a ModuleRegistry,
        importer: &'a ModuleFile,
        callee: &str,
    ) -> Option<(&'a ModuleFile, String)> {
        let scope = importer.summary.linkage.scope.as_ref()?;
        go_package_files(registry, importer, scope)
            .find(|file| file.summary.module_values.contains_key(callee))
            .map(|file| (file, callee.to_string()))
    }
    fn module_binding_candidate(
        &self,
        registry: &ModuleRegistry,
        importer: &ModuleFile,
        file: &ModuleFile,
    ) -> bool {
        !file.path.ends_with("_test.go")
            && registry.go_packages.get(&file.path) == registry.go_packages.get(&importer.path)
    }
    fn constructor_has_fields(&self) -> bool {
        true
    }
    fn constructor_result_is_instance(&self, edge: &effinterp_engine::CallEdge) -> bool {
        edge.result_bindings().next().is_some()
    }
    fn callbacks_escape(&self) -> bool {
        true
    }
    fn resolve_returned_instance(&self) -> bool {
        true
    }
    fn semantic_external_effects(
        &self,
        module: &str,
        member: &str,
        values: &[SemanticValue],
    ) -> Option<Vec<Effect>> {
        effinterp_engine::go_external_effects(module, member, values)
    }

    fn resolve_callee<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a> {
        let (head, member) = match callee.split_once('.') {
            Some(parts) => parts,
            None => {
                if let Some(binding) = find_import(file, callee)
                    && let Some(imported) = &binding.imported
                {
                    return go_resolve_to(reg, file, binding, imported);
                }
                if file.function(callee).is_some() {
                    return Resolution::Local;
                }
                return go_sibling(reg, file, callee)
                    .map(|target| one(target, callee.to_string(), Assurance::Exact))
                    .unwrap_or(Resolution::Unknown);
            }
        };
        if let Some(binding) = find_import(file, head) {
            return go_resolve_to(reg, file, binding, member);
        }
        Resolution::Unknown
    }

    fn class_candidates<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)> {
        let mut candidates = standard_class_candidates(self, reg, file, name);
        if !candidates.is_empty() {
            return candidates;
        }
        if let Some((head, rest)) = name.split_once('.') {
            if let Some(binding) = find_import(file, head)
                && let Some(package_file) = reg.resolve_import(file, binding)
                && let Some(target) = go_class(reg, package_file, rest)
            {
                candidates.push((instance(target, rest), Assurance::Exact));
            }
        } else if let Some(target) = go_class(reg, file, name) {
            candidates.push((instance(target, name), Assurance::Exact));
        }
        candidates
    }

    fn resolve_method<'a>(
        &self,
        reg: &'a ModuleRegistry,
        inst: &ResolvedObject,
        method: &str,
    ) -> Resolution<'a> {
        let common = resolve_common_method(self, reg, inst, method);
        if !matches!(common, Resolution::Unknown) {
            return common;
        }
        let interface = go_dispatch_targets(self, reg, inst, method);
        if !matches!(interface, Resolution::Unknown) {
            return interface;
        }
        let Some(file) = reg.files.get(&inst.file) else {
            return Resolution::Unknown;
        };
        let qualified = format!("{}.{method}", inst.class_name);
        go_sibling(reg, file, &qualified)
            .map(|target| one(target, qualified, Assurance::Exact))
            .unwrap_or(Resolution::Unknown)
    }

    fn classify_external(
        &self,
        _reg: &ModuleRegistry,
        module: &str,
        member: &str,
        _arity: Option<usize>,
    ) -> Option<ExternalCall> {
        classify_go_call(module, member)
    }

    fn classify_import(
        &self,
        _reg: &ModuleRegistry,
        _file: &ModuleFile,
        _spec: &str,
    ) -> Option<ExternalCall> {
        None
    }

    fn execution_roots<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
    ) -> Vec<(&'a ModuleFile, Option<&'a str>)> {
        let package = reg.go_packages.get(&file.path);
        let files: Vec<_> = reg
            .files
            .values()
            .map(|file| file.as_ref())
            .filter(|target| {
                target.summary.linkage.scope == file.summary.linkage.scope
                    && target.dir == file.dir
                    && !target.path.ends_with("_test.go")
                    && reg.go_packages.get(&target.path) == package
            })
            .collect();
        let mut roots: Vec<(&ModuleFile, Option<&str>)> =
            files.iter().copied().map(|target| (target, None)).collect();
        for target in files {
            let mut functions: Vec<_> = target
                .summary
                .functions
                .iter()
                .filter(|function| function.name.starts_with("init#"))
                .collect();
            functions.sort_by_key(|function| {
                function.name["init#".len()..]
                    .parse::<usize>()
                    .unwrap_or(usize::MAX)
            });
            roots.extend(
                functions
                    .into_iter()
                    .map(|function| (target, Some(function.name.as_str()))),
            );
        }
        roots
    }

    fn is_constructor_fact(&self, edge: &effinterp_engine::CallEdge) -> bool {
        if edge.result_bindings().next().is_some() {
            return edge.result_type().is_some();
        }
        match edge.result_type() {
            Some(TypeRef::Repo { name, .. }) => {
                edge.callee.rsplit('.').next() == Some(name.as_str())
            }
            Some(TypeRef::External { path }) => path.ends_with(&edge.callee),
            None => false,
        }
    }
}

fn go_package_value(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    name: &str,
) -> Option<SemanticValue> {
    let scope = importer.summary.linkage.scope.as_ref()?;
    let value = go_package_value_in_scope(registry, importer, scope, name)?;
    Some(resolve_package_value_at(
        registry,
        importer,
        &value,
        &mut HashSet::new(),
        0,
    ))
}

/// The selected build files of the Go package `importer` belongs to.
fn go_package_files<'a>(
    registry: &'a ModuleRegistry,
    importer: &'a ModuleFile,
    scope: &'a effinterp_engine::ScopeKey,
) -> impl Iterator<Item = &'a ModuleFile> {
    let package = registry.go_packages.get(&importer.path);
    registry
        .files
        .values()
        .map(|file| file.as_ref())
        .filter(move |file| {
            file.lang == effinterp_engine::Lang::Go
                && file.dir == importer.dir
                && !file.path.ends_with("_test.go")
                && file.summary.linkage.scope.as_ref() == Some(scope)
                && registry.go_packages.get(&file.path) == package
        })
}

fn go_package_value_in_scope(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    scope: &effinterp_engine::ScopeKey,
    name: &str,
) -> Option<SemanticValue> {
    if importer.lang != effinterp_engine::Lang::Go {
        return None;
    }
    // A package variable any file of the package assigns is not its
    // initializer: the value published here describes only the declaration, so
    // substituting it would state an exact value the program may never hold.
    if go_package_rebinds(registry, importer, scope, name) {
        return None;
    }
    let mut values = go_package_files(registry, importer, scope)
        .filter_map(|file| file.summary.module_values.get(name).cloned());
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

/// Whether any file assigns `name` outside its declaration: a file of the Go
/// package itself, or one of another package writing it through the import
/// qualifier (`lib.Target = ...`).
fn go_package_rebinds(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    scope: &effinterp_engine::ScopeKey,
    name: &str,
) -> bool {
    go_package_files(registry, importer, scope)
        .any(|file| file.summary.module_value_rebindings.contains(name))
        || go_importer_rebinds(registry, importer, name)
}

/// Whether a file importing the Go package `importer` belongs to assigns its
/// exported `name`. The frontend records such a write under the qualifier the
/// importing file used, so the qualifier is resolved back to the package here.
fn go_importer_rebinds(registry: &ModuleRegistry, importer: &ModuleFile, name: &str) -> bool {
    registry.files.values().any(|file| {
        file.lang == effinterp_engine::Lang::Go
            && !file.summary.module_value_rebindings.is_empty()
            && file
                .summary
                .imports
                .iter()
                .chain(&file.summary.scoped_imports)
                .any(|import| {
                    file.summary
                        .module_value_rebindings
                        .contains(&format!("{}.{name}", import.local))
                        && registry
                            .resolve_import(file, import)
                            .is_some_and(|target| target.dir == importer.dir)
                })
    })
}

/// A call through a package variable the package reassigns: the target is
/// whatever the variable holds when the call runs, never the declaration's
/// initializer.
fn go_rebound_callee(registry: &ModuleRegistry, importer: &ModuleFile, callee: &str) -> bool {
    if importer.lang != effinterp_engine::Lang::Go || callee.contains('.') {
        return false;
    }
    let Some(scope) = importer.summary.linkage.scope.as_ref() else {
        return false;
    };
    go_package_rebinds(registry, importer, scope, callee)
}

fn go_package_bindings(
    registry: &ModuleRegistry,
    target: &ModuleFile,
) -> HashMap<String, SemanticValue> {
    if target.lang != effinterp_engine::Lang::Go {
        return HashMap::new();
    }
    registry
        .files
        .values()
        .filter(|file| {
            file.lang == effinterp_engine::Lang::Go
                && file.dir == target.dir
                && file.summary.linkage.scope == target.summary.linkage.scope
                && registry.go_packages.get(&file.path) == registry.go_packages.get(&target.path)
        })
        .flat_map(|file| file.summary.module_values.keys())
        .filter_map(|name| {
            go_package_value(registry, target, name).map(|value| (name.clone(), value))
        })
        .chain(go_imported_package_bindings(registry, target))
        .collect()
}

/// The package values an importing file reads through its import qualifier
/// (`lib.Target`), bound under the qualified name the reader spells. The value
/// is resolved in the imported package's own scope, so a variable any file
/// assigns is refused there exactly as it is for a reader inside the package.
fn go_imported_package_bindings(
    registry: &ModuleRegistry,
    target: &ModuleFile,
) -> Vec<(String, SemanticValue)> {
    let mut out = Vec::new();
    for import in target
        .summary
        .imports
        .iter()
        .chain(&target.summary.scoped_imports)
    {
        let Some(dependency) = registry.resolve_import(target, import) else {
            continue;
        };
        if dependency.lang != effinterp_engine::Lang::Go || dependency.path == target.path {
            continue;
        }
        let Some(scope) = dependency.summary.linkage.scope.as_ref() else {
            continue;
        };
        for name in go_package_files(registry, dependency, scope)
            .flat_map(|file| file.summary.module_values.keys())
            .cloned()
            .collect::<BTreeSet<String>>()
        {
            // Only an exported name is visible to the importer.
            if !name.chars().next().is_some_and(char::is_uppercase) {
                continue;
            }
            if let Some(value) = go_package_value(registry, dependency, &name) {
                out.push((format!("{}.{name}", import.local), value));
            }
        }
    }
    out
}
