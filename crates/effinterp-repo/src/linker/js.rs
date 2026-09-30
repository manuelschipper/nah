use super::*;

pub(crate) struct JsLinker;

const MAX_JS_CHASE: usize = 64;
const JS_EXPORTS: &str = "<exports>";

#[derive(Debug, Clone)]
enum JsName<'a> {
    Function(&'a ModuleFile, String),
    External(String),
    ExternalFn(String, String),
}

impl PartialEq for JsName<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Function(a, an), Self::Function(b, bn)) => a.path == b.path && an == bn,
            (Self::External(a), Self::External(b)) => a == b,
            (Self::ExternalFn(am, af), Self::ExternalFn(bm, bf)) => am == bm && af == bf,
            _ => false,
        }
    }
}

fn resolve_js_name<'a>(
    reg: &'a Registry,
    file: &'a ModuleFile,
    name: &str,
    require_export: bool,
    seen: &mut HashSet<(String, String)>,
) -> Option<JsName<'a>> {
    if seen.len() >= MAX_JS_CHASE || !seen.insert((file.path.clone(), name.to_string())) {
        return None;
    }
    let function = if require_export {
        imported_function_name(file, name)
    } else {
        file.function(name).map(|_| name.to_string())
    };
    if let Some(function) = function {
        return Some(JsName::Function(file, function));
    }
    let binding = if require_export {
        file.summary
            .exports
            .iter()
            .find(|binding| binding.local == name)
    } else {
        find_import(file, name)
    };
    if let Some(binding) = binding {
        return match reg.resolve_import(file, binding) {
            Some(target) => match &binding.imported {
                Some(original) => resolve_js_name(reg, target, original, true, seen),
                None => None,
            },
            None => match &binding.imported {
                None => Some(JsName::External(binding.module.clone())),
                Some(original) => {
                    Some(JsName::ExternalFn(binding.module.clone(), original.clone()))
                }
            },
        };
    }
    let mut found = Vec::new();
    if name == "default" {
        return None;
    }
    for star in file
        .summary
        .exports
        .iter()
        .filter(|binding| binding.local == "*")
    {
        if let Some(target) = reg.resolve_import(file, star)
            && let Some(resolved) = resolve_js_name(reg, target, name, true, seen)
            && !found.contains(&resolved)
        {
            found.push(resolved);
        }
    }
    match found.as_slice() {
        [_] => found.pop(),
        _ => None,
    }
}
impl Linker for JsLinker {
    fn subprocess_boundary_domains(&self) -> Vec<String> {
        effinterp_engine::ALL_DOMAINS
            .iter()
            .map(|domain| (*domain).to_string())
            .collect()
    }

    fn import_call_reference(
        &self,
        importer: &ModuleFile,
        edge: &effinterp_engine::CallEdge,
    ) -> Option<CalleeReference> {
        let callee = &edge.callee;
        let (local, suffix) = callee.split_once('.').unwrap_or((callee, ""));
        let binding = find_import(importer, local)?;
        let symbol = match (&binding.imported, suffix) {
            (Some(imported), "") => imported.clone(),
            (Some(imported), suffix) => format!("{imported}.{suffix}"),
            (None, suffix) if !suffix.is_empty() => binding
                .module
                .strip_prefix(local)
                .and_then(|module_suffix| module_suffix.strip_prefix('.'))
                .and_then(|module_suffix| suffix.strip_prefix(module_suffix))
                .and_then(|symbol| symbol.strip_prefix('.'))
                .unwrap_or(suffix)
                .to_string(),
            (None, _) => return None,
        };
        Some(CalleeReference {
            module: binding.module.clone(),
            symbol,
        })
    }
    fn import_dispatch_reference(
        &self,
        registry: &Registry,
        importer: &ModuleFile,
        edge: &effinterp_engine::CallEdge,
        instance: &ResolvedObject,
        method: &str,
    ) -> Option<CalleeReference> {
        let receiver_name = match edge.receiver_identity() {
            Some(ObjectIdentity::Class { name, .. }) => name.as_str(),
            _ => instance.class_name.as_str(),
        };
        let binding = importer.summary.imports.iter().find(|binding| {
            (binding.local == receiver_name
                || binding.imported.as_deref() == Some(instance.class_name.as_str()))
                && registry
                    .resolve_import(importer, binding)
                    .is_some_and(|target| target.path == instance.file)
        })?;
        let symbol = match &binding.imported {
            Some(imported) => format!("{imported}.{method}"),
            None => method.to_string(),
        };
        Some(CalleeReference {
            module: binding.module.clone(),
            symbol,
        })
    }
    fn unresolved_call_is_boundary(&self) -> bool {
        true
    }

    fn resolve_callee<'a>(
        &self,
        reg: &'a Registry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a> {
        if let Some((head, member)) = callee.split_once('.') {
            match resolve_js_name(reg, file, head, false, &mut HashSet::new()) {
                Some(JsName::External(module)) => {
                    return Resolution::External {
                        module,
                        member: member.to_string(),
                    };
                }
                Some(JsName::ExternalFn(module, function)) => {
                    return if function == "promises" {
                        Resolution::External {
                            module: format!("{module}/{function}"),
                            member: member.to_string(),
                        }
                    } else if function == "default" {
                        Resolution::External {
                            module,
                            member: member.to_string(),
                        }
                    } else {
                        Resolution::External {
                            module,
                            member: format!("{function}.{member}"),
                        }
                    };
                }
                _ => {}
            }
        }
        if !callee.contains('.')
            && let Some(binding) = find_import(file, callee)
            && binding.imported.is_none()
            && let Some(target) = reg.resolve_import(file, binding)
            && let Some(default) = imported_function_name(target, "default")
        {
            return one(target, default, Assurance::Exact);
        }
        let common = resolve_standard_callee(self, reg, file, callee);
        let Resolution::Targets(targets) = common else {
            return common;
        };
        let [(target, name, assurance)] = targets.as_slice() else {
            return Resolution::Targets(targets);
        };
        if target.function(name).is_some() {
            return Resolution::Targets(targets);
        }
        match resolve_js_name(reg, target, name, true, &mut HashSet::new()) {
            Some(JsName::Function(definition, function)) => one(definition, function, *assurance),
            Some(JsName::External(module)) => Resolution::External {
                module,
                member: name.clone(),
            },
            Some(JsName::ExternalFn(module, function)) => Resolution::External {
                module,
                member: function,
            },
            None => Resolution::Unknown,
        }
    }

    fn class_candidates<'a>(
        &self,
        reg: &'a Registry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)> {
        let standard = standard_class_candidates(self, reg, file, name);
        if !standard.is_empty() {
            return standard;
        }
        let Some(binding) = find_import(file, name) else {
            return Vec::new();
        };
        let Some(target) = reg.resolve_import(file, binding) else {
            return Vec::new();
        };
        for candidate in ["default", name] {
            if let Some(local) = imported_class_name(target, candidate) {
                return vec![(instance(target, &local), Assurance::Exact)];
            }
        }
        for candidate in [binding.imported.as_deref().unwrap_or("default"), name] {
            if let Some((definition, resolved)) = resolve_export_class(reg, target, candidate) {
                return vec![(instance(definition, &resolved), Assurance::Exact)];
            }
        }
        if binding.imported.is_none() {
            vec![(instance(target, JS_EXPORTS), Assurance::Exact)]
        } else {
            Vec::new()
        }
    }

    fn resolve_method<'a>(
        &self,
        reg: &'a Registry,
        inst: &ResolvedObject,
        method: &str,
    ) -> Resolution<'a> {
        if inst.class_name == JS_EXPORTS
            && let Some(file) = reg.files.get(&inst.file)
            && let Some(local) = imported_function_name(file, method)
        {
            return one(file, local, Assurance::Exact);
        }
        resolve_common_method(self, reg, inst, method)
    }

    fn classify_external(
        &self,
        _reg: &Registry,
        module: &str,
        member: &str,
        _arity: Option<usize>,
    ) -> Option<ExternalCall> {
        if effinterp_engine::js_external_effects(module, member, &[]).is_some() {
            Some(ExternalCall::Modeled)
        } else {
            Some(ExternalCall::Unmodeled(effinterp_engine::ALL_DOMAINS))
        }
    }

    fn classify_import(
        &self,
        _reg: &Registry,
        _file: &ModuleFile,
        _spec: &str,
    ) -> Option<ExternalCall> {
        None
    }

    fn execution_roots<'a>(
        &self,
        _reg: &'a Registry,
        _file: &'a ModuleFile,
    ) -> Vec<(&'a ModuleFile, Option<&'a str>)> {
        Vec::new()
    }

    fn external_effects(
        &self,
        module: &str,
        member: &str,
        args: &[ResourceExpr],
    ) -> Option<Vec<Effect>> {
        effinterp_engine::js_external_effects(module, member, args)
    }
}
