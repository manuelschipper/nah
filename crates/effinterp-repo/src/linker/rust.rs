use std::collections::{BTreeSet, HashSet};

use effinterp_engine::{
    Assurance, DispatchSignature, DispatchStyle, ExternalCall, ImportBinding, ObjectIdentity,
    ResolvedObject, SemanticValue, SemanticValueKind, TypeRef, canonical_rust_std_type,
    classify_rust_call, rust_inert_receiver_method,
};
use effinterp_proto::BoundaryReason;

use super::{
    Linker, MAX_DISPATCH_CANDIDATES, MAX_EXPORT_CHASE, Resolution, bounded_dispatch, class_defined,
    dedup_targets, dispatch_contract, excluded_dispatch_file, find_import, imported_class_name,
    imported_function_name, instance, one, resolve_common_method, resolve_export,
    resolve_export_class, resolve_standard_callee, resolves_contract, standard_class_candidates,
    wildcard_exports,
};
use crate::module::{ModuleFile, ModuleRegistry};

pub(crate) struct RustLinker;

fn rust_dispatch_targets<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    inst: &ResolvedObject,
    method: &str,
) -> Resolution<'a> {
    let Some((contract_file, contract)) = dispatch_contract(reg, inst) else {
        return Resolution::Unknown;
    };
    if !contract.methods.iter().any(|candidate| candidate == method) {
        return Resolution::Unknown;
    }
    let required_signature = contract
        .method_signatures
        .iter()
        .find(|(name, _)| name == method)
        .map(|(_, signature)| signature);
    let suffix = format!(".{method}");
    let mut targets = Vec::new();
    for file in reg.files.values().map(|file| file.as_ref()) {
        if file.summary.linkage.dispatch != DispatchStyle::Trait
            || excluded_dispatch_file(&file.path)
        {
            continue;
        }
        for function in &file.summary.functions {
            let Some(implementation) = function.dispatch_impl.as_ref() else {
                continue;
            };
            let receiver =
                rust_type_identity(reg, file, &implementation.receiver, &mut HashSet::new())
                    .unwrap_or_else(|| implementation.receiver.clone());
            if !function.name.ends_with(&suffix)
                || function.name.matches('.').count() != 1
                || !required_signature.is_some_and(|required| {
                    function
                        .dispatch_signature
                        .as_ref()
                        .is_some_and(|candidate| {
                            rust_dispatch_signatures_match(
                                reg,
                                file,
                                candidate,
                                contract_file,
                                required,
                                &receiver,
                                &implementation.type_arguments,
                            )
                        })
                })
                || !resolves_contract(
                    linker,
                    reg,
                    file,
                    &implementation.contract,
                    &contract_file.path,
                    &contract.name,
                )
            {
                continue;
            }
            targets.push((file, function.name.clone(), Assurance::Exact));
        }
    }
    bounded_dispatch(targets, |count| {
        format!(
            "trait {} method {method:?} has {count} typed candidates",
            contract.name
        )
    })
}

fn rust_type_identity(
    reg: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
    seen: &mut HashSet<(String, String)>,
) -> Option<String> {
    if seen.len() >= MAX_EXPORT_CHASE || !seen.insert((file.path.clone(), name.to_string())) {
        return None;
    }
    let local = name.rsplit("::").next().filter(|part| !part.is_empty())?;
    if rust_type_defined(file, local) {
        return Some(format!("{}::{local}", file.path));
    }
    if name.contains("::") {
        let binding = ImportBinding {
            local: local.to_string(),
            module: name.to_string(),
            imported: Some(local.to_string()),
        };
        if let Some(target) = reg.resolve_import(file, &binding) {
            if rust_type_defined(target, local) {
                return Some(format!("{}::{local}", target.path));
            }
            if let Some((definition, resolved)) = resolve_export_rust_type(reg, target, local) {
                return Some(format!("{}::{resolved}", definition.path));
            }
        }
        return canonical_rust_std_type(name).or_else(|| Some(name.to_string()));
    }
    for binding in file
        .summary
        .imports
        .iter()
        .chain(&file.summary.scoped_imports)
        .filter(|binding| binding.local == name || binding.local == "*")
    {
        if let Some(target) = reg.resolve_import(file, binding) {
            let imported = if binding.local == "*" {
                name
            } else {
                binding.imported.as_deref().unwrap_or(name)
            };
            if rust_type_defined(target, imported) {
                return Some(format!("{}::{imported}", target.path));
            }
            if let Some((definition, resolved)) = resolve_export_rust_type(reg, target, imported) {
                return Some(format!("{}::{resolved}", definition.path));
            }
            if let Some(identity) = rust_type_identity(reg, target, imported, seen) {
                return Some(identity);
            }
        } else if binding.local == name {
            return canonical_rust_std_type(&binding.module)
                .or_else(|| Some(binding.module.clone()));
        }
    }
    canonical_rust_std_type(name)
}

fn rust_type_defined(file: &ModuleFile, name: &str) -> bool {
    class_defined(file, name)
        || file
            .summary
            .dispatch_type_aliases
            .iter()
            .any(|(alias, _)| alias == name)
}

fn resolve_export_rust_type<'a>(
    reg: &'a ModuleRegistry,
    file: &'a ModuleFile,
    name: &str,
) -> Option<(&'a ModuleFile, String)> {
    fn resolve<'a>(
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
        seen: &mut HashSet<(String, String)>,
    ) -> Option<(&'a ModuleFile, String)> {
        if seen.len() >= MAX_EXPORT_CHASE || !seen.insert((file.path.clone(), name.to_string())) {
            return None;
        }
        if rust_type_defined(file, name) {
            return Some((file, name.to_string()));
        }
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
            if let Some(found) = resolve(reg, target, target_name, seen)
                && !targets.iter().any(|(file, name): &(&ModuleFile, String)| {
                    file.path == found.0.path && name == &found.1
                })
            {
                targets.push(found);
            }
        }
        (targets.len() == 1).then(|| targets.pop().unwrap())
    }

    resolve(reg, file, name, &mut HashSet::new())
}

fn rust_dispatch_signatures_match(
    reg: &ModuleRegistry,
    left_file: &ModuleFile,
    left: &DispatchSignature,
    right_file: &ModuleFile,
    right: &DispatchSignature,
    receiver: &str,
    trait_arguments: &[String],
) -> bool {
    left.params.len() == right.params.len()
        && left.results.len() == right.results.len()
        && left.params.iter().zip(&right.params).all(|(left, right)| {
            !left.contains("<unsupported>")
                && !right.contains("<unsupported>")
                && canonical_rust_signature_type(reg, left_file, left, receiver)
                    == specialize_rust_trait_type(
                        reg,
                        left_file,
                        right_file,
                        right,
                        receiver,
                        trait_arguments,
                    )
        })
        && left
            .results
            .iter()
            .zip(&right.results)
            .all(|(left, right)| {
                !left.contains("<unsupported>")
                    && !right.contains("<unsupported>")
                    && canonical_rust_signature_type(reg, left_file, left, receiver)
                        == specialize_rust_trait_type(
                            reg,
                            left_file,
                            right_file,
                            right,
                            receiver,
                            trait_arguments,
                        )
            })
}

fn specialize_rust_trait_type(
    reg: &ModuleRegistry,
    impl_file: &ModuleFile,
    contract_file: &ModuleFile,
    typ: &str,
    receiver: &str,
    trait_arguments: &[String],
) -> String {
    let mut typ = canonical_rust_signature_type(reg, contract_file, typ, receiver);
    for (index, argument) in trait_arguments.iter().enumerate().rev() {
        typ = typ.replace(
            &format!("$trait{index}"),
            &canonical_rust_signature_type(reg, impl_file, argument, receiver),
        );
    }
    typ
}

fn canonical_rust_signature_type(
    reg: &ModuleRegistry,
    file: &ModuleFile,
    typ: &str,
    receiver: &str,
) -> String {
    let chars: Vec<_> = typ.chars().collect();
    let mut out = String::with_capacity(typ.len());
    let mut index = 0;
    let mut in_abi = false;
    while index < chars.len() {
        if (chars[index] == '_' || chars[index].is_alphabetic())
            && (index == 0 || chars[index - 1] != '\'')
        {
            let start = index;
            index += 1;
            while index < chars.len() && (chars[index] == '_' || chars[index].is_alphanumeric()) {
                index += 1;
            }
            while index + 2 < chars.len()
                && chars[index] == ':'
                && chars[index + 1] == ':'
                && (chars[index + 2] == '_' || chars[index + 2].is_alphabetic())
            {
                index += 3;
                while index < chars.len() && (chars[index] == '_' || chars[index].is_alphanumeric())
                {
                    index += 1;
                }
            }
            let written: String = chars[start..index].iter().collect();
            if written == "Self" {
                out.push_str(receiver);
            } else if in_abi
                || start > 0 && chars[start - 1] == '$'
                || matches!(
                    written.as_str(),
                    "self"
                        | "mut"
                        | "const"
                        | "impl"
                        | "fn"
                        | "unsafe"
                        | "extern"
                        | "true"
                        | "false"
                )
            {
                in_abi = written == "extern" || in_abi;
                out.push_str(&written);
            } else {
                out.push_str(
                    &rust_type_identity(reg, file, &written, &mut HashSet::new())
                        .unwrap_or(written),
                );
            }
        } else {
            out.push(chars[index]);
            if in_abi && chars[index].is_whitespace() {
                in_abi = false;
            }
            index += 1;
        }
    }
    out
}

fn rust_receiver_trait_targets<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    inst: &ResolvedObject,
    method: &str,
) -> Resolution<'a> {
    let external_matches_repository = matches!(
        &inst.ty,
        Some(TypeRef::External { path })
            if path.rsplit("::").next() == Some(inst.class_name.as_str())
                && reg
                    .files
                    .get(&inst.file)
                    .is_some_and(|file| rust_type_defined(file, &inst.class_name))
    );
    let receiver_identity = match &inst.ty {
        Some(TypeRef::External { .. }) if external_matches_repository => {
            format!("{}::{}", inst.file, inst.class_name)
        }
        Some(TypeRef::External { path }) => {
            canonical_rust_std_type(path).unwrap_or_else(|| path.clone())
        }
        Some(TypeRef::Repo { file, name }) => format!("{file}::{name}"),
        None => inst.class_name.clone(),
    };
    let receiver = match &inst.ty {
        Some(TypeRef::External { .. }) if external_matches_repository => inst.class_name.as_str(),
        Some(TypeRef::External { .. }) | Some(TypeRef::Repo { .. }) => receiver_identity
            .rsplit("::")
            .find(|part| !part.is_empty())
            .unwrap_or(&receiver_identity),
        None => inst
            .class_name
            .rsplit([':', '.'])
            .find(|part| !part.is_empty())
            .unwrap_or(&inst.class_name),
    }
    .to_string();
    if receiver.is_empty() {
        return Resolution::Unknown;
    }
    let receiver_identity = match &inst.ty {
        Some(_) => receiver_identity,
        None => reg
            .files
            .get(&inst.file)
            .and_then(|file| rust_type_identity(reg, file, &receiver, &mut HashSet::new()))
            .unwrap_or_else(|| inst.class_name.clone()),
    };
    let expected = format!("{receiver}.{method}");
    let mut targets = Vec::new();
    for file in reg.files.values().map(|file| file.as_ref()) {
        if file.summary.linkage.dispatch != DispatchStyle::Trait
            || excluded_dispatch_file(&file.path)
        {
            continue;
        }
        for function in &file.summary.functions {
            let Some(implementation) = function.dispatch_impl.as_ref() else {
                continue;
            };
            let Some(implementation_receiver) =
                rust_type_identity(reg, file, &implementation.receiver, &mut HashSet::new())
            else {
                continue;
            };
            if function.name != expected || implementation_receiver != receiver_identity {
                continue;
            }
            let declared = linker
                .class_candidates(reg, file, &implementation.contract)
                .into_iter()
                .any(|(candidate, assurance)| {
                    assurance == Assurance::Exact
                        && reg.files.get(&candidate.file).is_some_and(|definition| {
                            definition
                                .summary
                                .dispatch_contracts
                                .iter()
                                .any(|declared| {
                                    declared.name == candidate.class_name
                                        && declared.methods.iter().any(|name| name == method)
                                        && declared
                                            .method_signatures
                                            .iter()
                                            .find(|(name, _)| name == method)
                                            .is_some_and(|(_, required)| {
                                                function.dispatch_signature.as_ref().is_some_and(
                                                    |candidate| {
                                                        rust_dispatch_signatures_match(
                                                            reg,
                                                            file,
                                                            candidate,
                                                            definition,
                                                            required,
                                                            &implementation_receiver,
                                                            &implementation.type_arguments,
                                                        )
                                                    },
                                                )
                                            })
                                })
                        })
                });
            if declared {
                targets.push((file, function.name.clone(), Assurance::Exact));
            }
        }
    }
    dedup_targets(&mut targets);
    match targets.len() {
        0 => Resolution::Unknown,
        1 => Resolution::Targets(targets),
        2..=MAX_DISPATCH_CANDIDATES => {
            for target in &mut targets {
                target.2 = Assurance::Alternatives;
            }
            Resolution::Targets(targets)
        }
        count => Resolution::Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            detail: format!(
                "receiver {receiver} method {method:?} has {count} typed trait candidates"
            ),
        },
    }
}

fn rust_glob<'a>(
    reg: &'a ModuleRegistry,
    file: &ModuleFile,
    name: &str,
) -> Option<(&'a ModuleFile, String)> {
    for binding in &file.summary.imports {
        if binding.local != "*" {
            continue;
        }
        let Some(target) = reg.resolve_import(file, binding) else {
            continue;
        };
        if let Some(local) =
            imported_class_name(target, name).or_else(|| imported_function_name(target, name))
        {
            return Some((target, local));
        }
        if let Resolution::Targets(mut targets) = resolve_export(reg, target, name)
            && targets.len() == 1
        {
            let (file, resolved, _) = targets.pop().unwrap();
            return Some((file, resolved));
        }
        if let Some(resolved) = resolve_export_class(reg, target, name) {
            return Some(resolved);
        }
    }
    None
}

impl Linker for RustLinker {
    fn declared_result_value(
        &self,
        value: SemanticValue,
        value_limits: effinterp_engine::ValueLimits,
    ) -> SemanticValue {
        successful_rust_value(value, value_limits)
    }
    fn unresolved_method_detail(
        &self,
        insts: &[ResolvedObject],
        method: &str,
        edge: &effinterp_engine::CallEdge,
        exact_repository_receivers: bool,
    ) -> Option<String> {
        let receiver_types: BTreeSet<_> = insts
            .iter()
            .filter_map(|inst| match &inst.ty {
                Some(TypeRef::External { path }) => canonical_rust_std_type(path),
                _ => None,
            })
            .collect();
        let proven_std_receiver = receiver_types.len() == 1
            && insts.iter().all(|inst| {
                matches!(
                    &inst.ty,
                    Some(TypeRef::External { path })
                        if canonical_rust_std_type(path).is_some()
                )
            });
        if proven_std_receiver {
            let receiver_type = receiver_types.first().expect("one receiver type");
            let positional_arity = edge
                .arguments
                .iter()
                .filter(|argument| argument.name.is_none())
                .count();
            (!rust_inert_receiver_method(receiver_type, method, positional_arity)).then(|| {
                format!("{method} not classified as inert on proven receiver {receiver_type}")
            })
        } else if exact_repository_receivers {
            Some(format!("{method} not found on exact repository receiver"))
        } else {
            let external_types: BTreeSet<_> = insts
                .iter()
                .filter_map(|inst| match &inst.ty {
                    Some(TypeRef::External { path }) => Some(path.as_str()),
                    _ => None,
                })
                .collect();
            Some(
                match external_types
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .as_slice()
                {
                    [receiver_type] => {
                        format!("{method} unresolved on receiver {receiver_type}")
                    }
                    _ => format!("{method} unresolved on mixed or unproven receiver"),
                },
            )
        }
    }

    fn resolve_callee<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a> {
        if !callee.contains('.')
            && file
                .summary
                .exports
                .iter()
                .any(|binding| binding.local == callee)
        {
            return resolve_export(reg, file, callee);
        }
        let common = resolve_standard_callee(self, reg, file, callee);
        if !matches!(common, Resolution::Unknown) || callee.contains('.') {
            return common;
        }
        rust_glob(reg, file, callee)
            .filter(|(target, name)| target.function(name).is_some())
            .map(|(target, name)| one(target, name, Assurance::Exact))
            .unwrap_or(Resolution::Unknown)
    }

    fn class_candidates<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)> {
        let standard = standard_class_candidates(self, reg, file, name);
        if !standard.is_empty() {
            return standard;
        }
        if let Some(binding) = find_import(file, name)
            && let Some(target) = reg.resolve_import(file, binding)
        {
            let imported = binding.imported.as_deref().unwrap_or(name);
            if let Some((definition, resolved)) = resolve_export_class(reg, target, imported) {
                return vec![(instance(definition, &resolved), Assurance::Exact)];
            }
        }
        rust_glob(reg, file, name)
            .filter(|(target, resolved)| class_defined(target, resolved))
            .map(|(target, resolved)| vec![(instance(target, &resolved), Assurance::Exact)])
            .unwrap_or_default()
    }

    fn resolve_method<'a>(
        &self,
        reg: &'a ModuleRegistry,
        inst: &ResolvedObject,
        method: &str,
    ) -> Resolution<'a> {
        let exact_repository_receiver = matches!(
            &inst.ty,
            Some(TypeRef::External { path })
                if path.rsplit("::").next() == Some(inst.class_name.as_str())
                    && reg
                        .files
                        .get(&inst.file)
                        .is_some_and(|file| rust_type_defined(file, &inst.class_name))
        );
        if !matches!(inst.ty, Some(TypeRef::External { .. })) || exact_repository_receiver {
            let common = resolve_common_method(self, reg, inst, method);
            if !matches!(common, Resolution::Unknown) {
                return common;
            }
        }
        let receiver_traits = rust_receiver_trait_targets(self, reg, inst, method);
        if !matches!(receiver_traits, Resolution::Unknown) {
            return receiver_traits;
        }
        rust_dispatch_targets(self, reg, inst, method)
    }

    fn classify_external(
        &self,
        _reg: &ModuleRegistry,
        module: &str,
        member: &str,
        _arity: Option<usize>,
    ) -> Option<ExternalCall> {
        let canonical = if module.ends_with(member) {
            module.to_string()
        } else {
            format!("{module}::{member}")
        };
        classify_rust_call(&canonical)
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
        _reg: &'a ModuleRegistry,
        _file: &'a ModuleFile,
    ) -> Vec<(&'a ModuleFile, Option<&'a str>)> {
        Vec::new()
    }
}

fn successful_rust_value(
    value: SemanticValue,
    value_limits: effinterp_engine::ValueLimits,
) -> SemanticValue {
    match value.kind {
        SemanticValueKind::Alias { name, value }
            if name.starts_with("__effinterp_rust_branch:") =>
        {
            SemanticValue::new(SemanticValueKind::Alias {
                name,
                value: Box::new(successful_rust_value(*value, value_limits)),
            })
        }
        SemanticValueKind::Object(object) => {
            let variant = match &object.identity {
                ObjectIdentity::Class { name, .. } => name.as_str(),
                _ => return SemanticValue::new(SemanticValueKind::Object(object)),
            };
            match variant {
                "Ok" | "Some" => object
                    .properties
                    .get("0")
                    .cloned()
                    .map(|value| successful_rust_value(value, value_limits))
                    .unwrap_or_else(|| SemanticValue::unresolved("result")),
                "Err" | "None" => SemanticValue::unresolved("result"),
                _ => SemanticValue::new(SemanticValueKind::Object(object)),
            }
        }
        SemanticValueKind::Union(alternatives) => effinterp_engine::join_branches(
            alternatives
                .into_iter()
                .map(|value| successful_rust_value(value, value_limits)),
            value_limits,
        ),
        _ => value,
    }
}
