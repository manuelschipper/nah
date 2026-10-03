use super::*;

pub(crate) struct JavaLinker;

fn java_implements_contract(
    linker: &dyn Linker,
    reg: &ModuleRegistry,
    file: &ModuleFile,
    class: &str,
    contract_file: &str,
    contract_name: &str,
    seen: &mut HashSet<(String, String)>,
) -> bool {
    if !seen.insert((file.path.clone(), class.to_string())) {
        return false;
    }
    let Some(entry) = file
        .summary
        .classes
        .iter()
        .find(|entry| entry.name == class)
    else {
        return false;
    };
    for base in &entry.bases {
        for (candidate, assurance) in linker.class_candidates(reg, file, base) {
            if assurance != Assurance::Exact {
                continue;
            }
            if candidate.file == contract_file && candidate.class_name == contract_name {
                return true;
            }
            let Some(base_file) = reg.files.get(&candidate.file) else {
                continue;
            };
            if java_implements_contract(
                linker,
                reg,
                base_file,
                &candidate.class_name,
                contract_file,
                contract_name,
                seen,
            ) {
                return true;
            }
        }
    }
    false
}

fn java_dispatch_targets<'a>(
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
    let mut targets = Vec::new();
    for file in reg.files.values() {
        if file.summary.linkage.dispatch != DispatchStyle::Nominal
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
                || !java_implements_contract(
                    linker,
                    reg,
                    file,
                    &class.name,
                    &contract_file.path,
                    &contract.name,
                    &mut HashSet::new(),
                )
            {
                continue;
            }
            let candidate = instance(file, &class.name);
            if let Resolution::Targets(found) =
                resolve_method_in_class(linker, reg, &candidate, method, &mut HashSet::new())
            {
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

impl Linker for JavaLinker {
    fn resolve_callee<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a> {
        let Some((class, method)) = callee.split_once('.') else {
            return resolve_standard_callee(self, reg, file, callee);
        };
        let mut targets = Vec::new();
        for (candidate, assurance) in self.class_candidates(reg, file, class) {
            if let Resolution::Targets(found) =
                resolve_method_in_class(self, reg, &candidate, method, &mut HashSet::new())
            {
                targets.extend(
                    found
                        .into_iter()
                        .map(|(target, name, nested)| (target, name, assurance.max(nested))),
                );
            }
        }
        dedup_targets(&mut targets);
        match targets.len() {
            0 => resolve_standard_callee(self, reg, file, callee),
            1 => Resolution::Targets(targets),
            count => Resolution::Boundary {
                reason: BoundaryReason::REEXPORT_AMBIGUOUS,
                detail: format!("Java call {callee:?} has {count} inherited definitions"),
            },
        }
    }

    fn class_candidates<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)> {
        standard_class_candidates(self, reg, file, name)
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
        java_dispatch_targets(self, reg, inst, method)
    }

    fn classify_external(
        &self,
        _reg: &ModuleRegistry,
        module: &str,
        member: &str,
        _arity: Option<usize>,
    ) -> Option<ExternalCall> {
        classify_java_call(module, member)
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
