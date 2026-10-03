use super::*;

pub(crate) struct RubyLinker;

const MAX_RUBY_CLOSURE: usize = 128;

fn ruby_require_closure<'a>(reg: &'a ModuleRegistry, start: &ModuleFile) -> Vec<&'a ModuleFile> {
    let mut seen = HashSet::new();
    seen.insert(start.path.clone());
    let mut queue = VecDeque::new();
    for binding in start
        .summary
        .imports
        .iter()
        .chain(&start.summary.scoped_imports)
    {
        if binding.imported.is_none()
            && let Some(target) = reg.resolve_import(start, binding)
            && seen.insert(target.path.clone())
        {
            queue.push_back(target);
        }
    }
    let mut out = Vec::new();
    while let Some(file) = queue.pop_front() {
        if out.len() >= MAX_RUBY_CLOSURE {
            break;
        }
        out.push(file);
        for binding in file
            .summary
            .imports
            .iter()
            .chain(&file.summary.scoped_imports)
        {
            if binding.imported.is_none()
                && let Some(target) = reg.resolve_import(file, binding)
                && seen.insert(target.path.clone())
            {
                queue.push_back(target);
            }
        }
    }
    out
}

fn ruby_fallback_classes(
    reg: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
) -> Vec<ResolvedObject> {
    if name.contains('.') || name.contains("::") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for target in ruby_require_closure(reg, file).into_iter().chain(
        reg.files
            .values()
            .map(|file| file.as_ref())
            .filter(|target| target.summary.linkage.global_class_lookup),
    ) {
        if class_defined(target, name)
            && !out
                .iter()
                .any(|candidate: &ResolvedObject| candidate.file == target.path)
        {
            out.push(instance(target, name));
        }
    }
    out.sort_by(|a, b| {
        (a.file.as_str(), a.class_name.as_str()).cmp(&(b.file.as_str(), b.class_name.as_str()))
    });
    out
}

fn ruby_qualified_classes(
    reg: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
) -> Vec<ResolvedObject> {
    let mut matches = Vec::new();
    for target in std::iter::once(file).chain(ruby_require_closure(reg, file)) {
        if let Some((_, local)) = target
            .summary
            .exported_definitions
            .iter()
            .find(|(exported, local)| exported == name && class_defined(target, local))
        {
            let candidate = instance(target, local);
            if !matches.iter().any(|existing: &ResolvedObject| {
                existing.file == candidate.file && existing.class_name == candidate.class_name
            }) {
                matches.push(candidate);
            }
        }
    }
    matches
}

/// Resolve a qualified Ruby constant from exact namespace evidence, or from
/// the required file whose path mirrors the namespace.
fn ruby_constant_class(
    reg: &ModuleRegistry,
    file: &ModuleFile,
    name: &str,
) -> Option<ResolvedObject> {
    let (namespace, class) = name.rsplit_once("::").unwrap_or(("", name));
    if namespace.is_empty() {
        if class_defined(file, class) {
            return Some(instance(file, class));
        }
    } else {
        let mut qualified_matches = ruby_qualified_classes(reg, file, name);
        if qualified_matches.len() == 1 {
            return qualified_matches.pop();
        }
        if !qualified_matches.is_empty() {
            return Some(instance(file, name));
        }
    }
    let required_files = ruby_require_closure(reg, file);
    let mut expected = namespace
        .split("::")
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>();
    expected.push(class.to_ascii_lowercase());
    let suffix = format!("{}.rb", expected.join("/"));
    let required: HashSet<_> = required_files
        .into_iter()
        .map(|target| target.path.as_str())
        .collect();
    let mut matches = reg
        .files
        .values()
        .filter(|target| target.path.to_ascii_lowercase().ends_with(&suffix))
        .filter(|target| class_defined(target, class))
        .filter(|target| {
            required.contains(target.path.as_str())
                || reg.files.values().any(|loader| {
                    let loaded: HashSet<_> = loader
                        .summary
                        .imports
                        .iter()
                        .filter_map(|binding| reg.resolve_import(loader, binding))
                        .map(|loaded| loaded.path.as_str())
                        .collect();
                    loaded.contains(file.path.as_str()) && loaded.contains(target.path.as_str())
                })
        });
    let candidate = matches.next()?;
    matches.next().is_none().then(|| instance(candidate, class))
}

fn ruby_qualified_method<'a>(
    linker: &dyn Linker,
    reg: &'a ModuleRegistry,
    file: &'a ModuleFile,
    class: &str,
    method: &str,
) -> Resolution<'a> {
    let candidates = ruby_qualified_classes(reg, file, class);
    if candidates.is_empty()
        && reg.files.values().any(|target| {
            target
                .summary
                .exported_definitions
                .iter()
                .any(|(exported, local)| exported == class && class_defined(target, local))
        })
    {
        return Resolution::Boundary {
            reason: BoundaryReason::CROSS_MODULE,
            detail: format!("qualified Ruby class {class:?} has no loader evidence"),
        };
    }
    if candidates.len() > MAX_DISPATCH_CANDIDATES {
        return Resolution::Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            detail: format!(
                "qualified Ruby class {class:?} has {} loaded definitions",
                candidates.len()
            ),
        };
    }
    let mut targets = Vec::new();
    for candidate in candidates {
        if let Resolution::Targets(found) =
            resolve_method_in_class(linker, reg, &candidate, method, &mut HashSet::new())
        {
            targets.extend(found);
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
            detail: format!("method {method:?} has {count} reopened Ruby definitions"),
        },
    }
}

impl Linker for RubyLinker {
    fn qualified_class_dispatch(&self, class_name: &str) -> bool {
        class_name.contains("::")
    }

    fn resolve_callee<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a> {
        let common = resolve_standard_callee(self, reg, file, callee);
        if !matches!(common, Resolution::Unknown) || callee.contains('.') {
            return common;
        }
        let mut targets: Vec<_> = ruby_require_closure(reg, file)
            .into_iter()
            .filter(|target| target.function(callee).is_some())
            .map(|target| (target, callee.to_string(), Assurance::Heuristic))
            .collect();
        dedup_targets(&mut targets);
        match targets.len() {
            0 => Resolution::Unknown,
            1 => Resolution::Targets(targets),
            count => Resolution::Boundary {
                reason: BoundaryReason::REEXPORT_AMBIGUOUS,
                detail: format!("Ruby definition {callee:?} has {count} required origins"),
            },
        }
    }

    fn class_candidates<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)> {
        let exact = standard_class_candidates(self, reg, file, name);
        if !exact.is_empty() {
            return exact;
        }
        if let Some(candidate) = ruby_constant_class(reg, file, name) {
            return vec![(candidate, Assurance::Exact)];
        }
        let mut candidates = ruby_fallback_classes(reg, file, name);
        let assurance = match candidates.len() {
            1 => Assurance::Heuristic,
            2..=MAX_DISPATCH_CANDIDATES => Assurance::Alternatives,
            _ => return Vec::new(),
        };
        candidates
            .drain(..)
            .map(|candidate| (candidate, assurance))
            .collect()
    }

    fn resolve_method<'a>(
        &self,
        reg: &'a ModuleRegistry,
        inst: &ResolvedObject,
        method: &str,
    ) -> Resolution<'a> {
        let Some(file) = reg.files.get(&inst.file) else {
            return Resolution::Unknown;
        };
        if inst.class_name.contains("::") {
            return ruby_qualified_method(self, reg, file, &inst.class_name, method);
        }
        if class_defined(file, &inst.class_name) {
            return resolve_method_in_class(self, reg, inst, method, &mut HashSet::new());
        }
        let exact = standard_class_candidates(self, reg, file, &inst.class_name);
        if let Some((candidate, assurance)) = exact.into_iter().next()
            && let Resolution::Targets(mut targets) =
                resolve_method_in_class(self, reg, &candidate, method, &mut HashSet::new())
        {
            for target in &mut targets {
                target.2 = target.2.max(assurance);
            }
            return Resolution::Targets(targets);
        }
        let mut targets = Vec::new();
        for candidate in ruby_fallback_classes(reg, file, &inst.class_name) {
            if let Resolution::Targets(found) =
                resolve_method_in_class(self, reg, &candidate, method, &mut HashSet::new())
            {
                targets.extend(found);
            }
        }
        dedup_targets(&mut targets);
        match targets.len() {
            0 => Resolution::Unknown,
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
                detail: format!("method {method:?} has {count} candidate Ruby definitions"),
            },
        }
    }

    fn classify_external(
        &self,
        _reg: &ModuleRegistry,
        _module: &str,
        _member: &str,
        _arity: Option<usize>,
    ) -> Option<ExternalCall> {
        None
    }

    fn classify_import(
        &self,
        reg: &ModuleRegistry,
        _file: &ModuleFile,
        spec: &str,
    ) -> Option<ExternalCall> {
        classify_ruby_require(spec).or_else(|| {
            reg.ruby_gem(spec)
                .map(|_| ExternalCall::Unmodeled(effinterp_engine::ALL_DOMAINS))
        })
    }

    fn external_import_label(
        &self,
        reg: &ModuleRegistry,
        _file: &ModuleFile,
        spec: &str,
    ) -> String {
        if let Some((name, version, source)) = reg.ruby_gem(spec) {
            let version = if version.is_empty() {
                "(version unspecified)"
            } else {
                version
            };
            format!("require {spec:?} is gem {name} {version} ({source})")
        } else {
            format!("import {spec:?} is an unmodeled external library")
        }
    }

    fn execution_roots<'a>(
        &self,
        _reg: &'a ModuleRegistry,
        _file: &'a ModuleFile,
    ) -> Vec<(&'a ModuleFile, Option<&'a str>)> {
        Vec::new()
    }

    fn unknown_import_is_boundary(&self) -> bool {
        true
    }
}
