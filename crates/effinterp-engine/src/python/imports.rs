//! Invocation import traversal for Python programs.
//!
//! An analyzed launch (`python3 script.py`, `-c`, stdin, or a root Python
//! source subject) carries its observed `sys.path` roots. Absolute and relative
//! imports resolve against those roots through the caller's resolver, imported
//! modules nest as `Import` executions for their module-level effects, and a
//! call through an imported function applies that function's summary with the
//! caller's arguments. Uncalled functions in an imported module never execute.
//!
//! Unsupported: interpreter-configured search paths (site-packages, `.pth`
//! files, zip imports). Only launch roots and caller-supplied `PYTHONPATH`
//! entries are searched; a module found nowhere stays a precise boundary.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    BoundaryClass, BoundaryReason, CalleeReference, ExecutionAssurance, ExecutionContent,
    ExecutionEdgeKind, ExecutionInputReason, ExecutionSelection, ProvenanceKind, Subject,
};
use rustpython_parser::Parse;
use rustpython_parser::ast::{self, Expr};
use rustpython_parser::text_size::TextRange;

use crate::builder::PlanBuilder;
use crate::control_flow::{ControlExit, SiteFacts};
use crate::external::is_python_stdlib;
use crate::models::pyexec::{
    python_candidates_with_suffixes, python_module_candidate_roles, python_search_path,
};
use crate::nest::{Nest, SourceSearchObservation, Transition, source_refusal_reason};
use crate::summary::Summary;
use crate::value::fs_path_resource;
use crate::{SourcePurpose, SourceRefusal, UnavailableReason};

use super::import_bindings::{import_from_module, star_exports};
use super::package_search::{PackageDirs, package_dirs, push_directory};
use super::subprocess_launch::CapturedSpawn;
use super::{PythonWalker, control, python_boundary};

/// Observed import search facts for one launched Python program.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PythonImportSearch {
    /// Ordered `sys.path` entries this launch is known to search: the script
    /// directory or cwd (unless safe-path mode) and caller-supplied
    /// `PYTHONPATH` entries (unless isolated or environment-ignoring mode).
    pub roots: Vec<String>,
    /// The launching interpreter, used for extension-suffix observations.
    pub executable: Option<String>,
    /// Package directory of the importing module; None for `__main__`, where
    /// relative imports cannot resolve.
    pub package: Option<String>,
    pub package_name: Option<String>,
    /// Pytest treats this source as a collection candidate or a plugin.
    pub pytest_mode: Option<PytestMode>,
    /// The collection spelling determines package context for a linked source.
    pub pytest_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum PytestMode {
    #[default]
    Run,
    Collect,
    Help,
    Version,
}

impl PytestMode {
    pub(crate) fn startup_only(self) -> bool {
        matches!(self, Self::Help | Self::Version)
    }

    pub(super) fn enters_hook(self, name: &str) -> bool {
        if !name.starts_with("pytest_") {
            return false;
        }
        if self == Self::Run {
            return true;
        }
        // Collection-only still enters pytest_runtestloop, which returns
        // before dispatching the individual test protocols.
        if matches!(
            name,
            "pytest_runtest_protocol"
                | "pytest_runtest_logstart"
                | "pytest_runtest_logfinish"
                | "pytest_runtest_setup"
                | "pytest_runtest_call"
                | "pytest_runtest_teardown"
                | "pytest_runtest_makereport"
                | "pytest_runtest_logreport"
                | "pytest_fixture_setup"
                | "pytest_fixture_post_finalizer"
                | "pytest_pyfunc_call"
        ) {
            return false;
        }
        if self.startup_only()
            && matches!(
                name,
                "pytest_collection"
                    | "pytest_collection_modifyitems"
                    | "pytest_collection_finish"
                    | "pytest_ignore_collect"
                    | "pytest_collect_directory"
                    | "pytest_collect_file"
                    | "pytest_collectstart"
                    | "pytest_collectreport"
                    | "pytest_make_collect_report"
                    | "pytest_pycollect_makemodule"
                    | "pytest_pycollect_makeitem"
                    | "pytest_make_parametrize_id"
                    | "pytest_generate_tests"
                    | "pytest_itemcollected"
                    | "pytest_deselected"
                    | "pytest_report_collectionfinish"
                    | "pytest_runtestloop"
                    | "pytest_sessionstart"
                    | "pytest_sessionfinish"
            )
        {
            return false;
        }
        // Help configures the plugin manager so it can print plugin options.
        self != Self::Version || !matches!(name, "pytest_configure" | "pytest_unconfigure")
    }
}

impl PythonImportSearch {
    pub(crate) fn new(
        roots: Vec<String>,
        executable: Option<String>,
        package: Option<String>,
    ) -> Self {
        Self {
            roots,
            executable,
            package,
            package_name: None,
            pytest_mode: None,
            pytest_path: None,
        }
    }

    /// Ordinary imports execute module initialization only.
    fn without_pytest_collection(mut self) -> Self {
        self.pytest_mode = None;
        self.pytest_path = None;
        self
    }
}

/// A readable module that can win an import search.
struct PythonModuleSource {
    path: String,
    source: String,
    digest: String,
    selected: usize,
    package: String,
    package_name: Option<String>,
}

#[derive(Default)]
struct PythonModuleLookup {
    not_traversed: bool,
    candidates: Vec<String>,
    sources: Vec<PythonModuleSource>,
    gap: Option<(Option<usize>, ExecutionContent)>,
    children: PackageDirs,
}

impl PythonModuleLookup {
    fn unobserved(&mut self, reason: ExecutionInputReason) {
        // A search may already be ambiguous when it runs out of probes.
        // Keep the limit that left the rest of its candidates unread.
        let exhausted = matches!(reason, ExecutionInputReason::BudgetRefused { .. });
        let recorded_limit = matches!(
            self.gap,
            Some((
                _,
                ExecutionContent::Unobserved {
                    reason: ExecutionInputReason::BudgetRefused { .. },
                },
            ))
        );
        if self.gap.is_none() || exhausted && !recorded_limit {
            self.gap = Some((None, ExecutionContent::Unobserved { reason }));
        }
    }
}

/// A summary of one imported function, reusable at every call site with
/// distinct argument substitution.
pub(crate) struct ImportedFunction {
    pub(super) summary: Summary,
    pub(super) spawns: Vec<CapturedSpawn>,
    pub(super) source: Rc<ProvenanceKind>,
    positional_param_count: usize,
}

type ModuleKey = (PythonImportSearch, String);
type FunctionKey = (String, String, String);
type PytestModuleKey = (effinterp_proto::ExecutionNodeRef, String);

/// Per-invocation memo of module searches and imported function summaries.
#[derive(Default)]
pub(crate) struct PythonImportCache {
    modules: RefCell<HashMap<ModuleKey, Rc<PythonModuleLookup>>>,
    functions: RefCell<HashMap<FunctionKey, Vec<Rc<ImportedFunction>>>>,
    in_progress: RefCell<HashSet<FunctionKey>>,
    pytest_sources: RefCell<HashSet<PytestModuleKey>>,
    /// The resolver refused dependency traversal once; later imports keep
    /// their dependency-request boundaries without probing again.
    denied: Cell<bool>,
}

impl PythonImportCache {
    pub(crate) fn pytest_source_recorded(&self, builder: &PlanBuilder, path: &str) -> bool {
        self.pytest_sources
            .borrow()
            .contains(&(builder.current_dependency_launch(), path.to_string()))
    }

    pub(super) fn record_pytest_source(&self, builder: &PlanBuilder, path: String) -> bool {
        self.pytest_sources
            .borrow_mut()
            .insert((builder.current_dependency_launch(), path))
    }
}

/// Search roots for a root Python source subject: `sys.path[0]` is the cwd, as
/// for `python -c`, followed by caller-supplied `PYTHONPATH` entries.
pub(super) fn root_import_search(nest: &Nest) -> Option<PythonImportSearch> {
    let cwd = nest.current_runtime_cwd()?;
    let mut roots = vec![cwd.clone()];
    if let Some(path) = nest
        .context
        .and_then(|context| context.env.get("PYTHONPATH"))
    {
        roots.extend(crate::models::pyexec::python_path_entries(path, Some(&cwd)));
    }
    Some(PythonImportSearch::new(roots, None, None))
}

/// Look up a dotted (possibly relative) module under one search context. Each
/// candidate read is charged to the invocation budget and deadline.
fn lookup_python_module(
    builder: &PlanBuilder,
    nest: &Nest,
    search: &PythonImportSearch,
    module: &str,
) -> Rc<PythonModuleLookup> {
    let absolute = absolute_module(search, module);
    let module = absolute.as_deref().unwrap_or(module);
    let relative = module.starts_with('.');

    let key_search = PythonImportSearch {
        package: if relative {
            search.package.clone()
        } else {
            None
        },
        package_name: None,
        ..search.clone().without_pytest_collection()
    };
    let key = (key_search, module.to_string());
    if let Some(lookup) = nest.python_imports.modules.borrow().get(&key) {
        return Rc::clone(lookup);
    }
    let lookup = Rc::new(observe_python_module(builder, nest, search, module));
    // Budget refusals are not facts about the module; a later lookup may not retry them
    // under the same deadline, but the evidence must name the refusal each time.
    nest.python_imports
        .modules
        .borrow_mut()
        .insert(key, Rc::clone(&lookup));
    lookup
}

fn absolute_module(search: &PythonImportSearch, module: &str) -> Option<String> {
    let child = module.trim_start_matches('.');
    let levels = module.len() - child.len();
    if levels == 0 {
        return None;
    }
    let mut parent = search.package_name.as_deref()?;
    for _ in 1..levels {
        parent = parent.rsplit_once('.')?.0;
    }
    Some(if child.is_empty() {
        parent.to_string()
    } else {
        format!("{parent}.{child}")
    })
}

fn observe_python_module(
    builder: &PlanBuilder,
    nest: &Nest,
    search: &PythonImportSearch,
    module: &str,
) -> PythonModuleLookup {
    let not_traversed = nest.resolver.is_none()
        || nest.python_imports.denied.get()
        || is_python_stdlib(module.split('.').next().unwrap_or(module));
    if not_traversed {
        return PythonModuleLookup {
            not_traversed,
            ..Default::default()
        };
    }
    if let Some((parent, child)) = parent_module(module) {
        let parent = lookup_python_module(builder, nest, search, parent);
        if parent.not_traversed {
            return PythonModuleLookup {
                not_traversed: true,
                ..Default::default()
            };
        }
        return search_module_in_roots(builder, nest, search, &parent.children, child, module);
    }
    let dotted = module.trim_start_matches('.');
    let roots = if module.starts_with('.') {
        let Some(mut base) = search.package.clone() else {
            return PythonModuleLookup::default();
        };
        for _ in 1..module.len() - dotted.len() {
            base = crate::paths::parent_dir(&base);
        }
        vec![base]
    } else {
        search.roots.clone()
    };
    search_module_in_roots(
        builder,
        nest,
        search,
        &PackageDirs {
            roots,
            unordered: false,
        },
        dotted,
        module,
    )
}

/// Keep the leading dots when looking up a relative parent.
fn parent_module(module: &str) -> Option<(&str, &str)> {
    module
        .trim_start_matches('.')
        .contains('.')
        .then(|| module.rsplit_once('.'))
        .flatten()
}

fn search_module_in_roots(
    builder: &PlanBuilder,
    nest: &Nest,
    search: &PythonImportSearch,
    parents: &PackageDirs,
    component: &str,
    specifier: &str,
) -> PythonModuleLookup {
    let mut lookup = PythonModuleLookup::default();
    let runtime_cwd = nest.current_runtime_cwd();
    let mut namespaces = Vec::new();
    let mut unknown_package = false;
    if parents.unordered {
        lookup.unobserved(ExecutionInputReason::Ambiguous);
    }
    for root in &parents.roots {
        let directory = if component.is_empty() {
            root.clone()
        } else {
            python_search_path(root, component)
        };
        let candidates = if component.is_empty() {
            vec![(python_search_path(root, "__init__.py"), true)]
        } else if let Some(candidates) = python_module_candidate_roles(
            builder,
            nest,
            search.executable.as_deref(),
            runtime_cwd.as_deref(),
            std::slice::from_ref(root),
            component,
        ) {
            candidates
        } else {
            lookup.unobserved(ExecutionInputReason::Ambiguous);
            unknown_package = true;
            python_candidates_with_suffixes(std::slice::from_ref(root), component, &[])
        };
        let mut found = false;
        for (candidate, is_package) in candidates {
            let Some(request) = crate::paths::join_source_path(runtime_cwd.as_deref(), &candidate)
            else {
                lookup.unobserved(ExecutionInputReason::ResolverUnavailable);
                unknown_package |= is_package;
                continue;
            };
            // Implicit and explicit sys.path entries can name the same
            // directory. Probe each normalized candidate once, in search order.
            if lookup.candidates.contains(&request.1) {
                continue;
            }
            let observed = nest.observe_source_search(
                builder,
                std::slice::from_ref(&request),
                SourcePurpose::DependencySource,
            );
            let selected = lookup.candidates.len();
            let (_, path) = request;
            lookup.candidates.push(path.clone());
            match observed {
                SourceSearchObservation::Missing => continue,
                SourceSearchObservation::Refused(SourceRefusal::Unavailable(
                    UnavailableReason::DependencyDenied,
                )) => {
                    nest.python_imports.denied.set(true);
                    return PythonModuleLookup {
                        not_traversed: true,
                        ..Default::default()
                    };
                }
                SourceSearchObservation::Refused(refusal) => {
                    lookup.unobserved(source_refusal_reason(refusal));
                    unknown_package |= is_package;
                }
                SourceSearchObservation::ResolverUnavailable => {
                    lookup.unobserved(ExecutionInputReason::ResolverUnavailable);
                    unknown_package |= is_package;
                }
                SourceSearchObservation::Found { bytes, .. } => {
                    let digest = effinterp_proto::content_digest(&bytes);
                    let source = path
                        .ends_with(".py")
                        .then(|| String::from_utf8(bytes).ok())
                        .flatten();
                    if let Some(source) = source {
                        let package = crate::paths::parent_dir(&path);
                        let children = package_dirs(
                            builder,
                            nest,
                            parents,
                            search.executable.as_deref(),
                            specifier,
                            is_package.then_some(package.as_str()),
                            &source,
                        );
                        // Only an initializer implies a package directory
                        // among these roots. An ordinary module can install
                        // a search path, but an unknown value does not make
                        // its same-named directory a known child location.
                        unknown_package |= is_package && children.unordered;
                        lookup.children.merge(children);
                        let package_name = if specifier.starts_with('.') {
                            None
                        } else if is_package {
                            Some(specifier.to_string())
                        } else {
                            specifier
                                .rsplit_once('.')
                                .map(|(parent, _)| parent.to_string())
                        };
                        lookup.sources.push(PythonModuleSource {
                            path,
                            source,
                            digest,
                            selected,
                            package,
                            package_name,
                        });
                    } else {
                        lookup
                            .gap
                            .get_or_insert((Some(selected), ExecutionContent::Observed { digest }));
                        unknown_package |= is_package;
                    }
                    found = true;
                    break;
                }
            }
        }
        if found && !parents.unordered {
            // A file in this entry wins if every earlier possible file is
            // absent. A namespace portion cannot win in either case.
            namespaces.clear();
            break;
        }
        if !found {
            push_directory(&mut namespaces, directory);
        }
        if nest.budget.timed_out() {
            break;
        }
    }
    for dir in namespaces {
        push_directory(&mut lookup.children.roots, dir);
    }
    if unknown_package {
        // An unread or dynamically extended initializer can join any portion
        // on the parent's search path, including entries after a known file.
        lookup.children.include_portions(parents, component);
    }
    lookup.children.unordered |= unknown_package
        || parents.unordered
        || lookup.gap.is_some() && !lookup.children.roots.is_empty();
    lookup
}

/// Package prefixes of one import, including a dot-only relative package
/// (`from . import name`).
fn python_import_prefixes(module: &str) -> Vec<String> {
    let (dots, dotted) = module.split_at(module.len() - module.trim_start_matches('.').len());
    let mut prefixes = Vec::new();
    if !dots.is_empty() && dotted.is_empty() {
        prefixes.push(dots.to_string());
    }
    let parts: Vec<&str> = dotted.split('.').filter(|part| !part.is_empty()).collect();
    for end in 1..=parts.len() {
        prefixes.push(format!("{dots}{}", parts[..end].join(".")));
    }
    prefixes
}

impl PythonWalker<'_, '_> {
    /// Resolve an import for the invocation's search context. `Some(true)`
    /// means the module resolved to source, `Some(false)` that the import is
    /// traversed but did not resolve, and None that traversal does not apply.
    ///
    /// A dotted name stops at an ordinary module. `settings.py` has no
    /// `__path__`, so `settings.helper` is not a local module and the child
    /// file is not read.
    pub(super) fn traversed_python_module(&mut self, module: &str) -> Option<bool> {
        let search = self.import_search.as_ref()?;
        let lookup = lookup_python_module(self.builder, self.nest, search, module);
        (!lookup.not_traversed).then(|| !lookup.sources.is_empty())
    }

    /// Whether an import of the top-level `module` loads the installed
    /// module of that name: a standard-library module, which import
    /// traversal never looks for on the program's own search path, or one
    /// traversal looked for there and found no source of. False where
    /// traversal does not apply or a candidate could not be read.
    pub(super) fn standard_module_unshadowed(&mut self, module: &str) -> bool {
        if is_python_stdlib(module) {
            return true;
        }
        let Some(search) = self.import_search.as_ref() else {
            return false;
        };
        let lookup = lookup_python_module(self.builder, self.nest, search, module);
        !lookup.not_traversed && lookup.sources.is_empty() && lookup.gap.is_none()
    }

    /// Execute one import statement's module loads: every package prefix and
    /// the module itself, in order. False when traversal does not apply.
    pub(super) fn import_python_module(
        &mut self,
        module: &str,
        members: &[&str],
        span: TextRange,
    ) -> bool {
        let Some(search) = self.import_search.clone() else {
            return false;
        };
        let prefixes = python_import_prefixes(module);
        let Some(last) = prefixes.last() else {
            return false;
        };
        for prefix in &prefixes {
            let lookup = lookup_python_module(self.builder, self.nest, &search, prefix);
            if lookup.not_traversed {
                return false;
            }
            self.follow_python_lookup(prefix, &lookup, span, prefix == last && members.is_empty());
            if lookup.children.roots.is_empty()
                && !lookup.children.unordered
                && !lookup.sources.is_empty()
            {
                return true;
            }
        }
        for member in members {
            let separator = if last.ends_with('.') { "" } else { "." };
            let submodule = format!("{last}{separator}{member}");
            let lookup = lookup_python_module(self.builder, self.nest, &search, &submodule);
            // A member can be an attribute with no file of its own.
            self.follow_python_lookup(&submodule, &lookup, span, false);
        }
        true
    }

    fn follow_python_lookup(
        &mut self,
        specifier: &str,
        lookup: &PythonModuleLookup,
        span: TextRange,
        record_missing: bool,
    ) {
        if !self.builder.dependency_request_recorded(specifier) {
            if let Some((selected, content)) = &lookup.gap {
                self.record_python_import_boundary(
                    specifier,
                    &lookup.candidates,
                    *selected,
                    content.clone(),
                );
            } else if record_missing && lookup.sources.is_empty() {
                self.record_python_import_boundary(
                    specifier,
                    &lookup.candidates,
                    None,
                    ExecutionContent::Unobserved {
                        reason: ExecutionInputReason::Missing,
                    },
                );
            }
        }
        for (arm, source) in lookup.sources.iter().enumerate() {
            if lookup.gap.is_some() {
                // The source and its effects are concrete on this branch.
                // Which candidate wins remains a separate input gap.
                self.push_import_candidate(specifier, span, arm, lookup.sources.len() + 1);
            }
            self.load_python_module(specifier, source, &lookup.candidates, span);
            if lookup.gap.is_some() {
                self.builder.pop_condition();
            }
        }
    }

    fn push_import_candidate(&mut self, specifier: &str, span: TextRange, arm: usize, arms: usize) {
        let mut condition = self.builder.source_condition_path(
            effinterp_proto::Condition::from_source_with_digest(
                self.source,
                self.condition_source.digest().to_string(),
                effinterp_proto::ByteSpan {
                    start: span.start().into(),
                    end: span.end().into(),
                },
                effinterp_proto::ConditionKind::UnresolvedExecution,
                arm as u32,
                arms as u32,
                false,
                false,
            ),
        );
        condition.rebind(&self.condition_source.call_site(&[specifier]));
        self.builder.push_condition(condition);
    }

    /// Nest a module's import-time execution once per launch. Inside a
    /// callable summary the load cannot be sequenced, so it stays a boundary
    /// unless the launch already executed the module.
    fn load_python_module(
        &mut self,
        specifier: &str,
        module: &PythonModuleSource,
        candidates: &[String],
        span: TextRange,
    ) {
        if self.builder.dependency_source_recorded(&module.path) {
            return;
        }
        if self.capture.is_some() {
            let node = self.span_node(span);
            self.out_boundary(effinterp_proto::Boundary {
                reason: effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS,
                class: effinterp_proto::BoundaryClass::Unmodeled,
                scope: effinterp_proto::BoundaryScope::Invocation,
                domains: super::DOMAINS
                    .iter()
                    .map(|domain| effinterp_proto::Domain::new(*domain))
                    .collect(),
                affected_resource: Some(fs_path_resource(&module.path)),
                callee: Some(effinterp_proto::CalleeReference {
                    module: specifier.to_string(),
                    symbol: "__module_init__".to_string(),
                }),
                provenance: vec![node],
                limit: None,
                detail: Some("python module import inside a callable is not sequenced".into()),
            });
            return;
        }
        let node = self.span_node(span);
        let mut input = self.nest.source_input(
            self.builder,
            specifier,
            SourcePurpose::DependencySource,
            ExecutionContent::Observed {
                digest: module.digest.clone(),
            },
            &self.builder.current_execution_component(),
        );
        input.selected = Some(fs_path_resource(&module.path));
        input.selection = ExecutionSelection::Search {
            candidates: candidates
                .iter()
                .map(|path| fs_path_resource(path))
                .collect(),
            selected: Some(module.selected as u32),
        };
        self.nest.selected_source_inputs.borrow_mut().insert(
            module.path.clone(),
            crate::nest::SelectedSourceInput {
                input,
                authorship: crate::builder::SourceAuthorship::External,
            },
        );
        // During collection an imported file can contribute test callables.
        // Its package and spelling come from the import that selected it.
        let search = self.import_search.clone().map(|search| PythonImportSearch {
            package: Some(module.package.clone()),
            package_name: module.package_name.clone(),
            pytest_path: None,
            ..search
        });
        *self.nest.python_import_search.borrow_mut() = search;
        let argv = self.builder.current_execution_argv().to_vec();
        let depth = self.builder.execution_depth() - 1;
        self.nest.nest(
            self.builder,
            Transition::file(Subject::Source {
                language: "python".to_string(),
                source: module.source.clone(),
                dialect: None,
                cwd: self.nest.current_runtime_cwd(),
                context: Default::default(),
            })
            .kind(ExecutionEdgeKind::Import)
            .origin(module.path.clone())
            .source_cwd(Some(&module.package))
            .argv(argv),
            &[node],
            depth,
        );
        self.nest.python_import_search.borrow_mut().take();
    }

    fn record_python_import_boundary(
        &mut self,
        specifier: &str,
        candidates: &[String],
        selected: Option<usize>,
        content: ExecutionContent,
    ) {
        let mut input = self.nest.source_input(
            self.builder,
            specifier,
            SourcePurpose::DependencySource,
            content,
            &self.builder.current_execution_component(),
        );
        input.selected = selected.map(|index| fs_path_resource(&candidates[index]));
        if selected.is_none() {
            input.assurance = ExecutionAssurance::Widened;
        }
        // No candidates means no search could be formed (an unresolvable
        // relative import, or unobserved native-extension suffixes).
        if !candidates.is_empty() {
            input.selection = ExecutionSelection::Search {
                candidates: candidates
                    .iter()
                    .map(|path| fs_path_resource(path))
                    .collect(),
                selected: selected.map(|index| index as u32),
            };
        }
        self.nest
            .record_input_boundary(self.builder, specifier, input);
    }

    /// Apply a call through an imported function (`helpers.clean(path)`) from
    /// its module summary. False when the callee does not name a top-level
    /// function of a resolved module.
    pub(super) fn apply_imported_call(
        &mut self,
        canonical: &str,
        call: &ast::ExprCall,
        span: TextRange,
    ) -> bool {
        let mut arguments = self.resolved_value_args_of(call);
        for argument in &mut arguments {
            if let Some(resource) = super::model::path_object_resource(&argument.value) {
                argument.value = crate::SemanticValue::from(resource);
            }
        }
        self.apply_imported_arguments(canonical, &arguments, span)
    }

    pub(super) fn apply_imported_arguments(
        &mut self,
        canonical: &str,
        arguments: &[crate::ValueArgument],
        span: TextRange,
    ) -> bool {
        let functions = self.imported_functions(canonical);
        if functions.is_empty() {
            return false;
        }
        let choices = functions.len();
        for (index, function) in functions.into_iter().enumerate() {
            let key = format!("import:{canonical}:{index}");
            let bindings = super::summary_application::bind_python_arguments(
                &function.summary.params,
                function.positional_param_count,
                arguments,
            );
            self.imported_summaries.insert(key.clone(), function);
            if choices > 1 {
                self.push_import_candidate(canonical, span, index, choices + 1);
            }
            self.apply_summary(&key, &bindings, span);
            if choices > 1 {
                self.builder.pop_condition();
            }
        }
        true
    }

    /// Summarize the function a canonical imported name refers to, following
    /// re-exports through the defining module's own imports.
    fn imported_functions(&mut self, canonical: &str) -> Vec<Rc<ImportedFunction>> {
        let Some(search) = self.import_search.clone() else {
            return Vec::new();
        };
        let parts: Vec<&str> = canonical.split('.').collect();
        let (dots, _) =
            canonical.split_at(canonical.len() - canonical.trim_start_matches('.').len());
        for split in (1..parts.len()).rev() {
            let module = parts[..split].join(".");
            if module.is_empty() || module.trim_start_matches('.').is_empty() && dots.is_empty() {
                continue;
            }
            let function = parts[split..].join(".");
            let lookup = lookup_python_module(self.builder, self.nest, &search, &module);
            if lookup.sources.is_empty() {
                continue;
            }
            if function.contains('.') {
                break;
            }
            return lookup
                .sources
                .iter()
                .flat_map(|source| self.summarize_imported_function(source, &search, &function))
                .collect();
        }
        Vec::new()
    }

    fn summarize_imported_function(
        &mut self,
        module: &PythonModuleSource,
        search: &PythonImportSearch,
        function: &str,
    ) -> Vec<Rc<ImportedFunction>> {
        let key = (
            module.path.clone(),
            module.digest.clone(),
            function.to_string(),
        );
        if let Some(cached) = self.nest.python_imports.functions.borrow().get(&key) {
            return cached.clone();
        }
        // A recursive import cycle re-entering this function stays a loud
        // unresolved call inside the cycle rather than expanding again.
        if !self
            .nest
            .python_imports
            .in_progress
            .borrow_mut()
            .insert(key.clone())
        {
            return Vec::new();
        }
        let summarized = self.summarize_in_module(module, search, function);
        self.nest
            .python_imports
            .in_progress
            .borrow_mut()
            .remove(&key);
        if !self.nest.budget.timed_out() {
            self.nest
                .python_imports
                .functions
                .borrow_mut()
                .insert(key, summarized.clone());
        }
        summarized
    }

    fn summarize_in_module(
        &mut self,
        module: &PythonModuleSource,
        search: &PythonImportSearch,
        function: &str,
    ) -> Vec<Rc<ImportedFunction>> {
        if self.nest.budget.timed_out() {
            return Vec::new();
        }
        let Ok(suite) = ast::Suite::parse(&module.source, "<python-import>") else {
            return Vec::new();
        };
        if self.nest.budget.timed_out() {
            return Vec::new();
        }
        let (mut child, _) = PythonWalker::for_execution(
            self.builder,
            self.nest,
            &module.source,
            self.cwd.as_deref(),
            self.cwd_node,
            None,
            self.depth,
            &suite,
            None,
        );
        child.import_search = Some(PythonImportSearch {
            package: Some(module.package.clone()),
            package_name: module.package_name.clone(),
            ..search.clone().without_pytest_collection()
        });
        child.seed_import_bindings(&suite);
        child.collect_consts(&suite);
        child.var_scope = child.consts.clone();
        child.concatenated_vars = child.const_concatenations.clone();
        child.unbounded_string_vars = child.const_unbounded_strings.clone();
        let positional_param_count = child
            .defs
            .iter()
            .find(|def| def.name == function && def.parent.is_none() && def.owner.is_none())
            .map(|def| def.positional_param_count);
        if let Some(positional_param_count) = positional_param_count {
            child.ensure_summary(function);
            let Some(summary) = child.summaries.get(function).cloned() else {
                return Vec::new();
            };
            let mut spawns = child
                .spawn_summaries
                .get(function)
                .cloned()
                .unwrap_or_default();
            // The caller's span identifies the call site. The deferred
            // commands still get their bytes from the defining module.
            let source = Rc::new(ProvenanceKind::SourceInput {
                path: module.path.clone(),
                digest: module.digest.clone(),
            });
            for spawn in &mut spawns {
                spawn.source.get_or_insert_with(|| Rc::clone(&source));
            }
            return vec![Rc::new(ImportedFunction {
                summary,
                spawns,
                source,
                positional_param_count,
            })];
        }
        let name = Expr::Name(ast::ExprName {
            range: TextRange::default(),
            id: function.into(),
            ctx: ast::ExprContext::Load,
        });
        let Some(reexport) = child.imports.resolve_local_callee(&name) else {
            return Vec::new();
        };
        child.imported_functions(&reexport)
    }
}

impl PythonWalker<'_, '_> {
    /// Importing an unmodeled module runs its top level, which may complete
    /// the invocation; a repository view can discharge a resolved module.
    fn record_python_import_exit(&mut self, modules: &[&str], span: TextRange) {
        let unmodeled: Vec<_> = modules
            .iter()
            .filter(|module| !is_python_stdlib(module.split('.').next().unwrap_or(module)))
            .collect();
        let mut facts = SiteFacts::known(Vec::new());
        facts.exit = match unmodeled.as_slice() {
            [] => None,
            [module] => Some(ControlExit::Import {
                module: module.to_string(),
            }),
            _ => Some(ControlExit::Unknown),
        };
        self.builder.control_site(
            self.source,
            self.capture.is_some(),
            control::span(span),
            facts,
        );
    }

    fn import_boundary(&mut self, module: &str, span: TextRange) {
        if !crate::external::is_python_stdlib(module.split('.').next().unwrap_or(module))
            && !crate::LIFECYCLE_CATALOG.iter().any(|model| {
                model.lang == Some(crate::Lang::Python)
                    && model
                        .sigs
                        .iter()
                        .any(|sig| sig.component.is_some() && sig.import_path == Some(module))
            })
        {
            self.emit_unresolved_call(
                module,
                BoundaryReason::UNMODELED_IMPORT,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                span,
                Some(CalleeReference {
                    module: module.to_string(),
                    symbol: "__module_init__".to_string(),
                }),
            );
        }
    }

    /// Match the repository linker's absolute-import search order before a
    /// stdlib-shaped name can claim external ownership.
    pub(super) fn local_python_module(&mut self, module: &str) -> bool {
        if self.nest.resolver.is_none() {
            return false;
        }
        if let Some(resolved) = self.traversed_python_module(module) {
            return resolved;
        }
        let root = module.split('.').next().unwrap_or(module);
        if root.is_empty() {
            if self.builder.current_execution_is_launched_source() {
                self.nest.record_dependency_request(self.builder, module);
            }
            return false;
        }
        let source_cwd = self.nest.current_source_cwd();
        let local = [Some(""), Some("src"), source_cwd.as_deref()]
            .into_iter()
            .flatten()
            .flat_map(|base| {
                let prefix = if base.is_empty() {
                    root.to_string()
                } else {
                    format!("{base}/{root}")
                };
                [format!("{prefix}.py"), format!("{prefix}/__init__.py")]
            })
            .any(|path| {
                // Ownership probes use the admitted directory inventory, not source bytes.
                let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
                let directory = if parent.is_empty() {
                    ".".to_string()
                } else {
                    format!("{parent}/.")
                };
                self.nest
                    .source_siblings(&directory)
                    .is_some_and(|files| files.contains(&path))
            });
        if self.builder.current_execution_is_launched_source() {
            if local || !is_python_stdlib(root) {
                self.nest.record_dependency_request(self.builder, module);
            }
            return false;
        }
        local
    }
}

impl PythonWalker<'_, '_> {
    /// Follow module imports before replacing the local names those imports bind.
    pub(super) fn walk_python_import(&mut self, import: &ast::StmtImport) {
        let modules: Vec<_> = import
            .names
            .iter()
            .map(|alias| alias.name.as_str())
            .collect();
        self.record_python_import_exit(&modules, import.range);
        for alias in &import.names {
            if !self.import_python_module(alias.name.as_str(), &[], import.range) {
                self.import_boundary(alias.name.as_str(), import.range);
            }
            let name = alias.asname.as_deref().unwrap_or_else(|| {
                alias
                    .name
                    .as_str()
                    .split('.')
                    .next()
                    .unwrap_or(alias.name.as_str())
            });
            self.invalidate_rebound_name(name);
            self.add_import(alias.name.as_str(), alias.asname.as_deref());
        }
    }

    /// Resolve from-import members and expand star imports only for modeled exports.
    pub(super) fn walk_python_from_import(&mut self, from: &ast::StmtImportFrom) {
        let module = import_from_module(from);
        self.record_python_import_exit(&[&module], from.range);
        let members: Vec<&str> = from
            .names
            .iter()
            .map(|alias| alias.name.as_str())
            .filter(|name| *name != "*")
            .collect();
        if !self.import_python_module(&module, &members, from.range) {
            self.import_boundary(&module, from.range);
        }
        if from.names.iter().any(|a| a.name.as_str() == "*") {
            if let Some(exports) = star_exports(&module) {
                for member in exports {
                    self.invalidate_rebound_name(member);
                    self.add_from_import(&module, member, None);
                }
            } else {
                python_boundary(
                    self.builder,
                    self.scope,
                    BoundaryReason::UNMODELED_IMPORT,
                    BoundaryClass::Unmodeled,
                    None,
                    Some(format!("from {module} import *")),
                );
            }
            return;
        }
        for alias in &from.names {
            self.invalidate_rebound_name(alias.asname.as_deref().unwrap_or(alias.name.as_str()));
            self.add_from_import(&module, alias.name.as_str(), alias.asname.as_deref());
        }
    }
}
