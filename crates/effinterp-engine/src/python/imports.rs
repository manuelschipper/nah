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
    ExecutionAssurance, ExecutionContent, ExecutionEdgeKind, ExecutionInputReason,
    ExecutionSelection, ResourceExpr, ResourceIdentity, Subject,
};
use rustpython_parser::Parse;
use rustpython_parser::ast::{self, Expr};
use rustpython_parser::text_size::TextRange;

use super::{DeferredSpawn, PythonWalker};
use crate::builder::PlanBuilder;
use crate::external::is_python_stdlib;
use crate::models::pyexec::python_search_path;
use crate::nest::{Nest, SourceSearchObservation, Transition, source_refusal_reason};
use crate::summary::Summary;
use crate::{SourceNamespace, SourcePurpose, SourceRefusal, UnavailableReason};

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
}

/// A module source selected by an import search, bound to the exact bytes read.
pub(crate) struct PythonModuleSource {
    pub path: String,
    pub source: String,
    pub digest: String,
    candidates: Vec<String>,
    selected: usize,
    /// Directory against which this module's own relative imports resolve.
    package: String,
}

pub(crate) enum PythonModuleLookup {
    /// Standard-library models own the name, or the resolver's policy leaves
    /// module linking to repository indexing.
    NotTraversed,
    Found(Rc<PythonModuleSource>),
    Missing {
        candidates: Vec<String>,
    },
    Unobserved {
        candidates: Vec<String>,
        reason: ExecutionInputReason,
    },
    /// Observed bytes that are not Python source (a native extension or bytecode).
    Unsupported {
        candidates: Vec<String>,
        selected: usize,
        digest: String,
    },
}

/// A summary of one imported function, reusable at every call site with
/// distinct argument substitution.
pub(crate) struct ImportedFunction {
    summary: Summary,
    spawns: Vec<DeferredSpawn>,
    positional_param_count: usize,
}

type ModuleKey = (PythonImportSearch, String);
type FunctionKey = (String, String, String);

/// Per-invocation memo of module searches and imported function summaries.
#[derive(Default)]
pub(crate) struct PythonImportCache {
    modules: RefCell<HashMap<ModuleKey, Rc<PythonModuleLookup>>>,
    functions: RefCell<HashMap<FunctionKey, Option<Rc<ImportedFunction>>>>,
    in_progress: RefCell<HashSet<FunctionKey>>,
    /// The resolver refused dependency traversal once; later imports keep
    /// their dependency-request boundaries without probing again.
    denied: Cell<bool>,
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
    Some(PythonImportSearch {
        roots,
        executable: None,
        package: None,
    })
}

/// Look up a dotted (possibly relative) module under one search context. Each
/// candidate read is charged to the invocation budget and deadline.
fn lookup_python_module(
    builder: &PlanBuilder,
    nest: &Nest,
    search: &PythonImportSearch,
    module: &str,
) -> Rc<PythonModuleLookup> {
    let relative = module.starts_with('.');
    let key_search = PythonImportSearch {
        package: if relative {
            search.package.clone()
        } else {
            None
        },
        ..search.clone()
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

fn observe_python_module(
    builder: &PlanBuilder,
    nest: &Nest,
    search: &PythonImportSearch,
    module: &str,
) -> PythonModuleLookup {
    if nest.resolver.is_none() || nest.python_imports.denied.get() {
        return PythonModuleLookup::NotTraversed;
    }
    let (roots, dotted) = if let Some(stripped) = module.strip_prefix('.') {
        let level = 1 + stripped.len() - stripped.trim_start_matches('.').len();
        let Some(mut base) = search.package.clone() else {
            return PythonModuleLookup::Missing {
                candidates: Vec::new(),
            };
        };
        for _ in 1..level {
            base = crate::paths::parent_dir(&base);
        }
        (vec![base], stripped.trim_start_matches('.').to_string())
    } else {
        if is_python_stdlib(module.split('.').next().unwrap_or(module)) {
            return PythonModuleLookup::NotTraversed;
        }
        (search.roots.clone(), module.to_string())
    };
    if dotted.is_empty() {
        // `from . import name` loads the package itself.
        return observe_candidates(
            builder,
            nest,
            roots
                .iter()
                .map(|root| python_search_path(root, "__init__.py"))
                .collect(),
        );
    }
    let runtime_cwd = nest.current_runtime_cwd();
    if let Some(candidates) = crate::models::pyexec::python_module_candidates(
        builder,
        nest,
        search.executable.as_deref(),
        runtime_cwd.as_deref(),
        &roots,
        &dotted,
    ) {
        return observe_candidates(builder, nest, candidates);
    }
    // A native extension may win over any source candidate. Observe the
    // source candidates anyway so resolver policy and search evidence remain.
    let module = dotted.replace('.', "/");
    let candidates = roots
        .iter()
        .flat_map(|root| {
            [
                python_search_path(root, &format!("{module}/__init__.py")),
                python_search_path(root, &format!("{module}.py")),
            ]
        })
        .collect();
    match observe_candidates(builder, nest, candidates) {
        PythonModuleLookup::NotTraversed => PythonModuleLookup::NotTraversed,
        PythonModuleLookup::Found(module) => PythonModuleLookup::Unobserved {
            candidates: module.candidates.clone(),
            reason: ExecutionInputReason::Ambiguous,
        },
        PythonModuleLookup::Missing { candidates }
        | PythonModuleLookup::Unobserved { candidates, .. }
        | PythonModuleLookup::Unsupported { candidates, .. } => PythonModuleLookup::Unobserved {
            candidates,
            reason: ExecutionInputReason::Ambiguous,
        },
    }
}

fn observe_candidates(
    builder: &PlanBuilder,
    nest: &Nest,
    candidates: Vec<String>,
) -> PythonModuleLookup {
    let runtime_cwd = nest.current_runtime_cwd();
    let Some(requests) = candidates
        .iter()
        .map(|candidate| crate::paths::join_source_path(runtime_cwd.as_deref(), candidate))
        .collect::<Option<Vec<(SourceNamespace, String)>>>()
    else {
        return PythonModuleLookup::Unobserved {
            candidates,
            reason: ExecutionInputReason::ResolverUnavailable,
        };
    };
    let candidates: Vec<String> = requests.iter().map(|(_, path)| path.clone()).collect();
    match nest.observe_source_search(builder, &requests, SourcePurpose::DependencySource) {
        SourceSearchObservation::Found { index, bytes } => {
            let digest = effinterp_proto::content_digest(&bytes);
            // Native extensions and bytecode win searches but are not source.
            if !candidates[index].ends_with(".py") {
                return PythonModuleLookup::Unsupported {
                    candidates,
                    selected: index,
                    digest,
                };
            }
            match String::from_utf8(bytes) {
                Ok(source) => {
                    let path = candidates[index].clone();
                    let package = crate::paths::parent_dir(&path);
                    PythonModuleLookup::Found(Rc::new(PythonModuleSource {
                        path,
                        source,
                        digest,
                        candidates,
                        selected: index,
                        package,
                    }))
                }
                Err(_) => PythonModuleLookup::Unsupported {
                    candidates,
                    selected: index,
                    digest,
                },
            }
        }
        SourceSearchObservation::Missing => PythonModuleLookup::Missing { candidates },
        SourceSearchObservation::Refused(SourceRefusal::Unavailable(
            UnavailableReason::DependencyDenied,
        )) => {
            nest.python_imports.denied.set(true);
            PythonModuleLookup::NotTraversed
        }
        SourceSearchObservation::Refused(refusal) => PythonModuleLookup::Unobserved {
            candidates,
            reason: source_refusal_reason(refusal),
        },
        SourceSearchObservation::ResolverUnavailable => PythonModuleLookup::Unobserved {
            candidates,
            reason: ExecutionInputReason::ResolverUnavailable,
        },
    }
}

fn fs_resource(path: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: path.to_string(),
        },
    }
}

/// Key under which an imported function's summary is applied, distinct from
/// every same-file definition name.
pub(super) fn imported_summary_key(canonical: &str) -> String {
    format!("import:{canonical}")
}

impl PythonWalker<'_, '_> {
    /// Resolve an import for the invocation's search context. `Some(true)`
    /// means the module resolved to source, `Some(false)` that the import is
    /// traversed but did not resolve, and None that traversal does not apply.
    pub(super) fn traversed_python_module(&mut self, module: &str) -> Option<bool> {
        let search = self.import_search.as_ref()?;
        match lookup_python_module(self.builder, self.nest, search, module).as_ref() {
            PythonModuleLookup::NotTraversed => None,
            PythonModuleLookup::Found(_) => Some(true),
            _ => Some(false),
        }
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
        let (dots, dotted) = module.split_at(module.len() - module.trim_start_matches('.').len());
        let mut prefixes: Vec<String> = Vec::new();
        if !dots.is_empty() && dotted.is_empty() {
            prefixes.push(dots.to_string());
        }
        let parts: Vec<&str> = dotted.split('.').filter(|part| !part.is_empty()).collect();
        for end in 1..=parts.len() {
            prefixes.push(format!("{dots}{}", parts[..end].join(".")));
        }
        let Some(last) = prefixes.last().cloned() else {
            return false;
        };
        if matches!(
            lookup_python_module(self.builder, self.nest, &search, &last).as_ref(),
            PythonModuleLookup::NotTraversed
        ) {
            return false;
        }
        for prefix in &prefixes {
            let lookup = lookup_python_module(self.builder, self.nest, &search, prefix);
            match lookup.as_ref() {
                PythonModuleLookup::Found(source) => self.load_python_module(prefix, source, span),
                // A missing parent may be a namespace package; only the
                // requested module itself must resolve.
                PythonModuleLookup::Missing { .. } if prefix != &last => {}
                _ => {
                    self.record_python_import_boundary(prefix, &lookup);
                    return true;
                }
            }
        }
        let package = matches!(
            lookup_python_module(self.builder, self.nest, &search, &last).as_ref(),
            PythonModuleLookup::Found(source) if source.path.ends_with("/__init__.py")
        );
        for member in members {
            // `from package import name` loads a submodule when one exists.
            let submodule = if last.ends_with('.') {
                format!("{last}{member}")
            } else {
                format!("{last}.{member}")
            };
            if package
                && let PythonModuleLookup::Found(source) =
                    lookup_python_module(self.builder, self.nest, &search, &submodule).as_ref()
            {
                self.load_python_module(&submodule, source, span);
            }
        }
        true
    }

    /// Nest a module's import-time execution once per launch. Inside a
    /// callable summary the load cannot be sequenced, so it stays a boundary
    /// unless the launch already executed the module.
    fn load_python_module(
        &mut self,
        specifier: &str,
        module: &Rc<PythonModuleSource>,
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
                affected_resource: Some(fs_resource(&module.path)),
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
        input.selected = Some(fs_resource(&module.path));
        input.selection = ExecutionSelection::Search {
            candidates: module
                .candidates
                .iter()
                .map(|path| fs_resource(path))
                .collect(),
            selected: Some(module.selected as u32),
        };
        self.nest
            .selected_source_inputs
            .borrow_mut()
            .insert(module.path.clone(), input);
        let search = self.import_search.clone().map(|search| PythonImportSearch {
            package: Some(module.package.clone()),
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

    fn record_python_import_boundary(&mut self, specifier: &str, lookup: &PythonModuleLookup) {
        if self.builder.dependency_request_recorded(specifier) {
            return;
        }
        let (candidates, selected, content) = match lookup {
            PythonModuleLookup::NotTraversed | PythonModuleLookup::Found(_) => return,
            PythonModuleLookup::Missing { candidates } => (
                candidates,
                None,
                ExecutionContent::Unobserved {
                    reason: ExecutionInputReason::Missing,
                },
            ),
            PythonModuleLookup::Unobserved { candidates, reason } => (
                candidates,
                None,
                ExecutionContent::Unobserved {
                    reason: reason.clone(),
                },
            ),
            PythonModuleLookup::Unsupported {
                candidates,
                selected,
                digest,
            } => (
                candidates,
                Some(*selected),
                ExecutionContent::Observed {
                    digest: digest.clone(),
                },
            ),
        };
        let mut input = self.nest.source_input(
            self.builder,
            specifier,
            SourcePurpose::DependencySource,
            content,
            &self.builder.current_execution_component(),
        );
        input.selected = selected.map(|index| fs_resource(&candidates[index]));
        if selected.is_none() {
            input.assurance = ExecutionAssurance::Widened;
        }
        // No candidates means no search could be formed (an unresolvable
        // relative import, or unobserved native-extension suffixes).
        if !candidates.is_empty() {
            input.selection = ExecutionSelection::Search {
                candidates: candidates.iter().map(|path| fs_resource(path)).collect(),
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
        let key = imported_summary_key(canonical);
        if !self.imported_summaries.contains_key(&key) {
            let Some(function) = self.imported_function(canonical) else {
                return false;
            };
            self.imported_summaries.insert(key.clone(), function);
        }
        let function = Rc::clone(&self.imported_summaries[&key]);
        let mut arguments = self.resolved_value_args_of(call);
        for argument in &mut arguments {
            if let Some(resource) = super::model::path_object_resource(&argument.value) {
                argument.value = crate::SemanticValue::from(resource);
            }
        }
        let bindings = super::bind_python_arguments(
            &function.summary.params,
            function.positional_param_count,
            &arguments,
        );
        self.apply_summary(&key, &bindings, span);
        true
    }

    /// Summarize the function a canonical imported name refers to, following
    /// re-exports through the defining module's own imports.
    fn imported_function(&mut self, canonical: &str) -> Option<Rc<ImportedFunction>> {
        let search = self.import_search.clone()?;
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
            let PythonModuleLookup::Found(source) = lookup.as_ref() else {
                continue;
            };
            if function.contains('.') {
                return None;
            }
            return self.summarize_imported_function(source, &search, &function);
        }
        None
    }

    fn summarize_imported_function(
        &mut self,
        module: &Rc<PythonModuleSource>,
        search: &PythonImportSearch,
        function: &str,
    ) -> Option<Rc<ImportedFunction>> {
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
            return None;
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
        module: &Rc<PythonModuleSource>,
        search: &PythonImportSearch,
        function: &str,
    ) -> Option<Rc<ImportedFunction>> {
        if self.nest.budget.timed_out() {
            return None;
        }
        let suite = ast::Suite::parse(&module.source, "<python-import>").ok()?;
        if self.nest.budget.timed_out() {
            return None;
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
            ..search.clone()
        });
        child.collect_imports(&suite);
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
            let summary = child.summaries.get(function)?.clone();
            let spawns = child
                .spawn_summaries
                .get(function)
                .cloned()
                .unwrap_or_default();
            return Some(Rc::new(ImportedFunction {
                summary,
                spawns,
                positional_param_count,
            }));
        }
        let name = Expr::Name(ast::ExprName {
            range: TextRange::default(),
            id: function.into(),
            ctx: ast::ExprContext::Load,
        });
        let reexport = child.imports.resolve_local_callee(&name)?;
        child.imported_function(&reexport)
    }

    /// The imported function summary and deferred subprocesses behind a key
    /// from [`imported_summary_key`].
    pub(super) fn imported_summary(&self, key: &str) -> Option<(Summary, Vec<DeferredSpawn>)> {
        self.imported_summaries
            .get(key)
            .map(|function| (function.summary.clone(), function.spawns.clone()))
    }
}
