//! Callable-surface extraction for cross-file Python composition.
//!
//! Execution analysis emits one file's plan; this module captures stored
//! function summaries, call edges, imports, and top-level execution surfaces.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference, Domain, Subject,
};
use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{self, Expr, Stmt};

use super::resolve::Imports;
use super::{
    Capture, Def, PythonWalker, collect_class_bases, collect_class_sets, collect_class_strings,
    collect_classes, collect_defs, collect_path_attrs, extract_imports,
    materialize_deferred_spawns, partition_top_level,
};
use crate::builder::PlanBuilder;
use crate::module_summary::{DecoratorShape, FunctionEntry, ModuleSummary};
use crate::nest::Nest;
use crate::summary::Summary;
use crate::{ScopeKey, SemanticValue};

/// Iterations of the summary fixpoint before results are frozen (with
/// widening). Recursive functions converge within a few passes; the bound
/// guarantees termination regardless.
const MAX_SUMMARY_ITERS: usize = 6;

// Nested captures carry full scope frames; bound native stack use independently
// of the number of statements in a callable.
const MAX_SUMMARY_DEPTH: usize = 16;

/// Extract this module's callable surface for cross-file composition: each
/// top-level function's parameterized summary and its direct user-function
/// call edges, plus the module's import bindings. The summaries reuse the
/// same fixpoint inference as execution analysis.
pub(super) fn summarize_ast(
    source: &str,
    suite: &ast::Suite,
    file: &str,
    scope: ScopeKey,
) -> ModuleSummary {
    // A throwaway analysis context: summary inference runs in capture mode and
    // stores source ranges in the capture instead of emitting plan nodes, so
    // nothing here reaches a real plan.
    let catalog = crate::models::Catalog::shared_builtin();
    let mut limits = crate::AnalysisLimits::default();
    let registration_scan =
        super::registration::fastapi_registrations(suite, file, limits.max_analysis_bytes);
    let (registration_spans, registration_limit) = match registration_scan {
        Ok(registrations) => (
            registrations
                .into_iter()
                .flat_map(|registration| registration.spans)
                .collect(),
            None,
        ),
        Err(limit) => (HashSet::new(), Some(limit)),
    };
    limits.max_python_nodes = crate::limits::invocation_node_limit(limits.max_python_nodes);
    let mut builder = PlanBuilder::new(
        Subject::Source {
            dialect: None,
            language: "python".into(),
            source: String::new(),
            cwd: None,
            context: Default::default(),
        },
        crate::engine_version(),
        catalog.model_set_id(),
        limits.clone(),
    );
    let budget = builder.budget();
    let nest = Nest {
        registration: None,
        path_platform: effinterp_proto::PathPlatform::Posix,
        source_origin: None,
        script_origins: RefCell::new(vec![None]),
        current_script: RefCell::new(None),
        catalog: catalog.as_ref(),
        limits: &limits,
        budget: &budget,
        resolver: None,
        context: None,
        source_cwds: std::cell::RefCell::new(vec![Some(String::new())]),
        runtime_cwds: std::cell::RefCell::new(vec![Some(String::new())]),
        cwd_nodes: std::cell::RefCell::new(vec![None]),
        mounts: std::cell::RefCell::new(vec![Vec::new()]),
        environments: std::cell::RefCell::new(vec![std::collections::BTreeMap::new()]),
        environment_nodes: std::cell::RefCell::new(vec![std::collections::BTreeMap::new()]),
        environment_unsets: std::cell::RefCell::new(vec![Default::default()]),
        environment_concealed: std::cell::RefCell::new(vec![Default::default()]),
        environment_closed: std::cell::RefCell::new(vec![false]),
        source_resolution_disabled: Default::default(),
        package_manifest: Default::default(),
        selected_source_inputs: std::cell::RefCell::new(Default::default()),
        resolved_invocation_sources: std::cell::RefCell::new(Default::default()),
        shell_arguments: std::cell::RefCell::new(None),
        physical_cwd: Default::default(),
        python_import_search: std::cell::RefCell::new(None),
        python_imports: Default::default(),
        dependency_calls: Default::default(),
    };
    let mut defs: Vec<Def> = Vec::new();
    collect_defs(suite, &mut defs);
    let (mut classes, attr_values) = collect_classes(suite);
    for class in &mut classes {
        let resource_aliases: Vec<_> = class
            .attr_params
            .iter()
            .map(|(attr, param)| (format!("self.{attr}"), param.clone()))
            .collect();
        class.attr_params.extend(resource_aliases);
    }
    let path_attrs = collect_path_attrs(&classes);
    let class_bases = collect_class_bases(&classes);
    let class_strings = collect_class_strings(suite);
    let class_sets = collect_class_sets(suite);
    let max_nodes = limits.max_python_nodes;
    let mut walker = PythonWalker {
        builder: &mut builder,
        nest: &nest,
        source,
        condition_source: effinterp_proto::ConditionSource::new(source),
        cwd: None,
        cwd_node: None,
        chdir: None,
        scope: None,
        depth: 0,
        imports: Imports::default(),
        defs,
        summaries: std::collections::HashMap::new(),
        demand_summaries: false,
        summary_in_progress: HashSet::new(),
        summary_cycles: HashSet::new(),
        summary_refining: false,
        summary_spans: std::collections::HashMap::new(),
        decorated_summaries: std::collections::HashMap::new(),
        spawn_summaries: std::collections::HashMap::new(),
        consts: std::collections::HashMap::new(),
        shared_vars: HashSet::new(),
        const_concatenations: HashSet::new(),
        const_unbounded_strings: HashSet::new(),
        var_scope: std::collections::HashMap::new(),
        path_vars: HashSet::new(),
        branch_mixed_path_vars: HashSet::new(),
        concatenated_vars: HashSet::new(),
        unbounded_string_vars: HashSet::new(),
        collections: std::collections::HashMap::new(),
        widened_vars: HashSet::new(),
        sessions: std::collections::HashMap::new(),
        modeled_values: std::collections::HashMap::new(),
        return_receivers: std::collections::HashMap::new(),
        return_instances: std::collections::HashMap::new(),
        summary_instances: std::collections::HashMap::new(),
        instance_sequences: std::collections::HashMap::new(),
        capture: None,
        capture_condition_depth: 0,
        entered_callables: false,
        reported_unresolved: HashSet::new(),
        nodes_left: max_nodes,
        node_budget_hit: false,
        free_resource_parameter: Cell::new(false),
        walk_depth: 0,
        flow_vars: std::collections::HashMap::new(),
        stage_writer: crate::flow::StageWriter::default(),
        current_params: Vec::new(),
        current_function: None,
        current_path_params: HashSet::new(),
        current_class: None,
        framework_decorators: HashSet::new(),
        registration_spans,
        class_names: classes.iter().map(|c| c.name.clone()).collect(),
        class_bases,
        path_attrs,
        attr_values,
        class_strings,
        class_sets,
        class_set_vars: std::collections::HashMap::new(),
        instance_vars: std::collections::HashMap::new(),
        instance_attr_rebindings: std::collections::HashMap::new(),
        bound_vars: HashSet::new(),
        receiver_rebindings: HashSet::new(),
        pending_binds: None,
        discarded_call: None,
        source_changes_cwd: super::source_changes_cwd(source, None),
        eager_call: None,
        synchronous_call: None,
        deferred_containers: std::collections::HashMap::new(),
        deferred_vars: std::collections::HashMap::new(),
        pending_deferred_container: None,
        fact_file: file.to_string(),
        fact_scope: Some(scope),
        fact_function: String::new(),
        site_ordinal: Cell::new(0),
        site_origins: RefCell::new(std::collections::HashMap::new()),
        module_capture: false,
        execute_deferred: false,
        deferred_call: None,
        import_search: None,
        imported_summaries: std::collections::HashMap::new(),
        control_applications: Vec::new(),
        summary_requirements: std::collections::HashMap::new(),
        summary_stdout: std::collections::HashMap::new(),
        summary_returns: std::collections::HashMap::new(),
        call_returns: std::collections::HashMap::new(),
        module_binds: HashSet::new(),
        environment_rewritten: false,
        ipython: None,
        prime_bash: false,
    };
    walker.collect_imports(suite);
    super::control::collect_bound(suite, &mut walker.module_binds);
    walker.framework_decorators = super::python_framework_roots(
        suite,
        &walker.defs,
        &classes,
        &walker.imports,
        limits.max_analysis_bytes,
    )
    .1;
    walker.collect_consts(suite);
    walker.var_scope = walker.consts.clone();
    walker.concatenated_vars = walker.const_concatenations.clone();
    walker.unbounded_string_vars = walker.const_unbounded_strings.clone();
    walker.compute_summaries();

    // Functions in source order, each with its summary and direct call edges.
    let def_names: Vec<(String, Rc<Vec<Stmt>>, usize, bool)> = walker
        .defs
        .iter()
        .filter(|def| def.parent.is_none())
        .map(|d| {
            (
                d.name.clone(),
                Rc::clone(&d.body),
                d.positional_param_count,
                d.is_async,
            )
        })
        .collect();
    let mut functions: Vec<_> = def_names
        .into_iter()
        .filter_map(|(name, body, positional_param_count, is_async)| {
            let summary = walker.summaries.get(&name).cloned()?;
            let decorator_gate = walker.decorator_gate(&name);
            let decorator_shape = walker.decorator_shape(&name);
            walker.current_params = walker
                .defs
                .iter()
                .find(|def| def.name == name)
                .map(|def| def.params.clone())
                .unwrap_or_default();
            let cap = walker.capture_body(&body, &name, 0);
            walker.current_params.clear();
            let callable_defaults = walker
                .defs
                .iter()
                .find(|def| def.name == name)
                .map(|def| def.callable_defaults.clone())
                .unwrap_or_default();
            let mut summary = summary;
            if let Some(retained) = walker.decorated_summaries.get(&name) {
                summary = retained.clone();
            }
            // The stored graph must index this entry's own effects and calls,
            // which this final capture recorded.
            summary.control_flow = if !summary.control_flow.is_saturated()
                && summary.effects.starts_with(&cap.effects)
            {
                cap.control_flow
            } else {
                crate::control_flow::ControlFlow::widened()
            };
            if let Some(spawns) = walker.spawn_summaries.get(&name) {
                let (effects, boundaries) = materialize_deferred_spawns(spawns);
                summary.effects.extend(effects);
                summary.boundaries.extend(boundaries);
            }
            Some(FunctionEntry {
                name,
                decorator_shape,
                decorator_gate,
                visibility: crate::CallableVisibility::Public,
                is_async,
                summary,
                positional_param_count: Some(positional_param_count),
                calls: cap.calls,
                callable_defaults,
                parameter_type_narrowing: Vec::new(),
                returns_instances: cap.returns_instances,
                return_types: cap.return_types,
                return_bindings: cap.return_bindings,
                dispatch_impl: None,
                dispatch_signature: None,
                lexical_span: None,
            })
        })
        .collect();

    // Calls made by the module's own top-level execution (a def statement is
    // not descended, so only executed top-level calls are captured). Statements
    // under an `if __name__ == "__main__":` guard run only when the file is the
    // entrypoint, and a TYPE_CHECKING block never runs, so top-level statements
    // are partitioned before capture.
    let (import_stmts, main_stmts) = partition_top_level(suite);
    walker.module_capture = true;
    let mut module_cap = walker.capture_body(&import_stmts, "", 0);
    walker.receiver_rebindings = module_cap.rebound_callables.clone();
    let main_start = walker.site_ordinal.get();
    let main_cap = walker.capture_body(&main_stmts, "", main_start);
    module_cap
        .rebound_callables
        .extend(main_cap.rebound_callables);
    let main_calls = main_cap.calls;
    let main_control_flow = main_cap.control_flow;
    module_cap.boundaries.extend(main_cap.boundaries);
    walker.module_capture = false;

    let (mut imports, scoped_imports, import_bound) = extract_imports(suite);
    functions.retain(|function| !import_bound.contains(&function.name));
    classes.retain(|class| !import_bound.contains(&class.name));
    // Python module-level imports are attributes of the module and can be
    // imported by consumers, including package `__init__.py` forwarding.
    let exports = imports.clone();
    // Conditional star bindings are duplicated only to retain ambiguity in
    // the export walk; ordinary import traversal still visits the module once.
    imports.dedup();
    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            wildcard_excludes_private: true,
            ordered_wildcard_overrides: true,
            ..Default::default()
        },
        functions,
        module_calls: module_cap.calls,
        module_control_flow: module_cap.control_flow,
        module_effects: module_cap.effects,
        module_transfers: module_cap.transfers,
        module_boundaries: module_cap
            .boundaries
            .into_iter()
            .filter(|boundary| {
                boundary.limit.is_some()
                    || boundary.reason == effinterp_proto::BoundaryReason::CROSS_MODULE
            })
            .collect(),
        main_calls,
        main_control_flow,
        imports,
        module_loads: Vec::new(),
        load_path_roots: Vec::new(),
        scoped_imports,
        exports,
        exported_definitions: Vec::new(),
        module_values: walker
            .defs
            .iter()
            .filter(|def| {
                def.parent.is_none()
                    && def.owner.is_none()
                    && !module_cap.rebound_callables.contains(&def.name)
            })
            .map(|def| {
                (
                    def.name.clone(),
                    crate::SemanticValue::callable(def.name.clone()),
                )
            })
            .collect(),
        module_value_rebindings: Default::default(),
        classes,
        dispatch_contracts: Vec::new(),
        dispatch_type_aliases: Vec::new(),
    };
    if let Some(limit) = registration_limit {
        summary.module_boundaries.push(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: super::DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: Vec::new(),
            limit: Some(limit.into()),
            detail: Some("registration evidence exceeds byte budget".into()),
        });
    }
    let gated: HashSet<_> = summary
        .functions
        .iter()
        .filter(|function| !function.decorator_gate.is_empty())
        .map(|function| function.name.clone())
        .collect();
    crate::module_summary::set_effects_propagated(&mut summary, |edge| {
        !gated.contains(&edge.callee)
    });
    summary
}

impl PythonWalker<'_, '_> {
    fn decorators_are_transparent(&self, name: &str) -> bool {
        self.decorator_gate(name).is_empty()
    }

    pub(super) fn decorator_is_transparent(&self, decorator: &str) -> bool {
        let written = decorator.strip_suffix("()").unwrap_or(decorator);
        let resolved = self.imports.resolve_written(written);
        let canonical = resolved.as_deref().unwrap_or(written);
        if matches!(
            canonical,
            "staticmethod"
                | "classmethod"
                | "property"
                | "contextlib.contextmanager"
                | "contextlib.asynccontextmanager"
        ) || written
            .rsplit_once('.')
            .is_some_and(|(_, member)| matches!(member, "setter" | "getter" | "deleter"))
            || resolved.as_deref().is_some_and(|canonical| {
                matches!(
                    canonical,
                    "click.command"
                        | "click.group"
                        | "click.option"
                        | "click.argument"
                        | "click.version_option"
                        | "click.pass_context"
                        | "functools.lru_cache"
                        | "mypy_extensions.mypyc_attr"
                        | "abc.abstractmethod"
                        | "functools.cache"
                        | "functools.cached_property"
                        | "typing.final"
                        | "typing.override"
                        | "typing_extensions.override"
                ) || canonical == "functools.wraps" && decorator.ends_with("()")
            })
            || self.framework_decorators.contains(decorator)
        {
            return true;
        }
        let required = if decorator.ends_with("()") {
            DecoratorShape::IdentityFactory
        } else {
            DecoratorShape::Identity
        };
        self.decorator_shape(written) == required
    }

    fn decorator_gate(&self, name: &str) -> Vec<CalleeReference> {
        self.defs
            .iter()
            .find(|def| def.name == name)
            .into_iter()
            .flat_map(|def| &def.decorators)
            .filter(|decorator| !self.decorator_is_transparent(decorator))
            .map(|decorator| {
                let written = decorator.strip_suffix("()").unwrap_or(decorator);
                let canonical = self.imports.resolve_import_written(written);
                let mut reference = canonical
                    .as_deref()
                    .and_then(super::python_callee_reference)
                    .unwrap_or_else(|| CalleeReference {
                        module: String::new(),
                        symbol: written.to_string(),
                    });
                if decorator.ends_with("()") {
                    reference.symbol.push_str("()");
                }
                reference
            })
            .collect()
    }

    fn decorator_boundaries(&self, name: &str) -> Vec<Boundary> {
        self.decorator_gate(name)
            .into_iter()
            .map(|callee| {
                let written = if callee.module.is_empty() {
                    callee.symbol.clone()
                } else {
                    format!("{}.{}", callee.module, callee.symbol)
                };
                Boundary {
                    reason: BoundaryReason::UNRESOLVED_DECORATOR,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: Some(callee),
                    domains: crate::external::ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: Vec::new(),
                    limit: None,
                    detail: Some(format!("decorator {written} on {name}")),
                }
            })
            .collect()
    }

    fn decorator_shape(&self, name: &str) -> DecoratorShape {
        let Some(def) = self.defs.iter().find(|def| def.name == name) else {
            return DecoratorShape::Opaque;
        };
        // Decorated decorator definitions cannot export proof about their replacement.
        if def.is_async || !def.decorators.is_empty() {
            return DecoratorShape::Opaque;
        }
        if self.identity_decorator(def) {
            DecoratorShape::Identity
        } else if self.returned_inner(def).is_some_and(|(inner, _, _)| {
            !inner.is_async && inner.decorators.is_empty() && self.identity_decorator(inner)
        }) {
            DecoratorShape::IdentityFactory
        } else {
            DecoratorShape::Opaque
        }
    }

    pub(super) fn returned_inner<'a>(
        &'a self,
        def: &'a Def,
    ) -> Option<(&'a Def, &'a ast::Arguments, &'a [Expr])> {
        let body: Vec<_> = def
            .body
            .iter()
            .filter(|stmt| !decorator_docstring(stmt))
            .collect();
        let [definition, Stmt::Return(ret)] = body.as_slice() else {
            return None;
        };
        let (local, args, decorators, returns) = match definition {
            Stmt::FunctionDef(inner) => (
                inner.name.as_str(),
                inner.args.as_ref(),
                inner.decorator_list.as_slice(),
                &inner.returns,
            ),
            Stmt::AsyncFunctionDef(inner) => (
                inner.name.as_str(),
                inner.args.as_ref(),
                inner.decorator_list.as_slice(),
                &inner.returns,
            ),
            _ => return None,
        };
        // Defaults and annotations execute when a wrapper is constructed.
        if returns.is_some()
            || args
                .posonlyargs
                .iter()
                .chain(&args.args)
                .chain(&args.kwonlyargs)
                .any(|arg| arg.default.is_some() || arg.def.annotation.is_some())
            || args
                .vararg
                .as_ref()
                .is_some_and(|arg| arg.annotation.is_some())
            || args
                .kwarg
                .as_ref()
                .is_some_and(|arg| arg.annotation.is_some())
        {
            return None;
        }
        if !matches!(ret.value.as_deref(), Some(Expr::Name(name)) if name.id.as_str() == local) {
            return None;
        }
        self.defs
            .iter()
            .find(|inner| inner.parent.as_deref() == Some(&def.name) && inner.local_name == local)
            .map(|inner| (inner, args, decorators))
    }

    fn identity_decorator(&self, def: &Def) -> bool {
        let Some(parameter) = def.params.first() else {
            return false;
        };
        let body: Vec<_> = def
            .body
            .iter()
            .filter(|stmt| !decorator_docstring(stmt))
            .collect();
        if matches!(body.as_slice(), [Stmt::Return(ret)]
            if matches!(ret.value.as_deref(), Some(Expr::Name(name)) if name.id.as_str() == parameter))
        {
            return true;
        }
        self.returned_inner(def).is_some_and(|(inner, args, decorators)| {
            decorators.iter().all(|decorator| {
                let Expr::Call(call) = decorator else { return false; };
                super::callee_written(&call.func).and_then(|name| self.imports.resolve_written(&name)).as_deref() == Some("functools.wraps")
                    && call.keywords.is_empty()
                    && matches!(call.args.as_slice(), [Expr::Name(name)] if name.id.as_str() == parameter)
            }) && pure_forwarding_body(&inner.body, parameter, args)
        })
    }

    /// Invocation inference follows reached calls; only recursive groups need
    /// repeated passes. Repository extraction retains its whole-module fixpoint.
    pub(super) fn ensure_summary(&mut self, name: &str) {
        if !self.demand_summaries {
            return;
        }
        if self.summary_in_progress.contains(name) {
            self.summary_cycles
                .extend(self.summary_in_progress.iter().cloned());
            return;
        }
        if self.capture.is_none() && self.instance_vars != self.summary_instances {
            self.summaries.clear();
            self.summary_instances = self.instance_vars.clone();
        }
        if self.summaries.contains_key(name) {
            return;
        }
        if self.summary_in_progress.len() >= MAX_SUMMARY_DEPTH {
            if let Some(span) = self
                .defs
                .iter()
                .find(|def| def.name == name)
                .and_then(|def| def.body.first())
                .map(Ranged::range)
            {
                let node = self.span_node(span);
                self.out_boundary(Boundary {
                    reason: BoundaryReason::PARTIAL_ANALYSIS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    domains: super::DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    affected_resource: None,
                    callee: Some(CalleeReference {
                        module: "python".into(),
                        symbol: name.into(),
                    }),
                    provenance: vec![node],
                    limit: None,
                    detail: Some("Python summary call depth bound reached".into()),
                });
            }
            return;
        }
        self.summary_in_progress.insert(name.to_string());
        self.compute_named_summaries(&[name.to_string()]);
        self.summary_in_progress.remove(name);
        if self.summary_in_progress.is_empty()
            && !self.summary_refining
            && !self.summary_cycles.is_empty()
        {
            let mut names: Vec<_> = self.summary_cycles.drain().collect();
            names.sort();
            self.summary_refining = true;
            self.compute_named_summaries(&names);
            self.summary_refining = false;
        }
    }

    pub(super) fn compute_summaries(&mut self) {
        self.summary_instances = self.instance_vars.clone();
        // Deterministic order.
        let mut names: Vec<String> = self.defs.iter().map(|d| d.name.clone()).collect();
        names.sort();
        self.compute_named_summaries(&names);
    }

    fn compute_named_summaries(&mut self, names: &[String]) {
        let mut changed = false;
        // Callables whose summary was still moving in the final round, and the
        // callees each one reached, so an unsettled result can be traced to
        // the callers that applied it.
        let mut unsettled: HashSet<String> = HashSet::new();
        let mut callees: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let library_api_spans = std::cell::OnceCell::new();
        for _ in 0..MAX_SUMMARY_ITERS {
            changed = false;
            unsettled.clear();
            for name in names {
                let Some(def) = self.defs.iter().find(|d| d.name == *name) else {
                    continue;
                };
                let params = def.params.clone();
                let body = Rc::clone(&def.body);
                let settled = std::mem::replace(&mut changed, false);
                let cap = self.capture_body(&body, name, 0);
                callees.insert(
                    name.clone(),
                    cap.calls.iter().map(|edge| edge.callee.clone()).collect(),
                );
                let returns = cap.returns.clone().map(SemanticValue::from);
                let returned_class = match cap.returns_instances.as_slice() {
                    [Some(class)] if self.class_names.contains(class) => Some(class.clone()),
                    _ => None,
                };
                if self.return_instances.get(name) != returned_class.as_ref() {
                    if let Some(class) = returned_class {
                        self.return_instances.insert(name.clone(), class);
                    } else {
                        self.return_instances.remove(name);
                    }
                    changed = true;
                }
                if let Some(def) = self.defs.iter_mut().find(|def| def.name == *name) {
                    let previous = def.parameter_attr_writes.len();
                    def.parameter_attr_writes
                        .extend(cap.parameter_attr_writes.iter().cloned());
                    def.parameter_attr_writes.sort();
                    def.parameter_attr_writes.dedup();
                    changed |= def.parameter_attr_writes.len() != previous;
                }
                // Track which local functions return a network object, so a
                // caller binding their result gets a session receiver. A change
                // here can unlock an effect in a caller next iteration, so it
                // also drives the fixpoint.
                if self.return_receivers.get(name).copied() != cap.return_receiver {
                    match cap.return_receiver {
                        Some(kind) => {
                            self.return_receivers.insert(name.clone(), kind);
                        }
                        None => {
                            self.return_receivers.remove(name);
                        }
                    }
                    changed = true;
                }
                if self.summary_stdout.get(name) != Some(&cap.stdout) {
                    self.summary_stdout.insert(name.clone(), cap.stdout.clone());
                    changed = true;
                }
                if self.summary_returns.get(name) != Some(&cap.returned) {
                    self.summary_returns
                        .insert(name.clone(), cap.returned.clone());
                    changed = true;
                }
                self.summary_spans
                    .insert(name.clone(), cap.source_spans.clone());
                let mut effect_models = cap.effect_models;
                effect_models.resize(cap.effects.len(), Vec::new());
                for (index, effect) in cap.effects.iter().enumerate() {
                    for reference in &effect.provenance {
                        let Some(span) = cap.source_spans.get(reference.0 as usize) else {
                            continue;
                        };
                        let spans = library_api_spans.get_or_init(|| {
                            self.nest.catalog.python_library_api_spans(self.source)
                        });
                        if let Some(models) = spans.get(&(
                            effect.operation.0.clone(),
                            u32::from(span.start()) as usize,
                            u32::from(span.end()) as usize,
                        )) {
                            effect_models[index].extend(models.iter().cloned());
                        }
                    }
                    effect_models[index].sort();
                    effect_models[index].dedup();
                }
                let deferred_spawns = cap.deferred_spawns;
                let mut requirements = cap.requirements;
                let mut summary = Summary {
                    params,
                    effects: cap.effects,
                    effect_models,
                    transfers: cap.transfers,
                    returns,
                    boundaries: cap.boundaries,
                    coverage: cap.coverage,
                    control_flow: cap.control_flow,
                };
                if !self.decorators_are_transparent(name) {
                    // An opaque wrapper decides whether the body runs at all.
                    summary.control_flow = crate::control_flow::ControlFlow::widened();
                    requirements = None;
                    let mut retained = summary.clone();
                    let (effects, boundaries) = materialize_deferred_spawns(&deferred_spawns);
                    retained.effects.extend(effects);
                    retained.boundaries.extend(boundaries);
                    retained.boundaries.extend(self.decorator_boundaries(name));
                    self.decorated_summaries.insert(name.clone(), retained);

                    summary.returns = None;
                    summary.coverage.clear();
                    summary.boundaries.extend(self.decorator_boundaries(name));
                }
                match requirements {
                    Some(requirements) => {
                        self.summary_requirements.insert(name.clone(), requirements);
                    }
                    None => {
                        self.summary_requirements.remove(name);
                    }
                }
                if self.summaries.get(name) != Some(&summary)
                    || self.spawn_summaries.get(name) != Some(&deferred_spawns)
                {
                    self.summaries.insert(name.clone(), summary);
                    self.spawn_summaries.insert(name.clone(), deferred_spawns);
                    changed = true;
                }
                if changed {
                    unsettled.insert(name.clone());
                }
                changed |= settled;
            }
            if !changed || (self.demand_summaries && !self.summary_refining) {
                break;
            }
        }
        if changed && (!self.demand_summaries || self.summary_refining) {
            // Frozen before convergence: a caller may have applied facts from
            // an older revision of a callee that had not settled. Only the
            // unsettled callables and the callers that reached them lose their
            // proof; a callable that never reached one keeps its own.
            loop {
                let mut grew = false;
                for name in names {
                    if unsettled.contains(name) {
                        continue;
                    }
                    if callees
                        .get(name)
                        .is_some_and(|reached| reached.iter().any(|call| unsettled.contains(call)))
                    {
                        unsettled.insert(name.clone());
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }
            let boundary = Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("dataflow")],
                provenance: Vec::new(),
                limit: Some("max_summary_iterations".to_string()),
                detail: Some("python summary fixpoint frozen before convergence".to_string()),
            };
            for name in names {
                if !unsettled.contains(name) {
                    continue;
                }
                if let Some(summary) = self.summaries.get_mut(name) {
                    summary.control_flow = crate::control_flow::ControlFlow::widened();
                    summary.boundaries.push(boundary.clone());
                }
                self.summary_requirements.remove(name);
            }
        }
    }

    /// Walk a function body in capture mode, returning its collected effects.
    /// The variable scope is reset to module constants for the body (its locals
    /// must not leak out, and the caller's locals must not leak in), then
    /// restored.
    fn capture_body(&mut self, body: &[Stmt], function: &str, start_ordinal: u32) -> Capture {
        let walk = crate::limits::summary_walk();
        let saved_nodes = self.nodes_left;
        let saved_hit = self.node_budget_hit;
        if walk.is_active() {
            self.nodes_left = self.nest.limits.max_python_nodes;
            self.node_budget_hit = false;
        }
        let saved = self.capture.replace(Capture::default());
        if let Some(def) = self.defs.iter().find(|def| def.name == function)
            && let Some(capture) = self.capture.as_mut()
        {
            capture.live_returns = super::returns::reachable_returns(body, &def.params);
            capture.params = def
                .params
                .iter()
                .map(|param| (param.clone(), vec![param.clone()]))
                .collect();
        }
        let saved_condition_depth = self.capture_condition_depth;
        self.capture_condition_depth = self.builder.condition_depth();
        let mut saved_imports = self.imports.clone();
        let mut parents = Vec::new();
        let mut parent = self
            .defs
            .iter()
            .find(|def| def.name == function)
            .and_then(|def| def.parent.clone());
        while let Some(name) = parent {
            let Some(def) = self.defs.iter().find(|def| def.name == name) else {
                break;
            };
            parents.push((Rc::clone(&def.body), def.parameter_bindings.clone()));
            parent = def.parent.clone();
        }
        for (body, parameters) in parents.into_iter().rev() {
            self.collect_imports(&body);
            for param in parameters {
                self.imports.shadow(&param);
            }
        }
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            for param in &def.parameter_bindings {
                self.imports.shadow(param);
            }
        }
        let saved_execute_deferred = self.execute_deferred;
        let saved_deferred_call = self.deferred_call;
        self.execute_deferred = false;
        self.deferred_call = None;
        let saved_walk_depth = self.walk_depth;
        let saved_fact_function = self.fact_function.clone();
        let saved_ordinal = self.site_ordinal.get();
        let saved_origins = self.site_origins.borrow().clone();
        let saved_pending_binds = self.pending_binds.take();
        let saved_pending_container = self.pending_deferred_container.take();
        if self.demand_summaries {
            self.nodes_left = self
                .nodes_left
                .min(self.nest.budget.analysis_steps_remaining())
                .min(
                    self.nest.limits.max_python_nodes
                        / crate::limits::PYTHON_CALLABLE_BUDGET_DIVISOR,
                );
            self.node_budget_hit = false;
            self.walk_depth = 0;
        }
        let saved_reported_unresolved = std::mem::take(&mut self.reported_unresolved);
        let mut body_scope = self.consts.clone();
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            for param in &def.parameter_bindings {
                body_scope.remove(param);
            }
        }
        let saved_scope = std::mem::replace(&mut self.var_scope, body_scope);
        let saved_path_vars = self.path_vars.clone();
        let saved_branch_mixed_path_vars = self.branch_mixed_path_vars.clone();
        if self.demand_summaries {
            self.path_vars.retain(|name| self.consts.contains_key(name));
            self.branch_mixed_path_vars
                .retain(|name| self.consts.contains_key(name));
        }
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            for param in &def.parameter_bindings {
                self.path_vars.remove(param);
                self.branch_mixed_path_vars.remove(param);
            }
        }
        let mut body_concatenations = self.const_concatenations.clone();
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            for param in &def.parameter_bindings {
                body_concatenations.remove(param);
            }
        }
        let saved_concatenations =
            std::mem::replace(&mut self.concatenated_vars, body_concatenations);
        let mut body_unbounded_strings = self.const_unbounded_strings.clone();
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            for param in &def.parameter_bindings {
                body_unbounded_strings.remove(param);
            }
        }
        let saved_unbounded_strings =
            std::mem::replace(&mut self.unbounded_string_vars, body_unbounded_strings);
        let saved_collections = std::mem::take(&mut self.collections);
        let saved_instance_sequences = std::mem::take(&mut self.instance_sequences);
        let saved_widened = std::mem::take(&mut self.widened_vars);
        let saved_sessions = std::mem::take(&mut self.sessions);
        let saved_modeled = std::mem::take(&mut self.modeled_values);
        let saved_instances = self.instance_vars.clone();
        if self.demand_summaries {
            self.instance_vars = self.summary_instances.clone();
        }
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            for param in &def.parameter_bindings {
                self.instance_vars.remove(param);
            }
            for (param, class) in &def.param_types {
                if self.class_names.contains(class) {
                    self.instance_vars.insert(
                        param.clone(),
                        SemanticValue::object(crate::ObjectIdentity::Class {
                            name: class.clone(),
                            constructor: Vec::new(),
                        }),
                    );
                }
            }
        }
        let saved_instance_attr_rebindings = std::mem::take(&mut self.instance_attr_rebindings);
        let saved_bound = std::mem::take(&mut self.bound_vars);
        let saved_receiver_rebindings = std::mem::take(&mut self.receiver_rebindings);
        self.receiver_rebindings = saved_receiver_rebindings.clone();
        let saved_deferred_containers = std::mem::take(&mut self.deferred_containers);
        let saved_deferred_vars = std::mem::take(&mut self.deferred_vars);
        let saved_path_params = std::mem::take(&mut self.current_path_params);
        let saved_class = self.current_class.take();
        let saved_function = self.current_function.take();
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            self.current_function = Some(def.name.clone());
            self.current_path_params = def
                .param_types
                .iter()
                .filter(|(_, ty)| {
                    self.imports.resolve_written(ty).as_deref() == Some("pathlib.Path")
                })
                .map(|(name, _)| name.clone())
                .collect();
            self.path_vars
                .extend(self.current_path_params.iter().cloned());
            for param in &self.current_path_params {
                self.branch_mixed_path_vars.remove(param);
            }
            self.current_class = def.owner.clone();
            if let Some(class) = &self.current_class {
                for name in self
                    .attr_values
                    .iter()
                    .filter(|value| value.owner == *class)
                    .map(|value| format!("self.{}", value.attr))
                {
                    self.path_vars.insert(name.clone());
                    self.branch_mixed_path_vars.remove(&name);
                }
            }
        }
        self.pending_binds = None;
        self.pending_deferred_container = None;
        self.fact_function = function.to_string();
        self.site_ordinal.set(start_ordinal);
        self.site_origins.borrow_mut().clear();
        let mut module_bound = self.module_binds.clone();
        if let Some(def) = self.defs.iter().find(|def| def.name == function) {
            module_bound.extend(def.params.iter().cloned());
        }
        self.builder.control_enter(self.source, true, |graph| {
            super::control::build(graph, body, super::control::Entry::Callable, &module_bound)
        });
        self.walk_body(body);
        let control = self.builder.control_leave();
        // Infer the returned receiver kind while this body's local session
        // bindings are still live (they are cleared on restore below), and the
        // returned instance classes while `instance_vars` is still live.
        let return_receiver = self.infer_return_receiver(body);
        let returns = self.infer_return(body);
        let returns_instances = self.infer_returns_instances(body);
        let return_types = self.infer_return_types(body);
        let return_bindings = self.infer_return_bindings(body);
        self.var_scope = saved_scope;
        self.path_vars = saved_path_vars;
        self.branch_mixed_path_vars = saved_branch_mixed_path_vars;
        self.concatenated_vars = saved_concatenations;
        self.unbounded_string_vars = saved_unbounded_strings;
        self.collections = saved_collections;
        self.instance_sequences = saved_instance_sequences;
        self.widened_vars = saved_widened;
        self.sessions = saved_sessions;
        self.modeled_values = saved_modeled;
        self.instance_vars = saved_instances;
        self.instance_attr_rebindings = saved_instance_attr_rebindings;
        self.bound_vars = saved_bound;
        let rebound_callables =
            std::mem::replace(&mut self.receiver_rebindings, saved_receiver_rebindings);
        self.deferred_containers = saved_deferred_containers;
        self.deferred_vars = saved_deferred_vars;
        self.current_path_params = saved_path_params;
        self.current_class = saved_class;
        self.current_function = saved_function;
        self.pending_binds = None;
        self.pending_deferred_container = None;
        self.reported_unresolved = saved_reported_unresolved;
        let mut cap = self.capture.take().unwrap_or_default();
        if let Some(control) = control {
            cap.control_flow = control.flow;
            cap.requirements = Some(control.requirements);
        } else {
            cap.control_flow = crate::control_flow::ControlFlow::widened();
        }
        cap.rebound_callables = rebound_callables;
        cap.returns = returns;
        cap.return_receiver = return_receiver;
        cap.returns_instances = returns_instances;
        cap.return_types = return_types;
        cap.return_bindings = return_bindings;
        if walk.is_active() && self.node_budget_hit {
            cap.boundaries.push(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: Vec::new(),
                provenance: Vec::new(),
                limit: Some("max_python_nodes".to_string()),
                detail: Some(function.to_string()),
            });
        }
        if walk.is_active() {
            self.nodes_left = saved_nodes;
            self.node_budget_hit = saved_hit;
        }
        self.capture = saved;
        self.capture_condition_depth = saved_condition_depth;
        self.execute_deferred = saved_execute_deferred;
        self.deferred_call = saved_deferred_call;
        saved_imports.namespace_mutated |= self.imports.namespace_mutated;
        self.imports = saved_imports;
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        if self.demand_summaries {
            self.nodes_left = saved_nodes;
            self.node_budget_hit = saved_hit;
            self.walk_depth = saved_walk_depth;
            self.fact_function = saved_fact_function;
            self.site_ordinal.set(saved_ordinal);
            *self.site_origins.borrow_mut() = saved_origins;
            self.pending_binds = saved_pending_binds;
            self.pending_deferred_container = saved_pending_container;
        }
        cap
    }
}

// Only inert docstrings may accompany a proven decorator shape.
fn decorator_docstring(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(expr) if matches!(expr.value.as_ref(),
        Expr::Constant(value) if matches!(value.value, ast::Constant::Str(_))))
}

fn pure_forwarding_body(body: &[Stmt], parameter: &str, args: &ast::Arguments) -> bool {
    fn forwarding(expr: &Expr, parameter: &str, args: &ast::Arguments) -> bool {
        let expr = if let Expr::Await(expr) = expr {
            expr.value.as_ref()
        } else {
            expr
        };
        let Expr::Call(call) = expr else {
            return false;
        };
        if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == parameter) {
            return false;
        }
        let positional: Vec<_> = args.posonlyargs.iter().chain(&args.args).collect();
        if call.args.len() != positional.len() + usize::from(args.vararg.is_some())
            || call.keywords.len() != args.kwonlyargs.len() + usize::from(args.kwarg.is_some())
        {
            return false;
        }
        let named = |expr: &Expr, expected: &str| {
            matches!(expr, Expr::Name(name)
            if name.id.as_str() == expected && expected != parameter)
        };
        call.args
            .iter()
            .zip(&positional)
            .all(|(value, arg)| named(value, arg.def.arg.as_str()))
            && args.vararg.as_ref().is_none_or(|arg| {
                matches!(call.args.last(),
                Some(Expr::Starred(value)) if named(&value.value, arg.arg.as_str()))
            })
            && call
                .keywords
                .iter()
                .zip(&args.kwonlyargs)
                .all(|(value, arg)| {
                    value.arg.as_ref() == Some(&arg.def.arg)
                        && named(&value.value, arg.def.arg.as_str())
                })
            && args.kwarg.as_ref().is_none_or(|arg| {
                call.keywords.last().is_some_and(|value| {
                    value.arg.is_none() && named(&value.value, arg.arg.as_str())
                })
            })
    }
    let body: Vec<_> = body
        .iter()
        .filter(|stmt| !decorator_docstring(stmt))
        .collect();
    match body.as_slice() {
        [Stmt::Return(ret)] => ret
            .value
            .as_deref()
            .is_some_and(|expr| forwarding(expr, parameter, args)),
        [Stmt::Expr(expr)] => forwarding(&expr.value, parameter, args),
        _ => false,
    }
}
