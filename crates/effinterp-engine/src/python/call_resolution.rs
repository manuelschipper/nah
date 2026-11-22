//! Python call resolution: what a call expression runs. Dispatches a call to
//! its modeled effects, a framework entry point (Django management commands,
//! `importlib`, component lifecycles) or a same-file or imported callable, and
//! records the call edges the repository linker follows.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference, CoverageLevel, Domain,
    ResourceExpr,
};
use rustpython_parser::ast::{self, Expr, Ranged};
use rustpython_parser::text_size::TextRange;

use crate::control_flow::{ControlFact, SiteFacts};
use crate::external::PYTHON_MODELED_ROOTS;
use crate::module_summary::{CallEdge, call_results};
use crate::summary::substitute_resource_expr;
use crate::{ObjectIdentity, SemanticValue, ValueArgument, merge_arguments};

use super::ast_expressions::callee_written;
use super::ast_expressions::child_exprs;
use super::fs_path_lowering::python_plugin_path_pattern;
use super::name_bindings::bound_body_names;
use super::resolve::str_literal;
use super::subprocess_launch::DeferredSpawn;
use super::summary;
use super::{MAX_CALL_EDGES, PytestMode, PythonWalker, argv, control, model, resolve};
use crate::TypeRef;
use rustpython_parser::ast::{Constant, Stmt};

impl PythonWalker<'_, '_> {
    /// Evaluate a call and register what it establishes at its site: the
    /// occurrences a modeled API produced, a local callee's guarantees, or
    /// unknown code that may complete the invocation.
    pub(super) fn call(&mut self, call: &ast::ExprCall) {
        let capture = self.capture.is_some();
        let since = self.builder.control_registered();
        let effects = self.control_effects_len();
        let calls = self.capture.as_ref().map_or(0, |cap| cap.calls.len());
        let applications = std::mem::take(&mut self.control_applications);
        let control = self.call_inner(call);
        let applied = std::mem::replace(&mut self.control_applications, applications);
        let call_return =
            matches!(&control, CallControl::Local | CallControl::Opaque) && applied.len() <= 1;
        let direct_sink = matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some("os.remove" | "os.unlink" | "os.getenv" | "os.putenv" | "os.unsetenv")
        );
        let mut facts = match control {
            CallControl::Modeled if applied.is_empty() && direct_sink => SiteFacts::known(
                self.builder
                    .control_own_effects(effects..self.control_effects_len()),
            ),
            CallControl::Modeled if applied.is_empty() => SiteFacts::known(Vec::new()),
            CallControl::Local if applied.len() == 1 => applied.into_iter().next().unwrap(),
            // Callbacks run under the API's own control, and several
            // applications at one call are alternatives or wrappers.
            CallControl::Modeled | CallControl::Local | CallControl::Opaque => SiteFacts::unknown(),
        };
        if matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some("sys.exit" | "exit" | "quit" | "os._exit" | "os.abort")
        ) {
            facts.returns = false;
            facts.exit = None;
            facts.throws = !matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("os._exit" | "os.abort")
            );
            if facts.throws {
                facts.thrown =
                    crate::control_flow::Exn::named(crate::control_flow::Symbol::py("SystemExit"));
            }
        }
        // One recorded edge is this call; several are dispatch alternatives.
        facts.call_return = call_return && facts.returns;
        if let Some(cap) = &self.capture
            && cap.calls.len() == calls + 1
        {
            facts.facts.push(ControlFact::Call(calls as u32));
            facts.throw_facts.push(ControlFact::Call(calls as u32));
            // The callee name resolved to an edge; lookup does not throw.
            facts.reference_known = true;
        }
        self.builder.control_site_since(
            self.source,
            capture,
            control::span(call.range),
            since,
            facts,
        );
    }

    pub(super) fn control_effects_len(&self) -> usize {
        match &self.capture {
            Some(cap) => cap.effects.len(),
            None => self.builder.effects_len(),
        }
    }

    pub(super) fn call_inner(&mut self, call: &ast::ExprCall) -> CallControl {
        self.prepare_call_summaries(&call.func);
        for argument in &call.args {
            self.prepare_call_summaries(argument);
        }
        for keyword in &call.keywords {
            self.prepare_call_summaries(&keyword.value);
        }
        if self
            .import_search
            .as_ref()
            .and_then(|search| search.pytest_mode)
            == Some(PytestMode::Collect)
            && callee_written(&call.func).as_deref() == Some("metafunc.parametrize")
            && self.current_function.as_deref().is_some_and(|name| {
                name.rsplit('.').next() == Some("pytest_generate_tests")
                    && self.defs.iter().any(|def| {
                        def.name == name
                            && def
                                .parameter_bindings
                                .iter()
                                .any(|param| param == "metafunc")
                    })
            })
        {
            self.apply_pytest_parametrize_ids(call);
        }
        let span = call.range;
        if !self.safe_python_call(call) && !self.safe_python_method(call) {
            self.modeled_values
                .retain(|_, value| !matches!(value, model::ModeledValue::BuiltinData));
        }
        if self.ipython_call(call) {
            return CallControl::Modeled;
        }
        if let Some(class) = callee_written(&call.func)
            && self.class_names.contains(&class)
            && self
                .defs
                .iter()
                .any(|def| def.name == format!("{class}.__del__"))
        {
            self.apply_local_arguments(&format!("{class}.__del__"), &[], span);
        }
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && matches!(
                attribute.attr.as_str(),
                "append"
                    | "extend"
                    | "insert"
                    | "pop"
                    | "remove"
                    | "clear"
                    | "update"
                    | "setdefault"
            )
            && let Expr::Name(name) = attribute.value.as_ref()
        {
            self.invalidate_collection(name.id.as_str());
        }
        // In capture mode, record a user-function call edge (local or imported)
        // for cross-file linking, in addition to the effect handling below.
        if self.capture.is_some() {
            // Reserve the enclosing call before deriving receiver/argument
            // instances. Nested constructors then follow it lexically and
            // reuse the same Site when their own edge is visited later.
            let origin = self.site_origin(call.range, 0);
            if let Some(edges) = self.finite_class_edges(call) {
                let binds = if let Some((range, _)) = &self.pending_binds
                    && *range == call.range
                    && let Some((_, targets)) = self.pending_binds.take()
                {
                    for (_, name) in &targets {
                        self.bound_vars.insert(name.clone());
                    }
                    targets
                } else {
                    Vec::new()
                };
                for mut edge in edges {
                    edge.awaited = self.executes_deferred_call(call.range);
                    edge.results = call_results(
                        binds.clone(),
                        Some(origin.clone()),
                        self.python_external_call_type(call),
                    );
                    let pushed = if let Some(cap) = self.capture.as_mut()
                        && cap.calls.len() < MAX_CALL_EDGES
                    {
                        let index = cap.calls.len();
                        cap.calls.push(edge);
                        Some(index)
                    } else {
                        None
                    };
                    if let Some(index) = pushed
                        && let Some((name, ranges)) = &self.pending_deferred_container
                        && ranges.contains(&call.range)
                    {
                        self.deferred_containers
                            .entry(name.clone())
                            .or_default()
                            .push(index);
                    }
                }
            } else if let Some(mut edge) = self.call_edge(call) {
                edge.awaited = self.executes_deferred_call(call.range);
                let mut binds = Vec::new();
                // The enclosing assignment binds this call's result: record the
                // bound locals on the edge (typed at composition time via the
                // callee's `returns_instances`).
                if let Some((range, _)) = &self.pending_binds
                    && *range == call.range
                    && let Some((_, targets)) = self.pending_binds.take()
                {
                    for (_, name) in &targets {
                        self.bound_vars.insert(name.clone());
                    }
                    binds = targets;
                }
                edge.results =
                    call_results(binds, Some(origin), self.python_external_call_type(call));
                let pushed = if let Some(cap) = self.capture.as_mut()
                    && cap.calls.len() < MAX_CALL_EDGES
                {
                    let index = cap.calls.len();
                    cap.calls.push(edge);
                    Some(index)
                } else {
                    None
                };
                if let Some(index) = pushed
                    && let Some((name, ranges)) = &self.pending_deferred_container
                    && ranges.contains(&call.range)
                {
                    self.deferred_containers
                        .entry(name.clone())
                        .or_default()
                        .push(index);
                }
            }
        }
        if let Some(name) = self.imports.resolve_local_callee(&call.func) {
            if self.apply_imported_call(&name, call, span) {
                return CallControl::Modeled;
            }
            self.emit_unresolved_call(
                &name,
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                span,
                python_callee_reference(&name),
            );
            return CallControl::Opaque;
        }
        if self.imports.resolve_callee(&call.func).as_deref() == Some("getattr")
            && self.local_callee(&Expr::Call(call.clone())).is_some()
        {
            return CallControl::Opaque;
        }
        if self.importlib_boundary(call) || self.component_lifecycle_call(call) {
            return CallControl::Opaque;
        }
        if self.safe_python_method(call) || self.model_call(call, span) {
            return CallControl::Modeled;
        }
        if let Expr::Attribute(attr) = call.func.as_ref()
            && matches!(attr.attr.as_str(), "read" | "readline" | "readlines")
            && self.modeled_value(&attr.value) == Some(model::ModeledValue::FileContext)
        {
            return CallControl::Modeled;
        }
        if let Expr::Attribute(attr) = call.func.as_ref()
            && matches!(
                attr.attr.as_str(),
                "write" | "writelines" | "read" | "readline" | "readlines" | "close" | "flush"
            )
            && self
                .instance_class_name(&attr.value)
                .is_some_and(|class| matches!(class.as_str(), "open" | "io.open"))
        {
            return CallControl::Modeled;
        }

        if !self.safe_python_call(call) {
            self.invalidate_memory_tar();
        }

        // Unknown code can mutate a Request through an alias or a global.
        // Keep its endpoint only across calls whose behavior is accounted for.
        if !matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some("urllib.request.Request" | "urllib.request.urlopen")
        ) && !self.safe_python_call(call)
        {
            self.modeled_values
                .retain(|_, value| !matches!(value, model::ModeledValue::Request { .. }));
        }
        let Some(name) = self.imports.resolve_callee(&call.func) else {
            // Follow known same-file receivers; an unknown receiver with a
            // local method candidate needs an explicit dispatch boundary.
            if let Some(id) = self.local_callee(&call.func) {
                let def = self.defs.iter().find(|def| def.name == id);
                let deferred = def.is_some_and(|def| def.is_async || def.is_generator);
                let consumed_generator =
                    self.execute_deferred && def.is_some_and(|def| def.is_generator);
                if self.executes_deferred_call(call.range) || consumed_generator || !deferred {
                    self.apply_local(&id, call, span);
                    return CallControl::Local;
                }
                // Creating a coroutine or generator runs none of its body.
                return CallControl::Modeled;
            } else {
                let name = callee_written(&call.func).unwrap_or_else(|| {
                    self.source[usize::from(call.func.range().start())
                        ..usize::from(call.func.range().end())]
                        .to_string()
                });
                self.emit_unresolved_call(
                    &name,
                    BoundaryReason::DYNAMIC_DISPATCH,
                    BoundaryClass::Unresolved,
                    crate::external::ALL_DOMAINS,
                    span,
                    Some(CalleeReference {
                        module: "python".to_string(),
                        symbol: name.clone(),
                    }),
                );
            }
            return CallControl::Opaque;
        };
        if self.safe_python_call(call) {
            return CallControl::Modeled;
        }
        let arity = (!call.args.iter().any(|arg| matches!(arg, Expr::Starred(_)))
            && call.keywords.iter().all(|kw| kw.arg.is_some()))
        .then_some(call.args.len());
        if name == "django.core.management.execute_from_command_line" {
            self.django_management_call(call, span);
        }
        self.unresolved_call(&name, arity, span, self.python_operands_safe(call))
    }

    /// `execute_from_command_line` runs the management command its argument
    /// vector names after the program name, as `django-admin` does. A vector
    /// Nah cannot recover runs no command it can name, and says so. The call
    /// itself stays unresolved: the command runs project code.
    pub(super) fn django_management_call(&mut self, call: &ast::ExprCall, span: TextRange) {
        let launch = self.builder.current_execution_argv();
        let launch = launch
            .get(1..)
            .unwrap_or_default()
            .iter()
            .map(|word| match word {
                ResourceExpr::Literal { value } => Some(value.clone()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let words = match argv::argument_vector(&self.imports, self.source, call, launch) {
            argv::ArgumentVector::Known(words) => words,
            argv::ArgumentVector::Symbolic => return,
            argv::ArgumentVector::Unknown => {
                let node = self.span_node(span);
                for domain in crate::external::ALL_DOMAINS {
                    self.out_coverage(Domain::new(*domain), CoverageLevel::Partial);
                }
                self.out_boundary(Boundary {
                    reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: crate::external::ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: vec![node],
                    limit: None,
                    detail: Some(
                        "sys.argv or the argument vector is changed or shared where Nah cannot \
                         recover it; the management command execute_from_command_line runs is \
                         unknown"
                            .to_string(),
                    ),
                });
                return;
            }
        };
        let argv = std::iter::once("django-admin".to_string())
            .chain(words)
            .collect();
        let node = self.span_node(span);
        self.apply_deferred_spawn(
            super::subprocess_launch::CapturedSpawn {
                spawn: DeferredSpawn::Command { argv },
                source: None,
            },
            &std::collections::HashMap::new(),
            node,
            span,
        );
    }

    pub(super) fn importlib_boundary(&mut self, call: &ast::ExprCall) -> bool {
        let canonical = if let Expr::Attribute(attr) = call.func.as_ref()
            && attr.attr.as_str() == "select"
            && self.modeled_value(&attr.value) == Some(model::ModeledValue::EntryPoints)
        {
            "importlib.metadata.entry_points".to_string()
        } else if let Some(canonical) = callee_written(&call.func)
            .and_then(|written| self.imports.resolve_import_written(&written))
        {
            canonical
        } else {
            return false;
        };
        let (label, value) = match canonical.as_str() {
            "importlib.util.spec_from_file_location" => {
                ("plugin path", python_call_argument(call, 1, "location"))
            }
            "importlib.metadata.entry_points" => (
                "entry-point group",
                python_call_argument(call, usize::MAX, "group"),
            ),
            "importlib.import_module"
                if python_call_argument(call, 0, "name")
                    .is_none_or(|value| str_literal(value).is_none()) =>
            {
                ("dynamic module", python_call_argument(call, 0, "name"))
            }
            _ => return false,
        };
        let detail = value
            .map(|value| {
                if label != "plugin path"
                    && let Some(literal) = str_literal(value)
                {
                    return literal.to_string();
                }
                let resource = if label != "plugin path" {
                    substitute_resource_expr(&self.fs_resource(value), &self.var_scope)
                } else {
                    self.resolve_fs(value)
                };
                python_plugin_path_pattern(&resource).unwrap_or_else(|| {
                    self.source
                        [usize::from(value.range().start())..usize::from(value.range().end())]
                        .to_string()
                })
            })
            .unwrap_or_else(|| "unspecified".to_string());
        let node = self.span_node(call.range);
        self.out_boundary(Boundary {
            reason: BoundaryReason::CROSS_MODULE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: (label == "plugin path")
                .then(|| value.map(|value| self.resolve_fs(value)))
                .flatten(),
            callee: python_callee_reference(&canonical),
            domains: crate::external::ALL_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("{canonical}: {label} {detail}")),
        });
        true
    }

    pub(super) fn component_lifecycle_call(&mut self, call: &ast::ExprCall) -> bool {
        let Some(canonical) = self.imports.resolve_callee(&call.func) else {
            return false;
        };
        let Some((model, sig)) = crate::LIFECYCLE_CATALOG.iter().find_map(|model| {
            model
                .component_signature(&canonical)
                .map(|sig| (model, sig))
        }) else {
            return false;
        };
        let index = sig.component.unwrap();
        let component = python_call_argument(call, index, sig.params[0]);
        let name = component.and_then(callee_written);
        let class = name.as_ref().filter(|name| {
            self.class_names.contains(*name) && !self.receiver_rebindings.contains(*name)
        });
        let alternatives = component.is_none() || class.is_some();
        let roots: Vec<_> = if let Some(class) = class {
            self.defs
                .iter()
                .filter(|def| {
                    def.parent.is_none()
                        && def.owner.as_ref() == Some(class)
                        && def
                            .name
                            .strip_prefix(&format!("{class}."))
                            .is_some_and(|method| !method.starts_with('_'))
                })
                .map(|def| def.name.clone())
                .collect()
        } else if let Some(component) = component {
            (self.imports.resolve_callee(component).is_none()
                && self.imports.resolve_local_callee(component).is_none()
                && name
                    .as_ref()
                    .is_none_or(|name| !self.receiver_rebindings.contains(name)))
            .then(|| self.local_callee(component))
            .flatten()
            .into_iter()
            .collect()
        } else {
            self.defs
                .iter()
                .filter(|def| {
                    def.parent.is_none()
                        && def.owner.is_none()
                        && !self.receiver_rebindings.contains(&def.name)
                })
                .map(|def| def.name.clone())
                .collect()
        };
        if roots.is_empty()
            && self.fact_scope.is_none()
            && let Some(component) = component
            && let Some(canonical) = self
                .imports
                .resolve_local_callee(component)
                .or_else(|| self.imports.resolve_callee(component))
        {
            let invocation = ast::ExprCall {
                range: call.range,
                func: Box::new(component.clone()),
                args: Vec::new(),
                keywords: Vec::new(),
            };
            if self.apply_imported_call(&canonical, &invocation, call.range) {
                return true;
            }
        }
        if component.is_none() || roots.is_empty() {
            self.emit_unresolved_call(
                &if component.is_none() {
                    format!(
                        "{} component dispatch: {} module-level callable candidates",
                        model.id,
                        roots.len()
                    )
                } else {
                    format!(
                        "{} component dispatch: unresolved component{}",
                        model.id,
                        name.as_ref()
                            .map(|name| format!(" {name}"))
                            .unwrap_or_default()
                    )
                },
                BoundaryReason::DYNAMIC_DISPATCH,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                call.range,
                None,
            );
        }
        // Repository capture retains the lifecycle call; composition owns activation.
        if self.fact_scope.is_some() {
            return true;
        }
        let count = roots.len() as u32;
        for (arm, root) in roots.iter().enumerate() {
            if alternatives {
                self.builder.push_condition(self.builder.source_condition(
                    self.source,
                    effinterp_proto::ByteSpan {
                        start: call.range.start().into(),
                        end: call.range.end().into(),
                    },
                    effinterp_proto::ConditionKind::Branch,
                    arm as u32,
                    count.max(2),
                    true,
                    true,
                ));
            }
            self.apply_local_arguments(root, &[], call.range);
            if alternatives {
                self.builder.pop_condition();
            }
        }
        true
    }

    /// Decide whether a call is an outgoing user-function edge (a cross-file
    /// linking candidate), returning it with arguments resolved in the caller's
    /// scope. Modeled effect APIs and dynamic builtins contribute effects, not
    /// edges, and return None.
    pub(super) fn call_edge(&self, call: &ast::ExprCall) -> Option<CallEdge> {
        if self
            .registration_spans
            .contains(&(call.range.start().to_u32(), call.range.end().to_u32()))
        {
            return None;
        }
        if self.safe_python_method(call) {
            return None;
        }
        if self.deferred_consumer(call) {
            return None;
        }
        if let Expr::Attribute(attr) = call.func.as_ref()
            && self.is_path_method_receiver(attr.attr.as_str(), &attr.value)
        {
            return None;
        }
        if self.typed_path_call(call).is_some() {
            return None;
        }
        // `Class().method(...)` has no dotted written name (the base is a
        // call). Recover it from the constructor so composition can dispatch
        // `App().run()` through the constructed class.
        let mut ctor_recv = None;
        let callee = match callee_written(&call.func) {
            Some(c) => c,
            None => {
                let Expr::Attribute(attr) = call.func.as_ref() else {
                    return None;
                };
                let Expr::Call(inner) = attr.value.as_ref() else {
                    return None;
                };
                let iref = if matches!(inner.func.as_ref(), Expr::Name(name) if name.id.as_str() == "super")
                {
                    let owner = self.current_class.as_ref()?;
                    let base = self.class_bases.get(owner)?.first()?.clone();
                    SemanticValue::object(ObjectIdentity::Class {
                        name: base,
                        constructor: Vec::new(),
                    })
                } else {
                    self.ctor_class(inner)?
                };
                let name = match iref.as_object().map(|object| &object.identity) {
                    Some(ObjectIdentity::Class { name, .. }) => name.clone(),
                    Some(ObjectIdentity::DynamicClass) => "cls".to_string(),
                    _ => return None,
                };
                ctor_recv = Some(iref);
                format!("{name}.{}", attr.attr.as_str())
            }
        };
        let component_lifecycle =
            self.imports
                .resolve_callee(&call.func)
                .is_some_and(|canonical| {
                    crate::LIFECYCLE_CATALOG
                        .iter()
                        .any(|model| model.component_signature(&canonical).is_some())
                });
        let callback = |arg: &Expr| {
            if component_lifecycle {
                (self.imports.resolve_callee(arg).is_none()
                    && self.imports.resolve_local_callee(arg).is_none()
                    && callee_written(arg)
                        .is_none_or(|name| !self.receiver_rebindings.contains(&name)))
                .then(|| self.local_callee(arg))
                .flatten()
            } else {
                self.local_fn_name(arg)
            }
        };
        let mut extra_arguments = Vec::new();
        for (i, arg) in call.args.iter().enumerate() {
            if let Some(func) = callback(arg) {
                extra_arguments.push(ValueArgument {
                    name: None,
                    index: i,
                    value: SemanticValue::callable(func),
                });
            }
        }
        for kw in &call.keywords {
            let Some(param) = kw.arg.as_ref() else {
                continue;
            };
            if let Some(func) = callback(&kw.value) {
                extra_arguments.push(ValueArgument {
                    name: Some(param.to_string()),
                    index: 0,
                    value: SemanticValue::callable(func),
                });
            }
        }
        let mut recv = ctor_recv;
        let local_import = self.imports.resolve_local_callee(&call.func);
        match self
            .imports
            .resolve_callee(&call.func)
            .or_else(|| local_import.clone())
        {
            // Resolves through a tracked import: a modeled root or dynamic
            // builtin is an effect/boundary, not an edge; any other module is a
            // user function reached across files.
            Some(canon) => {
                let root = canon.split('.').next().unwrap_or(&canon);
                if local_import.is_none()
                    && (PYTHON_MODELED_ROOTS.contains(&root)
                        || resolve::is_builtin(&canon)
                        || is_builtin_effect(&canon))
                {
                    return None;
                }
                recv = self.recv_of(&call.func);
            }
            // Not a tracked import: a bare name bound to a module-level
            // function or to a parameter of the current function (a callback
            // site) is an edge; a `cls(...)` constructor or a method call on
            // an unambiguous receiver is a typed-dispatch edge; a call that
            // cannot be resolved at all still carries an edge when it is
            // handed local functions as arguments (argparse's
            // `p.set_defaults(func=_cmd_x)`), so the composer can treat the
            // registered callbacks as may-invoked; anything else is effectless.
            None if recv.is_none() => match call.func.as_ref() {
                Expr::Name(n) if n.id.as_str() == "cls" => {
                    recv = Some(SemanticValue::object(ObjectIdentity::DynamicClass))
                }
                Expr::Name(n)
                    if self.defs.iter().any(|d| d.name == n.id.as_str())
                        || self.current_params.iter().any(|p| p == n.id.as_str())
                        || self.class_names.contains(n.id.as_str()) => {}
                _ => {
                    recv = self.recv_of(&call.func);
                    if recv.is_none() && extra_arguments.is_empty() {
                        return None;
                    }
                }
            },
            None => {}
        }
        let mut arguments = self.value_args_of(call);
        merge_arguments(&mut arguments, extra_arguments);
        Some(CallEdge {
            condition: self.builder.condition_since(self.capture_condition_depth),
            call_site: Some(
                self.condition_source
                    .call_site(&(u32::from(call.range.start()), u32::from(call.range.end()))),
            ),
            callee,
            arguments,
            awaited: false,
            effects_propagated: false,
            external_inert: self
                .safe_python_call(call)
                .then(|| self.imports.resolve_callee(&call.func))
                .flatten(),
            lifecycle_registration: false,
            dynamic_target: false,
            callee_span: None,
            receiver: recv,
            results: Vec::new(),
            writes: Vec::new(),
        })
    }

    /// Expand `for cls in CLASSES: cls(arg)` only when `CLASSES` is a static
    /// tuple of written class names. Each constructor remains tied to its exact
    /// import; composition discards tuple members that are not real classes.
    pub(super) fn finite_class_edges(&self, call: &ast::ExprCall) -> Option<Vec<CallEdge>> {
        let Expr::Name(callee) = call.func.as_ref() else {
            return None;
        };
        let classes = self.class_set_vars.get(callee.id.as_str())?;
        let arguments = self.value_args_of(call);
        Some(
            classes
                .iter()
                .map(|name| CallEdge {
                    condition: None,
                    call_site: None,
                    callee: name.clone(),
                    arguments: arguments.clone(),
                    awaited: false,
                    effects_propagated: false,
                    external_inert: self
                        .safe_python_call(call)
                        .then(|| self.imports.resolve_callee(&call.func))
                        .flatten(),
                    lifecycle_registration: false,
                    dynamic_target: false,
                    callee_span: None,
                    receiver: Some(SemanticValue::object(ObjectIdentity::Class {
                        name: name.clone(),
                        constructor: arguments.clone(),
                    })),
                    results: Vec::new(),
                    writes: Vec::new(),
                })
                .collect(),
        )
    }
}

/// How a call's evaluation was modeled, for its control-flow site.
pub(super) enum CallControl {
    /// A modeled API or inert builtin: it returns, producing what it produced.
    Modeled,
    /// A same-file callee applied through its summary.
    Local,
    /// Code nothing models, which may complete the invocation.
    Opaque,
}

pub(super) fn python_callee_reference(name: &str) -> Option<CalleeReference> {
    let (module, symbol) = name.rsplit_once('.')?;
    (!module.is_empty() && !symbol.is_empty()).then(|| CalleeReference {
        module: module.to_string(),
        symbol: symbol.to_string(),
    })
}

/// Whether a resolved callee is a modeled builtin or dynamic construct (an
/// effect or boundary), rather than a user function to link across files.
fn is_builtin_effect(canon: &str) -> bool {
    matches!(
        canon,
        "open" | "eval" | "exec" | "__import__" | "compile" | "os.exec"
    )
}

pub(super) fn keyword_bool(call: &ast::ExprCall, name: &str) -> Option<bool> {
    call.keywords
        .iter()
        .find(|k| k.arg.as_ref().map(|a| a.as_str()) == Some(name))
        .and_then(|k| match &k.value {
            Expr::Constant(c) => match c.value {
                Constant::Bool(b) => Some(b),
                _ => None,
            },
            _ => None,
        })
}

pub(super) fn python_call_argument<'a>(
    call: &'a ast::ExprCall,
    index: usize,
    name: &str,
) -> Option<&'a Expr> {
    call.args.get(index).or_else(|| {
        call.keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some(name))
            .map(|keyword| &keyword.value)
    })
}

impl PythonWalker<'_, '_> {
    pub(super) fn python_external_call_type(&self, call: &ast::ExprCall) -> Option<TypeRef> {
        self.imports
            .resolve_callee(&call.func)
            .as_deref()
            .and_then(model::python_external_type)
    }

    /// A bare name that resolves to a module-level function in this file.
    fn local_fn_name(&self, expr: &Expr) -> Option<String> {
        let has = |n: &str| self.defs.iter().any(|d| d.name == n);
        match expr {
            Expr::Name(n) => {
                let id = n.id.as_str();
                if let Some(parent) = &self.current_function
                    && let Some(def) = self
                        .defs
                        .iter()
                        .find(|def| def.parent.as_deref() == Some(parent) && def.local_name == id)
                {
                    return Some(def.name.clone());
                }
                has(id).then(|| id.to_string())
            }
            // `self.boot` / `App.boot` passed to a registrar (`add_listener`,
            // `add_command`) is the same local function as a bare `boot`.
            Expr::Attribute(a) => {
                let method = a.attr.as_str();
                match a.value.as_ref() {
                    Expr::Name(n) if matches!(n.id.as_str(), "self" | "cls") => {
                        has(method).then(|| method.to_string())
                    }
                    Expr::Name(n) => {
                        let qualified = format!("{}.{method}", n.id);
                        if has(&qualified) {
                            Some(qualified)
                        } else {
                            has(method).then(|| method.to_string())
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// A call target that is a function defined in this file: a bare name,
    /// `self.method` / `cls.method`, `Class.method`, or a `Class()` constructor.
    pub(super) fn local_callee(&self, func: &Expr) -> Option<String> {
        let has = |n: &str| self.defs.iter().any(|d| d.name == n);
        match func {
            Expr::Name(n) => {
                let id = n.id.as_str();
                // A nested function names its own inner functions and
                // those of each function it is written inside (a sibling
                // helper), nearest first, until a scope binds the name as
                // something else.
                let mut scope = self.current_function.as_deref();
                while let Some(function) = scope {
                    if let Some(def) = self
                        .defs
                        .iter()
                        .find(|def| def.parent.as_deref() == Some(function) && def.local_name == id)
                    {
                        // An enclosing function that defines the name
                        // twice or also binds it another way (`load =
                        // str`), or a function that declares it
                        // `nonlocal`, may have replaced the helper by the
                        // time this body runs.
                        let defines = |stmt: &Stmt| {
                            matches!(stmt,
                                Stmt::FunctionDef(ast::StmtFunctionDef { name, .. })
                                | Stmt::AsyncFunctionDef(ast::StmtAsyncFunctionDef { name, .. })
                                    if name.as_str() == id)
                        };
                        let rebound = self.current_function.as_deref() != Some(function)
                            && ((self.defs.iter())
                                .any(|def| summary::declared_shared(&def.body).1.contains(id))
                                || (self.defs.iter())
                                    .find(|def| def.name == function)
                                    .is_some_and(|enclosing| {
                                        let body = enclosing.body.iter();
                                        body.clone().filter(|stmt| defines(stmt)).count() > 1
                                            || body.clone().any(|stmt| {
                                                !defines(stmt)
                                                    && bound_body_names(std::slice::from_ref(stmt))
                                                        .contains(id)
                                            })
                                    }));
                        return (!rebound).then(|| def.name.clone());
                    }
                    scope = (self.defs.iter())
                        .find(|def| def.name == function)
                        .filter(|def| {
                            !def.parameter_bindings.iter().any(|bound| bound == id)
                                && !bound_body_names(&def.body).contains(id)
                        })
                        .and_then(|def| def.parent.as_deref());
                }
                if has(id) {
                    return Some(id.to_string());
                }
                let init = format!("{id}.__init__");
                has(&init).then_some(init)
            }
            Expr::Attribute(attr) => {
                let method = attr.attr.as_str();
                match attr.value.as_ref() {
                    Expr::Name(n) if matches!(n.id.as_str(), "self" | "cls") => {
                        has(method).then(|| method.to_string())
                    }
                    Expr::Name(n) => {
                        if let Some(ObjectIdentity::Class { name, .. }) = self
                            .instance_vars
                            .get(n.id.as_str())
                            .and_then(SemanticValue::as_object)
                            .map(|object| &object.identity)
                        {
                            let qualified = format!("{name}.{method}");
                            if has(&qualified) {
                                return Some(qualified);
                            }
                        }
                        let qualified = format!("{}.{method}", n.id);
                        has(&qualified).then_some(qualified)
                    }
                    Expr::Call(_) => {
                        let receiver = self.instance_value(&attr.value)?;
                        let ObjectIdentity::Class { name, .. } = &receiver.as_object()?.identity
                        else {
                            return None;
                        };
                        let qualified = format!("{name}.{method}");
                        has(&qualified).then_some(qualified)
                    }
                    _ => None,
                }
            }
            Expr::Subscript(subscript) => {
                let key = str_literal(&subscript.slice)?;
                let Expr::Dict(dict) = subscript.value.as_ref() else {
                    return None;
                };
                let value =
                    dict.keys
                        .iter()
                        .zip(&dict.values)
                        .rev()
                        .find_map(|(candidate, value)| {
                            (candidate.as_ref().and_then(str_literal).as_deref()
                                == Some(key.as_str()))
                            .then_some(value)
                        })?;
                self.local_callee(value)
            }
            Expr::Call(call) => {
                if self.imports.resolve_callee(&call.func).as_deref() == Some("getattr")
                    && call.args.len() == 2
                    && call.keywords.is_empty()
                {
                    let class = self.instance_class_name(&call.args[0])?;
                    let member = str_literal(&call.args[1])?;
                    let name = format!("{class}.{member}");
                    return has(&name).then_some(name);
                }
                let producer = self.local_callee(&call.func)?;
                let definition = self
                    .defs
                    .iter()
                    .find(|def| def.name == producer && !def.is_async && !def.is_generator)?;
                let Stmt::Return(returned) = definition.body.last()? else {
                    return None;
                };
                let Expr::Name(returned) = returned.value.as_deref()? else {
                    return None;
                };
                self.defs
                    .iter()
                    .find(|def| {
                        def.parent.as_deref() == Some(producer.as_str())
                            && def.local_name == returned.id.as_str()
                    })
                    .map(|def| def.name.clone())
            }
            _ => None,
        }
    }

    // Return and receiver inference precedes effect emission at an assignment or
    // sink. Prepare only the calls in that expression, innermost first.
    pub(super) fn prepare_call_summaries(&mut self, value: &Expr) {
        if !self.demand_summaries {
            return;
        }
        let mut stack = vec![(value, false)];
        while let Some((expr, visited)) = stack.pop() {
            if visited {
                if let Expr::Call(call) = expr
                    && let Some(name) = self.local_callee(&call.func)
                {
                    self.ensure_summary(&name);
                }
            } else {
                if !self.charge(expr.range()) {
                    break;
                }
                stack.push((expr, true));
                stack.extend(
                    child_exprs(expr)
                        .into_iter()
                        .rev()
                        .map(|child| (child, false)),
                );
            }
        }
    }

    /// Record a call that resolved through a tracked import but matched no
    /// model arm or the operand safety check. It remains a loud boundary:
    /// module provenance alone never
    /// implies effect coverage. A callee whose module is not recognized as
    /// external stays the internal `unresolved_call` boundary across every
    /// domain, since nothing bounds what it can reach. Deduplicated by callee
    /// and source occurrence.
    fn unresolved_call(
        &mut self,
        name: &str,
        arity: Option<usize>,
        span: TextRange,
        operands_safe: bool,
    ) -> CallControl {
        let (reason, class, domains) = match crate::external::classify_python_call(name, arity) {
            Some(crate::external::ExternalCall::Unmodeled(domains)) => (
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                if operands_safe {
                    domains
                } else {
                    crate::external::ALL_DOMAINS
                },
            ),
            Some(_) => (
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                crate::external::ALL_DOMAINS,
            ),
            None => (
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
            ),
        };
        let callee = python_callee_reference(name).or_else(|| {
            resolve::is_builtin(name).then(|| CalleeReference {
                module: "builtins".into(),
                symbol: name.into(),
            })
        });
        self.emit_unresolved_call(name, reason, class, domains, span, callee);
        CallControl::Opaque
    }

    pub(super) fn emit_unresolved_call(
        &mut self,
        name: &str,
        reason: BoundaryReason,
        class: BoundaryClass,
        domains: crate::external::Domains,
        span: TextRange,
        callee: Option<CalleeReference>,
    ) {
        self.invalidate_memory_tar();
        self.invalidate_shared_vars();
        if !self.reported_unresolved.insert((name.to_string(), span)) {
            return;
        }
        let node = self.span_node(span);
        for domain in domains {
            self.out_coverage(Domain::new(*domain), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee,
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call to unmodeled {name}")),
        });
    }
}
