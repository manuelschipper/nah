//! Execution of resolved Go calls in a live plan or a summary walk.

use std::collections::{HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef, ResourceExpr,
};
use gosyn::ast::Expression;

use crate::control_flow::{ControlFact, SiteFacts};
use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::module_summary::{CallEdge, call_results};
use crate::summary::{bind_positional, substitute_resource_expr};
use crate::value::unresolved_resource;
use crate::{SemanticValue, ValueArgument, ValueOrigin, merge_arguments, positional_arguments};

use super::call_resolution::{GO_BUILTINS, GoCallee, go_callee_name};
use super::control::GoCallControlKind;
use super::semantic_values::exact_go_property_value;
use super::walk_output::GoWalkOutput;
use super::walker::GoWalker;
use super::{GO_DOMAINS, MAX_SUMMARY_ITEMS, control};

impl GoWalker<'_, '_> {
    /// Walk a Go call, reserving its assignment results while nested calls are walked.
    pub(super) fn walk_go_call(&mut self, call: &gosyn::ast::Call) {
        let depth = if let GoWalkOutput::Plan { builder, .. } = &mut self.out {
            let depth = builder.condition_depth();
            for condition in &self.conditions {
                builder.push_bound_condition(condition.clone());
            }
            Some(depth)
        } else {
            None
        };
        self.walk_go_call_inner(call);
        if let (Some(depth), GoWalkOutput::Plan { builder, .. }) = (depth, &mut self.out) {
            while builder.condition_depth() > depth {
                builder.pop_condition();
            }
        }
    }

    fn walk_go_call_inner(&mut self, call: &gosyn::ast::Call) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        if self.over_node_budget(control::call_span(call)) {
            self.partial_nodes();
            return;
        }
        self.walk_depth += 1;
        let control_since = self.control_registered();
        let control_saved = std::mem::take(&mut self.control_applications);
        // The enclosing assignment's binds belong to THIS call, not to calls
        // nested in its arguments.
        let binds = std::mem::take(&mut self.binds_next_call);
        // Reserve the enclosing call's Site before descending into its receiver
        // or arguments so ordinals follow lexical source order.
        let origin = self.collect_edges.then(|| self.next_go_site_origin());
        // An immediately-invoked literal (`defer func() {...}()`) executes.
        if let Expression::FuncLit(fl) = &*call.func {
            self.walk_function_literal(fl);
        }
        let control_immediate = self.control_applications.len();
        // Recurse into sub-expressions first (method chains like
        // exec.Command(...).Run() carry the effectful Command as func.x, and
        // arguments may themselves be effect calls). A receiver that is itself
        // a call is bound to a synthetic local first, so that call's own edge
        // records the local as its result and the method can dispatch on it.
        let chained_receiver = self.bind_chained_receiver(&call.func);
        if let Expression::Selector(sel) = &*call.func {
            if let Some(recv) = &chained_receiver {
                self.binds_next_call = vec![(0, recv.clone())];
            }
            self.walk_go_expression(&sel.x);
            self.binds_next_call.clear();
        } else if !matches!(&*call.func, Expression::FuncLit(_)) {
            self.walk_go_expression(&call.func);
        }
        for arg in &call.args {
            self.widen_escaped_channel(arg);
            self.walk_go_expression(arg);
        }

        self.current_binds = binds;
        let node = self.record_go_source_provenance(control::call_span(call));
        let mut callee = self.resolve_go_callee(&call.func);
        if let (GoCallee::Unknown, Some(recv), Expression::Selector(sel)) =
            (&callee, &chained_receiver, &*call.func)
        {
            callee = GoCallee::Method {
                recv: recv.clone(),
                method: sel.sel.name.clone(),
            };
        }
        // A standard-library call is entered by no later stage: neither this
        // file nor composition walks into `sort.Slice` or `sync.Once.Do`, so a
        // callable one of them invokes is accounted for here, as may-executed.
        // Only the argument positions such an entry point is known to call are
        // walked — every other argument is data, and passing a function value
        // as data (`fmt.Println(cleanup)`) is not a call. A call into an
        // unknown target is handled by the unknown-caller pass below instead:
        // outside a fact scope it walks the target's function arguments as
        // may-executed, and the target keeps its own unresolved boundary.
        let external_callee = match &callee {
            GoCallee::Pkg { path, method, .. } => self.stdlib_target(path, method),
            GoCallee::Method { recv, method } => self
                .go_receiver_import_path(recv)
                .is_some_and(|path| self.stdlib_target(&path, method)),
            _ => false,
        };
        // A callable this file cannot name (one arriving through a parameter,
        // a field, or a bound method) is walked by nobody, here or later.
        let mut escaped_callable = false;
        let callbacks = self.callback_positions(&callee);
        let mut entered: HashSet<usize> = HashSet::new();
        for index in callbacks {
            let Some(arg) = call.args.get(*index) else {
                continue;
            };
            if self.fire_callback_arg(arg, control::call_span(call), matches!(&callee, GoCallee::Pkg { path, method, .. } if matches!((path.as_str(), method.as_str(), *index), ("slices", "Sorted" | "Collect" | "SortedFunc" | "SortedStableFunc", 0) | ("slices", "AppendSeq", 1) | ("maps", "Collect", 0) | ("maps", "Insert", 1)))) {
                entered.insert(*index);
            } else {
                escaped_callable = true;
            }
        }
        // Unknown callees may invoke any function argument. Keep the local
        // may-effects as well as the caller's unresolved boundary.
        let unknown_caller = match &callee {
            GoCallee::Local(_) => false,
            GoCallee::Pkg { path, method, .. }
                if path == "fmt"
                    && matches!(
                        method.as_str(),
                        "Print"
                            | "Println"
                            | "Printf"
                            | "Sprint"
                            | "Sprintln"
                            | "Sprintf"
                            | "Fprint"
                            | "Fprintln"
                            | "Fprintf"
                    ) =>
            {
                false
            }
            GoCallee::Pkg { path, method, .. } => !matches!(
                crate::external::classify_go_call(path, method),
                Some(crate::external::ExternalCall::Inert | crate::external::ExternalCall::Modeled)
            ),
            _ => true,
        };
        if unknown_caller
            && self.fact_scope.is_none()
            && !matches!(&*call.func, Expression::Ident(id) if GO_BUILTINS.contains(&id.name.as_str()) && !self.local_vars.contains(&id.name))
        {
            for (index, argument) in call.args.iter().enumerate() {
                if !entered.contains(&index)
                    && (matches!(argument, Expression::FuncLit(_))
                        || self
                            .go_semantic_value(argument)
                            .is_some_and(|value| crate::contains_callable(&value)))
                    && self.fire_callback_arg(argument, control::call_span(call), false)
                {
                    entered.insert(index);
                }
            }
        }
        // A callable handed to a call this walk does not enter runs at a moment
        // nothing here observes, so the caller's bindings it assigns are stale
        // once the call returns. An argument the walk did enter above already
        // applied its writes exactly.
        let escaped_closures = self.escaped_argument_closures(&call.args, &entered);
        if !self.collect_edges
            && (escaped_callable
                || (!external_callee
                    && matches!(
                        &callee,
                        GoCallee::MaybeSibling(_)
                            | GoCallee::Dynamic(_)
                            | GoCallee::Method { .. }
                            | GoCallee::Unknown
                    )
                    && call.args.iter().any(|argument| {
                        self.go_semantic_value(argument)
                            .is_some_and(|value| crate::contains_callable(&value))
                    })))
        {
            self.out_boundary(Boundary {
                reason: BoundaryReason::ESCAPED_CALLABLE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: GO_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(
                    "callable passed to a call target this file cannot follow".to_string(),
                ),
            });
        }
        // Go hands a callee the caller's own storage for a pointer, a slice,
        // or a map, so a call may write what the caller holds. A body this file
        // can read names the parameters it writes through; a target it cannot
        // read may write through any of them.
        let escaped_arguments = self.escaped_call_arguments(&callee, &call.args);
        let written_names = escaped_arguments.names();
        self.pending_writes = written_names.clone();
        let control_callbacks = self.control_applications.len();
        let control_kind = self.go_call_control_kind(&callee, &call.func);
        let effects_before = self.effects_len();
        let calls_before = match &self.out {
            GoWalkOutput::Capture(cap) => cap.edges.len(),
            GoWalkOutput::Plan { .. } => 0,
        };
        match callee {
            GoCallee::Pkg {
                path,
                method,
                local,
            } => {
                // In edge-collection mode a call on an imported package qualifier
                // (`pkg.Func()`) is a cross-package call edge — the repo layer
                // resolves it to the package's file or emits an honest boundary
                // (quiet only for modeled or explicitly-inert stdlib calls).
                // Recording it is what lets composition leave `main` into
                // another package.
                if self.collect_edges {
                    let arg_exprs: Vec<ResourceExpr> = call
                        .args
                        .iter()
                        .map(|a| self.go_filesystem_resource(a))
                        .collect();
                    let obj_args = self.go_call_value_arguments(&call.args);
                    self.record_go_call_edge(
                        &format!("{local}.{method}"),
                        arg_exprs,
                        obj_args,
                        origin.clone(),
                    );
                    if self.capture_external_effects {
                        self.model_call(&path, &method, &call.args, node);
                    }
                } else {
                    self.model_call(&path, &method, &call.args, node);
                }
            }
            GoCallee::Local(name) => {
                self.enter_go_local_call(&name, &call.args, node, origin.clone(), false, None)
            }
            // A bare name defined in no local function: possibly a function in
            // a SIBLING file of the same package (a Go package spans the whole
            // directory). Recorded as an edge for the repo layer to resolve —
            // or drop — against the package's other files.
            GoCallee::MaybeSibling(name) => {
                if self.collect_edges {
                    self.record_go_bare_call_edge(&name, call, origin.clone(), false);
                } else {
                    self.unmodeled_external(&name, crate::external::ALL_DOMAINS, node, true);
                }
            }
            // A call through a locally bound name is recorded the same way,
            // but marked so composition follows only the bound value.
            GoCallee::Dynamic(name) => {
                if self.collect_edges {
                    self.record_go_bare_call_edge(&name, call, origin.clone(), true);
                } else if self.fact_scope.is_some() {
                    if !self.fire_callback_arg(&call.func, control::call_span(call), false) {
                        self.unmodeled_external(&name, crate::external::ALL_DOMAINS, node, true);
                    }
                } else if !self.dispatch_callable_value(&call.func, &call.args, node)
                    && !self.fire_callback_arg(&call.func, control::call_span(call), false)
                {
                    self.unresolved_callable(&name, node);
                }
            }
            // A method on a local variable: recorded with the receiver so the
            // composer can dispatch it when the variable is typed by an
            // unambiguous constructor's returns, a declared parameter type, or
            // a composite-literal assignment. An untyped receiver never
            // dispatches. Interface candidate cardinality is resolved across
            // the repository by the linker.
            GoCallee::Method { recv, method } => {
                if !self.collect_edges {
                    self.unresolved_interface(&recv, &method, node);
                }
                if self.collect_edges {
                    let arg_exprs: Vec<ResourceExpr> = call
                        .args
                        .iter()
                        .map(|a| self.go_filesystem_resource(a))
                        .collect();
                    let iref = self.go_receiver_value(&recv);
                    let mut obj_args = self.go_call_value_arguments(&call.args);
                    if let Some(value) = self.values.get(&recv).and_then(|value| {
                        exact_go_property_value(value, &method, self.value_limits)
                    }) {
                        obj_args.push(ValueArgument {
                            name: Some("$callee".to_string()),
                            index: usize::MAX,
                            value,
                        });
                    }
                    let origin = origin.clone().unwrap();
                    let binds = std::mem::take(&mut self.current_binds);
                    let mut arguments = positional_arguments(arg_exprs);
                    merge_arguments(&mut arguments, obj_args);
                    if let GoWalkOutput::Capture(cap) = &mut self.out
                        && cap.edges.len() < MAX_SUMMARY_ITEMS
                    {
                        cap.edges.push(CallEdge {
                            callee: format!("{recv}.{method}"),
                            arguments,
                            receiver: Some(iref),
                            results: call_results(binds, Some(origin), None),
                            writes: std::mem::take(&mut self.pending_writes),
                            ..Default::default()
                        });
                    }
                } else if self.fire_cobra_callbacks(&recv, &method, node) {
                } else if let Some(path) = self.go_receiver_import_path(&recv) {
                    if path == "database/sql"
                        && !self.go_receiver_type(&recv).is_some_and(|typ| {
                            matches!(typ.rsplit('.').next(), Some("DB" | "Tx" | "Conn"))
                        })
                    {
                        self.unmodeled_external(
                            &format!("{recv}.{method}"),
                            &["database"],
                            node,
                            false,
                        );
                    } else {
                        self.model_call(&path, &method, &call.args, node);
                    }
                } else if let Some(key) = self.go_receiver_method_key(&recv, &method) {
                    let receiver = self.values.get(&recv).cloned();
                    self.enter_go_local_call(
                        &key,
                        &call.args,
                        node,
                        origin.clone(),
                        false,
                        receiver,
                    );
                } else {
                    self.unmodeled_external(
                        &format!("{recv}.{method}"),
                        crate::external::ALL_DOMAINS,
                        node,
                        true,
                    );
                }
            }
            GoCallee::Unknown => {
                if !matches!(&*call.func, Expression::FuncLit(_))
                    && !matches!(&*call.func, Expression::Ident(id) if GO_BUILTINS.contains(&id.name.as_str()) && !self.local_vars.contains(&id.name))
                {
                    self.unmodeled_external(
                        &go_callee_name(&call.func),
                        crate::external::ALL_DOMAINS,
                        node,
                        true,
                    );
                }
            }
        }
        self.pending_writes.clear();
        let applied = std::mem::replace(&mut self.control_applications, control_saved);
        let mut facts = self.go_call_site_facts(
            control_kind,
            applied,
            control_immediate..control_callbacks,
            entered.len(),
            escaped_callable,
            effects_before..self.effects_len(),
        );
        facts.call_return = matches!(
            control_kind,
            GoCallControlKind::Local | GoCallControlKind::Opaque
        ) && control_immediate == control_callbacks
            && !escaped_callable;
        if let GoWalkOutput::Capture(cap) = &mut self.out
            && cap.edges.len() == calls_before + 1
        {
            facts.facts.push(ControlFact::Call(calls_before as u32));
            cap.call_sites
                .insert(control::call_span(call), calls_before as u32);
        }
        self.control_register_since(control::call_span(call), control_since, facts);
        for name in written_names {
            self.values.remove(&name);
            self.resource_values.remove(&name);
        }
        self.invalidate_escaped_storage(escaped_closures);
        for name in escaped_arguments.handed {
            // The declared type still holds — only what the binding contains is
            // stale — so the construction identity goes and the type stays. A
            // method writes through the object the receiver already names, so
            // that one keeps its identity: only its contents are stale.
            self.local_origins.remove(&name);
            self.instance_aliases.remove(&name);
        }
        self.current_binds.clear();
        self.walk_depth -= 1;
    }

    /// Enter local bodies with call-site values in a plan; summaries and edges serve composition.
    pub(super) fn enter_go_local_call(
        &mut self,
        name: &str,
        args: &[Expression],
        node: ProvenanceRef,
        origin: Option<ValueOrigin>,
        sequence: bool,
        receiver: Option<SemanticValue>,
    ) {
        let closure_body = self
            .named_go_function(name)
            .filter(|function| function.is_closure)
            .map(|function| (function.body.clone(), function.assigns_outer.clone()));
        if let Some((body, assigns_outer)) = closure_body {
            // A closure assigns the bindings it captured when it runs, so the
            // caller's exact view of a name it writes does not survive the call.
            for captured in assigns_outer {
                self.values.remove(&captured);
                self.resource_values.remove(&captured);
            }
            self.widen_channels_in_block(&body, 0);
            for value in self.channel_values.values_mut() {
                *value = unresolved_resource("filesystem");
            }
        }
        if self.collect_edges {
            let arg_exprs: Vec<ResourceExpr> = args
                .iter()
                .map(|a| self.go_filesystem_resource(a))
                .collect();
            let obj_args = self.go_call_value_arguments(args);
            self.record_go_call_edge(name, arg_exprs, obj_args, origin);
            return;
        }
        // Break recursion: a function already being inlined is not re-entered.
        if self.following.contains(name) {
            return;
        }
        if matches!(&self.out, GoWalkOutput::Plan { .. })
            && !sequence
            && let Some(function) = self.named_go_function(name).cloned()
        {
            // Ordinary functions see package bindings; closures also see their captured values.
            let mut values = if function.is_closure {
                self.values.clone()
            } else {
                self.package_constants.clone()
            };
            let mut params = HashMap::new();
            for param in &function.params {
                params.insert(
                    param.clone(),
                    ResourceExpr::Parameter {
                        name: param.clone(),
                    },
                );
                values.insert(param.clone(), SemanticValue::parameter(param));
            }
            for (param, arg) in function.params.iter().zip(args) {
                params.insert(param.clone(), self.go_filesystem_resource(arg));
                values.insert(
                    param.clone(),
                    // Function-typed parameter dispatch belongs to the repository composer.
                    self.go_semantic_value(arg)
                        .filter(|value| !crate::contains_callable(value))
                        .unwrap_or_else(|| SemanticValue::parameter(param)),
                );
            }
            if let Some(name) = &function.receiver
                && let Some(receiver) = receiver
            {
                values.insert(name.clone(), receiver);
            }
            let saved_params = std::mem::replace(&mut self.params, params);
            let saved_values = std::mem::replace(&mut self.values, values);
            let saved_types = self.local_types.clone();
            let saved_resources = self.resource_values.clone();
            if !function.is_closure {
                self.local_types = self.package_types.clone();
                self.resource_values.clear();
            }
            self.local_types.extend(function.types.clone());
            let saved_locals = std::mem::replace(&mut self.local_vars, function.locals.clone());
            let saved_function = std::mem::replace(&mut self.fact_function, name.to_string());
            self.entered_callables.insert(name.to_string());
            self.following.insert(name.to_string());
            let previous_call = if let GoWalkOutput::Plan { builder, .. } = &mut self.out {
                Some(
                    builder.enter_condition_call(
                        &self
                            .condition_source
                            .call_site(&(builder.source_span(&[node]), &origin)),
                    ),
                )
            } else {
                None
            };
            if function.is_closure {
                self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: function.body.pos.0 as u32,
                        end: function.body.pos.1 as u32,
                    },
                    effinterp_proto::ConditionKind::Dispatch,
                    0,
                    2,
                    true,
                    false,
                ));
            }
            self.control_enter(&function.body);
            self.walk_go_block(&function.body);
            self.control_leave();
            if function.is_closure {
                self.conditions.pop();
            }
            if let (Some(previous), GoWalkOutput::Plan { builder, .. }) =
                (previous_call, &mut self.out)
            {
                builder.leave_condition_call(previous);
            }
            self.following.remove(name);
            self.fact_function = saved_function;
            self.local_vars = saved_locals;
            self.local_types = saved_types;
            self.resource_values = saved_resources;
            self.values = saved_values;
            self.params = saved_params;
            return;
        }
        let Some(summary) = self.summaries.get(name) else {
            // A bare-name call to something not defined locally: unknown.
            return;
        };
        if matches!(&self.out, GoWalkOutput::Plan { .. }) {
            self.entered_callables.insert(name.to_string());
        }
        let arg_exprs: Vec<ResourceExpr> = args
            .iter()
            .map(|a| self.go_filesystem_resource(a))
            .collect();
        let bindings = bind_positional(&summary.params, &arg_exprs);
        let effects = summary.effects.clone();
        let requirements = match &mut self.out {
            GoWalkOutput::Capture(cap) => Some(cap.control.requirements(&summary.control_flow)),
            GoWalkOutput::Plan { .. } => None,
        };
        let transfers = summary.transfers.clone();
        let mut boundaries = summary.boundaries.clone();
        // A standard sequence collector supplies its own effect-free yield
        // callback. Retract only this function's first parameter invocation.
        if sequence && let Some(parameter) = summary.params.first() {
            boundaries.retain(|boundary| {
                !boundary
                    .callee
                    .as_ref()
                    .is_some_and(|callee| callee.module == name && callee.symbol == *parameter)
            });
        }
        let coverage: Vec<_> = summary
            .coverage
            .iter()
            .filter(|(domain, _)| {
                !sequence
                    || boundaries
                        .iter()
                        .any(|boundary| boundary.domains.contains(domain))
            })
            .cloned()
            .collect();
        let mut slots = Vec::with_capacity(effects.len());
        for effect in &effects {
            let mut specialized = effect.clone();
            specialized.resource = substitute_resource_expr(&effect.resource, &bindings);
            specialized.provenance = vec![node];
            slots.push(self.emit_go_prebuilt_effect(specialized));
        }
        for binding in &transfers {
            let (Some(source), Some(destination)) = (
                slots.get(binding.source as usize).copied().flatten(),
                slots.get(binding.destination as usize).copied().flatten(),
            ) else {
                continue;
            };
            self.record_transfer(Some(source), Some(destination));
        }
        if let Some(requirements) = requirements {
            self.control_applications
                .push(SiteFacts::call(&requirements, |fact| match fact {
                    ControlFact::Effect(slot) => slots
                        .get(slot as usize)
                        .copied()
                        .flatten()
                        .map(ControlFact::Effect),
                    ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
                }));
        }
        for b in boundaries {
            let mut b = b;
            b.provenance = vec![node];
            self.out_boundary(b);
        }
        for (d, l) in coverage {
            self.out_coverage(d, l);
        }
    }

    /// Whether a call names the standard library, whose behaviour this engine
    /// knows: it runs the callbacks it is handed, and nothing downstream will
    /// enter it to find out.
    fn stdlib_target(&self, path: &str, method: &str) -> bool {
        crate::external::classify_go_call(path, method).is_some()
    }
}
