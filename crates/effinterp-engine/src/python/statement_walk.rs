//! Python statement dispatch and condition tracking.

use effinterp_proto::ResourceExpr;
use rustpython_parser::ast;
use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{Expr, Stmt};

use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::summary::substitute_resource_expr;

use super::branch_join::BranchGuard;
use super::import_bindings::is_main_guard_test;
use super::name_bindings::rebound_pattern_names;
use super::returns::ReturnSite;
use super::summary_application::call_arguments;
use super::{PythonWalker, control, dataflow_capture, resolve};

impl PythonWalker<'_, '_> {
    /// Carry surviving branch conditions across later statements, then restore the caller's condition depth.
    pub(super) fn walk_body(&mut self, body: &[Stmt]) {
        let depth = self.builder.condition_depth();
        for stmt in body {
            if self.node_budget_hit {
                break;
            }
            self.walk_stmt(stmt);
            if let Stmt::If(branch) = stmt {
                let stops = |body: &[Stmt]| {
                    matches!(
                        body.last(),
                        Some(Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_))
                    )
                };
                let yes = stops(&branch.body);
                let no = stops(&branch.orelse);
                if yes != no {
                    let arm = u32::from(yes);
                    self.builder
                        .push_condition(self.builder.source_condition_path(
                            effinterp_proto::Condition::from_source_with_digest(
                                self.source,
                                self.condition_source.digest().to_string(),
                                effinterp_proto::ByteSpan {
                                    start: branch.range.start().into(),
                                    end: branch.range.end().into(),
                                },
                                effinterp_proto::ConditionKind::Branch,
                                arm,
                                2,
                                true,
                                true,
                            ),
                        ));
                }
            }
        }
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    fn walk_stmt(&mut self, stmt: &Stmt) {
        if !self.charge(stmt.range()) {
            return;
        }
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        self.walk_depth += 1;
        self.each_given(|walker| walker.end_rebound_environment(stmt));
        self.end_default_bindings(stmt);
        self.walk_stmt_inner(stmt);
        self.walk_depth -= 1;
    }

    fn walk_stmt_inner(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(import) => self.walk_python_import(import),
            Stmt::ImportFrom(from) => self.walk_python_from_import(from),
            Stmt::Assign(assign) => {
                // Any assignment to a bare name shadows a tracked import.
                for target in &assign.targets {
                    if let Expr::Name(n) = target {
                        self.imports.shadow(n.id.as_str());
                        self.widened_vars.remove(n.id.as_str());
                    }
                    if let Expr::Subscript(subscript) = target
                        && let Expr::Name(name) = subscript.value.as_ref()
                    {
                        self.invalidate_collection(name.id.as_str());
                    }
                    self.env_subscript_write(target, false);
                }
                // Track every bare name in `q = target = value` so a resource
                // returned by a helper (or a literal path) flows to later uses.
                // Other target shapes drop stale tracking for their bound names,
                // then restore exact static unpack bindings.
                let names: Vec<_> = assign
                    .targets
                    .iter()
                    .filter_map(|target| match target {
                        Expr::Name(name) => Some(name.id.to_string()),
                        _ => None,
                    })
                    .collect();
                for target in &assign.targets {
                    self.ipython_invalidate_getter_target(target);
                }
                if names.iter().any(|name| name == "get_ipython")
                    && let Some(state) = self.ipython.as_mut()
                {
                    state.get_ipython_owned = false;
                }
                if !self.bind_assigned_names(&names, &assign.value) {
                    return;
                }
                for target in &assign.targets {
                    self.walk_assignment_target(target);
                }
                if names.len() != assign.targets.len() {
                    let unpack = self.static_unpack(&assign.targets, &assign.value);
                    for target in &assign.targets {
                        if !matches!(target, Expr::Name(_) | Expr::Attribute(_)) {
                            self.invalidate_rebound_target(target);
                        }
                    }
                    if let Some(bindings) = unpack {
                        self.track_unpack(bindings);
                    }
                }
                // Track constructed receivers in both execution and capture;
                // capture additionally consumes the pending result binding.
                self.track_assign(assign);
                self.flow_assign(assign.targets.as_slice(), &assign.value);
                self.track_memory_tar_attributes(&assign.targets, &assign.value);
                self.ipython_track_assignment(&names, &assign.value);
                self.pending_binds = None;
                self.pending_deferred_container = None;
            }
            // `x: T = f()` is executed like `x = f()` — the annotation is not
            // a skip. Console-script mains often bind a constructor-chained
            // call this way (`code: int = App().run()`).
            Stmt::AnnAssign(assign) => {
                self.ipython_invalidate_getter_target(&assign.target);
                if let Expr::Name(n) = assign.target.as_ref() {
                    self.imports.shadow(n.id.as_str());
                    self.widened_vars.remove(n.id.as_str());
                }
                self.env_subscript_write(&assign.target, false);
                let Some(value) = &assign.value else {
                    return;
                };
                if let Expr::Name(target) = assign.target.as_ref()
                    && !self.bind_assigned_names(&[target.id.to_string()], value)
                {
                    return;
                }
                self.walk_assignment_target(&assign.target);
                self.track_named_value(assign.target.as_ref(), value);
                self.flow_assign(std::slice::from_ref(assign.target.as_ref()), value);
                self.track_memory_tar_attributes(
                    std::slice::from_ref(assign.target.as_ref()),
                    value,
                );
                if let Expr::Name(target) = assign.target.as_ref() {
                    self.ipython_track_assignment(&[target.id.to_string()], value);
                }
                self.pending_binds = None;
                self.pending_deferred_container = None;
            }
            Stmt::AugAssign(assign) => {
                self.ipython_invalidate_getter_target(&assign.target);
                self.walk_assignment_target(&assign.target);
                let before = self.capture.as_ref().map(|capture| capture.effects.len());
                let added = self.flow_expr(&assign.value);
                self.track_instance_attr_assignments(std::slice::from_ref(assign.target.as_ref()));
                let Expr::Name(target) = assign.target.as_ref() else {
                    return;
                };
                let name = target.id.to_string();
                self.clear_bound_receiver(&name);
                self.imports.shadow(&name);
                self.widened_vars.remove(&name);
                let part = (assign.op == ast::Operator::Add
                    && !self.unbounded_string_vars.contains(&name)
                    && !self.concatenation_uses_unbounded_binding(&assign.value))
                .then(|| {
                    resolve::concatenated_part_resource(
                        &assign.value,
                        &self.imports,
                        (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
                    )
                })
                .flatten()
                .map(|part| substitute_resource_expr(&part, &self.var_scope));
                match (self.var_scope.get(&name).cloned(), part) {
                    (Some(previous), Some(part)) => {
                        self.var_scope.insert(
                            name.clone(),
                            ResourceExpr::Join {
                                parts: vec![previous, part],
                            },
                        );
                        self.concatenated_vars.insert(name.clone());
                        self.unbounded_string_vars.remove(&name);
                    }
                    _ if self.path_vars.contains(&name) => {
                        self.invalidate_rebound_name(&name);
                    }
                    _ => {
                        self.var_scope.remove(&name);
                        self.path_vars.remove(&name);
                        self.branch_mixed_path_vars.remove(&name);
                        self.concatenated_vars.remove(&name);
                        self.unbounded_string_vars.insert(name.clone());
                    }
                }
                self.collections.remove(&name);
                self.sessions.remove(&name);
                self.connected_sockets.remove(&name);
                self.modeled_values.remove(&name);
                // `s += key` keeps what `s` held and adds what the value
                // carries; any other operator computes from both.
                let held = self.flow_vars.remove(&name);
                if assign.op == ast::Operator::Add {
                    match before {
                        Some(before) => {
                            let mut effects = self.carried_effects(&assign.value, before);
                            let mut origins = self.returned_params(&assign.value);
                            if let Some(capture) = self.capture.as_ref() {
                                effects.extend(capture.print_vars.get(&name).into_iter().flatten());
                                origins.extend(
                                    capture.params.get(&name).into_iter().flatten().cloned(),
                                );
                            }
                            self.capture_assign(&name, effects, origins);
                        }
                        None => {
                            let producers: Vec<_> = held.into_iter().chain(added).collect();
                            if let Some(joined) = self.joined_value(assign.range, &producers) {
                                self.flow_vars.insert(name.clone(), joined);
                            }
                        }
                    }
                }
                self.pending_binds = None;
                self.pending_deferred_container = None;
                if let Expr::Name(target) = assign.target.as_ref()
                    && let Some(state) = self.ipython.as_mut()
                {
                    state.bindings.remove(target.id.as_str());
                }
            }
            Stmt::Expr(expr) => {
                if !self.ipython_sentinel(expr) {
                    self.discarded_call = match expr.value.as_ref() {
                        Expr::Call(call) => Some(call.range),
                        _ => None,
                    };
                    let before = self.capture.as_ref().map(|capture| capture.effects.len());
                    self.flow_expr(&expr.value);
                    self.discarded_call = None;
                    if let Expr::Call(call) = expr.value.as_ref() {
                        self.each_given(|walker| walker.call_stores_environment(call));
                    }
                    // What a same-file call statement in a summarized body
                    // leaves in this body's bindings, now that its
                    // arguments are walked.
                    if let (Some(before), Expr::Call(call)) = (before, expr.value.as_ref())
                        && let Some((callee, writes)) = self.take_pending_writes(call)
                    {
                        self.capture_writes(&callee, call, writes, before);
                    }
                    // In a summarized body `box.append(key)` adds what its
                    // arguments carry to what `box` holds.
                    if let (Some(before), Expr::Call(call)) = (before, expr.value.as_ref())
                        && !self.is_local_callable(&call.func)
                        && let Some(name) = dataflow_capture::written_container(call)
                    {
                        self.capture_accumulate(name, &call_arguments(call), before);
                    }
                }
            }
            // A function definition does not execute its body; the body's
            // effects only count if execution reaches a call to it (see
            // `follow_def`). Defining a function shadows any tracked import
            // of the same name.
            Stmt::FunctionDef(f) => {
                for decorator in &f.decorator_list {
                    self.apply_decorator(decorator);
                }
                self.bind_defaults(&f.args);
                self.imports.shadow(f.name.as_str());
                self.invalidate_rebound_name(f.name.as_str());
                self.receiver_rebindings.remove(f.name.as_str());
            }
            Stmt::AsyncFunctionDef(f) => {
                for decorator in &f.decorator_list {
                    self.apply_decorator(decorator);
                }
                self.bind_defaults(&f.args);
                self.imports.shadow(f.name.as_str());
                self.invalidate_rebound_name(f.name.as_str());
                self.receiver_rebindings.remove(f.name.as_str());
            }
            // A class body executes at definition time; nested method
            // definitions within it are themselves no-ops.
            Stmt::ClassDef(c) => {
                for decorator in &c.decorator_list {
                    self.apply_decorator(decorator);
                }
                self.imports.shadow(c.name.as_str());
                // Class-body path bindings are local to the class namespace.
                let outer_var_scope = self.var_scope.clone();
                let outer_modeled_values = self.modeled_values.clone();
                let outer_path_vars = self.path_vars.clone();
                let outer_branch_mixed_path_vars = self.branch_mixed_path_vars.clone();
                let outer_widened_vars = self.widened_vars.clone();
                let outer_concatenated_vars = self.concatenated_vars.clone();
                let outer_unbounded_string_vars = self.unbounded_string_vars.clone();
                let outer_instance_vars = self.instance_vars.clone();
                let outer_bound_vars = self.bound_vars.clone();
                let outer_receiver_rebindings = self.receiver_rebindings.clone();
                self.class_namespace_entry(&c.body);
                self.walk_body(&c.body);
                self.class_namespace_exit();
                self.var_scope = outer_var_scope;
                self.modeled_values = outer_modeled_values;
                self.path_vars = outer_path_vars;
                self.branch_mixed_path_vars = outer_branch_mixed_path_vars;
                self.widened_vars = outer_widened_vars;
                self.concatenated_vars = outer_concatenated_vars;
                self.unbounded_string_vars = outer_unbounded_string_vars;
                self.instance_vars = outer_instance_vars;
                self.bound_vars = outer_bound_vars;
                self.receiver_rebindings = outer_receiver_rebindings;
                // Class-local bindings are restored above, but class execution can
                // rebind shared names directly or through an unknown callback.
                self.invalidate_shared_vars();
                self.invalidate_rebound_name(c.name.as_str());
                self.receiver_rebindings.remove(c.name.as_str());
            }
            // A launched program runs as `__main__`, so its module-level
            // entrypoint guard selects the body, as its control flow records.
            // An imported module keeps the guard as an ordinary branch.
            Stmt::If(s)
                if self.capture.is_none()
                    && self.current_function.is_none()
                    && is_main_guard_test(&s.test)
                    && !self.builder.current_execution_is_dependency() =>
            {
                self.walk_body(&s.body);
            }
            // A constant test selects one arm; the other never runs.
            Stmt::If(s) if control::truthy(&s.test).is_some() => {
                if control::truthy(&s.test) == Some(true) {
                    self.walk_body(&s.body);
                } else {
                    self.walk_body(&s.orelse);
                }
            }
            Stmt::If(s) => {
                self.walk_expr(&s.test);
                self.walk_branches(
                    &[
                        (s.body.as_slice(), None, None),
                        (s.orelse.as_slice(), None, None),
                    ],
                    Some(BranchGuard::selection(
                        s.range,
                        effinterp_proto::ConditionKind::Branch,
                        true,
                    )),
                );
            }
            Stmt::For(s) => self.walk_for(&s.target, &s.iter, &s.body, &s.orelse),
            Stmt::AsyncFor(s) => self.walk_for(&s.target, &s.iter, &s.body, &s.orelse),
            Stmt::While(s) => {
                // A single body walk represents every iteration, including back-edges.
                self.invalidate_loop_bindings(&s.body);
                self.walk_expr(&s.test);
                self.walk_branches(
                    &[
                        (s.body.as_slice(), None, None),
                        (s.orelse.as_slice(), None, None),
                    ],
                    Some(BranchGuard::selection(
                        s.range,
                        effinterp_proto::ConditionKind::Loop,
                        false,
                    )),
                );
            }
            Stmt::Match(s) => {
                self.walk_expr(&s.subject);
                for case in &s.cases {
                    for name in rebound_pattern_names(&case.pattern) {
                        self.invalidate_rebound_name(&name);
                    }
                }
                let mut branches: Vec<(&[Stmt], Option<&str>, Option<&Expr>)> = s
                    .cases
                    .iter()
                    .map(|case| (case.body.as_slice(), None, case.guard.as_deref()))
                    .collect();
                let exhaustive = s.cases.iter().any(|case| case.guard.is_none() && matches!(&case.pattern, ast::Pattern::MatchAs(pattern) if pattern.pattern.is_none()));
                if !exhaustive {
                    branches.push((&[], None, None));
                }
                self.walk_branches(
                    &branches,
                    Some(BranchGuard::selection(
                        s.range,
                        effinterp_proto::ConditionKind::Branch,
                        false,
                    )),
                );
            }
            Stmt::With(s) => {
                self.walk_with(&s.items, &s.body);
            }
            Stmt::AsyncWith(s) => {
                self.walk_with(&s.items, &s.body);
            }
            Stmt::Try(s) => {
                let mut branches: Vec<(&[Stmt], Option<&str>, Option<&Expr>)> =
                    vec![(s.body.as_slice(), None, None)];
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    branches.push((
                        h.body.as_slice(),
                        h.name.as_ref().map(|name| name.as_str()),
                        None,
                    ));
                }
                self.walk_branches(&branches, Some(BranchGuard::exception_handlers(s.range)));
                self.walk_body(&s.orelse);
                self.walk_body(&s.finalbody);
            }
            Stmt::TryStar(s) => {
                let mut branches: Vec<(&[Stmt], Option<&str>, Option<&Expr>)> =
                    vec![(s.body.as_slice(), None, None)];
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    branches.push((
                        h.body.as_slice(),
                        h.name.as_ref().map(|name| name.as_str()),
                        None,
                    ));
                }
                self.walk_branches(&branches, Some(BranchGuard::exception_handlers(s.range)));
                self.walk_body(&s.orelse);
                self.walk_body(&s.finalbody);
            }
            Stmt::Delete(s) => {
                for target in &s.targets {
                    self.ipython_invalidate_getter_target(target);
                    self.walk_assignment_target(target);
                    self.env_subscript_write(target, true);
                    self.track_instance_attr_assignments(std::slice::from_ref(target));
                    self.invalidate_rebound_target(target);
                    if let Expr::Name(target) = target
                        && let Some(state) = self.ipython.as_mut()
                    {
                        state.bindings.remove(target.id.as_str());
                    }
                }
            }
            Stmt::Raise(s) => {
                if let Some(exc) = &s.exc {
                    self.walk_expr(exc);
                }
                if let Some(cause) = &s.cause {
                    self.walk_expr(cause);
                }
            }
            Stmt::Return(s) => {
                if let Some(value) = &s.value {
                    let mut effects = self.capture_value(value);
                    effects.sort_unstable();
                    effects.dedup();
                    let params = self.returned_params(value);
                    if let Some(capture) = self.capture.as_mut()
                        && let Some(guards) = capture.live_returns.get(&s.range)
                        && !(effects.is_empty() && params.is_empty())
                    {
                        let site = ReturnSite {
                            guards: guards.clone(),
                            effects,
                            params,
                        };
                        if !capture.returned.contains(&site) {
                            capture.returned.push(site);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
