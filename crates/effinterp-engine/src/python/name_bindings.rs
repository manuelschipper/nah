//! Python name bindings.
//! Rebinding removes stale evidence about a name's resource and receiver.

use std::collections::HashSet;

use effinterp_proto::{BoundaryClass, BoundaryReason, ResourceExpr};
use rustpython_parser::ast;
use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{Expr, Stmt};

use crate::summary::{is_resolvable, substitute_resource_expr};

use super::ast_expressions::{callee_written, child_exprs};
use super::resolve::str_literal;
use super::{PythonWalker, resolve, summary};

// Collect possible writes without evaluating them. Loop entry drops these bindings
// because a later iteration can observe any write in the body. Shared declarations
// also prevent module constants from surviving writes through called helpers.
pub(super) fn rebound_body_names(body: &[Stmt], shared_only: bool) -> HashSet<String> {
    possibly_written_names(body, shared_only, true, true)
}

/// The names `body` binds or declares shared: not one it only stores into
/// (`box[k] = v` changes the container an outer name holds).
pub(super) fn bound_body_names(body: &[Stmt]) -> HashSet<String> {
    possibly_written_names(body, false, false, true)
}

/// The names `body` binds in its own namespace: those of
/// [`bound_body_names`] it does not declare `global` or `nonlocal`.
pub(super) fn namespace_names(body: &[Stmt]) -> HashSet<String> {
    let mut names = bound_body_names(body);
    let (globals, nonlocals) = summary::declared_shared(body);
    names.retain(|name| !globals.contains(name) && !nonlocals.contains(name));
    names
}

pub(super) fn possibly_written_names(
    body: &[Stmt],
    shared_only: bool,
    containers: bool,
    definitions: bool,
) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut statements: Vec<_> = body.iter().collect();
    let mut expressions = Vec::new();
    while let Some(stmt) = statements.pop() {
        match stmt {
            Stmt::Assign(s) => {
                expressions.extend(s.targets.iter());
                expressions.push(&s.value);
            }
            Stmt::AnnAssign(s) => {
                if let Some(value) = &s.value {
                    expressions.extend([s.target.as_ref(), value.as_ref()]);
                }
            }
            Stmt::AugAssign(s) => expressions.extend([s.target.as_ref(), s.value.as_ref()]),
            Stmt::Delete(s) => expressions.extend(s.targets.iter()),
            Stmt::Expr(s) => expressions.push(&s.value),
            Stmt::If(s) => {
                expressions.push(&s.test);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::While(s) => {
                expressions.push(&s.test);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::For(s) => {
                expressions.extend([s.target.as_ref(), s.iter.as_ref()]);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::AsyncFor(s) => {
                expressions.extend([s.target.as_ref(), s.iter.as_ref()]);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::With(s) => {
                for item in &s.items {
                    expressions.extend(item.optional_vars.as_deref());
                    expressions.push(&item.context_expr);
                }
                statements.extend(&s.body);
            }
            Stmt::AsyncWith(s) => {
                for item in &s.items {
                    expressions.extend(item.optional_vars.as_deref());
                    expressions.push(&item.context_expr);
                }
                statements.extend(&s.body);
            }
            Stmt::Try(s) => {
                statements.extend(s.body.iter().chain(&s.orelse).chain(&s.finalbody));
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    if !shared_only {
                        names.extend(h.name.iter().map(ToString::to_string));
                    }
                    statements.extend(&h.body);
                }
            }
            Stmt::TryStar(s) => {
                statements.extend(s.body.iter().chain(&s.orelse).chain(&s.finalbody));
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    if !shared_only {
                        names.extend(h.name.iter().map(ToString::to_string));
                    }
                    statements.extend(&h.body);
                }
            }
            Stmt::Match(s) => {
                expressions.push(&s.subject);
                for case in &s.cases {
                    if !shared_only {
                        names.extend(rebound_pattern_names(&case.pattern));
                    }
                    expressions.extend(case.guard.as_deref());
                    statements.extend(&case.body);
                }
            }
            Stmt::FunctionDef(s) => {
                if shared_only {
                    statements.extend(&s.body);
                } else if definitions {
                    names.insert(s.name.to_string());
                }
            }
            Stmt::AsyncFunctionDef(s) => {
                if shared_only {
                    statements.extend(&s.body);
                } else if definitions {
                    names.insert(s.name.to_string());
                }
            }
            Stmt::ClassDef(s) => {
                if shared_only {
                    statements.extend(&s.body);
                } else if definitions {
                    names.insert(s.name.to_string());
                }
            }
            Stmt::Import(s) if !shared_only => names.extend(s.names.iter().map(|a| {
                a.asname
                    .as_deref()
                    .unwrap_or(a.name.split('.').next().unwrap())
                    .to_string()
            })),
            Stmt::ImportFrom(s) if !shared_only => names.extend(
                s.names
                    .iter()
                    .map(|a| a.asname.as_deref().unwrap_or(a.name.as_str()).to_string()),
            ),
            Stmt::Global(s) => names.extend(s.names.iter().map(ToString::to_string)),
            Stmt::Nonlocal(s) => names.extend(s.names.iter().map(ToString::to_string)),
            _ => {}
        }
    }
    if !shared_only {
        while let Some(expr) = expressions.pop() {
            match expr {
                Expr::Name(name)
                    if matches!(name.ctx, ast::ExprContext::Store | ast::ExprContext::Del) =>
                {
                    names.insert(name.id.to_string());
                }
                Expr::NamedExpr(named) => names.extend(rebound_target_names(&named.target)),
                Expr::Subscript(subscript)
                    if containers
                        && matches!(
                            subscript.ctx,
                            ast::ExprContext::Store | ast::ExprContext::Del
                        ) =>
                {
                    names.extend(rebound_target_names(&subscript.value));
                }
                _ => {}
            }
            expressions.extend(child_exprs(expr));
        }
    }
    names
}

pub(super) fn rebound_target_names(target: &Expr) -> Vec<String> {
    match target {
        Expr::Name(name) => vec![name.id.to_string()],
        Expr::List(list) => list.elts.iter().flat_map(rebound_target_names).collect(),
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(rebound_target_names).collect(),
        Expr::Starred(starred) => rebound_target_names(&starred.value),
        _ => Vec::new(),
    }
}

pub(super) fn rebound_pattern_names(pattern: &ast::Pattern) -> Vec<String> {
    match pattern {
        ast::Pattern::MatchSequence(sequence) => sequence
            .patterns
            .iter()
            .flat_map(rebound_pattern_names)
            .collect(),
        ast::Pattern::MatchMapping(mapping) => mapping
            .patterns
            .iter()
            .flat_map(rebound_pattern_names)
            .chain(mapping.rest.iter().map(ToString::to_string))
            .collect(),
        ast::Pattern::MatchClass(class) => class
            .patterns
            .iter()
            .chain(&class.kwd_patterns)
            .flat_map(rebound_pattern_names)
            .collect(),
        ast::Pattern::MatchStar(star) => star.name.iter().map(ToString::to_string).collect(),
        ast::Pattern::MatchAs(as_pattern) => as_pattern
            .pattern
            .iter()
            .flat_map(|pattern| rebound_pattern_names(pattern))
            .chain(as_pattern.name.iter().map(ToString::to_string))
            .collect(),
        ast::Pattern::MatchOr(or) => or.patterns.iter().flat_map(rebound_pattern_names).collect(),
        ast::Pattern::MatchValue(_) | ast::Pattern::MatchSingleton(_) => Vec::new(),
    }
}

impl PythonWalker<'_, '_> {
    /// Retire stale import, resource and receiver evidence when a name may have been rebound.
    pub(super) fn invalidate_rebound_name(&mut self, name: &str) {
        if name == "get_ipython"
            && let Some(state) = self.ipython.as_mut()
        {
            state.get_ipython_owned = false;
        }
        self.imports.shadow(name);
        self.modeled_values.remove(name);
        self.connected_sockets.remove(name);
        self.clear_bound_receiver(name);
        self.var_scope.remove(name);
        self.collections.remove(name);
        if self.path_vars.contains(name) {
            self.widened_vars.insert(name.to_string());
        }
        self.concatenated_vars.remove(name);
        self.unbounded_string_vars.remove(name);
    }

    pub(super) fn invalidate_rebound_target(&mut self, target: &Expr) {
        self.invalidate_memory_tar_target(target);
        for name in rebound_target_names(target) {
            self.invalidate_rebound_name(&name);
        }
    }

    pub(super) fn walk_assignment_target(&mut self, target: &Expr) {
        let mut targets = vec![target];
        while let Some(target) = targets.pop() {
            match target {
                Expr::Attribute(attribute) => self.walk_expr(&attribute.value),
                Expr::Subscript(subscript) => {
                    self.walk_expr(&subscript.value);
                    self.walk_expr(&subscript.slice);
                }
                Expr::Tuple(tuple) => targets.extend(tuple.elts.iter().rev()),
                Expr::List(list) => targets.extend(list.elts.iter().rev()),
                Expr::Starred(starred) => targets.push(&starred.value),
                _ => {}
            }
            if self.imports.is_namespace_write(target) {
                self.imports.namespace_mutated = true;
                self.invalidate_namespace_values();
                self.emit_unresolved_call(
                    "namespace mutation",
                    BoundaryReason::DYNAMIC_DISPATCH,
                    BoundaryClass::Unresolved,
                    crate::external::ALL_DOMAINS,
                    target.range(),
                    None,
                );
            } else if let Expr::Attribute(_) = target
                && let Some(name) = self.imports.resolve_callee(target)
            {
                self.imports.shadow(&name);
            }
        }
    }

    pub(super) fn record_namespace_escape(&mut self, expr: &Expr) {
        if !self.imports.namespace_mutated && self.imports.is_namespace_value(expr) {
            self.imports.namespace_mutated = true;
            self.invalidate_namespace_values();
            self.emit_unresolved_call(
                "namespace escape",
                BoundaryReason::DYNAMIC_DISPATCH,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                expr.range(),
                None,
            );
        }
    }

    pub(super) fn invalidate_namespace_values(&mut self) {
        // Reflective namespace writes can replace any tracked binding. The
        // summary does not transfer their replacement values back to callers.
        let names: HashSet<_> = self
            .var_scope
            .keys()
            .chain(self.consts.keys())
            .chain(self.modeled_values.keys())
            .chain(self.instance_vars.keys())
            .cloned()
            .collect();
        for name in names {
            self.invalidate_rebound_name(&name);
        }
        self.consts.clear();
    }

    pub(super) fn invalidate_shared_vars(&mut self) {
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        // Calls can reach global/nonlocal writes whose values are not transferred
        // back through summaries or unresolved dispatch boundaries.
        for name in self.shared_vars.clone() {
            self.invalidate_rebound_name(&name);
        }
    }

    /// Record module-level `NAME = <path>` constants whose value resolves to a
    /// usable resource (a literal path, an `os.path.join`, an f-string). Later
    /// occurrences win. Used to resolve a constant referenced inside a helper's
    /// return or effect (e.g. `join(ROOT, t)`).
    pub(super) fn collect_consts(&mut self, body: &[Stmt]) {
        self.shared_vars = rebound_body_names(body, true);
        for stmt in body {
            let Stmt::Assign(assign) = stmt else { continue };
            let [Expr::Name(target)] = assign.targets.as_slice() else {
                continue;
            };
            if self.shared_vars.contains(target.id.as_str()) {
                continue;
            }
            let resolved = str_literal(&assign.value)
                .map(|value| ResourceExpr::Literal { value })
                .or_else(|| self.source_string_resource(&assign.value))
                .unwrap_or_else(|| self.fs_resource(&assign.value));
            let name = target.id.as_str().to_string();
            let unbounded_string =
                self.string_binding_is_unbounded(&assign.value, is_resolvable(&resolved));
            if unbounded_string {
                self.const_unbounded_strings.insert(name.clone());
                self.unbounded_string_vars.insert(name.clone());
            } else {
                self.const_unbounded_strings.remove(&name);
                self.unbounded_string_vars.remove(&name);
            }
            if is_resolvable(&resolved) && !unbounded_string {
                if self.lowered_concatenation(&assign.value).is_some() {
                    self.const_concatenations.insert(name.clone());
                } else {
                    self.const_concatenations.remove(&name);
                }
                self.consts.insert(name, resolved);
            } else {
                self.const_concatenations.remove(&name);
                self.consts.remove(&name);
            }
            if self.is_path_value(&assign.value) {
                self.path_vars.insert(target.id.to_string());
            } else {
                self.path_vars.remove(target.id.as_str());
            }
            self.branch_mixed_path_vars.remove(target.id.as_str());
        }
    }

    /// Bind each assigned name to the same evaluated resource. Chained
    /// assignment evaluates `value` once; an untrackable path RHS widens.
    pub(super) fn bind_assigned_names(&mut self, names: &[String], value: &Expr) -> bool {
        if names.is_empty() {
            return true;
        }
        self.prepare_call_summaries(value);
        self.retire_memory_tar_constructor(value);
        let path_value = self.is_path_value(value);
        let path_candidate = self.may_be_path_value(value);
        let branch_mixed_path = self.is_branch_mixed_path_value(value);
        let concatenated = self.lowered_concatenation(value).is_some();
        let was_paths: Vec<bool> = names
            .iter()
            .map(|name| self.path_vars.contains(name))
            .collect();
        let tracked = self.tracked_assignment_resource(value);
        if self.node_budget_hit {
            return false;
        }
        let unbounded_string = self.string_binding_is_unbounded(value, tracked.is_some());
        let session = self.net_receiver(value);
        // `t = s` names the same socket; any other value is not connected.
        let connection = match value {
            Expr::Name(source) => self.connected_sockets.get(source.id.as_str()).cloned(),
            _ => None,
        };
        let modeled = self.modeled_value(value);
        let container = self.static_container(value);
        for (name, was_path) in names.iter().zip(was_paths) {
            match &connection {
                Some(endpoint) => {
                    self.connected_sockets
                        .insert(name.clone(), endpoint.clone());
                }
                None => {
                    self.connected_sockets.remove(name);
                }
            }
            self.modeled_values.remove(name);
            if let Some(value) = &modeled {
                self.modeled_values.insert(name.clone(), value.clone());
            }
            match &tracked {
                Some(res) => {
                    self.var_scope.insert(name.clone(), res.clone());
                    if path_value {
                        self.path_vars.insert(name.clone());
                    } else {
                        self.path_vars.remove(name);
                    }
                    if path_value && branch_mixed_path {
                        self.branch_mixed_path_vars.insert(name.clone());
                    } else {
                        self.branch_mixed_path_vars.remove(name);
                    }
                    if concatenated {
                        self.concatenated_vars.insert(name.clone());
                    } else {
                        self.concatenated_vars.remove(name);
                    }
                }
                None => {
                    self.var_scope.remove(name);
                    self.concatenated_vars.remove(name);
                    if was_path || path_candidate {
                        self.path_vars.insert(name.clone());
                        self.widened_vars.insert(name.clone());
                        if path_candidate && branch_mixed_path {
                            self.branch_mixed_path_vars.insert(name.clone());
                        }
                    } else {
                        self.path_vars.remove(name);
                        self.branch_mixed_path_vars.remove(name);
                    }
                }
            }
            if unbounded_string {
                self.unbounded_string_vars.insert(name.clone());
            } else {
                self.unbounded_string_vars.remove(name);
            }
            match &session {
                Some(recv) => {
                    self.sessions.insert(name.clone(), recv.clone());
                }
                None => {
                    self.sessions.remove(name);
                }
            }
            match &container {
                Some(container) => {
                    self.collections.insert(name.clone(), container.clone());
                }
                None => {
                    self.collections.remove(name);
                }
            }
        }
        true
    }

    /// The resource a variable refers to after an assignment, or None to drop
    /// any stale tracking for it: the substituted return of a call into a
    /// summarized local function, otherwise the value resolved as a path.
    pub(super) fn tracked_assignment_resource(&mut self, value: &Expr) -> Option<ResourceExpr> {
        if let Some(resource) = self.modeled_path(value) {
            return Some(resource);
        }
        if let Some(value) = str_literal(value) {
            return Some(ResourceExpr::Literal { value });
        }
        if let Expr::Call(call) = value
            && callee_written(&call.func).as_deref() == Some("next")
            && let Some(iter) = call.args.first()
        {
            return self
                .static_sequence(iter)
                .or_else(|| self.static_iter_values(iter))?
                .into_iter()
                .next();
        }
        if let Some(call) = self.executed_local_call(value)
            && let Some(name) = self.local_callee(&call.func)
        {
            let bindings = self.call_bindings(&name, call);
            if let Some(returns) = self
                .summaries
                .get(&name)
                .and_then(|summary| summary.returns.as_ref())
            {
                let mut visited = 0;
                let substituted = crate::substitute_value_counted(
                    returns,
                    &bindings,
                    self.nest.limits.value_limits(),
                    &mut visited,
                );
                let range = value.range();
                let span = (u32::from(range.start()), u32::from(range.end()));
                if !self.charge_steps(visited, span) {
                    self.node_budget_hit = true;
                    return None;
                }
                return Some(substituted.lower_resource());
            }
        }
        if let Some(resource) = self.source_string_resource(value) {
            return Some(substitute_resource_expr(&resource, &self.var_scope));
        }
        if matches!(value, Expr::Call(call)
            if matches!(call.func.as_ref(), Expr::Attribute(method)
                if matches!(method.attr.as_str(), "with_name" | "with_suffix")))
        {
            let resolved = self.resolve_fs(value);
            return is_resolvable(&resolved).then_some(resolved);
        }
        let resolved =
            if self.is_path_value(value) && !self.path_expression_uses_widened_binding(value) {
                let resource = substitute_resource_expr(&self.fs_resource(value), &self.var_scope);
                let resource = if Self::path_expression_expands_user(value) {
                    resolve::expanduser_resource(resource)
                } else {
                    resource
                };
                resolve::normalize_pathlib_resource(resource)
            } else {
                self.resolve_fs(value)
            };
        is_resolvable(&resolved).then_some(resolved)
    }
}
