//! PHP local bindings and the writes that invalidate them.

use std::collections::HashMap;

use effinterp_proto::ResourceExpr;
use tree_sitter::Node;

use crate::lang::frontend::MAX_CALLBACK_VALUES;
use crate::summary::contains_unresolved;
use crate::value::unresolved_resource;

use super::super::file_context::resolve_php_class_name;
use super::super::syntax::{arg_nodes, callable_name, child_kind, param_names, text};
use super::PhpWalker;
use super::call_resolution::{PhpClosure, closure_uses};
use super::environment::{environment_effect, superglobal_resource};
use super::resource_recovery::text_concat;
use super::shell_output::PhpHeldCapture;

fn guarded_assignment(n: Node, src: &str) -> bool {
    let mut parent = n.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) {
            return false;
        }
        if matches!(
            node.kind(),
            "if_statement"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "foreach_statement"
                | "switch_statement"
                | "conditional_expression"
                | "try_statement"
                | "catch_clause"
                | "finally_clause"
                | "match_expression"
        ) || node.kind() == "binary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(text(operator, src), "&&" | "||" | "and" | "or" | "xor")
                })
        {
            return true;
        }
        parent = node.parent();
    }
    false
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// A guarded assignment can leave an earlier binding in place, including
    /// the class or closure a later call may enter.
    pub(super) fn bind_php_assignment(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        if let Some((name, resource)) = superglobal_resource(left, self.src)
            && name == "_ENV"
        {
            self.emit(environment_effect(resource, false), n);
        }
        if left.kind() != "variable_name" {
            return;
        }
        let Some(var) = child_kind(left, "name").map(|x| text(x, self.src).to_string()) else {
            return;
        };
        let guarded = guarded_assignment(n, self.src);
        let network_handle = (right.kind() == "function_call_expression")
            .then(|| callable_name(right, self.src))
            .flatten()
            .and_then(|name| match name.as_str() {
                "curl_init" | "fsockopen" | "pfsockopen" | "stream_socket_client" => {
                    Some(self.url_resource(arg_nodes(right).first().copied(), env))
                }
                "fopen" if self.is_url(arg_nodes(right).first().copied()) => {
                    Some(self.url_resource(arg_nodes(right).first().copied(), env))
                }
                _ => None,
            });
        let supported = matches!(
            right.kind(),
            "string"
                | "encapsed_string"
                | "binary_expression"
                | "name"
                | "variable_name"
                | "member_access_expression"
                | "class_constant_access_expression"
                | "scoped_property_access_expression"
        ) || right.kind() == "function_call_expression"
            && callable_name(right, self.src)
                .is_some_and(|name| matches!(name.as_str(), "getenv" | "dirname" | "sprintf"));
        let mut value = if supported {
            self.recover_php_argument(right, env)
        } else {
            unresolved_resource("filesystem")
        };
        if guarded
            && self
                .locals
                .get(&var)
                .or_else(|| env.get(&var))
                .is_some_and(|current| current != &value)
        {
            value = unresolved_resource("filesystem");
        }
        self.store_local(&var, value, guarded);
        if !guarded {
            self.vars.remove(&var);
            self.closures.remove(&var);
            match network_handle {
                Some(resource) => {
                    self.network_handles.insert(var.clone(), resource);
                }
                None => {
                    self.network_handles.remove(&var);
                }
            }
        }
        if matches!(right.kind(), "anonymous_function" | "arrow_function")
            && let Some(body) = right.child_by_field_name("body")
        {
            self.handled_closures.insert(right.id());
            let params = right
                .child_by_field_name("parameters")
                .map(|parameters| param_names(parameters, self.src))
                .unwrap_or_default();
            let closures = self.closures.entry(var).or_default();
            let duplicate = closures
                .iter()
                .any(|closure| closure.body.id() == body.id());
            let truncated = !duplicate && closures.len() >= MAX_CALLBACK_VALUES;
            if !duplicate && !truncated {
                closures.push(PhpClosure {
                    params,
                    body,
                    uses: closure_uses(right, self.src),
                });
            }
            if truncated {
                self.candidate_limit(n);
            }
            return;
        }
        if right.kind() != "object_creation_expression" {
            return;
        }
        let mut c = right.walk();
        let Some(cn) = right
            .named_children(&mut c)
            .find(|x| matches!(x.kind(), "name" | "qualified_name"))
        else {
            return;
        };
        let raw = text(cn, self.src);
        let fq = resolve_php_class_name(&self.ctx, raw);
        if self.local_class(&fq).is_some() || self.resolve_php_class_file(&fq).is_some() {
            let classes = self.vars.entry(var).or_default();
            let duplicate = classes.contains(&fq);
            let truncated = !duplicate && classes.len() >= MAX_CALLBACK_VALUES;
            if !duplicate && !truncated {
                classes.push(fq);
            }
            if truncated {
                self.candidate_limit(n);
            }
        }
    }

    pub(super) fn unset(&mut self, n: Node<'a>) {
        let mut cursor = n.walk();
        for target in n.named_children(&mut cursor) {
            if let Some((name, resource)) = superglobal_resource(target, self.src)
                && name == "_ENV"
            {
                self.emit(environment_effect(resource, true), n);
            }
        }
    }

    pub(super) fn augmented_assign(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        let (Some(left), Some(right), Some(operator)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
            n.child_by_field_name("operator"),
        ) else {
            return;
        };
        if left.kind() != "variable_name" {
            return;
        }
        let Some(name) = child_kind(left, "name").map(|name| text(name, self.src).to_string())
        else {
            return;
        };
        if text(operator, self.src) != ".=" {
            self.store_local(&name, unresolved_resource("filesystem"), false);
            return;
        }
        let old = self
            .locals
            .get(&name)
            .cloned()
            .or_else(|| env.get(&name).cloned())
            .unwrap_or_else(|| unresolved_resource("filesystem"));
        let guarded = guarded_assignment(n, self.src);
        let mut value = text_concat(vec![old, self.recover_php_argument(right, env)]);
        if guarded
            && self
                .locals
                .get(&name)
                .or_else(|| env.get(&name))
                .is_some_and(|current| current != &value)
        {
            value = unresolved_resource("filesystem");
        }
        self.store_local(&name, value, guarded);
    }

    pub(super) fn poison_declared_locals(&mut self, node: Node<'a>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "variable_name"
                && let Some(name) = child_kind(node, "name")
            {
                self.store_local(
                    text(name, self.src),
                    unresolved_resource("filesystem"),
                    false,
                );
                continue;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }

    pub(super) fn store_local(&mut self, name: &str, value: ResourceExpr, guarded: bool) {
        let conflict = guarded
            && self
                .locals
                .get(name)
                .is_some_and(|current| current != &value);
        if conflict || contains_unresolved(&value) {
            self.locals
                .insert(name.to_string(), unresolved_resource("filesystem"));
            self.poisoned.insert(name.to_string());
        } else {
            self.locals.insert(name.to_string(), value);
            self.poisoned.remove(name);
        }
    }

    /// Snapshot the top-level scope's value facts as the outermost call
    /// begins; says whether this call is that one.
    pub(super) fn enter_facts(
        &mut self,
        captures: &HashMap<String, Vec<PhpHeldCapture>>,
        truths: &HashMap<String, bool>,
    ) -> bool {
        let outermost = self.global_facts.is_none();
        if outermost {
            self.global_facts = Some((captures.clone(), truths.clone()));
        }
        outermost
    }

    /// Return to the caller's value facts after a call. A callee that wrote
    /// through `global` or `$GLOBALS` may have changed them.
    pub(super) fn restore_facts(
        &mut self,
        captures: HashMap<String, Vec<PhpHeldCapture>>,
        truths: HashMap<String, bool>,
        globals_written: bool,
    ) {
        let written = self.globals_written;
        self.capture_locals = captures;
        self.truth_locals = truths;
        self.globals_written = globals_written || written;
        if written {
            self.forget_facts(None);
        }
    }

    /// Value facts hold only while this scope's straight-line code is their
    /// only writer. A construct that may write locals this walk does not
    /// model forgets the facts about them.
    pub(super) fn forget_written(&mut self, n: Node<'a>) {
        let variables = |node: Node| -> Vec<String> {
            let mut names = Vec::new();
            let mut stack = vec![node];
            while let Some(node) = stack.pop() {
                if node.kind() == "variable_name" {
                    names.push(text(node, self.src).to_string());
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            names
        };
        match n.kind() {
            // Included code, `eval` and variable variables run in or name
            // this scope.
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression"
            | "dynamic_variable_name" => self.forget_facts(None),
            "variable_name" if text(n, self.src) == "$GLOBALS" => {
                self.globals_written = true;
                self.forget_facts(None);
            }
            // `global $x` binds the top-level `$x`: its facts as the calls
            // began, unless code since then wrote globals.
            "global_declaration" if self.global_facts.is_some() => {
                let stale = self.globals_written;
                self.globals_written = true;
                let names = variables(n);
                self.forget_facts(Some(&names));
                if let Some((captures, truths)) = &self.global_facts {
                    for name in names {
                        if let Some(held) = captures.get(&name) {
                            let held = held.iter().map(|&(span, exact)| (span, exact && !stale));
                            self.capture_locals.insert(name.clone(), held.collect());
                        }
                        match truths.get(&name) {
                            Some(truth) if !stale => self.truth_locals.insert(name, *truth),
                            _ => self.truth_locals.remove(&name),
                        };
                    }
                }
            }
            // An alias lets a later write through either name change both.
            "reference_assignment_expression" => self.forget_facts(Some(&variables(n))),
            "function_call_expression"
                if callable_name(n, self.src).is_some_and(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "extract" | "parse_str" | "mb_parse_str" | "compact" | "eval"
                    )
                }) =>
            {
                self.forget_facts(None)
            }
            _ => {}
        }
        // Writes a literal truth value does not survive: compound and
        // element assignments, increments, destructuring, loop and catch
        // variables, statics, and variables a call may take by reference.
        let written = match n.kind() {
            "augmented_assignment_expression" | "update_expression" | "list_literal" => {
                variables(n)
            }
            "assignment_expression" => n
                .child_by_field_name("left")
                .filter(|left| left.kind() != "variable_name")
                .map(variables)
                .unwrap_or_default(),
            "foreach_statement" | "catch_clause" | "static_variable_declaration" => {
                let body = n.child_by_field_name("body").map(|body| body.id());
                let mut cursor = n.walk();
                n.named_children(&mut cursor)
                    .filter(|child| Some(child.id()) != body)
                    .flat_map(variables)
                    .collect()
            }
            "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression"
                if !callable_name(n, self.src).is_some_and(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "print_r" | "printf" | "sprintf"
                    )
                }) =>
            {
                arg_nodes(n)
                    .into_iter()
                    .filter(|arg| arg.kind() == "variable_name")
                    .map(|arg| text(arg, self.src).to_string())
                    .collect()
            }
            _ => Vec::new(),
        };
        for name in written {
            self.truth_locals.remove(&name);
        }
    }

    /// Forget the facts about `names`, or about every local: a truth value
    /// becomes unknown, and output a local held may or may not still be
    /// there, so printing it raises a boundary.
    pub(super) fn forget_facts(&mut self, names: Option<&[String]>) {
        match names {
            None => {
                self.truth_locals.clear();
                for held in self.capture_locals.values_mut() {
                    held.iter_mut().for_each(|capture| capture.1 = false);
                }
            }
            Some(names) => {
                for name in names {
                    self.truth_locals.remove(name);
                    if let Some(held) = self.capture_locals.get_mut(name) {
                        held.iter_mut().for_each(|capture| capture.1 = false);
                    }
                }
            }
        }
    }
}
