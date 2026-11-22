//! Function and callback resolution from exact names and bounded candidates.

use std::collections::HashMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ResourceExpr,
};
use tree_sitter::Node;

use crate::builder::KNOWN_DOMAINS;
use crate::summary::{bind_positional, contains_unresolved};

use super::super::CALL_DEPTH_LIMIT;
use super::super::file_context::{resolve_php_class_name, same_namespace};
use super::super::syntax::{
    arg_nodes, callable_name, child_kind, literal_string, param_names, text,
};
use super::{PhpCall, PhpWalker};

/// A named callable's parameter names and body in the current file's tree.
pub(super) struct PhpFunction<'a> {
    params: Vec<String>,
    body: Node<'a>,
}

#[derive(Clone)]
pub(super) struct PhpClosure<'a> {
    pub(super) params: Vec<String>,
    pub(super) body: Node<'a>,
    pub(super) uses: Vec<String>,
}

pub(super) fn collect_php_functions<'a>(
    root: Node<'a>,
    src: &str,
) -> HashMap<String, PhpFunction<'a>> {
    let mut out = HashMap::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if (n.kind() == "function_definition" || n.kind() == "method_declaration")
            && let (Some(name), Some(body)) =
                (child_kind(n, "name"), child_kind(n, "compound_statement"))
        {
            let params = child_kind(n, "formal_parameters")
                .map(|p| param_names(p, src))
                .unwrap_or_default();
            out.entry(text(name, src).to_string())
                .or_insert(PhpFunction { params, body });
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            // Do not descend into function bodies when collecting siblings;
            // nested functions are rare and handled as separate entries only
            // at the same scan (they are still reachable here via the stack).
            stack.push(ch);
        }
    }
    out
}

pub(super) fn bind_php_params(
    params: &[String],
    args: &[ResourceExpr],
) -> HashMap<String, ResourceExpr> {
    let mut env: HashMap<_, _> = params
        .iter()
        .map(|name| (name.clone(), ResourceExpr::Parameter { name: name.clone() }))
        .collect();
    env.extend(
        bind_positional(params, args)
            .into_iter()
            .filter(|(_, value)| !contains_unresolved(value)),
    );
    env
}

pub(super) fn closure_uses(node: Node, src: &str) -> Vec<String> {
    let Some(clause) = child_kind(node, "anonymous_function_use_clause") else {
        return Vec::new();
    };
    let mut cursor = clause.walk();
    clause
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "variable_name")
        .filter_map(|variable| child_kind(variable, "name"))
        .map(|name| text(name, src).to_string())
        .collect()
}

pub(super) fn declared_php_callable_names(root: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, owner)) = stack.pop() {
        let class_name = matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "trait_declaration"
        )
        .then(|| child_kind(node, "name").map(|name| text(name, source).to_string()))
        .flatten();
        if matches!(node.kind(), "function_definition" | "method_declaration")
            && let Some(name) = child_kind(node, "name")
        {
            let name = text(name, source);
            let name = if node.kind() == "method_declaration" {
                owner
                    .as_deref()
                    .map_or_else(|| name.to_string(), |owner| format!("{owner}.{name}"))
            } else {
                name.to_string()
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
        let owner = class_name.or(owner);
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push((child, owner.clone()));
        }
    }
    names
}

fn callable_array(n: Node, src: &str) -> Option<(String, String)> {
    if n.kind() != "array_creation_expression" {
        return None;
    }
    let mut cursor = n.walk();
    let values: Vec<Node> = n
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "array_element_initializer")
        .filter_map(|element| {
            let mut cursor = element.walk();
            element.named_children(&mut cursor).last()
        })
        .collect();
    let receiver = values.first().map(|value| {
        literal_string(*value, src).unwrap_or_else(|| text(*value, src).to_string())
    })?;
    let method = values
        .get(1)
        .and_then(|value| literal_string(*value, src))?;
    Some((receiver, method))
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// Resolve a PHP function call using the current file, builtin model, or exact callable facts.
    pub(super) fn resolve_php_function_call(
        &mut self,
        n: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> PhpCall {
        let Some(fname) = callable_name(n, self.src) else {
            if let Some(function) = n.child_by_field_name("function") {
                let args: Vec<ResourceExpr> = arg_nodes(n)
                    .iter()
                    .map(|argument| self.recover_php_argument(*argument, env))
                    .collect();
                if self.invoke_php_callable(function, &args, n, env) {
                    return PhpCall::Entered;
                }
            }
            // An unbound variable function or computed callee is dynamic.
            self.opaque(BoundaryReason::DYNAMIC_CALL, BoundaryClass::Unresolved, n);
            return PhpCall::Opaque;
        };
        let args: Vec<Node> = arg_nodes(n);

        // tree-sitter-php parses these language constructs as ordinary calls,
        // but they only inspect their arguments and can never invoke a closure.
        if matches!(fname.as_str(), "isset" | "empty") {
            return PhpCall::Modeled;
        }

        // A written `Ns\fn()` is a static name, not a dynamic callee. Follow
        // a same-file function when the namespace matches; an include-defined
        // function is a later edge.
        let local = fname.rsplit('\\').next().unwrap_or(&fname).to_string();
        if self.functions.contains_key(&local) && same_namespace(&self.ctx, &fname) {
            let bound: Vec<ResourceExpr> = args
                .iter()
                .map(|argument| self.recover_php_argument(*argument, env))
                .collect();
            self.follow(&local, &bound, n);
            return PhpCall::Entered;
        }

        // Effect builtins are unqualified (`unlink`, `getenv`). A namespaced
        // call is never a PHP builtin. PHP function names are case-insensitive.
        let builtin = fname.to_ascii_lowercase();
        if !fname.contains('\\')
            && let Some(()) = self.model_php_builtin(&builtin, &args, n, env)
        {
            // These run callables or code the model does not follow.
            return match builtin.as_str() {
                "unlink" => PhpCall::Sink,
                "call_user_func" | "call_user_func_array" => PhpCall::Entered,
                "array_map" | "array_walk" | "usort" | "eval" | "assert" => PhpCall::Opaque,
                _ => PhpCall::Modeled,
            };
        }
        let array_callback = match fname.as_str() {
            "array_filter" | "preg_replace_callback" => Some(1),
            "header_register_callback"
            | "ob_start"
            | "register_shutdown_function"
            | "register_tick_function"
            | "set_error_handler"
            | "set_exception_handler"
            | "spl_autoload_register" => Some(0),
            _ => None,
        };
        self.invoke_callback_arguments(&args, n, env, array_callback);
        if !fname.contains('\\') && array_callback.is_none() {
            let arguments: Vec<_> = args
                .iter()
                .enumerate()
                .map(|(index, argument)| crate::ValueArgument {
                    name: None,
                    index,
                    value: crate::SemanticValue::from(self.recover_php_argument(*argument, env)),
                })
                .collect();
            let site = self.span(n);
            if crate::dependency_calls::apply_global_dependency_call(
                self.builder,
                self.nest,
                "php",
                &fname,
                &arguments,
                site,
            ) {
                return PhpCall::Opaque;
            }
        }
        self.opaque(
            BoundaryReason::UNRESOLVED_CALL,
            BoundaryClass::Unresolved,
            n,
        );
        PhpCall::Opaque
    }

    pub(super) fn invoke_php_callable(
        &mut self,
        callable: Node<'a>,
        args: &[ResourceExpr],
        site: Node<'a>,
        _env: &HashMap<String, ResourceExpr>,
    ) -> bool {
        if callable.kind() == "parenthesized_expression"
            && let Some(inner) = callable.named_child(0)
        {
            return self.invoke_php_callable(inner, args, site, _env);
        }
        if matches!(callable.kind(), "anonymous_function" | "arrow_function")
            && let Some(body) = callable.child_by_field_name("body")
        {
            self.handled_closures.insert(callable.id());
            let params = callable
                .child_by_field_name("parameters")
                .map(|parameters| param_names(parameters, self.src))
                .unwrap_or_default();
            self.run_closure(
                &PhpClosure {
                    params,
                    body,
                    uses: closure_uses(callable, self.src),
                },
                args,
            );
            return true;
        }
        if callable.kind() == "variable_name"
            && let Some(name) = child_kind(callable, "name").map(|name| text(name, self.src))
            && let Some(closures) = self.closures.get(name).cloned()
        {
            for closure in closures {
                self.run_closure(&closure, args);
            }
            return true;
        }
        if let Some(function) = literal_string(callable, self.src)
            && self.functions.contains_key(&function)
        {
            self.follow(&function, args, site);
            return true;
        }
        let Some((receiver, method)) = callable_array(callable, self.src) else {
            return false;
        };
        if let Some(variable) = receiver.strip_prefix('$')
            && let Some(classes) = self.vars.get(variable).cloned()
        {
            let mut dispatched = false;
            for class in classes {
                dispatched |= self.dispatch_local_php_method(&class, &method, args, site)
                    || self.dispatch_psr4_php_method(&class, &method, args, site);
            }
            return dispatched;
        }
        let class = resolve_php_class_name(&self.ctx, receiver.trim_end_matches("::class"));
        self.dispatch_local_php_method(&class, &method, args, site)
            || self.resolve_php_class_file(&class).is_some()
                && self.dispatch_psr4_php_method(&class, &method, args, site)
    }

    pub(super) fn invoke_callback_arguments(
        &mut self,
        args: &[Node<'a>],
        site: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
        array_callback: Option<usize>,
    ) {
        for callable in args
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, argument)| {
                (matches!(
                    argument.kind(),
                    "anonymous_function" | "arrow_function" | "variable_name"
                ) || array_callback == Some(index))
                .then_some(argument)
            })
        {
            self.invoke_php_callable(callable, &[], site, env);
        }
    }

    pub(super) fn run_closure(&mut self, closure: &PhpClosure<'a>, args: &[ResourceExpr]) {
        let key = closure.body.id();
        if !self.active_closures.insert(key) {
            return;
        }
        let caller_locals = std::mem::take(&mut self.locals);
        let caller_network_handles = std::mem::take(&mut self.network_handles);
        let caller_poisoned = std::mem::take(&mut self.poisoned);
        let caller_captures = std::mem::take(&mut self.capture_locals);
        let caller_truths = std::mem::take(&mut self.truth_locals);
        let caller_globals_written = std::mem::take(&mut self.globals_written);
        let outermost = self.enter_facts(&caller_captures, &caller_truths);
        // A closure starts with copies of the values it uses.
        for name in &closure.uses {
            let local = format!("${name}");
            if let Some(held) = caller_captures.get(&local) {
                self.capture_locals.insert(local.clone(), held.clone());
            }
            if let Some(truth) = caller_truths.get(&local) {
                self.truth_locals.insert(local, *truth);
            }
        }
        self.locals = closure
            .uses
            .iter()
            .filter_map(|name| {
                caller_locals
                    .get(name)
                    .cloned()
                    .map(|value| (name.clone(), value))
            })
            .collect();
        self.network_handles = closure
            .uses
            .iter()
            .filter_map(|name| {
                caller_network_handles
                    .get(name)
                    .cloned()
                    .map(|value| (name.clone(), value))
            })
            .collect();
        self.poisoned = closure
            .uses
            .iter()
            .filter(|name| caller_poisoned.contains(*name))
            .cloned()
            .collect();
        let env = bind_php_params(&closure.params, args);
        if closure.body.kind() == "compound_statement" {
            let mut cursor = closure.body.walk();
            let statements: Vec<Node> = closure.body.named_children(&mut cursor).collect();
            self.exec_statements(&statements, &env);
        } else {
            self.exec(closure.body, &env);
        }
        self.locals = caller_locals;
        self.network_handles = caller_network_handles;
        self.poisoned = caller_poisoned;
        self.restore_facts(caller_captures, caller_truths, caller_globals_written);
        if outermost {
            self.global_facts = None;
        }
        // A `use (&$x)` binding writes the caller's local.
        if let Some(clause) = closure
            .body
            .parent()
            .and_then(|function| child_kind(function, "anonymous_function_use_clause"))
        {
            let mut cursor = clause.walk();
            let shared: Vec<String> = clause
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "by_ref")
                .filter_map(|by_ref| child_kind(by_ref, "variable_name"))
                .map(|variable| text(variable, self.src).to_string())
                .collect();
            self.forget_facts(Some(&shared));
        }
        self.active_closures.remove(&key);
    }

    pub(super) fn run_escaped_closure(&mut self, n: Node<'a>) {
        let mut current = n;
        while let Some(parent) = current.parent() {
            if matches!(
                parent.kind(),
                "unset_statement" | "isset_expression" | "empty_expression"
            ) {
                return;
            }
            if parent.kind() == "function_call_expression"
                && callable_name(parent, self.src)
                    .is_some_and(|name| matches!(name.as_str(), "isset" | "empty"))
            {
                return;
            }
            if parent.kind() == "binary_expression"
                && parent
                    .child_by_field_name("operator")
                    .is_some_and(|operator| {
                        matches!(
                            text(operator, self.src),
                            "==" | "==="
                                | "!="
                                | "!=="
                                | "<"
                                | ">"
                                | "<="
                                | ">="
                                | "<=>"
                                | "&&"
                                | "||"
                                | "and"
                                | "or"
                                | "xor"
                        )
                    })
            {
                return;
            }
            if matches!(
                parent.kind(),
                "if_statement"
                    | "while_statement"
                    | "do_statement"
                    | "for_statement"
                    | "conditional_expression"
            ) && parent
                .child_by_field_name("condition")
                .is_some_and(|condition| {
                    condition.start_byte() <= n.start_byte() && condition.end_byte() >= n.end_byte()
                })
            {
                return;
            }
            if parent.kind() == "parenthesized_expression" {
                current = parent;
                continue;
            }
            if parent.kind() == "assignment_expression"
                && parent
                    .child_by_field_name("left")
                    .is_some_and(|left| left.id() == current.id())
                || parent.kind() == "function_call_expression"
                    && parent
                        .child_by_field_name("function")
                        .is_some_and(|function| function.id() == current.id())
                || matches!(parent.kind(), "argument" | "arguments")
            {
                return;
            }
            break;
        }
        let Some(name) = child_kind(n, "name").map(|name| text(name, self.src)) else {
            return;
        };
        if let Some(closures) = self.closures.get(name).cloned() {
            for closure in closures {
                self.run_closure(&closure, &[]);
            }
        }
    }

    fn follow(&mut self, name: &str, args: &[ResourceExpr], site: Node<'a>) {
        if self.call_depth >= CALL_DEPTH_LIMIT || !self.following.insert(name.to_string()) {
            return;
        }
        self.call_depth += 1;
        let previous_call = self
            .builder
            .enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(self.src, site.start_byte(), site.end_byte()),
            ));
        let caller_closures = std::mem::take(&mut self.closures);
        let caller_vars = std::mem::take(&mut self.vars);
        let caller_locals = std::mem::take(&mut self.locals);
        let caller_network_handles = std::mem::take(&mut self.network_handles);
        let caller_poisoned = std::mem::take(&mut self.poisoned);
        let caller_captures = std::mem::take(&mut self.capture_locals);
        let caller_truths = std::mem::take(&mut self.truth_locals);
        let caller_globals_written = std::mem::take(&mut self.globals_written);
        let outermost = self.enter_facts(&caller_captures, &caller_truths);
        let caller_class = self.current_class.take();
        let caller_parent = self.class_parent.take();
        if let Some(f) = self.functions.get(name) {
            self.entered_callables.insert(name.to_string());
            let env = bind_php_params(&f.params, args);
            let body = f.body;
            let _ = site;
            let mut c = body.walk();
            let children: Vec<Node> = body.named_children(&mut c).collect();
            self.control_body(body, |w| w.exec_statements(&children, &env));
        }
        self.class_parent = caller_parent;
        self.current_class = caller_class;
        self.vars = caller_vars;
        self.locals = caller_locals;
        self.network_handles = caller_network_handles;
        self.poisoned = caller_poisoned;
        self.closures = caller_closures;
        self.restore_facts(caller_captures, caller_truths, caller_globals_written);
        if outermost {
            self.global_facts = None;
        }
        self.call_depth -= 1;
        self.following.remove(name);
        self.builder.leave_condition_call(previous_call);
    }

    pub(super) fn candidate_limit(&mut self, site: Node<'a>) {
        if !self
            .reported
            .insert("dynamic_dispatch:candidate_limit".to_string())
        {
            return;
        }
        let node = self.span(site);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: Some("max_callback_values".to_string()),
            detail: Some("php callback or receiver candidate limit exceeded".to_string()),
        });
        for d in KNOWN_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(d), CoverageLevel::Partial);
        }
    }
}
