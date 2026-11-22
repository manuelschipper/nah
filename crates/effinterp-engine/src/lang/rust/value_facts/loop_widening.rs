//! Rust loop widening after one abstract walk of the body.

use std::collections::{HashMap, HashSet};

use syn::visit::Visit;
use syn::{Block, Expr, Item, Local, Pat};

use crate::SemanticValue;
use crate::lang::rust::syntax::{chain_base_ident, is_compound_assignment, mutated_base_ident};

use super::pattern_bindings::rust_pattern_binding_names;
use super::{
    ClosureCaptureVisitor, ExprKey, RustValueFacts, ValueState, dedup_commands, expr_key,
    join_live_values,
};

pub(super) fn widen_loop_state(
    original: &ValueState,
    inner: &ValueState,
    value_limits: crate::ValueLimits,
) -> ValueState {
    // A single body walk cannot enumerate iteration counts. Keep the
    // zero-iteration state and make every changed binding explicitly wider.
    let mut out = original.clone();
    for (name, value) in &original.values {
        if inner.values.get(name) != Some(value) {
            out.values.insert(
                name.clone(),
                join_live_values(
                    [value.clone(), SemanticValue::unresolved("loop_value")],
                    value_limits,
                ),
            );
        }
    }
    for (name, commands) in &original.commands {
        if inner.commands.get(name) != Some(commands) {
            let target = out.commands.get_mut(name).expect("original command");
            if let Some(inner) = inner.commands.get(name) {
                target.values.extend(inner.values.clone());
                if target.cwd != inner.cwd {
                    target.cwd = Some(join_live_values(
                        [
                            target
                                .cwd
                                .clone()
                                .unwrap_or_else(|| SemanticValue::unresolved("command_cwd")),
                            SemanticValue::unresolved("loop_value"),
                        ],
                        value_limits,
                    ));
                }
            }
            target.widened = true;
            dedup_commands(target, value_limits);
        }
    }
    out
}

/// Widen Rust loop body facts that depend on a changing binding, including through body-local aliases.
pub(super) fn widen_loop_facts(
    facts: &mut RustValueFacts,
    body: &Block,
    original: &ValueState,
    inner: &ValueState,
    pattern: Option<(&Pat, &Expr)>,
    value_limits: crate::ValueLimits,
) {
    let tracked_keys = facts
        .expressions
        .keys()
        .chain(facts.commands.keys())
        .copied()
        .collect();
    for key in widened_loop_fact_keys(&tracked_keys, body, original, inner, pattern) {
        if facts.expressions.contains_key(&key) {
            facts
                .expressions
                .insert(key, SemanticValue::unresolved("loop_value"));
        }
        if let Some(command) = facts.commands.get_mut(&key) {
            command.widened = true;
            dedup_commands(command, value_limits);
        }
    }
}

fn widened_loop_fact_keys(
    tracked_keys: &HashSet<ExprKey>,
    body: &Block,
    original: &ValueState,
    inner: &ValueState,
    pattern: Option<(&Pat, &Expr)>,
) -> HashSet<ExprKey> {
    // Scope restore drops body-local names before this diff, so a fact that
    // reads an alias of a changed outer binding would otherwise stay exact.
    let changed_bindings: HashSet<_> = original
        .values
        .keys()
        .chain(inner.values.keys())
        .filter(|name| original.values.get(*name) != inner.values.get(*name))
        .chain(
            original
                .commands
                .keys()
                .chain(inner.commands.keys())
                .filter(|name| original.commands.get(*name) != inner.commands.get(*name)),
        )
        .cloned()
        .collect();
    if changed_bindings.is_empty() {
        return HashSet::new();
    }
    let mut visitor = LoopFactVisitor {
        tracked_keys,
        changed_bindings: &changed_bindings,
        scopes: Vec::new(),
        widened: HashSet::new(),
    };
    if let Some((pattern, source)) = pattern {
        let tainted = visitor.expr_tainted(source);
        visitor.scopes.push(HashMap::new());
        visitor.bind_pattern(pattern, tainted);
    }
    visitor.visit_block(body);
    visitor.widened
}

struct LoopFactVisitor<'a> {
    tracked_keys: &'a HashSet<ExprKey>,
    changed_bindings: &'a HashSet<String>,
    scopes: Vec<HashMap<String, bool>>,
    widened: HashSet<ExprKey>,
}

impl LoopFactVisitor<'_> {
    fn is_tainted(&self, name: &str) -> bool {
        for scope in self.scopes.iter().rev() {
            if let Some(tainted) = scope.get(name) {
                return *tainted;
            }
        }
        self.changed_bindings.contains(name)
    }

    fn expr_tainted(&self, expr: &Expr) -> bool {
        let mut names = ClosureCaptureVisitor::default();
        names.visit_expr(expr);
        names.names.iter().any(|name| self.is_tainted(name))
    }

    fn bind_pattern(&mut self, pattern: &Pat, tainted: bool) {
        let mut names = Vec::new();
        rust_pattern_binding_names(pattern, &mut names, &HashMap::new());
        if let Some(scope) = self.scopes.last_mut() {
            for name in names {
                scope.insert(name, tainted);
            }
        }
    }

    fn taint(&mut self, name: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), true);
                return;
            }
        }
    }
}

impl<'ast> Visit<'ast> for LoopFactVisitor<'_> {
    fn visit_item(&mut self, _: &'ast Item) {}

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}

    fn visit_block(&mut self, block: &'ast Block) {
        self.scopes.push(HashMap::new());
        syn::visit::visit_block(self, block);
        self.scopes.pop();
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
        let tainted = local
            .init
            .as_ref()
            .is_some_and(|init| self.expr_tainted(&init.expr));
        self.bind_pattern(&local.pat, tainted);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, assign);
        if self.expr_tainted(&assign.right)
            && let Some(name) = mutated_base_ident(&assign.left)
        {
            self.taint(&name);
        }
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        syn::visit::visit_expr_binary(self, binary);
        if is_compound_assignment(&binary.op)
            && self.expr_tainted(&binary.right)
            && let Some(name) = mutated_base_ident(&binary.left)
        {
            self.taint(&name);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        let method = call.method.to_string();
        if matches!(method.as_str(), "arg" | "args")
            && call.args.iter().any(|argument| self.expr_tainted(argument))
            && let Some(name) = chain_base_ident(&call.receiver)
        {
            self.taint(&name);
        }
    }

    fn visit_expr_for_loop(&mut self, loop_: &'ast syn::ExprForLoop) {
        self.visit_expr(&loop_.expr);
        self.scopes.push(HashMap::new());
        self.bind_pattern(&loop_.pat, self.expr_tainted(&loop_.expr));
        self.visit_block(&loop_.body);
        self.scopes.pop();
    }

    fn visit_expr_while(&mut self, loop_: &'ast syn::ExprWhile) {
        if let Expr::Let(let_) = &*loop_.cond {
            self.visit_expr(&let_.expr);
            self.scopes.push(HashMap::new());
            self.bind_pattern(&let_.pat, self.expr_tainted(&let_.expr));
            self.visit_block(&loop_.body);
            self.scopes.pop();
        } else {
            syn::visit::visit_expr_while(self, loop_);
        }
    }

    fn visit_expr_if(&mut self, if_: &'ast syn::ExprIf) {
        if let Expr::Let(let_) = &*if_.cond {
            self.visit_expr(&let_.expr);
            self.scopes.push(HashMap::new());
            self.bind_pattern(&let_.pat, self.expr_tainted(&let_.expr));
            self.visit_block(&if_.then_branch);
            self.scopes.pop();
            if let Some((_, else_)) = &if_.else_branch {
                self.visit_expr(else_);
            }
        } else {
            syn::visit::visit_expr_if(self, if_);
        }
    }

    fn visit_expr_match(&mut self, match_: &'ast syn::ExprMatch) {
        self.visit_expr(&match_.expr);
        let tainted = self.expr_tainted(&match_.expr);
        for arm in &match_.arms {
            self.scopes.push(HashMap::new());
            self.bind_pattern(&arm.pat, tainted);
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            self.scopes.pop();
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        let key = expr_key(expr);
        if self.tracked_keys.contains(&key) && self.expr_tainted(expr) {
            self.widened.insert(key);
        }
        syn::visit::visit_expr(self, expr);
    }
}
