//! Callable bindings set during execution, which take precedence over collected declarations.

use std::collections::HashSet;

use oxc_ast::ast::Expression;
use oxc_span::Span;

use super::collect::{self, FnTable};
use super::expression_values::unparen;
use super::plus_coercion::{PLUS_COERCION_BINDING_SUFFIX, plus_coercion_binding_name};
use super::walker::JsWalker;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CallableBinding {
    Assigned(u32),
    Declarator(u32),
    PlusCoercion(u32),
    Unbounded,
}

/// Persistent bindings let snapshots of a scope share entries across a call.
pub(super) type CallableEnv = im::HashMap<String, CallableBinding>;

/// An executed binding supersedes a collected declaration at the use site.
pub(super) fn resolve_callable<'t, 'a>(
    functions: &'t FnTable<'a>,
    callable_env: &CallableEnv,
    name: &str,
    use_span: Span,
) -> Option<&'t collect::FnInfo<'a>> {
    match callable_env.get(name) {
        Some(CallableBinding::Assigned(assignment_span)) => {
            collect::resolve_assignment(functions, name, *assignment_span)
        }
        Some(CallableBinding::Declarator(initialized_at)) => {
            collect::resolve_declarator(functions, name, *initialized_at)
        }
        Some(CallableBinding::PlusCoercion(_)) => None,
        Some(CallableBinding::Unbounded) => None,
        None => collect::resolve(functions, name, use_span),
    }
}

impl<'a> JsWalker<'_, 'a> {
    pub(super) fn track_callable_declarator(
        &mut self,
        name: &str,
        init: &Expression<'a>,
        initialized_at: u32,
    ) {
        self.record_source_string_write_name(name);
        if matches!(
            unparen(init),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            self.callable_env.insert(
                name.to_string(),
                CallableBinding::Declarator(initialized_at),
            );
        } else {
            self.callable_env
                .insert(name.to_string(), CallableBinding::Unbounded);
        }
        self.sync_module_source_strings();
    }

    pub(super) fn track_callable_assignment(
        &mut self,
        name: &str,
        value: &Expression<'a>,
        assignment_span: u32,
    ) {
        self.record_source_string_write_name(name);
        let binding = if matches!(
            unparen(value),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) && collect::resolve_assignment(self.functions, name, assignment_span)
            .is_some()
        {
            CallableBinding::Assigned(assignment_span)
        } else {
            CallableBinding::Unbounded
        };
        self.callable_env.insert(name.to_string(), binding);
        self.sync_module_source_strings();
    }

    pub(super) fn mark_callable_binding_unbounded(&mut self, name: String) {
        self.record_source_string_write_name(&name);
        if !name.ends_with(PLUS_COERCION_BINDING_SUFFIX) {
            self.callable_env.insert(
                plus_coercion_binding_name(&name),
                CallableBinding::Unbounded,
            );
        }
        self.callable_env.insert(name, CallableBinding::Unbounded);
        self.sync_module_source_strings();
    }

    pub(super) fn mark_callable_bindings_unbounded(&mut self, names: &HashSet<String>) {
        if names.is_empty() {
            return;
        }
        self.record_source_string_write_names(names);
        for name in names {
            if !name.ends_with(PLUS_COERCION_BINDING_SUFFIX) {
                self.callable_env
                    .insert(plus_coercion_binding_name(name), CallableBinding::Unbounded);
            }
            self.callable_env
                .insert(name.clone(), CallableBinding::Unbounded);
        }
        self.sync_module_source_strings();
    }
}
