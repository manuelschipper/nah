//! Call reachability from the syntax walk: local bodies, dependency summaries and callback arguments.

use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_span::Span;

use super::aggregate_alias::AggregateAliasPaths;
use super::callable_bindings::resolve_callable;
use super::expression_values::{sequence_callee_value, unparen};
use super::resolve::{self, ModuleCall};
use super::source_string::SourceStringValue;
use super::source_string_state::SourceStringState;
use super::walker::JsWalker;

/// How the frontend evaluated a call, for its control-flow site.
#[derive(Clone, Copy)]
pub(super) enum JsCall {
    /// A modeled API or known-inert callee.
    Modeled,
    /// A same-file body entered at the call.
    Local,
    /// Code the frontend cannot see, which may complete the invocation.
    Opaque,
}

/// What following a call reached: the call itself, the bodies it entered
/// directly (the first `direct` recorded applications), and how many callback
/// arguments were followed after them.
pub(super) struct ReachedCall {
    pub(super) call: JsCall,
    pub(super) direct: usize,
    pub(super) callbacks: usize,
}

impl<'a> JsWalker<'_, 'a> {
    /// Follow a call into a same-file body or compose a dependency summary
    /// for the called export. Unknown callees record an `unresolved_call`
    /// boundary when no model or known-inert builtin covers them.
    /// Callback arguments are followed under their own conditions.
    pub(super) fn follow_reachable(
        &mut self,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) -> ReachedCall {
        if self.bindings.dynamic_imports.is_quiet_call(call) {
            let mut callbacks = 0;
            for arg in &call.arguments {
                if let Some(expr) = arg.as_expression() {
                    callbacks += usize::from(self.follow_callback(expr));
                }
            }
            return ReachedCall {
                call: JsCall::Modeled,
                direct: 0,
                callbacks,
            };
        }
        let original_callee = unparen(&call.callee);
        let callee = sequence_callee_value(original_callee);
        let quiet_promise = self.is_quiet_promise_callee(original_callee);

        let known = |visitor: &Self| visitor.is_modeled_call(call) || visitor.is_quiet_callee(call);
        // Immediately-invoked function/arrow: its body executes now.
        let reached = match callee {
            Expression::FunctionExpression(f) => {
                if f.generator {
                    JsCall::Modeled
                } else if let Some(body) = &f.body {
                    let self_binding = f.id.as_ref().map(|id| id.name.as_str());
                    let result = self.enter_inline_body(
                        body,
                        &f.params,
                        self_binding,
                        &call.arguments,
                        argument_states,
                        true,
                        f.r#async,
                        false,
                    );
                    self.record_call_source_return(call, result.source_return);
                    self.record_call_aggregate_return(call, result.aggregate_return);
                    JsCall::Local
                } else {
                    JsCall::Opaque
                }
            }
            Expression::ArrowFunctionExpression(a) => {
                let result = self.enter_inline_body(
                    &a.body,
                    &a.params,
                    None,
                    &call.arguments,
                    argument_states,
                    true,
                    a.r#async,
                    a.expression,
                );
                self.record_call_source_return(call, result.source_return);
                self.record_call_aggregate_return(call, result.aggregate_return);
                JsCall::Local
            }
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if let Some(info) =
                    resolve_callable(self.functions, &self.callable_env, name, call.span)
                {
                    if self.direct_statement == Some(call.span.start)
                        && !call.optional
                        && !info.is_async
                    {
                        self.certain_body = Some(info.body.span.start);
                    }
                    let result = self.enter_function(info, &call.arguments, argument_states, true);
                    if let Some(producer) = result.producer {
                        self.stage_by_span.insert(call.span.start, producer);
                    }
                    self.record_call_source_return(call, result.source_return);
                    self.record_call_aggregate_return(call, result.aggregate_return);
                    JsCall::Local
                } else if !known(self)
                    && !self.apply_dependency_call(original_callee, call, argument_states)
                {
                    self.unresolved_call(call.span, name, Some(original_callee));
                    JsCall::Opaque
                } else {
                    JsCall::Modeled
                }
            }
            Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => {
                if self.follow_local_member_call(callee, call, argument_states) {
                    JsCall::Local
                } else if !known(self)
                    && !self.apply_dependency_call(original_callee, call, argument_states)
                {
                    self.unresolved_call(call.span, "member call", Some(original_callee));
                    JsCall::Opaque
                } else {
                    JsCall::Modeled
                }
            }
            _ => {
                if known(self) {
                    JsCall::Modeled
                } else {
                    self.unresolved_call(call.span, "expression call", Some(original_callee));
                    self.record_call_source_return(
                        call,
                        Some(SourceStringValue {
                            resource: None,
                            concatenation: true,
                        }),
                    );
                    JsCall::Opaque
                }
            }
        };

        let direct = self.control_applications.len();
        let callbacks = self.follow_call_callbacks(call, original_callee, quiet_promise);
        ReachedCall {
            call: reached,
            direct,
            callbacks,
        }
    }

    /// Compose a call through an exported function of a followed dependency
    /// (`helper.clean(dir)`, `clean(dir)` from `import { clean }`).
    fn apply_dependency_call(
        &mut self,
        callee: &Expression<'a>,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) -> bool {
        let Some(reference) = resolve::resolve_callee_reference(callee, self.bindings)
            .or_else(|| self.module_value_call(callee))
        else {
            return false;
        };
        if !crate::dependency_calls::is_path_specifier(&reference.module)
            || reference.function.is_empty()
            || reference.function.contains('.')
            || call
                .arguments
                .iter()
                .any(|argument| matches!(argument, Argument::SpreadElement(_)))
        {
            return false;
        }
        let arguments: Vec<_> = call
            .arguments
            .iter()
            .enumerate()
            .filter_map(|(index, argument)| {
                let resource =
                    self.argument_resource(argument.as_expression()?, argument_states.get(index));
                Some(crate::ValueArgument {
                    name: None,
                    index,
                    value: crate::SemanticValue::from(resource),
                })
            })
            .collect();
        let site = self.span_node(call.span);
        crate::dependency_calls::apply_dependency_call(
            self.builder,
            self.nest,
            &crate::dependency_calls::DependencyRequestKey {
                source_cwd: self.nest.current_source_cwd(),
                language: "js",
                specifier: reference.module,
            },
            &reference.function,
            &arguments,
            site,
            !self.bindings.environment_is_rewritten(),
        )
    }

    /// A call of a default import or a `require` result itself
    /// (`import wipe from './h.mjs'; wipe()`,
    /// `const wipe = require('./h.js'); wipe()`) calls the module's default
    /// export, which a summary also names for `module.exports = fn`. Calling
    /// an `import * as` namespace throws instead.
    fn module_value_call(&self, callee: &Expression<'a>) -> Option<ModuleCall> {
        let Expression::Identifier(id) = unparen(callee) else {
            return None;
        };
        if self.bindings.namespace_imports.contains(id.name.as_str()) {
            return None;
        }
        Some(ModuleCall {
            module: self.bindings.namespaces.get(id.name.as_str())?.clone(),
            function: "default".to_string(),
        })
    }

    fn follow_local_member_call(
        &mut self,
        callee: &Expression<'a>,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) -> bool {
        let Expression::StaticMemberExpression(member) = callee else {
            return false;
        };
        let method = member.property.name.as_str();
        let function = match unparen(&member.object) {
            Expression::Identifier(owner) => self
                .functions
                .object_member(owner.name.as_str(), method, call.span)
                .filter(|(_, binding_scope)| {
                    self.member_binding_is_visible(owner.name.as_str(), *binding_scope)
                })
                .map(|(function, _)| function)
                .or_else(|| {
                    self.functions
                        .instance_member(owner.name.as_str(), method, call.span)
                        .filter(|(_, receiver_scope, class, class_scope)| {
                            self.member_binding_is_visible(owner.name.as_str(), *receiver_scope)
                                && self.member_binding_is_visible(class, *class_scope)
                        })
                        .map(|(function, _, _, _)| function)
                }),
            Expression::NewExpression(new) => match unparen(&new.callee) {
                Expression::Identifier(class) => self
                    .functions
                    .class_member(class.name.as_str(), method, call.span)
                    .filter(|(_, binding_scope)| {
                        self.member_binding_is_visible(class.name.as_str(), *binding_scope)
                    })
                    .map(|(function, _)| function),
                _ => None,
            },
            _ => None,
        };
        let Some(function) = function else {
            return false;
        };
        let result = self.enter_function(function, &call.arguments, argument_states, true);
        if let Some(producer) = result.producer {
            self.stage_by_span.insert(call.span.start, producer);
        }
        self.record_call_source_return(call, result.source_return);
        self.record_call_aggregate_return(call, result.aggregate_return);
        true
    }

    fn member_binding_is_visible(&self, name: &str, binding_scope: Span) -> bool {
        !self.active_bodies.iter().any(|active| {
            active.local_names.contains(name)
                && binding_scope.start < active.span.start
                && active.span.end < binding_scope.end
        })
    }

    fn record_call_source_return(
        &mut self,
        call: &CallExpression<'a>,
        source_return: Option<SourceStringValue>,
    ) {
        if let Some(source_return) = source_return {
            self.evaluated_source_strings
                .insert((call.span.start, call.span.end), source_return);
        }
    }

    fn record_call_aggregate_return(
        &mut self,
        call: &CallExpression<'a>,
        aggregate_return: AggregateAliasPaths,
    ) {
        if !aggregate_return.is_empty() {
            self.evaluated_aggregate_aliases
                .insert((call.span.start, call.span.end), aggregate_return);
        }
    }
}
