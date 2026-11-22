//! Call body entry and the state a reached body returns to its caller.
//! Lexical parents supply bindings. The call site supplies arguments and conditions.

use std::collections::{HashMap, HashSet};

use effinterp_proto::ResourceExpr;
use oxc_ast::ast::{Argument, BindingPattern, FormalParameters, FunctionBody, Statement};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use super::aggregate_alias::{
    AggregateAliasPaths, AggregateAliases, clear_aggregate_aliases,
    expression_aggregate_alias_paths, extend_aggregate_alias_paths,
};
use super::binding_paths::binding_is_within;
use super::bindings::{collect_binding_names, function_local_binding_names};
use super::call_arguments::{logical_call_argument, logical_call_argument_count};
use super::callable_bindings::{CallableBinding, CallableEnv};
use super::control::{self, statement_stops_sequential_execution};
use super::flow_tracking::ResponseKind;
use super::identifier_references::function_process_scope;
use super::plus_coercion::{PLUS_COERCION_BINDING_SUFFIX, plus_coercion_binding_name};
use super::resolve::ParamEnv;
use super::source_string::{
    SourceBindingValue, SourceStringValue, bind_source_string_pattern, is_global_undefined,
    is_string_concatenation, mark_unbounded_source_string, set_source_string_binding,
    source_string_resource,
};
use super::source_string_state::{
    SourceStringNames, SourceStringState, changed_captured_bindings, object_literal_bytes,
    restore_source_string_state_names,
};
use super::walker::JsWalker;
use super::{collect, printed_environment};
use crate::control_flow::SiteFacts;
use crate::summary::bind_positional;

/// A tracked local seeded into a callback: its name, its producer, and
/// whether it holds a response object.
pub(super) type FlowCapture = (String, usize, Option<ResponseKind>);

pub(super) struct ActiveBody {
    pub(super) span: Span,
    enclosing_source_state: SourceStringState,
    pub(super) local_names: HashSet<String>,
    pub(super) process_runtime: bool,
}

#[derive(Default)]
pub(super) struct BodyResult {
    pub(super) producer: Option<usize>,
    pub(super) source_return: Option<SourceStringValue>,
    pub(super) aggregate_return: AggregateAliasPaths,
}

/// Whether the program may run a body, or replace a function, where no call
/// is written. An accessor (`get x() {}`, a `defineProperty` descriptor, a
/// `Proxy`) runs on a property read or write, and `eval` or `Function` text
/// may rebind any name. What a called body leaves cleared is then not
/// established: the body may not be the one that ran, or a later statement
/// may have filled the binding again.
pub(super) fn runs_unwritten_calls(semantic: &oxc_semantic::Semantic<'_>) -> bool {
    use oxc_ast::AstKind;
    use oxc_ast::ast::{MethodDefinitionKind, PropertyKind};
    semantic.nodes().iter().any(|node| match node.kind() {
        AstKind::ObjectProperty(property) => {
            property.kind != PropertyKind::Init
                || matches!(property.key.static_name().as_deref(), Some("get" | "set"))
        }
        AstKind::MethodDefinition(method) => {
            matches!(
                method.kind,
                MethodDefinitionKind::Get | MethodDefinitionKind::Set
            )
        }
        AstKind::IdentifierReference(id) => {
            matches!(id.name.as_str(), "eval" | "Function" | "Proxy" | "Reflect")
        }
        AstKind::StaticMemberExpression(member) => matches!(
            member.property.name.as_str(),
            "defineProperty" | "defineProperties" | "__defineGetter__" | "__defineSetter__"
        ),
        AstKind::WithStatement(_) => true,
        _ => false,
    })
}

impl<'a> JsWalker<'_, 'a> {
    fn active_lexical_source_state(&self, body: Span) -> Option<SourceStringState> {
        let parent = self
            .active_bodies
            .iter()
            .rposition(|active| active.span.start < body.start && body.end < active.span.end)?;
        let mut state = self.source_string_state();
        for active in self.active_bodies[parent + 1..].iter().rev() {
            restore_source_string_state_names(
                self.nest.budget,
                &mut state,
                &active.enclosing_source_state,
                &active.local_names,
            );
        }
        Some(state)
    }

    fn active_lexical_process_runtime(&self, body: Span) -> Option<bool> {
        self.active_bodies
            .iter()
            .rfind(|active| active.span.start < body.start && body.end < active.span.end)
            .map(|active| active.process_runtime)
    }

    /// Enter a called local function: resolve the caller's arguments in the
    /// current environment, bind them positionally to the callee's parameters,
    /// and walk the body under that environment so a parameter identifier
    /// resolves to the argument the caller passed. Local bindings are restored
    /// afterwards; definitely executed calls retain writes to captured bindings.
    pub(super) fn enter_function(
        &mut self,
        function: &collect::FnInfo<'a>,
        args: &[Argument<'a>],
        argument_states: &[SourceStringState],
        preserve_captured_writes: bool,
    ) -> BodyResult {
        if self.saturated || function.is_generator {
            return BodyResult::default();
        }
        let cwd_arg_exprs: Vec<ResourceExpr> =
            args.iter().map(|arg| self.arg_cwd_resource(arg)).collect();
        let mut new_cwd_env = self.cwd_consts.clone();
        new_cwd_env.extend(bind_positional(&function.params, &cwd_arg_exprs));
        let argument_source_env = self.source_env.clone();
        let argument_unbounded_source_env = self.unbounded_source_env.clone();
        let saved_source_state = self.source_string_state();
        let saved_process = self.process_runtime;
        // A nested function sees its lexical parent. A top-level callee sees
        // live module bindings rather than locals from an unrelated caller.
        let enclosing_source_state = self
            .active_lexical_source_state(function.body.span)
            .unwrap_or_else(|| SourceStringState {
                param_env: self.module_env.clone(),
                source_env: self.source_strings.clone(),
                unbounded_source_env: self.unbounded_source_strings.clone(),
                definitely_nullish_env: self.module_definitely_nullish_env.clone(),
                callable_env: self.module_callable_env.clone(),
                aggregate_aliases: self.module_aggregate_aliases.clone(),
            });
        if !self.charge_retained_state(
            &enclosing_source_state,
            object_literal_bytes(&self.object_literal_vars),
            function.body.span,
        ) {
            return BodyResult::default();
        }
        let saved_object_literal_vars = self.object_literal_vars.clone();
        let saved_cwd = std::mem::replace(&mut self.cwd_param_env, new_cwd_env);
        self.builder
            .control_enter(self.control_source, false, |graph| {
                control::build_function(
                    graph,
                    function.parameters,
                    function.body,
                    &self.bindings.readonly_writes,
                )
            });
        let enclosing_process_runtime = self
            .active_lexical_process_runtime(function.body.span)
            .unwrap_or_else(|| self.bindings.process_runtime());
        let mut new_env = enclosing_source_state.param_env.clone();
        let mut new_source_env = enclosing_source_state.source_env.clone();
        let mut new_unbounded_source_env = enclosing_source_state.unbounded_source_env.clone();
        let mut new_definitely_nullish_env = enclosing_source_state.definitely_nullish_env.clone();
        let mut new_callable_env = enclosing_source_state.callable_env.clone();
        let mut new_aggregate_aliases = enclosing_source_state.aggregate_aliases.clone();
        let mut local_names = function_local_binding_names(function.body);
        local_names.extend(function.param_bindings.iter().cloned());
        local_names.extend(function.self_binding.iter().cloned());
        let mut new_object_literal_vars = if self.active_bodies.iter().any(|active| {
            active.span.start < function.body.span.start && function.body.span.end < active.span.end
        }) {
            self.object_literal_vars.clone()
        } else {
            self.module_object_literal_vars.clone()
        };
        for name in &local_names {
            new_env.remove(name);
            new_callable_env.remove(name);
            new_callable_env.remove(&plus_coercion_binding_name(name));
            mark_unbounded_source_string(name, &mut new_source_env, &mut new_unbounded_source_env);
            new_definitely_nullish_env.remove(name);
            new_object_literal_vars.remove(name);
        }
        clear_aggregate_aliases(&mut new_aggregate_aliases, &local_names);
        self.param_env = new_env;
        self.source_env = new_source_env;
        self.unbounded_source_env = new_unbounded_source_env;
        self.definitely_nullish_env = new_definitely_nullish_env;
        self.callable_env = new_callable_env;
        self.aggregate_aliases = new_aggregate_aliases;
        self.object_literal_vars = new_object_literal_vars;
        let body_entry = self.source_string_state();
        self.source_string_write_names.push(HashSet::new());
        self.process_runtime = function.process_scope.unwrap_or(enclosing_process_runtime);
        self.function_depth += 1;
        for (index, parameter) in function.parameters.items.iter().enumerate() {
            let logical_argument = logical_call_argument(args, index);
            let argument = logical_argument.and_then(|(argument, _)| argument);
            let argument_evaluation_state =
                logical_argument.and_then(|(_, syntax_index)| argument_states.get(syntax_index));
            let default_source_env =
                argument_evaluation_state.map_or(&argument_source_env, |state| &state.source_env);
            let default_unbounded_source_env = argument_evaluation_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            let uses_default = parameter.initializer.is_some()
                && match logical_argument {
                    None => true,
                    Some((Some(argument), _)) => is_global_undefined(
                        argument,
                        default_source_env,
                        default_unbounded_source_env,
                    ),
                    Some((None, _)) => false,
                };
            if uses_default {
                self.visit_expression(parameter.initializer.as_deref().unwrap());
            }
            if let BindingPattern::BindingIdentifier(id) = &parameter.pattern {
                let name = id.name.as_str();
                let resource = if uses_default {
                    parameter
                        .initializer
                        .as_deref()
                        .and_then(|initializer| self.tracked_value(initializer))
                } else {
                    argument
                        .map(|argument| self.argument_resource(argument, argument_evaluation_state))
                };
                self.param_env.remove(name);
                if let Some(resource) = resource {
                    self.param_env.insert(name.to_string(), resource);
                }
            }
            self.bind_environment_parameter(
                function.body.span.start,
                &parameter.pattern,
                if uses_default {
                    parameter.initializer.as_deref()
                } else {
                    argument
                },
            );
            let value = if uses_default {
                SourceBindingValue::Local(parameter.initializer.as_deref().unwrap())
            } else {
                match logical_argument {
                    None => SourceBindingValue::Missing,
                    Some((Some(argument), _)) => SourceBindingValue::Argument(argument),
                    Some((None, _)) => SourceBindingValue::Unbounded,
                }
            };
            let argument_state = (!uses_default)
                .then_some(argument_evaluation_state)
                .flatten();
            let argument_source_env =
                argument_state.map_or(&argument_source_env, |state| &state.source_env);
            let argument_unbounded_source_env = argument_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            self.visit_binding_pattern_defaults(&parameter.pattern, value);
            bind_source_string_pattern(
                &parameter.pattern,
                value,
                argument_source_env,
                argument_unbounded_source_env,
                &mut self.source_env,
                &mut self.unbounded_source_env,
                saved_process,
                self.process_runtime,
                &self.evaluated_source_strings,
            );
            self.bind_parameter_plus_coercion(
                &parameter.pattern,
                value,
                argument_state,
                &saved_source_state,
            );
            if !uses_default {
                self.bind_parameter_aggregate_alias(
                    &parameter.pattern,
                    argument,
                    argument_state,
                    &saved_source_state,
                );
            }
        }
        if let Some(rest) = &function.parameters.rest {
            self.bind_rest_parameter(
                &rest.rest.argument,
                function.parameters.items.len(),
                args,
                argument_states,
                &argument_source_env,
                &argument_unbounded_source_env,
                &saved_source_state.callable_env,
                &saved_source_state.aggregate_aliases,
                saved_process,
            );
        }
        self.function_depth -= 1;
        let mut result = self.enter_body(
            function.body,
            ActiveBody {
                span: function.body.span,
                enclosing_source_state,
                local_names: local_names.clone(),
                process_runtime: self.process_runtime,
            },
            function.expression_body,
        );
        self.leave_control_body(function.is_async);
        result.aggregate_return.retain(|_, targets| {
            targets.retain(|name| {
                !local_names
                    .iter()
                    .any(|local| binding_is_within(name, local))
            });
            !targets.is_empty()
        });
        if function.is_async {
            result.source_return = None;
            result.aggregate_return.clear();
        }
        let body_exit = self.source_string_state();
        let source_string_write_names = self.source_string_write_names.pop().unwrap();
        self.process_runtime = saved_process;
        self.cwd_param_env = saved_cwd;
        self.restore_source_string_state(saved_source_state);
        self.object_literal_vars = saved_object_literal_vars;
        self.propagate_captured_writes(
            &body_entry,
            &body_exit,
            &local_names,
            &source_string_write_names,
            preserve_captured_writes && !function.is_async,
            function.body.span,
        );
        result
    }

    /// Finish an entered body's control-flow frame and record what it
    /// guarantees to the call that entered it. An async body's continuation
    /// after its first await is not ordered with the caller.
    fn leave_control_body(&mut self, is_async: bool) {
        let finished = self.builder.control_leave();
        let application = match finished {
            Some(finished) if !is_async => SiteFacts::call(&finished.requirements, Some),
            _ => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn enter_inline_body<'b>(
        &mut self,
        body: &'b FunctionBody<'a>,
        params: &'b FormalParameters<'a>,
        self_binding: Option<&str>,
        args: &[Argument<'a>],
        argument_states: &[SourceStringState],
        preserve_captured_writes: bool,
        is_async: bool,
        expression_body: bool,
    ) -> BodyResult {
        let argument_source_env = self.source_env.clone();
        let argument_unbounded_source_env = self.unbounded_source_env.clone();
        let saved_process = self.process_runtime;
        let saved_source_state = self.source_string_state();
        if !self.charge_retained_state(&saved_source_state, 0, body.span) {
            return BodyResult::default();
        }
        let saved_object_literal_vars = self.object_literal_vars.clone();
        self.builder
            .control_enter(self.control_source, false, |graph| {
                control::build_function(graph, params, body, &self.bindings.readonly_writes)
            });
        let mut bound_names = HashSet::new();
        for parameter in &params.items {
            collect_binding_names(&parameter.pattern, &mut bound_names);
        }
        if let Some(rest) = &params.rest {
            collect_binding_names(&rest.rest.argument, &mut bound_names);
        }
        if let Some(name) = self_binding {
            bound_names.insert(name.to_string());
        }
        let mut local_names = function_local_binding_names(body);
        for name in &local_names {
            self.param_env.remove(name);
            self.callable_env.remove(name);
            self.callable_env.remove(&plus_coercion_binding_name(name));
            mark_unbounded_source_string(
                name,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            self.definitely_nullish_env.remove(name);
            self.object_literal_vars.remove(name);
        }
        for name in &bound_names {
            self.param_env.remove(name);
            self.callable_env.remove(name);
            self.callable_env.remove(&plus_coercion_binding_name(name));
            mark_unbounded_source_string(
                name,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            self.definitely_nullish_env.remove(name);
            self.object_literal_vars.remove(name);
        }
        let mut hidden_names = local_names.clone();
        hidden_names.extend(bound_names.iter().cloned());
        clear_aggregate_aliases(&mut self.aggregate_aliases, &hidden_names);
        let body_entry = self.source_string_state();
        self.source_string_write_names.push(HashSet::new());
        self.process_runtime = function_process_scope(body, params).unwrap_or(saved_process);
        self.function_depth += 1;
        for (index, parameter) in params.items.iter().enumerate() {
            let logical_argument = logical_call_argument(args, index);
            let argument = logical_argument.and_then(|(argument, _)| argument);
            let argument_evaluation_state =
                logical_argument.and_then(|(_, syntax_index)| argument_states.get(syntax_index));
            let default_source_env =
                argument_evaluation_state.map_or(&argument_source_env, |state| &state.source_env);
            let default_unbounded_source_env = argument_evaluation_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            let uses_default = parameter.initializer.is_some()
                && match logical_argument {
                    None => true,
                    Some((Some(argument), _)) => is_global_undefined(
                        argument,
                        default_source_env,
                        default_unbounded_source_env,
                    ),
                    Some((None, _)) => false,
                };
            if uses_default {
                self.visit_expression(parameter.initializer.as_deref().unwrap());
            }
            if let BindingPattern::BindingIdentifier(id) = &parameter.pattern {
                let name = id.name.as_str();
                let resource = if uses_default {
                    parameter
                        .initializer
                        .as_deref()
                        .and_then(|initializer| self.tracked_value(initializer))
                } else {
                    argument
                        .map(|argument| self.argument_resource(argument, argument_evaluation_state))
                };
                self.param_env.remove(name);
                if let Some(resource) = resource {
                    self.param_env.insert(name.to_string(), resource);
                }
            }
            self.bind_environment_parameter(
                body.span.start,
                &parameter.pattern,
                if uses_default {
                    parameter.initializer.as_deref()
                } else {
                    argument
                },
            );
            let value = if uses_default {
                SourceBindingValue::Local(parameter.initializer.as_deref().unwrap())
            } else {
                match logical_argument {
                    None => SourceBindingValue::Missing,
                    Some((Some(argument), _)) => SourceBindingValue::Argument(argument),
                    Some((None, _)) => SourceBindingValue::Unbounded,
                }
            };
            let argument_state = (!uses_default)
                .then_some(argument_evaluation_state)
                .flatten();
            let argument_source_env =
                argument_state.map_or(&argument_source_env, |state| &state.source_env);
            let argument_unbounded_source_env = argument_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            self.visit_binding_pattern_defaults(&parameter.pattern, value);
            bind_source_string_pattern(
                &parameter.pattern,
                value,
                argument_source_env,
                argument_unbounded_source_env,
                &mut self.source_env,
                &mut self.unbounded_source_env,
                saved_process,
                self.process_runtime,
                &self.evaluated_source_strings,
            );
            self.bind_parameter_plus_coercion(
                &parameter.pattern,
                value,
                argument_state,
                &saved_source_state,
            );
            if !uses_default {
                self.bind_parameter_aggregate_alias(
                    &parameter.pattern,
                    argument,
                    argument_state,
                    &saved_source_state,
                );
            }
        }
        if let Some(rest) = &params.rest {
            self.bind_rest_parameter(
                &rest.rest.argument,
                params.items.len(),
                args,
                argument_states,
                &argument_source_env,
                &argument_unbounded_source_env,
                &saved_source_state.callable_env,
                &saved_source_state.aggregate_aliases,
                saved_process,
            );
        }
        self.function_depth -= 1;
        local_names.extend(bound_names);
        let mut result = self.enter_body(
            body,
            ActiveBody {
                span: body.span,
                enclosing_source_state: saved_source_state.clone(),
                local_names: local_names.clone(),
                process_runtime: self.process_runtime,
            },
            expression_body,
        );
        self.leave_control_body(is_async);
        result.aggregate_return.retain(|_, targets| {
            targets.retain(|name| {
                !local_names
                    .iter()
                    .any(|local| binding_is_within(name, local))
            });
            !targets.is_empty()
        });
        if is_async {
            result.source_return = None;
            result.aggregate_return.clear();
        }
        let body_exit = self.source_string_state();
        let source_string_write_names = self.source_string_write_names.pop().unwrap();
        self.restore_source_string_state(saved_source_state);
        self.object_literal_vars = saved_object_literal_vars;
        self.propagate_captured_writes(
            &body_entry,
            &body_exit,
            &local_names,
            &source_string_write_names,
            preserve_captured_writes && !is_async,
            body.span,
        );
        self.process_runtime = saved_process;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn bind_rest_parameter(
        &mut self,
        pattern: &BindingPattern<'a>,
        first_argument: usize,
        args: &[Argument<'a>],
        argument_states: &[SourceStringState],
        argument_source_env: &ParamEnv,
        argument_unbounded_source_env: &SourceStringNames,
        argument_callable_env: &CallableEnv,
        argument_aggregate_aliases: &AggregateAliases,
        argument_process_runtime: bool,
    ) {
        let BindingPattern::BindingIdentifier(identifier) = pattern else {
            return;
        };
        let prefix = format!("{}.", identifier.name.as_str());
        self.source_env.retain(|name, _| !name.starts_with(&prefix));
        self.unbounded_source_env
            .retain(|name| !name.starts_with(&prefix));
        self.callable_env.retain(|name, _| {
            !name.starts_with(&prefix) || !name.ends_with(PLUS_COERCION_BINDING_SUFFIX)
        });
        let Some(argument_count) = logical_call_argument_count(args) else {
            return;
        };
        for argument_index in first_argument..argument_count {
            let Some((argument, syntax_index)) = logical_call_argument(args, argument_index) else {
                continue;
            };
            let state = argument_states.get(syntax_index);
            let source_env = state.map_or(argument_source_env, |state| &state.source_env);
            let unbounded_source_env = state.map_or(argument_unbounded_source_env, |state| {
                &state.unbounded_source_env
            });
            let callable_env = state.map_or(argument_callable_env, |state| &state.callable_env);
            let aggregate_aliases =
                state.map_or(argument_aggregate_aliases, |state| &state.aggregate_aliases);
            let (resource, concatenation) = argument.map_or((None, false), |argument| {
                (
                    source_string_resource(
                        argument,
                        source_env,
                        unbounded_source_env,
                        argument_process_runtime,
                        &self.evaluated_source_strings,
                    ),
                    is_string_concatenation(argument, source_env, &self.evaluated_source_strings),
                )
            });
            let binding_name = format!(
                "{}{rest_index}",
                prefix,
                rest_index = argument_index - first_argument
            );
            set_source_string_binding(
                &binding_name,
                resource,
                concatenation,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            let binding = argument
                .and_then(|argument| {
                    self.plus_coercion_binding(argument, callable_env, aggregate_aliases)
                })
                .unwrap_or(CallableBinding::Unbounded);
            self.callable_env
                .insert(plus_coercion_binding_name(&binding_name), binding);
        }
    }

    fn propagate_captured_writes(
        &mut self,
        body_entry: &SourceStringState,
        body_exit: &SourceStringState,
        local_names: &HashSet<String>,
        candidates: &HashSet<String>,
        definitely_executed: bool,
        span: Span,
    ) {
        let captured_writes = changed_captured_bindings(
            self.nest.budget,
            body_entry,
            body_exit,
            local_names,
            candidates,
        );
        if captured_writes.is_empty() {
            return;
        }
        self.record_source_string_write_names(&captured_writes);
        if definitely_executed {
            self.restore_source_string_names(body_exit, &captured_writes);
        } else {
            let call_entry = self.source_string_state();
            self.restore_source_string_names(body_exit, &captured_writes);
            let call_exit = self.source_string_state();
            self.join_source_string_states(call_entry, call_exit, span);
        }
    }

    /// Whether `name` in the body now ending is the binding its caller
    /// knows by that name: not a name the body declares, nor one the
    /// caller declares unless the body is written inside the caller.
    fn caller_shares_binding(&self, name: &str) -> bool {
        let bodies = self.active_bodies.len();
        let body = &self.active_bodies[bodies - 1];
        !body.local_names.contains(name)
            && bodies.checked_sub(2).is_none_or(|caller| {
                let caller = &self.active_bodies[caller];
                !caller.local_names.contains(name)
                    || (caller.span.start <= body.span.start && body.span.end <= caller.span.end)
            })
    }

    /// Analyze the statements of a reachable function body, guarding against
    /// call cycles by body span. Generic over the borrow so a local function's
    /// stored `'a` body and an inline IIFE/callback body both work.
    fn enter_body<'b>(
        &mut self,
        body: &'b oxc_ast::ast::FunctionBody<'a>,
        active_body: ActiveBody,
        expression_body: bool,
    ) -> BodyResult {
        let environment_params = self
            .environment_params
            .take_if(|(entered, _)| *entered == body.span.start);
        let certain = self
            .certain_body
            .take_if(|entered| *entered == body.span.start)
            .is_some()
            && !self.unwritten_calls;
        if self.saturated || !self.visiting.insert(body.span.start) {
            return BodyResult::default();
        }
        let previous_call = self
            .builder
            .enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(&self.bindings.source_digest, self.condition_site),
            ));
        self.entered_callable_body = true;
        // A body written outside a scope that redeclares a name means the
        // outer binding by it (`{ let key = "ok"; load() }`).
        let switched_scopes = self.view_bindings_from(body.span);
        // A nested body is a separate scope: the caller's tracked producers are
        // not visible under the callee's parameter names (a same-named parameter
        // shadows them), so def-use tracking starts empty and is restored after.
        let saved_flow = std::mem::take(&mut self.flow_vars);
        let saved_slots = std::mem::take(&mut self.flow_slots);
        let saved_shapes = std::mem::take(&mut self.flow_shapes);
        let saved_responses = std::mem::take(&mut self.response_vars);
        // A compiled local stays callable from the nested body.
        let saved_compiled = self.compiled_vars.clone();
        if let Some((_, name, stage, response)) = self
            .callback_seed
            .take_if(|(seeded, _, _, _)| *seeded == body.span.start)
            && self.insert_flow_slot(name.clone())
        {
            if let Some(response) = response {
                self.response_vars.insert(name.clone(), response);
            }
            self.flow_vars.insert(name, stage);
        }
        if let Some((_, captures)) = self
            .callback_captures
            .take_if(|(seeded, _)| *seeded == body.span.start)
        {
            // Names the callback binds itself shadow the enclosing ones.
            for (name, stage, response) in captures {
                let root = name.split('.').next().unwrap_or(&name);
                if active_body.local_names.contains(root) || !self.insert_flow_slot(name.clone()) {
                    continue;
                }
                if let Some(response) = response {
                    self.response_vars.insert(name.clone(), response);
                }
                self.flow_vars.insert(name, stage);
            }
        }
        // A closure reads the bindings of every scope it is written inside:
        // the module's, and those of each active body that contains it. A
        // name a nearer containing body, or this one, declares shadows them.
        self.enclosing_flows.push(
            saved_flow
                .iter()
                .map(|(name, stage)| (name.clone(), *stage, saved_responses.get(name).copied()))
                .collect(),
        );
        let contains = |outer: Span| outer.start <= body.span.start && body.span.end <= outer.end;
        let mut visible = Vec::new();
        for (depth, captures) in self.enclosing_flows.iter().enumerate() {
            if depth > 0 && !contains(self.active_bodies[depth - 1].span) {
                continue;
            }
            for (name, stage, response) in captures {
                let root = name.split('.').next().unwrap_or(name);
                let shadowed = active_body.local_names.contains(root)
                    || self.active_bodies[depth..]
                        .iter()
                        .any(|nearer| contains(nearer.span) && nearer.local_names.contains(root));
                if !shadowed {
                    visible.push((name.clone(), *stage, *response));
                }
            }
        }
        // What each enclosing binding held when the body began, to tell at
        // its end which of them it assigned.
        let mut inherited = HashMap::new();
        for (name, stage, response) in visible {
            if self.flow_vars.contains_key(&name) || !self.insert_flow_slot(name.clone()) {
                continue;
            }
            if let Some(response) = response {
                self.response_vars.insert(name.clone(), response);
            }
            inherited.insert(name.clone(), stage);
            self.flow_vars.insert(name, stage);
        }
        // The body sees the bindings that hold the environment in the
        // scopes it is written inside: not a name it declares itself, nor
        // one a caller it is not written inside declares. Its parameters
        // hold what their arguments did.
        let saved_environment = self.environment_holds.clone();
        for caller in &self.active_bodies {
            if !contains(caller.span) {
                self.environment_holds
                    .retain(|name, _| !caller.local_names.contains(name));
            }
        }
        self.environment_holds
            .retain(|name, _| !active_body.local_names.contains(name));
        if let Some((_, params)) = environment_params {
            self.environment_holds.extend(params);
        }
        self.function_depth += 1;
        self.active_bodies.push(active_body);
        let caller_blocks = std::mem::take(&mut self.block_bindings);
        self.block_bindings = caller_blocks
            .iter()
            .filter(|(block, _)| block.start <= body.span.start && body.span.end <= block.end)
            .cloned()
            .collect();
        self.return_producers.push(Vec::new());
        self.return_source_states.push(Vec::new());
        self.return_source_values.push(Vec::new());
        self.return_aggregate_aliases
            .push(AggregateAliasPaths::new());
        let mut continues = true;
        let caller_depth = std::mem::take(&mut self.statement_depth);
        for stmt in &body.statements {
            self.visit_statement(stmt);
            if statement_stops_sequential_execution(stmt) {
                continues = false;
                break;
            }
        }
        self.statement_depth = caller_depth;
        if continues
            && expression_body
            && let [Statement::ExpressionStatement(statement)] = body.statements.as_slice()
        {
            if !self.environment_result_followed
                && self.has_environment_value(&statement.expression)
            {
                self.unmodeled_dynamic(
                    statement.span,
                    "returned environment shape is not followed",
                );
            }
            let source_value = SourceStringValue {
                resource: source_string_resource(
                    &statement.expression,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                ),
                concatenation: self.is_string_concatenation(&statement.expression),
            };
            self.return_source_values
                .last_mut()
                .unwrap()
                .push(source_value);
            let aggregate_aliases = expression_aggregate_alias_paths(
                self.nest.budget,
                &statement.expression,
                &self.aggregate_aliases,
                &self.evaluated_aggregate_aliases,
            );
            extend_aggregate_alias_paths(
                self.return_aggregate_aliases.last_mut().unwrap(),
                "",
                aggregate_aliases,
            );
            self.retain_return_source_state(body.span);
            let producer = self.init_producer(&statement.expression);
            self.return_producers.last_mut().unwrap().push(producer);
            continues = false;
        }
        let returns = self.return_producers.pop().unwrap();
        let mut source_exits = self.return_source_states.pop().unwrap();
        let mut source_values = self.return_source_values.pop().unwrap();
        let aggregate_return = self.return_aggregate_aliases.pop().unwrap();
        if continues {
            source_exits.push(self.source_string_state());
            source_values.push(SourceStringValue {
                resource: None,
                concatenation: false,
            });
        }
        if let Some(first) = source_exits.first().cloned() {
            self.restore_source_string_state(first);
            for exit in source_exits.into_iter().skip(1) {
                let joined = self.source_string_state();
                self.join_source_string_states(joined, exit, body.span);
            }
        }
        if self.flow_slots_saturated {
            self.flow_vars.clear();
            self.flow_slots.clear();
            self.flow_shapes.clear();
        } else {
            let assigned = std::mem::replace(&mut self.flow_vars, saved_flow);
            self.flow_slots = saved_slots;
            self.flow_shapes = saved_shapes;
            // A binding of an enclosing scope the body assigned holds its
            // new value for the caller (`let key; function load() { key =
            // read() } load()`).
            for (name, stage) in &assigned {
                let root = name.split('.').next().unwrap_or(name);
                if self.caller_shares_binding(root)
                    && inherited.get(name) != Some(stage)
                    && self.insert_flow_slot(name.clone())
                {
                    self.flow_vars.insert(name.clone(), *stage);
                }
            }
            // One it certainly assigned a value that carries nothing no
            // longer holds what it did (`function clear() { key = "ok" }`),
            // where the call certainly ran the body.
            let cleared: Vec<String> = self
                .flow_vars
                .keys()
                .filter(|name| {
                    let root = name.split('.').next().unwrap_or(name);
                    certain
                        && !assigned.contains_key(root)
                        && !assigned.contains_key(*name)
                        && self.caller_shares_binding(root)
                        && printed_environment::assigns_unconditionally(body, root)
                })
                .cloned()
                .collect();
            for name in cleared {
                self.flow_vars.remove(&name);
            }
        }
        self.response_vars = saved_responses;
        // The same holds for an enclosing binding and the environment.
        let held = std::mem::replace(&mut self.environment_holds, saved_environment);
        let names: HashSet<String> = held
            .keys()
            .chain(self.environment_holds.keys())
            .filter(|name| certain && self.caller_shares_binding(name))
            .cloned()
            .collect();
        for name in names {
            match held.get(&name) {
                Some(shape) => self.environment_holds.insert(name, *shape),
                None => self.environment_holds.remove(&name),
            };
        }
        self.compiled_vars = saved_compiled;
        self.enclosing_flows.pop();
        self.active_bodies.pop();
        self.block_bindings = caller_blocks;
        self.restore_bindings_view(switched_scopes);
        self.function_depth -= 1;
        self.visiting.remove(&body.span.start);
        let producer = returns
            .first()
            .copied()
            .flatten()
            .filter(|first| returns.iter().all(|producer| *producer == Some(*first)));
        let source_return = source_values.first().cloned().and_then(|first| {
            if source_values.iter().all(|value| value == &first) {
                Some(first)
            } else if source_values.iter().any(|value| value.concatenation) {
                Some(SourceStringValue {
                    resource: None,
                    concatenation: true,
                })
            } else {
                None
            }
        });
        self.builder.leave_condition_call(previous_call);
        BodyResult {
            producer,
            source_return,
            aggregate_return,
        }
    }
}
