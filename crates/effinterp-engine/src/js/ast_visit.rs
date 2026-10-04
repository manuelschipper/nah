//! The JavaScript effect walk over the syntax tree: what the `EffectVisitor`
//! does at each statement, declaration and expression node it visits.

use std::collections::HashSet;

use effinterp_proto::ResourceExpr;
use oxc_ast::ast::{
    AccessorProperty, Argument, ArrayExpression, ArrayExpressionElement, AssignmentTarget,
    AwaitExpression, BinaryExpression, BindingPattern, BlockStatement, CallExpression, CatchClause,
    ChainExpression, Class, ClassType, ConditionalExpression, DoWhileStatement, Expression,
    ForInStatement, ForOfStatement, ForStatement, FormalParameters, IfStatement, ImportDeclaration,
    ImportExpression, LabeledStatement, LogicalExpression, MethodDefinition, NewExpression,
    ObjectExpression, ObjectProperty, PrivateInExpression, PropertyDefinition, ReturnStatement,
    Statement, StaticBlock, StaticMemberExpression, SwitchStatement, TaggedTemplateExpression,
    TemplateLiteral, ThrowStatement, TryStatement, UnaryExpression, UpdateExpression,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator, WhileStatement,
    WithStatement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

use crate::control_flow::{ControlExit, SiteFacts};

use super::aggregate_alias::{
    AggregateAliasPaths, aggregate_alias_binding_names, clear_aggregate_aliases,
    expression_aggregate_alias_paths, extend_aggregate_alias_paths,
};
use super::bindings::{
    AssignmentTargetBindings, collect_binding_names, collect_scope_binding_names,
    loop_binding_writes,
};
use super::plus_coercion::{plus_coercion_assignment_object, plus_coercion_binding_name};
use super::source_string::{
    AggregateBindingValue, SourceBindingValue, SourceStringValue, append_source_string_parts,
    bind_source_string_pattern, home_directory_value, is_home_directory_call,
    is_string_concatenation, source_expression_key, source_string_resource,
};
use super::source_string_state::callable_env_bytes;
use super::{
    CallableBinding, ConsoleAssignment, EffectVisitor, SequentialStop,
    aggregate_mutation_target_bindings, assignment_flow_key, console_printed_arguments, control,
    expression_flow_key, expression_write_binding_name, is_create_server, literal_property_name,
    literal_truth, logical_call_argument, model, resolve,
    simple_assignment_target_write_binding_name, statement_sequential_stop,
    statement_sequential_stop_in_switch, statement_stops_sequential_execution, unparen,
};

impl<'a> Visit<'a> for EffectVisitor<'_, 'a> {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind.is_using() {
            self.unresolved_call(it.span, "resource disposal or asynchronous cleanup", None);
        }
        walk::walk_variable_declaration(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !self.enter_walk() {
            return;
        }
        let guard = self.bindings.guards.at(effinterp_proto::ByteSpan {
            start: it.span().start,
            end: it.span().end,
        });
        if let Some(guard) = &guard {
            self.builder.push_condition(guard.clone());
        }
        let previous_site =
            std::mem::replace(&mut self.condition_site, (it.span().start, it.span().end));
        walk::walk_expression(self, it);
        self.condition_site = previous_site;
        if guard.is_some() {
            self.builder.pop_condition();
        }
        self.observe_state_budget(it.span());
        if matches!(it, Expression::Identifier(identifier)
            if self.runtime_missing_identifier_spans.contains(&identifier.span.start))
        {
            self.retain_exception_source_state(it.span());
        }
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if !self.enter_walk() {
            return;
        }
        walk::walk_statement(self, it);
        self.observe_state_budget(it.span());
        self.walk_depth -= 1;
    }

    fn visit_array_expression(&mut self, it: &ArrayExpression<'a>) {
        walk::walk_array_expression(self, it);
        if it
            .elements
            .iter()
            .any(|element| matches!(element, ArrayExpressionElement::SpreadElement(_)))
        {
            self.retain_exception_source_state(it.span());
        }
    }

    fn visit_array_expression_element(&mut self, it: &ArrayExpressionElement<'a>) {
        if let Some(expression) = it.as_expression() {
            self.evaluated_source_strings
                .remove(&source_expression_key(expression));
            self.evaluated_aggregate_aliases
                .remove(&source_expression_key(expression));
        }
        walk::walk_array_expression_element(self, it);
        let Some(expression) = it.as_expression() else {
            return;
        };
        let value = SourceStringValue {
            resource: source_string_resource(
                expression,
                &self.source_env,
                &self.unbounded_source_env,
                self.process_runtime,
                &self.evaluated_source_strings,
            ),
            concatenation: self.is_string_concatenation(expression),
        };
        self.evaluated_source_strings
            .insert(source_expression_key(expression), value);
        let aliases = expression_aggregate_alias_paths(
            self.nest.budget,
            expression,
            &self.aggregate_aliases,
            &self.evaluated_aggregate_aliases,
        );
        if !aliases.is_empty() {
            self.evaluated_aggregate_aliases
                .insert(source_expression_key(expression), aliases);
        }
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        self.evaluated_source_strings
            .remove(&source_expression_key(&it.value));
        self.evaluated_aggregate_aliases
            .remove(&source_expression_key(&it.value));
        self.visit_property_key(&it.key);
        if it.computed {
            self.retain_exception_source_state(it.span());
        }
        self.visit_expression(&it.value);
        let value = SourceStringValue {
            resource: source_string_resource(
                &it.value,
                &self.source_env,
                &self.unbounded_source_env,
                self.process_runtime,
                &self.evaluated_source_strings,
            ),
            concatenation: self.is_string_concatenation(&it.value),
        };
        self.evaluated_source_strings
            .insert(source_expression_key(&it.value), value);
        let aliases = expression_aggregate_alias_paths(
            self.nest.budget,
            &it.value,
            &self.aggregate_aliases,
            &self.evaluated_aggregate_aliases,
        );
        if !aliases.is_empty() {
            self.evaluated_aggregate_aliases
                .insert(source_expression_key(&it.value), aliases);
        }
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        walk::walk_object_expression(self, it);
        if it.properties.iter().any(|property| {
            matches!(
                property,
                oxc_ast::ast::ObjectPropertyKind::SpreadProperty(_)
            )
        }) {
            self.retain_exception_source_state(it.span());
        }
    }

    // A function definition does not run its body; the body is analyzed only
    // when a call reaches it (see `visit_call_expression`). Skipping every
    // function body during the default walk is what keeps a never-called
    // function out of the execution plan.
    fn visit_function_body(&mut self, _it: &oxc_ast::ast::FunctionBody<'a>) {}

    fn visit_formal_parameters(&mut self, _it: &FormalParameters<'a>) {}

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        if let Statement::SwitchStatement(statement) = &it.body {
            self.labeled_switches
                .push((statement.span.start, it.label.name.as_str().to_string()));
            walk::walk_labeled_statement(self, it);
            self.labeled_switches.pop();
        } else {
            walk::walk_labeled_statement(self, it);
        }
    }

    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        if !self.charge_state_bytes(callable_env_bytes(&self.callable_env), it.span()) {
            return;
        }
        self.visit_expression(&it.object);
        let source_entry = self.source_string_state();
        let flow_entry = self.flow_entry();
        let mut live_names = source_entry
            .param_env
            .keys()
            .chain(source_entry.source_env.keys())
            .chain(source_entry.unbounded_source_env.iter())
            .chain(source_entry.callable_env.keys())
            .cloned()
            .collect::<HashSet<_>>();
        live_names.insert("String".to_string());
        live_names.insert("undefined".to_string());
        let writes = loop_binding_writes(
            &it.body,
            None,
            None,
            HashSet::new(),
            self.functions,
            &self.callable_env,
        );
        // A with-object may intercept live identifiers and recognized globals.
        // Analyze the body conservatively, then join outer writes with
        // intercepted writes.
        self.mark_source_bindings_unbounded(&live_names);
        self.mark_callable_bindings_unbounded(&live_names);
        let process_runtime = self.process_runtime;
        self.process_runtime = false;
        self.visit_statement(&it.body);
        self.process_runtime = process_runtime;

        let untouched = live_names
            .difference(&writes)
            .cloned()
            .collect::<HashSet<_>>();
        self.restore_source_string_names(&source_entry, &untouched);
        let outer_write = self.source_string_state();
        self.restore_source_string_names(&source_entry, &writes);
        let object_write = self.source_string_state();
        self.join_source_string_states(outer_write, object_write, it.span());
        self.flow_join(flow_entry);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        if it.operator.as_str() != "+" {
            walk::walk_binary_expression(self, it);
            self.retain_exception_source_state(it.span());
            return;
        }
        self.visit_expression(&it.left);
        let left = source_string_resource(
            &it.left,
            &self.source_env,
            &self.unbounded_source_env,
            self.process_runtime,
            &self.evaluated_source_strings,
        );
        self.visit_expression(&it.right);
        let right = source_string_resource(
            &it.right,
            &self.source_env,
            &self.unbounded_source_env,
            self.process_runtime,
            &self.evaluated_source_strings,
        );
        let resource = left.zip(right).map(|(left, right)| {
            let mut parts = Vec::new();
            append_source_string_parts(&mut parts, left);
            append_source_string_parts(&mut parts, right);
            ResourceExpr::Join { parts }
        });
        self.evaluated_source_strings.insert(
            (it.span.start, it.span.end),
            SourceStringValue {
                resource,
                concatenation: true,
            },
        );
        self.follow_plus_coercion_callbacks(&it.left);
        self.follow_plus_coercion_callbacks(&it.right);
        self.retain_exception_source_state(it.span());
    }

    fn visit_private_in_expression(&mut self, it: &PrivateInExpression<'a>) {
        walk::walk_private_in_expression(self, it);
        self.retain_exception_source_state(it.span());
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        if it.expressions.is_empty() {
            walk::walk_template_literal(self, it);
            return;
        }
        let mut parts = Vec::new();
        let mut bounded = true;
        for (index, quasi) in it.quasis.iter().enumerate() {
            match &quasi.value.cooked {
                Some(cooked) if !cooked.is_empty() => parts.push(ResourceExpr::Literal {
                    value: cooked.as_str().to_string(),
                }),
                Some(_) => {}
                None => bounded = false,
            }
            if let Some(expression) = it.expressions.get(index) {
                self.visit_expression(expression);
                match source_string_resource(
                    expression,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                ) {
                    Some(resource) => append_source_string_parts(&mut parts, resource),
                    None => bounded = false,
                }
                self.follow_plus_coercion_callbacks(expression);
                self.retain_exception_source_state(it.span());
            }
        }
        self.evaluated_source_strings.insert(
            (it.span.start, it.span.end),
            SourceStringValue {
                resource: bounded.then_some(ResourceExpr::Join { parts }),
                concatenation: true,
            },
        );
    }

    fn visit_tagged_template_expression(&mut self, it: &TaggedTemplateExpression<'a>) {
        walk::walk_tagged_template_expression(self, it);
        self.retain_exception_source_state(it.span());
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        let scope_entry = self.source_string_state();
        let mut shadowed = HashSet::new();
        for statement in &it.body {
            if let Some(declaration) = statement.as_declaration() {
                collect_scope_binding_names(declaration, false, &mut shadowed);
            }
        }
        self.mark_source_bindings_unbounded(&shadowed);
        // A binding the block declares ends with it and uncovers the outer one.
        let outer_compiled = shadowed
            .iter()
            .map(|name| (name.clone(), self.compiled_vars.get(name).cloned()))
            .collect::<Vec<_>>();
        self.block_bindings.push((it.span, shadowed.clone()));
        for statement in &it.body {
            self.visit_statement(statement);
            if statement_stops_sequential_execution(statement) {
                break;
            }
        }
        self.block_bindings.pop();
        for (name, outer) in outer_compiled {
            match outer {
                Some(compiled) => self.compiled_vars.insert(name, compiled),
                None => self.compiled_vars.remove(&name),
            };
        }
        self.restore_source_string_names(&scope_entry, &shadowed);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        let scope_entry = self.source_string_state();
        let mut shadowed = HashSet::new();
        if it.r#type == ClassType::ClassExpression
            && let Some(id) = &it.id
        {
            shadowed.insert(id.name.as_str().to_string());
        }
        self.mark_source_bindings_unbounded(&shadowed);
        let inherited_plus_coercion = it.super_class.as_ref().and_then(|super_class| {
            self.plus_coercion_binding(super_class, &self.callable_env, &self.aggregate_aliases)
        });
        if let Some(CallableBinding::PlusCoercion(owner_span)) = inherited_plus_coercion {
            self.class_super_plus_coercions
                .insert(it.span.start, owner_span);
        } else {
            self.class_super_plus_coercions.remove(&it.span.start);
        }
        self.instantiable_classes.push(
            !self
                .bindings
                .uninstantiated_classes
                .contains(&it.span.start),
        );
        walk::walk_class(self, it);
        self.instantiable_classes.pop();
        self.restore_source_string_names(&scope_entry, &shadowed);
        if it.r#type == ClassType::ClassDeclaration
            && let Some(id) = &it.id
        {
            let binding = if self.class_has_plus_coercion_callbacks(it.span.start)
                || inherited_plus_coercion.is_some()
            {
                CallableBinding::PlusCoercion(it.span.start)
            } else {
                CallableBinding::Unbounded
            };
            self.callable_env
                .insert(plus_coercion_binding_name(id.name.as_str()), binding);
            self.sync_module_source_strings();
        }
        if it.super_class.is_some() {
            self.retain_exception_source_state(it.span());
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        walk::walk_method_definition(self, it);
        if it.computed {
            self.retain_exception_source_state(it.span());
        }
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        self.visit_decorators(&it.decorators);
        self.visit_property_key(&it.key);
        if it.computed {
            self.retain_exception_source_state(it.span());
        }
        if let Some(type_annotation) = &it.type_annotation {
            self.visit_ts_type_annotation(type_annotation);
        }
        if let Some(value) = &it.value {
            if it.r#static {
                self.visit_expression(value);
            } else if self.instantiable_classes.last() == Some(&true) {
                self.instance_field_initializer(value);
            }
        }
    }

    fn visit_accessor_property(&mut self, it: &AccessorProperty<'a>) {
        self.visit_decorators(&it.decorators);
        self.visit_property_key(&it.key);
        if it.computed {
            self.retain_exception_source_state(it.span());
        }
        if let Some(type_annotation) = &it.type_annotation {
            self.visit_ts_type_annotation(type_annotation);
        }
        if let Some(value) = &it.value {
            if it.r#static {
                self.visit_expression(value);
            } else if self.instantiable_classes.last() == Some(&true) {
                self.instance_field_initializer(value);
            }
        }
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        let scope_entry = self.source_string_state();
        let mut shadowed = HashSet::new();
        for statement in &it.body {
            if let Some(declaration) = statement.as_declaration() {
                collect_scope_binding_names(declaration, true, &mut shadowed);
            }
        }
        self.mark_source_bindings_unbounded(&shadowed);
        walk::walk_static_block(self, it);
        self.restore_source_string_names(&scope_entry, &shadowed);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        self.visit_expression(&it.argument);
        self.retain_exception_source_state(it.span());
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && callee.name.as_str() == "require"
            && !self.bindings.require_shadowed
            && !self
                .active_bodies
                .iter()
                .any(|body| body.local_names.contains("require"))
            && let Some(Argument::StringLiteral(source)) = it.arguments.first()
            && !model::is_node_builtin_module(source.value.as_str())
        {
            self.nest
                .follow_dependency(self.builder, source.value.as_str(), "js");
        }
        if !self.charge(it.span) {
            return;
        }
        let control_since = self.builder.control_registered();
        self.evaluated_source_strings
            .remove(&(it.span.start, it.span.end));
        self.evaluated_aggregate_aliases
            .remove(&(it.span.start, it.span.end));
        let promise_resolve_call =
            expression_flow_key(&it.callee).as_deref() == Some("Promise.resolve");
        let promise_resolve_is_builtin = promise_resolve_call
            && !self.source_env.contains_key("Promise")
            && !self.unbounded_source_env.contains("Promise")
            && !self.source_env.contains_key("Promise.resolve")
            && !self.unbounded_source_env.contains("Promise.resolve");
        let (source_passthrough_argument, source_passthrough_is_exact) =
            if !self.source_env.contains_key("String")
                && !self.unbounded_source_env.contains("String")
                && matches!(unparen(&it.callee), Expression::Identifier(id) if id.name == "String")
            {
                (logical_call_argument(&it.arguments, 0), true)
            } else if promise_resolve_call {
                (
                    logical_call_argument(&it.arguments, 0),
                    promise_resolve_is_builtin,
                )
            } else {
                (None, false)
            };
        // JavaScript evaluates the callee and arguments before entering the
        // called body or performing the modeled operation.
        self.visit_expression(&it.callee);
        if let Some(type_arguments) = &it.type_arguments {
            self.visit_ts_type_parameter_instantiation(type_arguments);
        }
        let mut argument_states = Vec::with_capacity(it.arguments.len());
        for argument in &it.arguments {
            self.visit_argument(argument);
            if matches!(argument, Argument::SpreadElement(_)) {
                self.retain_exception_source_state(it.span());
            }
            argument_states.push(self.source_string_state());
        }
        if let Some((Some(argument), syntax_index)) = source_passthrough_argument
            && let Some(state) = argument_states.get(syntax_index)
        {
            self.evaluated_source_strings.insert(
                (it.span.start, it.span.end),
                SourceStringValue {
                    // A replaced Promise.resolve is not a value passthrough,
                    // but its concatenated argument still marks the unknown
                    // result so a consuming sink emits a dynamic boundary.
                    resource: if source_passthrough_is_exact {
                        source_string_resource(
                            argument,
                            &state.source_env,
                            &state.unbounded_source_env,
                            self.process_runtime,
                            &self.evaluated_source_strings,
                        )
                    } else {
                        None
                    },
                    concatenation: is_string_concatenation(
                        argument,
                        &state.source_env,
                        &self.evaluated_source_strings,
                    ),
                },
            );
        }
        if is_home_directory_call(it, self.bindings) {
            self.evaluated_source_strings
                .insert((it.span.start, it.span.end), home_directory_value(it));
        }
        // Snapshot the effects this call produces itself (before following into
        // reachable bodies) so they form this call's flow stage.
        // A bare `process.env` argument hands the whole environment to the
        // callee — an environment read with no single name.
        let assigns_process_env = model::object_assigns_process_env(it);
        for (index, arg) in it.arguments.iter().enumerate() {
            if let Some(expr) = arg.as_expression()
                && resolve::is_process_env(expr)
                && !(assigns_process_env && index == 0)
            {
                if self.process_runtime {
                    self.whole_env_read(it.span);
                } else {
                    self.unsupported_process_receiver(it.span);
                }
            }
        }
        let before = self.builder.effects_len();
        // Any call can throw after its arguments have been evaluated, including
        // a call whose target cannot be resolved by the frontend.
        self.retain_exception_source_state(it.span());
        self.model_call(it, &argument_states);
        let after = self.builder.effects_len();
        let stage = self.new_stage(it.span, before, after);
        // Calling a function compiled from code runs that code. Its own
        // stage keeps the call's arguments, which are data, off the code.
        let compiled = match self.compiled_code(&it.callee) {
            Some(code) => Some(self.code_producers(code)),
            None => self.compiled_local(&it.callee),
        };
        if let Some(producers) = compiled {
            let before = self.builder.effects_len();
            self.code_execution(it.span);
            let node = self.span_node(it.span);
            if let Some(run) = self
                .stage_writer
                .new_stage(node, before, self.builder.effects_len())
            {
                for producer in producers {
                    self.stage_writer.add_edge(producer, run, 0);
                }
            }
        }
        let applications = std::mem::take(&mut self.control_applications);
        let reached = self.follow_reachable(it, &argument_states);
        let applied = std::mem::replace(&mut self.control_applications, applications);
        let facts = self.call_control(it, reached, applied, before..after);
        self.builder.control_site_since(
            self.control_source,
            false,
            control::span(it.span),
            control_since,
            facts,
        );
        let mutation_targets = aggregate_mutation_target_bindings(it);
        self.mark_source_binding_writes_unbounded(&mutation_targets);
        if let Some(c) = stage {
            self.wire_arguments(&it.arguments, c);
        } else if self.prints_to_stdout(&it.callee) {
            let mut producers = Vec::new();
            for argument in console_printed_arguments(&it.arguments) {
                self.collect_producers(argument, &mut producers);
            }
            if !producers.is_empty() {
                let node = self.span_node(it.span);
                let execution = self.builder.current_execution();
                self.stage_writer
                    .print_to_stdout(node, execution, &producers);
            }
        }
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let loads =
            !it.import_kind.is_type() && !model::is_node_builtin_module(it.source.value.as_str());
        if loads {
            self.nest
                .follow_dependency(self.builder, it.source.value.as_str(), "js");
        }
        let mut facts = SiteFacts::known(Vec::new());
        if loads {
            facts.exit = Some(ControlExit::Import {
                module: it.source.value.to_string(),
            });
        }
        self.builder
            .control_site(self.control_source, false, control::span(it.span), facts);
        walk::walk_import_declaration(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if let Expression::StringLiteral(source) = &it.source
            && !model::is_node_builtin_module(source.value.as_str())
        {
            self.nest
                .follow_dependency(self.builder, source.value.as_str(), "js");
        }
        if !self
            .bindings
            .dynamic_imports
            .is_literal_import(it.span.start)
        {
            self.opaque(it.span, "dynamic import target");
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        let function_constructor = resolve::is_function_constructor(it)
            && !self.bindings.dynamic_imports.is_transparent_constructor(it);
        if function_constructor {
            self.opaque(it.span, "Function");
        }
        walk::walk_new_expression(self, it);
        // Built-in value constructors run no user code; anything else may.
        if let Expression::Identifier(class) = unparen(&it.callee)
            && matches!(
                class.name.as_str(),
                "Map"
                    | "Set"
                    | "WeakMap"
                    | "WeakSet"
                    | "Array"
                    | "Object"
                    | "Error"
                    | "TypeError"
                    | "RangeError"
                    | "URL"
                    | "URLSearchParams"
                    | "Date"
                    | "RegExp"
                    | "Uint8Array"
                    | "ArrayBuffer"
                    | "TextEncoder"
                    | "TextDecoder"
                    | "AbortController"
            )
            && !self.bindings.declared.contains(class.name.as_str())
            && !self
                .active_bodies
                .iter()
                .any(|body| body.local_names.contains(class.name.as_str()))
        {
            self.builder.control_site(
                self.control_source,
                false,
                control::span(it.span),
                SiteFacts::known(Vec::new()),
            );
        }
        self.retain_exception_source_state(it.span());
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        // `process.env.X` read (writes are handled on the assignment target
        // and excluded here).
        let before = self.builder.effects_len();
        if self.charge(it.span)
            && let Some(name) = resolve::process_env_name(it)
            && !self.env_write_spans.contains(&it.span.start)
        {
            if self.process_runtime {
                self.env_effect("environment.read", &name, false, it.span);
            } else {
                self.unsupported_process_receiver(it.span);
            }
        }
        let after = self.builder.effects_len();
        self.new_stage(it.span, before, after);
        walk::walk_static_member_expression(self, it);
        self.retain_exception_source_state(it.span());
    }

    fn visit_computed_member_expression(
        &mut self,
        it: &oxc_ast::ast::ComputedMemberExpression<'a>,
    ) {
        let before = self.builder.effects_len();
        if self.charge(it.span)
            && resolve::is_process_env(&it.object)
            && !self.env_write_spans.contains(&it.span.start)
        {
            if self.process_runtime {
                if let Some(name) = literal_property_name(&it.expression) {
                    self.env_effect("environment.read", &name, false, it.span);
                } else {
                    self.unknown_env_effect("environment.read", false, it.span);
                }
            } else {
                self.unsupported_process_receiver(it.span);
            }
        }
        let after = self.builder.effects_len();
        self.new_stage(it.span, before, after);
        walk::walk_computed_member_expression(self, it);
        self.retain_exception_source_state(it.span());
    }

    fn visit_chain_expression(&mut self, it: &ChainExpression<'a>) {
        // An optional link whose base is null or undefined short-circuits the
        // whole chain: nothing to its right runs, so keys, call arguments, and
        // the call itself are never evaluated.
        if let Some(base) = self.short_circuited_chain_base(&it.expression) {
            self.visit_expression(base);
            return;
        }
        walk::walk_chain_expression(self, it);
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if let AssignmentTarget::StaticMemberExpression(m) = it
            && let Some(name) = resolve::process_env_name(m)
        {
            if self.process_runtime {
                self.env_effect("environment.write", &name, false, m.span);
            } else {
                self.unsupported_process_receiver(m.span);
            }
        }
        if let AssignmentTarget::ComputedMemberExpression(m) = it
            && resolve::is_process_env(&m.object)
        {
            if self.process_runtime {
                if let Some(name) = literal_property_name(&m.expression) {
                    self.env_effect("environment.write", &name, false, m.span);
                } else {
                    self.unknown_env_effect("environment.write", false, m.span);
                }
            } else {
                self.unsupported_process_receiver(m.span);
            }
        }
        walk::walk_assignment_target(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        // Track a simple `const/let/var name = value` so a resource returned by
        // a local helper (or a literal path) flows to later uses of the name.
        // Any other binding shape drops stale tracking for its name.
        if !matches!(
            (&it.id, &it.init),
            (BindingPattern::BindingIdentifier(_), Some(_))
        ) {
            let mut names = HashSet::new();
            collect_binding_names(&it.id, &mut names);
            self.mark_source_bindings_unbounded(&names);
            self.mark_callable_bindings_unbounded(&names);
        }
        let init_source_state = it.init.as_ref().map(|init| {
            self.visit_expression(init);
            let state = self.source_string_state();
            // The right-hand side is complete before computed keys and
            // selected defaults execute during destructuring.
            self.visit_binding_pattern_defaults(&it.id, SourceBindingValue::Local(init));
            state
        });
        if it.init.is_none() {
            self.visit_binding_pattern_defaults(&it.id, SourceBindingValue::Unbounded);
        }
        match (&it.id, &it.init) {
            (BindingPattern::BindingIdentifier(alias), Some(init)) => {
                let prints = self.is_console_printer(init);
                self.bind_console_printer(alias.span.start, prints);
            }
            (BindingPattern::ObjectPattern(pattern), Some(init))
                if self.bindings.console.is_console(init) =>
            {
                for property in &pattern.properties {
                    if let BindingPattern::BindingIdentifier(alias) = &property.value {
                        let prints = property
                            .key
                            .static_name()
                            .is_some_and(|method| self.console_method_prints(&method));
                        self.bind_console_printer(alias.span.start, prints);
                    }
                }
            }
            _ => {}
        }
        let mut declared_names = HashSet::new();
        collect_binding_names(&it.id, &mut declared_names);
        for name in &declared_names {
            self.object_literal_vars.remove(name);
        }
        if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init)
            && let Some(object) =
                model::object_literal_resolving(init, &self.object_literal_vars, &|value| {
                    self.expr_to_word(value).as_literal().map(str::to_string)
                })
        {
            self.object_literal_vars
                .insert(id.name.as_str().to_string(), object);
        }
        self.sync_module_object_literals();
        if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init) {
            // Install the binding only after evaluating the initializer so
            // mutations in an earlier operand are visible to later operands.
            if is_create_server(unparen(init)) {
                self.server_vars.insert(id.name.as_str().to_string());
            } else {
                self.server_vars.remove(id.name.as_str());
            }
            match self.tracked_value(init) {
                Some(res) => {
                    self.param_env.insert(id.name.as_str().to_string(), res);
                }
                None => {
                    self.param_env.remove(id.name.as_str());
                }
            }
            match self.tracked_cwd_value(init) {
                Some(resource) => {
                    self.cwd_param_env
                        .insert(id.name.as_str().to_string(), resource);
                }
                None => {
                    self.cwd_param_env.remove(id.name.as_str());
                }
            }
            let name = id.name.as_str().to_string();
            let resource = source_string_resource(
                init,
                &self.source_env,
                &self.unbounded_source_env,
                self.process_runtime,
                &self.evaluated_source_strings,
            );
            self.track_source_string(name.clone(), resource, self.is_string_concatenation(init));
            self.track_aggregate_source_strings(&name, init);
            self.track_callable_declarator(&name, init, it.span.end);
            self.track_plus_coercion_binding(&name, init);
            self.track_aggregate_alias(&name, init);
            self.track_definitely_nullish(&name, self.expression_is_definitely_nullish(init));
        } else if let (BindingPattern::BindingIdentifier(id), None) = (&it.id, &it.init)
            && it.kind != VariableDeclarationKind::Var
        {
            self.track_definitely_nullish(id.name.as_str(), true);
        } else if !matches!(&it.id, BindingPattern::BindingIdentifier(_))
            && let Some(init) = &it.init
        {
            let init_source_state = init_source_state.as_ref().unwrap();
            bind_source_string_pattern(
                &it.id,
                SourceBindingValue::Argument(init),
                &init_source_state.source_env,
                &init_source_state.unbounded_source_env,
                &mut self.source_env,
                &mut self.unbounded_source_env,
                self.process_runtime,
                self.process_runtime,
                &self.evaluated_source_strings,
            );
            self.bind_aggregate_alias_pattern(
                &it.id,
                AggregateBindingValue::Argument(init),
                &init_source_state.source_env,
                &init_source_state.unbounded_source_env,
                &init_source_state.aggregate_aliases,
            );
            self.sync_module_source_strings();
        }
        // Dataflow bindings are installed after walking the initializer, when
        // every producer call in it has a stage. Patterns project only the
        // exact array element or object property they bind.
        if let Some(init) = &it.init {
            self.bind_flow_pattern(&it.id, init);
        }
        if matches!(
            &it.id,
            BindingPattern::ArrayPattern(_) | BindingPattern::ObjectPattern(_)
        ) {
            self.retain_exception_source_state(it.span());
        }
    }

    fn visit_assignment_expression(&mut self, it: &oxc_ast::ast::AssignmentExpression<'a>) {
        // A plain `name = value` reassignment drops any tracked producer for the
        // name unless the new value is itself a producer call (linked after the
        // walk below records its stage).
        // Logical assignment may skip its RHS, so retain the state after
        // evaluating the target as the alternate branch.
        let mut destructuring_source_state = None;
        let logical_entry = if it.operator.is_logical() {
            self.visit_assignment_target(&it.left);
            let entry = self.source_string_state();
            self.visit_expression(&it.right);
            Some(entry)
        } else if matches!(
            &it.left,
            AssignmentTarget::ArrayAssignmentTarget(_)
                | AssignmentTarget::ObjectAssignmentTarget(_)
        ) {
            // Destructuring evaluates its right-hand side before computed keys
            // and only evaluates defaults selected by the projected value.
            self.visit_expression(&it.right);
            destructuring_source_state = Some(self.source_string_state());
            self.visit_assignment_target_defaults(&it.left, SourceBindingValue::Local(&it.right));
            None
        } else {
            walk::walk_assignment_expression(self, it);
            None
        };
        let logical_aliases = it.operator.is_logical().then(|| {
            expression_aggregate_alias_paths(
                self.nest.budget,
                &it.right,
                &self.aggregate_aliases,
                &self.evaluated_aggregate_aliases,
            )
        });
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left {
            let name = id.name.as_str().to_string();
            self.object_literal_vars.remove(&name);
            self.sync_module_object_literals();
            if it.operator.is_assign() {
                let tracked_value = self.tracked_value(&it.right);
                let resource = source_string_resource(
                    &it.right,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                );
                let concatenation = self.is_string_concatenation(&it.right);
                clear_aggregate_aliases(
                    &mut self.aggregate_aliases,
                    &HashSet::from([name.clone()]),
                );
                self.mark_source_binding_writes_unbounded(&HashSet::from([name.clone()]));
                match tracked_value {
                    Some(resource) => {
                        self.param_env.insert(name.clone(), resource);
                    }
                    None => {
                        self.param_env.remove(&name);
                    }
                }
                self.track_source_string(name.clone(), resource, concatenation);
                self.track_aggregate_source_strings(&name, &it.right);
                self.track_callable_assignment(&name, &it.right, it.span.start);
                self.track_plus_coercion_binding(&name, &it.right);
                self.track_aggregate_alias(&name, &it.right);
                self.track_definitely_nullish(
                    &name,
                    self.expression_is_definitely_nullish(&it.right),
                );
            } else {
                clear_aggregate_aliases(
                    &mut self.aggregate_aliases,
                    &HashSet::from([name.clone()]),
                );
                self.mark_source_binding_writes_unbounded(&HashSet::from([name.clone()]));
                self.param_env.remove(&name);
                self.track_source_string(
                    name.clone(),
                    None,
                    it.operator.as_str() == "+="
                        || it.operator.is_logical() && self.is_string_concatenation(&it.right),
                );
                self.definitely_nullish_env.remove(&name);
                if let Some(paths) = &logical_aliases {
                    self.insert_aggregate_alias_paths(&name, paths.clone());
                }
                self.mark_callable_binding_unbounded(name);
            }
        } else {
            let mut bindings = AssignmentTargetBindings::default();
            bindings.visit_assignment_target(&it.left);
            for name in &bindings.names {
                self.object_literal_vars.remove(name);
            }
            self.sync_module_object_literals();
            self.mark_source_binding_writes_unbounded(&bindings.names);
            self.mark_callable_bindings_unbounded(&bindings.names);
            if let Some(name) = assignment_flow_key(&it.left) {
                if it.operator.is_assign() {
                    self.track_aggregate_alias(&name, &it.right);
                } else if let Some(paths) = &logical_aliases {
                    clear_aggregate_aliases(
                        &mut self.aggregate_aliases,
                        &HashSet::from([name.clone()]),
                    );
                    self.insert_aggregate_alias_paths(&name, paths.clone());
                }
            }
        }
        if it.operator.is_assign()
            && let Some(name) = plus_coercion_assignment_object(&it.left)
        {
            let binding = if self.plus_coercion_callbacks.contains_key(&it.span.start) {
                CallableBinding::PlusCoercion(it.span.start)
            } else {
                CallableBinding::Unbounded
            };
            let mut names = aggregate_alias_binding_names(
                self.nest.budget,
                &self.aggregate_aliases,
                &HashSet::from([name.clone()]),
            );
            if let Some(constructor) = name.strip_suffix(".prototype") {
                names.extend(aggregate_alias_binding_names(
                    self.nest.budget,
                    &self.aggregate_aliases,
                    &HashSet::from([constructor.to_string()]),
                ));
            }
            for name in names {
                self.callable_env
                    .insert(plus_coercion_binding_name(&name), binding);
            }
            self.sync_module_source_strings();
        }
        if let Some(state) = &destructuring_source_state {
            self.bind_assignment_aggregate_alias(
                &it.left,
                AggregateBindingValue::Argument(&it.right),
                &state.source_env,
                &state.unbounded_source_env,
                &state.aggregate_aliases,
            );
            self.sync_module_source_strings();
        }
        if let Some(entry) = logical_entry {
            let assigned = self.source_string_state();
            self.join_source_string_states(entry, assigned, it.span());
        }
        if let Some(name) = assignment_flow_key(&it.left) {
            self.bind_flow_name(&name, &it.right);
        } else if let AssignmentTarget::ComputedMemberExpression(member) = &it.left
            && let Some(base) = expression_flow_key(&member.object)
        {
            self.kill_flow_name(&base);
        }
        // `a &&= v` replaces a function as `a = v` does, and makes nothing
        // else print; `||=` and `??=` keep a function.
        let replaces = matches!(
            it.operator,
            oxc_ast::ast::AssignmentOperator::Assign | oxc_ast::ast::AssignmentOperator::LogicalAnd
        );
        if let Some(member) = it.left.as_member_expression() {
            let silences = replaces && self.is_silent(&it.right);
            self.note_console_assignment(member, silences);
        } else if let AssignmentTarget::AssignmentTargetIdentifier(alias) = &it.left
            && let Some(symbol) = self.bindings.console.references.get(&alias.span.start)
        {
            let prints = self.is_console_printer(&it.right);
            if prints || replaces {
                self.note_console_binding_write(*symbol, prints);
            }
        }
        self.retain_exception_source_state(it.span());
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        walk::walk_update_expression(self, it);
        if let Some(name) = simple_assignment_target_write_binding_name(&it.argument) {
            let names = HashSet::from([name.clone()]);
            self.object_literal_vars.remove(&name);
            self.sync_module_object_literals();
            self.mark_source_binding_writes_unbounded(&names);
            self.mark_callable_bindings_unbounded(&names);
            self.kill_flow_name(&name);
        }
        self.retain_exception_source_state(it.span());
    }

    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        walk::walk_await_expression(self, it);
        self.retain_exception_source_state(it.span());
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'a>) {
        // Code Nah does not follow may rewrite any method of a console that
        // escapes as a value.
        if self.bindings.console.escapes.contains(&it.span.start) {
            self.console_assignments.push(ConsoleAssignment {
                method: None,
                silences: false,
                condition: self.builder.current_condition(),
                regions: self.exception_regions.clone(),
            });
        }
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        if !it.operator.is_typeof() || !matches!(unparen(&it.argument), Expression::Identifier(_)) {
            walk::walk_unary_expression(self, it);
        }
        if it.operator.as_str() == "delete" {
            if let Some(member) = unparen(&it.argument).as_member_expression() {
                self.note_console_assignment(member, true);
            }
            match unparen(&it.argument) {
                Expression::StaticMemberExpression(member) => {
                    if let Some(name) = resolve::process_env_name(member) {
                        if self.process_runtime {
                            self.env_effect("environment.write", &name, true, it.span);
                        } else {
                            self.unsupported_process_receiver(it.span);
                        }
                    }
                }
                Expression::ComputedMemberExpression(member)
                    if resolve::is_process_env(&member.object) =>
                {
                    if self.process_runtime {
                        if let Some(name) = literal_property_name(&member.expression) {
                            self.env_effect("environment.write", &name, true, it.span);
                        } else {
                            self.unknown_env_effect("environment.write", true, it.span);
                        }
                    } else {
                        self.unsupported_process_receiver(it.span);
                    }
                }
                _ => {}
            }
        }
        if it.operator.as_str() == "delete"
            && let Some(name) = expression_write_binding_name(&it.argument)
        {
            let names = HashSet::from([name.clone()]);
            self.mark_source_binding_writes_unbounded(&names);
            self.mark_callable_bindings_unbounded(&names);
            self.kill_flow_name(&name);
        }
        if !it.operator.is_typeof() {
            self.retain_exception_source_state(it.span());
        }
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        walk::walk_return_statement(self, it);
        let source_value = it.argument.as_ref().map_or(
            SourceStringValue {
                resource: None,
                concatenation: false,
            },
            |argument| SourceStringValue {
                resource: source_string_resource(
                    argument,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                ),
                concatenation: self.is_string_concatenation(argument),
            },
        );
        if let Some(values) = self.return_source_values.last_mut() {
            values.push(source_value);
        }
        let aggregate_aliases =
            it.argument
                .as_ref()
                .map_or_else(AggregateAliasPaths::new, |argument| {
                    expression_aggregate_alias_paths(
                        self.nest.budget,
                        argument,
                        &self.aggregate_aliases,
                        &self.evaluated_aggregate_aliases,
                    )
                });
        if let Some(aliases) = self.return_aggregate_aliases.last_mut() {
            extend_aggregate_alias_paths(aliases, "", aggregate_aliases);
        }
        self.retain_return_source_state(it.span());
        let producer = it
            .argument
            .as_ref()
            .and_then(|argument| self.init_producer(argument));
        if let Some(returns) = self.return_producers.last_mut() {
            returns.push(producer);
        }
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.visit_expression(&it.left);
        let branch_entry = self.source_string_state();

        self.visit_expression(&it.right);

        let right = self.source_string_state();
        self.join_source_string_states(branch_entry, right, it.span());
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.visit_expression(&it.test);
        let branch_entry = self.source_string_state();

        self.visit_expression(&it.consequent);

        let consequent = self.source_string_state();
        self.restore_source_string_state(branch_entry);

        self.visit_expression(&it.alternate);

        let alternate = self.source_string_state();
        self.join_source_string_states(consequent, alternate, it.span());
    }

    // Conditionally-executed constructs isolate their def-use bindings: a
    // variable assigned inside a branch or loop body has no single unambiguous
    // producer at the join (the block may not have run, or a sibling branch may
    // assign it differently), so its tracking is dropped there. Within-block
    // producer→consumer edges still form during the walk.
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if let Some(taken) = literal_truth(&it.test) {
            self.visit_expression(&it.test);
            if taken {
                self.visit_statement(&it.consequent);
            } else if let Some(alternate) = &it.alternate {
                self.visit_statement(alternate);
            }
            return;
        }
        let flow_entry = self.flow_entry();
        self.visit_expression(&it.test);
        let branch_entry = self.source_string_state();

        self.visit_statement(&it.consequent);

        let consequent = self.source_string_state();
        let consequent_stops = statement_sequential_stop(&it.consequent).is_some();
        self.restore_source_string_state(branch_entry.clone());
        let alternate_stops = if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);

            statement_sequential_stop(alternate).is_some()
        } else {
            false
        };
        let alternate = self.source_string_state();
        match (consequent_stops, alternate_stops) {
            (true, false) => self.restore_source_string_state(alternate),
            (false, true) => self.restore_source_string_state(consequent),
            _ => self.join_source_string_states(consequent, alternate, it.span()),
        }
        self.flow_join(flow_entry);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if !self.charge_state_bytes(callable_env_bytes(&self.callable_env), it.span()) {
            return;
        }
        let source_entry = self.source_string_state();
        let mut lexical_names = HashSet::new();
        if let Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(declaration)) = &it.init
            && declaration.kind != VariableDeclarationKind::Var
        {
            for declarator in &declaration.declarations {
                collect_binding_names(&declarator.id, &mut lexical_names);
            }
        }
        let entry = self.flow_entry();
        self.mark_source_bindings_unbounded(&lexical_names);
        self.mark_callable_bindings_unbounded(&lexical_names);
        if let Some(init) = &it.init {
            self.visit_for_statement_init(init);
        }
        let loop_writes = loop_binding_writes(
            &it.body,
            it.test.as_ref(),
            it.update.as_ref(),
            lexical_names.clone(),
            self.functions,
            &self.callable_env,
        );
        self.mark_source_binding_writes_unbounded(&loop_writes);
        self.mark_callable_bindings_unbounded(&loop_writes);
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }

        self.visit_statement(&it.body);

        if let Some(update) = &it.update {
            self.visit_expression(update);
        }
        self.restore_source_string_names(&source_entry, &lexical_names);
        let source_exit = self.source_string_state();
        self.join_source_string_states(source_entry, source_exit, it.span());
        self.flow_join(entry);
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        if !self.charge_state_bytes(callable_env_bytes(&self.callable_env), it.span()) {
            return;
        }
        let source_entry = self.source_string_state();
        let lexical_names = self.for_statement_left_lexical_names(&it.left);
        let assignment_names = self.for_statement_left_assignment_names(&it.left);
        let entry = self.flow_entry();
        self.mark_source_bindings_unbounded(&lexical_names);
        self.mark_callable_bindings_unbounded(&lexical_names);

        self.visit_expression(&it.right);

        self.retain_exception_source_state(it.span());
        self.mark_source_binding_writes_unbounded(&assignment_names);
        self.mark_callable_bindings_unbounded(&assignment_names);
        let loop_writes = loop_binding_writes(
            &it.body,
            None,
            None,
            lexical_names.clone(),
            self.functions,
            &self.callable_env,
        );
        self.mark_source_binding_writes_unbounded(&loop_writes);
        self.mark_callable_bindings_unbounded(&loop_writes);
        self.visit_for_statement_left(&it.left);

        self.visit_statement(&it.body);

        self.restore_source_string_names(&source_entry, &lexical_names);
        let source_exit = self.source_string_state();
        self.join_source_string_states(source_entry, source_exit, it.span());
        self.flow_join(entry);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        if !self.charge_state_bytes(callable_env_bytes(&self.callable_env), it.span()) {
            return;
        }
        let source_entry = self.source_string_state();
        let lexical_names = self.for_statement_left_lexical_names(&it.left);
        let assignment_names = self.for_statement_left_assignment_names(&it.left);
        let entry = self.flow_entry();
        self.mark_source_bindings_unbounded(&lexical_names);
        self.mark_callable_bindings_unbounded(&lexical_names);

        self.visit_expression(&it.right);

        self.retain_exception_source_state(it.span());
        self.mark_source_binding_writes_unbounded(&assignment_names);
        self.mark_callable_bindings_unbounded(&assignment_names);
        let loop_writes = loop_binding_writes(
            &it.body,
            None,
            None,
            lexical_names.clone(),
            self.functions,
            &self.callable_env,
        );
        self.mark_source_binding_writes_unbounded(&loop_writes);
        self.mark_callable_bindings_unbounded(&loop_writes);
        self.visit_for_statement_left(&it.left);

        self.visit_statement(&it.body);

        self.restore_source_string_names(&source_entry, &lexical_names);
        let source_exit = self.source_string_state();
        self.join_source_string_states(source_entry, source_exit, it.span());
        self.flow_join(entry);
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        let source_entry = self.source_string_state();
        let mut bound_names = HashSet::new();
        if let Some(param) = &it.param {
            collect_binding_names(&param.pattern, &mut bound_names);
        }
        self.mark_source_bindings_unbounded(&bound_names);
        walk::walk_catch_clause(self, it);
        self.restore_source_string_names(&source_entry, &bound_names);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        if !self.charge_state_bytes(callable_env_bytes(&self.callable_env), it.span()) {
            return;
        }
        let source_entry = self.source_string_state();
        let entry = self.flow_entry();
        let loop_writes = loop_binding_writes(
            &it.body,
            Some(&it.test),
            None,
            HashSet::new(),
            self.functions,
            &self.callable_env,
        );
        self.mark_source_binding_writes_unbounded(&loop_writes);
        self.mark_callable_bindings_unbounded(&loop_writes);
        self.visit_expression(&it.test);

        self.visit_statement(&it.body);

        let source_exit = self.source_string_state();
        self.join_source_string_states(source_entry, source_exit, it.span());
        self.flow_join(entry);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        if !self.charge_state_bytes(callable_env_bytes(&self.callable_env), it.span()) {
            return;
        }
        let source_entry = self.source_string_state();
        let entry = self.flow_entry();
        let loop_writes = loop_binding_writes(
            &it.body,
            Some(&it.test),
            None,
            HashSet::new(),
            self.functions,
            &self.callable_env,
        );
        self.mark_source_binding_writes_unbounded(&loop_writes);
        self.mark_callable_bindings_unbounded(&loop_writes);

        self.visit_statement(&it.body);

        self.visit_expression(&it.test);
        let source_exit = self.source_string_state();
        self.join_source_string_states(source_entry, source_exit, it.span());
        self.flow_join(entry);
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        let switch_label = self
            .labeled_switches
            .last()
            .filter(|(span, _)| *span == it.span.start)
            .map(|(_, label)| label.clone());
        let scope_entry = self.source_string_state();
        let mut lexical_names = HashSet::new();
        for case in &it.cases {
            for statement in &case.consequent {
                if let Some(declaration) = statement.as_declaration() {
                    collect_scope_binding_names(declaration, false, &mut lexical_names);
                }
            }
        }
        let entry = self.flow_entry();
        self.visit_expression(&it.discriminant);
        self.mark_source_bindings_unbounded(&lexical_names);
        let switch_entry = self.source_string_state();
        let mut matched_entries = Vec::with_capacity(it.cases.len());
        for case in &it.cases {
            if let Some(test) = &case.test {
                self.visit_expression(test);
                matched_entries.push(Some(self.source_string_state()));
            } else {
                matched_entries.push(None);
            }
        }
        let unmatched = self.source_string_state();
        let mut fallthrough = None;
        let mut exits = Vec::new();
        for (case, matched) in it.cases.iter().zip(matched_entries) {
            let matched = matched.unwrap_or_else(|| unmatched.clone());
            self.restore_source_string_state(matched.clone());
            if let Some(previous) = fallthrough {
                self.join_source_string_states(previous, matched, it.span());
            }
            let mut stop = None;
            for statement in &case.consequent {
                self.visit_statement(statement);
                if let Some(statement_stop) =
                    statement_sequential_stop_in_switch(statement, switch_label.as_deref())
                {
                    stop = Some(statement_stop);
                    break;
                }
            }
            let case_exit = self.source_string_state();
            match stop {
                None => {
                    fallthrough = Some(case_exit);
                }
                Some(SequentialStop::SwitchBreak) => {
                    fallthrough = None;
                    exits.push(case_exit);
                }
                Some(SequentialStop::Abrupt) => {
                    fallthrough = None;
                }
            }
        }
        if let Some(fallthrough) = fallthrough {
            exits.push(fallthrough);
        }
        if !it.cases.iter().any(|case| case.test.is_none()) {
            exits.push(unmatched);
        }
        let mut exits = exits.into_iter();
        if let Some(first) = exits.next() {
            self.restore_source_string_state(first);
            for exit in exits {
                let joined = self.source_string_state();
                self.join_source_string_states(joined, exit, it.span());
            }
        } else {
            self.restore_source_string_state(switch_entry);
        }
        self.restore_source_string_names(&scope_entry, &lexical_names);
        self.flow_join(entry);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        let source_entry = self.source_string_state();
        let return_state_start = self
            .return_source_states
            .last()
            .map_or(0, std::vec::Vec::len);
        let entry = self.flow_entry();
        self.exception_source_states.push(Vec::new());
        self.exception_regions.push(it.block.span.start);
        self.visit_block_statement(&it.block);
        self.exception_regions.pop();
        let exception_states = self.exception_source_states.pop().unwrap();
        let try_exit = self.source_string_state();
        let mut catch_exception_states = Vec::new();
        if let Some(handler) = &it.handler {
            self.join_source_string_states(source_entry, try_exit.clone(), it.span());
            for exception_state in &exception_states {
                let handler_entry = self.source_string_state();
                self.join_source_string_states(handler_entry, exception_state.clone(), it.span());
            }
            if it.finalizer.is_some() {
                self.exception_source_states.push(Vec::new());
            }
            self.exception_regions.push(handler.span.start);
            self.visit_catch_clause(handler);
            self.exception_regions.pop();
            if it.finalizer.is_some() {
                catch_exception_states = self.exception_source_states.pop().unwrap();
            }
            let catch_exit = self.source_string_state();
            self.join_source_string_states(try_exit, catch_exit, it.span());
            for exception_state in &catch_exception_states {
                let finalizer_entry = self.source_string_state();
                self.join_source_string_states(finalizer_entry, exception_state.clone(), it.span());
            }
        } else if it.finalizer.is_some() {
            self.join_source_string_states(source_entry, try_exit, it.span());
            for exception_state in &exception_states {
                let finalizer_entry = self.source_string_state();
                self.join_source_string_states(finalizer_entry, exception_state.clone(), it.span());
            }
        }
        let pending_return_states = if it.finalizer.is_some() {
            self.return_source_states
                .last_mut()
                .map(|states| states.split_off(return_state_start))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for return_state in &pending_return_states {
            let finalizer_entry = self.source_string_state();
            self.join_source_string_states(finalizer_entry, return_state.clone(), it.span());
        }
        if let Some(finalizer) = &it.finalizer {
            self.visit_block_statement(finalizer);
            let finalizer_stops = finalizer
                .body
                .iter()
                .any(statement_stops_sequential_execution);
            if !pending_return_states.is_empty() && !finalizer_stops {
                self.retain_return_source_state(it.span());
            }
        }
        if (it.handler.is_none() && !exception_states.is_empty())
            || !catch_exception_states.is_empty()
        {
            self.retain_exception_source_state(it.span());
        }
        self.flow_join(entry);
    }
}
