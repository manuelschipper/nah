//! Plus coercion: the `valueOf`, `toString` and `Symbol.toPrimitive`
//! callbacks an object may run when it is coerced. Tracks which bindings hold
//! such an object and follows their callbacks.

use std::collections::HashSet;

use oxc_ast::ast::{AssignmentTarget, BindingPattern, Class, Expression, PropertyKey};

use super::aggregate_alias::{aggregate_alias_binding_names, expression_aggregate_alias_paths};
use super::resolve::ParamEnv;
use super::source_string::{
    AggregateBindingValue, SourceBindingValue, project_array_aggregate_binding,
    project_object_aggregate_binding,
};
use super::source_string_state::SourceStringState;
use super::{
    AggregateAliases, CallableBinding, CallableEnv, EffectVisitor, SourceStringNames,
    expression_flow_key, literal_property_name, unparen,
};

pub(super) const PLUS_COERCION_BINDING_SUFFIX: &str = ".[plus-coercion]";

pub(super) fn plus_coercion_binding_name(name: &str) -> String {
    format!("{name}{PLUS_COERCION_BINDING_SUFFIX}")
}

pub(super) fn is_plus_coercion_property(key: &PropertyKey<'_>) -> bool {
    if matches!(key.static_name().as_deref(), Some("valueOf" | "toString")) {
        return true;
    }
    match key {
        PropertyKey::StaticMemberExpression(member) => {
            expression_flow_key(&member.object).as_deref() == Some("Symbol")
                && member.property.name == "toPrimitive"
        }
        PropertyKey::ComputedMemberExpression(member) => {
            expression_flow_key(&member.object).as_deref() == Some("Symbol")
                && literal_property_name(&member.expression).as_deref() == Some("toPrimitive")
        }
        _ => false,
    }
}

pub(super) fn plus_coercion_assignment_object(target: &AssignmentTarget<'_>) -> Option<String> {
    match target {
        AssignmentTarget::StaticMemberExpression(member)
            if matches!(member.property.name.as_str(), "valueOf" | "toString") =>
        {
            expression_flow_key(&member.object)
        }
        AssignmentTarget::ComputedMemberExpression(member)
            if matches!(
                literal_property_name(&member.expression).as_deref(),
                Some("valueOf" | "toString")
            ) || expression_flow_key(&member.expression).as_deref()
                == Some("Symbol.toPrimitive") =>
        {
            expression_flow_key(&member.object)
        }
        _ => None,
    }
}

impl<'a> EffectVisitor<'_, 'a> {
    pub(super) fn follow_plus_coercion_callbacks(&mut self, expr: &Expression<'a>) {
        self.follow_plus_coercion_callbacks_inner(expr, &mut HashSet::new());
    }

    pub(super) fn follow_plus_coercion_callbacks_inner(
        &mut self,
        expr: &Expression<'a>,
        visiting: &mut HashSet<u32>,
    ) {
        let direct_callbacks = match unparen(expr) {
            Expression::ObjectExpression(object) => object
                .properties
                .iter()
                .filter_map(|property| property.as_property())
                .filter(|property| is_plus_coercion_property(&property.key))
                .map(|property| &property.value)
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        for callback in direct_callbacks {
            self.follow_callback(callback);
        }
        if matches!(unparen(expr), Expression::ObjectExpression(_)) {
            return;
        }
        let Some(CallableBinding::PlusCoercion(owner_span)) =
            self.plus_coercion_binding(expr, &self.callable_env, &self.aggregate_aliases)
        else {
            return;
        };
        self.follow_plus_coercion_owner(owner_span, visiting);
    }

    pub(super) fn follow_plus_coercion_owner(
        &mut self,
        owner_span: u32,
        visiting: &mut HashSet<u32>,
    ) {
        if !visiting.insert(owner_span) {
            return;
        }
        if let Some(callbacks) = self.plus_coercion_callbacks.get(&owner_span).cloned() {
            for callback in callbacks {
                self.follow_callback(callback);
            }
        }
        if let Some(callbacks) = self
            .functions
            .class_plus_coercion_callbacks
            .get(&owner_span)
            .cloned()
        {
            for callback in callbacks {
                if callback.generator {
                    continue;
                }
                if let Some(body) = &callback.body {
                    let self_binding = callback.id.as_ref().map(|id| id.name.as_str());
                    let _ = self.enter_inline_body(
                        body,
                        &callback.params,
                        self_binding,
                        &[],
                        &[],
                        false,
                        callback.r#async,
                        false,
                    );
                }
            }
        }
        if let Some(returns) = self
            .functions
            .class_constructor_returns
            .get(&owner_span)
            .cloned()
        {
            for returned in returns {
                self.follow_plus_coercion_callbacks_inner(returned, visiting);
            }
        }
        if let Some(super_span) = self.class_super_plus_coercions.get(&owner_span).copied() {
            self.follow_plus_coercion_owner(super_span, visiting);
        }
        visiting.remove(&owner_span);
    }

    pub(super) fn bind_parameter_plus_coercion(
        &mut self,
        pattern: &BindingPattern<'a>,
        value: SourceBindingValue<'_, 'a>,
        argument_state: Option<&SourceStringState>,
        caller_state: &SourceStringState,
    ) {
        let state = argument_state.unwrap_or(caller_state);
        let value = match value {
            SourceBindingValue::Argument(expression) => AggregateBindingValue::Argument(expression),
            SourceBindingValue::Local(expression) => AggregateBindingValue::Local(expression),
            SourceBindingValue::Missing => AggregateBindingValue::Missing,
            SourceBindingValue::Unbounded => AggregateBindingValue::Unbounded,
        };
        self.bind_plus_coercion_pattern(
            pattern,
            value,
            &state.source_env,
            &state.unbounded_source_env,
            &state.callable_env,
            &state.aggregate_aliases,
        );
    }

    pub(super) fn plus_coercion_binding(
        &self,
        expression: &Expression<'a>,
        callable_env: &CallableEnv,
        aggregate_aliases: &AggregateAliases,
    ) -> Option<CallableBinding> {
        match unparen(expression) {
            Expression::ObjectExpression(object)
                if self
                    .plus_coercion_callbacks
                    .contains_key(&object.span.start) =>
            {
                Some(CallableBinding::PlusCoercion(object.span.start))
            }
            Expression::ClassExpression(class) => {
                self.class_plus_coercion_binding(class, callable_env, aggregate_aliases)
            }
            Expression::NewExpression(new_expression) => match unparen(&new_expression.callee) {
                Expression::ClassExpression(class) => {
                    self.class_plus_coercion_binding(class, callable_env, aggregate_aliases)
                }
                Expression::Identifier(identifier) => callable_env
                    .get(&plus_coercion_binding_name(identifier.name.as_str()))
                    .copied()
                    .filter(|binding| matches!(binding, CallableBinding::PlusCoercion(_))),
                _ => None,
            },
            _ => {
                let paths = expression_aggregate_alias_paths(
                    self.nest.budget,
                    expression,
                    aggregate_aliases,
                    &self.evaluated_aggregate_aliases,
                );
                let mut binding = None;
                for source in paths.get("")? {
                    let candidate = self.plus_coercion_binding_from_key(
                        source,
                        callable_env,
                        aggregate_aliases,
                    )?;
                    if binding.is_some_and(|binding| binding != candidate) {
                        return None;
                    }
                    binding = Some(candidate);
                }
                binding
            }
        }
    }

    pub(super) fn class_plus_coercion_binding(
        &self,
        class: &Class<'a>,
        callable_env: &CallableEnv,
        aggregate_aliases: &AggregateAliases,
    ) -> Option<CallableBinding> {
        if self.class_has_plus_coercion_callbacks(class.span.start)
            || self
                .class_super_plus_coercions
                .contains_key(&class.span.start)
        {
            return Some(CallableBinding::PlusCoercion(class.span.start));
        }
        self.plus_coercion_binding(class.super_class.as_ref()?, callable_env, aggregate_aliases)
    }

    pub(super) fn class_has_plus_coercion_callbacks(&self, span: u32) -> bool {
        self.plus_coercion_callbacks.contains_key(&span)
            || self
                .functions
                .class_plus_coercion_callbacks
                .contains_key(&span)
            || self.functions.class_constructor_returns.contains_key(&span)
    }

    pub(super) fn plus_coercion_binding_from_key(
        &self,
        source: &str,
        callable_env: &CallableEnv,
        aggregate_aliases: &AggregateAliases,
    ) -> Option<CallableBinding> {
        let mut binding = None;
        for source in aggregate_alias_binding_names(
            self.nest.budget,
            aggregate_aliases,
            &HashSet::from([source.to_string()]),
        ) {
            let Some(candidate) = callable_env
                .get(&plus_coercion_binding_name(&source))
                .copied()
            else {
                continue;
            };
            if !matches!(candidate, CallableBinding::PlusCoercion(_))
                || binding.is_some_and(|binding| binding != candidate)
            {
                return None;
            }
            binding = Some(candidate);
        }
        binding
    }

    pub(super) fn bind_plus_coercion_pattern<'r>(
        &mut self,
        pattern: &BindingPattern<'a>,
        value: AggregateBindingValue<'r, 'a>,
        argument_source_env: &ParamEnv,
        argument_unbounded_source_env: &SourceStringNames,
        argument_callable_env: &CallableEnv,
        argument_aggregate_aliases: &AggregateAliases,
    ) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                let binding = match value {
                    AggregateBindingValue::Argument(expression) => self.plus_coercion_binding(
                        expression,
                        argument_callable_env,
                        argument_aggregate_aliases,
                    ),
                    AggregateBindingValue::Local(expression) => self.plus_coercion_binding(
                        expression,
                        &self.callable_env,
                        &self.aggregate_aliases,
                    ),
                    AggregateBindingValue::ArgumentKey(source) => self
                        .plus_coercion_binding_from_key(
                            &source,
                            argument_callable_env,
                            argument_aggregate_aliases,
                        ),
                    AggregateBindingValue::LocalKey(source) => self.plus_coercion_binding_from_key(
                        &source,
                        &self.callable_env,
                        &self.aggregate_aliases,
                    ),
                    AggregateBindingValue::Projected(_)
                    | AggregateBindingValue::Missing
                    | AggregateBindingValue::Unbounded => None,
                }
                .unwrap_or(CallableBinding::Unbounded);
                self.callable_env.insert(
                    plus_coercion_binding_name(identifier.name.as_str()),
                    binding,
                );
            }
            BindingPattern::AssignmentPattern(assignment) => {
                let value = self.aggregate_binding_default(
                    value,
                    &assignment.right,
                    argument_source_env,
                    argument_unbounded_source_env,
                );
                self.bind_plus_coercion_pattern(
                    &assignment.left,
                    value,
                    argument_source_env,
                    argument_unbounded_source_env,
                    argument_callable_env,
                    argument_aggregate_aliases,
                );
            }
            BindingPattern::ArrayPattern(array) => {
                for (index, element) in array.elements.iter().enumerate() {
                    let Some(element) = element else { continue };
                    self.bind_plus_coercion_pattern(
                        element,
                        project_array_aggregate_binding(value.clone(), index),
                        argument_source_env,
                        argument_unbounded_source_env,
                        argument_callable_env,
                        argument_aggregate_aliases,
                    );
                }
                if let Some(rest) = &array.rest {
                    self.bind_plus_coercion_pattern(
                        &rest.argument,
                        AggregateBindingValue::Unbounded,
                        argument_source_env,
                        argument_unbounded_source_env,
                        argument_callable_env,
                        argument_aggregate_aliases,
                    );
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    let property_value = property
                        .key
                        .static_name()
                        .map_or(AggregateBindingValue::Unbounded, |key| {
                            project_object_aggregate_binding(value.clone(), &key)
                        });
                    self.bind_plus_coercion_pattern(
                        &property.value,
                        property_value,
                        argument_source_env,
                        argument_unbounded_source_env,
                        argument_callable_env,
                        argument_aggregate_aliases,
                    );
                }
                if let Some(rest) = &object.rest {
                    self.bind_plus_coercion_pattern(
                        &rest.argument,
                        AggregateBindingValue::Unbounded,
                        argument_source_env,
                        argument_unbounded_source_env,
                        argument_callable_env,
                        argument_aggregate_aliases,
                    );
                }
            }
        }
    }

    pub(super) fn track_plus_coercion_binding(&mut self, name: &str, value: &Expression<'a>) {
        self.record_source_string_write_name(name);
        let binding = self
            .plus_coercion_binding(value, &self.callable_env, &self.aggregate_aliases)
            .unwrap_or(CallableBinding::Unbounded);
        self.callable_env
            .insert(plus_coercion_binding_name(name), binding);
        self.sync_module_source_strings();
    }
}
