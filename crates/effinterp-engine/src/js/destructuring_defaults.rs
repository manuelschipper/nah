//! JavaScript destructuring defaults: visiting the default initializers of
//! binding and assignment patterns, which run only when the matched value is
//! undefined.

use oxc_ast::ast::{AssignmentTarget, BindingPattern, Expression};
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

use super::source_string::{
    SourceBindingValue, SourceStringValue, is_global_undefined, is_string_concatenation,
    project_object_source_binding, source_expression_key, source_string_resource,
};
use super::{EffectVisitor, array_element, array_literal_len, unparen};

impl<'a> EffectVisitor<'_, 'a> {
    pub(super) fn visit_selected_source_binding_default(&mut self, init: &Expression<'a>) {
        let key = source_expression_key(unparen(init));
        self.evaluated_source_strings.remove(&key);
        self.visit_expression(init);
        self.evaluated_source_strings.insert(
            key,
            SourceStringValue {
                resource: source_string_resource(
                    init,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                ),
                concatenation: is_string_concatenation(
                    init,
                    &self.source_env,
                    &self.evaluated_source_strings,
                ),
            },
        );
    }

    pub(super) fn visit_source_binding_default<'r>(
        &mut self,
        init: &'r Expression<'a>,
        value: SourceBindingValue<'r, 'a>,
    ) -> SourceBindingValue<'r, 'a> {
        match value {
            SourceBindingValue::Argument(expression) | SourceBindingValue::Local(expression)
                if is_global_undefined(
                    expression,
                    &self.source_env,
                    &self.unbounded_source_env,
                ) =>
            {
                self.visit_selected_source_binding_default(init);
                SourceBindingValue::Local(init)
            }
            SourceBindingValue::Missing => {
                self.visit_selected_source_binding_default(init);
                SourceBindingValue::Local(init)
            }
            SourceBindingValue::Argument(expression) | SourceBindingValue::Local(expression)
                if matches!(
                    unparen(expression),
                    Expression::BooleanLiteral(_)
                        | Expression::NullLiteral(_)
                        | Expression::NumericLiteral(_)
                        | Expression::BigIntLiteral(_)
                        | Expression::RegExpLiteral(_)
                        | Expression::StringLiteral(_)
                        | Expression::TemplateLiteral(_)
                        | Expression::ArrayExpression(_)
                        | Expression::ArrowFunctionExpression(_)
                        | Expression::ClassExpression(_)
                        | Expression::FunctionExpression(_)
                        | Expression::ObjectExpression(_)
                        | Expression::NewExpression(_)
                ) =>
            {
                value
            }
            value => {
                let entry = self.source_string_state();
                self.visit_expression(init);
                let default = self.source_string_state();
                self.join_source_string_states(entry, default, init.span());
                match value {
                    SourceBindingValue::Argument(_) | SourceBindingValue::Local(_) => {
                        SourceBindingValue::Unbounded
                    }
                    value => value,
                }
            }
        }
    }

    pub(super) fn visit_assignment_target_maybe_default<'r>(
        &mut self,
        target: &'r oxc_ast::ast::AssignmentTargetMaybeDefault<'a>,
        value: SourceBindingValue<'r, 'a>,
    ) {
        match target {
            oxc_ast::ast::AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(default) => {
                let value = self.visit_source_binding_default(&default.init, value);
                self.visit_assignment_target_defaults(&default.binding, value);
            }
            _ => self.visit_assignment_target_defaults(target.to_assignment_target(), value),
        }
    }

    pub(super) fn visit_assignment_target_defaults<'r>(
        &mut self,
        target: &'r AssignmentTarget<'a>,
        value: SourceBindingValue<'r, 'a>,
    ) {
        match target {
            AssignmentTarget::ArrayAssignmentTarget(array) => {
                let exact = match value {
                    SourceBindingValue::Argument(expression)
                    | SourceBindingValue::Local(expression) => {
                        array_literal_len(expression).is_some()
                    }
                    SourceBindingValue::Missing | SourceBindingValue::Unbounded => false,
                };
                for (index, element) in array.elements.iter().enumerate() {
                    let Some(element) = element else { continue };
                    let element_value = if exact {
                        match value {
                            SourceBindingValue::Argument(expression) => array_element(
                                expression, index,
                            )
                            .map_or(SourceBindingValue::Missing, SourceBindingValue::Argument),
                            SourceBindingValue::Local(expression) => {
                                array_element(expression, index)
                                    .map_or(SourceBindingValue::Missing, SourceBindingValue::Local)
                            }
                            SourceBindingValue::Missing | SourceBindingValue::Unbounded => {
                                SourceBindingValue::Unbounded
                            }
                        }
                    } else {
                        SourceBindingValue::Unbounded
                    };
                    self.visit_assignment_target_maybe_default(element, element_value);
                }
                if let Some(rest) = &array.rest {
                    self.visit_assignment_target_defaults(
                        &rest.target,
                        SourceBindingValue::Unbounded,
                    );
                }
            }
            AssignmentTarget::ObjectAssignmentTarget(object) => {
                let exact = match value {
                    SourceBindingValue::Argument(expression)
                    | SourceBindingValue::Local(expression) => {
                        matches!(unparen(expression), Expression::ObjectExpression(_))
                    }
                    SourceBindingValue::Missing | SourceBindingValue::Unbounded => false,
                };
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(
                            property,
                        ) => {
                            let property_value = if exact {
                                project_object_source_binding(
                                    value,
                                    property.binding.name.as_str(),
                                )
                            } else {
                                SourceBindingValue::Unbounded
                            };
                            if let Some(init) = &property.init {
                                self.visit_source_binding_default(init, property_value);
                            }
                            self.visit_identifier_reference(&property.binding);
                        }
                        oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyProperty(
                            property,
                        ) => {
                            self.visit_property_key(&property.name);
                            let property_value = if exact {
                                let Some(key) = property.name.static_name() else {
                                    self.visit_assignment_target_maybe_default(
                                        &property.binding,
                                        SourceBindingValue::Unbounded,
                                    );
                                    continue;
                                };
                                project_object_source_binding(value, &key)
                            } else {
                                SourceBindingValue::Unbounded
                            };
                            self.visit_assignment_target_maybe_default(
                                &property.binding,
                                property_value,
                            );
                        }
                    }
                }
                if let Some(rest) = &object.rest {
                    self.visit_assignment_target_defaults(
                        &rest.target,
                        SourceBindingValue::Unbounded,
                    );
                }
            }
            _ => self.visit_assignment_target(target),
        }
    }

    pub(super) fn visit_binding_pattern_defaults<'r>(
        &mut self,
        pattern: &'r BindingPattern<'a>,
        value: SourceBindingValue<'r, 'a>,
    ) {
        match pattern {
            BindingPattern::BindingIdentifier(_) => {}
            BindingPattern::AssignmentPattern(assignment) => {
                let value = self.visit_source_binding_default(&assignment.right, value);
                self.visit_binding_pattern_defaults(&assignment.left, value);
            }
            BindingPattern::ArrayPattern(array) => {
                let exact = match value {
                    SourceBindingValue::Argument(expression)
                    | SourceBindingValue::Local(expression) => {
                        array_literal_len(expression).is_some()
                    }
                    SourceBindingValue::Missing | SourceBindingValue::Unbounded => false,
                };
                for (index, element) in array.elements.iter().enumerate() {
                    let Some(element) = element else { continue };
                    let element_value = if exact {
                        match value {
                            SourceBindingValue::Argument(expression) => array_element(
                                expression, index,
                            )
                            .map_or(SourceBindingValue::Missing, SourceBindingValue::Argument),
                            SourceBindingValue::Local(expression) => {
                                array_element(expression, index)
                                    .map_or(SourceBindingValue::Missing, SourceBindingValue::Local)
                            }
                            SourceBindingValue::Missing | SourceBindingValue::Unbounded => {
                                SourceBindingValue::Unbounded
                            }
                        }
                    } else {
                        SourceBindingValue::Unbounded
                    };
                    self.visit_binding_pattern_defaults(element, element_value);
                }
                if let Some(rest) = &array.rest {
                    self.visit_binding_pattern_defaults(
                        &rest.argument,
                        SourceBindingValue::Unbounded,
                    );
                }
            }
            BindingPattern::ObjectPattern(object) => {
                let exact = match value {
                    SourceBindingValue::Argument(expression)
                    | SourceBindingValue::Local(expression) => {
                        matches!(unparen(expression), Expression::ObjectExpression(_))
                    }
                    SourceBindingValue::Missing | SourceBindingValue::Unbounded => false,
                };
                for property in &object.properties {
                    self.visit_property_key(&property.key);
                    let property_value = if exact {
                        let Some(key) = property.key.static_name() else {
                            self.visit_binding_pattern_defaults(
                                &property.value,
                                SourceBindingValue::Unbounded,
                            );
                            continue;
                        };
                        project_object_source_binding(value, &key)
                    } else {
                        SourceBindingValue::Unbounded
                    };
                    self.visit_binding_pattern_defaults(&property.value, property_value);
                }
                if let Some(rest) = &object.rest {
                    self.visit_binding_pattern_defaults(
                        &rest.argument,
                        SourceBindingValue::Unbounded,
                    );
                }
            }
        }
    }
}
