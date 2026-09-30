//! Source-string recovery: lowering untyped JavaScript string values
//! (literals, templates, concatenation, `process.env`, `os.homedir()`)
//! into resources, and binding source values through destructuring
//! patterns and member reads.

use std::collections::{HashMap, HashSet};

use effinterp_proto::ResourceExpr;
use oxc_ast::ast::{
    ArrayExpressionElement, BindingPattern, CallExpression, ChainElement,
    ExportDefaultDeclarationKind, Expression, ImportDeclarationSpecifier, Statement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

use super::aggregate_alias::{AggregateAliasPaths, project_aggregate_alias_paths};
use super::resolve::{self, ParamEnv};
use super::{
    Bindings, ObjectPropertyProjection, SourceStringNames, array_element,
    array_element_is_string_concatenation, array_literal_len, collect_scope_binding_names,
    expression_flow_key, literal_property_name, member_flow_key, object_property,
    object_property_is_string_concatenation, object_property_projection,
    string_conversion_argument, unparen,
};
use crate::lang::frontend::MAX_WALK_DEPTH;

pub(super) fn collect_source_string_bindings(statements: &[Statement<'_>]) -> HashSet<String> {
    let mut bindings = HashSet::new();
    for statement in statements {
        match statement {
            Statement::ImportDeclaration(import) => {
                for specifier in import.specifiers.iter().flatten() {
                    let name = match specifier {
                        ImportDeclarationSpecifier::ImportSpecifier(specifier) => {
                            &specifier.local.name
                        }
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                            &specifier.local.name
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                            &specifier.local.name
                        }
                    };
                    bindings.insert(name.as_str().to_string());
                }
            }
            Statement::ExportNamedDeclaration(export) => {
                if let Some(declaration) = &export.declaration {
                    collect_scope_binding_names(declaration, true, &mut bindings);
                }
            }
            Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                    if let Some(id) = &function.id {
                        bindings.insert(id.name.as_str().to_string());
                    }
                }
                ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                    if let Some(id) = &class.id {
                        bindings.insert(id.name.as_str().to_string());
                    }
                }
                _ => {}
            },
            _ => {
                if let Some(declaration) = statement.as_declaration() {
                    collect_scope_binding_names(declaration, true, &mut bindings);
                }
            }
        }
    }
    bindings
}

/// Lower an untyped JavaScript string value before its consuming effect gives
/// the parts a filesystem or network domain.
pub(super) fn source_string_resource(
    expr: &Expression<'_>,
    env: &ParamEnv,
    unbounded: &SourceStringNames,
    process_runtime: bool,
    evaluated: &EvaluatedSourceStrings,
) -> Option<ResourceExpr> {
    let expr = unparen(expr);
    if let Some(value) = evaluated.get(&source_expression_key(expr)) {
        return value.resource.clone();
    }
    if !env.contains_key("String")
        && !unbounded.contains("String")
        && let Some(argument) = string_conversion_argument(expr)
    {
        return source_string_resource(argument, env, unbounded, process_runtime, evaluated);
    }
    match expr {
        Expression::StringLiteral(literal) => Some(ResourceExpr::Literal {
            value: literal.value.as_str().to_string(),
        }),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            Some(ResourceExpr::Literal {
                value: template
                    .quasis
                    .first()?
                    .value
                    .cooked
                    .as_ref()?
                    .as_str()
                    .to_string(),
            })
        }
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            let mut parts = Vec::new();
            source_string_parts(
                expr,
                env,
                unbounded,
                process_runtime,
                evaluated,
                &mut parts,
                0,
            )?;
            Some(ResourceExpr::Join { parts })
        }
        Expression::TemplateLiteral(_) => {
            let mut parts = Vec::new();
            source_string_parts(
                expr,
                env,
                unbounded,
                process_runtime,
                evaluated,
                &mut parts,
                0,
            )?;
            Some(ResourceExpr::Join { parts })
        }
        Expression::AssignmentExpression(assignment) if assignment.operator.is_assign() => {
            source_string_resource(
                &assignment.right,
                env,
                unbounded,
                process_runtime,
                evaluated,
            )
        }
        Expression::AwaitExpression(awaited) => source_string_resource(
            &awaited.argument,
            env,
            unbounded,
            process_runtime,
            evaluated,
        ),
        Expression::Identifier(id) if !unbounded.contains(id.name.as_str()) => {
            env.get(id.name.as_str()).cloned()
        }
        Expression::StaticMemberExpression(member) => {
            if process_runtime
                && let Some(name) = resolve::process_env_name(member)
                && !name.is_empty()
            {
                Some(resolve::environment_value(&name, member.span.start))
            } else if let Some(name) =
                source_member_binding_name(&member.object, member.property.name.as_str())
                && !unbounded.contains(&name)
                && let Some(resource) = env.get(&name)
            {
                Some(resource.clone())
            } else {
                member_source_value(&member.object, member.property.name.as_str()).and_then(
                    |value| {
                        source_string_resource(value, env, unbounded, process_runtime, evaluated)
                    },
                )
            }
        }
        Expression::ComputedMemberExpression(member) => {
            if process_runtime
                && let Some(index) = resolve::process_argv_index(member)
                && let Some(value) = env.get(&format!("process.argv[{index}]"))
            {
                return Some(value.clone());
            }
            if process_runtime
                && resolve::is_process_env(&member.object)
                && let Some(name) = literal_property_name(&member.expression)
                && !name.is_empty()
            {
                Some(resolve::environment_value(&name, member.span.start))
            } else {
                let property = literal_property_name(&member.expression)?;
                if let Some(name) = source_member_binding_name(&member.object, &property)
                    && !unbounded.contains(&name)
                    && let Some(resource) = env.get(&name)
                {
                    Some(resource.clone())
                } else {
                    member_source_value(&member.object, &property).and_then(|value| {
                        source_string_resource(value, env, unbounded, process_runtime, evaluated)
                    })
                }
            }
        }
        Expression::ChainExpression(chain) => match &chain.expression {
            ChainElement::StaticMemberExpression(member) => {
                if process_runtime
                    && let Some(name) = resolve::process_env_name(member)
                    && !name.is_empty()
                {
                    Some(resolve::environment_value(&name, member.span.start))
                } else if let Some(name) =
                    source_member_binding_name(&member.object, member.property.name.as_str())
                    && !unbounded.contains(&name)
                    && let Some(resource) = env.get(&name)
                {
                    Some(resource.clone())
                } else {
                    member_source_value(&member.object, member.property.name.as_str()).and_then(
                        |value| {
                            source_string_resource(
                                value,
                                env,
                                unbounded,
                                process_runtime,
                                evaluated,
                            )
                        },
                    )
                }
            }
            ChainElement::ComputedMemberExpression(member) => {
                if process_runtime
                    && resolve::is_process_env(&member.object)
                    && let Some(name) = literal_property_name(&member.expression)
                    && !name.is_empty()
                {
                    Some(resolve::environment_value(&name, member.span.start))
                } else {
                    let property = literal_property_name(&member.expression)?;
                    if let Some(name) = source_member_binding_name(&member.object, &property)
                        && !unbounded.contains(&name)
                        && let Some(resource) = env.get(&name)
                    {
                        Some(resource.clone())
                    } else {
                        member_source_value(&member.object, &property).and_then(|value| {
                            source_string_resource(
                                value,
                                env,
                                unbounded,
                                process_runtime,
                                evaluated,
                            )
                        })
                    }
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn source_string_parts(
    expr: &Expression<'_>,
    env: &ParamEnv,
    unbounded: &SourceStringNames,
    process_runtime: bool,
    evaluated: &EvaluatedSourceStrings,
    parts: &mut Vec<ResourceExpr>,
    depth: u32,
) -> Option<()> {
    if depth >= MAX_WALK_DEPTH {
        return None;
    }
    match unparen(expr) {
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            source_string_parts(
                &binary.left,
                env,
                unbounded,
                process_runtime,
                evaluated,
                parts,
                depth + 1,
            )?;
            source_string_parts(
                &binary.right,
                env,
                unbounded,
                process_runtime,
                evaluated,
                parts,
                depth + 1,
            )
        }
        Expression::TemplateLiteral(template) => {
            for (index, quasi) in template.quasis.iter().enumerate() {
                let value = quasi.value.cooked.as_ref()?.as_str();
                if !value.is_empty() {
                    parts.push(ResourceExpr::Literal {
                        value: value.to_string(),
                    });
                }
                if let Some(expression) = template.expressions.get(index) {
                    source_string_parts(
                        expression,
                        env,
                        unbounded,
                        process_runtime,
                        evaluated,
                        parts,
                        depth + 1,
                    )?;
                }
            }
            Some(())
        }
        _ => {
            parts.push(source_string_resource(
                expr,
                env,
                unbounded,
                process_runtime,
                evaluated,
            )?);
            Some(())
        }
    }
}

pub(super) type EvaluatedSourceStrings = HashMap<(u32, u32), SourceStringValue>;

/// `os.homedir()` returns `$HOME` whenever it is set, which is the value a
/// host context supplies, so a call to it evaluates to that variable.
pub(super) fn is_home_directory_call(call: &CallExpression<'_>, bindings: &Bindings) -> bool {
    call.arguments.is_empty()
        && resolve::resolve_callee(unparen(&call.callee), bindings)
            .is_some_and(|callee| callee.module == "os" && callee.function == "homedir")
}

pub(super) fn home_directory_value(call: &CallExpression<'_>) -> SourceStringValue {
    SourceStringValue {
        resource: Some(resolve::environment_value("HOME", call.span.start)),
        concatenation: false,
    }
}

/// A filesystem path a summarized function builds from environment values,
/// such as `process.env.HOME + '/.ssh'` or `` `${os.homedir()}/.ssh` ``. The
/// variables stay symbolic for the call site to resolve. None when the path
/// reads no environment value, or the module can rewrite one first.
pub(super) fn summary_environment_path(
    expr: &Expression<'_>,
    env: &ParamEnv,
    process_runtime: bool,
    bindings: &Bindings,
) -> Option<ResourceExpr> {
    struct HomeDirectoryCalls<'b> {
        bindings: &'b Bindings,
        evaluated: EvaluatedSourceStrings,
    }
    impl<'a> Visit<'a> for HomeDirectoryCalls<'_> {
        fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
            if is_home_directory_call(it, self.bindings) {
                self.evaluated
                    .insert((it.span.start, it.span.end), home_directory_value(it));
            }
            walk::walk_call_expression(self, it);
        }
    }
    if bindings.environment_is_rewritten() {
        return None;
    }
    let mut calls = HomeDirectoryCalls {
        bindings,
        evaluated: EvaluatedSourceStrings::new(),
    };
    calls.visit_expression(expr);
    let ResourceExpr::Join { parts } = source_string_resource(
        expr,
        env,
        &SourceStringNames::new(),
        process_runtime,
        &calls.evaluated,
    )?
    else {
        return None;
    };
    if !parts
        .iter()
        .any(|part| matches!(part, ResourceExpr::Environment { .. }))
    {
        return None;
    }
    let resource = effinterp_proto::normalize_resource(
        crate::value::sink_typed_concat(parts, "filesystem", None),
        effinterp_proto::PathPlatform::Posix,
    );
    (!matches!(resource, ResourceExpr::Unresolved { .. })).then_some(resource)
}

pub(super) fn source_expression_key(expr: &Expression<'_>) -> (u32, u32) {
    let span = expr.span();
    (span.start, span.end)
}

pub(super) fn append_source_string_parts(parts: &mut Vec<ResourceExpr>, resource: ResourceExpr) {
    match resource {
        ResourceExpr::Join { parts: nested } => parts.extend(nested),
        resource => parts.push(resource),
    }
}

pub(super) fn is_string_concatenation(
    expr: &Expression<'_>,
    source_env: &ParamEnv,
    evaluated: &EvaluatedSourceStrings,
) -> bool {
    let expr = unparen(expr);
    if let Some(value) = evaluated.get(&source_expression_key(expr)) {
        return value.concatenation;
    }
    if !source_env.contains_key("String")
        && let Some(argument) = string_conversion_argument(expr)
    {
        return is_string_concatenation(argument, source_env, evaluated);
    }
    match expr {
        Expression::BinaryExpression(binary) => binary.operator.as_str() == "+",
        Expression::TemplateLiteral(template) => !template.expressions.is_empty(),
        Expression::Identifier(id) => matches!(
            source_env.get(id.name.as_str()),
            Some(ResourceExpr::Join { .. })
        ),
        Expression::StaticMemberExpression(member) => {
            source_member_binding_name(&member.object, member.property.name.as_str())
                .is_some_and(|name| source_binding_is_string_concatenation(&name, source_env))
                || member_source_is_string_concatenation(
                    &member.object,
                    member.property.name.as_str(),
                    source_env,
                    evaluated,
                )
        }
        Expression::ComputedMemberExpression(member) => literal_property_name(&member.expression)
            .map_or_else(
                || aggregate_member_is_string_concatenation(&member.object, source_env, evaluated),
                |property| {
                    source_member_binding_name(&member.object, &property).is_some_and(|name| {
                        source_binding_is_string_concatenation(&name, source_env)
                    }) || member_source_is_string_concatenation(
                        &member.object,
                        &property,
                        source_env,
                        evaluated,
                    )
                },
            ),
        Expression::ChainExpression(chain) => match &chain.expression {
            ChainElement::StaticMemberExpression(member) => {
                source_member_binding_name(&member.object, member.property.name.as_str())
                    .is_some_and(|name| source_binding_is_string_concatenation(&name, source_env))
                    || member_source_is_string_concatenation(
                        &member.object,
                        member.property.name.as_str(),
                        source_env,
                        evaluated,
                    )
            }
            ChainElement::ComputedMemberExpression(member) => literal_property_name(
                &member.expression,
            )
            .map_or_else(
                || aggregate_member_is_string_concatenation(&member.object, source_env, evaluated),
                |property| {
                    source_member_binding_name(&member.object, &property).is_some_and(|name| {
                        source_binding_is_string_concatenation(&name, source_env)
                    }) || member_source_is_string_concatenation(
                        &member.object,
                        &property,
                        source_env,
                        evaluated,
                    )
                },
            ),
            _ => false,
        },
        Expression::ConditionalExpression(conditional) => {
            is_string_concatenation(&conditional.consequent, source_env, evaluated)
                || is_string_concatenation(&conditional.alternate, source_env, evaluated)
        }
        Expression::LogicalExpression(logical) => {
            is_string_concatenation(&logical.left, source_env, evaluated)
                || is_string_concatenation(&logical.right, source_env, evaluated)
        }
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .last()
            .is_some_and(|expr| is_string_concatenation(expr, source_env, evaluated)),
        Expression::AssignmentExpression(assignment) => {
            assignment.operator.as_str() == "+="
                || (assignment.operator.is_assign() || assignment.operator.is_logical())
                    && is_string_concatenation(&assignment.right, source_env, evaluated)
        }
        Expression::AwaitExpression(awaited) => {
            is_string_concatenation(&awaited.argument, source_env, evaluated)
        }
        _ => false,
    }
}

#[derive(Clone, Copy)]
pub(super) enum SourceBindingValue<'r, 'a> {
    Argument(&'r Expression<'a>),
    Local(&'r Expression<'a>),
    Missing,
    Unbounded,
}

#[derive(Clone)]
pub(super) enum AggregateBindingValue<'r, 'a> {
    Argument(&'r Expression<'a>),
    Local(&'r Expression<'a>),
    ArgumentKey(String),
    LocalKey(String),
    Projected(AggregateAliasPaths),
    Missing,
    Unbounded,
}

pub(super) fn project_array_aggregate_binding<'r, 'a>(
    value: AggregateBindingValue<'r, 'a>,
    index: usize,
) -> AggregateBindingValue<'r, 'a> {
    match value {
        AggregateBindingValue::Argument(expression) => {
            if array_literal_len(expression).is_some() {
                array_element(expression, index).map_or(
                    AggregateBindingValue::Missing,
                    AggregateBindingValue::Argument,
                )
            } else {
                expression_flow_key(expression).map_or(AggregateBindingValue::Unbounded, |key| {
                    AggregateBindingValue::ArgumentKey(format!("{key}.{index}"))
                })
            }
        }
        AggregateBindingValue::Local(expression) => {
            if array_literal_len(expression).is_some() {
                array_element(expression, index)
                    .map_or(AggregateBindingValue::Missing, AggregateBindingValue::Local)
            } else {
                expression_flow_key(expression).map_or(AggregateBindingValue::Unbounded, |key| {
                    AggregateBindingValue::LocalKey(format!("{key}.{index}"))
                })
            }
        }
        AggregateBindingValue::ArgumentKey(key) => {
            AggregateBindingValue::ArgumentKey(format!("{key}.{index}"))
        }
        AggregateBindingValue::LocalKey(key) => {
            AggregateBindingValue::LocalKey(format!("{key}.{index}"))
        }
        AggregateBindingValue::Projected(paths) => AggregateBindingValue::Projected(
            project_aggregate_alias_paths(paths, &index.to_string()),
        ),
        AggregateBindingValue::Missing => AggregateBindingValue::Missing,
        AggregateBindingValue::Unbounded => AggregateBindingValue::Unbounded,
    }
}

pub(super) fn project_object_aggregate_binding<'r, 'a>(
    value: AggregateBindingValue<'r, 'a>,
    wanted: &str,
) -> AggregateBindingValue<'r, 'a> {
    match value {
        AggregateBindingValue::Argument(expression) => {
            match object_property_projection(expression, wanted) {
                ObjectPropertyProjection::Value(expression) => {
                    AggregateBindingValue::Argument(expression)
                }
                ObjectPropertyProjection::Missing => AggregateBindingValue::Missing,
                ObjectPropertyProjection::Unbounded => expression_flow_key(expression)
                    .map_or(AggregateBindingValue::Unbounded, |key| {
                        AggregateBindingValue::ArgumentKey(format!("{key}.{wanted}"))
                    }),
            }
        }
        AggregateBindingValue::Local(expression) => {
            match object_property_projection(expression, wanted) {
                ObjectPropertyProjection::Value(expression) => {
                    AggregateBindingValue::Local(expression)
                }
                ObjectPropertyProjection::Missing => AggregateBindingValue::Missing,
                ObjectPropertyProjection::Unbounded => expression_flow_key(expression)
                    .map_or(AggregateBindingValue::Unbounded, |key| {
                        AggregateBindingValue::LocalKey(format!("{key}.{wanted}"))
                    }),
            }
        }
        AggregateBindingValue::ArgumentKey(key) => {
            AggregateBindingValue::ArgumentKey(format!("{key}.{wanted}"))
        }
        AggregateBindingValue::LocalKey(key) => {
            AggregateBindingValue::LocalKey(format!("{key}.{wanted}"))
        }
        AggregateBindingValue::Projected(paths) => {
            AggregateBindingValue::Projected(project_aggregate_alias_paths(paths, wanted))
        }
        AggregateBindingValue::Missing => AggregateBindingValue::Missing,
        AggregateBindingValue::Unbounded => AggregateBindingValue::Unbounded,
    }
}

pub(super) fn project_object_source_binding<'r, 'a>(
    value: SourceBindingValue<'r, 'a>,
    wanted: &str,
) -> SourceBindingValue<'r, 'a> {
    match value {
        SourceBindingValue::Argument(expression) => {
            match object_property_projection(expression, wanted) {
                ObjectPropertyProjection::Value(expression) => {
                    SourceBindingValue::Argument(expression)
                }
                ObjectPropertyProjection::Missing => SourceBindingValue::Missing,
                ObjectPropertyProjection::Unbounded => SourceBindingValue::Unbounded,
            }
        }
        SourceBindingValue::Local(expression) => {
            match object_property_projection(expression, wanted) {
                ObjectPropertyProjection::Value(expression) => {
                    SourceBindingValue::Local(expression)
                }
                ObjectPropertyProjection::Missing => SourceBindingValue::Missing,
                ObjectPropertyProjection::Unbounded => SourceBindingValue::Unbounded,
            }
        }
        SourceBindingValue::Missing | SourceBindingValue::Unbounded => {
            SourceBindingValue::Unbounded
        }
    }
}

pub(super) fn is_global_undefined(
    expression: &Expression<'_>,
    source_env: &ParamEnv,
    unbounded_source_env: &SourceStringNames,
) -> bool {
    matches!(unparen(expression), Expression::Identifier(id) if id.name.as_str() == "undefined")
        && !source_env.contains_key("undefined")
        && !unbounded_source_env.contains("undefined")
}

pub(super) fn set_source_string_binding(
    name: &str,
    resource: Option<ResourceExpr>,
    concatenation: bool,
    source_env: &mut ParamEnv,
    unbounded_source_env: &mut SourceStringNames,
) {
    match resource {
        Some(resource) => {
            source_env.insert(name.to_string(), resource);
            unbounded_source_env.remove(name);
        }
        None => {
            if concatenation {
                source_env.insert(name.to_string(), ResourceExpr::Join { parts: Vec::new() });
            }
            mark_unbounded_source_string(name, source_env, unbounded_source_env);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn bind_source_string_pattern<'r, 'a>(
    pattern: &BindingPattern<'a>,
    value: SourceBindingValue<'r, 'a>,
    argument_env: &ParamEnv,
    argument_unbounded: &SourceStringNames,
    source_env: &mut ParamEnv,
    unbounded_source_env: &mut SourceStringNames,
    argument_process_runtime: bool,
    process_runtime: bool,
    evaluated: &EvaluatedSourceStrings,
) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            let (resource, concatenation) = match value {
                SourceBindingValue::Argument(expression) => (
                    source_string_resource(
                        expression,
                        argument_env,
                        argument_unbounded,
                        argument_process_runtime,
                        evaluated,
                    ),
                    is_string_concatenation(expression, argument_env, evaluated),
                ),
                SourceBindingValue::Local(expression) => (
                    source_string_resource(
                        expression,
                        source_env,
                        unbounded_source_env,
                        process_runtime,
                        evaluated,
                    ),
                    is_string_concatenation(expression, source_env, evaluated),
                ),
                SourceBindingValue::Missing | SourceBindingValue::Unbounded => (None, false),
            };
            set_source_string_binding(
                id.name.as_str(),
                resource,
                concatenation,
                source_env,
                unbounded_source_env,
            );
        }
        BindingPattern::AssignmentPattern(assignment) => {
            let value = match value {
                SourceBindingValue::Argument(expression)
                    if is_global_undefined(expression, argument_env, argument_unbounded) =>
                {
                    SourceBindingValue::Local(&assignment.right)
                }
                SourceBindingValue::Local(expression)
                    if is_global_undefined(expression, source_env, unbounded_source_env) =>
                {
                    SourceBindingValue::Local(&assignment.right)
                }
                SourceBindingValue::Missing => SourceBindingValue::Local(&assignment.right),
                value => value,
            };
            bind_source_string_pattern(
                &assignment.left,
                value,
                argument_env,
                argument_unbounded,
                source_env,
                unbounded_source_env,
                argument_process_runtime,
                process_runtime,
                evaluated,
            );
        }
        BindingPattern::ArrayPattern(array) => {
            let exact = match value {
                SourceBindingValue::Argument(expression)
                | SourceBindingValue::Local(expression) => array_literal_len(expression).is_some(),
                SourceBindingValue::Missing | SourceBindingValue::Unbounded => false,
            };
            for (index, element) in array.elements.iter().enumerate() {
                let Some(element) = element else { continue };
                let element_value = if exact {
                    match value {
                        SourceBindingValue::Argument(expression) => {
                            array_element(expression, index)
                                .map_or(SourceBindingValue::Missing, SourceBindingValue::Argument)
                        }
                        SourceBindingValue::Local(expression) => array_element(expression, index)
                            .map_or(SourceBindingValue::Missing, SourceBindingValue::Local),
                        SourceBindingValue::Missing | SourceBindingValue::Unbounded => {
                            SourceBindingValue::Unbounded
                        }
                    }
                } else {
                    SourceBindingValue::Unbounded
                };
                bind_source_string_pattern(
                    element,
                    element_value,
                    argument_env,
                    argument_unbounded,
                    source_env,
                    unbounded_source_env,
                    argument_process_runtime,
                    process_runtime,
                    evaluated,
                );
            }
            if let Some(rest) = &array.rest {
                bind_source_string_pattern(
                    &rest.argument,
                    SourceBindingValue::Unbounded,
                    argument_env,
                    argument_unbounded,
                    source_env,
                    unbounded_source_env,
                    argument_process_runtime,
                    process_runtime,
                    evaluated,
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
                let property_value = if exact {
                    let Some(key) = property.key.static_name() else {
                        bind_source_string_pattern(
                            &property.value,
                            SourceBindingValue::Unbounded,
                            argument_env,
                            argument_unbounded,
                            source_env,
                            unbounded_source_env,
                            argument_process_runtime,
                            process_runtime,
                            evaluated,
                        );
                        continue;
                    };
                    project_object_source_binding(value, &key)
                } else {
                    SourceBindingValue::Unbounded
                };
                bind_source_string_pattern(
                    &property.value,
                    property_value,
                    argument_env,
                    argument_unbounded,
                    source_env,
                    unbounded_source_env,
                    argument_process_runtime,
                    process_runtime,
                    evaluated,
                );
            }
            if let Some(rest) = &object.rest {
                bind_source_string_pattern(
                    &rest.argument,
                    SourceBindingValue::Unbounded,
                    argument_env,
                    argument_unbounded,
                    source_env,
                    unbounded_source_env,
                    argument_process_runtime,
                    process_runtime,
                    evaluated,
                );
            }
        }
    }
}

fn source_member_binding_name(object: &Expression<'_>, property: &str) -> Option<String> {
    member_flow_key(object, property)
}

fn source_binding_is_string_concatenation(name: &str, source_env: &ParamEnv) -> bool {
    if let Some(resource) = source_env.get(name) {
        return matches!(resource, ResourceExpr::Join { .. });
    }
    let mut ancestor = name;
    while let Some((parent, _)) = ancestor.rsplit_once('.') {
        if matches!(
            source_env.get(&format!("{parent}.*")),
            Some(ResourceExpr::Join { .. })
        ) {
            return true;
        }
        ancestor = parent;
    }
    false
}

fn member_source_value<'a, 'b>(
    object: &'b Expression<'a>,
    property: &str,
) -> Option<&'b Expression<'a>> {
    object_property(object, property).or_else(|| {
        let index = property.parse::<usize>().ok()?;
        (index.to_string() == property)
            .then(|| array_element(object, index))
            .flatten()
    })
}

fn member_source_is_string_concatenation(
    object: &Expression<'_>,
    property: &str,
    source_env: &ParamEnv,
    evaluated: &EvaluatedSourceStrings,
) -> bool {
    object_property_is_string_concatenation(object, property, source_env, evaluated)
        || property.parse::<usize>().ok().is_some_and(|index| {
            index.to_string() == property
                && array_element_is_string_concatenation(object, index, source_env, evaluated)
        })
}

pub(super) fn aggregate_member_is_string_concatenation(
    expr: &Expression<'_>,
    source_env: &ParamEnv,
    evaluated: &EvaluatedSourceStrings,
) -> bool {
    if let Some(name) = expression_flow_key(expr) {
        let prefix = format!("{name}.");
        if source_env.iter().any(|(name, resource)| {
            name.starts_with(&prefix) && matches!(resource, ResourceExpr::Join { .. })
        }) {
            return true;
        }
    }
    match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            aggregate_member_is_string_concatenation(&awaited.argument, source_env, evaluated)
        }
        Expression::ObjectExpression(object) => {
            object.properties.iter().any(|property| match property {
                oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                    is_string_concatenation(&property.value, source_env, evaluated)
                        || aggregate_member_is_string_concatenation(
                            &property.value,
                            source_env,
                            evaluated,
                        )
                }
                oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                    aggregate_member_is_string_concatenation(
                        &spread.argument,
                        source_env,
                        evaluated,
                    )
                }
            })
        }
        Expression::ArrayExpression(array) => array.elements.iter().any(|element| match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                aggregate_member_is_string_concatenation(&spread.argument, source_env, evaluated)
            }
            element => element.as_expression().is_some_and(|expression| {
                is_string_concatenation(expression, source_env, evaluated)
                    || aggregate_member_is_string_concatenation(expression, source_env, evaluated)
            }),
        }),
        Expression::ConditionalExpression(conditional) => {
            aggregate_member_is_string_concatenation(&conditional.consequent, source_env, evaluated)
                || aggregate_member_is_string_concatenation(
                    &conditional.alternate,
                    source_env,
                    evaluated,
                )
        }
        Expression::LogicalExpression(logical) => {
            aggregate_member_is_string_concatenation(&logical.left, source_env, evaluated)
                || aggregate_member_is_string_concatenation(&logical.right, source_env, evaluated)
        }
        Expression::SequenceExpression(sequence) => {
            sequence.expressions.last().is_some_and(|expression| {
                aggregate_member_is_string_concatenation(expression, source_env, evaluated)
            })
        }
        Expression::AssignmentExpression(assignment) if assignment.operator.is_assign() => {
            aggregate_member_is_string_concatenation(&assignment.right, source_env, evaluated)
        }
        _ => false,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SourceStringValue {
    pub(super) resource: Option<ResourceExpr>,
    pub(super) concatenation: bool,
}

pub(super) fn mark_unbounded_source_string(
    name: &str,
    source_env: &mut ParamEnv,
    unbounded_source_env: &mut SourceStringNames,
) {
    if !matches!(source_env.get(name), Some(ResourceExpr::Join { .. })) {
        source_env.remove(name);
    }
    unbounded_source_env.insert(name.to_string());
}
