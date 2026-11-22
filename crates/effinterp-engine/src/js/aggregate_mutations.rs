//! Aggregate mutation targets of Object APIs and their borrowed call forms.

use std::collections::HashSet;

use oxc_ast::ast::{Argument, CallExpression, Expression};

use super::binding_paths::{canonical_global_builtin_binding, expression_flow_key};
use super::call_arguments::{
    logical_call_argument, logical_call_argument_bindings, logical_call_argument_count,
};
use super::expression_values::unparen;
use super::literal_members::{array_element, array_literal_len, literal_property_name};

/// A known key narrows invalidation to that member. Unknown keys invalidate the target.
pub(super) fn aggregate_mutation_target_bindings(call: &CallExpression<'_>) -> HashSet<String> {
    let mut bindings = HashSet::new();
    let callee_key = expression_flow_key(&call.callee);
    if let Some((target, method)) = callee_key
        .as_deref()
        .and_then(|callee| callee.rsplit_once('.'))
        && matches!(
            method,
            "fill" | "reverse" | "copyWithin" | "splice" | "shift" | "unshift" | "sort" | "pop"
        )
    {
        bindings.insert(target.to_string());
        return bindings;
    }
    if matches!(
        callee_key.as_deref(),
        Some(
            "Object.assign.apply" | "Object.defineProperty.apply" | "Object.defineProperties.apply"
        )
    ) {
        let arguments =
            logical_call_argument(&call.arguments, 1).and_then(|(argument, _)| argument);
        if let Some(arguments) = arguments
            && let Some(name) = array_element_binding(arguments, 0)
        {
            bindings.insert(name);
        }
        bindings.extend(
            logical_call_argument_bindings(&call.arguments, 1)
                .into_iter()
                .map(|name| format!("{name}.0")),
        );
        if callee_key.as_deref() == Some("Object.defineProperty.apply") {
            return defined_property_member_bindings(
                &bindings,
                arguments
                    .and_then(|arguments| array_element(arguments, 1))
                    .and_then(literal_property_name),
            );
        }
        return if callee_key.as_deref() == Some("Object.assign.apply") {
            static_object_member_bindings_from_array(&bindings, arguments, 1)
        } else {
            static_object_member_bindings(
                &bindings,
                arguments.and_then(|arguments| array_element(arguments, 1)),
            )
        };
    }
    let target_index = match callee_key.as_deref() {
        Some(
            "Object.assign.call" | "Object.defineProperty.call" | "Object.defineProperties.call",
        ) => 1,
        Some(
            "Object.assign"
            | "Object.defineProperty"
            | "Object.defineProperties"
            | "Array.prototype.fill.call"
            | "Array.prototype.fill.apply"
            | "Array.prototype.reverse.call"
            | "Array.prototype.reverse.apply"
            | "Array.prototype.splice.call"
            | "Array.prototype.splice.apply"
            | "Array.prototype.copyWithin.call"
            | "Array.prototype.copyWithin.apply"
            | "Array.prototype.shift.call"
            | "Array.prototype.shift.apply"
            | "Array.prototype.unshift.call"
            | "Array.prototype.unshift.apply"
            | "Array.prototype.sort.call"
            | "Array.prototype.sort.apply"
            | "Array.prototype.pop.call"
            | "Array.prototype.pop.apply",
        ) => 0,
        _ => return bindings,
    };
    bindings.extend(logical_call_argument_bindings(
        &call.arguments,
        target_index,
    ));
    let property_index = match callee_key.as_deref() {
        Some("Object.defineProperty") => Some(1),
        Some("Object.defineProperty.call") => Some(2),
        _ => None,
    };
    if let Some(property_index) = property_index {
        return defined_property_member_bindings(
            &bindings,
            logical_call_argument(&call.arguments, property_index)
                .and_then(|(argument, _)| argument)
                .and_then(literal_property_name),
        );
    }
    match callee_key.as_deref() {
        Some("Object.assign") => {
            return static_object_member_bindings_from_arguments(&bindings, &call.arguments, 1);
        }
        Some("Object.assign.call") => {
            return static_object_member_bindings_from_arguments(&bindings, &call.arguments, 2);
        }
        Some("Object.defineProperties") => {
            return static_object_member_bindings(
                &bindings,
                logical_call_argument(&call.arguments, 1).and_then(|(argument, _)| argument),
            );
        }
        Some("Object.defineProperties.call") => {
            return static_object_member_bindings(
                &bindings,
                logical_call_argument(&call.arguments, 2).and_then(|(argument, _)| argument),
            );
        }
        _ => {}
    }
    bindings
}

fn defined_property_member_bindings(
    targets: &HashSet<String>,
    property: Option<String>,
) -> HashSet<String> {
    let mut bindings = targets.clone();
    let Some(property) = property else {
        // An unknown property may replace either transparent builtin.
        for property in ["String", "Promise"] {
            for target in targets {
                let member = format!("{target}.{property}");
                bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
            }
        }
        return bindings;
    };
    for target in targets {
        let member = format!("{target}.{property}");
        bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
    }
    bindings
}

fn static_object_member_bindings(
    targets: &HashSet<String>,
    object: Option<&Expression<'_>>,
) -> HashSet<String> {
    let mut bindings = targets.clone();
    let mut has_unbounded_properties = false;
    if let Some(Expression::ObjectExpression(object)) = object.map(unparen) {
        for property in &object.properties {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property else {
                has_unbounded_properties = true;
                continue;
            };
            let Some(property) = property.key.static_name() else {
                has_unbounded_properties = true;
                continue;
            };
            for target in targets {
                let member = format!("{target}.{property}");
                bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
            }
        }
    } else {
        has_unbounded_properties = true;
    }
    if has_unbounded_properties {
        // An unprojectable bulk source may replace either transparent builtin.
        for property in ["String", "Promise"] {
            for target in targets {
                let member = format!("{target}.{property}");
                bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
            }
        }
    }
    bindings
}

fn static_object_member_bindings_from_arguments(
    targets: &HashSet<String>,
    arguments: &[Argument<'_>],
    first_source: usize,
) -> HashSet<String> {
    let Some(argument_count) = logical_call_argument_count(arguments) else {
        return static_object_member_bindings(targets, None);
    };
    let mut bindings = targets.clone();
    for index in first_source..argument_count {
        bindings.extend(static_object_member_bindings(
            targets,
            logical_call_argument(arguments, index).and_then(|(argument, _)| argument),
        ));
    }
    bindings
}

fn static_object_member_bindings_from_array(
    targets: &HashSet<String>,
    array: Option<&Expression<'_>>,
    first_source: usize,
) -> HashSet<String> {
    let Some(array) = array else {
        return static_object_member_bindings(targets, None);
    };
    let Some(argument_count) = array_literal_len(array) else {
        return static_object_member_bindings(targets, None);
    };
    let mut bindings = targets.clone();
    for index in first_source..argument_count {
        bindings.extend(static_object_member_bindings(
            targets,
            array_element(array, index),
        ));
    }
    bindings
}

fn array_element_binding(expr: &Expression<'_>, wanted: usize) -> Option<String> {
    array_element(expr, wanted)
        .and_then(expression_flow_key)
        .or_else(|| Some(format!("{}.{}", expression_flow_key(expr)?, wanted)))
}
