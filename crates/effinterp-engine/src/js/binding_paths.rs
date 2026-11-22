//! Binding paths for flow slots and for writes that may invalidate a whole aggregate.

use std::collections::HashSet;

use oxc_ast::ast::{AssignmentTarget, Expression, SimpleAssignmentTarget};

use super::expression_values::unparen;
use super::literal_members::literal_property_name;

/// Descendants share the root name followed by a member separator.
pub(super) fn binding_is_within(binding: &str, name: &str) -> bool {
    binding == name
        || binding
            .strip_prefix(name)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

pub(super) fn binding_names_with_descendants<'a>(
    names: &HashSet<String>,
    candidates: impl Iterator<Item = &'a String>,
) -> HashSet<String> {
    let mut expanded = names.clone();
    expanded.extend(
        candidates
            .filter(|candidate| names.iter().any(|name| binding_is_within(candidate, name)))
            .cloned(),
    );
    expanded
}

pub(super) fn assignment_flow_key(target: &AssignmentTarget<'_>) -> Option<String> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str().to_string()),
        AssignmentTarget::StaticMemberExpression(member) => {
            member_flow_key(&member.object, member.property.name.as_str())
        }
        AssignmentTarget::ComputedMemberExpression(member) => {
            let property = literal_property_name(&member.expression)?;
            member_flow_key(&member.object, &property)
        }
        AssignmentTarget::TSAsExpression(target) => expression_flow_key(&target.expression),
        AssignmentTarget::TSSatisfiesExpression(target) => expression_flow_key(&target.expression),
        AssignmentTarget::TSNonNullExpression(target) => expression_flow_key(&target.expression),
        AssignmentTarget::TSTypeAssertion(target) => expression_flow_key(&target.expression),
        _ => None,
    }
}

/// An unknown member key widens a write to the enclosing aggregate binding.
pub(super) fn assignment_target_write_binding_name(
    target: &AssignmentTarget<'_>,
) -> Option<String> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str().to_string()),
        AssignmentTarget::StaticMemberExpression(member) => member_write_binding_name(
            &member.object,
            Some(member.property.name.as_str().to_string()),
        ),
        AssignmentTarget::ComputedMemberExpression(member) => {
            member_write_binding_name(&member.object, literal_property_name(&member.expression))
        }
        AssignmentTarget::TSAsExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        AssignmentTarget::TSSatisfiesExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        AssignmentTarget::TSNonNullExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        AssignmentTarget::TSTypeAssertion(target) => {
            expression_write_binding_name(&target.expression)
        }
        _ => None,
    }
}

pub(super) fn simple_assignment_target_write_binding_name(
    target: &SimpleAssignmentTarget<'_>,
) -> Option<String> {
    match target {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
            Some(id.name.as_str().to_string())
        }
        SimpleAssignmentTarget::StaticMemberExpression(member) => member_write_binding_name(
            &member.object,
            Some(member.property.name.as_str().to_string()),
        ),
        SimpleAssignmentTarget::ComputedMemberExpression(member) => {
            member_write_binding_name(&member.object, literal_property_name(&member.expression))
        }
        SimpleAssignmentTarget::TSAsExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        SimpleAssignmentTarget::TSSatisfiesExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        SimpleAssignmentTarget::TSNonNullExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        SimpleAssignmentTarget::TSTypeAssertion(target) => {
            expression_write_binding_name(&target.expression)
        }
        _ => None,
    }
}

pub(super) fn expression_write_binding_name(expression: &Expression<'_>) -> Option<String> {
    match unparen(expression) {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        Expression::StaticMemberExpression(member) => member_write_binding_name(
            &member.object,
            Some(member.property.name.as_str().to_string()),
        ),
        Expression::ComputedMemberExpression(member) => {
            member_write_binding_name(&member.object, literal_property_name(&member.expression))
        }
        _ => None,
    }
}

fn member_write_binding_name(object: &Expression<'_>, property: Option<String>) -> Option<String> {
    match property {
        Some(property) => member_flow_key(object, &property),
        None => expression_flow_key(object),
    }
}

pub(super) fn expression_flow_key(expr: &Expression<'_>) -> Option<String> {
    match unparen(expr) {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        Expression::StaticMemberExpression(member) => {
            member_flow_key(&member.object, member.property.name.as_str())
        }
        Expression::ComputedMemberExpression(member) => {
            let property = literal_property_name(&member.expression)?;
            member_flow_key(&member.object, &property)
        }
        Expression::AwaitExpression(awaited) => expression_flow_key(&awaited.argument),
        _ => None,
    }
}

pub(super) fn member_flow_key(object: &Expression<'_>, property: &str) -> Option<String> {
    let base = expression_flow_key(object)?;
    let name = format!("{base}.{property}");
    Some(canonical_global_builtin_binding(&name).unwrap_or(name))
}

pub(super) fn canonical_global_builtin_binding(name: &str) -> Option<String> {
    let suffix = name.strip_prefix("globalThis.")?;
    let (builtin, member) = suffix.split_once('.').unwrap_or((suffix, ""));
    matches!(builtin, "Promise" | "String").then(|| {
        if member.is_empty() {
            builtin.to_string()
        } else {
            format!("{builtin}.{member}")
        }
    })
}
