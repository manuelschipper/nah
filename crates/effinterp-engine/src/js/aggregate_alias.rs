//! Aggregate aliases: which bindings name the same object or array, so a
//! write through one alias reaches every other. Propagates, projects,
//! clears and restores aggregate alias paths.

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{ChainElement, Expression};

use super::source_string::source_expression_key;
use super::{
    AggregateAliases, array_element, array_literal_len, assignment_flow_key, binding_is_within,
    canonical_global_builtin_binding, expression_flow_key, literal_property_name, unparen,
};

/// Relative member path to aggregate aliases; the empty path names the value itself.
pub(super) type AggregateAliasPaths = HashMap<String, HashSet<String>>;
pub(super) type EvaluatedAggregateAliases = HashMap<(u32, u32), AggregateAliasPaths>;

pub(super) fn add_aggregate_alias(aliases: &mut AggregateAliases, left: String, right: String) {
    if left == right {
        return;
    }
    aliases
        .entry(left.clone())
        .or_default()
        .insert(right.clone());
    aliases.entry(right).or_default().insert(left);
}

pub(super) fn clear_aggregate_aliases(aliases: &mut AggregateAliases, names: &HashSet<String>) {
    for name in aliases.keys().cloned().collect::<Vec<_>>() {
        if names
            .iter()
            .any(|binding| binding_is_within(&name, binding))
        {
            aliases.remove(&name);
            continue;
        }
        let targets = aliases.get_mut(&name).unwrap();
        targets.retain(|target| {
            !names
                .iter()
                .any(|binding| binding_is_within(target, binding))
        });
        if targets.is_empty() {
            aliases.remove(&name);
        }
    }
}

pub(super) fn restore_aggregate_aliases(
    aliases: &mut AggregateAliases,
    source: &AggregateAliases,
    names: &HashSet<String>,
) {
    clear_aggregate_aliases(aliases, names);
    let restored: Vec<_> = source
        .iter()
        .flat_map(|(name, targets)| {
            targets
                .iter()
                .filter(move |target| {
                    names.iter().any(|binding| {
                        binding_is_within(name, binding) || binding_is_within(target, binding)
                    })
                })
                .map(move |target| (name.clone(), target.clone()))
        })
        .collect();
    for (name, target) in restored {
        add_aggregate_alias(aliases, name, target);
    }
}

pub(super) fn aggregate_alias_binding_names(
    budget: &crate::nest::Budget,
    aliases: &AggregateAliases,
    names: &HashSet<String>,
) -> HashSet<String> {
    if budget.bytes_saturated()
        || budget.cancelled()
        || !budget.try_charge_bytes(
            names
                .iter()
                .map(|name| crate::limits::NODE_BYTES + name.len() as u64)
                .sum(),
        )
    {
        return HashSet::new();
    }
    let mut expanded = names.clone();
    let mut pending: Vec<_> = names.iter().cloned().collect();
    // Recursive aggregates can keep adding a member suffix without visiting
    // another AST node. Charge each new name inside that expansion loop.
    while let Some(binding) = pending.pop() {
        if let Some(canonical) = canonical_global_builtin_binding(&binding)
            && !expanded.contains(&canonical)
        {
            if !budget.try_charge_bytes(crate::limits::NODE_BYTES + canonical.len() as u64) {
                return HashSet::new();
            }
            expanded.insert(canonical.clone());
            pending.push(canonical);
        }
        for (alias, targets) in aliases {
            let Some(suffix) = binding.strip_prefix(alias) else {
                continue;
            };
            if !suffix.is_empty() && !suffix.starts_with('.') {
                continue;
            }
            for target in targets {
                let candidate = format!("{target}{suffix}");
                if !expanded.contains(&candidate) {
                    if !budget.try_charge_bytes(crate::limits::NODE_BYTES + candidate.len() as u64)
                    {
                        return HashSet::new();
                    }
                    expanded.insert(candidate.clone());
                    pending.push(candidate);
                }
            }
        }
    }
    expanded
}

pub(super) fn extend_aggregate_alias_paths(
    paths: &mut AggregateAliasPaths,
    prefix: &str,
    nested: AggregateAliasPaths,
) {
    for (path, targets) in nested {
        paths
            .entry(format!("{prefix}{path}"))
            .or_default()
            .extend(targets);
    }
}

pub(super) fn aggregate_alias_binding_paths(
    budget: &crate::nest::Budget,
    aliases: &AggregateAliases,
    name: &str,
) -> AggregateAliasPaths {
    let mut paths = AggregateAliasPaths::from([(
        String::new(),
        aggregate_alias_binding_names(budget, aliases, &HashSet::from([name.to_string()])),
    )]);
    let bindings: HashSet<_> = aliases
        .iter()
        .flat_map(|(alias, targets)| std::iter::once(alias).chain(targets))
        .filter(|binding| {
            binding
                .strip_prefix(name)
                .is_some_and(|suffix| suffix.starts_with('.'))
        })
        .cloned()
        .collect();
    for binding in bindings {
        let path = binding.strip_prefix(name).unwrap().to_string();
        paths
            .entry(path)
            .or_default()
            .extend(aggregate_alias_binding_names(
                budget,
                aliases,
                &HashSet::from([binding]),
            ));
    }
    paths
}

pub(super) fn project_aggregate_alias_paths(
    paths: AggregateAliasPaths,
    property: &str,
) -> AggregateAliasPaths {
    let prefix = format!(".{property}");
    paths
        .into_iter()
        .filter_map(|(path, targets)| {
            path.strip_prefix(&prefix).and_then(|suffix| {
                (suffix.is_empty() || suffix.starts_with('.'))
                    .then(|| (suffix.to_string(), targets))
            })
        })
        .collect()
}

pub(super) fn project_array_rest_aggregate_alias_paths(
    paths: AggregateAliasPaths,
    first_index: usize,
) -> AggregateAliasPaths {
    paths
        .into_iter()
        .filter_map(|(path, targets)| {
            let path = path.strip_prefix('.')?;
            let (index, suffix) = path
                .split_once('.')
                .map_or((path, None), |(index, suffix)| (index, Some(suffix)));
            let index = index.parse::<usize>().ok()?;
            (index >= first_index).then(|| {
                let path = suffix.map_or_else(
                    || format!(".{}", index - first_index),
                    |suffix| format!(".{}.{suffix}", index - first_index),
                );
                (path, targets)
            })
        })
        .collect()
}

pub(super) fn project_object_rest_aggregate_alias_paths(
    paths: AggregateAliasPaths,
    excluded: &HashSet<String>,
) -> AggregateAliasPaths {
    paths
        .into_iter()
        .filter(|(path, _)| {
            path.strip_prefix('.')
                .and_then(|path| path.split('.').next())
                .is_some_and(|property| !excluded.contains(property))
        })
        .collect()
}

pub(super) fn expression_aggregate_alias_paths(
    budget: &crate::nest::Budget,
    expression: &Expression<'_>,
    aliases: &AggregateAliases,
    evaluated: &EvaluatedAggregateAliases,
) -> AggregateAliasPaths {
    if let Some(paths) = evaluated.get(&source_expression_key(unparen(expression))) {
        return paths.clone();
    }
    if let Some(name) = expression_flow_key(expression) {
        return aggregate_alias_binding_paths(budget, aliases, &name);
    }
    match unparen(expression) {
        Expression::ObjectExpression(object) => {
            let mut paths = AggregateAliasPaths::new();
            for property in &object.properties {
                match property {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                        if let Some(name) = property.key.static_name() {
                            extend_aggregate_alias_paths(
                                &mut paths,
                                &format!(".{name}"),
                                expression_aggregate_alias_paths(
                                    budget,
                                    &property.value,
                                    aliases,
                                    evaluated,
                                ),
                            );
                        }
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                        extend_aggregate_alias_paths(
                            &mut paths,
                            "",
                            expression_aggregate_alias_paths(
                                budget,
                                &spread.argument,
                                aliases,
                                evaluated,
                            ),
                        );
                    }
                }
            }
            paths
        }
        Expression::ArrayExpression(_) => {
            let mut paths = AggregateAliasPaths::new();
            if let Some(len) = array_literal_len(expression) {
                for index in 0..len {
                    if let Some(element) = array_element(expression, index) {
                        extend_aggregate_alias_paths(
                            &mut paths,
                            &format!(".{index}"),
                            expression_aggregate_alias_paths(budget, element, aliases, evaluated),
                        );
                    }
                }
            }
            paths
        }
        Expression::StaticMemberExpression(member) => project_aggregate_alias_paths(
            expression_aggregate_alias_paths(budget, &member.object, aliases, evaluated),
            member.property.name.as_str(),
        ),
        Expression::ComputedMemberExpression(member) => literal_property_name(&member.expression)
            .map_or_else(AggregateAliasPaths::new, |name| {
                project_aggregate_alias_paths(
                    expression_aggregate_alias_paths(budget, &member.object, aliases, evaluated),
                    &name,
                )
            }),
        Expression::ChainExpression(chain) => match &chain.expression {
            ChainElement::StaticMemberExpression(member) => project_aggregate_alias_paths(
                expression_aggregate_alias_paths(budget, &member.object, aliases, evaluated),
                member.property.name.as_str(),
            ),
            ChainElement::ComputedMemberExpression(member) => literal_property_name(
                &member.expression,
            )
            .map_or_else(AggregateAliasPaths::new, |name| {
                project_aggregate_alias_paths(
                    expression_aggregate_alias_paths(budget, &member.object, aliases, evaluated),
                    &name,
                )
            }),
            _ => AggregateAliasPaths::new(),
        },
        Expression::ConditionalExpression(conditional) => {
            let mut paths = expression_aggregate_alias_paths(
                budget,
                &conditional.consequent,
                aliases,
                evaluated,
            );
            extend_aggregate_alias_paths(
                &mut paths,
                "",
                expression_aggregate_alias_paths(
                    budget,
                    &conditional.alternate,
                    aliases,
                    evaluated,
                ),
            );
            paths
        }
        Expression::LogicalExpression(logical) => {
            let mut paths =
                expression_aggregate_alias_paths(budget, &logical.left, aliases, evaluated);
            extend_aggregate_alias_paths(
                &mut paths,
                "",
                expression_aggregate_alias_paths(budget, &logical.right, aliases, evaluated),
            );
            paths
        }
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .last()
            .map_or_else(AggregateAliasPaths::new, |expression| {
                expression_aggregate_alias_paths(budget, expression, aliases, evaluated)
            }),
        Expression::AssignmentExpression(assignment) if assignment.operator.is_assign() => {
            expression_aggregate_alias_paths(budget, &assignment.right, aliases, evaluated)
        }
        Expression::AssignmentExpression(assignment) if assignment.operator.is_logical() => {
            let mut paths = assignment_flow_key(&assignment.left)
                .map_or_else(AggregateAliasPaths::new, |name| {
                    aggregate_alias_binding_paths(budget, aliases, &name)
                });
            extend_aggregate_alias_paths(
                &mut paths,
                "",
                expression_aggregate_alias_paths(budget, &assignment.right, aliases, evaluated),
            );
            paths
        }
        Expression::AwaitExpression(awaited) => {
            expression_aggregate_alias_paths(budget, &awaited.argument, aliases, evaluated)
        }
        _ => AggregateAliasPaths::new(),
    }
}
