//! Aggregate source-string members: the per-member source strings of an
//! object or array value, including spread elements and unknown-length
//! spread tails.

use std::collections::HashSet;

use effinterp_proto::ResourceExpr;
use oxc_ast::ast::{ArrayExpressionElement, Expression};

use super::resolve::ParamEnv;
use super::source_string::{
    EvaluatedSourceStrings, aggregate_member_is_string_concatenation, is_string_concatenation,
    source_string_resource,
};
use super::{
    ObjectPropertyProjection, SourceStringNames, array_element, array_literal_len,
    binding_is_within, expression_flow_key, object_property_projection, unparen,
};
use crate::lang::frontend::MAX_WALK_DEPTH;

/// Indexed argv words after an unknown-length spread. Distinct from `name.N`
/// so `arr[i]` does not treat a tail literal as a stable index.
pub(super) const SOURCE_SPREAD_TAIL: &str = "*spread";

pub(super) fn source_wildcard_key(name: &str) -> String {
    format!("{name}.*")
}

fn source_spread_tail_key(name: &str, index: usize) -> String {
    format!("{name}.{SOURCE_SPREAD_TAIL}.{index}")
}

fn source_name_has_unknown_spread(
    name: &str,
    source_env: &ParamEnv,
    unbounded_source_env: &SourceStringNames,
) -> bool {
    let wildcard = source_wildcard_key(name);
    let tail_prefix = format!("{name}.{SOURCE_SPREAD_TAIL}.");
    unbounded_source_env.contains(&wildcard)
        || source_env.contains_key(&wildcard)
        || source_env
            .keys()
            .chain(unbounded_source_env.iter())
            .any(|key| key.starts_with(&tail_prefix))
}

fn copy_indexed_aggregate_members(
    dest: &str,
    source: &str,
    offset: usize,
    source_env: &ParamEnv,
    unbounded_source_env: &SourceStringNames,
    members: &mut Vec<(String, Option<ResourceExpr>, bool)>,
) -> usize {
    let mut count = 0;
    loop {
        let key = format!("{source}.{count}");
        if unbounded_source_env.contains(&key) {
            replace_aggregate_source_string_member(
                members,
                format!("{dest}.{}", offset + count),
                None,
                false,
            );
            count += 1;
        } else if let Some(resource) = source_env.get(&key) {
            let concatenation = matches!(resource, ResourceExpr::Join { .. });
            replace_aggregate_source_string_member(
                members,
                format!("{dest}.{}", offset + count),
                Some(resource.clone()),
                concatenation,
            );
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn copy_spread_tail_aggregate_members(
    dest: &str,
    source: &str,
    dest_offset: usize,
    source_env: &ParamEnv,
    unbounded_source_env: &SourceStringNames,
    members: &mut Vec<(String, Option<ResourceExpr>, bool)>,
) -> usize {
    let mut count = 0;
    loop {
        let key = source_spread_tail_key(source, count);
        if unbounded_source_env.contains(&key) {
            replace_aggregate_source_string_member(
                members,
                source_spread_tail_key(dest, dest_offset + count),
                None,
                false,
            );
            count += 1;
        } else if let Some(resource) = source_env.get(&key) {
            let concatenation = matches!(resource, ResourceExpr::Join { .. });
            replace_aggregate_source_string_member(
                members,
                source_spread_tail_key(dest, dest_offset + count),
                Some(resource.clone()),
                concatenation,
            );
            count += 1;
        } else {
            break;
        }
    }
    count
}

#[allow(clippy::too_many_arguments)]
pub(super) fn collect_aggregate_source_string_members(
    name: &str,
    expr: &Expression<'_>,
    source_env: &ParamEnv,
    unbounded_source_env: &SourceStringNames,
    process_runtime: bool,
    evaluated: &EvaluatedSourceStrings,
    members: &mut Vec<(String, Option<ResourceExpr>, bool)>,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    if let Some(source) = expression_flow_key(expr) {
        let prefix = format!("{source}.");
        for source_name in source_env
            .keys()
            .chain(unbounded_source_env.iter())
            .filter(|candidate| candidate.starts_with(&prefix))
        {
            let target = format!("{name}.{}", &source_name[prefix.len()..]);
            let concatenation =
                matches!(source_env.get(source_name), Some(ResourceExpr::Join { .. }));
            let resource = (!unbounded_source_env.contains(source_name))
                .then(|| source_env.get(source_name).cloned())
                .flatten();
            replace_aggregate_source_string_member(members, target, resource, concatenation);
        }
        return;
    }
    match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            collect_aggregate_source_string_members(
                name,
                &awaited.argument,
                source_env,
                unbounded_source_env,
                process_runtime,
                evaluated,
                members,
                depth + 1,
            );
        }
        Expression::ObjectExpression(object) => {
            for property in &object.properties {
                match property {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                        let Some(key) = property.key.static_name() else {
                            mark_aggregate_source_string_members_unbounded(members, name);
                            if is_string_concatenation(&property.value, source_env, evaluated)
                                || aggregate_member_is_string_concatenation(
                                    &property.value,
                                    source_env,
                                    evaluated,
                                )
                            {
                                replace_aggregate_source_string_member(
                                    members,
                                    format!("{name}.*"),
                                    None,
                                    true,
                                );
                            }
                            continue;
                        };
                        let member = format!("{name}.{key}");
                        collect_aggregate_source_string_member(
                            member,
                            &property.value,
                            source_env,
                            unbounded_source_env,
                            process_runtime,
                            evaluated,
                            members,
                            depth,
                        );
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                        let prefix = format!("{name}.");
                        let keys = members
                            .iter()
                            .filter_map(|(member, _, _)| {
                                member
                                    .strip_prefix(&prefix)
                                    .and_then(|suffix| suffix.split('.').next())
                                    .filter(|key| *key != "*")
                                    .map(str::to_string)
                            })
                            .collect::<HashSet<_>>();
                        for key in keys {
                            if matches!(
                                object_property_projection(&spread.argument, &key),
                                ObjectPropertyProjection::Unbounded
                            ) {
                                mark_aggregate_source_string_members_unbounded(
                                    members,
                                    &format!("{name}.{key}"),
                                );
                            }
                        }
                        if aggregate_member_is_string_concatenation(
                            &spread.argument,
                            source_env,
                            evaluated,
                        ) {
                            replace_aggregate_source_string_member(
                                members,
                                format!("{name}.*"),
                                None,
                                true,
                            );
                        }
                        collect_aggregate_source_string_members(
                            name,
                            &spread.argument,
                            source_env,
                            unbounded_source_env,
                            process_runtime,
                            evaluated,
                            members,
                            depth + 1,
                        );
                    }
                }
            }
        }
        Expression::ArrayExpression(array) => {
            if let Some(len) = array_literal_len(expr) {
                for index in 0..len {
                    let Some(value) = array_element(expr, index) else {
                        continue;
                    };
                    collect_aggregate_source_string_member(
                        format!("{name}.{index}"),
                        value,
                        source_env,
                        unbounded_source_env,
                        process_runtime,
                        evaluated,
                        members,
                        depth,
                    );
                }
            } else {
                let mut exact_index = Some(0usize);
                let mut uncertain_concatenation = false;
                let mut incomplete = false;
                let mut spread_tail = 0usize;
                for element in &array.elements {
                    match element {
                        ArrayExpressionElement::SpreadElement(spread) => {
                            if let (Some(index), Some(len)) =
                                (exact_index, array_literal_len(&spread.argument))
                            {
                                for offset in 0..len {
                                    let Some(value) = array_element(&spread.argument, offset)
                                    else {
                                        continue;
                                    };
                                    collect_aggregate_source_string_member(
                                        format!("{name}.{}", index + offset),
                                        value,
                                        source_env,
                                        unbounded_source_env,
                                        process_runtime,
                                        evaluated,
                                        members,
                                        depth,
                                    );
                                }
                                exact_index = Some(index + len);
                            } else if let Some(index) = exact_index
                                && let Some(source) = expression_flow_key(&spread.argument)
                            {
                                let len = copy_indexed_aggregate_members(
                                    name,
                                    &source,
                                    index,
                                    source_env,
                                    unbounded_source_env,
                                    members,
                                );
                                if len > 0
                                    && !source_name_has_unknown_spread(
                                        &source,
                                        source_env,
                                        unbounded_source_env,
                                    )
                                {
                                    exact_index = Some(index + len);
                                } else {
                                    // Known prefix copied; an unknown-length
                                    // spread still makes later indices unstable.
                                    if len == 0 {
                                        uncertain_concatenation |=
                                            aggregate_member_is_string_concatenation(
                                                &spread.argument,
                                                source_env,
                                                evaluated,
                                            );
                                    }
                                    incomplete = true;
                                    exact_index = None;
                                    spread_tail += copy_spread_tail_aggregate_members(
                                        name,
                                        &source,
                                        spread_tail,
                                        source_env,
                                        unbounded_source_env,
                                        members,
                                    );
                                }
                            } else {
                                uncertain_concatenation |= aggregate_member_is_string_concatenation(
                                    &spread.argument,
                                    source_env,
                                    evaluated,
                                );
                                incomplete = true;
                                if exact_index.is_some() {
                                    exact_index = None;
                                } else {
                                    replace_aggregate_source_string_member(
                                        members,
                                        source_spread_tail_key(name, spread_tail),
                                        None,
                                        false,
                                    );
                                    spread_tail += 1;
                                }
                            }
                        }
                        ArrayExpressionElement::Elision(_) => {
                            if let Some(index) = exact_index.as_mut() {
                                *index += 1;
                            } else {
                                replace_aggregate_source_string_member(
                                    members,
                                    source_spread_tail_key(name, spread_tail),
                                    None,
                                    false,
                                );
                                spread_tail += 1;
                            }
                        }
                        element => {
                            let Some(value) = element.as_expression() else {
                                continue;
                            };
                            if let Some(index) = exact_index.as_mut() {
                                collect_aggregate_source_string_member(
                                    format!("{name}.{index}"),
                                    value,
                                    source_env,
                                    unbounded_source_env,
                                    process_runtime,
                                    evaluated,
                                    members,
                                    depth,
                                );
                                *index += 1;
                            } else {
                                collect_aggregate_source_string_member(
                                    source_spread_tail_key(name, spread_tail),
                                    value,
                                    source_env,
                                    unbounded_source_env,
                                    process_runtime,
                                    evaluated,
                                    members,
                                    depth,
                                );
                                spread_tail += 1;
                                uncertain_concatenation |=
                                    is_string_concatenation(value, source_env, evaluated)
                                        || aggregate_member_is_string_concatenation(
                                            value, source_env, evaluated,
                                        );
                            }
                        }
                    }
                }
                if uncertain_concatenation {
                    replace_aggregate_source_string_member(
                        members,
                        source_wildcard_key(name),
                        None,
                        true,
                    );
                } else if incomplete {
                    replace_aggregate_source_string_member(
                        members,
                        source_wildcard_key(name),
                        None,
                        false,
                    );
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_aggregate_source_string_member(
    name: String,
    value: &Expression<'_>,
    source_env: &ParamEnv,
    unbounded_source_env: &SourceStringNames,
    process_runtime: bool,
    evaluated: &EvaluatedSourceStrings,
    members: &mut Vec<(String, Option<ResourceExpr>, bool)>,
    depth: u32,
) {
    replace_aggregate_source_string_member(
        members,
        name.clone(),
        source_string_resource(
            value,
            source_env,
            unbounded_source_env,
            process_runtime,
            evaluated,
        ),
        is_string_concatenation(value, source_env, evaluated),
    );
    collect_aggregate_source_string_members(
        &name,
        value,
        source_env,
        unbounded_source_env,
        process_runtime,
        evaluated,
        members,
        depth + 1,
    );
}

fn replace_aggregate_source_string_member(
    members: &mut Vec<(String, Option<ResourceExpr>, bool)>,
    name: String,
    resource: Option<ResourceExpr>,
    concatenation: bool,
) {
    members.retain(|(member, _, _)| !binding_is_within(member, &name));
    members.push((name, resource, concatenation));
}

fn mark_aggregate_source_string_members_unbounded(
    members: &mut [(String, Option<ResourceExpr>, bool)],
    name: &str,
) {
    for (member, resource, _) in members {
        if binding_is_within(member, name) {
            *resource = None;
        }
    }
}
