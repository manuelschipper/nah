//! Rust pattern bindings and the restoration of pattern-local names.

use std::collections::{BTreeMap, HashMap, HashSet};

use syn::Pat;

use crate::{ObjectIdentity, SemanticValue, SemanticValueKind};

use super::{
    RustCommandCandidates, ValueState, expression_diverges, is_rust_branch, is_symbolic_value,
    is_unresolved_value, join_value_states, rust_branch_value, transparent_value_ident,
};

pub(super) type ScopedBindings = HashMap<
    String,
    (
        Option<SemanticValue>,
        Option<RustCommandCandidates>,
        Option<HashSet<String>>,
    ),
>;

pub(super) fn save_pattern_bindings(
    pattern: &Pat,
    state: &ValueState,
    saved: &mut ScopedBindings,
    unit_variants: &HashMap<String, String>,
) {
    let mut names = Vec::new();
    rust_pattern_binding_names(pattern, &mut names, unit_variants);
    for name in names {
        saved.entry(name.clone()).or_insert_with(|| {
            (
                state.values.get(&name).cloned(),
                state.commands.get(&name).cloned(),
                state.closures.get(&name).cloned(),
            )
        });
    }
}

pub(super) fn rust_pattern_binding_names(
    pattern: &Pat,
    names: &mut Vec<String>,
    unit_variants: &HashMap<String, String>,
) {
    match pattern {
        Pat::Ident(identifier) if unit_variant_pattern(identifier, unit_variants).is_none() => {
            names.push(identifier.ident.to_string());
            if let Some((_, subpattern)) = &identifier.subpat {
                rust_pattern_binding_names(subpattern, names, unit_variants);
            }
        }
        Pat::Type(typed) => rust_pattern_binding_names(&typed.pat, names, unit_variants),
        Pat::Reference(reference) => {
            rust_pattern_binding_names(&reference.pat, names, unit_variants);
        }
        Pat::Paren(paren) => rust_pattern_binding_names(&paren.pat, names, unit_variants),
        Pat::Tuple(tuple) => {
            for pattern in &tuple.elems {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        Pat::TupleStruct(tuple) => {
            for pattern in &tuple.elems {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        Pat::Struct(struct_) => {
            for field in &struct_.fields {
                rust_pattern_binding_names(&field.pat, names, unit_variants);
            }
        }
        Pat::Slice(slice) => {
            for pattern in &slice.elems {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        Pat::Or(or_) => {
            for pattern in &or_.cases {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        _ => {}
    }
}

fn unit_variant_pattern<'a>(
    identifier: &syn::PatIdent,
    unit_variants: &'a HashMap<String, String>,
) -> Option<&'a str> {
    (identifier.by_ref.is_none() && identifier.mutability.is_none() && identifier.subpat.is_none())
        .then(|| unit_variants.get(&identifier.ident.to_string()))
        .flatten()
        .map(String::as_str)
}

pub(super) fn restore_scope_bindings(state: &mut ValueState, saved: ScopedBindings) {
    for (name, (value, commands, closure)) in saved {
        if let Some(value) = value {
            state.values.insert(name.clone(), value);
        } else {
            state.values.remove(&name);
        }
        if let Some(commands) = commands {
            state.commands.insert(name.clone(), commands);
        } else {
            state.commands.remove(&name);
        }
        if let Some(closure) = closure {
            state.closures.insert(name, closure);
        } else {
            state.closures.remove(&name);
        }
    }
}

/// Bind Rust patterns against recovered values and retain branch choice in the bindings.
pub(super) fn bind_rust_pattern(
    pattern: &Pat,
    value: &SemanticValue,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    if let SemanticValueKind::Alias { name: alias, value } = &value.kind
        && is_rust_branch(alias)
    {
        let before = state.values.clone();
        let matched = bind_rust_pattern(
            pattern,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
        if matched {
            for (name, value) in &mut state.values {
                if before.get(name) != Some(value) {
                    *value = rust_branch_value(alias, value.clone());
                }
            }
        }
        return matched;
    }
    if let SemanticValueKind::Union(alternatives) = &value.kind {
        let mut matches = Vec::new();
        for (index, alternative) in alternatives.iter().enumerate() {
            let choice = branch
                .map(|branch| format!("{branch}.{index}"))
                .unwrap_or_else(|| index.to_string());
            let mut alternative_state = state.clone();
            if bind_rust_pattern(
                pattern,
                alternative,
                &mut alternative_state,
                group,
                Some(&choice),
                unit_variants,
                value_limits,
            ) {
                matches.push(alternative_state);
            }
        }
        if matches.is_empty() {
            return false;
        }
        *state = join_value_states(matches, value_limits);
        return true;
    }
    match pattern {
        Pat::Ident(identifier) => {
            if let Some(expected) = unit_variant_pattern(identifier, unit_variants) {
                return variant_properties(value, Some(expected)).is_some()
                    || is_unresolved_value(value);
            }
            let value = branch
                .map(|branch| rust_branch_value(&format!("{group}:{branch}"), value.clone()))
                .unwrap_or_else(|| value.clone());
            state
                .values
                .insert(identifier.ident.to_string(), value.clone());
            if let Some((_, subpattern)) = &identifier.subpat {
                bind_rust_pattern(
                    subpattern,
                    &value,
                    state,
                    group,
                    branch,
                    unit_variants,
                    value_limits,
                )
            } else {
                true
            }
        }
        Pat::Type(typed) => bind_rust_pattern(
            &typed.pat,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::Reference(reference) => bind_rust_pattern(
            &reference.pat,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::Paren(paren) => bind_rust_pattern(
            &paren.pat,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::Tuple(tuple) => bind_pattern_elements(
            &tuple.elems,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::TupleStruct(tuple) => {
            let expected = tuple
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            let Some(properties) = variant_properties(value, expected.as_deref()) else {
                if is_symbolic_value(value) && tuple.elems.len() == 1 {
                    return bind_rust_pattern(
                        &tuple.elems[0],
                        value,
                        state,
                        group,
                        branch,
                        unit_variants,
                        value_limits,
                    );
                }
                return is_unresolved_value(value)
                    && bind_unknown_patterns(
                        tuple.elems.iter(),
                        state,
                        group,
                        branch,
                        unit_variants,
                        value_limits,
                    );
            };
            bind_pattern_properties(
                tuple.elems.iter(),
                properties,
                state,
                group,
                branch,
                unit_variants,
                value_limits,
            )
        }
        Pat::Struct(struct_) => {
            let expected = struct_
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            let Some(properties) = variant_properties(value, expected.as_deref()) else {
                return is_unresolved_value(value)
                    && bind_unknown_patterns(
                        struct_.fields.iter().map(|field| &*field.pat),
                        state,
                        group,
                        branch,
                        unit_variants,
                        value_limits,
                    );
            };
            for field in &struct_.fields {
                let name = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                let field_value = properties
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| SemanticValue::unresolved("field"));
                bind_rust_pattern(
                    &field.pat,
                    &field_value,
                    state,
                    group,
                    branch,
                    unit_variants,
                    value_limits,
                );
            }
            true
        }
        Pat::Path(path) => {
            let expected = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            variant_properties(value, expected.as_deref()).is_some() || is_unresolved_value(value)
        }
        Pat::Or(or_) => or_.cases.iter().any(|case| {
            let mut case_state = state.clone();
            if bind_rust_pattern(
                case,
                value,
                &mut case_state,
                group,
                branch,
                unit_variants,
                value_limits,
            ) {
                *state = case_state;
                true
            } else {
                false
            }
        }),
        Pat::Wild(_) | Pat::Rest(_) => true,
        _ => is_unresolved_value(value),
    }
}

// A failed binding is either a proven variant mismatch or a pattern shape this
// value layer cannot decide. The latter keeps an unresolved match alternative.
pub(super) fn rust_pattern_match_is_ambiguous(
    pattern: &Pat,
    value: &SemanticValue,
    unit_variants: &HashMap<String, String>,
) -> bool {
    match &value.kind {
        SemanticValueKind::Alias { value, .. } => {
            return rust_pattern_match_is_ambiguous(pattern, value, unit_variants);
        }
        SemanticValueKind::Union(alternatives) => {
            return alternatives
                .iter()
                .any(|value| rust_pattern_match_is_ambiguous(pattern, value, unit_variants));
        }
        _ => {}
    }
    match pattern {
        Pat::Type(typed) => rust_pattern_match_is_ambiguous(&typed.pat, value, unit_variants),
        Pat::Reference(reference) => {
            rust_pattern_match_is_ambiguous(&reference.pat, value, unit_variants)
        }
        Pat::Paren(paren) => rust_pattern_match_is_ambiguous(&paren.pat, value, unit_variants),
        Pat::Or(or_) => or_
            .cases
            .iter()
            .any(|case| rust_pattern_match_is_ambiguous(case, value, unit_variants)),
        Pat::Ident(identifier) if unit_variant_pattern(identifier, unit_variants).is_some() => {
            !matches!(value.kind, SemanticValueKind::Object(_))
        }
        Pat::Path(_) | Pat::Struct(_) | Pat::TupleStruct(_)
            if matches!(value.kind, SemanticValueKind::Object(_)) =>
        {
            false
        }
        Pat::Ident(_) | Pat::Wild(_) | Pat::Rest(_) => false,
        _ => true,
    }
}

fn bind_pattern_elements(
    patterns: &syn::punctuated::Punctuated<Pat, syn::Token![,]>,
    value: &SemanticValue,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    let SemanticValueKind::Collection { elements, .. } = &value.kind else {
        return is_unresolved_value(value)
            && bind_unknown_patterns(
                patterns.iter(),
                state,
                group,
                branch,
                unit_variants,
                value_limits,
            );
    };
    for (index, pattern) in patterns.iter().enumerate() {
        let element = elements
            .get(index)
            .cloned()
            .unwrap_or_else(|| SemanticValue::unresolved("collection_element"));
        bind_rust_pattern(
            pattern,
            &element,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
    }
    true
}

fn bind_pattern_properties<'a>(
    patterns: impl Iterator<Item = &'a Pat>,
    properties: &BTreeMap<String, SemanticValue>,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    for (index, pattern) in patterns.enumerate() {
        let value = properties
            .get(&index.to_string())
            .cloned()
            .unwrap_or_else(|| SemanticValue::unresolved("variant_value"));
        bind_rust_pattern(
            pattern,
            &value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
    }
    true
}

pub(super) fn bind_unknown_patterns<'a>(
    patterns: impl Iterator<Item = &'a Pat>,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    for pattern in patterns {
        bind_rust_pattern(
            pattern,
            &SemanticValue::unresolved("value"),
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
    }
    true
}

fn variant_properties<'a>(
    value: &'a SemanticValue,
    expected: Option<&str>,
) -> Option<&'a BTreeMap<String, SemanticValue>> {
    let SemanticValueKind::Object(object) = &value.kind else {
        return None;
    };
    match &object.identity {
        ObjectIdentity::Class { name, .. } if expected.is_none_or(|expected| expected == name) => {
            Some(&object.properties)
        }
        _ => None,
    }
}

pub(in crate::lang::rust) fn match_preserves_scrutinee(
    match_: &syn::ExprMatch,
    unit_variants: &HashMap<String, String>,
) -> bool {
    let mut found_identity = false;
    for arm in &match_.arms {
        if expression_diverges(&arm.body) {
            continue;
        }
        let Some(name) = transparent_value_ident(&arm.body) else {
            return false;
        };
        if !pattern_preserves_value(&arm.pat, &name, unit_variants) {
            return false;
        }
        found_identity = true;
    }
    found_identity
}

fn pattern_preserves_value(
    pattern: &Pat,
    name: &str,
    unit_variants: &HashMap<String, String>,
) -> bool {
    match pattern {
        Pat::Ident(identifier) => {
            unit_variant_pattern(identifier, unit_variants).is_none()
                && identifier.ident == name
                && identifier.subpat.is_none()
        }
        Pat::Type(typed) => pattern_preserves_value(&typed.pat, name, unit_variants),
        Pat::Reference(reference) => pattern_preserves_value(&reference.pat, name, unit_variants),
        Pat::Paren(paren) => pattern_preserves_value(&paren.pat, name, unit_variants),
        Pat::TupleStruct(tuple) => {
            matches!(
                tuple.path.segments.last().map(|segment| segment.ident.to_string()),
                Some(variant) if matches!(variant.as_str(), "Ok" | "Some")
            ) && tuple.elems.len() == 1
                && pattern_preserves_value(&tuple.elems[0], name, unit_variants)
        }
        _ => false,
    }
}
