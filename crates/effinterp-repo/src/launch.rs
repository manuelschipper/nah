//! Composition of deferred process-launch effects.
//!
//! Rust `Command` values retain symbolic executable and argument branches
//! until repository composition supplies caller and package bindings.

use std::collections::{BTreeMap, HashMap};

use effinterp_engine::{RUST_DEFERRED_COMMAND, SemanticValue, SemanticValueKind, substitute_value};
use effinterp_proto::{
    Effect, Modality, PathPlatform, ResourceExpr, ResourceFamily, ResourceIdentity,
    normalize_resource,
};

use crate::compose::cap_depth;

/// A deferred `Command` the Rust frontend left for composition to resolve: the
/// executable and the arguments are still expressions in `argv`. The frontend
/// names the effect with an explicit marker, so a process effect from any other
/// producer is never claimed by this shape.
pub(crate) fn is_process_template(effect: &Effect) -> bool {
    matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, argv, .. },
        } if executable == RUST_DEFERRED_COMMAND && !argv.is_empty()
    )
}

pub(crate) fn specialize_process_template_with_bindings(
    effect: &Effect,
    bindings: &HashMap<String, SemanticValue>,
    value_limits: effinterp_engine::ValueLimits,
) -> Option<(Vec<Effect>, bool)> {
    if !is_process_template(effect) {
        return None;
    }
    let value = substitute_value(
        &restore_rust_process_branches(SemanticValue::from(&effect.resource)),
        bindings,
        value_limits,
    );
    let SemanticValueKind::Process { argv, cwd, .. } = value.kind else {
        return None;
    };
    let (head, arguments) = argv.split_first()?;
    let heads = rust_process_value_alternatives(head);
    let (argument_sets, mut widened) = expand_rust_process_arguments(arguments, value_limits);
    let limit = value_limits.max_cardinality;
    let mut specializations = Vec::new();
    'heads: for head in heads {
        let mut head_branch_tags = BTreeMap::new();
        rust_process_branch_tags(&head, &mut head_branch_tags);
        for arguments in &argument_sets {
            if !rust_process_branch_tags_compatible(&head_branch_tags, &arguments.branch_tags) {
                continue;
            }
            let exact_limit = limit.saturating_sub(usize::from(widened));
            if specializations.len() >= exact_limit {
                if !widened {
                    widened = true;
                    specializations.truncate(limit.saturating_sub(1));
                }
                break 'heads;
            }
            let mut specialized = effect.clone();
            specialized.modality = Modality::May;
            specialized.request_assurance = effinterp_proto::RequestAssurance::Conservative;
            specialized.resource = match rust_process_word(&head) {
                Some(argv0) if !argv0.is_empty() => ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable: argv0.rsplit('/').next().unwrap_or(&argv0).to_string(),
                        path: argv0
                            .contains('/')
                            .then(|| effinterp_proto::normalize_path(&argv0, PathPlatform::Posix)),
                        argv: arguments.values.iter().map(rust_process_argument).collect(),
                        cwd: cwd
                            .as_deref()
                            .map(SemanticValue::lower_resource)
                            .map(Box::new),
                    },
                },
                _ => ResourceExpr::Unresolved {
                    family: ResourceFamily::new("process"),
                },
            };
            specialized.resource =
                normalize_resource(cap_depth(specialized.resource), PathPlatform::Posix);
            specializations.push(specialized);
        }
    }
    if widened {
        let mut specialized = effect.clone();
        specialized.modality = Modality::May;
        specialized.request_assurance = effinterp_proto::RequestAssurance::Conservative;
        specialized.resource = ResourceExpr::Unresolved {
            family: ResourceFamily::new("process"),
        };
        specializations.push(specialized);
    }
    Some((specializations, widened))
}

#[derive(Clone, Default)]
struct RustProcessArgumentSet {
    values: Vec<SemanticValue>,
    branch_tags: BTreeMap<String, String>,
}

fn restore_rust_process_branches(value: SemanticValue) -> SemanticValue {
    let evidence = value.evidence;
    let kind = match value.kind {
        SemanticValueKind::Process {
            executable,
            path,
            argv,
            cwd,
        } => SemanticValueKind::Process {
            executable,
            path,
            argv: argv
                .into_iter()
                .map(restore_rust_process_branches)
                .collect(),
            cwd: cwd.map(|value| Box::new(restore_rust_process_branches(*value))),
        },
        SemanticValueKind::Union(alternatives) => SemanticValueKind::Union(
            alternatives
                .into_iter()
                .map(restore_rust_process_branches)
                .collect(),
        ),
        SemanticValueKind::Property { base, name } => SemanticValueKind::Property {
            base: Box::new(restore_rust_process_branches(*base)),
            name,
        },
        SemanticValueKind::Join(parts) => {
            if let [marker, name, inner] = parts.as_slice()
                && matches!(&marker.kind, SemanticValueKind::Literal(marker) if marker == "__effinterp_rust_branch")
                && let SemanticValueKind::Literal(name) = &name.kind
                && name.starts_with("__effinterp_rust_branch:")
            {
                return SemanticValue {
                    kind: SemanticValueKind::Alias {
                        name: name.clone(),
                        value: Box::new(restore_rust_process_branches(inner.clone())),
                    },
                    evidence,
                };
            }
            SemanticValueKind::Join(
                parts
                    .into_iter()
                    .map(restore_rust_process_branches)
                    .collect(),
            )
        }
        kind => kind,
    };
    SemanticValue { kind, evidence }
}

fn expand_rust_process_arguments(
    arguments: &[SemanticValue],
    value_limits: effinterp_engine::ValueLimits,
) -> (Vec<RustProcessArgumentSet>, bool) {
    let mut out = vec![RustProcessArgumentSet::default()];
    let mut widened = false;
    let limit = value_limits.max_cardinality;
    for argument in arguments {
        let alternatives = rust_process_argument_alternatives(argument);
        let mut expanded = Vec::new();
        'prefixes: for prefix in &out {
            for alternative in &alternatives {
                if !rust_process_branch_tags_compatible(
                    &prefix.branch_tags,
                    &alternative.branch_tags,
                ) {
                    continue;
                }
                let exact_limit = limit.saturating_sub(usize::from(widened));
                if expanded.len() >= exact_limit {
                    if !widened {
                        widened = true;
                        expanded.truncate(limit.saturating_sub(1));
                    }
                    break 'prefixes;
                }
                let mut candidate = prefix.clone();
                candidate.values.extend(alternative.values.clone());
                candidate
                    .branch_tags
                    .extend(alternative.branch_tags.clone());
                expanded.push(candidate);
            }
        }
        out = expanded;
    }
    (out, widened)
}

fn rust_process_argument_alternatives(value: &SemanticValue) -> Vec<RustProcessArgumentSet> {
    if let SemanticValueKind::Join(parts) = &value.kind
        && let [marker, value] = parts.as_slice()
        && matches!(&marker.kind, SemanticValueKind::Literal(marker) if marker == "__effinterp_rust_args")
    {
        return rust_process_spread_alternatives(value);
    }
    rust_process_value_alternatives(value)
        .into_iter()
        .map(|alternative| rust_process_argument_set(vec![alternative]))
        .collect()
}

fn rust_process_value_alternatives(value: &SemanticValue) -> Vec<SemanticValue> {
    match &value.kind {
        SemanticValueKind::Union(alternatives) => alternatives
            .iter()
            .flat_map(rust_process_value_alternatives)
            .collect(),
        SemanticValueKind::Alias { name, value }
            if name.starts_with("__effinterp_rust_branch:") =>
        {
            rust_process_value_alternatives(value)
                .into_iter()
                .map(|value| {
                    SemanticValue::new(SemanticValueKind::Alias {
                        name: name.clone(),
                        value: Box::new(value),
                    })
                })
                .collect()
        }
        _ => vec![value.clone()],
    }
}

fn rust_process_spread_alternatives(value: &SemanticValue) -> Vec<RustProcessArgumentSet> {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => {
            vec![rust_process_argument_set(elements.clone())]
        }
        SemanticValueKind::Union(alternatives) => alternatives
            .iter()
            .flat_map(rust_process_spread_alternatives)
            .collect(),
        SemanticValueKind::Alias { name, value }
            if name.starts_with("__effinterp_rust_branch:") =>
        {
            rust_process_spread_alternatives(value)
                .into_iter()
                .map(|mut arguments| {
                    insert_rust_process_branch_tag(name, &mut arguments.branch_tags);
                    arguments.values = arguments
                        .values
                        .into_iter()
                        .map(|element| {
                            SemanticValue::new(SemanticValueKind::Alias {
                                name: name.clone(),
                                value: Box::new(element),
                            })
                        })
                        .collect();
                    arguments
                })
                .collect()
        }
        _ => vec![rust_process_argument_set(vec![SemanticValue::unresolved(
            "process",
        )])],
    }
}

fn rust_process_argument_set(values: Vec<SemanticValue>) -> RustProcessArgumentSet {
    let mut branch_tags = BTreeMap::new();
    for value in &values {
        rust_process_branch_tags(value, &mut branch_tags);
    }
    RustProcessArgumentSet {
        values,
        branch_tags,
    }
}

fn insert_rust_process_branch_tag(name: &str, tags: &mut BTreeMap<String, String>) {
    if let Some(branch) = name.strip_prefix("__effinterp_rust_branch:")
        && let Some((group, choice)) = branch.rsplit_once(':')
    {
        tags.insert(group.to_string(), choice.to_string());
    }
}

fn rust_process_branch_tags(value: &SemanticValue, tags: &mut BTreeMap<String, String>) {
    if let SemanticValueKind::Alias { name, value } = &value.kind {
        insert_rust_process_branch_tag(name, tags);
        rust_process_branch_tags(value, tags);
    }
}

fn rust_process_branch_tags_compatible(
    left_tags: &BTreeMap<String, String>,
    right_tags: &BTreeMap<String, String>,
) -> bool {
    right_tags.iter().all(|(group, choice)| {
        left_tags
            .get(group)
            .is_none_or(|left_choice| left_choice == choice)
    })
}

fn rust_process_word(value: &SemanticValue) -> Option<String> {
    match &value.kind {
        SemanticValueKind::Literal(value) | SemanticValueKind::Executable(value) => {
            Some(value.clone())
        }
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } => Some(value.clone()),
        SemanticValueKind::Alias { value, .. } => rust_process_word(value),
        _ => None,
    }
}

fn rust_process_argument(value: &SemanticValue) -> ResourceExpr {
    match &value.kind {
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } => ResourceExpr::Literal {
            value: value.clone(),
        },
        _ => value.lower_resource(),
    }
}
