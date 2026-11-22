//! Rust Command candidates preserve argument choices from the same branch.

use std::collections::BTreeMap;

use syn::Expr;

use super::{
    RustValueAnalyzer, ValueState, collection_value, invalidate_value_binding, is_rust_branch,
    join_live_values, rust_branch_value,
};
use crate::lang::rust::model::rust_unwalked_call_value;
use crate::lang::rust::syntax::{chain_base_ident, path_segments, single_ident};
use crate::{SemanticValue, SemanticValueKind};

#[derive(Clone, Default, PartialEq, Eq)]
pub(in crate::lang::rust) struct RustCommandCandidates {
    pub(in crate::lang::rust) values: Vec<Vec<SemanticValue>>,
    pub(in crate::lang::rust) cwd: Option<SemanticValue>,
    pub(in crate::lang::rust) widened: bool,
}

pub(in crate::lang::rust) fn command_method_preserves_executable_and_argv(method: &str) -> bool {
    matches!(
        method,
        "env"
            | "envs"
            | "env_clear"
            | "env_remove"
            | "current_dir"
            | "stdin"
            | "stdout"
            | "stderr"
            | "uid"
            | "gid"
            | "groups"
            | "process_group"
    )
}

fn command_heads(value: &SemanticValue, value_limits: crate::ValueLimits) -> RustCommandCandidates {
    let mut commands = RustCommandCandidates::default();
    match &value.kind {
        SemanticValueKind::Union(alternatives) => {
            for alternative in alternatives {
                let branch = command_heads(alternative, value_limits);
                commands.values.extend(branch.values);
                commands.widened |= branch.widened;
            }
        }
        _ => commands.values.push(vec![value.clone()]),
    }
    dedup_commands(&mut commands, value_limits);
    commands
}

pub(super) fn merge_command_cwds(
    left: Option<SemanticValue>,
    right: Option<SemanticValue>,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    match (left, right) {
        (Some(left), Some(right)) => Some(join_live_values([left, right], value_limits)),
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(join_live_values(
            [value, SemanticValue::unresolved("command_cwd")],
            value_limits,
        )),
    }
}

fn rust_branch_tags(value: &SemanticValue, tags: &mut BTreeMap<String, String>) {
    if let SemanticValueKind::Alias { name, value } = &value.kind {
        if let Some(branch) = name.strip_prefix("__effinterp_rust_branch:")
            && let Some((group, choice)) = branch.rsplit_once(':')
        {
            tags.insert(group.to_string(), choice.to_string());
        }
        rust_branch_tags(value, tags);
    }
}

fn command_branch_compatible(command: &[SemanticValue], value: &SemanticValue) -> bool {
    let mut command_tags = BTreeMap::new();
    for word in command {
        rust_branch_tags(word, &mut command_tags);
    }
    let mut value_tags = BTreeMap::new();
    rust_branch_tags(value, &mut value_tags);
    value_tags.iter().all(|(group, choice)| {
        command_tags
            .get(group)
            .is_none_or(|command_choice| command_choice == choice)
    })
}

pub(super) fn append_command_argument(
    commands: &mut RustCommandCandidates,
    value: &SemanticValue,
    value_limits: crate::ValueLimits,
) {
    let alternatives = match &value.kind {
        SemanticValueKind::Union(alternatives) => alternatives.clone(),
        _ => vec![value.clone()],
    };
    let mut expanded = Vec::new();
    for command in &commands.values {
        for alternative in &alternatives {
            if !command_branch_compatible(command, alternative) {
                continue;
            }
            let mut command = command.clone();
            command.push(alternative.clone());
            expanded.push(command);
        }
    }
    commands.values = expanded;
    dedup_commands(commands, value_limits);
}

pub(super) fn append_command_arguments(
    commands: &mut RustCommandCandidates,
    value: &SemanticValue,
    value_limits: crate::ValueLimits,
) {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => {
            for element in elements {
                append_command_argument(commands, element, value_limits);
            }
        }
        SemanticValueKind::Union(alternatives) => {
            let original = commands.clone();
            let mut expanded = RustCommandCandidates {
                values: Vec::new(),
                cwd: original.cwd.clone(),
                widened: original.widened,
            };
            for alternative in alternatives {
                let mut branch = RustCommandCandidates {
                    values: original
                        .values
                        .iter()
                        .filter(|command| command_branch_compatible(command, alternative))
                        .cloned()
                        .collect(),
                    cwd: original.cwd.clone(),
                    widened: false,
                };
                append_command_arguments(&mut branch, alternative, value_limits);
                expanded.values.extend(branch.values);
                expanded.widened |= branch.widened;
            }
            *commands = expanded;
            dedup_commands(commands, value_limits);
        }
        SemanticValueKind::Alias {
            name: branch,
            value,
        } if is_rust_branch(branch) => match &value.kind {
            SemanticValueKind::Collection { elements, .. } => {
                commands.values.retain(|command| {
                    command_branch_compatible(
                        command,
                        &rust_branch_value(branch, value.as_ref().clone()),
                    )
                });
                for element in elements {
                    append_command_argument(
                        commands,
                        &rust_branch_value(branch, element.clone()),
                        value_limits,
                    );
                }
            }
            SemanticValueKind::Union(alternatives) => {
                append_command_arguments(
                    commands,
                    &SemanticValue::new(SemanticValueKind::Union(
                        alternatives
                            .iter()
                            .cloned()
                            .map(|value| rust_branch_value(branch, value))
                            .collect(),
                    )),
                    value_limits,
                );
            }
            SemanticValueKind::Alias { name, .. } if is_rust_branch(name) => {
                append_command_arguments(commands, value, value_limits);
            }
            _ => {
                commands.values.retain(|command| {
                    command_branch_compatible(
                        command,
                        &rust_branch_value(branch, value.as_ref().clone()),
                    )
                });
                let spread = SemanticValue::new(SemanticValueKind::Alias {
                    name: "rust_args".to_string(),
                    value: Box::new(rust_branch_value(branch, value.as_ref().clone())),
                });
                for command in &mut commands.values {
                    command.push(spread.clone());
                }
            }
        },
        _ => {
            let spread = SemanticValue::new(SemanticValueKind::Alias {
                name: "rust_args".to_string(),
                value: Box::new(value.clone()),
            });
            for command in &mut commands.values {
                command.push(spread.clone());
            }
        }
    }
}

pub(super) fn dedup_commands(
    commands: &mut RustCommandCandidates,
    value_limits: crate::ValueLimits,
) {
    commands
        .values
        .sort_by_key(|command| format!("{command:?}"));
    commands.values.dedup();
    let limit = value_limits.max_cardinality;
    if commands.values.len() > limit {
        commands.widened = true;
    }
    if commands.widened {
        commands.values.truncate(limit.saturating_sub(1));
    }
}

pub(super) fn command_marker(commands: RustCommandCandidates) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Alias {
        name: "rust_command".to_string(),
        value: Box::new(collection_value(
            commands
                .values
                .into_iter()
                .map(collection_value)
                .collect::<Vec<_>>(),
        )),
    })
}

pub(super) fn bound_command_chain_appends_arguments(expr: &Expr, state: &ValueState) -> bool {
    match expr {
        Expr::MethodCall(call) => {
            (matches!(call.method.to_string().as_str(), "arg" | "args")
                && chain_base_ident(&call.receiver)
                    .is_some_and(|name| state.commands.contains_key(&name)))
                || bound_command_chain_appends_arguments(&call.receiver, state)
        }
        Expr::Reference(reference) => bound_command_chain_appends_arguments(&reference.expr, state),
        Expr::Paren(paren) => bound_command_chain_appends_arguments(&paren.expr, state),
        Expr::Group(group) => bound_command_chain_appends_arguments(&group.expr, state),
        Expr::Try(try_) => bound_command_chain_appends_arguments(&try_.expr, state),
        _ => false,
    }
}

pub(super) fn invalidate_command_alias_source(expr: &Expr, binding: &str, state: &mut ValueState) {
    let source = match expr {
        Expr::MethodCall(call)
            if !matches!(
                call.method.to_string().as_str(),
                "spawn" | "output" | "status"
            ) =>
        {
            chain_base_ident(&call.receiver)
        }
        Expr::Path(path) => single_ident(&path.path),
        Expr::Paren(paren) => {
            invalidate_command_alias_source(&paren.expr, binding, state);
            return;
        }
        Expr::Group(group) => {
            invalidate_command_alias_source(&group.expr, binding, state);
            return;
        }
        Expr::Try(try_) => {
            invalidate_command_alias_source(&try_.expr, binding, state);
            return;
        }
        _ => None,
    };
    if let Some(source) = source
        && source != binding
        && state.commands.contains_key(&source)
    {
        invalidate_value_binding(state, &source);
    }
}

impl RustValueAnalyzer<'_, '_> {
    /// Recover command candidates only if the receiver chain starts at a known Command.
    pub(super) fn command_candidates(
        &mut self,
        expr: &Expr,
        state: &mut ValueState,
    ) -> Option<RustCommandCandidates> {
        match expr {
            Expr::Path(path) => {
                single_ident(&path.path).and_then(|name| state.commands.get(&name).cloned())
            }
            Expr::Reference(reference) => self.command_candidates(&reference.expr, state),
            Expr::Paren(paren) => self.command_candidates(&paren.expr, state),
            Expr::Group(group) => self.command_candidates(&group.expr, state),
            Expr::Try(try_) => self.command_candidates(&try_.expr, state),
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                let mut commands = self.command_candidates(&call.receiver, state)?;
                match method.as_str() {
                    "arg" => {
                        if let Some(argument) = call.args.first() {
                            let value = self.expr(argument, state);
                            append_command_argument(&mut commands, &value, self.value_limits);
                        }
                    }
                    "args" => {
                        if let Some(argument) = call.args.first() {
                            let value = self.expr(argument, state);
                            append_command_arguments(&mut commands, &value, self.value_limits);
                        }
                    }
                    "current_dir" => {
                        if let Some(argument) = call.args.first() {
                            let value = self.expr(argument, state);
                            commands.cwd = Some(rust_unwalked_call_value(argument, value));
                        }
                    }
                    method if command_method_preserves_executable_and_argv(method) => {}
                    _ => return None,
                }
                Some(commands)
            }
            Expr::Call(call) => {
                let segments = path_segments(&call.func)?;
                (self.uses.resolve_use_path(&segments) == "std::process::Command::new").then(|| {
                    call.args
                        .first()
                        .map(|argument| {
                            command_heads(&self.expr(argument, state), self.value_limits)
                        })
                        .unwrap_or_else(|| RustCommandCandidates {
                            values: vec![vec![SemanticValue::unresolved("process")]],
                            cwd: None,
                            widened: false,
                        })
                })
            }
            _ => None,
        }
    }
}
