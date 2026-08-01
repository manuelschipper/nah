//! Lowers destructive Git operations and metadata effects; it does not choose a verdict.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::Platform;

use crate::bash_git_config::{ParsedGit, parse};
use crate::shell_word::static_word;

pub(crate) fn command_operation(program: &str, arguments: &[Word]) -> Option<&'static str> {
    if program != "git" {
        return None;
    }
    let parsed = parse(arguments);
    let (subcommand, arguments) = parsed.command()?;
    if has_help(subcommand, arguments)
        || option_before_separator(arguments, "--version")
        || has_no_side_effect(subcommand, arguments)
    {
        return None;
    }
    match subcommand {
        "push" if force_push(arguments) => Some("force-push"),
        "reset" if option_before_separator(arguments, "--hard") => Some("hard-reset"),
        "filter-repo" if option_before_separator(arguments, "--force") => Some("rewrite-force"),
        "filter-branch"
            if option_before_separator(arguments, "--force")
                || short_option_before_separator(arguments, 'f') =>
        {
            Some("rewrite-force")
        }
        "gc" if gc_destroys_recovery(&parsed, arguments) => Some("recovery-destroy"),
        "prune" if immediate_expiry(arguments, "--expire") => Some("recovery-destroy"),
        "reflog" if destroys_all_reflog_recovery(arguments) => Some("recovery-destroy"),
        _ => None,
    }
}

pub(crate) fn metadata_mutation(
    requested: &str,
    operation: FilesystemOperation,
    recursive: bool,
    platform: Platform,
) -> bool {
    if !matches!(
        operation,
        FilesystemOperation::Write | FilesystemOperation::Delete
    ) {
        return false;
    }
    let path = if platform == Platform::Windows {
        requested.replace('\\', "/").to_ascii_lowercase()
    } else {
        requested.replace('\\', "/")
    };
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    let Some(index) = components
        .iter()
        .position(|component| *component == ".git" || component.ends_with(".git"))
    else {
        return false;
    };
    let dot_git = components[index] == ".git";
    let Some(first) = components.get(index + 1) else {
        return dot_git || operation == FilesystemOperation::Delete && recursive;
    };
    if matches!(
        *first,
        "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
    ) {
        return true;
    }
    if matches!(*first, "*" | "**" | "{*,.*}") {
        return true;
    }
    first
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .is_some_and(|choices| {
            choices.split(',').any(|choice| {
                matches!(
                    choice,
                    "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
                )
            })
        })
}

fn force_push(arguments: &[Word]) -> bool {
    let mut before_separator = true;
    let mut explicit_force = false;
    let mut all_refs_leased = false;
    let mut leased_refs = Vec::new();
    let mut forced_refs = Vec::new();
    for argument in arguments
        .iter()
        .filter_map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
    {
        if argument == "--" {
            before_separator = false;
            continue;
        }
        if before_separator {
            explicit_force |= matches!(argument.as_str(), "--force" | "--mirror")
                || (argument.starts_with('-')
                    && !argument.starts_with("--")
                    && argument[1..].contains('f'));
            all_refs_leased |= argument == "--force-with-lease";
            if let Some(lease) = argument.strip_prefix("--force-with-lease=") {
                leased_refs.push(lease.split(':').next().unwrap_or(lease).to_owned());
            }
        }
        if let Some(refspec) = argument.strip_prefix('+')
            && !refspec.is_empty()
        {
            forced_refs.push(
                refspec
                    .split_once(':')
                    .map_or(refspec, |(_, destination)| destination)
                    .to_owned(),
            );
        }
    }
    explicit_force
        || forced_refs
            .iter()
            .any(|forced| !all_refs_leased && !leased_refs.iter().any(|leased| leased == forced))
}

fn gc_destroys_recovery(parsed: &ParsedGit<'_>, arguments: &[Word]) -> bool {
    enum Prune {
        Default,
        Disabled,
        Value(String),
        Unknown,
    }

    let mut prune = Prune::Default;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            prune = Prune::Unknown;
            index += 1;
            continue;
        };
        if argument == "--" {
            break;
        }
        if argument == "--no-prune" {
            prune = Prune::Disabled;
        } else if argument == "--prune" {
            prune = Prune::Default;
        } else if let Some(value) = argument.strip_prefix("--prune=") {
            prune = Prune::Value(value.to_owned());
        }
        index += 1;
    }
    match prune {
        Prune::Disabled | Prune::Unknown => false,
        Prune::Value(value) => immediate_value(&value),
        Prune::Default => parsed.config("gc.pruneexpire").is_some_and(immediate_value),
    }
}

fn has_no_side_effect(subcommand: &str, arguments: &[Word]) -> bool {
    match subcommand {
        "push" => {
            option_before_separator(arguments, "--dry-run")
                || short_option_before_separator(arguments, 'n')
        }
        "filter-repo" => {
            option_before_separator(arguments, "--dry-run")
                || option_before_separator(arguments, "--analyze")
        }
        "reflog" => option_before_separator(arguments, "--dry-run"),
        "prune" => {
            option_before_separator(arguments, "--dry-run")
                || short_option_before_separator(arguments, 'n')
        }
        _ => false,
    }
}

fn destroys_all_reflog_recovery(arguments: &[Word]) -> bool {
    arguments.first().is_some_and(|argument| {
        static_word(argument.raw(), argument.substitutions().is_empty()).as_deref()
            == Some("expire")
    }) && option_before_separator(arguments, "--all")
        && (immediate_expiry(arguments, "--expire")
            || immediate_expiry(arguments, "--expire-unreachable"))
}

/// Git spells the same immediate expiry three ways.
fn immediate_expiry(arguments: &[Word], option: &str) -> bool {
    enum Value {
        Absent,
        Known(String),
        Unknown,
    }

    let mut value = Value::Absent;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            value = Value::Unknown;
            index += 1;
            continue;
        };
        if argument == "--" {
            break;
        }
        if argument == option {
            match arguments
                .get(index + 1)
                .and_then(|word| static_word(word.raw(), word.substitutions().is_empty()))
            {
                Some(next) => {
                    value = Value::Known(next);
                    index += 1;
                }
                None => value = Value::Unknown,
            }
        } else if let Some(next) = argument
            .strip_prefix(option)
            .and_then(|value| value.strip_prefix('='))
        {
            value = Value::Known(next.to_owned());
        }
        index += 1;
    }
    matches!(value, Value::Known(value) if immediate_value(&value))
}

fn immediate_value(value: &str) -> bool {
    value.eq_ignore_ascii_case("now") || matches!(value, "all" | "0")
}

fn option_before_separator(arguments: &[Word], option: &str) -> bool {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument.as_deref() != Some("--"))
        .flatten()
        .any(|argument| argument == option)
}

fn short_option_before_separator(arguments: &[Word], option: char) -> bool {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument.as_deref() != Some("--"))
        .flatten()
        .any(|argument| {
            argument.starts_with('-')
                && !argument.starts_with("--")
                && argument[1..].contains(option)
        })
}

fn has_help(subcommand: &str, arguments: &[Word]) -> bool {
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            index += 1;
            continue;
        };
        if argument == "--" {
            return false;
        }
        if matches!(argument, "-h" | "--help") {
            return true;
        }
        if argument.starts_with("--")
            && !argument.contains('=')
            && values
                .get(index + 1)
                .and_then(Option::as_deref)
                .is_some_and(|next| matches!(next, "-h" | "--help"))
            && !git_switch_option(subcommand, argument)
        {
            return false;
        }
        index += 1;
    }
    false
}

fn git_switch_option(subcommand: &str, argument: &str) -> bool {
    match subcommand {
        "push" => matches!(
            argument,
            "--force"
                | "--force-with-lease"
                | "--mirror"
                | "--dry-run"
                | "--delete"
                | "--prune"
                | "--porcelain"
                | "--atomic"
                | "--no-verify"
        ),
        "reset" => matches!(
            argument,
            "--hard" | "--soft" | "--mixed" | "--merge" | "--keep"
        ),
        "filter-repo" => matches!(argument, "--force" | "--dry-run" | "--analyze"),
        "filter-branch" => matches!(argument, "--force"),
        "gc" => matches!(argument, "--aggressive" | "--auto" | "--quiet"),
        "prune" => matches!(argument, "--dry-run" | "--verbose" | "--progress"),
        "reflog" => matches!(
            argument,
            "--all" | "--dry-run" | "--verbose" | "--single-worktree"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_paths_are_compared_after_lexical_normalization() {
        for path in ["/repo/.git//objects/aa", "/repo/.git/tmp/../objects/aa"] {
            for operation in [FilesystemOperation::Write, FilesystemOperation::Delete] {
                assert!(metadata_mutation(path, operation, false, Platform::Linux));
            }
        }
        assert!(!metadata_mutation(
            "/repo/.git/objects/../index",
            FilesystemOperation::Delete,
            true,
            Platform::Linux
        ));
        assert!(metadata_mutation(
            "/repo/backup.git",
            FilesystemOperation::Delete,
            true,
            Platform::Linux
        ));
        assert!(!metadata_mutation(
            "/repo/backup.git",
            FilesystemOperation::Delete,
            false,
            Platform::Linux
        ));
    }
}
