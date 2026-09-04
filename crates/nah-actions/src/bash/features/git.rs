//! Lowers destructive Git operations and metadata effects; it does not choose a verdict.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::Platform;

use crate::bash_git_config::git_boolean;
use crate::bash_git_config::{ParsedGit, parse};
use crate::bash_git_operations::clean_options;
use crate::shell_word::static_word;

pub(crate) fn command_operation(program: &str, arguments: &[Word]) -> Option<&'static str> {
    if program != "git" {
        return None;
    }
    let parsed = parse(arguments);
    let (subcommand, arguments) = parsed.command()?;
    if (!matches!(subcommand, "clean" | "checkout" | "switch") && has_help(subcommand, arguments))
        || option_before_separator(arguments, "--version")
        || has_no_side_effect(subcommand, arguments)
    {
        return None;
    }
    match subcommand {
        "clean" if clean_force(&parsed, arguments) => Some("clean-force"),
        "checkout" if forced_checkout(arguments) => Some("worktree-discard"),
        "switch" if forced_switch(arguments) => Some("worktree-discard"),
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
        "rebase" if rebase_rewrites_history(arguments) => Some("history-rewrite"),
        "filter-branch" | "filter-repo" => Some("history-rewrite"),
        "reflog" if reflog_expires(arguments) => Some("history-rewrite"),
        "gc" if gc_rewrites_history(arguments) => Some("history-rewrite"),
        "push" if force_with_lease(arguments) => Some("history-rewrite"),
        _ => None,
    }
}

fn rebase_rewrites_history(arguments: &[Word]) -> bool {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument.as_deref() != Some("--"))
        .flatten()
        .all(|argument| {
            !matches!(
                argument.as_str(),
                "--abort" | "--quit" | "--show-current-patch"
            )
        })
}

fn clean_force(parsed: &ParsedGit<'_>, arguments: &[Word]) -> bool {
    if !parsed.complete() {
        return false;
    }
    let Some(values) = static_values(arguments) else {
        return false;
    };
    let values = values.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(options) = clean_options(&values) else {
        return false;
    };
    !options.terminal
        && !options.dry_run
        && !options.interactive
        && (options.force
            || parsed.config("clean.requireforce").and_then(git_boolean) == Some(false))
}

fn forced_checkout(arguments: &[Word]) -> bool {
    let Some(values) = static_values(arguments) else {
        return false;
    };
    let mut force = false;
    let mut branch_mode = false;
    let mut detach = false;
    let mut merge = false;
    let mut patch = false;
    let mut target = false;
    let mut operands = 0;
    let mut index = 0;
    while index < values.len() {
        let argument = values[index].as_str();
        match argument {
            "--" => return false,
            "--force" => force = true,
            "--no-force" => force = false,
            "--detach" => detach = true,
            "--no-detach" => detach = false,
            "--merge" => merge = true,
            "--no-merge" => merge = false,
            "--patch" => patch = true,
            "--no-patch" => patch = false,
            "--orphan" => {
                index += 1;
                if values.get(index).is_none() {
                    return false;
                }
                branch_mode = true;
                target = true;
            }
            "--quiet"
            | "--no-quiet"
            | "--guess"
            | "--no-guess"
            | "--progress"
            | "--no-progress"
            | "--overwrite-ignore"
            | "--no-overwrite-ignore"
            | "--ignore-other-worktrees"
            | "--no-ignore-other-worktrees" => {}
            "--help"
            | "--version"
            | "--ours"
            | "--theirs"
            | "--pathspec-from-file"
            | "--pathspec-file-nul" => return false,
            argument if argument.starts_with("--orphan=") => {
                branch_mode = true;
                target = argument.len() > "--orphan=".len();
            }
            argument if argument.starts_with("--pathspec-from-file=") => return false,
            argument if argument.starts_with("--conflict") => return false,
            "-" => {
                branch_mode = true;
                target = true;
                operands += 1;
            }
            argument if argument.starts_with('-') && !argument.starts_with("--") => {
                let flags = &argument.as_bytes()[1..];
                let mut position = 0;
                while position < flags.len() {
                    match flags[position] as char {
                        'f' => force = true,
                        'q' | 'l' => {}
                        'd' => detach = true,
                        'p' => patch = true,
                        'b' | 'B' => {
                            branch_mode = true;
                            target = true;
                            if position + 1 == flags.len() {
                                index += 1;
                                if values.get(index).is_none() {
                                    return false;
                                }
                            }
                            break;
                        }
                        _ => return false,
                    }
                    position += 1;
                }
            }
            argument if argument.starts_with('-') => return false,
            _ => {
                target = true;
                operands += 1;
            }
        }
        index += 1;
    }
    force && !merge && !patch && operands <= 1 && (!target || branch_mode || detach)
}

fn forced_switch(arguments: &[Word]) -> bool {
    let Some(values) = static_values(arguments) else {
        return false;
    };
    let mut force = false;
    let mut discard = false;
    let mut merge = false;
    let mut target = false;
    let mut target_option = None;
    let mut operands = 0;
    let mut after_separator = false;
    let mut index = 0;
    while index < values.len() {
        let argument = values[index].as_str();
        if after_separator {
            target = true;
            operands += 1;
            index += 1;
            continue;
        }
        match argument {
            "--" => after_separator = true,
            "--force" => force = true,
            "--no-force" => force = false,
            "--discard-changes" => discard = true,
            "--no-discard-changes" => discard = false,
            "--merge" => merge = true,
            "--no-merge" => merge = false,
            "--quiet"
            | "--no-quiet"
            | "--guess"
            | "--no-guess"
            | "--detach"
            | "--no-detach"
            | "--progress"
            | "--no-progress"
            | "--overwrite-ignore"
            | "--no-overwrite-ignore"
            | "--ignore-other-worktrees"
            | "--no-ignore-other-worktrees" => {}
            "--help" | "--version" => return false,
            "--create" | "--force-create" | "--orphan" => {
                if target_option.is_some() {
                    return false;
                }
                target_option = Some(argument == "--orphan");
                index += 1;
                if values.get(index).is_none() {
                    return false;
                }
                target = true;
            }
            argument
                if argument.starts_with("--create=")
                    || argument.starts_with("--force-create=")
                    || argument.starts_with("--orphan=") =>
            {
                if target_option.is_some() {
                    return false;
                }
                target_option = Some(argument.starts_with("--orphan="));
                target = argument
                    .split_once('=')
                    .is_some_and(|(_, value)| !value.is_empty());
            }
            argument if argument.starts_with("--conflict") => return false,
            "-" => {
                target = true;
                operands += 1;
            }
            argument if argument.starts_with('-') && !argument.starts_with("--") => {
                let flags = &argument.as_bytes()[1..];
                let mut position = 0;
                while position < flags.len() {
                    match flags[position] as char {
                        'f' => force = true,
                        'q' | 'd' => {}
                        'c' | 'C' => {
                            if target_option.is_some() {
                                return false;
                            }
                            target_option = Some(false);
                            target = true;
                            if position + 1 == flags.len() {
                                index += 1;
                                if values.get(index).is_none() {
                                    return false;
                                }
                            }
                            break;
                        }
                        _ => return false,
                    }
                    position += 1;
                }
            }
            argument if argument.starts_with('-') => return false,
            _ => {
                target = true;
                operands += 1;
            }
        }
        index += 1;
    }
    let valid_operands = match target_option {
        Some(true) => operands == 0,
        Some(false) => operands <= 1,
        None => operands == 1,
    };
    target && !merge && valid_operands && (force || discard)
}

fn static_values(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
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
    let mut explicit_force = false;
    let mut mirror = false;
    let mut all_refs_leased = false;
    let mut leased_refs = Vec::new();
    let mut forced_refs = Vec::new();
    let mut before_separator = true;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            index += 1;
            continue;
        };
        if argument == "--" {
            before_separator = false;
            index += 1;
            continue;
        }
        if before_separator {
            if push_option_takes_value(&argument) {
                index += 2;
                continue;
            }
            match argument.as_str() {
                "--force" => explicit_force = true,
                "--no-force" => explicit_force = false,
                "--mirror" => mirror = true,
                "--no-mirror" => mirror = false,
                "--force-with-lease" => all_refs_leased = true,
                "--no-force-with-lease" => {
                    all_refs_leased = false;
                    leased_refs.clear();
                }
                argument if argument.starts_with('-') && !argument.starts_with("--") => {
                    explicit_force |= argument[1..].contains('f');
                }
                _ => {}
            }
            if let Some(lease) = argument
                .strip_prefix("--force-with-lease=")
                .filter(|lease| !lease.is_empty())
            {
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
        index += 1;
    }
    explicit_force
        || mirror
        || forced_refs
            .iter()
            .any(|forced| !all_refs_leased && !leased_refs.iter().any(|leased| leased == forced))
}

fn force_with_lease(arguments: &[Word]) -> bool {
    let mut enabled = false;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            index += 1;
            continue;
        };
        if argument == "--" {
            break;
        }
        if push_option_takes_value(&argument) {
            index += 2;
            continue;
        }
        if argument == "--force-with-lease"
            || argument
                .strip_prefix("--force-with-lease=")
                .is_some_and(|value| !value.is_empty())
        {
            enabled = true;
        } else if argument == "--no-force-with-lease" {
            enabled = false;
        }
        index += 1;
    }
    enabled
}

fn push_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--repo" | "--receive-pack" | "--exec" | "--recurse-submodules" | "-o" | "--push-option"
    )
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

fn gc_rewrites_history(arguments: &[Word]) -> bool {
    let mut aggressive = false;
    let mut non_immediate_prune = false;
    for word in arguments {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            aggressive = false;
            non_immediate_prune = false;
            continue;
        };
        if argument == "--" {
            break;
        }
        match argument.as_str() {
            "--aggressive" => aggressive = true,
            "--no-aggressive" => aggressive = false,
            "--prune" | "--no-prune" => non_immediate_prune = false,
            argument if argument.starts_with("--prune=") => {
                let value = argument
                    .strip_prefix("--prune=")
                    .expect("matched prune value");
                non_immediate_prune = !value.is_empty() && !immediate_value(value);
            }
            _ => {}
        }
    }
    aggressive || non_immediate_prune
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
        "reflog" => {
            option_before_separator(arguments, "--dry-run")
                || short_option_before_separator(arguments, 'n')
        }
        "prune" => {
            option_before_separator(arguments, "--dry-run")
                || short_option_before_separator(arguments, 'n')
        }
        _ => false,
    }
}

fn destroys_all_reflog_recovery(arguments: &[Word]) -> bool {
    reflog_expires(arguments)
        && option_before_separator(arguments, "--all")
        && (immediate_expiry(arguments, "--expire")
            || immediate_expiry(arguments, "--expire-unreachable"))
}

fn reflog_expires(arguments: &[Word]) -> bool {
    arguments.first().is_some_and(|argument| {
        static_word(argument.raw(), argument.substitutions().is_empty()).as_deref()
            == Some("expire")
    })
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
