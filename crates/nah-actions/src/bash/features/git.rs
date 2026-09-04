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
        "push" => push_operation(arguments),
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

fn push_operation(arguments: &[Word]) -> Option<&'static str> {
    let mut before_separator = true;
    let mut explicit_force = false;
    let mut all_refs_leased = false;
    let mut leased_refs = Vec::new();
    let mut forced_refs = Vec::new();
    let mut repository = false;
    let mut delete = false;
    let mut all = false;
    let mut protected_destination = false;
    let mut protected_parse = true;
    let mut dry_run = false;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            if before_separator {
                protected_parse = false;
            } else if protected_parse && !repository {
                repository = true;
            }
            index += 1;
            continue;
        };
        if argument == "--" {
            before_separator = false;
            index += 1;
            continue;
        }
        if before_separator && push_option_takes_value(&argument) {
            if arguments.get(index + 1).is_none() {
                protected_parse = false;
            }
            repository |= argument == "--repo";
            index += 2;
            continue;
        }
        if before_separator && push_short_option_takes_value(&argument) {
            explicit_force |= push_short_switch(&argument, 'f');
            dry_run |= push_short_switch(&argument, 'n');
            index += 2;
            continue;
        }
        if before_separator {
            explicit_force |= matches!(argument.as_str(), "--force" | "--mirror")
                || push_short_switch(&argument, 'f');
            dry_run |= argument == "--dry-run" || push_short_switch(&argument, 'n');
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
        if protected_parse && before_separator {
            if argument.starts_with("--repo=") {
                repository = true;
                index += 1;
                continue;
            }
            if [
                "--receive-pack=",
                "--exec=",
                "--recurse-submodules=",
                "--push-option=",
            ]
            .iter()
            .any(|option| argument.starts_with(option))
            {
                index += 1;
                continue;
            }
            match argument.as_str() {
                "--all" | "--branches" => all = true,
                "--no-all" | "--no-branches" => all = false,
                "--delete" => delete = true,
                "--no-delete" => delete = false,
                argument
                    if push_switch_option(argument)
                        || argument.starts_with("--force-with-lease=")
                        || argument.starts_with("--signed=") => {}
                argument if argument.starts_with("--") => protected_parse = false,
                argument if argument.starts_with('-') && argument != "-" => {
                    let flags = &argument.as_bytes()[1..];
                    let mut position = 0;
                    while position < flags.len() {
                        match flags[position] as char {
                            'd' => delete = true,
                            'v' | 'q' | 'n' | 'f' | 'u' | '4' | '6' => {}
                            'o' => {
                                if position + 1 == flags.len() {
                                    if arguments.get(index + 1).is_none() {
                                        protected_parse = false;
                                    }
                                    index += 1;
                                }
                                break;
                            }
                            _ => protected_parse = false,
                        }
                        position += 1;
                    }
                }
                _ if !repository => repository = true,
                _ => protected_destination |= protected_push_refspec(&argument),
            }
            index += 1;
            continue;
        }
        if protected_parse {
            if !repository {
                repository = true;
            } else {
                protected_destination |= protected_push_refspec(&argument);
            }
        }
        index += 1;
    }
    if dry_run {
        return None;
    }
    if explicit_force
        || forced_refs
            .iter()
            .any(|forced| !all_refs_leased && !leased_refs.iter().any(|leased| leased == forced))
    {
        Some("force-push")
    } else if protected_parse && protected_destination && !delete && !all {
        Some("protected-push")
    } else {
        None
    }
}

fn protected_push_refspec(argument: &str) -> bool {
    let refspec = argument.strip_prefix('+').unwrap_or(argument);
    let destination = match refspec.split_once(':') {
        Some(("", _)) => return false,
        Some((_, destination)) => destination,
        None => refspec,
    };
    matches!(
        destination,
        "main" | "master" | "refs/heads/main" | "refs/heads/master"
    )
}

fn push_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--repo" | "--receive-pack" | "--exec" | "--recurse-submodules" | "--push-option"
    )
}

fn push_short_switch(argument: &str, switch: char) -> bool {
    argument.starts_with('-')
        && !argument.starts_with("--")
        && argument.as_bytes()[1..]
            .iter()
            .take_while(|flag| **flag != b'o')
            .any(|flag| *flag as char == switch)
}

fn push_short_option_takes_value(argument: &str) -> bool {
    argument
        .strip_prefix('-')
        .filter(|flags| !flags.is_empty() && !flags.starts_with('-'))
        .is_some_and(|flags| flags.find('o') == Some(flags.len() - 1))
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
        if subcommand == "push"
            && (push_option_takes_value(argument) || push_short_option_takes_value(argument))
        {
            index += 2;
            continue;
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
        "push" => push_switch_option(argument),
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

fn push_switch_option(argument: &str) -> bool {
    let option = argument
        .strip_prefix("--no-")
        .or_else(|| argument.strip_prefix("--"));
    option.is_some_and(|option| {
        matches!(
            option,
            "verbose"
                | "quiet"
                | "all"
                | "branches"
                | "mirror"
                | "delete"
                | "tags"
                | "dry-run"
                | "porcelain"
                | "force"
                | "force-with-lease"
                | "force-if-includes"
                | "thin"
                | "set-upstream"
                | "progress"
                | "prune"
                | "verify"
                | "follow-tags"
                | "signed"
                | "atomic"
                | "ipv4"
                | "ipv6"
        ) || argument.strip_prefix("--no-").is_some_and(|_| {
            matches!(
                option,
                "repo" | "receive-pack" | "exec" | "recurse-submodules" | "push-option"
            )
        })
    })
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
