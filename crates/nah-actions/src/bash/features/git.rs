//! Lowers destructive Git operations and metadata effects; it does not choose a verdict.

use nah_parse::Word;

use crate::bash_git_config::git_boolean;
use crate::bash_git_config::{ParsedGit, parse};
use crate::bash_git_operations::{clean_options, stash_deletes_entries};
use crate::shell_word::static_word;

/// Collects applicable Git meanings independently of guard enablement.
pub(crate) fn git_command_operations(program: &str, arguments: &[Word]) -> Vec<&'static str> {
    use nah_proto::effects::{FactPayload, GitDiscardMode, GitHistoryOperation, Knowledge::Known};
    let mut operations = git_command_facts(program, arguments)
        .iter()
        .filter_map(|fact| match fact {
            FactPayload::GitPush {
                dry_run: Known(false),
                ..
            } => Some("push"),
            FactPayload::GitDiscard {
                mode: GitDiscardMode::Reset,
                ..
            } => Some("hard-reset"),
            FactPayload::GitDiscard { .. } => Some("worktree-discard"),
            FactPayload::GitRecovery { .. } => Some("recovery-destroy"),
            FactPayload::GitRefChange { .. } => Some("ref-delete"),
            FactPayload::GitHistory {
                operation: GitHistoryOperation::Filter,
                force: Known(true),
                ..
            } => Some("rewrite-force"),
            FactPayload::GitHistory { .. } => Some("history-rewrite"),
            _ => None,
        })
        .collect::<Vec<_>>();
    if program == "git" {
        let parsed = parse(arguments);
        if let Some(("clean", args)) = parsed.command()
            && clean_force(&parsed, args)
        {
            operations.push("clean-force");
        }
    }
    operations
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

fn ref_delete(subcommand: &str, arguments: &[Word]) -> bool {
    match subcommand {
        "branch" => branch_deletes_refs(arguments),
        "tag" => tag_deletes_refs(arguments),
        "stash" => stash_deletes_entries(arguments) && stash_delete_is_valid(arguments),
        "push" => push_deletes_refs(arguments),
        "update-ref" => update_ref_deletes_ref(arguments),
        _ => false,
    }
}

fn static_argument(argument: &Word) -> Option<String> {
    static_word(argument.raw(), argument.substitutions().is_empty())
}

fn target_count(arguments: &[Word], valid_option: impl Fn(&str) -> bool) -> Option<usize> {
    let mut targets = 0;
    let mut after_separator = false;
    for word in arguments {
        let Some(argument) = static_argument(word) else {
            targets += 1;
            continue;
        };
        if !after_separator && argument == "--" {
            after_separator = true;
        } else if argument.is_empty() {
            return None;
        } else if !after_separator && argument.starts_with('-') {
            if !valid_option(&argument) && !bundled_short_flags(&argument, &valid_option) {
                return None;
            }
        } else {
            targets += 1;
        }
    }
    Some(targets)
}

/// Accepts bundled short options such as `-ff` when each letter is a valid `-{flag}`.
fn bundled_short_flags(argument: &str, valid_option: impl Fn(&str) -> bool) -> bool {
    argument
        .strip_prefix('-')
        .filter(|flags| !argument.starts_with("--") && !flags.is_empty())
        .is_some_and(|flags| flags.chars().all(|flag| valid_option(&format!("-{flag}"))))
}

fn branch_deletes_refs(arguments: &[Word]) -> bool {
    let mut deleting = false;
    let mut targets = 0;
    let mut after_separator = false;
    for word in arguments {
        let Some(argument) = static_argument(word) else {
            if !deleting && !after_separator {
                return false;
            }
            targets += 1;
            continue;
        };
        if after_separator {
            if argument.is_empty() {
                return false;
            }
            targets += 1;
            continue;
        }
        match argument.as_str() {
            "--" => after_separator = true,
            "-d" | "-D" | "--delete" => deleting = true,
            "-q" | "--quiet" | "--no-quiet" | "-v" | "--verbose" | "--no-verbose" | "-r"
            | "--remotes" | "--no-remotes" | "-f" | "--force" | "--no-force" => {}
            argument if argument.starts_with('-') && !argument.starts_with("--") => {
                for flag in argument[1..].chars() {
                    match flag {
                        'd' | 'D' => deleting = true,
                        'q' | 'v' | 'r' | 'f' => {}
                        _ => return false,
                    }
                }
            }
            argument if argument.is_empty() || argument.starts_with('-') => return false,
            _ => targets += 1,
        }
    }
    deleting && targets > 0
}

fn tag_deletes_refs(arguments: &[Word]) -> bool {
    let mut deleting = false;
    let mut targets = 0;
    let mut after_separator = false;
    for word in arguments {
        let Some(argument) = static_argument(word) else {
            if !deleting && !after_separator {
                return false;
            }
            targets += 1;
            continue;
        };
        if after_separator {
            if argument.is_empty() {
                return false;
            }
            targets += 1;
            continue;
        }
        match argument.as_str() {
            "--" => after_separator = true,
            "-d" | "--delete" => deleting = true,
            argument if argument.is_empty() || argument.starts_with('-') => return false,
            _ => targets += 1,
        }
    }
    deleting && targets > 0
}

fn stash_delete_is_valid(arguments: &[Word]) -> bool {
    let verb = arguments.first().and_then(static_argument);
    match verb.as_deref() {
        Some("clear") => {
            arguments.len() == 1
                || (arguments.len() == 2
                    && arguments.get(1).and_then(static_argument).as_deref() == Some("--"))
        }
        Some("drop") => target_count(&arguments[1..], |argument| {
            matches!(argument, "-q" | "--quiet" | "--no-quiet")
        })
        .is_some_and(|targets| targets <= 1),
        _ => false,
    }
}

fn push_deletes_refs(arguments: &[Word]) -> bool {
    let mut deleting = false;
    let mut deletion_refspec = false;
    let mut operands = 0;
    let mut repository_option = false;
    let mut after_separator = false;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_argument(word) else {
            operands += 1;
            index += 1;
            continue;
        };
        if after_separator {
            if argument.is_empty() {
                return false;
            }
            deletion_refspec |= argument.starts_with(':') && argument.len() > 1;
            operands += 1;
            index += 1;
            continue;
        }
        match argument.as_str() {
            "--" => after_separator = true,
            "-d" | "--delete" => deleting = true,
            "-n" | "--dry-run" => return false,
            "--all" | "--branches" | "--mirror" | "--tags" | "--prune" => return false,
            "--repo"
            | "--receive-pack"
            | "--exec"
            | "--recurse-submodules"
            | "-o"
            | "--push-option" => {
                if arguments.get(index + 1).is_none() {
                    return false;
                }
                repository_option |= argument == "--repo";
                index += 1;
            }
            argument
                if argument.starts_with("--repo=")
                    || argument.starts_with("--receive-pack=")
                    || argument.starts_with("--exec=")
                    || argument.starts_with("--recurse-submodules=")
                    || argument.starts_with("--push-option=") =>
            {
                if argument.ends_with('=') {
                    return false;
                }
                repository_option |= argument.starts_with("--repo=");
            }
            "-v"
            | "--verbose"
            | "--no-verbose"
            | "-q"
            | "--quiet"
            | "--no-quiet"
            | "-f"
            | "--force"
            | "--no-force"
            | "--force-with-lease"
            | "--no-force-with-lease"
            | "--force-if-includes"
            | "--no-force-if-includes"
            | "--no-dry-run"
            | "--thin"
            | "--no-thin"
            | "-u"
            | "--set-upstream"
            | "--no-set-upstream"
            | "--progress"
            | "--no-progress"
            | "--no-verify"
            | "--verify"
            | "--follow-tags"
            | "--no-follow-tags"
            | "--signed"
            | "--no-signed"
            | "--atomic"
            | "--no-atomic"
            | "-4"
            | "--ipv4"
            | "-6"
            | "--ipv6" => {}
            argument
                if argument.starts_with("--force-with-lease=")
                    || argument.starts_with("--signed=") => {}
            argument if argument.starts_with('-') && !argument.starts_with("--") => {
                for flag in argument[1..].chars() {
                    match flag {
                        'd' => deleting = true,
                        'n' => return false,
                        'v' | 'q' | 'f' | 'u' | '4' | '6' => {}
                        _ => return false,
                    }
                }
            }
            argument if argument.is_empty() || argument.starts_with('-') => return false,
            _ => {
                deletion_refspec |= argument.starts_with(':') && argument.len() > 1;
                operands += 1;
            }
        }
        index += 1;
    }
    if deleting {
        !deletion_refspec && (operands >= 2 || repository_option && operands >= 1)
    } else {
        deletion_refspec
    }
}

fn update_ref_deletes_ref(arguments: &[Word]) -> bool {
    let mut deleting = false;
    let mut operands = 0;
    let mut after_separator = false;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_argument(word) else {
            if !deleting && !after_separator {
                return false;
            }
            operands += 1;
            index += 1;
            continue;
        };
        if after_separator {
            if argument.is_empty() {
                return false;
            }
            operands += 1;
            index += 1;
            continue;
        }
        match argument.as_str() {
            "--" => after_separator = true,
            "-d" | "--delete" => deleting = true,
            "--no-deref" | "--deref" | "--create-reflog" | "--no-create-reflog" => {}
            "-m" => {
                if arguments.get(index + 1).is_none() {
                    return false;
                }
                index += 1;
            }
            argument if argument.starts_with("-m") && argument.len() > 2 => {}
            argument if argument.is_empty() || argument.starts_with('-') => return false,
            _ => operands += 1,
        }
        index += 1;
    }
    deleting && matches!(operands, 1 | 2)
}

// Some(false) still carries independently selectable ref deletion evidence.
fn worktree_deletion(arguments: &[Word]) -> Option<bool> {
    match arguments.first().and_then(static_argument).as_deref() {
        Some("remove") => {
            let mut force = false;
            let mut targets = 0;
            let mut after_separator = false;
            for word in &arguments[1..] {
                let Some(argument) = static_argument(word) else {
                    if !after_separator {
                        force = false;
                    }
                    targets += 1;
                    continue;
                };
                if argument.is_empty() {
                    return None;
                }
                if after_separator {
                    targets += 1;
                    continue;
                }
                match argument.as_str() {
                    "--" => after_separator = true,
                    "--force" => force = true,
                    "--no-force" => force = false,
                    argument if bundled_short_flags(argument, |flag| flag == "-f") => force = true,
                    argument if argument.starts_with('-') => return None,
                    _ => targets += 1,
                }
            }
            if targets != 1 {
                return None;
            }
            Some(force)
        }
        Some("prune") => worktree_prune_is_valid(&arguments[1..]).then_some(false),
        _ => None,
    }
}

fn worktree_prune_is_valid(arguments: &[Word]) -> bool {
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_argument(word) else {
            return false;
        };
        match argument.as_str() {
            "--" | "-v" | "--verbose" | "--no-verbose" => {}
            "-n" | "--dry-run" => return false,
            "--expire" => {
                if arguments.get(index + 1).is_none() {
                    return false;
                }
                index += 1;
            }
            argument if argument.starts_with("--expire=") => {
                if argument.ends_with('=') {
                    return false;
                }
            }
            argument if argument.starts_with('-') && !argument.starts_with("--") => {
                if argument[1..].chars().any(|flag| flag == 'n')
                    || !argument[1..].chars().all(|flag| flag == 'v')
                {
                    return false;
                }
            }
            _ => return false,
        }
        index += 1;
    }
    true
}

fn submodule_deinit(arguments: &[Word]) -> Option<bool> {
    let mut index = 0;
    let mut executable = true;
    while let Some(argument) = arguments.get(index).and_then(static_argument) {
        if matches!(argument.as_str(), "-q" | "--quiet" | "--no-quiet") {
            executable &= argument != "--no-quiet";
            index += 1;
            continue;
        }
        break;
    }
    if arguments.get(index).and_then(static_argument).as_deref() != Some("deinit") {
        return None;
    }
    let mut force = false;
    let mut all = false;
    let mut targets = 0;
    let mut after_options = false;
    // The public submodule shell command accepts only these whole flags and
    // stops at the first path. Retain the existing ref deletion evidence for
    // helper-only flags, but never use them to prove an executable forced wipe.
    for word in &arguments[index + 1..] {
        let Some(argument) = static_argument(word) else {
            if !after_options {
                force = false;
            }
            after_options = true;
            targets += 1;
            continue;
        };
        if argument.is_empty() {
            return None;
        }
        if after_options {
            targets += 1;
            continue;
        }
        match argument.as_str() {
            "--" => after_options = true,
            "-f" | "--force" => force = true,
            "-q" | "--quiet" => {}
            "--no-force" | "--no-quiet" => executable = false,
            argument if bundled_short_flags(argument, |flag| matches!(flag, "-f" | "-q")) => {
                executable = false;
            }
            "--all" => all = true,
            argument if argument.starts_with('-') => return None,
            _ => {
                after_options = true;
                targets += 1;
            }
        }
    }
    ((all && targets == 0) || (!all && targets > 0)).then_some(force && executable)
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
    arguments.iter().map(static_argument).collect()
}

fn push_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--repo" | "--receive-pack" | "--exec" | "--recurse-submodules" | "-o" | "--push-option"
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

fn push_fact(arguments: &[Word]) -> nah_proto::effects::FactPayload {
    use Knowledge::Known;
    use nah_proto::effects::*;
    let mut before_separator = true;
    let mut explicit_force = false;
    let mut mirror = false;
    let mut all_refs_leased = false;
    let mut force_with_lease = false;
    let mut leased_refs = Vec::new();
    let mut forced_refs = Vec::new();
    let mut repository = false;
    let mut delete = false;
    let mut all = false;
    let mut tags = false;
    let mut prune = false;
    let mut destinations = Vec::new();
    let mut destinations_complete = true;
    let mut dry_run = false;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_word(word.raw(), word.substitutions().is_empty()) else {
            if before_separator {
                destinations_complete = false;
            } else if destinations_complete && !repository {
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
                destinations_complete = false;
            }
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
            match argument.as_str() {
                "--force" => explicit_force = true,
                "--no-force" => explicit_force = false,
                "--mirror" => mirror = true,
                "--no-mirror" => mirror = false,
                "--dry-run" => dry_run = true,
                "--no-dry-run" => dry_run = false,
                "--force-with-lease" => {
                    all_refs_leased = true;
                    force_with_lease = true;
                }
                "--no-force-with-lease" => {
                    all_refs_leased = false;
                    force_with_lease = false;
                    leased_refs.clear();
                }
                argument if argument.starts_with('-') && !argument.starts_with("--") => {
                    explicit_force |= push_short_switch(argument, 'f');
                    dry_run |= push_short_switch(argument, 'n');
                }
                _ => {}
            }
            if let Some(lease) = argument
                .strip_prefix("--force-with-lease=")
                .filter(|lease| !lease.is_empty())
            {
                force_with_lease = true;
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
        if destinations_complete && before_separator {
            if argument.starts_with("--repo=") {
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
                "--tags" => tags = true,
                "--no-tags" => tags = false,
                "--prune" => prune = true,
                "--no-prune" => prune = false,
                "--delete" => delete = true,
                "--no-delete" => delete = false,
                argument
                    if push_switch_option(argument)
                        || argument.starts_with("--force-with-lease=")
                        || argument.starts_with("--signed=") => {}
                argument if argument.starts_with("--") => destinations_complete = false,
                argument if argument.starts_with('-') && argument != "-" => {
                    let flags = &argument.as_bytes()[1..];
                    let mut position = 0;
                    while position < flags.len() {
                        match flags[position] as char {
                            'd' => delete = true,
                            'v' | 'q' | 'n' | 'f' | 'u' | '4' | '6' => {}
                            'o' => break,
                            _ => destinations_complete = false,
                        }
                        position += 1;
                    }
                }
                _ if !repository => repository = true,
                "tag" => {
                    index += 2;
                    continue;
                }
                _ => {
                    if let Some(destination) = push_destination(&argument) {
                        destinations.push(destination);
                    }
                }
            }
            index += 1;
            continue;
        }
        if destinations_complete {
            if !repository {
                repository = true;
            } else if argument == "tag" {
                index += 2;
                continue;
            } else if let Some(destination) = push_destination(&argument) {
                destinations.push(destination);
            }
        }
        index += 1;
    }
    for destination in forced_refs {
        if !destinations
            .iter()
            .any(|d| d.destination == Known(destination.clone()) && d.forced == Known(true))
        {
            destinations.push(PushDestination {
                source: Knowledge::Unknown,
                destination: Known(destination),
                forced: Known(true),
            });
        }
    }
    FactPayload::GitPush {
        repository: ResourceId(0),
        destinations,
        destinations_complete: Known(destinations_complete),
        selection: if all || tags {
            Selection::Whole
        } else {
            Selection::Unknown
        },
        explicit_force: Known(explicit_force),
        lease_requested: Known(force_with_lease),
        all_refs_lease: Known(all_refs_leased),
        leased_refs: Known(leased_refs),
        delete: Known(delete),
        all: Known(all),
        branches: Known(all),
        mirror: Known(mirror),
        prune: Known(prune),
        dry_run: Known(dry_run),
    }
}

fn push_destination(argument: &str) -> Option<nah_proto::effects::PushDestination> {
    use nah_proto::effects::{Knowledge::Known, PushDestination};
    let refspec = argument.strip_prefix('+').unwrap_or(argument);
    if refspec.is_empty() {
        return None;
    }
    let (source, destination) = refspec.split_once(':').unwrap_or((refspec, refspec));
    Some(PushDestination {
        source: Known(source.into()),
        destination: Known(destination.into()),
        forced: Known(argument.starts_with('+')),
    })
}

/// Retains command facts at interpretation, before the public semantic projection.
pub(crate) fn git_command_facts(
    program: &str,
    arguments: &[Word],
) -> Vec<nah_proto::effects::FactPayload> {
    use Knowledge::{Known, Unknown};
    use nah_proto::effects::*;
    if program != "git" {
        return vec![];
    }
    let parsed = parse(arguments);
    let Some((subcommand, arguments)) = parsed.command() else {
        return vec![];
    };
    if (!matches!(subcommand, "clean" | "checkout" | "switch") && has_help(subcommand, arguments))
        || option_before_separator(arguments, "--version")
        || has_no_side_effect(subcommand, arguments)
    {
        return vec![];
    }
    let target = ResourceId(0);
    let deletion = || FactPayload::GitRefChange {
        target,
        operation: GitRefOperation::Delete,
        selection: Selection::Unknown,
        active: Known(true),
        abort: Known(false),
        dry_run: Known(false),
        force: Unknown,
    };
    let discard = |mode, force| FactPayload::GitDiscard {
        target,
        mode,
        reset: Unknown,
        selection: Selection::Whole,
        untracked: Known(false),
        force: Known(force),
        dry_run: Known(false),
    };
    let recovery = || FactPayload::GitRecovery {
        target,
        operation: GitRecoveryOperation::Remove,
        selection: Selection::Whole,
        active: Known(true),
        abort: Known(false),
        dry_run: Known(false),
        force: Unknown,
    };
    let history = |operation, force| FactPayload::GitHistory {
        target,
        operation,
        selection: Selection::Unknown,
        active: Known(true),
        abort: Known(false),
        dry_run: Known(false),
        force: Known(force),
    };
    if let Some(force) = match subcommand {
        "worktree" => worktree_deletion(arguments),
        "submodule" => submodule_deinit(arguments),
        _ => None,
    } {
        let mut facts = vec![deletion()];
        if force && parsed.complete() {
            facts.push(discard(
                if subcommand == "worktree" {
                    GitDiscardMode::WorktreeRemove
                } else {
                    GitDiscardMode::SubmoduleDeinit
                },
                force,
            ));
        }
        return facts;
    }
    if subcommand == "stash"
        && stash_delete_is_valid(arguments)
        && arguments.first().and_then(static_argument).as_deref() == Some("clear")
    {
        let mut facts = vec![deletion()];
        if parsed.complete() {
            facts.push(recovery());
        }
        return facts;
    }
    match subcommand {
        "push" => {
            let mut facts = vec![push_fact(arguments)];
            if push_deletes_refs(arguments) {
                facts.push(deletion());
            }
            facts
        }
        "reset" if option_before_separator(arguments, "--hard") => vec![FactPayload::GitDiscard {
            target,
            mode: GitDiscardMode::Reset,
            reset: Known(ResetMode::Hard),
            selection: Selection::Whole,
            untracked: Unknown,
            force: Unknown,
            dry_run: Known(false),
        }],
        "checkout" if forced_checkout(arguments) => vec![discard(GitDiscardMode::Checkout, true)],
        "switch" if forced_switch(arguments) => vec![discard(GitDiscardMode::Checkout, true)],
        "filter-repo" | "filter-branch" => vec![history(
            GitHistoryOperation::Filter,
            option_before_separator(arguments, "--force")
                || subcommand == "filter-branch" && short_option_before_separator(arguments, 'f'),
        )],
        "gc" if gc_destroys_recovery(&parsed, arguments) => vec![recovery()],
        "prune" if immediate_expiry(arguments, "--expire") => vec![recovery()],
        "reflog" if destroys_all_reflog_recovery(arguments) => vec![recovery()],
        "rebase" if rebase_rewrites_history(arguments) => {
            vec![history(GitHistoryOperation::Rebase, false)]
        }
        "reflog" if reflog_expires(arguments) => vec![history(GitHistoryOperation::Other, false)],
        "gc" if gc_rewrites_history(arguments) => vec![history(GitHistoryOperation::Other, false)],
        _ if ref_delete(subcommand, arguments) => vec![deletion()],
        _ => vec![],
    }
}
