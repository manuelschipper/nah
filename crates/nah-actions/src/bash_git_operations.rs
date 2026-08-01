//! Lowers Git read and local-write operations into typed effects; it does not decide them.

use nah_parse::Word;

use crate::shell_word::{contains_shell_pattern, has_unmodeled_expansion, static_word};

pub(crate) struct Lowering {
    pub(crate) complete: bool,
    pub(crate) existing_filesystems: Vec<String>,
    pub(crate) filesystems: Vec<String>,
    pub(crate) written_filesystems: Vec<String>,
    pub(crate) operation: &'static str,
    pub(crate) network_outbound: bool,
    pub(crate) project_scoped: bool,
}

pub(crate) fn lower(program: &str, arguments: &[Word]) -> Option<Lowering> {
    if program != "git" {
        return None;
    }
    let (subcommand, arguments) = semantic_subcommand(arguments)?;
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let complete = values.iter().all(Option::is_some);
    let values = values
        .iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let written_filesystems = worktree_paths(&subcommand, &values).unwrap_or_default();

    let (operation, reviewed) = match subcommand.as_str() {
        "status" => ("status", !has_help(&values)),
        "log" => ("log", false),
        "diff" => ("diff", false),
        "show" => ("show", false),
        "cat-file" => ("cat-file", false),
        "blame" => ("blame", false),
        "branch" if !complete || branch_mentions_list(&values) || branch_is_list(&values) => {
            ("branch-list", branch_is_list(&values))
        }
        "tag" if !complete || tag_mentions_list(&values) || tag_is_list(&values) => {
            ("tag-list", tag_is_list(&values))
        }
        "rev-parse" => (
            "rev-parse",
            !has_help(&values) && !has_option_prefix(&values, "--resolve-git-dir"),
        ),
        "describe" => ("describe", !has_help(&values)),
        "remote" if !complete || remote_is_list(&values) => ("remote-list", complete),
        "add" => ("add", add_files(&values).is_some()),
        "commit" => ("commit", commit_is_reviewed(&values)),
        "stash" if !stash_deletes_entries(&values) => ("stash", !has_help(&values)),
        "switch" => ("switch", switch_is_reviewed(&values)),
        "checkout" if !complete || checkout_creates_branch(&values) => {
            ("checkout-branch", checkout_is_reviewed(&values))
        }
        "checkout" if !written_filesystems.is_empty() => ("checkout-worktree", true),
        "restore" if !complete || restores_staged(&values) => {
            ("restore-staged", restore_is_reviewed(&values))
        }
        "restore" if !written_filesystems.is_empty() => ("restore-worktree", true),
        "fetch" if !has_help(&values) => {
            return Some(Lowering {
                complete,
                existing_filesystems: vec![],
                filesystems: vec![],
                written_filesystems: vec![],
                operation: "fetch",
                network_outbound: true,
                project_scoped: false,
            });
        }
        _ => return None,
    };
    let filesystems = match operation {
        "log" | "diff" | "show" | "cat-file" | "blame" => content_paths(operation, &values),
        _ => vec![],
    };
    Some(Lowering {
        complete: complete && reviewed,
        existing_filesystems: (operation == "add")
            .then(|| add_files(&values))
            .flatten()
            .unwrap_or_default(),
        filesystems,
        written_filesystems,
        operation,
        network_outbound: false,
        project_scoped: true,
    })
}

pub(crate) fn worktree_mutations(program: &str, arguments: &[Word]) -> Option<Vec<String>> {
    if program != "git" {
        return None;
    }
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    let (directory, subcommand, values) = worktree_subcommand(&values)?;
    let values = values.iter().map(String::as_str).collect::<Vec<_>>();
    let paths = worktree_paths(subcommand, &values)?;
    Some(
        paths
            .into_iter()
            .map(|path| qualify_worktree_path(directory, &path))
            .collect(),
    )
}

fn worktree_subcommand(arguments: &[String]) -> Option<(Option<&str>, &str, &[String])> {
    let mut directory = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "-C" {
            directory = Some(arguments.get(index + 1)?.as_str());
            index += 2;
        } else if let Some(value) = argument
            .strip_prefix("-C")
            .filter(|value| !value.is_empty())
        {
            directory = Some(value);
            index += 1;
        } else if matches!(
            argument.as_str(),
            "-P" | "--no-pager"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
                | "--no-advice"
        ) {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some((directory, argument, &arguments[index + 1..]));
        }
    }
    None
}

fn qualify_worktree_path(directory: Option<&str>, path: &str) -> String {
    match directory {
        Some(directory) if !path.starts_with(['/', '~']) => {
            format!("{}/{path}", directory.trim_end_matches(['/', '\\']))
        }
        _ => path.to_owned(),
    }
}

fn worktree_paths(subcommand: &str, arguments: &[&str]) -> Option<Vec<String>> {
    match subcommand {
        "checkout" => {
            let separator = arguments.iter().position(|argument| *argument == "--")?;
            exact_paths(&arguments[separator + 1..])
        }
        "restore" => restore_worktree_paths(arguments),
        _ => None,
    }
}

fn restore_worktree_paths(arguments: &[&str]) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut staged = false;
    let mut worktree = false;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "--staged" | "-S") {
            staged = true;
        } else if !after_options && matches!(argument, "--worktree" | "-W") {
            worktree = true;
        } else if !after_options && matches!(argument, "--source" | "-s") {
            index += 1;
            arguments.get(index)?;
        } else if !after_options
            && (argument.starts_with("--source=")
                || matches!(
                    argument,
                    "--ours"
                        | "--theirs"
                        | "--overlay"
                        | "--no-overlay"
                        | "--ignore-unmerged"
                        | "--recurse-submodules"
                        | "--no-recurse-submodules"
                        | "--progress"
                        | "--quiet"
                        | "-q"
                ))
        {
        } else if !after_options && argument.starts_with('-') {
            return None;
        } else if explicit_path(argument) {
            paths.push(argument.to_owned());
        } else {
            return None;
        }
        index += 1;
    }
    if staged && !worktree {
        return Some(Vec::new());
    }
    (!paths.is_empty()).then_some(paths)
}

fn exact_paths(arguments: &[&str]) -> Option<Vec<String>> {
    let paths = arguments
        .iter()
        .map(|path| explicit_path(path).then(|| (*path).to_owned()))
        .collect::<Option<Vec<_>>>()?;
    (!paths.is_empty()).then_some(paths)
}

fn semantic_subcommand(arguments: &[Word]) -> Option<(String, &[Word])> {
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let argument = static_word(word.raw(), word.substitutions().is_empty())?;
        if matches!(
            argument.as_str(),
            "-P" | "--no-pager"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
                | "--no-advice"
        ) {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some((argument, &arguments[index + 1..]));
    }
    None
}

fn branch_is_list(arguments: &[&str]) -> bool {
    if arguments.is_empty() {
        return true;
    }
    let mut explicit_list = false;
    for argument in arguments {
        if matches!(*argument, "--list" | "-l") {
            explicit_list = true;
        } else if matches!(*argument, "--all" | "--remotes" | "--verbose")
            || (argument.starts_with('-')
                && !argument.starts_with("--")
                && argument[1..]
                    .chars()
                    .all(|flag| matches!(flag, 'a' | 'r' | 'v' | 'l')))
        {
        } else if argument.starts_with('-') || !explicit_list {
            return false;
        }
    }
    true
}

fn branch_mentions_list(arguments: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        matches!(*argument, "--list" | "-l")
            || argument.starts_with('-')
                && !argument.starts_with("--")
                && argument[1..].chars().any(|flag| flag == 'l')
    })
}

fn tag_is_list(arguments: &[&str]) -> bool {
    if arguments.is_empty() {
        return true;
    }
    let mut explicit_list = false;
    for argument in arguments {
        if matches!(*argument, "--list" | "-l") {
            explicit_list = true;
        } else if argument.starts_with('-') || !explicit_list {
            return false;
        }
    }
    true
}

fn tag_mentions_list(arguments: &[&str]) -> bool {
    arguments
        .iter()
        .any(|argument| matches!(*argument, "--list" | "-l"))
}

fn remote_is_list(arguments: &[&str]) -> bool {
    arguments.is_empty()
}

fn add_files(arguments: &[&str]) -> Option<Vec<String>> {
    let mut files = Vec::new();
    let mut after_options = false;
    for argument in arguments {
        if !after_options && *argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options && argument.starts_with('-') {
            if matches!(
                *argument,
                "-n" | "--dry-run"
                    | "-v"
                    | "--verbose"
                    | "-f"
                    | "--force"
                    | "-N"
                    | "--intent-to-add"
                    | "--ignore-errors"
                    | "--sparse"
                    | "--chmod=+x"
                    | "--chmod=-x"
            ) || argument.starts_with('-')
                && !argument.starts_with("--")
                && argument[1..]
                    .chars()
                    .all(|flag| matches!(flag, 'n' | 'v' | 'f' | 'N'))
            {
                continue;
            }
            return None;
        }
        if *argument == "."
            || *argument == ".."
            || argument.starts_with([':', '!'])
            || contains_shell_pattern(argument)
            || argument.contains(['{', '}'])
        {
            return None;
        }
        files.push((*argument).to_owned());
    }
    (!files.is_empty()).then_some(files)
}

fn content_paths(operation: &str, arguments: &[&str]) -> Vec<String> {
    let mut files = arguments
        .iter()
        .position(|argument| *argument == "--")
        .map(|separator| {
            arguments[separator + 1..]
                .iter()
                .filter(|argument| explicit_path(argument))
                .map(|argument| (*argument).to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if matches!(operation, "show" | "cat-file") {
        files.extend(arguments.iter().filter_map(|argument| {
            let (_, path) = argument.rsplit_once(':')?;
            explicit_path(path).then(|| path.to_owned())
        }));
    } else if operation == "blame"
        && files.is_empty()
        && let Some(path) = arguments.last().filter(|path| explicit_path(path))
    {
        files.push((*path).to_owned());
    }
    files.sort();
    files.dedup();
    files
}

fn explicit_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('-')
        && !path.starts_with([':', '!'])
        && !contains_shell_pattern(path)
        && !path.contains(['{', '}'])
        && !has_unmodeled_expansion(path)
}

fn commit_is_reviewed(arguments: &[&str]) -> bool {
    let mut index = 0;
    let mut has_message = false;
    while let Some(argument) = arguments.get(index) {
        match *argument {
            "-m" | "--message" => {
                if arguments.get(index + 1).is_none() {
                    return false;
                }
                has_message = true;
                index += 2;
            }
            "--allow-empty" | "--allow-empty-message" | "--no-gpg-sign" | "--quiet" | "-q" => {
                index += 1
            }
            argument
                if argument
                    .strip_prefix("--message=")
                    .is_some_and(|message| !message.is_empty())
                    || argument.starts_with("-m") && argument.len() > 2 =>
            {
                has_message = true;
                index += 1;
            }
            _ => return false,
        }
    }
    has_message
}

fn stash_deletes_entries(arguments: &[&str]) -> bool {
    matches!(arguments.first().copied(), Some("drop" | "clear"))
}

fn switch_is_reviewed(arguments: &[&str]) -> bool {
    match arguments {
        [create] if create_target(create).is_some_and(branch_operand) => true,
        ["-c" | "--create", branch] => branch_operand(branch),
        _ => false,
    }
}

fn checkout_creates_branch(arguments: &[&str]) -> bool {
    arguments
        .iter()
        .any(|argument| *argument == "-b" || argument.starts_with("-b") && argument.len() > 2)
}

fn checkout_is_reviewed(arguments: &[&str]) -> bool {
    match arguments {
        ["-b", branch] => branch_operand(branch),
        [create] if short_create_target(create).is_some_and(branch_operand) => true,
        _ => false,
    }
}

fn branch_operand(argument: &str) -> bool {
    !argument.is_empty()
        && !argument.starts_with('-')
        && !contains_shell_pattern(argument)
        && !argument.contains(['{', '}'])
        && !has_unmodeled_expansion(argument)
}

fn create_target(argument: &str) -> Option<&str> {
    argument
        .strip_prefix("--create=")
        .or_else(|| argument.strip_prefix("-c"))
        .filter(|target| !target.is_empty())
}

fn short_create_target(argument: &str) -> Option<&str> {
    argument
        .strip_prefix("-b")
        .filter(|target| !target.is_empty())
}

fn restores_staged(arguments: &[&str]) -> bool {
    has_option(arguments, "--staged") || has_short_option(arguments, 'S')
}

fn restore_is_reviewed(arguments: &[&str]) -> bool {
    let mut staged = false;
    let mut path = false;
    let mut after_options = false;
    for argument in arguments {
        if !after_options && *argument == "--" {
            after_options = true;
        } else if !after_options {
            match *argument {
                "--staged" | "-S" => staged = true,
                "--quiet" | "-q" => {}
                argument if argument.starts_with('-') => return false,
                argument if restore_path(argument) => path = true,
                _ => return false,
            }
        } else if restore_path(argument) {
            path = true;
        } else {
            return false;
        }
    }
    staged && path
}

fn restore_path(argument: &str) -> bool {
    !argument.is_empty()
        && !argument.starts_with([':', '!'])
        && !contains_shell_pattern(argument)
        && !argument.contains(['{', '}'])
        && !has_unmodeled_expansion(argument)
}

fn has_help(arguments: &[&str]) -> bool {
    arguments
        .iter()
        .any(|argument| matches!(*argument, "-h" | "--help"))
}

fn has_option(arguments: &[&str], expected: &str) -> bool {
    arguments.contains(&expected)
}

fn has_option_prefix(arguments: &[&str], expected: &str) -> bool {
    arguments.iter().any(|argument| {
        argument
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('='))
    })
}

fn has_short_option(arguments: &[&str], expected: char) -> bool {
    arguments.iter().any(|argument| {
        argument.starts_with('-')
            && !argument.starts_with("--")
            && argument[1..].chars().any(|flag| flag == expected)
    })
}
