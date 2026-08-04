//! Lowers Git read and local-write operations into typed effects; it does not decide them.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;

use crate::bash_git_config::parse;
use crate::shell_word::{contains_shell_pattern, has_unmodeled_expansion, static_word};

pub(crate) struct Lowering {
    pub(crate) complete: bool,
    pub(crate) existing_filesystems: Vec<String>,
    pub(crate) filesystems: Vec<String>,
    pub(crate) written_filesystems: Vec<String>,
    pub(crate) deleted_filesystems: Vec<String>,
    pub(crate) operation: &'static str,
    pub(crate) network_outbound: bool,
    pub(crate) project_scoped: bool,
}

pub(crate) fn lower(program: &str, arguments: &[Word]) -> Option<Lowering> {
    if program != "git" {
        return None;
    }
    let parsed = parse(arguments);
    let parsed_worktree = parsed
        .command()
        .filter(|(subcommand, _)| matches!(*subcommand, "clean" | "checkout" | "restore"));
    let (subcommand, arguments, directory, globals_complete) =
        if let Some((subcommand, arguments)) = parsed_worktree {
            (
                subcommand.to_owned(),
                arguments,
                parsed.directory(),
                parsed.complete() && !parsed.alternate_worktree(),
            )
        } else {
            let (subcommand, arguments) = semantic_subcommand(arguments)?;
            (subcommand, arguments, None, true)
        };
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let complete = globals_complete && values.iter().all(Option::is_some);
    let values = values
        .iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mutations = complete
        .then(|| command_mutations(&subcommand, &values))
        .flatten();
    let mutation_paths = |operation| {
        mutations
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|(_, actual, _)| *actual == operation)
            .map(|(path, _, _)| qualify_worktree_path(directory, path))
            .collect::<Vec<_>>()
    };
    let written_filesystems = mutation_paths(FilesystemOperation::Write);
    let deleted_filesystems = mutation_paths(FilesystemOperation::Delete);

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
        "clean" => ("clean", mutations.is_some()),
        "switch" => ("switch", switch_is_reviewed(&values)),
        "checkout" if !complete || checkout_creates_branch(&values) => {
            ("checkout-branch", checkout_is_reviewed(&values))
        }
        "checkout" if !written_filesystems.is_empty() => ("checkout-worktree", true),
        "checkout" if values.iter().any(|argument| unsupported_pathspec(argument)) => {
            ("checkout-worktree", false)
        }
        "restore" if !written_filesystems.is_empty() => ("restore-worktree", true),
        "restore" if !complete || restores_staged(&values) => {
            ("restore-staged", restore_is_reviewed(&values))
        }
        "restore" => ("restore-worktree", false),
        "fetch" if !has_help(&values) => {
            return Some(Lowering {
                complete,
                existing_filesystems: vec![],
                filesystems: vec![],
                written_filesystems: vec![],
                deleted_filesystems: vec![],
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
        deleted_filesystems,
        operation,
        network_outbound: false,
        project_scoped: true,
    })
}

pub(crate) fn worktree_mutations(
    program: &str,
    arguments: &[Word],
) -> Option<Vec<(String, FilesystemOperation, bool)>> {
    if program != "git" {
        return None;
    }
    let parsed = parse(arguments);
    let (subcommand, arguments) = parsed.command()?;
    if !parsed.complete() || parsed.alternate_worktree() {
        return None;
    }
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    let values = values.iter().map(String::as_str).collect::<Vec<_>>();
    let mutations = command_mutations(subcommand, &values)?;
    Some(
        mutations
            .into_iter()
            .map(|(path, operation, recursive)| {
                (
                    qualify_worktree_path(parsed.directory(), &path),
                    operation,
                    recursive,
                )
            })
            .collect(),
    )
}

fn qualify_worktree_path(directory: Option<&str>, path: &str) -> String {
    match directory {
        Some(directory) if !path.starts_with(['/', '~']) => {
            format!("{}/{path}", directory.trim_end_matches(['/', '\\']))
        }
        _ => path.to_owned(),
    }
}

fn command_mutations(
    subcommand: &str,
    arguments: &[&str],
) -> Option<Vec<(String, FilesystemOperation, bool)>> {
    match subcommand {
        "clean" => clean_options(arguments).map(|options| {
            if options.terminal || options.dry_run || options.interactive {
                return Vec::new();
            }
            let paths = if options.paths.is_empty() {
                vec![".".to_owned()]
            } else {
                options.paths
            };
            paths
                .into_iter()
                .map(|path| (path, FilesystemOperation::Delete, false))
                .collect()
        }),
        "checkout" => checkout_worktree_paths(arguments).map(|paths| {
            paths
                .into_iter()
                .map(|path| (path, FilesystemOperation::Write, false))
                .collect()
        }),
        "restore" => restore_options(arguments).map(|options| {
            if !options.worktree || options.patch {
                return Vec::new();
            }
            options
                .paths
                .into_iter()
                .map(|path| (path, FilesystemOperation::Write, false))
                .collect()
        }),
        _ => None,
    }
}

pub(crate) struct CleanOptions {
    pub(crate) force: bool,
    pub(crate) dry_run: bool,
    pub(crate) interactive: bool,
    pub(crate) terminal: bool,
    paths: Vec<String>,
}

pub(crate) fn clean_options(arguments: &[&str]) -> Option<CleanOptions> {
    let mut paths = Vec::new();
    let mut force = false;
    let mut dry_run = false;
    let mut interactive = false;
    let mut terminal = false;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options {
            match argument {
                "--force" => force = true,
                "--no-force" => force = false,
                "--dry-run" => dry_run = true,
                "--no-dry-run" => dry_run = false,
                "--interactive" => interactive = true,
                "--no-interactive" => interactive = false,
                "--quiet" | "--no-quiet" | "-d" | "-x" | "-X" => {}
                "--help" | "--version" | "-h" => terminal = true,
                "--exclude" => {
                    index += 1;
                    arguments.get(index)?;
                }
                argument if argument.starts_with("--exclude=") => {}
                argument if argument.starts_with('-') => {
                    let flags = argument.strip_prefix('-')?;
                    if flags.is_empty() || !flags.is_ascii() {
                        return None;
                    }
                    let bytes = flags.as_bytes();
                    let mut position = 0;
                    while position < bytes.len() {
                        match bytes[position] as char {
                            'f' => force = true,
                            'n' => dry_run = true,
                            'i' => interactive = true,
                            'd' | 'x' | 'X' | 'q' => {}
                            'e' => {
                                if position + 1 == bytes.len() {
                                    index += 1;
                                    arguments.get(index)?;
                                }
                                break;
                            }
                            _ => return None,
                        }
                        position += 1;
                    }
                }
                argument if explicit_path(argument) => {
                    after_options = true;
                    paths.push(argument.to_owned());
                }
                _ => return None,
            }
        } else if explicit_path(argument) {
            paths.push(argument.to_owned());
        } else {
            return None;
        }
        index += 1;
    }
    Some(CleanOptions {
        force,
        dry_run,
        interactive,
        terminal,
        paths,
    })
}

fn checkout_worktree_paths(arguments: &[&str]) -> Option<Vec<String>> {
    if let Some(separator) = arguments.iter().position(|argument| *argument == "--") {
        if !checkout_path_prefix(&arguments[..separator]) {
            return None;
        }
        return exact_paths(&arguments[separator + 1..]);
    }
    if !checkout_path_prefix(arguments) {
        return None;
    }
    let paths = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .copied()
        .collect::<Vec<_>>();
    paths
        .iter()
        .any(|path| {
            matches!(*path, "." | "./" | ".." | "../")
                || path.starts_with("./")
                || path.starts_with("../")
                || path.starts_with('/')
        })
        .then(|| paths.into_iter().map(str::to_owned).collect())
}

fn checkout_path_prefix(arguments: &[&str]) -> bool {
    arguments.iter().all(|argument| {
        explicit_path(argument)
            || matches!(
                *argument,
                "-f" | "-q" | "-fq" | "-qf" | "--force" | "--no-force" | "--quiet" | "--no-quiet"
            )
    })
}

struct RestoreOptions {
    staged: bool,
    worktree: bool,
    patch: bool,
    paths: Vec<String>,
}

fn restore_options(arguments: &[&str]) -> Option<RestoreOptions> {
    let mut paths = Vec::new();
    let mut staged = false;
    let mut worktree = None;
    let mut patch = false;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && argument == "--staged" {
            staged = true;
        } else if !after_options && argument == "--no-staged" {
            staged = false;
        } else if !after_options && argument == "--worktree" {
            worktree = Some(true);
        } else if !after_options && argument == "--no-worktree" {
            worktree = Some(false);
        } else if !after_options && argument == "--patch" {
            patch = true;
        } else if !after_options && argument == "--no-patch" {
            patch = false;
        } else if !after_options && matches!(argument, "--source" | "-s") {
            index += 1;
            arguments.get(index)?;
        } else if !after_options
            && (argument.starts_with("--source=")
                || matches!(
                    argument,
                    "--overlay"
                        | "--no-overlay"
                        | "--ignore-unmerged"
                        | "--recurse-submodules"
                        | "--no-recurse-submodules"
                        | "--progress"
                        | "--no-progress"
                        | "--quiet"
                        | "--no-quiet"
                        | "-q"
                ))
        {
        } else if !after_options && argument.starts_with('-') && !argument.starts_with("--") {
            let flags = argument.strip_prefix('-')?;
            if flags.is_empty() || !flags.is_ascii() {
                return None;
            }
            let bytes = flags.as_bytes();
            let mut position = 0;
            while position < bytes.len() {
                match bytes[position] as char {
                    'S' => staged = true,
                    'W' => worktree = Some(true),
                    'p' => patch = true,
                    'q' => {}
                    's' => {
                        if position + 1 == bytes.len() {
                            index += 1;
                            arguments.get(index)?;
                        }
                        break;
                    }
                    _ => return None,
                }
                position += 1;
            }
        } else if !after_options && argument.starts_with('-') {
            return None;
        } else if explicit_path(argument) {
            paths.push(argument.to_owned());
        } else {
            return None;
        }
        index += 1;
    }
    Some(RestoreOptions {
        staged,
        worktree: worktree.unwrap_or(!staged),
        patch,
        paths,
    })
}

fn exact_paths(arguments: &[&str]) -> Option<Vec<String>> {
    let paths = arguments
        .iter()
        .map(|path| explicit_path(path).then(|| (*path).to_owned()))
        .collect::<Option<Vec<_>>>()?;
    Some(paths)
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

fn unsupported_pathspec(argument: &str) -> bool {
    !argument.starts_with('-') && !explicit_path(argument)
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
    let mut staged = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if argument == "--" {
            break;
        }
        if argument == "--staged" {
            staged = true;
        } else if argument == "--no-staged" {
            staged = false;
        } else if argument == "--source" || argument == "-s" {
            index += 1;
        } else if argument.starts_with('-') && !argument.starts_with("--") {
            let flags = &argument.as_bytes()[1..];
            let mut position = 0;
            while position < flags.len() {
                match flags[position] as char {
                    'S' => staged = true,
                    's' => break,
                    _ => {}
                }
                position += 1;
            }
        }
        index += 1;
    }
    staged
}

fn restore_is_reviewed(arguments: &[&str]) -> bool {
    restore_options(arguments).is_some_and(|options| {
        options.staged && !options.worktree && !options.patch && !options.paths.is_empty()
    })
}

fn has_help(arguments: &[&str]) -> bool {
    arguments
        .iter()
        .any(|argument| matches!(*argument, "-h" | "--help"))
}

fn has_option_prefix(arguments: &[&str], expected: &str) -> bool {
    arguments.iter().any(|argument| {
        argument
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('='))
    })
}
