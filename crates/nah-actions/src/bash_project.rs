//! Lowers project file capabilities from Bash commands; it does not authorize them.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;

use crate::bash_model::FilesystemSpec;
use crate::shell_word::{
    contains_shell_pattern, contains_unquoted_pattern, static_filesystem_word,
};

pub(crate) struct Lowering {
    pub(crate) complete: bool,
    pub(crate) operation: &'static str,
    pub(crate) filesystems: Vec<FilesystemSpec>,
    pub(crate) root_move_destination: Option<usize>,
}

pub(crate) fn lower(program: &str, arguments: &[Word]) -> Option<Lowering> {
    let mut lowering = match program {
        "cp" => copy(arguments),
        "mv" => move_paths(arguments),
        "rm" => remove(arguments, true),
        "rmdir" => remove(arguments, false),
        "unlink" => unlink(arguments),
        "mkdir" => create(arguments, "create", "pv", &["--parents", "--verbose"]),
        "touch" => create(
            arguments,
            "update",
            "achm",
            &["--no-create", "--no-dereference"],
        ),
        _ => return None,
    };
    if lowering
        .filesystems
        .iter()
        .any(|(target, _, _)| contains_shell_pattern(target) || target.contains('{'))
    {
        lowering.complete = false;
    }
    Some(lowering)
}

fn copy(arguments: &[Word]) -> Lowering {
    let parsed = scan(
        arguments,
        "afilLnPpRrsTtuvx",
        &[
            "--archive",
            "--attributes-only",
            "--copy-contents",
            "--dereference",
            "--force",
            "--interactive",
            "--link",
            "--no-clobber",
            "--no-dereference",
            "--no-target-directory",
            "--one-file-system",
            "--parents",
            "--recursive",
            "--strip-trailing-slashes",
            "--symbolic-link",
            "--target-directory",
            "--update",
            "--verbose",
        ],
        &[
            "--context=",
            "--no-preserve=",
            "--preserve=",
            "--reflink=",
            "--sparse=",
            "--update=",
        ],
    );
    let recursive = has_short_option(arguments, 'a')
        || has_short_option(arguments, 'r')
        || has_short_option(arguments, 'R')
        || has_long_option(arguments, "--archive")
        || has_long_option(arguments, "--recursive");
    let mut lowering = sources_and_destination(parsed, "copy", FilesystemOperation::Read);
    for filesystem in &mut lowering.filesystems {
        if filesystem.1 == FilesystemOperation::Read {
            filesystem.2 = recursive;
        }
    }
    lowering
}

fn move_paths(arguments: &[Word]) -> Lowering {
    let parsed = scan(
        arguments,
        "finTtuv",
        &[
            "--force",
            "--interactive",
            "--no-clobber",
            "--no-copy",
            "--no-target-directory",
            "--strip-trailing-slashes",
            "--target-directory",
            "--update",
            "--verbose",
        ],
        &["--update="],
    );
    let mut lowering = sources_and_destination(parsed, "move", FilesystemOperation::Delete);
    lowering.root_move_destination = root_move_destination(arguments);
    lowering
}

fn root_move_destination(arguments: &[Word]) -> Option<usize> {
    let admitted = match arguments {
        [first, second] => {
            active_root_pattern(first) && ordinary_destination(second).is_some()
                || exact_word(first)
                    .and_then(|value| value.strip_prefix("--target-directory=").map(str::to_owned))
                    .is_some_and(|destination| {
                        !destination.is_empty() && !destination.contains('{')
                    })
                    && !contains_unquoted_pattern(first.raw())
                    && active_root_pattern(second)
        }
        [first, second, third] => {
            exact_word(first).as_deref() == Some("--")
                && active_root_pattern(second)
                && exact_destination(third).is_some()
                || matches!(
                    exact_word(first).as_deref(),
                    Some("-t" | "--target-directory")
                ) && exact_destination(second).is_some()
                    && active_root_pattern(third)
        }
        _ => false,
    };
    admitted.then_some(1)
}

fn active_root_pattern(word: &Word) -> bool {
    exact_word(word).as_deref() == Some("/*") && contains_unquoted_pattern(word.raw())
}

fn exact_destination(word: &Word) -> Option<String> {
    let destination = exact_word(word)?;
    (!destination.is_empty()
        && !destination.contains('{')
        && !contains_unquoted_pattern(word.raw()))
    .then_some(destination)
}

fn ordinary_destination(word: &Word) -> Option<String> {
    exact_destination(word).filter(|destination| !destination.starts_with('-'))
}

fn exact_word(word: &Word) -> Option<String> {
    static_filesystem_word(word.raw(), word.substitutions().is_empty())
}

fn sources_and_destination(
    mut parsed: Parsed,
    operation: &'static str,
    source_operation: FilesystemOperation,
) -> Lowering {
    if !parsed.exited
        && (parsed.operands.is_empty()
            || parsed.target_directory.is_none() && parsed.operands.len() < 2)
    {
        parsed.complete = false;
    }
    let mut filesystems = Vec::new();
    if !parsed.exited
        && let Some(destination) = parsed.target_directory.as_ref()
    {
        filesystems.extend(
            parsed
                .operands
                .iter()
                .flatten()
                .map(|target| (target.clone(), source_operation, false)),
        );
        filesystems.push((destination.clone(), FilesystemOperation::Write, false));
    } else if !parsed.exited
        && let Some((destination, sources)) = parsed.operands.split_last()
    {
        filesystems.extend(
            sources
                .iter()
                .flatten()
                .map(|target| (target.clone(), source_operation, false)),
        );
        if let Some(destination) = destination {
            filesystems.push((destination.clone(), FilesystemOperation::Write, false));
        }
    }
    Lowering {
        complete: parsed.complete,
        operation,
        filesystems,
        root_move_destination: None,
    }
}

fn remove(arguments: &[Word], rm: bool) -> Lowering {
    let allowed_short = if rm { "dfiIrRv" } else { "v" };
    let allowed_long = if rm {
        &[
            "--dir",
            "--force",
            "--no-preserve-root",
            "--one-file-system",
            "--recursive",
            "--verbose",
        ][..]
    } else {
        &["--ignore-fail-on-non-empty", "--verbose"][..]
    };
    let allowed_prefixes = if rm {
        &["--interactive=", "--preserve-root="][..]
    } else {
        &[][..]
    };
    let mut parsed = scan(arguments, allowed_short, allowed_long, allowed_prefixes);
    let recursive = if rm {
        has_short_option(arguments, 'r')
            || has_short_option(arguments, 'R')
            || has_long_option(arguments, "--recursive")
    } else {
        let parents = has_short_option(arguments, 'p') || has_long_option(arguments, "--parents");
        if parents {
            parsed.complete = false;
        }
        parents
    };
    if !parsed.exited && parsed.operands.is_empty() {
        parsed.complete = false;
    }
    Lowering {
        complete: parsed.complete,
        operation: "remove",
        filesystems: parsed
            .operands
            .into_iter()
            .flatten()
            .map(|target| (target, FilesystemOperation::Delete, recursive))
            .collect(),
        root_move_destination: None,
    }
}

fn unlink(arguments: &[Word]) -> Lowering {
    let mut parsed = scan(arguments, "", &[], &[]);
    if !parsed.exited && parsed.operands.len() != 1 {
        parsed.complete = false;
    }
    Lowering {
        complete: parsed.complete,
        operation: "remove",
        filesystems: parsed
            .operands
            .into_iter()
            .flatten()
            .map(|target| (target, FilesystemOperation::Delete, false))
            .collect(),
        root_move_destination: None,
    }
}

fn create(
    arguments: &[Word],
    operation: &'static str,
    allowed_short: &str,
    allowed_long: &[&str],
) -> Lowering {
    let mut parsed = scan(arguments, allowed_short, allowed_long, &[]);
    if !parsed.exited && parsed.operands.is_empty() {
        parsed.complete = false;
    }
    Lowering {
        complete: parsed.complete,
        operation,
        filesystems: parsed
            .operands
            .into_iter()
            .flatten()
            .map(|target| (target, FilesystemOperation::Write, false))
            .collect(),
        root_move_destination: None,
    }
}

struct Parsed {
    complete: bool,
    exited: bool,
    operands: Vec<Option<String>>,
    target_directory: Option<String>,
}

fn scan(
    arguments: &[Word],
    allowed_short: &str,
    allowed_long: &[&str],
    allowed_prefixes: &[&str],
) -> Parsed {
    let mut parsed = Parsed {
        complete: true,
        exited: false,
        operands: Vec::new(),
        target_directory: None,
    };
    let mut after_options = false;
    let parses_target_directory =
        allowed_short.contains('t') && allowed_long.contains(&"--target-directory");
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        let Some(value) =
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
        else {
            parsed.complete = false;
            parsed.operands.push(None);
            continue;
        };
        if parses_target_directory
            && !after_options
            && matches!(value.as_str(), "-t" | "--target-directory")
        {
            let Some(argument) = arguments.get(index) else {
                parsed.complete = false;
                continue;
            };
            index += 1;
            let Some(target) =
                static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
            else {
                parsed.complete = false;
                continue;
            };
            parsed.target_directory = Some(target);
        } else if parses_target_directory
            && !after_options
            && let Some(target) = value
                .strip_prefix("--target-directory=")
                .or_else(|| value.strip_prefix("-t").filter(|target| !target.is_empty()))
        {
            parsed.target_directory = Some(target.to_owned());
        } else if !after_options && value == "--" {
            if !parsed.operands.is_empty() {
                parsed.complete = false;
            }
            after_options = true;
        } else if !after_options && matches!(value.as_str(), "--help" | "--version") {
            if parsed.operands.is_empty() && parsed.complete {
                parsed.exited = true;
                break;
            }
            parsed.complete = false;
        } else if !after_options && value.starts_with("--") {
            if !parsed.operands.is_empty()
                || (!allowed_long.contains(&value.as_str())
                    && !allowed_prefixes
                        .iter()
                        .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len()))
            {
                parsed.complete = false;
            }
        } else if !after_options && value.starts_with('-') && value != "-" {
            if !parsed.operands.is_empty()
                || !value[1..]
                    .chars()
                    .all(|option| allowed_short.contains(option))
            {
                parsed.complete = false;
            }
        } else {
            parsed.operands.push(Some(value));
        }
    }
    parsed
}

fn has_short_option(arguments: &[Word], expected: char) -> bool {
    arguments
        .iter()
        .take_while(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
                .is_none_or(|value| value != "--")
        })
        .any(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty()).is_some_and(
                |value| {
                    value.starts_with('-')
                        && !value.starts_with("--")
                        && value[1..].chars().any(|option| option == expected)
                },
            )
        })
}

fn has_long_option(arguments: &[Word], expected: &str) -> bool {
    arguments
        .iter()
        .take_while(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
                .is_none_or(|value| value != "--")
        })
        .any(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
                .is_some_and(|value| value == expected)
        })
}
