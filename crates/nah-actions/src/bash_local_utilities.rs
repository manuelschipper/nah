//! Classifies fully lowered local utility invocations; it does not infer their effects.

use nah_parse::{Substitution, Word};
use nah_proto::action::{FilesystemOperation, SemanticCode};

use crate::bash_descriptor_paths::descriptor_reference_path;
use crate::shell_word::{
    contains_shell_pattern, has_unmodeled_expansion, static_filesystem_word, static_word,
};

use crate::bash_model::FilesystemSpec;

pub(crate) struct Lowering {
    pub(crate) complete: bool,
    pub(crate) filesystems: Vec<FilesystemSpec>,
    pub(crate) system_states: Vec<SemanticCode>,
}

impl Lowering {
    fn new() -> Self {
        Self {
            complete: true,
            filesystems: Vec::new(),
            system_states: Vec::new(),
        }
    }

    fn filesystem(&mut self, target: String, operation: FilesystemOperation) {
        if contains_shell_pattern(&target) || target.contains(['{', '}']) {
            self.complete = false;
        }
        self.filesystems.push((target, operation, false));
    }

    fn recursive_filesystem(&mut self, target: String, operation: FilesystemOperation) {
        if contains_shell_pattern(&target) || target.contains(['{', '}']) {
            self.complete = false;
        }
        self.filesystems.push((target, operation, true));
    }
}

pub(crate) fn lower(program: &str, arguments: &[Word]) -> Option<Lowering> {
    let mut lowering = match program {
        ":" | "echo" | "false" | "true" => Some(Lowering::new()),
        "break" | "continue" => Some(loop_control(arguments)),
        "cat" => Some(cat(arguments)),
        "cd" => Some(cd(arguments)),
        "cut" => Some(cut(arguments)),
        "date" => Some(date(arguments)),
        "grep" => Some(grep(arguments)),
        "head" => Some(head_or_tail(arguments)),
        "jq" => Some(jq(arguments)),
        "pwd" => Some(pwd(arguments)),
        "rg" => Some(rg(arguments)),
        "sort" => Some(sort(arguments)),
        "stat" => Some(stat(arguments)),
        "tail" => Some(head_or_tail(arguments)),
        "tee" => Some(tee(arguments)),
        "uniq" => Some(uniq(arguments)),
        "wc" => Some(wc(arguments)),
        _ => None,
    }?;
    if matches!(program, ":" | "echo" | "false" | "true")
        && arguments
            .iter()
            .any(|argument| has_unmodeled_expansion(argument.raw()))
    {
        lowering.complete = false;
    }
    Some(lowering)
}

fn loop_control(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    match arguments {
        [] => {}
        [levels] => {
            let Some(levels) = static_word(levels.raw(), levels.substitutions().is_empty()) else {
                lowering.complete = false;
                return lowering;
            };
            if levels
                .parse::<usize>()
                .ok()
                .is_none_or(|levels| levels == 0)
            {
                lowering.complete = false;
            }
        }
        _ => lowering.complete = false,
    }
    lowering
}

fn cd(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    match arguments {
        [] => {}
        [target] => {
            let Some(target) = static_word(target.raw(), target.substitutions().is_empty()) else {
                lowering.complete = false;
                return lowering;
            };
            if target != "-" && (target.starts_with('-') || contains_shell_pattern(&target)) {
                lowering.complete = false;
            }
        }
        _ => lowering.complete = false,
    }
    lowering
}

fn cat(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut after_options = false;
    let mut saw_operand = false;
    for argument in arguments {
        if process_path(argument) {
            saw_operand = true;
            continue;
        }
        let Some(value) = filesystem_word(argument) else {
            lowering.complete = false;
            saw_operand = true;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if !after_options && matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if !after_options && value.starts_with("--") {
            if !matches!(
                value.as_str(),
                "--show-all"
                    | "--number-nonblank"
                    | "--show-ends"
                    | "--number"
                    | "--squeeze-blank"
                    | "--show-tabs"
                    | "--show-nonprinting"
            ) {
                lowering.complete = false;
            }
        } else if !after_options && value.starts_with('-') && value != "-" {
            if !value[1..].chars().all(|flag| {
                matches!(
                    flag,
                    'A' | 'b' | 'e' | 'E' | 'n' | 's' | 't' | 'T' | 'u' | 'v'
                )
            }) {
                lowering.complete = false;
            }
        } else {
            saw_operand = true;
            if value != "-" {
                lowering.filesystem(value, FilesystemOperation::Read);
            }
        }
    }
    lowering
}

fn head_or_tail(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut saw_operand = false;
    while index < arguments.len() {
        if process_path(&arguments[index]) {
            saw_operand = true;
            index += 1;
            continue;
        }
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if after_options || !value.starts_with('-') || value == "-" {
            saw_operand = true;
            if value != "-" {
                lowering.filesystem(value, FilesystemOperation::Read);
            }
        } else if matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if matches!(value.as_str(), "-c" | "--bytes" | "-n" | "--lines") {
            consume_value(arguments, &mut index, &mut lowering);
        } else if value.starts_with("--bytes=")
            || value.starts_with("--lines=")
            || matches!(value.as_str(), "-q" | "-v" | "-z")
            || matches!(
                value.as_str(),
                "--quiet" | "--silent" | "--verbose" | "--zero-terminated"
            )
            || value.len() > 2
                && (value.starts_with("-c")
                    || value.starts_with("-n")
                    || value[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            // Fully accounted display option.
        } else {
            lowering.complete = false;
        }
        index += 1;
    }
    lowering
}

fn pwd(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    for (index, argument) in arguments.iter().enumerate() {
        let Some(value) = static_word(argument.raw(), argument.substitutions().is_empty()) else {
            lowering.complete = false;
            continue;
        };
        if matches!(value.as_str(), "-L" | "-P") {
            continue;
        }
        if index == 0 && matches!(value.as_str(), "--help" | "--version") {
            return Lowering::new();
        }
        lowering.complete = false;
    }
    lowering
}

fn wc(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut saw_operand = false;
    while index < arguments.len() {
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if after_options || !value.starts_with('-') || value == "-" {
            saw_operand = true;
            if value != "-" {
                lowering.filesystem(value, FilesystemOperation::Read);
            }
        } else if matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if let Some(target) = value.strip_prefix("--files0-from=") {
            lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
            // The named file supplies additional paths that are not visible in
            // the shell syntax.
            lowering.complete = false;
        } else if value == "--files0-from" {
            consume_filesystem(
                arguments,
                &mut index,
                FilesystemOperation::Read,
                &mut lowering,
            );
            lowering.complete = false;
        } else if matches!(
            value.as_str(),
            "--bytes"
                | "--chars"
                | "--lines"
                | "--max-line-length"
                | "--words"
                | "--total=auto"
                | "--total=always"
                | "--total=only"
                | "--total=never"
        ) || value[1..]
            .chars()
            .all(|flag| matches!(flag, 'c' | 'm' | 'l' | 'L' | 'w'))
        {
            // Fully accounted counting option.
        } else {
            lowering.complete = false;
        }
        index += 1;
    }
    lowering
}

fn stat(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut saw_operand = false;
    while index < arguments.len() {
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if after_options || !value.starts_with('-') || value == "-" {
            saw_operand = true;
            lowering.filesystem(value, FilesystemOperation::Read);
        } else if matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if matches!(value.as_str(), "-c" | "--format" | "--printf") {
            consume_value(arguments, &mut index, &mut lowering);
        } else if value.starts_with("--format=")
            || value.starts_with("--printf=")
            || matches!(
                value.as_str(),
                "-L" | "-f" | "-t" | "--dereference" | "--file-system" | "--terse"
            )
        {
            // Fully accounted metadata or output option.
        } else {
            lowering.complete = false;
        }
        index += 1;
    }
    lowering
}

fn cut(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut saw_operand = false;
    while index < arguments.len() {
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if after_options || !value.starts_with('-') || value == "-" {
            saw_operand = true;
            if value != "-" {
                lowering.filesystem(value, FilesystemOperation::Read);
            }
        } else if matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if matches!(
            value.as_str(),
            "-b" | "-c" | "-d" | "-f" | "--bytes" | "--characters" | "--delimiter" | "--fields"
        ) {
            consume_value(arguments, &mut index, &mut lowering);
        } else if value.starts_with("--bytes=")
            || value.starts_with("--characters=")
            || value.starts_with("--delimiter=")
            || value.starts_with("--fields=")
            || value.starts_with("--output-delimiter=")
            || matches!(
                value.as_str(),
                "-n" | "-s" | "-z" | "--complement" | "--only-delimited" | "--zero-terminated"
            )
            || value.len() > 2 && matches!(value.as_bytes().get(1), Some(b'b' | b'c' | b'd' | b'f'))
        {
            // Fully accounted selection or output option.
        } else if value == "--output-delimiter" {
            consume_value(arguments, &mut index, &mut lowering);
        } else {
            lowering.complete = false;
        }
        index += 1;
    }
    lowering
}

fn uniq(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut operands = Vec::new();
    while index < arguments.len() {
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            index += 1;
            continue;
        };
        if !after_options && value == "--" {
            after_options = true;
        } else if after_options || !value.starts_with('-') || value == "-" {
            operands.push(value);
        } else if matches!(value.as_str(), "--help" | "--version") {
            if operands.is_empty() && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if matches!(
            value.as_str(),
            "-f" | "-s" | "-w" | "--skip-fields" | "--skip-chars" | "--check-chars"
        ) {
            consume_value(arguments, &mut index, &mut lowering);
        } else if value.starts_with("--skip-fields=")
            || value.starts_with("--skip-chars=")
            || value.starts_with("--check-chars=")
            || value.starts_with("--group=")
            || value.starts_with("--all-repeated=")
            || matches!(
                value.as_str(),
                "-c" | "-d"
                    | "-D"
                    | "-i"
                    | "-u"
                    | "-z"
                    | "--count"
                    | "--repeated"
                    | "--all-repeated"
                    | "--ignore-case"
                    | "--unique"
                    | "--zero-terminated"
                    | "--group"
            )
        {
            // Fully accounted comparison or display option.
        } else {
            lowering.complete = false;
        }
        index += 1;
    }
    if operands.len() > 2 {
        lowering.complete = false;
    }
    if let Some(input) = operands.first().filter(|target| target.as_str() != "-") {
        lowering.filesystem(input.clone(), FilesystemOperation::Read);
    }
    if let Some(output) = operands.get(1).filter(|target| target.as_str() != "-") {
        lowering.filesystem(output.clone(), FilesystemOperation::Write);
    }
    lowering
}

fn grep(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut pattern_supplied = false;
    let mut saw_operand = false;
    let mut recursive = false;
    while index < arguments.len() {
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && value == "--" {
            after_options = true;
        } else if !after_options && value.starts_with("--") {
            if matches!(value.as_str(), "--help" | "--version") {
                if !saw_operand && lowering.complete {
                    return Lowering::new();
                }
                lowering.complete = false;
            } else if matches!(value.as_str(), "--regexp" | "--file" | "--exclude-from") {
                if matches!(value.as_str(), "--file" | "--exclude-from") {
                    consume_filesystem(
                        arguments,
                        &mut index,
                        FilesystemOperation::Read,
                        &mut lowering,
                    );
                } else {
                    consume_value(arguments, &mut index, &mut lowering);
                }
                if value != "--exclude-from" {
                    pattern_supplied = true;
                }
            } else if let Some(target) = value.strip_prefix("--file=") {
                lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
                pattern_supplied = true;
            } else if let Some(target) = value.strip_prefix("--exclude-from=") {
                lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
            } else if value.starts_with("--regexp=") {
                pattern_supplied = true;
            } else if value == "--recursive" {
                recursive = true;
            } else if value == "--dereference-recursive" {
                recursive = true;
                lowering.complete = false;
            } else if grep_long_option(&value) {
                // Fully accounted selection or display option.
            } else if grep_long_value_option(&value) {
                consume_value(arguments, &mut index, &mut lowering);
            } else if grep_long_attached_option(&value) {
                // Fully accounted option with an attached value.
            } else {
                lowering.complete = false;
            }
        } else if !after_options && value.starts_with('-') && value != "-" {
            parse_grep_short(
                &value,
                arguments,
                &mut index,
                &mut pattern_supplied,
                &mut recursive,
                &mut lowering,
            );
        } else if !pattern_supplied {
            pattern_supplied = true;
            saw_operand = true;
        } else {
            saw_operand = true;
            if value != "-" {
                if recursive {
                    lowering.recursive_filesystem(value, FilesystemOperation::Read);
                } else {
                    lowering.filesystem(value, FilesystemOperation::Read);
                }
            }
        }
        index += 1;
    }
    if !pattern_supplied {
        lowering.complete = false;
    }
    lowering
}

fn grep_long_option(value: &str) -> bool {
    matches!(
        value,
        "--basic-regexp"
            | "--extended-regexp"
            | "--fixed-strings"
            | "--perl-regexp"
            | "--ignore-case"
            | "--no-ignore-case"
            | "--word-regexp"
            | "--line-regexp"
            | "--null-data"
            | "--no-messages"
            | "--invert-match"
            | "--version"
            | "--help"
            | "--byte-offset"
            | "--line-number"
            | "--line-buffered"
            | "--with-filename"
            | "--no-filename"
            | "--only-matching"
            | "--quiet"
            | "--silent"
            | "--text"
            | "--binary"
            | "--files-without-match"
            | "--files-with-matches"
            | "--count"
            | "--initial-tab"
            | "--null"
            | "--color"
            | "--colour"
            | "--no-group-separator"
    )
}

fn grep_long_value_option(value: &str) -> bool {
    matches!(
        value,
        "--after-context"
            | "--before-context"
            | "--context"
            | "--max-count"
            | "--label"
            | "--binary-files"
            | "--directories"
            | "--devices"
            | "--include"
            | "--exclude"
            | "--exclude-dir"
            | "--group-separator"
    )
}

fn grep_long_attached_option(value: &str) -> bool {
    [
        "--after-context=",
        "--before-context=",
        "--context=",
        "--max-count=",
        "--label=",
        "--binary-files=",
        "--directories=",
        "--devices=",
        "--include=",
        "--exclude=",
        "--exclude-dir=",
        "--group-separator=",
        "--color=",
        "--colour=",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}

fn parse_grep_short(
    value: &str,
    arguments: &[Word],
    index: &mut usize,
    pattern_supplied: &mut bool,
    recursive: &mut bool,
    lowering: &mut Lowering,
) {
    let flags = value[1..].char_indices();
    for (offset, flag) in flags {
        if matches!(flag, 'e' | 'f') {
            let attached = &value[offset + 2..];
            if flag == 'f' {
                if attached.is_empty() {
                    consume_filesystem(arguments, index, FilesystemOperation::Read, lowering);
                } else {
                    lowering.filesystem(attached.to_owned(), FilesystemOperation::Read);
                }
            } else if attached.is_empty() {
                consume_value(arguments, index, lowering);
            }
            *pattern_supplied = true;
            return;
        }
        if matches!(flag, 'A' | 'B' | 'C' | 'D' | 'd' | 'm') {
            if value[offset + 2..].is_empty() {
                consume_value(arguments, index, lowering);
            }
            return;
        }
        if matches!(flag, 'r' | 'R') {
            *recursive = true;
            if flag == 'R' {
                lowering.complete = false;
            }
        } else if !matches!(
            flag,
            'E' | 'F'
                | 'G'
                | 'P'
                | 'i'
                | 'w'
                | 'x'
                | 'z'
                | 's'
                | 'v'
                | 'b'
                | 'n'
                | 'H'
                | 'h'
                | 'o'
                | 'q'
                | 'a'
                | 'I'
                | 'L'
                | 'l'
                | 'c'
                | 'T'
                | 'Z'
        ) {
            lowering.complete = false;
        }
    }
}

fn rg(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut pattern_supplied = false;
    let mut files_mode = false;
    let mut paths = Vec::new();
    while index < arguments.len() {
        let Some(value) = filesystem_word(&arguments[index]) else {
            lowering.complete = false;
            index += 1;
            continue;
        };
        if !after_options && value == "--" {
            after_options = true;
        } else if !after_options && value.starts_with("--") {
            if matches!(value.as_str(), "--help" | "--version") {
                if index == 0 && lowering.complete {
                    return Lowering::new();
                }
                lowering.complete = false;
            } else if value == "--files" {
                files_mode = true;
                pattern_supplied = true;
            } else if value == "--regexp" {
                consume_value(arguments, &mut index, &mut lowering);
                pattern_supplied = true;
            } else if value.starts_with("--regexp=") {
                pattern_supplied = true;
            } else if matches!(value.as_str(), "--file" | "--ignore-file") {
                consume_filesystem(
                    arguments,
                    &mut index,
                    FilesystemOperation::Read,
                    &mut lowering,
                );
                if value == "--file" {
                    pattern_supplied = true;
                }
            } else if let Some(target) = value
                .strip_prefix("--file=")
                .or_else(|| value.strip_prefix("--ignore-file="))
            {
                lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
                if value.starts_with("--file=") {
                    pattern_supplied = true;
                }
            } else if matches!(value.as_str(), "--pre" | "--pre-glob") {
                // `--pre` can execute an arbitrary command. Keep the visible
                // invocation partial so it can never be cleared as a utility.
                consume_value(arguments, &mut index, &mut lowering);
                lowering.complete = false;
            } else if rg_long_value_option(&value) {
                consume_value(arguments, &mut index, &mut lowering);
            } else if value == "--follow" {
                lowering.complete = false;
            } else if rg_long_attached_option(&value) || rg_long_option(&value) {
                // Fully accounted search or display option.
            } else {
                lowering.complete = false;
            }
        } else if !after_options && value.starts_with('-') && value != "-" {
            parse_rg_short(
                &value,
                arguments,
                &mut index,
                &mut pattern_supplied,
                &mut lowering,
            );
        } else if !pattern_supplied && !files_mode {
            pattern_supplied = true;
        } else {
            paths.push(value);
        }
        index += 1;
    }
    if !pattern_supplied {
        lowering.complete = false;
    }
    if paths.is_empty() && pattern_supplied {
        paths.push(".".to_owned());
    }
    for path in paths.into_iter().filter(|path| path != "-") {
        lowering.recursive_filesystem(path, FilesystemOperation::Read);
    }
    lowering
}

fn rg_long_option(value: &str) -> bool {
    matches!(
        value,
        "--binary"
            | "--block-buffered"
            | "--byte-offset"
            | "--case-sensitive"
            | "--column"
            | "--count"
            | "--count-matches"
            | "--crlf"
            | "--debug"
            | "--files-with-matches"
            | "--files-without-match"
            | "--fixed-strings"
            | "--glob-case-insensitive"
            | "--heading"
            | "--hidden"
            | "--ignore-case"
            | "--invert-match"
            | "--json"
            | "--line-buffered"
            | "--line-number"
            | "--max-columns-preview"
            | "--mmap"
            | "--multiline"
            | "--multiline-dotall"
            | "--no-config"
            | "--no-filename"
            | "--no-heading"
            | "--no-ignore"
            | "--no-ignore-dot"
            | "--no-ignore-exclude"
            | "--no-ignore-files"
            | "--no-ignore-global"
            | "--no-ignore-messages"
            | "--no-ignore-parent"
            | "--no-ignore-vcs"
            | "--no-line-number"
            | "--no-messages"
            | "--no-pcre2-unicode"
            | "--no-require-git"
            | "--no-unicode"
            | "--null"
            | "--null-data"
            | "--one-file-system"
            | "--only-matching"
            | "--passthru"
            | "--pcre2"
            | "--pcre2-unicode"
            | "--pretty"
            | "--quiet"
            | "--search-zip"
            | "--smart-case"
            | "--stats"
            | "--stop-on-nonmatch"
            | "--text"
            | "--trim"
            | "--type-list"
            | "--unrestricted"
            | "--vimgrep"
            | "--with-filename"
            | "--word-regexp"
            | "--line-regexp"
    )
}

fn rg_long_value_option(value: &str) -> bool {
    matches!(
        value,
        "--after-context"
            | "--before-context"
            | "--context"
            | "--color"
            | "--colors"
            | "--context-separator"
            | "--dfa-size-limit"
            | "--encoding"
            | "--engine"
            | "--field-context-separator"
            | "--field-match-separator"
            | "--glob"
            | "--iglob"
            | "--max-columns"
            | "--max-count"
            | "--max-depth"
            | "--max-filesize"
            | "--path-separator"
            | "--regex-size-limit"
            | "--replace"
            | "--sort"
            | "--sortr"
            | "--threads"
            | "--type"
            | "--type-add"
            | "--type-clear"
            | "--type-not"
    )
}

fn rg_long_attached_option(value: &str) -> bool {
    [
        "--after-context=",
        "--before-context=",
        "--context=",
        "--color=",
        "--colors=",
        "--context-separator=",
        "--dfa-size-limit=",
        "--encoding=",
        "--engine=",
        "--field-context-separator=",
        "--field-match-separator=",
        "--glob=",
        "--iglob=",
        "--max-columns=",
        "--max-count=",
        "--max-depth=",
        "--max-filesize=",
        "--path-separator=",
        "--regex-size-limit=",
        "--replace=",
        "--sort=",
        "--sortr=",
        "--threads=",
        "--type=",
        "--type-add=",
        "--type-clear=",
        "--type-not=",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}

fn parse_rg_short(
    value: &str,
    arguments: &[Word],
    index: &mut usize,
    pattern_supplied: &mut bool,
    lowering: &mut Lowering,
) {
    let flags = value[1..].char_indices();
    for (offset, flag) in flags {
        if matches!(flag, 'e' | 'f') {
            let attached = &value[offset + 2..];
            if flag == 'f' {
                if attached.is_empty() {
                    consume_filesystem(arguments, index, FilesystemOperation::Read, lowering);
                } else {
                    lowering.filesystem(attached.to_owned(), FilesystemOperation::Read);
                }
            } else if attached.is_empty() {
                consume_value(arguments, index, lowering);
            }
            *pattern_supplied = true;
            return;
        }
        if matches!(
            flag,
            'A' | 'B' | 'C' | 'E' | 'g' | 'j' | 'M' | 'm' | 'r' | 't' | 'T'
        ) {
            if value[offset + 2..].is_empty() {
                consume_value(arguments, index, lowering);
            }
            return;
        }
        if flag == 'L' {
            lowering.complete = false;
        }
        if !matches!(
            flag,
            'a' | 'b'
                | 'c'
                | 'F'
                | 'h'
                | 'H'
                | 'i'
                | 'I'
                | 'l'
                | 'L'
                | 'n'
                | 'N'
                | 'o'
                | 'p'
                | 'q'
                | 's'
                | 'S'
                | 'u'
                | 'v'
                | 'w'
                | 'x'
                | 'z'
        ) {
            lowering.complete = false;
        }
    }
}

fn jq(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut filter_supplied = false;
    let mut arguments_are_values = false;
    let mut explicit_library_path = false;
    while index < arguments.len() {
        let Some(value) = static_word(
            arguments[index].raw(),
            arguments[index].substitutions().is_empty(),
        ) else {
            lowering.complete = false;
            index += 1;
            continue;
        };
        if !after_options && value == "--" {
            after_options = true;
        } else if !after_options && matches!(value.as_str(), "--help" | "--version") {
            if index == 0 && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if !after_options && matches!(value.as_str(), "-f" | "--from-file") {
            consume_filesystem(
                arguments,
                &mut index,
                FilesystemOperation::Read,
                &mut lowering,
            );
            filter_supplied = true;
        } else if !after_options && matches!(value.as_str(), "-L" | "--library-path") {
            if let Some(target) = arguments.get(index + 1).and_then(filesystem_word) {
                lowering.recursive_filesystem(target, FilesystemOperation::Read);
                explicit_library_path = true;
                index += 1;
            } else {
                lowering.complete = false;
            }
        } else if !after_options
            && matches!(value.as_str(), "--slurpfile" | "--rawfile" | "--argfile")
        {
            if index + 2 < arguments.len() {
                index += 1;
                consume_filesystem(
                    arguments,
                    &mut index,
                    FilesystemOperation::Read,
                    &mut lowering,
                );
            } else {
                lowering.complete = false;
            }
        } else if !after_options && matches!(value.as_str(), "--arg" | "--argjson") {
            if index + 2 < arguments.len() {
                index += 2;
            } else {
                lowering.complete = false;
            }
        } else if !after_options && matches!(value.as_str(), "--args" | "--jsonargs") {
            arguments_are_values = true;
        } else if !after_options && jq_long_option(&value) {
            // Fully accounted input or output option.
        } else if !after_options && value.starts_with("--") {
            lowering.complete = false;
        } else if !after_options
            && (value.starts_with('-')
                && value != "-"
                && value[1..].chars().all(|flag| {
                    matches!(
                        flag,
                        'c' | 'n' | 'e' | 's' | 'R' | 'r' | 'S' | 'C' | 'M' | 'a' | 'j' | 'V' | 'b'
                    )
                }))
        {
            // Fully accounted input or output option.
        } else if !filter_supplied {
            filter_supplied = true;
            if jq_filter_reads_unmodeled_state(&value, explicit_library_path) {
                // Imports without an explicit library path can read from
                // implementation-defined search directories.
                lowering.complete = false;
            }
        } else if !arguments_are_values && value != "-" {
            lowering.filesystem(value, FilesystemOperation::Read);
        }
        index += 1;
    }
    if !filter_supplied {
        lowering.complete = false;
    }
    lowering
}

fn jq_filter_reads_unmodeled_state(filter: &str, explicit_library_path: bool) -> bool {
    filter
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|word| {
            matches!(word, "env" | "ENV")
                || !explicit_library_path && matches!(word, "import" | "include")
        })
}

fn jq_long_option(value: &str) -> bool {
    matches!(
        value,
        "--compact-output"
            | "--null-input"
            | "--exit-status"
            | "--slurp"
            | "--raw-input"
            | "--sort-keys"
            | "--color-output"
            | "--monochrome-output"
            | "--ascii-output"
            | "--join-output"
            | "--raw-output"
            | "--raw-output0"
            | "--binary"
            | "--seq"
            | "--stream"
            | "--stream-errors"
            | "--unbuffered"
    )
}

fn tee(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut after_options = false;
    let mut saw_operand = false;
    for argument in arguments {
        if process_path(argument) {
            saw_operand = true;
            continue;
        }
        let Some(value) = filesystem_word(argument) else {
            lowering.complete = false;
            saw_operand = true;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if !after_options && matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if !after_options && value.starts_with("--") {
            let valid_output_error = value.strip_prefix("--output-error=").is_some_and(|mode| {
                matches!(mode, "warn" | "warn-nopipe" | "exit" | "exit-nopipe")
            });
            if !valid_output_error
                && !matches!(
                    value.as_str(),
                    "--append" | "--ignore-interrupts" | "--output-error"
                )
            {
                lowering.complete = false;
            }
        } else if !after_options && value.starts_with('-') && value != "-" {
            if !value[1..]
                .chars()
                .all(|flag| matches!(flag, 'a' | 'i' | 'p'))
            {
                lowering.complete = false;
            }
        } else {
            saw_operand = true;
            lowering.filesystem(value, FilesystemOperation::Write);
        }
    }
    lowering
}

fn date(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut saw_operand = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        let Some(value) = static_word(argument.raw(), argument.substitutions().is_empty()) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && value == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if after_options {
            saw_operand = true;
            if !value.starts_with('+') {
                lowering.complete = false;
            }
            index += 1;
            continue;
        }
        if value.starts_with('+') {
            saw_operand = true;
        }
        if saw_operand && value.starts_with('-') {
            lowering.complete = false;
        }
        if matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if matches!(value.as_str(), "-s" | "--set") {
            lowering.system_states.push(SemanticCode::CLOCK_SET);
            if index + 1 >= arguments.len() {
                lowering.complete = false;
            } else {
                index += 1;
            }
        } else if value.starts_with("--set=") || (value.starts_with("-s") && value.len() > 2) {
            lowering.system_states.push(SemanticCode::CLOCK_SET);
        } else if matches!(value.as_str(), "-f" | "--file" | "-r" | "--reference") {
            if let Some(target) = arguments.get(index + 1).and_then(filesystem_word) {
                lowering.filesystem(target, FilesystemOperation::Read);
                index += 1;
            } else {
                lowering.complete = false;
            }
        } else if let Some(target) = value
            .strip_prefix("--file=")
            .or_else(|| value.strip_prefix("--reference="))
            .or_else(|| value.strip_prefix("-f").filter(|_| value.len() > 2))
            .or_else(|| value.strip_prefix("-r").filter(|_| value.len() > 2))
        {
            lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
        } else if matches!(value.as_str(), "-d" | "--date") {
            if index + 1 >= arguments.len() {
                lowering.complete = false;
            } else {
                index += 1;
            }
        } else if value.starts_with("--date=")
            || value.starts_with("-d") && value.len() > 2
            || value.starts_with('+')
            || matches!(
                value.as_str(),
                "-I" | "-R"
                    | "-u"
                    | "--debug"
                    | "--iso-8601"
                    | "--resolution"
                    | "--rfc-email"
                    | "--universal"
                    | "--utc"
            )
            || value.starts_with("-I") && value.len() > 2
            || value.starts_with("--iso-8601=")
            || value.starts_with("--rfc-3339=")
        {
            // Fully accounted display-only option.
        } else {
            saw_operand = true;
            lowering.complete = false;
        }
        index += 1;
    }
    lowering.system_states.sort_unstable();
    lowering.system_states.dedup();
    lowering
}

fn sort(arguments: &[Word]) -> Lowering {
    let mut lowering = Lowering::new();
    let mut index = 0;
    let mut after_options = false;
    let mut saw_operand = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if process_path(argument) {
            saw_operand = true;
            index += 1;
            continue;
        }
        let Some(value) = filesystem_word(argument) else {
            lowering.complete = false;
            saw_operand = true;
            index += 1;
            continue;
        };
        if !after_options && saw_operand && value.starts_with('-') && value != "-" {
            lowering.complete = false;
        }
        if !after_options && value == "--" {
            after_options = true;
        } else if after_options || !value.starts_with('-') || value == "-" {
            saw_operand = true;
            if value != "-" {
                lowering.filesystem(value, FilesystemOperation::Read);
            }
        } else if matches!(value.as_str(), "--help" | "--version") {
            if !saw_operand && lowering.complete {
                return Lowering::new();
            }
            lowering.complete = false;
        } else if matches!(value.as_str(), "-o" | "--output") {
            if let Some(target) = arguments.get(index + 1).and_then(filesystem_word) {
                lowering.filesystem(target, FilesystemOperation::Write);
                index += 1;
            } else {
                lowering.complete = false;
            }
        } else if let Some(target) = value
            .strip_prefix("--output=")
            .or_else(|| value.strip_prefix("-o").filter(|_| value.len() > 2))
        {
            lowering.filesystem(target.to_owned(), FilesystemOperation::Write);
        } else if value == "--random-source" {
            consume_filesystem(
                arguments,
                &mut index,
                FilesystemOperation::Read,
                &mut lowering,
            );
        } else if let Some(target) = value.strip_prefix("--random-source=") {
            lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
        } else if value == "--files0-from" {
            consume_filesystem(
                arguments,
                &mut index,
                FilesystemOperation::Read,
                &mut lowering,
            );
            lowering.complete = false;
        } else if let Some(target) = value.strip_prefix("--files0-from=") {
            lowering.filesystem(target.to_owned(), FilesystemOperation::Read);
            lowering.complete = false;
        } else if matches!(value.as_str(), "-T" | "--temporary-directory") {
            consume_filesystem(
                arguments,
                &mut index,
                FilesystemOperation::Write,
                &mut lowering,
            );
        } else if let Some(target) = value
            .strip_prefix("--temporary-directory=")
            .or_else(|| value.strip_prefix("-T").filter(|_| value.len() > 2))
        {
            lowering.filesystem(target.to_owned(), FilesystemOperation::Write);
        } else if matches!(value.as_str(), "-S" | "--buffer-size" | "--parallel") {
            if index + 1 >= arguments.len() {
                lowering.complete = false;
            } else {
                index += 1;
            }
        } else if value.starts_with("--buffer-size=")
            || value.starts_with("--parallel=")
            || value.starts_with("-S") && value.len() > 2
        {
            // Fully accounted resource option.
        } else if matches!(value.as_str(), "-k" | "--key" | "-t" | "--field-separator") {
            if index + 1 >= arguments.len() {
                lowering.complete = false;
            } else {
                index += 1;
            }
        } else if value.starts_with("--key=")
            || value.starts_with("--field-separator=")
            || value.starts_with("-k") && value.len() > 2
            || value.starts_with("-t") && value.len() > 2
            || matches!(
                value.as_str(),
                "--ignore-leading-blanks"
                    | "--dictionary-order"
                    | "--ignore-case"
                    | "--general-numeric-sort"
                    | "--human-numeric-sort"
                    | "--ignore-nonprinting"
                    | "--month-sort"
                    | "--numeric-sort"
                    | "--random-sort"
                    | "--reverse"
                    | "--stable"
                    | "--unique"
                    | "--version-sort"
                    | "--zero-terminated"
                    | "--check"
                    | "--merge"
            )
            || value.starts_with("--check=")
            || value[1..].chars().all(|flag| {
                matches!(
                    flag,
                    'b' | 'd'
                        | 'f'
                        | 'g'
                        | 'h'
                        | 'i'
                        | 'M'
                        | 'm'
                        | 'n'
                        | 'R'
                        | 'r'
                        | 's'
                        | 'u'
                        | 'V'
                        | 'z'
                        | 'c'
                        | 'C'
                )
            })
        {
            // Fully accounted comparison or display option.
        } else {
            lowering.complete = false;
        }
        index += 1;
    }
    lowering
}

fn filesystem_word(argument: &Word) -> Option<String> {
    static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
        .or_else(|| descriptor_reference_path(argument.raw()))
}

fn consume_filesystem(
    arguments: &[Word],
    index: &mut usize,
    operation: FilesystemOperation,
    lowering: &mut Lowering,
) {
    if let Some(target) = arguments.get(*index + 1).and_then(filesystem_word) {
        lowering.filesystem(target, operation);
        *index += 1;
    } else {
        lowering.complete = false;
    }
}

fn consume_value(arguments: &[Word], index: &mut usize, lowering: &mut Lowering) {
    if arguments
        .get(*index + 1)
        .and_then(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .is_some()
    {
        *index += 1;
    } else {
        lowering.complete = false;
    }
}

fn process_path(argument: &Word) -> bool {
    match argument.substitutions() {
        [Substitution::ProcessInput { .. }] => {
            argument.raw().starts_with("<(") && argument.raw().ends_with(')')
        }
        [Substitution::ProcessOutput { .. }] => {
            argument.raw().starts_with(">(") && argument.raw().ends_with(')')
        }
        _ => false,
    }
}
