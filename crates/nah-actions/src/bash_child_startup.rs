//! Parses the bounded environment and option state inherited by child Bash processes.

use nah_parse::{Statement, Word};

use crate::bash_execution::{shell_program, shell_syntax_check};
use crate::shell_word::static_word;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChildShell {
    pub(crate) argv0: Option<String>,
    pub(crate) argv0_argument: Option<usize>,
    pub(crate) positionals: Vec<Option<String>>,
    pub(crate) positional_arguments: Vec<usize>,
    pub(crate) imports_bash_environment: bool,
    pub(crate) runs_bash_env: bool,
    pub(crate) executes_payload: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EnvOperation {
    Clear,
    Unset(String),
    Function { name: String, definition: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnvOverlay {
    pub(crate) operations: Vec<EnvOperation>,
    pub(crate) complete: bool,
    pub(crate) analysis_refused: bool,
}

pub(crate) fn child_shell(program: &str, arguments: &[Word]) -> Option<ChildShell> {
    if !shell_program(program) {
        return None;
    }
    let noexec = shell_syntax_check(arguments);
    let mut privileged = false;
    let mut interactive = false;
    let mut stdin = false;
    let mut command = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index).and_then(static_argument) {
        if argument == "--" {
            index += 1;
            break;
        }
        if argument == "-" || !argument.starts_with(['-', '+']) {
            break;
        }
        if argument == "--privileged" {
            privileged = true;
            index += 1;
            continue;
        }
        if argument.starts_with("--") {
            index += 1;
            continue;
        }
        let enabled = argument.starts_with('-');
        let flags = &argument[1..];
        if flags.contains('p') {
            privileged = enabled;
        }
        if flags.contains('i') {
            interactive = enabled;
        }
        if flags.contains('s') {
            stdin = enabled;
        }
        if flags.contains('c') {
            let payload = index
                + 1
                + usize::from(
                    arguments
                        .get(index + 1)
                        .and_then(static_argument)
                        .is_some_and(|argument| argument == "--"),
                );
            command = Some(payload);
            break;
        }
        if flags.ends_with('o') || flags.ends_with('O') {
            index += 1;
        }
        index += 1;
    }
    let (argv0, argv0_argument, positionals, positional_arguments) = if let Some(payload) = command
    {
        (
            arguments
                .get(payload + 1)
                .and_then(static_argument)
                .or_else(|| (payload + 1 >= arguments.len()).then(|| program.to_owned())),
            arguments.get(payload + 1).map(|_| payload + 1),
            arguments
                .get(payload + 2..)
                .unwrap_or_default()
                .iter()
                .map(static_argument)
                .collect(),
            (payload + 2..arguments.len()).collect(),
        )
    } else if stdin
        || arguments
            .get(index)
            .is_none_or(|argument| static_argument(argument).as_deref() == Some("-"))
    {
        let start = index
            + usize::from(arguments.get(index).and_then(static_argument).as_deref() == Some("-"));
        (
            Some(program.to_owned()),
            None,
            arguments
                .get(start..)
                .unwrap_or_default()
                .iter()
                .map(static_argument)
                .collect(),
            (start..arguments.len()).collect(),
        )
    } else {
        (
            static_argument(&arguments[index]),
            Some(index),
            arguments
                .get(index + 1..)
                .unwrap_or_default()
                .iter()
                .map(static_argument)
                .collect(),
            (index + 1..arguments.len()).collect(),
        )
    };
    let imports_bash_environment = program == "bash" && !privileged;
    Some(ChildShell {
        argv0,
        argv0_argument,
        positionals,
        positional_arguments,
        imports_bash_environment,
        runs_bash_env: imports_bash_environment && !noexec && !interactive,
        executes_payload: !noexec,
    })
}

pub(crate) fn env_payload(arguments: &[Word]) -> Option<String> {
    let mut index = 0;
    let mut assignments = Vec::new();
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        let value = static_argument(argument)?;
        if options && value == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && matches!(value.as_str(), "-u" | "--unset") {
            index += 2;
            if index > arguments.len() {
                return None;
            }
            continue;
        }
        if options && value == "-S" {
            let split = arguments.get(index + 1).and_then(static_argument)?;
            let words = exact_env_split_words(&split)?;
            return Some(env_split_payload(words, &arguments[index + 2..]));
        }
        if options && let Some(split) = value.strip_prefix("--split-string=") {
            let words = exact_env_split_words(split)?;
            return Some(env_split_payload(words, &arguments[index + 1..]));
        }
        if options
            && (matches!(
                value.as_str(),
                "-i" | "--ignore-environment" | "-0" | "--null" | "-v" | "--debug"
            ) || value.starts_with("--unset="))
        {
            index += 1;
            continue;
        }
        if let Some((name, assigned)) = value.split_once('=')
            && (valid_assignment_name(name) || bash_function_name(name).is_some())
        {
            if bash_function_name(name).is_none() {
                assignments.push(format!("{name}='{}'", assigned.replace('\'', "'\\''")));
            }
            index += 1;
            continue;
        }
        if options && value.starts_with('-') {
            return None;
        }
        break;
    }
    let command = arguments.get(index)?;
    Some(
        assignments
            .into_iter()
            .chain(std::iter::once(command.raw().to_owned()))
            .chain(
                arguments[index + 1..]
                    .iter()
                    .map(|word| word.raw().to_owned()),
            )
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Decodes the quote-and-whitespace subset shared by GNU `env -S` and its
/// documented syntax. Escapes, comments, and environment expansion remain
/// partial instead of being guessed.
fn exact_env_split_words(value: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut quote = Quote::None;
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    for character in value.chars() {
        match (quote, character) {
            (Quote::None, character) if character.is_ascii_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (Quote::None, '\'') => {
                quote = Quote::Single;
                started = true;
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                started = true;
            }
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::None,
            (_, '\\' | '$' | '#') => return None,
            (_, character) => {
                word.push(character);
                started = true;
            }
        }
    }
    if quote != Quote::None {
        return None;
    }
    if started {
        words.push(word);
    }
    (!words.is_empty()).then_some(words)
}

fn env_split_payload(words: Vec<String>, trailing: &[Word]) -> String {
    let mut payload = vec!["env".to_owned()];
    payload.extend(
        words
            .into_iter()
            .map(|word| format!("'{}'", word.replace('\'', "'\\''"))),
    );
    payload.extend(trailing.iter().map(|word| word.raw().to_owned()));
    payload.join(" ")
}

pub(crate) fn env_overlay(program: &str, arguments: &[Word]) -> EnvOverlay {
    if program != "env" {
        return EnvOverlay {
            operations: Vec::new(),
            complete: true,
            analysis_refused: false,
        };
    }
    let mut overlay = EnvOverlay {
        operations: Vec::new(),
        complete: true,
        analysis_refused: false,
    };
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let Some(argument) = static_argument(argument) else {
            overlay.complete = false;
            break;
        };
        if argument == "--" {
            break;
        }
        if matches!(argument.as_str(), "-i" | "--ignore-environment") {
            overlay.operations.push(EnvOperation::Clear);
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "-u" | "--unset") {
            let Some(name) = arguments.get(index + 1).and_then(static_argument) else {
                overlay.complete = false;
                break;
            };
            overlay.operations.push(EnvOperation::Unset(name));
            index += 2;
            continue;
        }
        if let Some(name) = argument.strip_prefix("--unset=") {
            overlay
                .operations
                .push(EnvOperation::Unset(name.to_owned()));
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "-0" | "--null" | "-v" | "--debug") {
            index += 1;
            continue;
        }
        if let Some((wire, value)) = argument.split_once('=')
            && let Some(name) = bash_function_name(wire)
        {
            match exact_function_definition(name, value) {
                Ok(Some(definition)) => overlay.operations.push(EnvOperation::Function {
                    name: name.to_owned(),
                    definition,
                }),
                Ok(None) => {}
                Err(()) => {
                    overlay.complete = false;
                    overlay.analysis_refused = true;
                }
            }
            index += 1;
            continue;
        }
        if argument
            .split_once('=')
            .is_some_and(|(name, _)| valid_assignment_name(name))
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            overlay.complete = false;
        }
        break;
    }
    overlay
}

pub(crate) fn env_requires_refusal(program: &str, arguments: &[Word]) -> bool {
    if program != "env" {
        return false;
    }
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let Some(argument) = static_argument(argument) else {
            return true;
        };
        if argument == "--" {
            return false;
        }
        if matches!(argument.as_str(), "-u" | "--unset") {
            if arguments.get(index + 1).and_then(static_argument).is_none() {
                return true;
            }
            index += 2;
            continue;
        }
        if matches!(
            argument.as_str(),
            "-i" | "--ignore-environment" | "-0" | "--null" | "-v" | "--debug"
        ) || argument
            .strip_prefix("--unset=")
            .is_some_and(|name| !name.is_empty())
        {
            index += 1;
            continue;
        }
        if argument.split_once('=').is_some_and(|(name, _)| {
            valid_assignment_name(name) || bash_function_name(name).is_some()
        }) {
            index += 1;
            continue;
        }
        return argument.starts_with('-');
    }
    false
}

pub(crate) fn env_clears_name(program: &str, arguments: &[Word], name: &str) -> bool {
    let mut cleared = false;
    for operation in env_overlay(program, arguments).operations {
        match operation {
            EnvOperation::Clear => cleared = true,
            EnvOperation::Unset(unset) if unset == name => cleared = true,
            EnvOperation::Function { name: function, .. }
                if bash_function_wire_name(&function) == name =>
            {
                cleared = false
            }
            EnvOperation::Unset(_) | EnvOperation::Function { .. } => {}
        }
    }
    cleared
}

pub(crate) fn bash_function_wire_name(name: &str) -> String {
    format!("BASH_FUNC_{name}%%")
}

fn exact_function_definition(name: &str, value: &str) -> Result<Option<String>, ()> {
    if !value.trim_start().starts_with("()") {
        return Ok(None);
    }
    let definition = format!("{name}{value}");
    if definition.len() > crate::INVOCATION_EVIDENCE_CAP {
        return Err(());
    }
    let syntax = match nah_parse::normalize(&definition) {
        Ok(syntax) => syntax,
        Err(nah_parse::ParseError::ExceedsLimit(_)) => return Err(()),
        Err(_) => return Ok(None),
    };
    match syntax.statements() {
        [
            Statement::FunctionDefinition {
                name: parsed_name, ..
            },
        ] if parsed_name == name => Ok(Some(definition)),
        _ => Ok(None),
    }
}

fn bash_function_name(name: &str) -> Option<&str> {
    let name = name.strip_prefix("BASH_FUNC_")?.strip_suffix("%%")?;
    valid_assignment_name(name).then_some(name)
}

fn valid_assignment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn static_argument(argument: &Word) -> Option<String> {
    static_word(argument.raw(), argument.substitutions().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_env_function_wire() {
        assert!(
            exact_function_definition("f", "() { rm -rf /; }")
                .expect("bounded definition")
                .is_some()
        );
        let arguments = [
            Word::from_literal("BASH_FUNC_f%%=() { rm -rf /; }"),
            Word::from_literal("bash"),
            Word::from_literal("-c"),
            Word::from_literal("f"),
        ];
        let overlay = env_overlay("env", &arguments);
        assert!(
            matches!(
                overlay.operations.as_slice(),
                [EnvOperation::Function { name, .. }] if name == "f"
            ),
            "{overlay:?}"
        );
    }
}
