//! Recognizes complete commands that print inherited environment values.

use nah_parse::Word;

use crate::shell_word::static_word;

const CREDENTIAL_NAMES: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "DATABASE_URL",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "PGPASSWORD",
    "TWINE_PASSWORD",
    "VAULT_TOKEN",
];

pub(crate) fn operation(
    program: &str,
    arguments: &[Word],
    has_declaration_assignments: bool,
) -> Option<&'static str> {
    let arguments = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    match program {
        "env" => environment_dump(&arguments),
        "printenv" => printenv_dump(&arguments),
        "set" => arguments.is_empty(),
        "export" | "declare" | "typeset" => {
            !has_declaration_assignments && builtin_dump(&arguments)
        }
        _ => false,
    }
    .then_some("environment-disclosure")
}

fn environment_dump(arguments: &[String]) -> bool {
    let mut index = 0;
    let mut inherited = true;
    let mut after_options = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument.as_str(), "-i" | "--ignore-environment") {
            inherited = false;
        } else if !after_options && matches!(argument.as_str(), "-0" | "--null" | "-v" | "--debug")
        {
        } else if !after_options && matches!(argument.as_str(), "-u" | "--unset" | "-C" | "--chdir")
        {
            index += 1;
            if index == arguments.len() {
                return false;
            }
        } else if !after_options
            && (argument.starts_with("--unset=") || argument.starts_with("--chdir="))
        {
            if argument.ends_with('=') {
                return false;
            }
        } else if !after_options && argument.starts_with('-') {
            return false;
        } else if is_assignment(argument) {
        } else {
            return false;
        }
        index += 1;
    }
    inherited
}

fn printenv_dump(arguments: &[String]) -> bool {
    let mut names = arguments;
    if names
        .first()
        .is_some_and(|argument| matches!(argument.as_str(), "-0" | "--null"))
    {
        names = &names[1..];
    }
    !names.iter().any(|name| name.starts_with('-'))
        && (names.is_empty() || names.iter().any(|name| is_credential_name(name)))
}

fn builtin_dump(arguments: &[String]) -> bool {
    if arguments.is_empty() {
        return true;
    }
    let Some((print, names)) = arguments.split_first() else {
        return false;
    };
    print == "-p" && (names.is_empty() || names.iter().any(|name| is_credential_name(name)))
}

fn is_credential_name(name: &str) -> bool {
    CREDENTIAL_NAMES.contains(&name)
}

fn is_assignment(argument: &str) -> bool {
    let Some((name, _)) = argument.split_once('=') else {
        return false;
    };
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}
