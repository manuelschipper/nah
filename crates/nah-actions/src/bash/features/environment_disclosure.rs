//! Recognizes complete commands that print inherited environment values.

use nah_parse::Word;

use crate::bash_model::VariableValue;
use crate::bash_state::VariableBinding;
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
    resolved_arguments: &[Word],
    source_arguments: &[Word],
    has_declaration_assignments: bool,
    local_variables: &[VariableBinding],
    ambient_variables: &[(String, VariableValue)],
) -> Option<&'static str> {
    let arguments = resolved_arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>();
    match program {
        "env" => environment_dump(arguments.as_deref()?).then_some("environment-disclosure"),
        "printenv" => printenv_operation(arguments.as_deref()?),
        "set" if arguments.as_ref().is_some_and(Vec::is_empty) => Some("environment-disclosure"),
        "export" | "declare" | "typeset" if !has_declaration_assignments => {
            builtin_operation(arguments.as_deref()?)
        }
        "echo" | "printf"
            if source_arguments.iter().any(|argument| {
                discloses_credential_expansion(argument.raw(), local_variables, ambient_variables)
            }) =>
        {
            Some("credential-disclosure")
        }
        _ => None,
    }
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

fn printenv_operation(arguments: &[String]) -> Option<&'static str> {
    let mut names = arguments;
    if names
        .first()
        .is_some_and(|argument| matches!(argument.as_str(), "-0" | "--null"))
    {
        names = &names[1..];
    }
    if names.iter().any(|name| name.starts_with('-')) {
        return None;
    }
    if names.is_empty() {
        Some("environment-disclosure")
    } else if names.iter().any(|name| is_credential_name(name)) {
        Some("credential-disclosure")
    } else {
        None
    }
}

fn builtin_operation(arguments: &[String]) -> Option<&'static str> {
    if arguments.is_empty() {
        return Some("environment-disclosure");
    }
    let (print, names) = arguments.split_first()?;
    if print != "-p" {
        return None;
    }
    if names.is_empty() {
        Some("environment-disclosure")
    } else if names.iter().any(|name| is_credential_name(name)) {
        Some("credential-disclosure")
    } else {
        None
    }
}

fn is_credential_name(name: &str) -> bool {
    CREDENTIAL_NAMES.contains(&name)
}

fn discloses_credential_expansion(
    raw: &str,
    local_variables: &[VariableBinding],
    ambient_variables: &[(String, VariableValue)],
) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut quote = None;
    while index < bytes.len() {
        match (quote, bytes[index]) {
            (None, b'\'') => {
                quote = Some(b'\'');
                index += 1;
            }
            (None, b'"') => {
                quote = Some(b'"');
                index += 1;
            }
            (Some(b'\''), b'\'') | (Some(b'"'), b'"') => {
                quote = None;
                index += 1;
            }
            (None, b'\\') => index = (index + 2).min(bytes.len()),
            (Some(b'"'), b'\\')
                if bytes
                    .get(index + 1)
                    .is_some_and(|byte| matches!(byte, b'$' | b'`' | b'"' | b'\\' | b'\n')) =>
            {
                index += 2;
            }
            (None | Some(b'"'), b'$') if bytes.get(index + 1) == Some(&b'{') => {
                let mut name_start = index + 2;
                let length = bytes.get(name_start) == Some(&b'#');
                if length {
                    name_start += 1;
                }
                let mut name_end = name_start;
                while bytes
                    .get(name_end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    name_end += 1;
                }
                let valid_name = name_end > name_start
                    && (bytes[name_start].is_ascii_alphabetic() || bytes[name_start] == b'_');
                if !valid_name {
                    index += 1;
                    continue;
                }
                if length {
                    index = if bytes.get(name_end) == Some(&b'}') {
                        name_end + 1
                    } else {
                        name_end
                    };
                    continue;
                }
                let name = &raw[name_start..name_end];
                let non_value_check = bytes.get(name_end) == Some(&b'+')
                    || bytes.get(name_end) == Some(&b':') && bytes.get(name_end + 1) == Some(&b'+');
                if is_credential_name(name)
                    && credential_value_may_be_emitted(name, local_variables, ambient_variables)
                    && !non_value_check
                {
                    return true;
                }
                index = name_end + if non_value_check { 1 } else { 0 };
            }
            (None | Some(b'"'), b'$') => {
                let name_start = index + 1;
                let mut name_end = name_start;
                while bytes
                    .get(name_end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    name_end += 1;
                }
                if name_end > name_start {
                    let name = &raw[name_start..name_end];
                    if is_credential_name(name)
                        && credential_value_may_be_emitted(name, local_variables, ambient_variables)
                    {
                        return true;
                    }
                }
                index = name_end.max(index + 1);
            }
            _ => index += 1,
        }
    }
    false
}

fn credential_value_may_be_emitted(
    name: &str,
    local_variables: &[VariableBinding],
    ambient_variables: &[(String, VariableValue)],
) -> bool {
    if let Some(binding) = local_variables.iter().find(|binding| binding.name == name) {
        return matches!(binding.value, VariableValue::Unknown);
    }
    ambient_variables
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .is_none_or(|value| {
            matches!(value, VariableValue::Unknown)
                || matches!(value, VariableValue::Static(value) if !value.is_empty())
        })
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
