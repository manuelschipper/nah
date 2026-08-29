//! Recognizes exact whole-repository deletion through reviewed GitHub and GitLab CLI syntax.

use nah_parse::Word;

use crate::shell_word::static_word;

pub(crate) fn deletes_repository(program: &str, arguments: &[Word]) -> bool {
    let provider = match program {
        "gh" => Provider::GitHub,
        "glab" => Provider::GitLab,
        _ => return false,
    };
    let arguments = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>();
    let Some(arguments) = arguments else {
        return false;
    };
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    match provider {
        Provider::GitHub => github_repo_delete(&arguments) || github_api_delete(&arguments),
        Provider::GitLab => gitlab_repo_delete(&arguments) || gitlab_api_delete(&arguments),
    }
}

fn github_repo_delete(arguments: &[&str]) -> bool {
    let Some(rest) = arguments.strip_prefix(&["repo", "delete"]) else {
        return false;
    };
    repo_delete_target(rest, Provider::GitHub)
        .is_some_and(|target| target.is_none_or(valid_github_repository))
}

fn gitlab_repo_delete(arguments: &[&str]) -> bool {
    let Some(rest) = arguments
        .strip_prefix(&["repo", "delete"])
        .or_else(|| arguments.strip_prefix(&["project", "delete"]))
    else {
        return false;
    };
    repo_delete_target(rest, Provider::GitLab)
        .is_some_and(|target| target.is_none_or(valid_gitlab_repository))
}

fn repo_delete_target<'a>(arguments: &'a [&str], provider: Provider) -> Option<Option<&'a str>> {
    let mut target = None;
    let mut after_options = false;
    for argument in arguments {
        if !after_options && *argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options {
            match help_flag(argument) {
                Some(true) => return None,
                Some(false) => continue,
                None => {}
            }
            if confirmation_flag(argument, provider) {
                continue;
            }
            if argument.starts_with('-') {
                return None;
            }
        }
        if target.replace(*argument).is_some() {
            return None;
        }
    }
    Some(target)
}

fn confirmation_flag(argument: &str, provider: Provider) -> bool {
    let long = match provider {
        Provider::GitHub => ["--yes", "--confirm"].as_slice(),
        Provider::GitLab => ["--yes"].as_slice(),
    };
    long.iter()
        .any(|flag| boolean_flag(argument, flag).is_some())
        || provider == Provider::GitLab && boolean_flag(argument, "-y").is_some()
}

fn help_flag(argument: &str) -> Option<bool> {
    boolean_flag(argument, "--help").or_else(|| boolean_flag(argument, "-h"))
}

fn boolean_flag(argument: &str, flag: &str) -> Option<bool> {
    if argument == flag {
        return Some(true);
    }
    let value = argument.strip_prefix(flag)?.strip_prefix('=')?;
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn valid_github_repository(target: &str) -> bool {
    let segments = target.split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        [repository] => valid_literal_segment(repository),
        [owner, repository] => valid_literal_segment(owner) && valid_literal_segment(repository),
        [host, owner, repository] => {
            valid_host(host) && valid_literal_segment(owner) && valid_literal_segment(repository)
        }
        _ => false,
    }
}

fn valid_gitlab_repository(target: &str) -> bool {
    let segments = target.split('/').collect::<Vec<_>>();
    !segments.is_empty() && segments.into_iter().all(valid_literal_segment)
}

fn github_api_delete(arguments: &[&str]) -> bool {
    let Some(arguments) = arguments.strip_prefix(&["api"]) else {
        return false;
    };
    api_request(arguments, Provider::GitHub).is_some_and(|request| {
        request.method.eq_ignore_ascii_case("DELETE") && github_delete_endpoint(request.endpoint)
    })
}

fn gitlab_api_delete(arguments: &[&str]) -> bool {
    let Some(arguments) = arguments.strip_prefix(&["api"]) else {
        return false;
    };
    api_request(arguments, Provider::GitLab).is_some_and(|request| {
        request.method.eq_ignore_ascii_case("DELETE") && gitlab_delete_endpoint(request.endpoint)
    })
}

struct ApiRequest<'a> {
    endpoint: &'a str,
    method: &'a str,
}

fn api_request<'a>(arguments: &'a [&str], provider: Provider) -> Option<ApiRequest<'a>> {
    let mut endpoint = None;
    let mut method = None;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if !after_options && argument == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if !after_options && let Some(help_requested) = help_flag(argument) {
            if help_requested {
                return None;
            }
            index += 1;
            continue;
        }
        if !after_options && api_boolean_option(argument, provider) {
            index += 1;
            continue;
        }
        if !after_options
            && argument.starts_with("--")
            && let Some((name, value)) = argument.split_once('=')
        {
            if !api_value_option(name, provider) {
                return None;
            }
            if name == "--method" {
                method = Some(value);
            }
            index += 1;
            continue;
        }
        if !after_options && api_value_option(argument, provider) {
            let value = *arguments.get(index + 1)?;
            if matches!(argument, "-X" | "--method") {
                method = Some(value);
            }
            index += 2;
            continue;
        }
        if !after_options && let Some((name, value)) = short_value_option(argument, provider) {
            if name == "-X" {
                method = Some(value);
            }
            index += 1;
            continue;
        }
        if !after_options && argument.starts_with('-') {
            return None;
        }
        if endpoint.replace(argument).is_some() {
            return None;
        }
        index += 1;
    }
    Some(ApiRequest {
        endpoint: endpoint?,
        method: method?,
    })
}

fn api_boolean_option(argument: &str, provider: Provider) -> bool {
    if argument == "-i" {
        return true;
    }
    let options = match provider {
        Provider::GitHub => [
            "--include",
            "--paginate",
            "--silent",
            "--slurp",
            "--verbose",
        ]
        .as_slice(),
        Provider::GitLab => ["--include", "--paginate", "--silent"].as_slice(),
    };
    options
        .iter()
        .any(|option| boolean_flag(argument, option).is_some())
}

fn api_value_option(argument: &str, provider: Provider) -> bool {
    let options = match provider {
        Provider::GitHub => [
            "--cache",
            "--field",
            "--header",
            "--hostname",
            "--input",
            "--jq",
            "--method",
            "--preview",
            "--raw-field",
            "--template",
            "-F",
            "-H",
            "-q",
            "-X",
            "-p",
            "-f",
            "-t",
        ]
        .as_slice(),
        Provider::GitLab => [
            "--field",
            "--form",
            "--header",
            "--hostname",
            "--input",
            "--method",
            "--output",
            "--raw-field",
            "-F",
            "-H",
            "-X",
            "-f",
        ]
        .as_slice(),
    };
    options.contains(&argument)
}

fn short_value_option(argument: &str, provider: Provider) -> Option<(&str, &str)> {
    let options = match provider {
        Provider::GitHub => ["-F", "-H", "-q", "-X", "-p", "-f", "-t"].as_slice(),
        Provider::GitLab => ["-F", "-H", "-X", "-f"].as_slice(),
    };
    options.iter().find_map(|option| {
        argument
            .strip_prefix(option)
            .filter(|value| !value.is_empty())
            .map(|value| (*option, value.strip_prefix('=').unwrap_or(value)))
    })
}

fn github_delete_endpoint(endpoint: &str) -> bool {
    let path = endpoint
        .split_once(['?', '#'])
        .map_or(endpoint, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);
    let segments = path.split('/').collect::<Vec<_>>();
    matches!(segments.as_slice(), ["repos", owner, repository]
        if valid_github_endpoint_segment(owner, "{owner}")
            && valid_github_endpoint_segment(repository, "{repo}"))
}

fn valid_github_endpoint_segment(segment: &str, placeholder: &str) -> bool {
    segment == placeholder || valid_literal_segment(segment)
}

fn gitlab_delete_endpoint(endpoint: &str) -> bool {
    let path = endpoint.split_once('?').map_or(endpoint, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some(identifier) = path.strip_prefix("projects/") else {
        return false;
    };
    !identifier.contains('/') && valid_gitlab_project_identifier(identifier)
}

fn valid_gitlab_project_identifier(identifier: &str) -> bool {
    if matches!(identifier, ":id" | ":fullpath")
        || !identifier.is_empty() && identifier.bytes().all(|byte| byte.is_ascii_digit())
    {
        return true;
    }
    let components = split_encoded_path(identifier);
    components.len() >= 2
        && components.into_iter().all(|component| {
            matches!(component, ":namespace" | ":repo") || valid_literal_segment(component)
        })
}

fn split_encoded_path(mut value: &str) -> Vec<&str> {
    let mut components = Vec::new();
    loop {
        let separator = value
            .as_bytes()
            .windows(3)
            .position(|window| window.eq_ignore_ascii_case(b"%2f"));
        let Some(separator) = separator else {
            components.push(value);
            return components;
        };
        components.push(&value[..separator]);
        value = &value[separator + 3..];
    }
}

fn valid_literal_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | "..")
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_host(host: &str) -> bool {
    host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Provider {
    GitHub,
    GitLab,
}
