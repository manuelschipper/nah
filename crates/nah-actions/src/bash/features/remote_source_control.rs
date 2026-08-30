//! Recognizes exact whole-repository deletion through reviewed GitHub and GitLab CLI syntax.

use nah_parse::Word;

use crate::shell_word::{has_unmodeled_expansion, static_word};

pub(crate) fn deletes_repository(program: &str, arguments: &[Word]) -> bool {
    let provider = match program {
        "gh" => Provider::GitHub,
        "glab" => Provider::GitLab,
        _ => return false,
    };
    let arguments = arguments
        .iter()
        .map(static_remote_argument)
        .collect::<Option<Vec<_>>>();
    let Some(arguments) = arguments else {
        return false;
    };
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let mut help_requested = None;
    let mut command_index = 0;
    while let Some(value) = arguments
        .get(command_index)
        .and_then(|argument| help_flag(argument))
    {
        help_requested = Some(value);
        command_index += 1;
    }
    let arguments = &arguments[command_index..];
    match provider {
        Provider::GitHub => {
            github_repo_delete(arguments, help_requested)
                || github_api_delete(arguments, help_requested)
        }
        Provider::GitLab => {
            gitlab_repo_delete(arguments, help_requested)
                || gitlab_api_delete(arguments, help_requested)
        }
    }
}

fn static_remote_argument(argument: &Word) -> Option<String> {
    let expansion_check = argument
        .raw()
        .replace("{owner}", "owner")
        .replace("{repo}", "repo")
        .replace("{branch}", "branch");
    if has_unmodeled_expansion(&expansion_check) {
        return None;
    }
    static_word(argument.raw(), argument.substitutions().is_empty())
}

fn github_repo_delete(arguments: &[&str], help_requested: Option<bool>) -> bool {
    let Some((rest, help_requested)) =
        repo_delete_command(arguments, Provider::GitHub, help_requested)
    else {
        return false;
    };
    repo_delete_target(rest, Provider::GitHub, help_requested)
        .is_some_and(|target| target.is_none_or(valid_github_repository))
}

fn gitlab_repo_delete(arguments: &[&str], help_requested: Option<bool>) -> bool {
    let Some((rest, help_requested)) =
        repo_delete_command(arguments, Provider::GitLab, help_requested)
    else {
        return false;
    };
    repo_delete_target(rest, Provider::GitLab, help_requested)
        .is_some_and(|target| target.is_none_or(valid_gitlab_repository))
}

fn repo_delete_command<'a>(
    arguments: &'a [&str],
    provider: Provider,
    mut help_requested: Option<bool>,
) -> Option<(&'a [&'a str], Option<bool>)> {
    let (parent, mut rest) = arguments.split_first()?;
    if !matches!(
        (provider, *parent),
        (Provider::GitHub, "repo") | (Provider::GitLab, "repo" | "project")
    ) {
        return None;
    }
    while let Some(value) = rest.first().and_then(|argument| help_flag(argument)) {
        help_requested = Some(value);
        rest = &rest[1..];
    }
    Some((rest.strip_prefix(&["delete"])?, help_requested))
}

fn repo_delete_target<'a>(
    arguments: &'a [&str],
    provider: Provider,
    mut help_requested: Option<bool>,
) -> Option<Option<&'a str>> {
    let mut target = None;
    let mut after_options = false;
    for argument in arguments {
        if !after_options && *argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options {
            if let Some(value) = help_flag(argument) {
                help_requested = Some(value);
                continue;
            }
            if provider == Provider::GitLab
                && let Some(options) = glab_short_options(argument)
            {
                if options.include || options.value.is_some() || !options.confirmation {
                    return None;
                }
                if let Some(value) = options.help {
                    help_requested = Some(value);
                }
                continue;
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
    if help_requested == Some(true) {
        None
    } else {
        Some(target)
    }
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
    parse_boolean_value(value)
}

fn parse_boolean_value(value: &str) -> Option<bool> {
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

fn github_api_delete(arguments: &[&str], help_requested: Option<bool>) -> bool {
    let Some(arguments) = arguments.strip_prefix(&["api"]) else {
        return false;
    };
    api_request(arguments, Provider::GitHub, help_requested).is_some_and(|request| {
        request.method.eq_ignore_ascii_case("DELETE") && github_delete_endpoint(request.endpoint)
    })
}

fn gitlab_api_delete(arguments: &[&str], help_requested: Option<bool>) -> bool {
    let Some(arguments) = arguments.strip_prefix(&["api"]) else {
        return false;
    };
    api_request(arguments, Provider::GitLab, help_requested).is_some_and(|request| {
        request.method.eq_ignore_ascii_case("DELETE") && gitlab_delete_endpoint(request.endpoint)
    })
}

struct ApiRequest<'a> {
    endpoint: &'a str,
    method: &'a str,
}

fn api_request<'a>(
    arguments: &'a [&str],
    provider: Provider,
    mut help_requested: Option<bool>,
) -> Option<ApiRequest<'a>> {
    let mut endpoint = None;
    let mut method = None;
    let mut paginate_requested = None;
    let mut github_slurp_requested = None;
    let mut github_jq = false;
    let mut github_silent = false;
    let mut github_template = false;
    let mut github_verbose = false;
    let mut gitlab_form = false;
    let mut gitlab_non_form_body = false;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if !after_options && argument == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if !after_options
            && provider == Provider::GitLab
            && let Some(options) = glab_short_options(argument)
        {
            if options.confirmation {
                return None;
            }
            if let Some(value) = options.help {
                help_requested = Some(value);
            }
            if let Some((name, attached_value)) = options.value {
                let value = attached_value.or_else(|| arguments.get(index + 1).copied())?;
                if name == 'X' {
                    method = Some(value);
                }
                gitlab_non_form_body |= matches!(name, 'F' | 'f');
                index += usize::from(attached_value.is_none());
            }
            index += 1;
            continue;
        }
        if !after_options && let Some(value) = help_flag(argument) {
            help_requested = Some(value);
            index += 1;
            continue;
        }
        if !after_options && let Some(paginate) = boolean_flag(argument, "--paginate") {
            paginate_requested = Some(paginate);
            index += 1;
            continue;
        }
        if !after_options
            && provider == Provider::GitHub
            && let Some(slurp) = boolean_flag(argument, "--slurp")
        {
            github_slurp_requested = Some(slurp);
            index += 1;
            continue;
        }
        if !after_options && api_boolean_option(argument, provider) {
            if provider == Provider::GitHub {
                if let Some(value) = boolean_flag(argument, "--silent") {
                    github_silent = value;
                }
                if let Some(value) = boolean_flag(argument, "--verbose") {
                    github_verbose = value;
                }
            }
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
            if provider == Provider::GitLab {
                gitlab_form |= name == "--form";
                gitlab_non_form_body |= matches!(name, "--field" | "--raw-field" | "--input");
            }
            if provider == Provider::GitHub {
                github_jq |= name == "--jq";
                github_template |= name == "--template";
            }
            index += 1;
            continue;
        }
        if !after_options && api_value_option(argument, provider) {
            let value = *arguments.get(index + 1)?;
            if matches!(argument, "-X" | "--method") {
                method = Some(value);
            }
            if provider == Provider::GitLab {
                gitlab_form |= argument == "--form";
                gitlab_non_form_body |= matches!(
                    argument,
                    "--field" | "--raw-field" | "--input" | "-F" | "-f"
                );
            }
            if provider == Provider::GitHub {
                github_jq |= matches!(argument, "-q" | "--jq");
                github_template |= matches!(argument, "-t" | "--template");
            }
            index += 2;
            continue;
        }
        if !after_options
            && provider == Provider::GitHub
            && github_separated_method_option(argument)
        {
            method = Some(*arguments.get(index + 1)?);
            index += 2;
            continue;
        }
        if !after_options
            && provider == Provider::GitHub
            && let Some((name, value)) = github_short_value_option(argument)
        {
            if name == 'X' {
                method = Some(value);
            }
            github_jq |= name == 'q';
            github_template |= name == 't';
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
    let github_output_options = [github_jq, github_silent, github_template, github_verbose]
        .into_iter()
        .filter(|selected| *selected)
        .count();
    if help_requested == Some(true)
        || paginate_requested == Some(true)
        || github_slurp_requested == Some(true)
        || github_output_options > 1
        || gitlab_form && gitlab_non_form_body
    {
        return None;
    }
    Some(ApiRequest {
        endpoint: endpoint?,
        method: method?,
    })
}

fn api_boolean_option(argument: &str, provider: Provider) -> bool {
    if boolean_flag(argument, "-i").is_some()
        || provider == Provider::GitHub
            && argument
                .strip_prefix('-')
                .is_some_and(|flags| !flags.is_empty() && flags.bytes().all(|flag| flag == b'i'))
    {
        return true;
    }
    let options = match provider {
        Provider::GitHub => [
            "--allow-escape-sequences",
            "--include",
            "--silent",
            "--verbose",
        ]
        .as_slice(),
        Provider::GitLab => ["--include", "--silent"].as_slice(),
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

fn github_separated_method_option(argument: &str) -> bool {
    argument
        .strip_prefix("-i")
        .and_then(|flags| flags.strip_suffix('X'))
        .is_some_and(|flags| flags.bytes().all(|flag| flag == b'i'))
}

struct GlabShortOptions<'a> {
    confirmation: bool,
    help: Option<bool>,
    include: bool,
    value: Option<(char, Option<&'a str>)>,
}

fn glab_short_options(argument: &str) -> Option<GlabShortOptions<'_>> {
    let flags = argument.strip_prefix('-')?;
    if flags.is_empty() || flags.starts_with('-') {
        return None;
    }
    let mut options = GlabShortOptions {
        confirmation: false,
        help: None,
        include: false,
        value: None,
    };
    let mut indices = flags.char_indices().peekable();
    while let Some((_, flag)) = indices.next() {
        let value = indices.peek().map_or("", |(index, _)| &flags[*index..]);
        match flag {
            'h' | 'i' | 'y' => {
                let parsed = if let Some(value) = value.strip_prefix('=') {
                    parse_boolean_value(value)?
                } else {
                    true
                };
                match flag {
                    'h' => options.help = Some(parsed),
                    'i' => options.include = true,
                    'y' => options.confirmation = true,
                    _ => unreachable!(),
                }
                if value.starts_with('=') {
                    return Some(options);
                }
            }
            'F' | 'H' | 'X' | 'f' => {
                let value = if value.is_empty() {
                    None
                } else {
                    Some(value.strip_prefix('=').unwrap_or(value))
                };
                options.value = Some((flag, value));
                return Some(options);
            }
            _ => return None,
        }
    }
    Some(options)
}

fn github_short_value_option(argument: &str) -> Option<(char, &str)> {
    let options = ['F', 'H', 'q', 'X', 'p', 'f', 't'];
    let options_and_value = argument.strip_prefix('-')?;
    let options_and_value = options_and_value.trim_start_matches('i');
    options.iter().find_map(|option| {
        options_and_value
            .strip_prefix(*option)
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
    let path = endpoint
        .split_once(['?', '#'])
        .map_or(endpoint, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some(identifier) = path.strip_prefix("projects/") else {
        return false;
    };
    if matches!(identifier, ":namespace/:repo" | ":group/:namespace/:repo") {
        return true;
    }
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
            matches!(
                component,
                ":group" | ":namespace" | ":repo" | ":user" | ":username"
            ) || valid_percent_encoded_literal_segment(component)
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

fn valid_percent_encoded_literal_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let mut decoded_len = 0;
    let mut only_dots = true;
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'%' {
            let Some(encoded) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            let (Some(high), Some(low)) = (hex_value(encoded[0]), hex_value(encoded[1])) else {
                return false;
            };
            index += 3;
            high << 4 | low
        } else {
            let byte = bytes[index];
            index += 1;
            byte
        };
        if !valid_literal_byte(byte) {
            return false;
        }
        decoded_len += 1;
        only_dots &= byte == b'.';
    }
    decoded_len > 0 && !(only_dots && decoded_len <= 2)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_literal_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | "..") && segment.bytes().all(valid_literal_byte)
}

fn valid_literal_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn valid_host(host: &str) -> bool {
    let (hostname, port) = host
        .split_once(':')
        .map_or((host, None), |(hostname, port)| (hostname, Some(port)));
    if port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().is_err()
    }) {
        return false;
    }
    hostname.split('.').all(|label| {
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
