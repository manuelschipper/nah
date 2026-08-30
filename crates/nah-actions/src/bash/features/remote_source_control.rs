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
    let arguments = if provider == Provider::GitLab {
        let Some((arguments, repo_override)) = gitlab_repo_override(&arguments) else {
            return false;
        };
        if repo_override
            .as_deref()
            .is_some_and(|target| !valid_gitlab_repository(target))
        {
            return false;
        }
        arguments
    } else {
        arguments
    };
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let mut help_requested = None;
    let mut command_index = 0;
    while let Some(value) = arguments
        .get(command_index)
        .and_then(|argument| help_flag(argument, provider))
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

fn gitlab_repo_override(arguments: &[String]) -> Option<(Vec<String>, Option<String>)> {
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut repo_override = None;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "--" {
            after_options = true;
        }
        if !after_options && matches!(argument, "-R" | "--repo") {
            repo_override = Some(arguments.get(index + 1)?.clone());
            index += 2;
            continue;
        }
        if !after_options
            && let Some(value) = argument
                .strip_prefix("--repo=")
                .or_else(|| argument.strip_prefix("-R="))
        {
            if value.is_empty() {
                return None;
            }
            repo_override = Some(value.to_owned());
            index += 1;
            continue;
        }
        if !after_options
            && let Some(value) = argument.strip_prefix("-R")
            && !value.is_empty()
        {
            repo_override = Some(value.to_owned());
            index += 1;
            continue;
        }
        if !after_options
            && let Some(options) = glab_short_options(argument)
            && let Some(('R', attached_value)) = options.value
        {
            let value = attached_value
                .map(str::to_owned)
                .or_else(|| arguments.get(index + 1).cloned())?;
            if value.is_empty() {
                return None;
            }
            repo_override = Some(value);
            if options.include {
                remaining.push("-i".to_owned());
            }
            if let Some(help) = options.help {
                remaining.push(if help { "-h" } else { "-h=false" }.to_owned());
            }
            if options.confirmation {
                remaining.push("-y".to_owned());
            }
            index += 1 + usize::from(attached_value.is_none());
            continue;
        }
        remaining.push(argument.to_owned());
        index += 1;
    }
    Some((remaining, repo_override))
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
    while let Some(value) = rest
        .first()
        .and_then(|argument| help_flag(argument, provider))
    {
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
            if let Some(value) = help_flag(argument, provider) {
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

fn help_flag(argument: &str, provider: Provider) -> Option<bool> {
    boolean_flag(argument, "--help").or_else(|| match provider {
        Provider::GitHub if argument == "-h" || argument.starts_with("-h=") => Some(true),
        Provider::GitHub => None,
        Provider::GitLab => boolean_flag(argument, "-h"),
    })
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
            (valid_host(host) || valid_idn_hostname(host))
                && valid_literal_segment(owner)
                && valid_literal_segment(repository)
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
    let mut api_hostname = None;
    let mut github_template_value = None;
    let mut gitlab_form = false;
    let mut gitlab_form_stdin_count = 0;
    let mut gitlab_input = false;
    let mut gitlab_non_form_body = false;
    let mut gitlab_typed_fields = Vec::new();
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
                if name == 'F' {
                    if !update_gitlab_typed_field(&mut gitlab_typed_fields, value) {
                        return None;
                    }
                } else if name == 'f' && !valid_gitlab_raw_field(value)
                    || name == 'H' && !valid_gitlab_api_header(value)
                {
                    return None;
                }
                if name == 'X' {
                    method = Some(value);
                }
                gitlab_non_form_body |= matches!(name, 'F' | 'f');
                index += usize::from(attached_value.is_none());
            }
            index += 1;
            continue;
        }
        if !after_options
            && provider == Provider::GitHub
            && let Some(options) = github_short_options(argument)
        {
            if let Some((name, attached_value)) = options.value {
                let value = attached_value.or_else(|| arguments.get(index + 1).copied())?;
                let option = match name {
                    'F' => Some("--field"),
                    'H' => Some("--header"),
                    'f' => Some("--raw-field"),
                    't' => Some("--template"),
                    _ => None,
                };
                if option.is_some_and(|name| !valid_api_option_value(name, value, Provider::GitHub))
                {
                    return None;
                }
                if name == 't' {
                    github_template_value = Some(value);
                }
                if name == 'X' {
                    method = Some(value);
                }
                if name == 'q' {
                    github_jq = !value.is_empty();
                }
                if name == 't' {
                    github_template = !value.is_empty();
                }
                index += usize::from(attached_value.is_none());
            }
            index += 1;
            continue;
        }
        if !after_options && let Some(value) = help_flag(argument, provider) {
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
            if !valid_api_option_value(name, value, provider) {
                return None;
            }
            if provider == Provider::GitLab && name == "--field" {
                if !update_gitlab_typed_field(&mut gitlab_typed_fields, value) {
                    return None;
                }
            } else if provider == Provider::GitLab
                && name == "--raw-field"
                && !valid_gitlab_raw_field(value)
            {
                return None;
            }
            if provider == Provider::GitLab
                && name == "--output"
                && !matches!(value, "json" | "ndjson")
            {
                return None;
            }
            if name == "--method" {
                method = Some(value);
            }
            if name == "--hostname" {
                api_hostname = Some(value);
            }
            if provider == Provider::GitLab {
                gitlab_form |= name == "--form";
                gitlab_form_stdin_count += usize::from(name == "--form" && value.ends_with("=@-"));
                gitlab_input |= name == "--input";
                gitlab_non_form_body |= matches!(name, "--field" | "--raw-field" | "--input");
            }
            if provider == Provider::GitHub {
                if name == "--jq" {
                    github_jq = !value.is_empty();
                }
                if name == "--template" {
                    github_template = !value.is_empty();
                    github_template_value = Some(value);
                }
            }
            index += 1;
            continue;
        }
        if !after_options && api_value_option(argument, provider) {
            let value = *arguments.get(index + 1)?;
            if !valid_api_option_value(argument, value, provider) {
                return None;
            }
            if provider == Provider::GitLab && argument == "--field" {
                if !update_gitlab_typed_field(&mut gitlab_typed_fields, value) {
                    return None;
                }
            } else if provider == Provider::GitLab
                && argument == "--raw-field"
                && !valid_gitlab_raw_field(value)
            {
                return None;
            }
            if provider == Provider::GitLab
                && argument == "--output"
                && !matches!(value, "json" | "ndjson")
            {
                return None;
            }
            if argument == "--method" {
                method = Some(value);
            }
            if argument == "--hostname" {
                api_hostname = Some(value);
            }
            if provider == Provider::GitLab {
                gitlab_form |= argument == "--form";
                gitlab_form_stdin_count +=
                    usize::from(argument == "--form" && value.ends_with("=@-"));
                gitlab_input |= argument == "--input";
                gitlab_non_form_body |= matches!(argument, "--field" | "--raw-field" | "--input");
            }
            if provider == Provider::GitHub {
                if argument == "--jq" {
                    github_jq = !value.is_empty();
                }
                if argument == "--template" {
                    github_template = !value.is_empty();
                    github_template_value = Some(value);
                }
            }
            index += 2;
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
        || api_hostname.is_some_and(|hostname| !valid_api_hostname(hostname, provider))
        || github_template_value.is_some_and(|template| !valid_github_template(template))
        || provider == Provider::GitLab && paginate_requested.is_some() && gitlab_input
        || gitlab_form && gitlab_non_form_body
        || gitlab_form_stdin_count > 1
        || gitlab_typed_fields
            .iter()
            .any(|(_, query_compatible)| !query_compatible)
    {
        return None;
    }
    Some(ApiRequest {
        endpoint: endpoint?,
        method: method?,
    })
}

fn valid_api_option_value(name: &str, value: &str, provider: Provider) -> bool {
    match (provider, name) {
        (Provider::GitHub, "--field" | "--raw-field") => valid_github_api_field(value),
        (Provider::GitHub, "--header") => valid_github_api_header(value),
        (Provider::GitHub, "--cache") => valid_go_duration(value),
        (Provider::GitLab, "--header") => valid_gitlab_api_header(value),
        _ => true,
    }
}

fn valid_api_hostname(hostname: &str, provider: Provider) -> bool {
    !hostname.contains(':')
        && (valid_host(hostname) || provider == Provider::GitHub && valid_idn_hostname(hostname))
}

fn valid_idn_hostname(hostname: &str) -> bool {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    !hostname.is_ascii()
        && hostname.split('.').all(|label| {
            label.chars().next().is_some_and(char::is_alphanumeric)
                && label.chars().last().is_some_and(|character| {
                    character.is_alphanumeric() || is_combining_diacritical_mark(character)
                })
                && label.chars().all(|character| {
                    character.is_alphanumeric()
                        || character == '-'
                        || is_combining_diacritical_mark(character)
                })
        })
}

fn is_combining_diacritical_mark(character: char) -> bool {
    matches!(character, '\u{300}'..='\u{36f}')
}

fn valid_github_api_field(field: &str) -> bool {
    let mut key_start = 0;
    let mut has_key = false;
    let mut last_key_empty = false;
    for (index, character) in field.char_indices() {
        match character {
            '[' => {
                if key_start == 0 {
                    has_key = true;
                    last_key_empty = index == 0;
                }
                key_start = index + 1;
            }
            ']' => {
                has_key = true;
                last_key_empty = key_start == index;
            }
            '=' => return true,
            _ => {}
        }
    }
    has_key && last_key_empty
}

fn valid_github_api_header(header: &str) -> bool {
    let Some((name, value)) = header.split_once(':') else {
        return false;
    };
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
        && (!name.eq_ignore_ascii_case("Content-Length") || value.trim().parse::<i64>().is_ok())
}

fn valid_gitlab_api_header(header: &str) -> bool {
    header
        .split_once(':')
        .is_some_and(|(name, _)| !name.is_empty())
}

fn valid_go_duration(value: &str) -> bool {
    let (negative, mut value) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if value == "0" {
        return true;
    }
    if value.is_empty() {
        return false;
    }

    let mut duration = 0_u128;
    while !value.is_empty() {
        let integer_len = value.bytes().take_while(u8::is_ascii_digit).count();
        let integer = value[..integer_len]
            .bytes()
            .try_fold(0_u128, |value, digit| {
                value.checked_mul(10)?.checked_add(u128::from(digit - b'0'))
            });
        let Some(integer) = integer.filter(|value| *value <= 1_u128 << 63) else {
            return false;
        };
        value = &value[integer_len..];

        let mut fraction = 0_u128;
        let mut scale = 1_f64;
        let mut fraction_digits = 0;
        let mut fraction_overflow = false;
        if let Some(rest) = value.strip_prefix('.') {
            fraction_digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            for digit in rest.bytes().take(fraction_digits) {
                if fraction_overflow {
                    continue;
                }
                let Some(next) = fraction
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u128::from(digit - b'0')))
                    .filter(|value| *value <= 1_u128 << 63)
                else {
                    fraction_overflow = true;
                    continue;
                };
                fraction = next;
                scale *= 10.0;
            }
            value = &rest[fraction_digits..];
        }
        if integer_len == 0 && fraction_digits == 0 {
            return false;
        }

        let unit_len = value
            .bytes()
            .take_while(|byte| *byte != b'.' && !byte.is_ascii_digit())
            .count();
        let unit = match &value[..unit_len] {
            "ns" => 1_u128,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 60 * 60 * 1_000_000_000,
            _ => return false,
        };
        let Some(component) = integer.checked_mul(unit) else {
            return false;
        };
        let component = component + (fraction as f64 * (unit as f64 / scale)) as u128;
        let Some(total) = duration.checked_add(component) else {
            return false;
        };
        if total > 1_u128 << 63 {
            return false;
        }
        duration = total;
        value = &value[unit_len..];
    }
    negative || duration < 1_u128 << 63
}

fn valid_github_template(mut template: &str) -> bool {
    let mut blocks = Vec::new();
    let mut variables = vec!["$".to_owned()];
    loop {
        let Some(open) = template.find("{{") else {
            return blocks.is_empty();
        };
        let action_source = &template[open + 2..];
        let Some(close) = github_template_action_end(action_source) else {
            return false;
        };
        let mut action = action_source[..close].trim();
        if let Some(trimmed) = action.strip_prefix('-') {
            action = trimmed.trim_start();
        }
        if let Some(trimmed) = action.strip_suffix('-') {
            action = trimmed.trim_end();
        }
        if action.is_empty() {
            return false;
        }
        let variable_count = variables.len();
        if !valid_github_template_action(action, &mut variables) {
            return false;
        }
        let mut words = action.split_whitespace();
        match words.next() {
            Some(keyword @ ("if" | "with")) => {
                let pipeline = action
                    .strip_prefix(keyword)
                    .expect("matched template keyword")
                    .trim_start();
                if pipeline.is_empty() || pipeline.starts_with('|') {
                    return false;
                }
                blocks.push(GithubTemplateBlock {
                    kind: GithubTemplateBlockKind::Other,
                    variable_count,
                });
            }
            Some("define") => {
                let Some(remaining) = github_template_name_remainder(
                    action
                        .strip_prefix("define")
                        .expect("matched template keyword"),
                ) else {
                    return false;
                };
                if !remaining.trim().is_empty() {
                    return false;
                }
                blocks.push(GithubTemplateBlock {
                    kind: GithubTemplateBlockKind::Other,
                    variable_count,
                });
            }
            Some("block") => {
                let Some(remaining) = github_template_name_remainder(
                    action
                        .strip_prefix("block")
                        .expect("matched template keyword"),
                ) else {
                    return false;
                };
                let pipeline = remaining.trim_start();
                if pipeline.is_empty() || pipeline.starts_with('|') {
                    return false;
                }
                blocks.push(GithubTemplateBlock {
                    kind: GithubTemplateBlockKind::Other,
                    variable_count,
                });
            }
            Some("template") => {
                let Some(remaining) = github_template_name_remainder(
                    action
                        .strip_prefix("template")
                        .expect("matched template keyword"),
                ) else {
                    return false;
                };
                if remaining.trim_start().starts_with('|') {
                    return false;
                }
            }
            Some("range") => {
                let pipeline = action
                    .strip_prefix("range")
                    .expect("matched template keyword")
                    .trim_start();
                if pipeline.is_empty() || pipeline.starts_with('|') {
                    return false;
                }
                blocks.push(GithubTemplateBlock {
                    kind: GithubTemplateBlockKind::Range,
                    variable_count,
                });
            }
            Some("else") => {
                if blocks.is_empty() {
                    return false;
                }
                match words.next() {
                    None => {}
                    Some(keyword @ ("if" | "with")) => {
                        let pipeline = action
                            .strip_prefix("else")
                            .expect("matched template keyword")
                            .trim_start()
                            .strip_prefix(keyword)
                            .expect("matched template keyword")
                            .trim_start();
                        if pipeline.is_empty() || pipeline.starts_with('|') {
                            return false;
                        }
                    }
                    Some(_) => return false,
                }
            }
            Some("end") => {
                let Some(block) = blocks.pop() else {
                    return false;
                };
                if words.next().is_some() {
                    return false;
                }
                variables.truncate(block.variable_count);
            }
            Some("break" | "continue") => {
                if words.next().is_some()
                    || !blocks
                        .iter()
                        .any(|block| block.kind == GithubTemplateBlockKind::Range)
                {
                    return false;
                }
            }
            _ => {}
        }
        template = &action_source[close + 2..];
    }
}

struct GithubTemplateBlock {
    kind: GithubTemplateBlockKind,
    variable_count: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GithubTemplateBlockKind {
    Other,
    Range,
}

struct GithubTemplatePipeline {
    after_pipe: bool,
    command_empty: bool,
    declaration_pending: bool,
    has_term: bool,
}

fn valid_github_template_action(action: &str, variables: &mut Vec<String>) -> bool {
    if action.starts_with("/*") {
        return action.ends_with("*/");
    }
    let bytes = action.as_bytes();
    let mut pipelines = vec![GithubTemplatePipeline {
        after_pipe: false,
        command_empty: true,
        declaration_pending: false,
        has_term: false,
    }];
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'|' => {
                let pipeline = pipelines.last_mut().expect("template pipeline");
                if pipeline.command_empty || pipeline.declaration_pending {
                    return false;
                }
                pipeline.after_pipe = true;
                pipeline.command_empty = true;
                index += 1;
            }
            b'(' => {
                let pipeline = pipelines.last_mut().expect("template pipeline");
                pipeline.after_pipe = false;
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
                pipelines.push(GithubTemplatePipeline {
                    after_pipe: false,
                    command_empty: true,
                    declaration_pending: false,
                    has_term: false,
                });
                index += 1;
            }
            b')' => {
                if pipelines.len() == 1
                    || !pipelines.last().expect("template pipeline").has_term
                    || pipelines
                        .last()
                        .expect("template pipeline")
                        .declaration_pending
                {
                    return false;
                }
                pipelines.pop();
                index += 1;
            }
            b'\'' => {
                let pipeline = pipelines.last_mut().expect("template pipeline");
                if pipeline.after_pipe {
                    return false;
                }
                let Some(length) = github_template_rune_len(&action[index..]) else {
                    return false;
                };
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
                index += length;
            }
            delimiter @ (b'"' | b'`') => {
                let pipeline = pipelines.last_mut().expect("template pipeline");
                if pipeline.after_pipe {
                    return false;
                }
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
                index += 1;
                loop {
                    let Some(byte) = bytes.get(index).copied() else {
                        return false;
                    };
                    index += 1;
                    if delimiter != b'`' && byte == b'\\' {
                        let Some(length) = github_template_escape_len(&bytes[index..]) else {
                            return false;
                        };
                        index += length;
                    } else if byte == delimiter {
                        break;
                    }
                }
            }
            b'.' => {
                let start = index;
                index += 1;
                while bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
                {
                    index += 1;
                }
                let path = &action[start..index];
                if path != "." && path.ends_with('.') || path.contains("..") {
                    return false;
                }
                let pipeline = pipelines.last_mut().expect("template pipeline");
                if pipeline.after_pipe && path == "." {
                    return false;
                }
                pipeline.after_pipe = false;
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
            }
            b'$' => {
                let start = index;
                index += 1;
                while bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
                {
                    index += 1;
                }
                let variable = &action[start..index];
                let base = variable.split_once('.').map_or(variable, |(base, _)| base);
                if base == "$" && variable != "$" && !variable.starts_with("$.")
                    || variable.ends_with('.')
                    || variable.contains("..")
                {
                    return false;
                }
                let mut next = index;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b',') {
                    if pipelines.len() != 1 || action[..start].trim() != "range" {
                        return false;
                    }
                    next += 1;
                    while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                        next += 1;
                    }
                    let second_start = next;
                    if bytes.get(next) != Some(&b'$') {
                        return false;
                    }
                    next += 1;
                    while bytes
                        .get(next)
                        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    {
                        next += 1;
                    }
                    let second = &action[second_start..next];
                    while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                        next += 1;
                    }
                    let declaration = if bytes.get(next..next + 2) == Some(b":=") {
                        true
                    } else if bytes.get(next) == Some(&b'=') {
                        false
                    } else {
                        return false;
                    };
                    if variable == "$"
                        || variable.contains('.')
                        || second == "$"
                        || variable == second
                        || !declaration
                            && (!variables.iter().any(|current| current == variable)
                                || !variables.iter().any(|current| current == second))
                    {
                        return false;
                    }
                    if declaration {
                        for variable in [variable, second] {
                            if !variables.iter().any(|current| current == variable) {
                                variables.push(variable.to_owned());
                            }
                        }
                    }
                    index = next + if declaration { 2 } else { 1 };
                    pipelines
                        .last_mut()
                        .expect("template pipeline")
                        .declaration_pending = true;
                    continue;
                }
                let declaration = if bytes.get(next..next + 2) == Some(b":=") {
                    Some(true)
                } else if bytes.get(next) == Some(&b'=') {
                    Some(false)
                } else {
                    None
                };
                if let Some(is_declaration) = declaration {
                    if variable.contains('.')
                        || !is_declaration && !variables.iter().any(|current| current == base)
                    {
                        return false;
                    }
                    if is_declaration && !variables.iter().any(|current| current == base) {
                        variables.push(base.to_owned());
                    }
                    index = next + if is_declaration { 2 } else { 1 };
                    pipelines
                        .last_mut()
                        .expect("template pipeline")
                        .declaration_pending = true;
                    continue;
                }
                if !variables.iter().any(|current| current == base) {
                    return false;
                }
                let pipeline = pipelines.last_mut().expect("template pipeline");
                pipeline.after_pipe = false;
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
            }
            b'+' | b'-' | b'0'..=b'9' => {
                let pipeline = pipelines.last_mut().expect("template pipeline");
                if pipeline.after_pipe {
                    return false;
                }
                let start = index;
                index += 1;
                while bytes.get(index).is_some_and(|byte| {
                    !byte.is_ascii_whitespace() && !matches!(byte, b'|' | b'(' | b')')
                }) {
                    index += 1;
                }
                if !valid_github_template_number(&action[start..index]) {
                    return false;
                }
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
            }
            b':' | b'=' => return false,
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    index += 1;
                }
                if !valid_github_template_identifier(&action[start..index]) {
                    return false;
                }
                let identifier = &action[start..index];
                let pipeline = pipelines.last_mut().expect("template pipeline");
                if pipeline.after_pipe && matches!(identifier, "false" | "nil" | "true") {
                    return false;
                }
                pipeline.after_pipe = false;
                pipeline.command_empty = false;
                pipeline.declaration_pending = false;
                pipeline.has_term = true;
            }
            _ => return false,
        }
    }
    pipelines.len() == 1
        && !pipelines
            .first()
            .expect("template pipeline")
            .declaration_pending
}

fn github_template_name_remainder(source: &str) -> Option<&str> {
    let source = source.trim_start();
    let delimiter = *source.as_bytes().first()?;
    if !matches!(delimiter, b'"' | b'`') {
        return None;
    }
    let bytes = source.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if delimiter != b'`' && byte == b'\\' {
            index += github_template_escape_len(&bytes[index..])?;
        } else if byte == delimiter {
            return Some(&source[index..]);
        }
    }
    None
}

fn github_template_rune_len(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.first() != Some(&b'\'') {
        return None;
    }
    let mut index = 1;
    if bytes.get(index) == Some(&b'\\') {
        index += 1;
        index += github_template_escape_len(&bytes[index..])?;
    } else {
        let rune = source.get(index..)?.chars().next()?;
        if matches!(rune, '\'' | '\\' | '\n' | '\r') {
            return None;
        }
        index += rune.len_utf8();
    }
    (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
}

fn github_template_escape_len(source: &[u8]) -> Option<usize> {
    match *source.first()? {
        b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' | b'\\' | b'"' | b'\'' => Some(1),
        b'x' => source
            .get(1..3)
            .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))
            .map(|_| 3),
        marker @ (b'u' | b'U') => {
            let digits = if marker == b'u' { 4 } else { 8 };
            let hexadecimal = source
                .get(1..digits + 1)
                .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))?;
            let value = hexadecimal.iter().fold(0_u32, |value, digit| {
                value * 16 + u32::from(hex_value(*digit).expect("checked hexadecimal digit"))
            });
            char::from_u32(value).map(|_| digits + 1)
        }
        b'0'..=b'7' => {
            let octal = source
                .get(..3)
                .filter(|digits| digits.iter().all(|digit| matches!(digit, b'0'..=b'7')))?;
            let value = octal
                .iter()
                .fold(0_u16, |value, digit| value * 8 + u16::from(digit - b'0'));
            (value <= u16::from(u8::MAX)).then_some(3)
        }
        _ => None,
    }
}

fn valid_github_template_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "and"
            | "autocolor"
            | "block"
            | "break"
            | "call"
            | "color"
            | "contains"
            | "continue"
            | "define"
            | "else"
            | "end"
            | "eq"
            | "ge"
            | "gt"
            | "hasPrefix"
            | "hasSuffix"
            | "html"
            | "hyperlink"
            | "if"
            | "index"
            | "join"
            | "js"
            | "le"
            | "len"
            | "lt"
            | "ne"
            | "nil"
            | "not"
            | "or"
            | "pluck"
            | "print"
            | "printf"
            | "println"
            | "range"
            | "regexMatch"
            | "replace"
            | "slice"
            | "tablerender"
            | "tablerow"
            | "template"
            | "timeago"
            | "timefmt"
            | "true"
            | "truncate"
            | "false"
            | "urlquery"
            | "with"
    )
}

fn valid_github_template_number(number: &str) -> bool {
    let unsigned = number.strip_prefix(['+', '-']).unwrap_or(number);
    let unsigned = unsigned.strip_suffix('i').unwrap_or(unsigned);
    let (radix, prefix_len) = if unsigned.starts_with("0x") || unsigned.starts_with("0X") {
        (16, 2)
    } else if unsigned.starts_with("0b") || unsigned.starts_with("0B") {
        (2, 2)
    } else if unsigned.starts_with("0o") || unsigned.starts_with("0O") {
        (8, 2)
    } else {
        (10, 0)
    };
    let bytes = unsigned.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'_' {
            continue;
        }
        let follows_prefix = prefix_len > 0 && index == prefix_len;
        if (!follows_prefix
            && (index == 0 || !valid_github_template_digit(bytes[index - 1], radix)))
            || !bytes
                .get(index + 1)
                .is_some_and(|byte| valid_github_template_digit(*byte, radix))
        {
            return false;
        }
    }
    let normalized = unsigned.replace('_', "");
    let unsigned = normalized.as_str();
    if let Some(hexadecimal) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        return !hexadecimal.is_empty() && hexadecimal.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    if let Some(binary) = unsigned
        .strip_prefix("0b")
        .or_else(|| unsigned.strip_prefix("0B"))
    {
        return !binary.is_empty() && binary.bytes().all(|byte| matches!(byte, b'0' | b'1'));
    }
    if let Some(octal) = unsigned
        .strip_prefix("0o")
        .or_else(|| unsigned.strip_prefix("0O"))
    {
        return !octal.is_empty() && octal.bytes().all(|byte| matches!(byte, b'0'..=b'7'));
    }
    !unsigned.is_empty() && unsigned.parse::<f64>().is_ok()
}

fn valid_github_template_digit(byte: u8, radix: u8) -> bool {
    match radix {
        2 => matches!(byte, b'0' | b'1'),
        8 => matches!(byte, b'0'..=b'7'),
        10 => byte.is_ascii_digit(),
        16 => byte.is_ascii_hexdigit(),
        _ => false,
    }
}

fn github_template_action_end(action: &str) -> Option<usize> {
    if action.trim_start().starts_with("/*") {
        return action.find("*/}}").map(|index| index + 2);
    }
    let bytes = action.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index + 1 < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if delimiter != b'`' && byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        } else if byte == b'}' && bytes[index + 1] == b'}' {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn valid_gitlab_raw_field(field: &str) -> bool {
    field.contains('=')
}

fn update_gitlab_typed_field<'a>(fields: &mut Vec<(&'a str, bool)>, field: &'a str) -> bool {
    let Some((name, value)) = field.split_once('=') else {
        return false;
    };
    let query_compatible = if value.starts_with(['[', '{']) {
        let mut parser = JsonParser {
            remaining: value.as_bytes(),
        };
        let Some(value) = parser.parse_value(0) else {
            return false;
        };
        parser.skip_whitespace();
        if !parser.remaining.is_empty() {
            return false;
        }
        value.query_compatible()
    } else {
        true
    };
    if let Some((_, current)) = fields.iter_mut().find(|(current, _)| *current == name) {
        *current = query_compatible;
    } else {
        fields.push((name, query_compatible));
    }
    true
}

enum JsonValue {
    Scalar,
    Null,
    Array(bool),
    Object,
}

impl JsonValue {
    fn query_compatible(&self) -> bool {
        matches!(self, Self::Scalar | Self::Null | Self::Array(true))
    }

    fn array_element_compatible(&self) -> bool {
        matches!(self, Self::Scalar)
    }
}

struct JsonParser<'a> {
    remaining: &'a [u8],
}

impl JsonParser<'_> {
    fn parse_value(&mut self, depth: usize) -> Option<JsonValue> {
        if depth == 128 {
            return None;
        }
        self.skip_whitespace();
        match self.remaining.first() {
            Some(b'"') => self.parse_string().then_some(JsonValue::Scalar),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b't') => self.take(b"true").then_some(JsonValue::Scalar),
            Some(b'f') => self.take(b"false").then_some(JsonValue::Scalar),
            Some(b'n') => self.take(b"null").then_some(JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number().then_some(JsonValue::Scalar),
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: usize) -> Option<JsonValue> {
        self.take(b"{");
        self.skip_whitespace();
        if self.take(b"}") {
            return Some(JsonValue::Object);
        }
        loop {
            if !self.parse_string() {
                return None;
            }
            self.skip_whitespace();
            if !self.take(b":") {
                return None;
            }
            self.parse_value(depth)?;
            self.skip_whitespace();
            if self.take(b"}") {
                return Some(JsonValue::Object);
            }
            if !self.take(b",") {
                return None;
            }
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> Option<JsonValue> {
        self.take(b"[");
        self.skip_whitespace();
        if self.take(b"]") {
            return Some(JsonValue::Array(true));
        }
        let mut query_compatible = true;
        loop {
            query_compatible &= self.parse_value(depth)?.array_element_compatible();
            self.skip_whitespace();
            if self.take(b"]") {
                return Some(JsonValue::Array(query_compatible));
            }
            if !self.take(b",") {
                return None;
            }
        }
    }

    fn parse_string(&mut self) -> bool {
        if !self.take(b"\"") {
            return false;
        }
        while let Some((byte, rest)) = self.remaining.split_first() {
            self.remaining = rest;
            match byte {
                b'"' => return true,
                b'\\' => {
                    let Some((escaped, rest)) = self.remaining.split_first() else {
                        return false;
                    };
                    self.remaining = rest;
                    if *escaped == b'u' {
                        if self.remaining.len() < 4
                            || !self.remaining[..4].iter().all(u8::is_ascii_hexdigit)
                        {
                            return false;
                        }
                        self.remaining = &self.remaining[4..];
                    } else if !matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        return false;
                    }
                }
                0..=0x1f => return false,
                _ => {}
            }
        }
        false
    }

    fn parse_number(&mut self) -> bool {
        if self.remaining.first() == Some(&b'-') {
            self.remaining = &self.remaining[1..];
        }
        match self.remaining.first() {
            Some(b'0') => self.remaining = &self.remaining[1..],
            Some(b'1'..=b'9') => {
                self.take_digits();
            }
            _ => return false,
        }
        if self.remaining.first() == Some(&b'.') {
            self.remaining = &self.remaining[1..];
            if !self.take_digits() {
                return false;
            }
        }
        if matches!(self.remaining.first(), Some(b'e' | b'E')) {
            self.remaining = &self.remaining[1..];
            if matches!(self.remaining.first(), Some(b'+' | b'-')) {
                self.remaining = &self.remaining[1..];
            }
            if !self.take_digits() {
                return false;
            }
        }
        true
    }

    fn take_digits(&mut self) -> bool {
        let count = self
            .remaining
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        self.remaining = &self.remaining[count..];
        count > 0
    }

    fn skip_whitespace(&mut self) {
        let count = self
            .remaining
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .count();
        self.remaining = &self.remaining[count..];
    }

    fn take(&mut self, expected: &[u8]) -> bool {
        let Some(remaining) = self.remaining.strip_prefix(expected) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

fn api_boolean_option(argument: &str, provider: Provider) -> bool {
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
        ]
        .as_slice(),
    };
    options.contains(&argument)
}

struct GithubShortOptions<'a> {
    value: Option<(char, Option<&'a str>)>,
}

fn github_short_options(argument: &str) -> Option<GithubShortOptions<'_>> {
    let flags = argument.strip_prefix('-')?;
    if flags.is_empty() || flags.starts_with('-') {
        return None;
    }
    let mut options = GithubShortOptions { value: None };
    let mut indices = flags.char_indices().peekable();
    while let Some((_, flag)) = indices.next() {
        let value = indices.peek().map_or("", |(index, _)| &flags[*index..]);
        match flag {
            'i' => {
                if let Some(value) = value.strip_prefix('=') {
                    parse_boolean_value(value)?;
                    return Some(options);
                }
            }
            'F' | 'H' | 'q' | 'X' | 'p' | 'f' | 't' => {
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
            'F' | 'H' | 'R' | 'X' | 'f' => {
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
    if let Some(bracketed) = host.strip_prefix('[') {
        let Some((address, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        return valid_ipv6_address(address)
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port));
    }
    let (hostname, port) = host
        .split_once(':')
        .map_or((host, None), |(hostname, port)| (hostname, Some(port)));
    if port.is_some_and(|port| !valid_port(port)) {
        return false;
    }
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
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

fn valid_ipv6_address(address: &str) -> bool {
    if let Some((left, right)) = address.split_once("::") {
        if right.contains("::") {
            return false;
        }
        return ipv6_hextet_count(left)
            .zip(ipv6_hextet_count(right))
            .is_some_and(|(left, right)| left + right < 8);
    }
    ipv6_hextet_count(address) == Some(8)
}

fn ipv6_hextet_count(address: &str) -> Option<usize> {
    if address.is_empty() {
        return Some(0);
    }
    if address.contains('.') {
        let (prefix, address) = address.rsplit_once(':').unwrap_or(("", address));
        let octets = address.split('.').collect::<Vec<_>>();
        if prefix.contains('.')
            || octets.len() != 4
            || !octets.into_iter().all(|octet| {
                !octet.is_empty()
                    && (octet == "0" || !octet.starts_with('0'))
                    && octet.bytes().all(|byte| byte.is_ascii_digit())
                    && octet.parse::<u8>().is_ok()
            })
        {
            return None;
        }
        return ipv6_hextet_count(prefix).map(|count| count + 2);
    }
    address.split(':').try_fold(0, |count, hextet| {
        (!hextet.is_empty()
            && hextet.len() <= 4
            && hextet.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(count + 1)
    })
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Provider {
    GitHub,
    GitLab,
}
