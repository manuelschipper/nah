//! Classifies reviewed secret-store deletion commands.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::shell_word::static_word;

pub(crate) struct Classification {
    pub(crate) complete: bool,
    pub(crate) system_state: Option<SemanticCode>,
}

impl Classification {
    const fn deletion() -> Self {
        Self {
            complete: true,
            system_state: Some(SemanticCode::SECRETS_STORE_DELETE),
        }
    }

    const fn control() -> Self {
        Self {
            complete: true,
            system_state: None,
        }
    }

    const fn incomplete() -> Self {
        Self {
            complete: false,
            system_state: None,
        }
    }
}

pub(crate) fn classify(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Word)],
    path_overridden: bool,
    qualified_program: bool,
) -> Option<Classification> {
    if !secret_store_program(program) {
        return None;
    }
    if !qualified_program && (path_overridden || assignments.iter().any(|(name, _)| name == "PATH"))
    {
        return Some(Classification::incomplete());
    }
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    Some(match program {
        "vault" => vault(&arguments),
        "aws" => aws(&arguments),
        "gcloud" => gcloud(&arguments),
        "az" => azure(&arguments),
        "doppler" => doppler(&arguments),
        "infisical" => infisical(&arguments),
        "op" => one_password(&arguments),
        _ => unreachable!("secret-store programs are matched above"),
    })
}

fn secret_store_program(program: &str) -> bool {
    matches!(
        program,
        "vault" | "aws" | "gcloud" | "az" | "doppler" | "infisical" | "op"
    )
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}

fn vault(arguments: &[String]) -> Classification {
    let parsed = match parse_options(
        arguments,
        &[
            "-h",
            "-help",
            "--help",
            "-version",
            "--version",
            "-disable-redirects",
            "-non-interactive",
            "-output-curl-string",
            "-output-policy",
            "-policy-override",
            "-tls-skip-verify",
        ],
        &[
            "-address",
            "-agent-address",
            "-ca-cert",
            "-ca-path",
            "-client-cert",
            "-client-key",
            "-field",
            "-format",
            "-header",
            "-mfa",
            "-mount",
            "-namespace",
            "-ns",
            "-tls-server-name",
            "-versions",
            "-wrap-ttl",
        ],
        &[],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("vault", &parsed),
    };
    if parsed.non_executing() || parsed.flag("-output-curl-string") || parsed.flag("-output-policy")
    {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [kv, delete, path] if kv == "kv" && delete == "delete" && valid_operand(path) => {
            Classification::deletion()
        }
        [kv, destroy, path]
            if kv == "kv"
                && destroy == "destroy"
                && valid_operand(path)
                && parsed.value("-versions").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        [kv, metadata, delete, path]
            if kv == "kv"
                && metadata == "metadata"
                && delete == "delete"
                && valid_operand(path) =>
        {
            Classification::deletion()
        }
        [secrets, disable, path]
            if secrets == "secrets" && disable == "disable" && valid_operand(path) =>
        {
            Classification::deletion()
        }
        positions if vault_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn vault_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [kv, delete, ..] if kv == "kv" && matches!(delete.as_str(), "delete" | "destroy"))
        || matches!(positions, [kv, metadata, delete, ..] if kv == "kv" && metadata == "metadata" && delete == "delete")
        || matches!(positions, [secrets, disable, ..] if secrets == "secrets" && disable == "disable")
}

fn aws(arguments: &[String]) -> Classification {
    if arguments.iter().any(|argument| {
        argument == "--generate-cli-skeleton" || argument.starts_with("--generate-cli-skeleton=")
    }) {
        return Classification::control();
    }
    let parsed = match parse_options(
        arguments,
        &[
            "--cli-auto-prompt",
            "--debug",
            "--force-delete-without-recovery",
            "--help",
            "--no-cli-auto-prompt",
            "--no-cli-pager",
            "--no-force-delete-without-recovery",
            "--no-paginate",
            "--no-sign-request",
            "--no-verify-ssl",
            "--version",
        ],
        &[
            "--ca-bundle",
            "--cli-binary-format",
            "--cli-connect-timeout",
            "--cli-read-timeout",
            "--color",
            "--endpoint-url",
            "--name",
            "--output",
            "--profile",
            "--query",
            "--recovery-window-in-days",
            "--region",
            "--secret-id",
        ],
        &["--names"],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("aws", &parsed),
    };
    if parsed.non_executing()
        || parsed
            .positionals
            .last()
            .is_some_and(|value| value == "help")
    {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [service, command]
            if service == "secretsmanager"
                && command == "delete-secret"
                && parsed.value("--secret-id").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        [service, command]
            if service == "ssm"
                && command == "delete-parameter"
                && parsed.value("--name").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        [service, command]
            if service == "ssm"
                && command == "delete-parameters"
                && parsed.values("--names").is_some_and(|values| {
                    !values.is_empty() && values.iter().all(|value| valid_operand(value))
                }) =>
        {
            Classification::deletion()
        }
        positions if aws_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn aws_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [service, command, ..] if service == "secretsmanager" && command == "delete-secret")
        || matches!(positions, [service, command, ..] if service == "ssm" && matches!(command.as_str(), "delete-parameter" | "delete-parameters"))
}

fn gcloud(arguments: &[String]) -> Classification {
    let parsed = match parse_options(
        arguments,
        &[
            "-h",
            "--help",
            "--log-http",
            "--quiet",
            "-q",
            "--user-output-enabled",
            "--no-user-output-enabled",
            "--version",
        ],
        &[
            "--account",
            "--billing-project",
            "--configuration",
            "--format",
            "--impersonate-service-account",
            "--location",
            "--project",
            "--secret",
            "--trace-token",
            "--verbosity",
        ],
        &[],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("gcloud", &parsed),
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [secrets, delete, name]
            if secrets == "secrets" && delete == "delete" && valid_operand(name) =>
        {
            Classification::deletion()
        }
        [secrets, versions, destroy, version]
            if secrets == "secrets"
                && versions == "versions"
                && destroy == "destroy"
                && valid_operand(version)
                && parsed.value("--secret").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        positions if gcloud_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn gcloud_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [secrets, delete, ..] if secrets == "secrets" && delete == "delete")
        || matches!(positions, [secrets, versions, destroy, ..] if secrets == "secrets" && versions == "versions" && destroy == "destroy")
}

fn azure(arguments: &[String]) -> Classification {
    let parsed = match parse_options(
        arguments,
        &[
            "--debug",
            "-h",
            "--help",
            "--no-wait",
            "--only-show-errors",
            "--verbose",
            "--version",
            "--yes",
            "-y",
        ],
        &[
            "-g",
            "--id",
            "--location",
            "-n",
            "--name",
            "-o",
            "--output",
            "--query",
            "--resource-group",
            "--subscription",
            "--vault-name",
        ],
        &[],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("az", &parsed),
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [keyvault, resource, action]
            if keyvault == "keyvault"
                && matches!(resource.as_str(), "secret" | "key" | "certificate")
                && matches!(action.as_str(), "delete" | "purge")
                && azure_object_selected(&parsed) =>
        {
            Classification::deletion()
        }
        [keyvault, action]
            if keyvault == "keyvault"
                && matches!(action.as_str(), "delete" | "purge")
                && azure_vault_selected(&parsed) =>
        {
            Classification::deletion()
        }
        positions if azure_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn azure_object_selected(parsed: &ParsedOptions) -> bool {
    parsed.value("--id").is_some_and(valid_operand)
        || parsed.value("--vault-name").is_some_and(valid_operand)
            && parsed
                .value_any(&["--name", "-n"])
                .is_some_and(valid_operand)
}

fn azure_vault_selected(parsed: &ParsedOptions) -> bool {
    parsed.value("--id").is_some_and(valid_operand)
        || parsed
            .value_any(&["--name", "-n"])
            .is_some_and(valid_operand)
}

fn azure_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [keyvault, resource, action, ..]
        if keyvault == "keyvault"
            && matches!(resource.as_str(), "secret" | "key" | "certificate")
            && matches!(action.as_str(), "delete" | "purge"))
        || matches!(positions, [keyvault, action, ..]
            if keyvault == "keyvault" && matches!(action.as_str(), "delete" | "purge"))
}

fn doppler(arguments: &[String]) -> Classification {
    let parsed = match parse_options(
        arguments,
        &[
            "--debug",
            "-h",
            "--help",
            "--json",
            "--no-check-version",
            "--no-interactive",
            "--no-prompt",
            "--no-read-env",
            "--no-timeout",
            "--no-verify-tls",
            "--raw",
            "--silent",
            "--version",
            "-v",
            "--yes",
            "-y",
        ],
        &[
            "--api-host",
            "--attempts",
            "-c",
            "--config",
            "--config-dir",
            "--configuration",
            "--dashboard-host",
            "--dns-resolver-address",
            "--dns-resolver-proto",
            "--dns-resolver-timeout",
            "-e",
            "--environment",
            "-p",
            "--project",
            "--scope",
            "-t",
            "--timeout",
            "--token",
        ],
        &[],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("doppler", &parsed),
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [secrets, delete, names @ ..]
            if secrets == "secrets"
                && delete == "delete"
                && !names.is_empty()
                && names.iter().all(|name| valid_operand(name)) =>
        {
            Classification::deletion()
        }
        [configs, delete, config]
            if configs == "configs" && delete == "delete" && valid_operand(config) =>
        {
            Classification::deletion()
        }
        [configs, delete]
            if configs == "configs"
                && delete == "delete"
                && parsed.value("--config").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        [environments, delete, environment]
            if environments == "environments"
                && delete == "delete"
                && valid_operand(environment) =>
        {
            Classification::deletion()
        }
        [projects, delete, project]
            if projects == "projects" && delete == "delete" && valid_operand(project) =>
        {
            Classification::deletion()
        }
        [projects, delete]
            if projects == "projects"
                && delete == "delete"
                && parsed.value("--project").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        positions if doppler_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn doppler_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [resource, delete, ..]
        if matches!(resource.as_str(), "secrets" | "configs" | "environments" | "projects")
            && delete == "delete")
}

fn infisical(arguments: &[String]) -> Classification {
    let parsed = match parse_options(
        arguments,
        &[
            "--expand",
            "-h",
            "--help",
            "--plain",
            "--silent",
            "--version",
        ],
        &[
            "--domain",
            "--env",
            "--name",
            "--path",
            "--projectId",
            "--token",
        ],
        &[],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("infisical", &parsed),
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [secrets, delete, names @ ..]
            if secrets == "secrets"
                && delete == "delete"
                && !names.is_empty()
                && names.iter().all(|name| valid_operand(name)) =>
        {
            Classification::deletion()
        }
        [secrets, folders, delete]
            if secrets == "secrets"
                && folders == "folders"
                && delete == "delete"
                && parsed.value("--name").is_some_and(valid_operand) =>
        {
            Classification::deletion()
        }
        positions if infisical_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn infisical_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [secrets, delete, ..] if secrets == "secrets" && delete == "delete")
        || matches!(positions, [secrets, folders, delete, ..]
            if secrets == "secrets" && folders == "folders" && delete == "delete")
}

fn one_password(arguments: &[String]) -> Classification {
    let parsed = match parse_options(
        arguments,
        &[
            "--archive",
            "--cache",
            "--debug",
            "-h",
            "--help",
            "--iso-timestamps",
            "--no-color",
            "--version",
        ],
        &[
            "--account",
            "--config",
            "--encoding",
            "--format",
            "--in-file",
            "-i",
            "--out-file",
            "-o",
            "--session",
            "--vault",
        ],
        &[],
    ) {
        Ok(parsed) => parsed,
        Err(parsed) => return secret_store_parse_failure("op", &parsed),
    };
    if parsed.non_executing() || parsed.flag("--archive") {
        return Classification::control();
    }
    match parsed.positionals.as_slice() {
        [resource, delete, target]
            if matches!(resource.as_str(), "item" | "document")
                && delete == "delete"
                && valid_operand(target) =>
        {
            Classification::deletion()
        }
        [vault, delete, target]
            if vault == "vault" && delete == "delete" && valid_operand(target) =>
        {
            Classification::deletion()
        }
        positions if one_password_delete_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn one_password_delete_prefix(positions: &[String]) -> bool {
    matches!(positions, [resource, delete, ..]
        if matches!(resource.as_str(), "item" | "document" | "vault") && delete == "delete")
}

fn valid_operand(value: &str) -> bool {
    !value.is_empty() && value != "-"
}

fn secret_store_parse_failure(program: &str, parsed: &ParsedOptions) -> Classification {
    if secret_store_command_prefix(program, &parsed.positionals) {
        Classification::incomplete()
    } else {
        Classification::control()
    }
}

fn secret_store_command_prefix(program: &str, positions: &[String]) -> bool {
    let commands: &[&[&str]] = match program {
        "vault" => &[
            &["kv", "delete"],
            &["kv", "destroy"],
            &["kv", "metadata", "delete"],
            &["secrets", "disable"],
        ],
        "aws" => &[
            &["secretsmanager", "delete-secret"],
            &["ssm", "delete-parameter"],
            &["ssm", "delete-parameters"],
        ],
        "gcloud" => &[&["secrets", "delete"], &["secrets", "versions", "destroy"]],
        "az" => &[
            &["keyvault", "secret", "delete"],
            &["keyvault", "secret", "purge"],
            &["keyvault", "key", "delete"],
            &["keyvault", "key", "purge"],
            &["keyvault", "certificate", "delete"],
            &["keyvault", "certificate", "purge"],
            &["keyvault", "delete"],
            &["keyvault", "purge"],
        ],
        "doppler" => &[
            &["secrets", "delete"],
            &["configs", "delete"],
            &["environments", "delete"],
            &["projects", "delete"],
        ],
        "infisical" => &[&["secrets", "delete"], &["secrets", "folders", "delete"]],
        "op" => &[
            &["item", "delete"],
            &["document", "delete"],
            &["vault", "delete"],
        ],
        _ => unreachable!("secret-store programs are matched before option parsing"),
    };
    commands.iter().any(|command| {
        positions
            .iter()
            .zip(command.iter())
            .all(|(position, segment)| position == segment)
    })
}

#[derive(Default)]
struct ParsedOptions {
    positionals: Vec<String>,
    flags: Vec<String>,
    values: Vec<(String, Vec<String>)>,
}

impl ParsedOptions {
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|candidate| candidate == name)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values(name)
            .and_then(|values| values.last())
            .map(String::as_str)
    }

    fn value_any(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|name| self.value(name))
    }

    fn values(&self, name: &str) -> Option<&[String]> {
        self.values
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, values)| values.as_slice())
    }

    fn non_executing(&self) -> bool {
        self.flags.iter().any(|flag| {
            matches!(
                flag.as_str(),
                "-h" | "-help" | "--help" | "-version" | "--version" | "-v"
            )
        }) || self
            .positionals
            .first()
            .is_some_and(|position| matches!(position.as_str(), "help" | "version"))
    }
}

fn parse_options(
    arguments: &[String],
    flags: &[&str],
    values: &[&str],
    list_values: &[&str],
) -> Result<ParsedOptions, ParsedOptions> {
    let mut parsed = ParsedOptions::default();
    let mut index = 0;
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            let (name, attached) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(name, value)| {
                    (name, Some(value))
                });
            if flags.contains(&name) {
                let enabled = match attached {
                    None => true,
                    Some("true") => true,
                    Some("false") => false,
                    Some(_) => return Err(parsed),
                };
                if enabled {
                    parsed.flags.push(name.to_owned());
                }
                index += 1;
                continue;
            }
            if values.contains(&name) {
                let value = if let Some(value) = attached {
                    value
                } else {
                    index += 1;
                    let Some(value) = arguments.get(index).map(String::as_str) else {
                        return Err(parsed);
                    };
                    value
                };
                if value.is_empty() {
                    return Err(parsed);
                }
                parsed
                    .values
                    .push((name.to_owned(), vec![value.to_owned()]));
                index += 1;
                continue;
            }
            if list_values.contains(&name) {
                let mut found = Vec::new();
                if let Some(value) = attached {
                    if value.is_empty() {
                        return Err(parsed);
                    }
                    found.push(value.to_owned());
                } else {
                    while arguments
                        .get(index + 1)
                        .is_some_and(|value| !value.starts_with('-') && !value.is_empty())
                    {
                        index += 1;
                        found.push(arguments[index].clone());
                    }
                    if found.is_empty() {
                        return Err(parsed);
                    }
                }
                parsed.values.push((name.to_owned(), found));
                index += 1;
                continue;
            }
            return Err(parsed);
        }
        if argument.is_empty() {
            return Err(parsed);
        }
        parsed.positionals.push(argument.clone());
        index += 1;
    }
    Ok(parsed)
}
