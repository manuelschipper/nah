//! Classifies reviewed secret-store value reads and deletion commands.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::shell_word::static_word;

pub(crate) struct Classification {
    pub(crate) complete: bool,
    pub(crate) known_invocation: Option<SemanticCode>,
    pub(crate) system_state: Option<SemanticCode>,
}

impl Classification {
    const fn deletion() -> Self {
        Self {
            complete: true,
            known_invocation: None,
            system_state: Some(SemanticCode::SECRETS_STORE_DELETE),
        }
    }

    const fn destruction(valid: bool) -> Self {
        if !valid {
            return Self::incomplete();
        }
        Self {
            complete: true,
            known_invocation: None,
            system_state: Some(SemanticCode::SECRETS_STORE_DESTROY),
        }
    }

    const fn read() -> Self {
        Self {
            complete: true,
            known_invocation: Some(SemanticCode::SECRETS_STORE_READ),
            system_state: None,
        }
    }

    const fn control() -> Self {
        Self {
            complete: true,
            known_invocation: None,
            system_state: None,
        }
    }

    const fn incomplete() -> Self {
        Self {
            complete: false,
            known_invocation: None,
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
            "-snapshot-id",
            "-tls-server-name",
            "-version",
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
        [kv, get, path] if kv == "kv" && get == "get" && valid_operand(path) => {
            Classification::read()
        }
        [read, path] if read == "read" && valid_operand(path) => Classification::read(),
        [kv, delete, path] if kv == "kv" && delete == "delete" && valid_operand(path) => {
            Classification::deletion()
        }
        [kv, destroy, path]
            if kv == "kv"
                && destroy == "destroy"
                && valid_operand(path)
                && parsed.value("-versions").is_some()
                && parsed
                    .values
                    .iter()
                    .filter(|(name, _)| name == "-versions")
                    .flat_map(|(_, values)| values)
                    .all(|versions| {
                        versions.split(',').all(|version| {
                            version
                                .trim()
                                .parse::<i64>()
                                .is_ok_and(|version| version > 0)
                        })
                    }) =>
        {
            Classification::destruction(vault_destruction_options(&parsed))
        }
        [kv, metadata, delete, path]
            if kv == "kv"
                && metadata == "metadata"
                && delete == "delete"
                && valid_operand(path) =>
        {
            Classification::destruction(vault_destruction_options(&parsed))
        }
        [secrets, disable, path]
            if secrets == "secrets" && disable == "disable" && valid_operand(path) =>
        {
            Classification::destruction(vault_destruction_options(&parsed))
        }
        positions if vault_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

// Read-only selection options are not accepted by these destructive Vault forms.
fn vault_destruction_options(parsed: &ParsedOptions) -> bool {
    parsed.only_options(
        &[
            "-disable-redirects",
            "-non-interactive",
            "-output-curl-string",
            "-output-policy",
            "-policy-override",
            "-tls-skip-verify",
            "-address",
            "-agent-address",
            "-ca-cert",
            "-ca-path",
            "-client-cert",
            "-client-key",
            "-header",
            "-mfa",
            "-namespace",
            "-ns",
            "-tls-server-name",
            "-wrap-ttl",
        ],
        match parsed.positionals.get(1).map(String::as_str) {
            Some("destroy") => &["-mount", "-versions", "-format"],
            Some("metadata") => &["-mount"],
            _ => &[],
        },
    )
}

fn vault_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [read, ..] if read == "read")
        || matches!(positions, [kv, action, ..]
            if kv == "kv" && matches!(action.as_str(), "get" | "delete" | "destroy"))
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
            "--no-recursive",
            "--no-sign-request",
            "--no-with-decryption",
            "--no-verify-ssl",
            "--recursive",
            "--version",
            "--with-decryption",
        ],
        &[
            "--ca-bundle",
            "--cli-binary-format",
            "--cli-connect-timeout",
            "--cli-read-timeout",
            "--color",
            "--endpoint-url",
            "--name",
            "--max-items",
            "--output",
            "--page-size",
            "--path",
            "--profile",
            "--query",
            "--recovery-window-in-days",
            "--region",
            "--secret-id",
            "--starting-token",
            "--version-id",
            "--version-stage",
        ],
        &["--names", "--parameter-filters"],
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
                && command == "get-secret-value"
                && parsed.value("--secret-id").is_some_and(valid_operand) =>
        {
            Classification::read()
        }
        [service, command]
            if service == "ssm"
                && command == "get-parameter"
                && parsed.value("--name").is_some_and(valid_operand) =>
        {
            if aws_decryption_requested(&parsed) {
                Classification::read()
            } else {
                Classification::control()
            }
        }
        [service, command]
            if service == "ssm"
                && command == "get-parameters"
                && parsed.values("--names").is_some_and(|values| {
                    !values.is_empty() && values.iter().all(|value| valid_operand(value))
                }) =>
        {
            if aws_decryption_requested(&parsed) {
                Classification::read()
            } else {
                Classification::control()
            }
        }
        [service, command]
            if service == "ssm"
                && command == "get-parameters-by-path"
                && parsed.value("--path").is_some_and(valid_operand) =>
        {
            if aws_decryption_requested(&parsed) {
                Classification::read()
            } else {
                Classification::control()
            }
        }
        [service, command]
            if service == "secretsmanager"
                && command == "delete-secret"
                && parsed.value("--secret-id").is_some_and(valid_operand) =>
        {
            if !aws_deletion_options(
                arguments,
                &parsed,
                &[
                    "--secret-id",
                    "--recovery-window-in-days",
                    "--force-delete-without-recovery",
                    "--no-force-delete-without-recovery",
                ],
            ) {
                return Classification::incomplete();
            }
            let force = parsed
                .flags
                .iter()
                .rev()
                .find(|(name, _)| {
                    matches!(
                        name.as_str(),
                        "--force-delete-without-recovery" | "--no-force-delete-without-recovery"
                    )
                })
                .is_some_and(|(name, _)| name == "--force-delete-without-recovery");
            let recovery = parsed.value("--recovery-window-in-days");
            if recovery.is_some_and(|days| {
                !days
                    .parse::<u32>()
                    .is_ok_and(|days| (7..=30).contains(&days))
            }) || force && recovery.is_some()
            {
                Classification::incomplete()
            } else if force {
                Classification::destruction(true)
            } else {
                Classification::deletion()
            }
        }
        [service, command]
            if service == "ssm"
                && command == "delete-parameter"
                && parsed.value("--name").is_some_and(valid_operand) =>
        {
            Classification::destruction(aws_deletion_options(arguments, &parsed, &["--name"]))
        }
        [service, command]
            if service == "ssm"
                && command == "delete-parameters"
                && parsed.values("--names").is_some_and(|values| {
                    !values.is_empty() && values.iter().all(|value| valid_operand(value))
                }) =>
        {
            Classification::destruction(aws_deletion_options(arguments, &parsed, &["--names"]))
        }
        positions if aws_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn aws_deletion_options(arguments: &[String], parsed: &ParsedOptions, operation: &[&str]) -> bool {
    // AWS boolean switches take no attached value, including =true and =false.
    !arguments.iter().any(|argument| {
        argument
            .split_once('=')
            .is_some_and(|(name, _)| parsed.flags.iter().any(|(flag, _)| flag == name))
    }) && parsed.only_options(
        &[
            "--cli-auto-prompt",
            "--debug",
            "--no-cli-auto-prompt",
            "--no-cli-pager",
            "--no-paginate",
            "--no-sign-request",
            "--no-verify-ssl",
            "--ca-bundle",
            "--cli-binary-format",
            "--cli-connect-timeout",
            "--cli-read-timeout",
            "--color",
            "--endpoint-url",
            "--output",
            "--profile",
            "--query",
            "--region",
        ],
        operation,
    ) && parsed.values.iter().all(|(_, values)| {
        values
            .iter()
            .all(|value| !value.starts_with("file://") && !value.starts_with("fileb://"))
    })
}

fn aws_decryption_requested(parsed: &ParsedOptions) -> bool {
    parsed
        .flags
        .iter()
        .rev()
        .find(|(name, _)| matches!(name.as_str(), "--with-decryption" | "--no-with-decryption"))
        .is_some_and(|(name, enabled)| name == "--with-decryption" && *enabled)
}

fn aws_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [service, command, ..]
        if service == "secretsmanager"
            && matches!(command.as_str(), "get-secret-value" | "delete-secret"))
        || matches!(positions, [service, command, ..]
            if service == "ssm"
                && matches!(command.as_str(),
                    "get-parameter" | "get-parameters" | "get-parameters-by-path"
                        | "delete-parameter" | "delete-parameters"))
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
            "--out-file",
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
        [secrets, versions, access, version]
            if secrets == "secrets"
                && versions == "versions"
                && access == "access"
                && valid_operand(version)
                && parsed.value("--secret").is_some_and(valid_operand) =>
        {
            Classification::read()
        }
        [secrets, delete, name]
            if secrets == "secrets" && delete == "delete" && valid_operand(name) =>
        {
            Classification::destruction(parsed.only_options(
                &[
                    "--log-http",
                    "--quiet",
                    "-q",
                    "--user-output-enabled",
                    "--no-user-output-enabled",
                    "--account",
                    "--billing-project",
                    "--configuration",
                    "--format",
                    "--impersonate-service-account",
                    "--location",
                    "--project",
                    "--trace-token",
                    "--verbosity",
                ],
                &[],
            ))
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
        positions if gcloud_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn gcloud_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [secrets, versions, access, ..]
        if secrets == "secrets" && versions == "versions" && access == "access")
        || matches!(positions, [secrets, delete, ..] if secrets == "secrets" && delete == "delete")
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
            "--overwrite",
            "--verbose",
            "--yes",
            "-y",
        ],
        &[
            "-g",
            "--id",
            "--encoding",
            "--file",
            "-f",
            "--location",
            "-n",
            "--name",
            "-o",
            "--output",
            "--query",
            "--resource-group",
            "--subscription",
            "--vault-name",
            "--version",
            "-v",
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
        [keyvault, secret, action]
            if keyvault == "keyvault"
                && secret == "secret"
                && action == "show"
                && azure_object_selected(&parsed) =>
        {
            Classification::read()
        }
        [keyvault, secret, action]
            if keyvault == "keyvault"
                && secret == "secret"
                && action == "download"
                && azure_object_selected(&parsed)
                && parsed
                    .value_any(&["--file", "-f"])
                    .is_some_and(valid_operand) =>
        {
            Classification::read()
        }
        [keyvault, resource, action]
            if keyvault == "keyvault"
                && matches!(resource.as_str(), "secret" | "key" | "certificate")
                && matches!(action.as_str(), "delete" | "purge")
                && azure_object_selected(&parsed) =>
        {
            if action == "purge" {
                Classification::destruction(azure_purge_options(arguments, &parsed))
            } else {
                Classification::deletion()
            }
        }
        [keyvault, action]
            if keyvault == "keyvault"
                && matches!(action.as_str(), "delete" | "purge")
                && azure_vault_selected(&parsed) =>
        {
            if action == "purge" {
                Classification::destruction(azure_purge_options(arguments, &parsed))
            } else {
                Classification::deletion()
            }
        }
        positions if azure_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn azure_purge_options(arguments: &[String], parsed: &ParsedOptions) -> bool {
    !arguments.iter().any(|argument| {
        argument
            .split_once('=')
            .is_some_and(|(name, _)| parsed.flags.iter().any(|(flag, _)| flag == name))
    }) && parsed.only_options(
        &[
            "--debug",
            "--only-show-errors",
            "--verbose",
            "-n",
            "--name",
            "-o",
            "--output",
            "--query",
            "--subscription",
        ],
        if parsed.positionals.len() == 2 {
            &["--location", "--no-wait"]
        } else {
            &["--id", "--vault-name"]
        },
    )
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

fn azure_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [keyvault, secret, action, ..]
        if keyvault == "keyvault"
            && secret == "secret"
            && matches!(action.as_str(), "show" | "download"))
        || matches!(positions, [keyvault, resource, action, ..]
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
            "--no-file",
            "--no-check-version",
            "--no-interactive",
            "--no-prompt",
            "--no-read-env",
            "--no-timeout",
            "--no-verify-tls",
            "--only-names",
            "--plain",
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
            "--dynamic-ttl",
            "--dns-resolver-address",
            "--dns-resolver-proto",
            "--dns-resolver-timeout",
            "-e",
            "--environment",
            "--format",
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
        [secrets] if secrets == "secrets" && !parsed.flag("--only-names") => Classification::read(),
        [secrets, get, names @ ..]
            if secrets == "secrets"
                && get == "get"
                && !names.is_empty()
                && names.iter().all(|name| valid_operand(name))
                && !parsed.flag("--only-names") =>
        {
            Classification::read()
        }
        [secrets, download] if secrets == "secrets" && download == "download" => {
            if parsed.flag("--no-file") {
                Classification::read()
            } else {
                Classification::control()
            }
        }
        [secrets, delete, names @ ..]
            if secrets == "secrets"
                && delete == "delete"
                && !names.is_empty()
                && names.iter().all(|name| valid_operand(name)) =>
        {
            Classification::deletion()
        }
        [configs, delete, targets @ ..]
            if configs == "configs"
                && delete == "delete"
                && match targets {
                    [config] => valid_operand(config),
                    [] => parsed.value("--config").is_some_and(valid_operand),
                    _ => false,
                } =>
        {
            Classification::destruction(parsed.only_options(
                &[
                    "--debug",
                    "--json",
                    "--no-check-version",
                    "--no-interactive",
                    "--no-prompt",
                    "--no-read-env",
                    "--no-timeout",
                    "--no-verify-tls",
                    "--silent",
                    "--yes",
                    "-y",
                    "--api-host",
                    "--attempts",
                    "-c",
                    "--config",
                    "--config-dir",
                    "--dashboard-host",
                    "--dns-resolver-address",
                    "--dns-resolver-proto",
                    "--dns-resolver-timeout",
                    "-p",
                    "--project",
                    "--scope",
                    "-t",
                    "--timeout",
                    "--token",
                ],
                &[],
            ))
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
        positions if doppler_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn doppler_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [secrets, action, ..]
        if secrets == "secrets" && matches!(action.as_str(), "get" | "download"))
        || matches!(positions, [resource, delete, ..]
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
            "--include-imports",
            "--plain",
            "--raw-value",
            "--secret-overriding",
            "--silent",
            "--version",
        ],
        &[
            "--domain",
            "--env",
            "--format",
            "--name",
            "--output-file",
            "--path",
            "--projectId",
            "--tags",
            "--template",
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
        [secrets] if secrets == "secrets" => Classification::read(),
        [secrets, get, names @ ..]
            if secrets == "secrets"
                && get == "get"
                && !names.is_empty()
                && names.iter().all(|name| valid_operand(name)) =>
        {
            Classification::read()
        }
        [export] if export == "export" => Classification::read(),
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
        positions if infisical_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn infisical_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [export, ..] if export == "export")
        || matches!(positions, [secrets, get, ..] if secrets == "secrets" && get == "get")
        || matches!(positions, [secrets, delete, ..] if secrets == "secrets" && delete == "delete")
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
            "--force",
            "-f",
            "-h",
            "--help",
            "--include-archive",
            "--iso-timestamps",
            "--no-color",
            "--no-newline",
            "-n",
            "--otp",
            "--reveal",
            "--share-link",
            "--version",
        ],
        &[
            "--account",
            "--config",
            "--encoding",
            "--fields",
            "--file-mode",
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
        [read, reference] if read == "read" && valid_operand(reference) => Classification::read(),
        [item, get, target] if item == "item" && get == "get" && valid_operand(target) => {
            if parsed.flag("--reveal")
                || parsed.flag("--otp")
                || parsed.value("--fields").is_some_and(valid_operand)
            {
                Classification::read()
            } else {
                Classification::control()
            }
        }
        [document, get, target]
            if document == "document" && get == "get" && valid_operand(target) =>
        {
            Classification::read()
        }
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
        positions if one_password_classified_prefix(positions) => Classification::incomplete(),
        _ => Classification::control(),
    }
}

fn one_password_classified_prefix(positions: &[String]) -> bool {
    matches!(positions, [read, ..] if read == "read")
        || matches!(positions, [resource, get, ..]
            if matches!(resource.as_str(), "item" | "document") && get == "get")
        || matches!(positions, [resource, delete, ..]
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
            &["kv", "get"],
            &["read"],
            &["kv", "delete"],
            &["kv", "destroy"],
            &["kv", "metadata", "delete"],
            &["secrets", "disable"],
        ],
        "aws" => &[
            &["secretsmanager", "get-secret-value"],
            &["ssm", "get-parameter"],
            &["ssm", "get-parameters"],
            &["ssm", "get-parameters-by-path"],
            &["secretsmanager", "delete-secret"],
            &["ssm", "delete-parameter"],
            &["ssm", "delete-parameters"],
        ],
        "gcloud" => &[
            &["secrets", "versions", "access"],
            &["secrets", "delete"],
            &["secrets", "versions", "destroy"],
        ],
        "az" => &[
            &["keyvault", "secret", "show"],
            &["keyvault", "secret", "download"],
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
            &["secrets"],
            &["secrets", "get"],
            &["secrets", "download"],
            &["secrets", "delete"],
            &["configs", "delete"],
            &["environments", "delete"],
            &["projects", "delete"],
        ],
        "infisical" => &[
            &["secrets"],
            &["secrets", "get"],
            &["export"],
            &["secrets", "delete"],
            &["secrets", "folders", "delete"],
        ],
        "op" => &[
            &["read"],
            &["item", "get"],
            &["document", "get"],
            &["item", "delete"],
            &["document", "delete"],
            &["vault", "delete"],
        ],
        _ => unreachable!("secret-store programs are matched before option parsing"),
    };
    commands.iter().any(|command| {
        positions.len() >= command.len()
            && positions
                .iter()
                .zip(command.iter())
                .all(|(position, segment)| position == segment)
    })
}

#[derive(Default)]
struct ParsedOptions {
    positionals: Vec<String>,
    flags: Vec<(String, bool)>,
    values: Vec<(String, Vec<String>)>,
}

impl ParsedOptions {
    fn only_options(&self, common: &[&str], operation: &[&str]) -> bool {
        self.flags
            .iter()
            .map(|(name, _)| name)
            .chain(self.values.iter().map(|(name, _)| name))
            .all(|name| common.contains(&name.as_str()) || operation.contains(&name.as_str()))
            && self.values.iter().all(|(_, values)| {
                values
                    .iter()
                    .all(|value| valid_operand(value) && !value.starts_with('-'))
            })
    }

    fn flag(&self, name: &str) -> bool {
        self.flags
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == name)
            .is_some_and(|(_, enabled)| *enabled)
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
        ["-h", "-help", "--help", "-version", "--version", "-v"]
            .iter()
            .any(|name| self.flag(name))
            || self
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
                parsed.flags.push((name.to_owned(), enabled));
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
