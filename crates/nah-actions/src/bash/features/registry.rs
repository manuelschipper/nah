//! Classifies reviewed package-registry publication, removal, and ownership commands.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::shell_word::static_word;

pub(crate) struct Classification {
    pub(crate) complete: bool,
    pub(crate) system_state: Option<SemanticCode>,
}

impl Classification {
    const fn operation(system_state: SemanticCode) -> Self {
        Self {
            complete: true,
            system_state: Some(system_state),
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
    if !registry_program(program) {
        return None;
    }
    if !qualified_program && (path_overridden || assignments.iter().any(|(name, _)| name == "PATH"))
    {
        return Some(Classification::incomplete());
    }
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    classify_static(program, &arguments)
}

fn registry_program(program: &str) -> bool {
    matches!(
        program,
        "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "cargo"
            | "gem"
            | "twine"
            | "python"
            | "python3"
            | "uv"
            | "poetry"
            | "hatch"
            | "flit"
            | "dotnet"
            | "nuget"
            | "npx"
            | "bunx"
    )
}

fn classify_static(program: &str, arguments: &[String]) -> Option<Classification> {
    match program {
        "npm" => npm(arguments),
        "pnpm" => pnpm(arguments),
        "yarn" => yarn(arguments),
        "bun" => bun(arguments),
        "cargo" => cargo(arguments),
        "gem" => gem(arguments),
        "twine" => twine(arguments),
        "python" | "python3" => python(arguments),
        "uv" => uv(arguments),
        "poetry" => poetry(arguments),
        "hatch" => hatch(arguments),
        "flit" => flit(arguments),
        "dotnet" => dotnet(arguments),
        "nuget" => nuget(arguments),
        "npx" => package_wrapper(arguments, NPX_BOOLEAN, NPX_VALUE),
        "bunx" => package_wrapper(arguments, BUNX_BOOLEAN, BUNX_VALUE),
        _ => None,
    }
}

#[derive(Default)]
struct ParsedOptions {
    positionals: Vec<String>,
    options: Vec<(String, Option<String>)>,
}

impl ParsedOptions {
    fn present(&self, names: &[&str]) -> bool {
        self.options
            .iter()
            .any(|(name, _)| names.contains(&name.as_str()))
    }

    fn boolean(&self, name: &str) -> bool {
        self.options
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == name)
            .is_some_and(|(_, value)| {
                value.as_deref().map(parse_bool).unwrap_or(Some(true)) == Some(true)
            })
    }

    fn value_count(&self, names: &[&str]) -> usize {
        self.options
            .iter()
            .filter(|(name, _)| names.contains(&name.as_str()))
            .count()
    }
}

fn parse_options(
    arguments: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
) -> Result<ParsedOptions, ()> {
    parse_options_with_boolean_values(arguments, boolean_options, value_options, &[])
}

fn parse_options_with_boolean_values(
    arguments: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
    boolean_value_options: &[&str],
) -> Result<ParsedOptions, ()> {
    let mut parsed = ParsedOptions::default();
    let mut index = 0;
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if !options {
            if argument.is_empty() {
                return Err(());
            }
            parsed.positionals.push(argument.clone());
            index += 1;
            continue;
        }
        let Some(consumed) = parse_option_at(
            &mut parsed,
            arguments,
            index,
            boolean_options,
            value_options,
            boolean_value_options,
        )?
        else {
            if argument.is_empty() {
                return Err(());
            }
            parsed.positionals.push(argument.clone());
            index += 1;
            continue;
        };
        index += consumed;
    }
    Ok(parsed)
}

fn parse_option_at(
    parsed: &mut ParsedOptions,
    arguments: &[String],
    index: usize,
    boolean_options: &[&str],
    value_options: &[&str],
    boolean_value_options: &[&str],
) -> Result<Option<usize>, ()> {
    let argument = &arguments[index];
    if !argument.starts_with('-') || argument == "-" {
        return Ok(None);
    }
    if let Some((name, value)) = split_joined_option(argument) {
        if boolean_value_options.contains(&name) && parse_bool(value).is_some() {
            parsed
                .options
                .push((name.to_owned(), Some(value.to_owned())));
            return Ok(Some(1));
        }
        if value_options.contains(&name) && !value.is_empty() {
            parsed
                .options
                .push((name.to_owned(), Some(value.to_owned())));
            return Ok(Some(1));
        }
        return Err(());
    }
    if let Some(name) = argument.strip_prefix("--no-") {
        let name = format!("--{name}");
        if boolean_value_options.contains(&name.as_str()) {
            parsed.options.push((name, Some("false".to_owned())));
            return Ok(Some(1));
        }
    }
    if boolean_options.contains(&argument.as_str()) {
        parsed.options.push((argument.clone(), None));
        return Ok(Some(1));
    }
    if value_options.contains(&argument.as_str()) {
        let value = arguments
            .get(index + 1)
            .filter(|value| !value.is_empty() && !value.starts_with('-'))
            .ok_or(())?;
        parsed.options.push((argument.clone(), Some(value.clone())));
        return Ok(Some(2));
    }
    if let Some((name, value)) = attached_short_value(argument, value_options) {
        parsed
            .options
            .push((name.to_owned(), Some(value.to_owned())));
        return Ok(Some(1));
    }
    if let Some(cluster) = argument
        .strip_prefix('-')
        .filter(|cluster| !cluster.starts_with('-'))
        && cluster.len() > 1
        && cluster
            .chars()
            .all(|flag| boolean_options.contains(&format!("-{flag}").as_str()))
    {
        parsed
            .options
            .extend(cluster.chars().map(|flag| (format!("-{flag}"), None)));
        return Ok(Some(1));
    }
    Err(())
}

fn split_joined_option(argument: &str) -> Option<(&str, &str)> {
    let (name, value) = argument.split_once('=')?;
    name.starts_with("--").then_some((name, value))
}

fn attached_short_value<'a>(
    argument: &'a str,
    value_options: &[&'a str],
) -> Option<(&'a str, &'a str)> {
    value_options.iter().copied().find_map(|name| {
        (name.len() == 2 && name.starts_with('-'))
            .then(|| argument.strip_prefix(name))
            .flatten()
            .and_then(|value| {
                let value = value.strip_prefix('=').unwrap_or(value);
                (!value.is_empty()).then_some((name, value))
            })
    })
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "TRUE" | "True" => Some(true),
        "0" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

fn parsed_or_incomplete(
    arguments: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
) -> Result<ParsedOptions, Classification> {
    parse_options(arguments, boolean_options, value_options)
        .map_err(|()| Classification::incomplete())
}

fn parsed_or_incomplete_with_boolean_values(
    arguments: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
    boolean_value_options: &[&str],
) -> Result<ParsedOptions, Classification> {
    parse_options_with_boolean_values(
        arguments,
        boolean_options,
        value_options,
        boolean_value_options,
    )
    .map_err(|()| Classification::incomplete())
}

fn help_requested(parsed: &ParsedOptions) -> bool {
    ["-h", "--help", "-?", "--version", "-V"]
        .into_iter()
        .any(|name| parsed.boolean(name))
}

const NPM_BOOLEAN: &[&str] = &[
    "-f",
    "-h",
    "-v",
    "--dry-run",
    "--force",
    "--foreground-scripts",
    "--help",
    "--ignore-scripts",
    "--include-workspace-root",
    "--json",
    "--provenance",
    "--version",
    "--workspaces",
    "--yes",
];
const NPM_VALUE: &[&str] = &[
    "-w",
    "--access",
    "--cache",
    "--otp",
    "--provenance-file",
    "--registry",
    "--tag",
    "--userconfig",
    "--workspace",
];

fn npm(arguments: &[String]) -> Option<Classification> {
    let parsed = match parsed_or_incomplete_with_boolean_values(
        arguments,
        NPM_BOOLEAN,
        NPM_VALUE,
        NPM_BOOLEAN,
    ) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if help_requested(&parsed) || parsed.present(&["-v"]) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command] | [command, _] if command == "unpublish" => {
            Some(Classification::operation(SemanticCode::REGISTRY_UNPUBLISH))
        }
        [command, action, _, _]
            if matches!(command.as_str(), "author" | "owner")
                && matches!(action.as_str(), "add" | "remove" | "rm") =>
        {
            Some(Classification::operation(SemanticCode::REGISTRY_UNPUBLISH))
        }
        [command] | [command, _] if command == "publish" => Some(if parsed.boolean("--dry-run") {
            Classification::control()
        } else {
            Classification::operation(SemanticCode::REGISTRY_PUBLISH)
        }),
        [command, ..]
            if matches!(
                command.as_str(),
                "access"
                    | "add"
                    | "deprecate"
                    | "install"
                    | "org"
                    | "pack"
                    | "remove"
                    | "team"
                    | "token"
                    | "uninstall"
            ) =>
        {
            Some(Classification::control())
        }
        [command, action, ..]
            if matches!(command.as_str(), "author" | "owner") && action == "ls" =>
        {
            Some(Classification::control())
        }
        [command, ..]
            if matches!(
                command.as_str(),
                "author" | "owner" | "publish" | "unpublish"
            ) =>
        {
            Some(Classification::incomplete())
        }
        _ => None,
    }
}

const PNPM_BOOLEAN: &[&str] = &[
    "-h",
    "-r",
    "--dry-run",
    "--force",
    "--help",
    "--json",
    "--no-git-checks",
    "--recursive",
    "--report-summary",
];
const PNPM_VALUE: &[&str] = &[
    "-C",
    "-p",
    "--access",
    "--allow-build",
    "--dir",
    "--filter",
    "--otp",
    "--package",
    "--publish-branch",
    "--registry",
    "--tag",
];

fn pnpm(arguments: &[String]) -> Option<Classification> {
    let wrapper = match parse_wrapper_command(arguments, PNPM_BOOLEAN, PNPM_VALUE) {
        Ok(wrapper) => wrapper,
        Err(()) => return Some(Classification::incomplete()),
    };
    if help_requested(&wrapper.options) {
        return Some(Classification::control());
    }
    if wrapper.program == Some("dlx") {
        return package_wrapper(wrapper.arguments, PNPM_BOOLEAN, PNPM_VALUE);
    }
    let parsed = match parsed_or_incomplete(arguments, PNPM_BOOLEAN, PNPM_VALUE) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if help_requested(&parsed) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command] | [command, _] if command == "publish" => Some(if parsed.boolean("--dry-run") {
            Classification::control()
        } else {
            Classification::operation(SemanticCode::REGISTRY_PUBLISH)
        }),
        [command, ..] if command == "publish" || command == "dlx" => {
            Some(Classification::incomplete())
        }
        [command, ..]
            if matches!(
                command.as_str(),
                "add" | "install" | "pack" | "remove" | "uninstall"
            ) =>
        {
            Some(Classification::control())
        }
        _ => None,
    }
}

const YARN_BOOLEAN: &[&str] = &[
    "-h",
    "--help",
    "--json",
    "--non-interactive",
    "--provenance",
    "--tolerate-republish",
];
const YARN_VALUE: &[&str] = &["--access", "--new-version", "--otp", "--registry", "--tag"];

fn yarn(arguments: &[String]) -> Option<Classification> {
    let parsed = match parsed_or_incomplete(arguments, YARN_BOOLEAN, YARN_VALUE) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if help_requested(&parsed) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command] | [command, _] if command == "publish" => {
            Some(Classification::operation(SemanticCode::REGISTRY_PUBLISH))
        }
        [npm, command] if npm == "npm" && command == "publish" => {
            Some(Classification::operation(SemanticCode::REGISTRY_PUBLISH))
        }
        [command, ..] if command == "publish" || command == "npm" => {
            Some(Classification::incomplete())
        }
        [command, ..] if matches!(command.as_str(), "add" | "install" | "pack" | "remove") => {
            Some(Classification::control())
        }
        _ => None,
    }
}

const BUN_BOOLEAN: &[&str] = &["-h", "--help", "--provenance"];
const BUN_VALUE: &[&str] = &[
    "--access",
    "--auth-type",
    "--gzip-level",
    "--otp",
    "--registry",
    "--tag",
];

fn bun(arguments: &[String]) -> Option<Classification> {
    if arguments.first().map(String::as_str) != Some("publish") {
        return None;
    }
    simple_publish(arguments, BUN_BOOLEAN, BUN_VALUE, false, Some(1))
}

const CARGO_BOOLEAN: &[&str] = &[
    "-h",
    "-q",
    "-v",
    "-V",
    "--all-features",
    "--allow-dirty",
    "--dry-run",
    "--frozen",
    "--help",
    "--keep-going",
    "--list",
    "--locked",
    "--no-default-features",
    "--no-verify",
    "--offline",
    "--quiet",
    "--undo",
    "--verbose",
    "--versioned-dirs",
];
const CARGO_VALUE: &[&str] = &[
    "-F",
    "-a",
    "-j",
    "-p",
    "-r",
    "--add",
    "--color",
    "--config",
    "--features",
    "--index",
    "--jobs",
    "--manifest-path",
    "--package",
    "--registry",
    "--remove",
    "--target",
    "--token",
    "--version",
];

const CARGO_OWNER_BOOLEAN: &[&str] = &[
    "-h",
    "-q",
    "-v",
    "-V",
    "--frozen",
    "--help",
    "--list",
    "--locked",
    "--offline",
    "--quiet",
];
const CARGO_OWNER_VALUE: &[&str] = &[
    "-a",
    "-r",
    "--add",
    "--color",
    "--config",
    "--index",
    "--registry",
    "--remove",
    "--token",
];
const CARGO_PUBLISH_BOOLEAN: &[&str] = &[
    "-h",
    "-q",
    "-v",
    "-V",
    "--all-features",
    "--allow-dirty",
    "--dry-run",
    "--frozen",
    "--help",
    "--keep-going",
    "--locked",
    "--no-default-features",
    "--no-verify",
    "--offline",
    "--quiet",
    "--versioned-dirs",
];
const CARGO_PUBLISH_VALUE: &[&str] = &[
    "-F",
    "-j",
    "-p",
    "--color",
    "--config",
    "--features",
    "--index",
    "--jobs",
    "--manifest-path",
    "--package",
    "--registry",
    "--target",
    "--token",
];

fn cargo(arguments: &[String]) -> Option<Classification> {
    let arguments = if arguments
        .first()
        .is_some_and(|argument| argument.starts_with('+') && argument.len() > 1)
    {
        &arguments[1..]
    } else {
        arguments
    };
    if matches!(arguments, [flag] if matches!(flag.as_str(), "--version" | "-V")) {
        return Some(Classification::control());
    }
    let subcommand = cargo_subcommand(arguments);
    if subcommand.is_some_and(|command| {
        matches!(
            command,
            "add" | "build" | "check" | "install" | "remove" | "run" | "test" | "uninstall"
        )
    }) {
        return None;
    }
    let (boolean_options, value_options) = match subcommand {
        Some("owner") => (CARGO_OWNER_BOOLEAN, CARGO_OWNER_VALUE),
        Some("publish") => (CARGO_PUBLISH_BOOLEAN, CARGO_PUBLISH_VALUE),
        _ => (CARGO_BOOLEAN, CARGO_VALUE),
    };
    let parsed = match parsed_or_incomplete(arguments, boolean_options, value_options) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if parsed.present(&["-h", "--help", "-V"]) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command] if command == "publish" => Some(if parsed.boolean("--dry-run") {
            Classification::control()
        } else {
            Classification::operation(SemanticCode::REGISTRY_PUBLISH)
        }),
        [command] | [command, _]
            if command == "owner" && parsed.present(&["-a", "--add", "-r", "--remove"]) =>
        {
            Some(Classification::operation(SemanticCode::REGISTRY_UNPUBLISH))
        }
        [command, ..] if matches!(command.as_str(), "owner" | "publish") => {
            if command == "owner" && parsed.present(&["--list"]) {
                Some(Classification::control())
            } else {
                Some(Classification::incomplete())
            }
        }
        [command, ..] if matches!(command.as_str(), "install" | "package" | "remove" | "yank") => {
            Some(Classification::control())
        }
        _ => None,
    }
}

fn cargo_subcommand(arguments: &[String]) -> Option<&str> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            return arguments.get(index + 1).map(String::as_str);
        }
        if CARGO_BOOLEAN.contains(&argument.as_str()) {
            index += 1;
            continue;
        }
        if CARGO_VALUE.contains(&argument.as_str()) {
            index += 2;
            continue;
        }
        if split_joined_option(argument)
            .is_some_and(|(name, value)| CARGO_VALUE.contains(&name) && !value.is_empty())
            || attached_short_value(argument, CARGO_VALUE).is_some()
        {
            index += 1;
            continue;
        }
        return (!argument.starts_with('-')).then_some(argument.as_str());
    }
    None
}

const GEM_BOOLEAN: &[&str] = &["-h", "--dry-run", "--help", "--silent", "--verbose"];
const GEM_VALUE: &[&str] = &[
    "-a",
    "-p",
    "-r",
    "-v",
    "--add",
    "--config-file",
    "--host",
    "--key",
    "--otp",
    "--platform",
    "--remove",
    "--version",
];

fn gem(arguments: &[String]) -> Option<Classification> {
    let parsed = match parsed_or_incomplete(arguments, GEM_BOOLEAN, GEM_VALUE) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if parsed.present(&["-h", "--help"]) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command, _] if command == "yank" && parsed.value_count(&["-v", "--version"]) == 1 => {
            Some(Classification::operation(SemanticCode::REGISTRY_UNPUBLISH))
        }
        [command, _]
            if command == "owner" && parsed.present(&["-a", "--add", "-r", "--remove"]) =>
        {
            Some(Classification::operation(SemanticCode::REGISTRY_UNPUBLISH))
        }
        [command, _] if command == "push" => {
            Some(Classification::operation(SemanticCode::REGISTRY_PUBLISH))
        }
        [command, ..] if matches!(command.as_str(), "owner" | "push" | "yank") => {
            if command == "owner" && parsed.value_count(&["-a", "--add", "-r", "--remove"]) == 0 {
                Some(Classification::control())
            } else {
                Some(Classification::incomplete())
            }
        }
        [command, ..] if matches!(command.as_str(), "install" | "uninstall") => {
            Some(Classification::control())
        }
        _ => None,
    }
}

const TWINE_BOOLEAN: &[&str] = &[
    "-h",
    "--attestations",
    "--disable-progress-bar",
    "--help",
    "--non-interactive",
    "--sign",
    "--skip-existing",
    "--verbose",
];
const TWINE_VALUE: &[&str] = &[
    "-c",
    "-i",
    "-p",
    "-r",
    "-u",
    "--cert",
    "--client-cert",
    "--comment",
    "--config-file",
    "--identity",
    "--password",
    "--repository",
    "--repository-url",
    "--username",
];

fn twine(arguments: &[String]) -> Option<Classification> {
    let parsed = match parsed_or_incomplete(arguments, TWINE_BOOLEAN, TWINE_VALUE) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if help_requested(&parsed) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command, files @ ..] if command == "upload" && !files.is_empty() => {
            Some(Classification::operation(SemanticCode::REGISTRY_PUBLISH))
        }
        [command, ..] if command == "upload" => Some(Classification::incomplete()),
        _ => None,
    }
}

fn python(arguments: &[String]) -> Option<Classification> {
    if matches!(arguments, [flag] if matches!(flag.as_str(), "-h" | "--help" | "-V" | "--version"))
    {
        return Some(Classification::control());
    }
    let mut index = 0;
    while matches!(
        arguments.get(index).map(String::as_str),
        Some("-B" | "-E" | "-I" | "-s" | "-S" | "-u" | "-v" | "-x")
    ) {
        index += 1;
    }
    if arguments.get(index).map(String::as_str) != Some("-m") {
        return None;
    }
    let Some(module) = arguments.get(index + 1) else {
        return Some(Classification::incomplete());
    };
    if module != "twine" {
        return Some(Classification::control());
    }
    twine(&arguments[index + 2..])
}

const UV_BOOLEAN: &[&str] = &[
    "-h",
    "--help",
    "--managed-python",
    "--native-tls",
    "--no-attestations",
    "--no-cache",
    "--no-managed-python",
    "--no-progress",
    "--offline",
];
const UV_VALUE: &[&str] = &[
    "--allow-insecure-host",
    "--check-url",
    "--config-file",
    "--directory",
    "--index",
    "--keyring-provider",
    "--password",
    "--publish-url",
    "--trusted-publishing",
    "--username",
];

fn uv(arguments: &[String]) -> Option<Classification> {
    simple_publish(arguments, UV_BOOLEAN, UV_VALUE, false, None)
}

const POETRY_BOOLEAN: &[&str] = &["-h", "--build", "--dry-run", "--help", "--skip-existing"];
const POETRY_VALUE: &[&str] = &[
    "-p",
    "-r",
    "-u",
    "--cert",
    "--client-cert",
    "--dist-dir",
    "--password",
    "--repository",
    "--username",
];

fn poetry(arguments: &[String]) -> Option<Classification> {
    simple_publish(arguments, POETRY_BOOLEAN, POETRY_VALUE, true, Some(0))
}

const HATCH_BOOLEAN: &[&str] = &[
    "-h",
    "--help",
    "--initialize-auth",
    "--no-prompt",
    "--no-store-auth",
    "--store-auth",
];
const HATCH_VALUE: &[&str] = &["-a", "-r", "-u", "--auth", "--repo", "--user"];

fn hatch(arguments: &[String]) -> Option<Classification> {
    simple_publish(arguments, HATCH_BOOLEAN, HATCH_VALUE, false, None)
}

const FLIT_BOOLEAN: &[&str] = &[
    "-h",
    "--dry-run",
    "--help",
    "--no-setup-py",
    "--no-use-vcs",
    "--setup-py",
];
const FLIT_VALUE: &[&str] = &["--format", "--pypirc", "--repository"];

fn flit(arguments: &[String]) -> Option<Classification> {
    simple_publish(arguments, FLIT_BOOLEAN, FLIT_VALUE, true, Some(0))
}

fn simple_publish(
    arguments: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
    honors_dry_run: bool,
    maximum_operands: Option<usize>,
) -> Option<Classification> {
    let parsed = match parsed_or_incomplete(arguments, boolean_options, value_options) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if help_requested(&parsed) {
        return Some(Classification::control());
    }
    let [command, operands @ ..] = parsed.positionals.as_slice() else {
        return None;
    };
    if command != "publish" {
        return None;
    }
    if maximum_operands.is_some_and(|maximum| operands.len() > maximum) {
        return Some(Classification::incomplete());
    }
    Some(if honors_dry_run && parsed.boolean("--dry-run") {
        Classification::control()
    } else {
        Classification::operation(SemanticCode::REGISTRY_PUBLISH)
    })
}

const DOTNET_BOOLEAN: &[&str] = &[
    "-h",
    "--disable-buffering",
    "--force-english-output",
    "--help",
    "--interactive",
    "--no-symbols",
    "--skip-duplicate",
];
const DOTNET_VALUE: &[&str] = &[
    "-k",
    "-s",
    "-t",
    "--api-key",
    "--source",
    "--symbol-api-key",
    "--symbol-source",
    "--timeout",
];

fn dotnet(arguments: &[String]) -> Option<Classification> {
    let parsed = match parsed_or_incomplete(arguments, DOTNET_BOOLEAN, DOTNET_VALUE) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if help_requested(&parsed) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [nuget, command, _] if nuget == "nuget" && command == "push" => {
            Some(Classification::operation(SemanticCode::REGISTRY_PUBLISH))
        }
        [nuget, command, ..] if nuget == "nuget" && command == "delete" => {
            Some(Classification::control())
        }
        [nuget, command, ..] if nuget == "nuget" && command == "push" => {
            Some(Classification::incomplete())
        }
        _ => None,
    }
}

const NUGET_BOOLEAN: &[&str] = &[
    "-disablebuffering",
    "-forceenglishoutput",
    "-help",
    "-h",
    "-noninteractive",
    "-nosymbols",
    "-skipduplicate",
];
const NUGET_VALUE: &[&str] = &[
    "-apikey",
    "-configfile",
    "-source",
    "-symbolapikey",
    "-symbolsource",
    "-timeout",
    "-verbosity",
];

fn nuget(arguments: &[String]) -> Option<Classification> {
    let normalized = arguments
        .iter()
        .map(|argument| {
            if argument.starts_with('-') {
                argument.to_ascii_lowercase()
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>();
    let parsed = match parsed_or_incomplete(&normalized, NUGET_BOOLEAN, NUGET_VALUE) {
        Ok(parsed) => parsed,
        Err(classification) => return Some(classification),
    };
    if parsed.present(&["-help", "-h"]) {
        return Some(Classification::control());
    }
    match parsed.positionals.as_slice() {
        [command, _] | [command, _, _] if command.eq_ignore_ascii_case("push") => {
            Some(Classification::operation(SemanticCode::REGISTRY_PUBLISH))
        }
        [command, ..] if command.eq_ignore_ascii_case("delete") => Some(Classification::control()),
        [command, ..] if command.eq_ignore_ascii_case("push") => Some(Classification::incomplete()),
        _ => None,
    }
}

const NPX_BOOLEAN: &[&str] = &[
    "-h",
    "-q",
    "-y",
    "--help",
    "--ignore-existing",
    "--no-install",
    "--quiet",
    "--yes",
];
const NPX_VALUE: &[&str] = &["-p", "--cache", "--call", "--package", "--userconfig"];
const BUNX_BOOLEAN: &[&str] = &["--bun", "--help", "--no-install", "--silent", "--verbose"];
const BUNX_VALUE: &[&str] = &["-p", "--package"];

fn package_wrapper(
    arguments: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
) -> Option<Classification> {
    let wrapper = match parse_wrapper_command(arguments, boolean_options, value_options) {
        Ok(wrapper) => wrapper,
        Err(()) => return Some(Classification::incomplete()),
    };
    if help_requested(&wrapper.options) {
        return Some(Classification::control());
    }
    let Some(program) = wrapper.program else {
        return Some(Classification::incomplete());
    };
    if !registry_program(program) {
        return None;
    }
    classify_static(program, wrapper.arguments)
}

struct WrapperCommand<'a> {
    options: ParsedOptions,
    program: Option<&'a str>,
    arguments: &'a [String],
}

fn parse_wrapper_command<'a>(
    arguments: &'a [String],
    boolean_options: &[&str],
    value_options: &[&str],
) -> Result<WrapperCommand<'a>, ()> {
    let mut parsed = ParsedOptions::default();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            index += 1;
            break;
        }
        let Some(consumed) = parse_option_at(
            &mut parsed,
            arguments,
            index,
            boolean_options,
            value_options,
            &[],
        )?
        else {
            if argument.is_empty() {
                return Err(());
            }
            break;
        };
        index += consumed;
    }
    Ok(WrapperCommand {
        options: parsed,
        program: arguments.get(index).map(String::as_str),
        arguments: arguments.get(index + 1..).unwrap_or(&[]),
    })
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}
