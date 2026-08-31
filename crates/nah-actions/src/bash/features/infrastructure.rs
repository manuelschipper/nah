//! Classifies fully visible Terraform, OpenTofu, and Pulumi whole-stack destruction.

use nah_parse::Word;

use crate::shell_word::static_word;

pub(crate) struct Classification {
    pub(crate) complete: bool,
    pub(crate) destroys_whole_stack: bool,
}

impl Classification {
    const fn complete(destroys_whole_stack: bool) -> Self {
        Self {
            complete: true,
            destroys_whole_stack,
        }
    }

    const fn incomplete() -> Self {
        Self {
            complete: false,
            destroys_whole_stack: false,
        }
    }
}

pub(crate) fn classify(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Word)],
) -> Option<Classification> {
    match program {
        "terraform" | "tofu" => terraform(arguments, assignments),
        "pulumi" => pulumi(arguments),
        _ => None,
    }
}

fn terraform(arguments: &[Word], assignments: &[(String, Word)]) -> Option<Classification> {
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    let (subcommand, command_index) = match terraform_subcommand(&arguments) {
        TerraformCommand::Relevant(subcommand, index) => (subcommand, index),
        TerraformCommand::Other => return None,
        TerraformCommand::NonExecuting => return Some(Classification::complete(false)),
        TerraformCommand::Incomplete => return Some(Classification::incomplete()),
    };
    let command_variable = match subcommand {
        "apply" => "TF_CLI_ARGS_apply",
        "destroy" => "TF_CLI_ARGS_destroy",
        _ => unreachable!("reviewed Terraform subcommands are exhaustive"),
    };
    let mut command_arguments = Vec::new();
    for name in ["TF_CLI_ARGS", command_variable] {
        let Some((_, value)) = assignments
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == name)
        else {
            continue;
        };
        let Some(value) = static_word(value.raw(), value.substitutions().is_empty()) else {
            return Some(Classification::incomplete());
        };
        let Some(mut words) = terraform_cli_words(&value) else {
            return Some(Classification::incomplete());
        };
        command_arguments.append(&mut words);
    }
    command_arguments.extend_from_slice(&arguments[command_index + 1..]);
    Some(terraform_destroy(subcommand, &command_arguments))
}

enum TerraformCommand<'a> {
    Relevant(&'a str, usize),
    Other,
    NonExecuting,
    Incomplete,
}

fn terraform_subcommand(arguments: &[String]) -> TerraformCommand<'_> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if help_or_version(argument) {
            return TerraformCommand::NonExecuting;
        }
        if let Some(consumed) = value_option(arguments, index, &["-chdir"]) {
            let Ok(consumed) = consumed else {
                return TerraformCommand::Incomplete;
            };
            index += consumed;
            continue;
        }
        if argument.starts_with('-') {
            return TerraformCommand::Incomplete;
        }
        return match argument.as_str() {
            "apply" | "destroy" => TerraformCommand::Relevant(argument, index),
            "version" => TerraformCommand::NonExecuting,
            _ => TerraformCommand::Other,
        };
    }
    TerraformCommand::Incomplete
}

fn terraform_destroy(subcommand: &str, arguments: &[String]) -> Classification {
    const SELECTORS: &[&str] = &[
        "-exclude",
        "-exclude-file",
        "-invoke",
        "-replace",
        "-target",
        "-target-file",
    ];
    const VALUE_OPTIONS: &[&str] = &[
        "-backup",
        "-deprecation",
        "-lock-timeout",
        "-parallelism",
        "-state",
        "-state-out",
        "-var",
        "-var-file",
    ];
    const BOOLEAN_OPTIONS: &[&str] = &[
        "-auto-approve",
        "-compact-warnings",
        "-input",
        "-json",
        "-lock",
        "-no-color",
        "-refresh",
        "-show-sensitive",
    ];

    let mut index = 0;
    let mut destroy = subcommand == "destroy";
    while let Some(argument) = arguments.get(index) {
        if help_or_version(argument) {
            return Classification::complete(false);
        }
        if option_name(argument, SELECTORS).is_some() {
            return match value_option(arguments, index, SELECTORS) {
                Some(Ok(_)) => Classification::complete(false),
                Some(Err(())) | None => Classification::incomplete(),
            };
        }
        if let Some(value) = boolean_option(argument, "-destroy") {
            if subcommand != "apply" {
                return Classification::incomplete();
            }
            let Some(value) = value else {
                return Classification::incomplete();
            };
            destroy = value;
            index += 1;
            continue;
        }
        if let Some(value) = boolean_option(argument, "-refresh-only") {
            let Some(value) = value else {
                return Classification::incomplete();
            };
            if value {
                return Classification::complete(false);
            }
            index += 1;
            continue;
        }
        if let Some(value) = BOOLEAN_OPTIONS
            .iter()
            .find_map(|name| boolean_option(argument, name))
        {
            if value.is_none() {
                return Classification::incomplete();
            }
            index += 1;
            continue;
        }
        if let Some(consumed) = value_option(arguments, index, VALUE_OPTIONS) {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            index += consumed;
            continue;
        }
        if argument.starts_with('-') || argument == "--" {
            return Classification::incomplete();
        }
        // `apply` positional operands are opaque saved plans. `destroy` has no operands.
        return Classification::complete(false);
    }
    Classification::complete(destroy)
}

fn pulumi(arguments: &[Word]) -> Option<Classification> {
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    let (subcommand, command_index) = match pulumi_subcommand(&arguments) {
        Ok(Some(subcommand)) => subcommand,
        Ok(None) => return None,
        Err(()) => return Some(Classification::incomplete()),
    };
    Some(pulumi_destroy(subcommand, &arguments[command_index + 1..]))
}

fn pulumi_subcommand(arguments: &[String]) -> Result<Option<(&str, usize)>, ()> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if pulumi_help_or_version(argument) {
            return Ok(None);
        }
        if let Some(consumed) = pulumi_value_option(arguments, index, true) {
            index += consumed?;
            continue;
        }
        if let Some(valid) = pulumi_boolean_option(argument, true) {
            if !valid {
                return Err(());
            }
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return Err(());
        }
        return match argument.as_str() {
            "destroy" | "down" | "dn" => Ok(Some((argument, index))),
            "version" => Ok(None),
            _ => Ok(None),
        };
    }
    Err(())
}

fn pulumi_destroy(_subcommand: &str, arguments: &[String]) -> Classification {
    const SELECTORS: &[&str] = &["--exclude", "--target", "-t", "-x"];
    const SELECTION_FLAGS: &[&str] = &[
        "--exclude-dependents",
        "--exclude-protected",
        "--preview-only",
        "--target-dependents",
    ];

    let mut index = 0;
    let mut operand = false;
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && pulumi_help_or_version(argument) {
            return Classification::complete(false);
        }
        if options && let Some(valid) = pulumi_selector(arguments, index, SELECTORS) {
            return if valid {
                Classification::complete(false)
            } else {
                Classification::incomplete()
            };
        }
        if options
            && SELECTION_FLAGS.iter().any(|flag| {
                argument == flag
                    || argument
                        .strip_prefix(flag)
                        .is_some_and(|tail| tail.starts_with('='))
            })
        {
            return Classification::complete(false);
        }
        if options && let Some(consumed) = pulumi_value_option(arguments, index, false) {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            index += consumed;
            continue;
        }
        if options && pulumi_optional_value(argument) {
            index += 1;
            continue;
        }
        if options && let Some(valid) = pulumi_boolean_option(argument, false) {
            if !valid {
                return Classification::incomplete();
            }
            index += 1;
            continue;
        }
        if options && argument.starts_with('-') {
            return Classification::incomplete();
        }
        if operand {
            return Classification::incomplete();
        }
        operand = true;
        index += 1;
    }
    Classification::complete(true)
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}

fn help_or_version(argument: &str) -> bool {
    matches!(
        argument,
        "-h" | "--help" | "-help" | "-v" | "--version" | "-version"
    )
}

fn pulumi_help_or_version(argument: &str) -> bool {
    matches!(
        argument,
        "-h" | "--help" | "-help" | "--version" | "-version"
    )
}

fn option_name<'a>(argument: &str, names: &'a [&str]) -> Option<&'a str> {
    names.iter().copied().find(|name| {
        argument == *name
            || argument
                .strip_prefix(*name)
                .is_some_and(|tail| tail.starts_with('='))
    })
}

fn value_option(arguments: &[String], index: usize, names: &[&str]) -> Option<Result<usize, ()>> {
    let argument = &arguments[index];
    let name = option_name(argument, names)?;
    if argument == name {
        return Some(
            arguments
                .get(index + 1)
                .filter(|value| !value.is_empty())
                .map(|_| 2)
                .ok_or(()),
        );
    }
    Some(
        argument
            .strip_prefix(name)
            .and_then(|tail| tail.strip_prefix('='))
            .filter(|value| !value.is_empty())
            .map(|_| 1)
            .ok_or(()),
    )
}

fn boolean_option(argument: &str, name: &str) -> Option<Option<bool>> {
    if argument == name {
        return Some(Some(true));
    }
    argument
        .strip_prefix(name)
        .and_then(|tail| tail.strip_prefix('='))
        .map(parse_go_bool)
}

fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn pulumi_selector(arguments: &[String], index: usize, names: &[&str]) -> Option<bool> {
    let argument = &arguments[index];
    if let Some(result) = value_option(arguments, index, names) {
        return Some(result.is_ok());
    }
    ["-t", "-x"]
        .iter()
        .any(|name| argument.starts_with(name) && argument.len() > name.len())
        .then_some(true)
}

fn pulumi_value_option(
    arguments: &[String],
    index: usize,
    global_only: bool,
) -> Option<Result<usize, ()>> {
    const GLOBAL: &[&str] = &[
        "--color",
        "--cwd",
        "--memprofilerate",
        "--profiling",
        "--tracing",
        "--verbose",
        "-C",
        "-v",
    ];
    const DESTROY: &[&str] = &[
        "--config",
        "--config-file",
        "--message",
        "--parallel",
        "--remote-agent-pool-id",
        "--remote-env",
        "--stack",
        "-c",
        "-m",
        "-p",
        "-s",
    ];
    if let Some(result) = value_option(arguments, index, GLOBAL) {
        return Some(result);
    }
    if global_only {
        None
    } else {
        value_option(arguments, index, DESTROY)
    }
}

fn pulumi_optional_value(argument: &str) -> bool {
    ["--refresh", "--suppress-permalink", "-r"]
        .iter()
        .any(|name| {
            argument == *name
                || argument
                    .strip_prefix(*name)
                    .and_then(|tail| tail.strip_prefix('='))
                    .is_some_and(|value| !value.is_empty())
        })
}

fn pulumi_boolean_option(argument: &str, global_only: bool) -> Option<bool> {
    const GLOBAL: &[&str] = &[
        "--disable-integrity-checking",
        "--emoji",
        "--fully-qualify-stack-names",
        "--logflow",
        "--logtostderr",
        "--non-interactive",
        "-Q",
        "-e",
    ];
    const DESTROY: &[&str] = &[
        "--config-path",
        "--continue-on-error",
        "--debug",
        "--diff",
        "--json",
        "--neo",
        "--remote",
        "--remote-skip-install-dependencies",
        "--remove",
        "--run-program",
        "--show-config",
        "--show-full-output",
        "--show-replacement-steps",
        "--show-sames",
        "--skip-preview",
        "--suppress-outputs",
        "--suppress-progress",
        "--suppress-stream-logs",
        "--yes",
        "-d",
        "-f",
        "-j",
        "-y",
    ];
    let names = if global_only {
        GLOBAL
    } else {
        &[GLOBAL, DESTROY].concat()
    };
    for name in names {
        if let Some(value) = boolean_option(argument, name) {
            return Some(value.is_some());
        }
    }
    if argument.starts_with('-') && !argument.starts_with("--") {
        let flags = if global_only { "eQ" } else { "eQdfjy" };
        return Some(argument[1..].chars().all(|flag| flags.contains(flag)));
    }
    None
}

/// Terraform parses `TF_CLI_ARGS*` as shell-like words after the subcommand.
/// This accepts only the quote and escape forms whose exact argv is visible.
fn terraform_cli_words(value: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut quote = Quote::None;
    let mut escaped = false;
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    for character in value.chars() {
        if escaped {
            word.push(character);
            started = true;
            escaped = false;
            continue;
        }
        match (quote, character) {
            (Quote::None, character) if character.is_ascii_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (Quote::None, '\\') | (Quote::Double, '\\') => escaped = true,
            (Quote::None, '\'') => {
                quote = Quote::Single;
                started = true;
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                started = true;
            }
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::None,
            (_, character) => {
                word.push(character);
                started = true;
            }
        }
    }
    if escaped || quote != Quote::None {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terraform_environment_words_preserve_exact_argv() {
        assert_eq!(
            terraform_cli_words(r#"-target='module.web["blue"]' -lock=false"#),
            Some(vec![
                r#"-target=module.web["blue"]"#.into(),
                "-lock=false".into()
            ])
        );
        assert_eq!(
            terraform_cli_words("-tar\"\"get resource"),
            Some(vec!["-target".into(), "resource".into()])
        );
        assert_eq!(terraform_cli_words("'-target"), None);
    }
}
