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
    path_overridden: bool,
    qualified_program: bool,
) -> Option<Classification> {
    if matches!(program, "terraform" | "tofu" | "pulumi")
        && !qualified_program
        && (path_overridden || assignments.iter().any(|(name, _)| name == "PATH"))
    {
        return Some(Classification::incomplete());
    }
    match program {
        "terraform" | "tofu" => terraform(program, arguments, assignments),
        "pulumi" => pulumi(arguments),
        _ => None,
    }
}

fn terraform(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Word)],
) -> Option<Classification> {
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    if arguments.iter().any(|argument| terraform_version(argument)) {
        return Some(Classification::complete(false));
    }
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
    for name in [command_variable, "TF_CLI_ARGS"] {
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
    Some(terraform_destroy(program, subcommand, &command_arguments))
}

enum TerraformCommand<'a> {
    Relevant(&'a str, usize),
    Other,
    NonExecuting,
    Incomplete,
}

fn terraform_subcommand(arguments: &[String]) -> TerraformCommand<'_> {
    let mut index = 0;
    let mut chdir = false;
    while let Some(argument) = arguments.get(index) {
        if help_or_version(argument) {
            return TerraformCommand::NonExecuting;
        }
        if argument == "-chdir" || argument == "-chdir=" {
            return TerraformCommand::Incomplete;
        }
        if let Some(directory) = argument.strip_prefix("-chdir=") {
            if directory.is_empty() || chdir {
                return TerraformCommand::Incomplete;
            }
            chdir = true;
            index += 1;
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

fn terraform_destroy(program: &str, subcommand: &str, arguments: &[String]) -> Classification {
    const SELECTORS: &[&str] = &[
        "-exclude",
        "-exclude-file",
        "-invoke",
        "-replace",
        "-target",
        "-target-file",
    ];
    const VALUE_OPTIONS: &[&str] = &["-backup", "-state", "-state-out", "-var", "-var-file"];
    const BOOLEAN_OPTIONS: &[&str] = &[
        "-auto-approve",
        "-compact-warnings",
        "-input",
        "-json",
        "-lock",
        "-no-color",
        "-refresh",
    ];

    let mut index = 0;
    let mut destroy = subcommand == "destroy";
    let mut options = true;
    let mut refresh_only = false;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if !options {
            return Classification::complete(false);
        }
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
            refresh_only = value;
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
        if let Some(consumed) = integer_value_option::<i64>(arguments, index, &["-parallelism"]) {
            let Ok((consumed, parallelism)) = consumed else {
                return Classification::incomplete();
            };
            if parallelism <= 0 {
                return Classification::incomplete();
            }
            index += consumed;
            continue;
        }
        if let Some(consumed) = duration_value_option(arguments, index, &["-lock-timeout"]) {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            index += consumed;
            continue;
        }
        if program == "tofu"
            && let Some(consumed) = value_option(arguments, index, &["-deprecation"])
        {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            index += consumed;
            continue;
        }
        if program == "tofu"
            && let Some(value) = boolean_option(argument, "-show-sensitive")
        {
            if value.is_none() {
                return Classification::incomplete();
            }
            index += 1;
            continue;
        }
        if program == "tofu"
            && let Some(value) = ["-concise", "-consolidate-errors"]
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
        if argument.starts_with('-') {
            return Classification::incomplete();
        }
        // `apply` positional operands are opaque saved plans. `destroy` has no operands.
        return Classification::complete(false);
    }
    Classification::complete(destroy && !refresh_only)
}

fn pulumi(arguments: &[Word]) -> Option<Classification> {
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    let (subcommand, command_index, help, version) = match pulumi_subcommand(&arguments) {
        Ok(Some(subcommand)) => subcommand,
        Ok(None) => return None,
        Err(()) => return Some(Classification::incomplete()),
    };
    Some(pulumi_destroy(
        subcommand,
        &arguments[command_index + 1..],
        help,
        version,
    ))
}

fn pulumi_subcommand(arguments: &[String]) -> Result<Option<(&str, usize, bool, bool)>, ()> {
    let mut index = 0;
    let mut help = false;
    let mut version = false;
    while let Some(argument) = arguments.get(index) {
        if pulumi_nonexecuting_option(argument) {
            return Ok(None);
        }
        if let Some(value) = pulumi_help_option(argument) {
            help = value.ok_or(())?;
            index += 1;
            continue;
        }
        if let Some(value) = pulumi_version_option(argument) {
            version = value.ok_or(())?;
            index += 1;
            continue;
        }
        if let Some(consumed) = pulumi_short_option_cluster(arguments, index, true) {
            index += consumed?;
            continue;
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
            "destroy" | "down" | "dn" => Ok(Some((argument, index, help, version))),
            "version" => Ok(None),
            _ => Ok(None),
        };
    }
    Err(())
}

fn pulumi_destroy(
    _subcommand: &str,
    arguments: &[String],
    mut help: bool,
    mut version: bool,
) -> Classification {
    const SELECTORS: &[&str] = &["--exclude", "--target", "-t", "-x"];
    const SELECTION_FLAGS: &[&str] = &["--exclude-protected", "--preview-only"];

    let mut index = 0;
    let mut options = true;
    let mut selection_flags = [false; SELECTION_FLAGS.len()];
    let mut exclude_protected_changed = false;
    let mut ignore_protect_changed = false;
    let mut json_changed = false;
    let mut output_changed = false;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && let Some(value) = pulumi_version_option(argument) {
            let Some(value) = value else {
                return Classification::incomplete();
            };
            version = value;
            index += 1;
            continue;
        }
        if options && pulumi_nonexecuting_option(argument) {
            return Classification::complete(false);
        }
        if options && let Some(value) = pulumi_help_option(argument) {
            let Some(value) = value else {
                return Classification::incomplete();
            };
            help = value;
            index += 1;
            continue;
        }
        if options && let Some(valid) = pulumi_selector(arguments, index, SELECTORS) {
            return if valid {
                Classification::complete(false)
            } else {
                Classification::incomplete()
            };
        }
        if options
            && let Some((flag_index, value)) =
                SELECTION_FLAGS
                    .iter()
                    .enumerate()
                    .find_map(|(flag_index, flag)| {
                        boolean_option(argument, flag).map(|value| (flag_index, value))
                    })
        {
            let Some(value) = value else {
                return Classification::incomplete();
            };
            if flag_index == 0 {
                exclude_protected_changed = true;
                if ignore_protect_changed {
                    return Classification::incomplete();
                }
            }
            selection_flags[flag_index] = value;
            index += 1;
            continue;
        }
        if options && let Some(value) = boolean_option(argument, "--ignore-protect") {
            if value.is_none() {
                return Classification::incomplete();
            }
            ignore_protect_changed = true;
            if exclude_protected_changed {
                return Classification::incomplete();
            }
            index += 1;
            continue;
        }
        if options
            && let Some(value) = ["--json", "-j"]
                .iter()
                .find_map(|name| boolean_option(argument, name))
        {
            if value.is_none() {
                return Classification::incomplete();
            }
            json_changed = true;
            if output_changed {
                return Classification::incomplete();
            }
            index += 1;
            continue;
        }
        if options && let Some(consumed) = pulumi_output_option(arguments, index) {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            output_changed = true;
            if json_changed {
                return Classification::incomplete();
            }
            index += consumed;
            continue;
        }
        if options && let Some(consumed) = pulumi_short_option_cluster(arguments, index, false) {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            index += consumed;
            continue;
        }
        if options && let Some(consumed) = pulumi_value_option(arguments, index, false) {
            let Ok(consumed) = consumed else {
                return Classification::incomplete();
            };
            index += consumed;
            continue;
        }
        if options && let Some(valid) = pulumi_optional_value(argument) {
            if !valid {
                return Classification::incomplete();
            }
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
        return Classification::incomplete();
    }
    Classification::complete(
        !help && !version && !selection_flags.into_iter().any(|selected| selected),
    )
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

fn terraform_version(argument: &str) -> bool {
    matches!(argument, "-v" | "--version" | "-version")
}

fn pulumi_nonexecuting_option(argument: &str) -> bool {
    matches!(argument, "-help" | "-version")
}

fn pulumi_help_option(argument: &str) -> Option<Option<bool>> {
    ["--help", "-h"]
        .iter()
        .find_map(|name| boolean_option(argument, name))
}

fn pulumi_version_option(argument: &str) -> Option<Option<bool>> {
    boolean_option(argument, "--version")
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

fn integer_value_option<T: std::str::FromStr>(
    arguments: &[String],
    index: usize,
    names: &[&str],
) -> Option<Result<(usize, T), ()>> {
    let consumed = match value_option(arguments, index, names)? {
        Ok(consumed) => consumed,
        Err(()) => return Some(Err(())),
    };
    let value = if consumed == 2 {
        &arguments[index + 1]
    } else {
        arguments[index].split_once('=').expect("joined option").1
    };
    Some(
        value
            .parse::<T>()
            .map(|value| (consumed, value))
            .map_err(|_| ()),
    )
}

fn duration_value_option(
    arguments: &[String],
    index: usize,
    names: &[&str],
) -> Option<Result<usize, ()>> {
    let consumed = match value_option(arguments, index, names)? {
        Ok(consumed) => consumed,
        Err(()) => return Some(Err(())),
    };
    let value = if consumed == 2 {
        &arguments[index + 1]
    } else {
        arguments[index].split_once('=').expect("joined option").1
    };
    Some(valid_go_duration(value).then_some(consumed).ok_or(()))
}

fn valid_go_duration(value: &str) -> bool {
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    if value == "0" {
        return true;
    }
    if value.is_empty() {
        return false;
    }

    let mut rest = value;
    let mut seconds = 0.0;
    while !rest.is_empty() {
        let number_end = rest
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(rest.len());
        let number = &rest[..number_end];
        if number.is_empty() || number.matches('.').count() > 1 || number.parse::<f64>().is_err() {
            return false;
        }
        rest = &rest[number_end..];
        let Some((unit, unit_seconds)) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("μs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3_600.0),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit)) else {
            return false;
        };
        let component = number.parse::<f64>().expect("validated duration number");
        seconds += component * unit_seconds;
        if !seconds.is_finite() || seconds >= 9_223_372_000.0 {
            return false;
        }
        rest = &rest[unit.len()..];
    }
    true
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
    const GLOBAL: &[&str] = &["--cwd", "--profiling", "--tracing", "-C"];
    const DESTROY: &[&str] = &[
        "--config",
        "--config-file",
        "--message",
        "--stack",
        "-c",
        "-m",
        "-s",
    ];
    if let Some(result) = value_option(arguments, index, &["--color"]) {
        return Some(result.and_then(|consumed| {
            let value = if consumed == 2 {
                &arguments[index + 1]
            } else {
                arguments[index].split_once('=').expect("joined option").1
            };
            matches!(value, "always" | "never" | "raw" | "auto")
                .then_some(consumed)
                .ok_or(())
        }));
    }
    if let Some(result) = pulumi_raw_value_option(arguments, index, GLOBAL, &["-C"]) {
        return Some(result.map(|(consumed, _)| consumed));
    }
    if let Some(result) = pulumi_raw_value_option(
        arguments,
        index,
        &["--memprofilerate", "--verbose", "-v"],
        &["-v"],
    ) {
        return Some(
            result
                .and_then(|(consumed, value)| parse_pulumi_i32(value).map(|_| consumed).ok_or(())),
        );
    }
    if global_only {
        None
    } else if let Some(result) =
        pulumi_raw_value_option(arguments, index, &["--parallel", "-p"], &["-p"])
    {
        Some(
            result
                .and_then(|(consumed, value)| parse_pulumi_i32(value).map(|_| consumed).ok_or(())),
        )
    } else {
        pulumi_raw_value_option(arguments, index, DESTROY, &["-c", "-m", "-s"])
            .map(|result| result.map(|(consumed, _)| consumed))
    }
}

fn parse_pulumi_i32(value: &str) -> Option<i32> {
    if !valid_go_integer_underscores(value) {
        return None;
    }
    let (negative, value) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if value.is_empty() {
        return None;
    }
    let (radix, digits) = if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        (2, digits)
    } else if let Some(digits) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        (8, digits)
    } else if value.len() > 1 && value.starts_with('0') {
        (8, &value[1..])
    } else {
        (10, value)
    };
    if digits.is_empty() {
        return None;
    }
    let digits = digits.replace('_', "");
    let magnitude = i64::from_str_radix(&digits, radix).ok()?;
    let signed = if negative { -magnitude } else { magnitude };
    i32::try_from(signed).ok()
}

fn valid_go_integer_underscores(value: &str) -> bool {
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let prefix_len = usize::from(
        value.len() >= 2
            && value.starts_with('0')
            && matches!(value.as_bytes()[1], b'b' | b'B' | b'o' | b'O' | b'x' | b'X'),
    ) * 2;
    let mut digit_before = prefix_len > 0;
    for character in value[prefix_len..].chars() {
        if character == '_' {
            if !digit_before {
                return false;
            }
            digit_before = false;
        } else {
            digit_before = true;
        }
    }
    digit_before
}

fn pulumi_short_option_cluster(
    arguments: &[String],
    index: usize,
    global_only: bool,
) -> Option<Result<usize, ()>> {
    let argument = &arguments[index];
    let cluster = argument.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() < 2 {
        return None;
    }
    let boolean_flags = if global_only { "eQ" } else { "eQdfjy" };
    if !boolean_flags.contains(cluster.chars().next().expect("nonempty cluster")) {
        return None;
    }
    let mut options = cluster.char_indices().peekable();
    while let Some((_, option)) = options.next() {
        if boolean_flags.contains(option) {
            let value_start = options.peek().map_or(cluster.len(), |(index, _)| *index);
            if let Some(value) = cluster[value_start..].strip_prefix('=') {
                return Some(parse_go_bool(value).map(|_| 1).ok_or(()));
            }
            continue;
        }
        let value_start = options.peek().map_or(cluster.len(), |(index, _)| *index);
        let attached = cluster[value_start..]
            .strip_prefix('=')
            .unwrap_or(&cluster[value_start..]);
        if option == 'r' && !global_only && attached.is_empty() {
            return Some(Ok(1));
        }
        let (consumed, value) = if attached.is_empty() {
            (2, arguments.get(index + 1)?.as_str())
        } else {
            (1, attached)
        };
        let valid = match option {
            'C' | 'c' | 'm' | 's' if !global_only || option == 'C' => !value.is_empty(),
            'v' => parse_pulumi_i32(value).is_some(),
            'p' if !global_only => parse_pulumi_i32(value).is_some(),
            'r' if !global_only => parse_go_bool(value).is_some(),
            _ => false,
        };
        return Some(valid.then_some(consumed).ok_or(()));
    }
    Some(Ok(1))
}

fn pulumi_output_option(arguments: &[String], index: usize) -> Option<Result<usize, ()>> {
    value_option(arguments, index, &["--output"]).map(|result| {
        result.and_then(|consumed| {
            let value = if consumed == 2 {
                &arguments[index + 1]
            } else {
                arguments[index].split_once('=').expect("joined option").1
            };
            matches!(value, "default" | "json")
                .then_some(consumed)
                .ok_or(())
        })
    })
}

fn pulumi_raw_value_option<'a>(
    arguments: &'a [String],
    index: usize,
    names: &[&str],
    shorthands: &[&str],
) -> Option<Result<(usize, &'a str), ()>> {
    if let Some(result) = value_option(arguments, index, names) {
        return Some(result.map(|consumed| {
            let value = if consumed == 2 {
                arguments[index + 1].as_str()
            } else {
                arguments[index].split_once('=').expect("joined option").1
            };
            (consumed, value)
        }));
    }
    let argument = &arguments[index];
    shorthands.iter().find_map(|name| {
        argument.strip_prefix(name).map(|value| {
            let value = value.strip_prefix('=').unwrap_or(value);
            (!value.is_empty()).then_some((1, value)).ok_or(())
        })
    })
}

fn pulumi_optional_value(argument: &str) -> Option<bool> {
    if argument == "--refresh" {
        return Some(true);
    }
    if let Some(value) = argument.strip_prefix("--refresh=") {
        return Some(parse_go_bool(value).is_some());
    }
    if argument == "-r" {
        return Some(true);
    }
    if let Some(value) = argument.strip_prefix("-r") {
        return Some(parse_go_bool(value.strip_prefix('=').unwrap_or(value)).is_some());
    }
    if argument == "--suppress-permalink" {
        return Some(true);
    }
    argument
        .strip_prefix("--suppress-permalink=")
        .map(|value| !value.is_empty())
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
        "--neo",
        "--remove",
        "--run-program",
        "--show-config",
        "--show-full-output",
        "--show-replacement-steps",
        "--show-sames",
        "--skip-config-validation",
        "--skip-plugin-pre-install",
        "--skip-preview",
        "--suppress-outputs",
        "--suppress-progress",
        "--suppress-stream-logs",
        "--target-dependents",
        "--urns",
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
    None
}

/// Terraform parses `TF_CLI_ARGS*` as shell-like words after the subcommand.
/// This accepts only shell-word forms whose exact argv is visible.
fn terraform_cli_words(value: &str) -> Option<Vec<String>> {
    let mut escaped = false;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut back_quoted = false;
    let mut dollar_quoted = false;
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
        if character == '\\' {
            if single_quoted {
                word.push(character);
                started = true;
            } else {
                escaped = true;
            }
            continue;
        }
        if character.is_ascii_whitespace() {
            if single_quoted || double_quoted || back_quoted || dollar_quoted {
                word.push(character);
                started = true;
            } else if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
            continue;
        }
        match character {
            '`' if !single_quoted && !double_quoted && !dollar_quoted => {
                back_quoted = !back_quoted;
                word.push(character);
                started = true;
            }
            '(' if !single_quoted && !double_quoted && !back_quoted => {
                if dollar_quoted || !word.ends_with('$') {
                    return None;
                }
                dollar_quoted = true;
                word.push(character);
                started = true;
            }
            ')' if !single_quoted && !double_quoted && !back_quoted => {
                if !dollar_quoted {
                    return None;
                }
                dollar_quoted = false;
                word.push(character);
                started = true;
            }
            '"' if !single_quoted && !dollar_quoted => {
                double_quoted = !double_quoted;
                started = true;
            }
            '\'' if !double_quoted && !dollar_quoted => {
                single_quoted = !single_quoted;
                started = true;
            }
            ';' | '&' | '|' | '<' | '>'
                if !single_quoted && !double_quoted && !back_quoted && !dollar_quoted =>
            {
                break;
            }
            _ => {
                word.push(character);
                started = true;
            }
        }
    }
    if escaped || single_quoted || double_quoted || back_quoted || dollar_quoted {
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
        assert_eq!(
            terraform_cli_words("-backup `foo bar`"),
            Some(vec!["-backup".into(), "`foo bar`".into()])
        );
        assert_eq!(terraform_cli_words("-var foo(bar)"), None);
    }
}
