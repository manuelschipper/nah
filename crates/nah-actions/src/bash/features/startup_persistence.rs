//! Recognizes reviewed static commands that persist startup configuration or
//! stop running services.

use nah_parse::Word;
use nah_proto::action::SemanticCode;
use nah_proto::ctx::Platform;

use crate::shell_word::{has_unmodeled_expansion, static_word};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrontabMutation {
    InstallStdin,
    InstallFile,
    Remove,
}

pub(crate) fn operation(
    program: &str,
    arguments: &[Word],
    platform: Platform,
) -> Option<SemanticCode> {
    match (platform, program) {
        (Platform::Linux, "systemctl") => systemctl_operation(arguments),
        (Platform::Linux, "service") => service_stop_operation(arguments),
        (Platform::Macos, "launchctl") => launchctl_operation(arguments),
        (Platform::Linux | Platform::Macos, "crontab") => crontab_mutation(arguments)
            .is_some()
            .then_some(SemanticCode::STARTUP_MANAGEMENT),
        _ => None,
    }
}

fn exact_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| {
            let raw = argument.raw();
            (!has_unmodeled_expansion(raw)
                || raw.starts_with('~') && !has_unmodeled_expansion(&raw[1..]))
            .then(|| static_word(argument.raw(), argument.substitutions().is_empty()))
            .flatten()
        })
        .collect()
}

fn systemctl_operation(arguments: &[Word]) -> Option<SemanticCode> {
    let arguments = exact_arguments(arguments)?;
    let mut command = None;
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut stdin = false;
    let mut edit_option = false;
    let mut preset_option = false;
    let mut now = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if after_options {
            if command.is_none() {
                command = Some(argument);
            } else {
                operands.push(argument);
            }
            index += 1;
            continue;
        }
        if argument == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if matches!(
            argument,
            "--help" | "--version" | "-h" | "--runtime" | "--dry-run"
        ) || argument == "--root"
            || argument.starts_with("--root=")
            || argument == "--image"
            || argument.starts_with("--image=")
        {
            return None;
        }
        if matches!(
            argument,
            "--system"
                | "--user"
                | "--global"
                | "--force"
                | "--no-reload"
                | "--no-block"
                | "--quiet"
                | "-q"
                | "--no-pager"
                | "--no-ask-password"
        ) {
            index += 1;
            continue;
        }
        if argument == "--now" {
            now = true;
            index += 1;
            continue;
        }
        if argument == "--stdin" {
            stdin = true;
            edit_option = true;
            index += 1;
            continue;
        }
        if argument == "--full" {
            edit_option = true;
            index += 1;
            continue;
        }
        if argument == "--drop-in" {
            index += 1;
            if arguments
                .get(index)
                .is_none_or(|value| value.is_empty() || value.starts_with('-'))
            {
                return None;
            }
            edit_option = true;
            index += 1;
            continue;
        }
        if argument
            .strip_prefix("--drop-in=")
            .is_some_and(|value| !value.is_empty())
        {
            edit_option = true;
            index += 1;
            continue;
        }
        if argument == "--preset-mode" {
            index += 1;
            if arguments
                .get(index)
                .is_none_or(|value| value.is_empty() || value.starts_with('-'))
            {
                return None;
            }
            preset_option = true;
            index += 1;
            continue;
        }
        if argument
            .strip_prefix("--preset-mode=")
            .is_some_and(|value| !value.is_empty())
        {
            preset_option = true;
            index += 1;
            continue;
        }
        if matches!(argument, "--host" | "--machine" | "-H" | "-M") {
            index += 1;
            if arguments
                .get(index)
                .is_none_or(|value| value.is_empty() || value.starts_with('-'))
            {
                return None;
            }
            index += 1;
            continue;
        }
        if ["--host=", "--machine=", "-H", "-M"].iter().any(|prefix| {
            argument
                .strip_prefix(prefix)
                .is_some_and(|value| !value.is_empty())
        }) {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        if command.is_none() {
            command = Some(argument);
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    if operands.iter().any(|operand| operand.is_empty()) {
        return None;
    }
    let command = command?;
    if edit_option && command != "edit"
        || preset_option && !matches!(command, "preset" | "preset-all")
        || now && !matches!(command, "enable" | "disable" | "reenable" | "mask")
    {
        return None;
    }
    match command {
        "enable" | "disable" | "reenable" | "preset" | "mask" | "unmask" | "link" | "revert" => {
            (!operands.is_empty()).then_some(SemanticCode::STARTUP_MANAGEMENT)
        }
        "preset-all" => operands
            .is_empty()
            .then_some(SemanticCode::STARTUP_MANAGEMENT),
        "add-wants" | "add-requires" => {
            (operands.len() >= 2).then_some(SemanticCode::STARTUP_MANAGEMENT)
        }
        "set-default" => (operands.len() == 1).then_some(SemanticCode::STARTUP_MANAGEMENT),
        "edit" => (stdin && !operands.is_empty()).then_some(SemanticCode::STARTUP_MANAGEMENT),
        "stop" | "kill" | "isolate" => (!operands.is_empty()).then_some(SemanticCode::SERVICE_STOP),
        _ => None,
    }
}

fn service_stop_operation(arguments: &[Word]) -> Option<SemanticCode> {
    let arguments = exact_arguments(arguments)?;
    match arguments.as_slice() {
        [name, command] if !name.is_empty() && !name.starts_with('-') && command == "stop" => {
            Some(SemanticCode::SERVICE_STOP)
        }
        _ => None,
    }
}

fn launchctl_operation(arguments: &[Word]) -> Option<SemanticCode> {
    let arguments = exact_arguments(arguments)?;
    let (command, arguments) = arguments.split_first()?;
    match command.as_str() {
        "enable" | "disable" => matches!(arguments, [target] if service_target(target))
            .then_some(SemanticCode::STARTUP_MANAGEMENT),
        "load" | "unload" => {
            launchctl_legacy_mutation(arguments).then_some(SemanticCode::STARTUP_MANAGEMENT)
        }
        "stop" => matches!(arguments, [label] if !label.is_empty() && !label.starts_with('-'))
            .then_some(SemanticCode::SERVICE_STOP),
        "bootout" => matches!(arguments, [target] if service_target(target))
            .then_some(SemanticCode::SERVICE_STOP),
        _ => None,
    }
}

fn service_target(target: &str) -> bool {
    let parts = target.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["system", service] => !service.is_empty(),
        [domain, identifier, service]
            if matches!(*domain, "user" | "login" | "gui" | "session" | "pid") =>
        {
            !identifier.is_empty() && !service.is_empty()
        }
        _ => false,
    }
}

fn launchctl_legacy_mutation(arguments: &[String]) -> bool {
    let mut write = false;
    let mut paths = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if after_options {
            paths.push(argument);
            index += 1;
            continue;
        }
        if argument == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if !argument.starts_with('-') {
            paths.push(argument);
            index += 1;
            continue;
        }
        let flags = &argument[1..];
        if flags.is_empty() {
            return false;
        }
        let mut flags = flags.char_indices().peekable();
        while let Some((_, flag)) = flags.next() {
            match flag {
                'w' => write = true,
                'F' => {}
                'S' | 'D' => {
                    let value = if let Some((next, _)) = flags.peek() {
                        &argument[1 + *next..]
                    } else {
                        index += 1;
                        arguments.get(index).map(String::as_str).unwrap_or_default()
                    };
                    if value.is_empty() {
                        return false;
                    }
                    break;
                }
                _ => return false,
            }
        }
        index += 1;
    }
    write && !paths.is_empty() && paths.iter().all(|path| !path.is_empty())
}

pub(crate) fn crontab_mutation(arguments: &[Word]) -> Option<CrontabMutation> {
    let arguments = exact_arguments(arguments)?;
    let mut user = false;
    let mut remove = false;
    let mut prompt = false;
    let mut files = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "-" {
            files.push(argument);
            index += 1;
            continue;
        }
        if !argument.starts_with('-') {
            files.push(argument);
            index += 1;
            continue;
        }
        if matches!(
            argument,
            "--help" | "--version" | "-h" | "-V" | "-l" | "-e" | "-T"
        ) {
            return None;
        }
        let flags = argument.strip_prefix('-')?;
        if flags.is_empty() {
            return None;
        }
        let mut flags = flags.char_indices().peekable();
        while let Some((_, flag)) = flags.next() {
            match flag {
                'r' => remove = true,
                'i' => prompt = true,
                'u' if !user => {
                    let value = if let Some((offset, _)) = flags.peek() {
                        &argument[1 + *offset..]
                    } else {
                        index += 1;
                        arguments.get(index).map(String::as_str).unwrap_or_default()
                    };
                    if value.is_empty() || value.starts_with('-') {
                        return None;
                    }
                    user = true;
                    break;
                }
                _ => return None,
            }
        }
        index += 1;
    }
    if remove {
        return (files.is_empty()).then_some(CrontabMutation::Remove);
    }
    if prompt || files.len() != 1 || files[0].is_empty() {
        return None;
    }
    Some(if files[0] == "-" {
        CrontabMutation::InstallStdin
    } else {
        CrontabMutation::InstallFile
    })
}
