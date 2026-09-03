//! Classifies fully visible local host power commands.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::shell_word::{has_unmodeled_expansion, static_word};

pub(crate) fn operation(
    program: &str,
    arguments: &[Word],
    path_overridden: bool,
    qualified_program: bool,
    dynamic_words: bool,
) -> Option<SemanticCode> {
    if !matches!(
        program,
        "shutdown" | "reboot" | "halt" | "poweroff" | "init" | "telinit" | "systemctl"
    ) {
        return None;
    }
    if dynamic_words || !qualified_program && path_overridden {
        return None;
    }
    let arguments = static_arguments(arguments)?;
    let executes = match program {
        "shutdown" => shutdown_executes(&arguments),
        "reboot" | "halt" | "poweroff" => direct_power_executes(&arguments),
        "init" | "telinit" => {
            matches!(arguments.as_slice(), [level] if matches!(level.as_str(), "0" | "6"))
        }
        "systemctl" => systemctl_power_executes(&arguments),
        _ => false,
    };
    executes.then_some(SemanticCode::HOST_POWER)
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| {
            (!has_unmodeled_expansion(argument.raw()))
                .then(|| static_word(argument.raw(), argument.substitutions().is_empty()))
                .flatten()
        })
        .collect()
}

fn shutdown_executes(arguments: &[String]) -> bool {
    let mut options = true;
    let mut time = None;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.starts_with("--") {
            match argument.as_str() {
                "--halt" | "--poweroff" | "--reboot" | "--no-wall" => continue,
                "--help" | "--version" | "--show" => return false,
                _ => return false,
            }
        }
        if options && argument.starts_with('-') && argument != "-" {
            let mut non_executing = false;
            if argument[1..].is_empty()
                || !argument[1..].chars().all(|option| match option {
                    'H' | 'P' | 'p' | 'r' | 'h' => true,
                    'c' | 'k' => {
                        non_executing = true;
                        true
                    }
                    _ => false,
                })
                || non_executing
            {
                return false;
            }
            continue;
        }
        if time.is_none() {
            if !shutdown_time(argument) {
                return false;
            }
            time = Some(argument);
        }
    }
    time.is_some()
}

fn shutdown_time(value: &str) -> bool {
    !value.is_empty()
        && (value == "now"
            || value.bytes().all(|byte| byte.is_ascii_digit())
            || value.strip_prefix('+').is_some_and(|minutes| {
                !minutes.is_empty() && minutes.bytes().all(|byte| byte.is_ascii_digit())
            })
            || value.split_once(':').is_some_and(|(hour, minute)| {
                !hour.is_empty()
                    && !minute.is_empty()
                    && hour.bytes().all(|byte| byte.is_ascii_digit())
                    && minute.bytes().all(|byte| byte.is_ascii_digit())
            }))
}

fn direct_power_executes(arguments: &[String]) -> bool {
    let mut options = true;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if !options || !argument.starts_with('-') || argument == "-" {
            return false;
        }
        if argument.starts_with("--") {
            match argument.as_str() {
                "--halt" | "--poweroff" | "--reboot" | "--force" | "--no-wtmp" | "--no-sync"
                | "--no-wall" => continue,
                "--help" | "--version" | "--dry-run" | "--wtmp-only" => return false,
                _ => return false,
            }
        }
        let mut non_executing = false;
        if argument[1..].is_empty()
            || !argument[1..].chars().all(|option| match option {
                'f' | 'd' | 'n' | 'p' => true,
                'w' => {
                    non_executing = true;
                    true
                }
                _ => false,
            })
            || non_executing
        {
            return false;
        }
    }
    true
}

fn systemctl_power_executes(arguments: &[String]) -> bool {
    let mut action = None;
    let mut dry_run = false;
    let mut options = true;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument.starts_with("--") {
            match argument.as_str() {
                "--help" | "--version" => return false,
                "--dry-run" => dry_run = true,
                "--force" | "--no-wall" | "--no-block" | "--system" | "--quiet"
                | "--firmware-setup" => {}
                _ => {
                    let Some((name, value, consumed)) = long_option_value(arguments, index) else {
                        return false;
                    };
                    if name == "--when" && matches!(value, "" | "show" | "cancel") {
                        return false;
                    }
                    index += consumed;
                }
            }
            index += 1;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            if argument[1..]
                .chars()
                .any(|option| !matches!(option, 'f' | 'i' | 'q'))
            {
                return false;
            }
            index += 1;
            continue;
        }
        if action.is_some()
            || !matches!(
                argument.as_str(),
                "poweroff"
                    | "reboot"
                    | "halt"
                    | "kexec"
                    | "suspend"
                    | "hibernate"
                    | "hybrid-sleep"
                    | "suspend-then-hibernate"
            )
        {
            return false;
        }
        action = Some(argument);
        index += 1;
    }
    action.is_some() && !dry_run
}

fn long_option_value(arguments: &[String], index: usize) -> Option<(&str, &str, usize)> {
    const OPTIONS: &[&str] = &[
        "--job-mode",
        "--check-inhibitors",
        "--message",
        "--when",
        "--reboot-argument",
        "--boot-loader-entry",
        "--boot-loader-menu",
    ];
    let argument = arguments.get(index)?;
    for name in OPTIONS {
        if let Some(value) = argument.strip_prefix(&format!("{name}=")) {
            return Some((name, value, 0));
        }
        if argument == name {
            return arguments
                .get(index + 1)
                .map(|value| (*name, value.as_str(), 1));
        }
    }
    None
}
