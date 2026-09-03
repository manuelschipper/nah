//! Decodes transparent wrappers and shell payloads; it does not execute either.

use crate::bash_execution::{shell_program, shell_syntax_check};
use crate::bash_model::VariableValue;
use crate::bash_tar;
use crate::shell_word::{referenced_positional_names, static_word};
use nah_parse::{Redirect, Word};

pub(crate) fn shell_payload(
    program: &str,
    arguments: &[Word],
    redirects: &[Redirect],
) -> Option<String> {
    if program == "eval" {
        return arguments
            .iter()
            .map(static_argument)
            .collect::<Option<Vec<_>>>()
            .map(|arguments| arguments.join(" "));
    }
    if program == "trap" {
        return trap_handler(arguments);
    }
    if !shell_program(program) {
        return None;
    }
    if shell_syntax_check(arguments) {
        return None;
    }
    for (index, argument) in arguments.iter().enumerate() {
        let argument = static_argument(argument)?;
        if argument.starts_with('-') && !argument.starts_with("--") && argument[1..].contains('c') {
            let payload = index
                + 1
                + usize::from(
                    arguments
                        .get(index + 1)
                        .and_then(static_argument)
                        .is_some_and(|argument| argument == "--"),
                );
            return arguments.get(payload).and_then(static_argument);
        }
    }
    redirects
        .iter()
        .rev()
        .find_map(|redirect| match redirect.operator() {
            "<<<" => redirect
                .target()
                .and_then(|target| static_word(target, redirect.target_substitutions().is_empty())),
            "<<" | "<<-" => redirect.body().map(str::to_owned),
            "<" | "<&" => Some(String::new()),
            _ => None,
        })
        .filter(|payload| !payload.is_empty())
}

pub(crate) fn wrapper_payload(program: &str, arguments: &[Word]) -> Option<String> {
    if program == "script" {
        return script_command(arguments);
    }
    if program == "env" {
        return crate::bash_child_startup::env_payload(arguments);
    }
    if program == "tmux" {
        return tmux_payload(arguments);
    }
    let start = match program {
        "command" | "builtin" | "exec" => direct_wrapper_payload_start(program, arguments)?,
        "coproc" => match arguments.first().map(Word::raw) {
            Some(argument) if !argument.starts_with('-') => 0,
            _ => return None,
        },
        // Wrappers that run their operand directly. Their own options are not
        // modelled, so an option operand leaves the payload undecoded rather
        // than guessing which word starts the command.
        "busybox" | "toybox" | "eatmydata" | "firejail" | "ltrace" | "pkexec" | "proot" => {
            match arguments.first().map(Word::raw) {
                Some(argument) if !argument.starts_with('-') => 0,
                _ => return None,
            }
        }
        "dbus-run-session" => dbus_run_session_command_start(arguments)?,
        "screen" => screen_command_start(arguments)?,
        "strace" => strace_command_start(arguments)?,
        "systemd-run" => systemd_run_command_start(arguments)?,
        "unshare" => unshare_command_start(arguments)?,
        "nice" => nice_command_start(arguments)?,
        "nohup" => match arguments.first().map(Word::raw) {
            Some("--") if arguments.len() > 1 => 1,
            Some(argument) if !argument.starts_with('-') => 0,
            _ => return None,
        },
        "time" => time_command_start(arguments)?,
        "timeout" => timeout_command_start(arguments)?,
        "stdbuf" => stdbuf_command_start(arguments)?,
        "setsid" => setsid_command_start(arguments)?,
        "ionice" => ionice_command_start(arguments)?,
        "taskset" => taskset_command_start(arguments)?,
        "chrt" => chrt_command_start(arguments)?,
        "prlimit" => prlimit_command_start(arguments)?,
        "doas" => doas_command_start(arguments)?,
        "sudo" => sudo_command_start(arguments)?,
        _ => return None,
    };
    (start < arguments.len()).then(|| {
        arguments[start..]
            .iter()
            .map(Word::raw)
            .collect::<Vec<_>>()
            .join(" ")
    })
}

pub(crate) fn direct_wrapper_payload_start(program: &str, arguments: &[Word]) -> Option<usize> {
    match program {
        "command" => match arguments.first().map(Word::raw) {
            Some("-p") | Some("--") => Some(1),
            Some(argument) if argument.starts_with('-') => None,
            Some(_) => Some(0),
            None => None,
        },
        "builtin" => match arguments.first().map(Word::raw) {
            Some("--") => Some(1),
            Some(argument) if argument.starts_with('-') => None,
            Some(_) => Some(0),
            None => None,
        },
        "exec" => exec_command_start(arguments),
        _ => None,
    }
}

/// Decodes wrappers that pass a string to a shell rather than executing the
/// visible argument vector directly. `bool` is true only when the wrapper
/// really does preserve argv boundaries, as with `watch --exec`.
pub(crate) fn shell_string_wrapper_payload(
    program: &str,
    arguments: &[Word],
) -> Result<Option<(String, bool)>, ()> {
    match program {
        "watch" => watch_payload(arguments),
        "su" | "runuser" => account_shell_payload(program, arguments),
        "sg" => sg_payload(arguments),
        "parallel" => parallel_payload(arguments),
        _ => Ok(None),
    }
}

pub(crate) fn wrapper_clears_environment(program: &str, arguments: &[Word], name: &str) -> bool {
    crate::bash_child_startup::env_clears_name(program, arguments, name)
}

/// `trap` defers shell code that runs later. A handler nah cannot read
/// statically hides that code, which the joined arguments never reveal because
/// the handler is one quoted word rather than a command line.
pub(crate) fn hides_deferred_code(program: &str, arguments: &[Word]) -> bool {
    program == "trap"
        && matches!(arguments, [handler, _signal, ..] if static_argument(handler).is_none())
}

/// `trap <handler> <signal>...` defers shell code that runs later, so the
/// handler lowers like any other payload. `-` restores the default, an empty
/// handler ignores the signal, and the option forms only report existing traps.
fn trap_handler(arguments: &[Word]) -> Option<String> {
    let arguments = match arguments.first().map(Word::raw) {
        Some("--") => &arguments[1..],
        _ => arguments,
    };
    let [handler, _signal, ..] = arguments else {
        return None;
    };
    let handler = static_argument(handler)?;
    (!handler.is_empty() && !handler.starts_with('-')).then_some(handler)
}

fn script_command(arguments: &[Word]) -> Option<String> {
    let arguments = arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()?;
    for (index, argument) in arguments.iter().enumerate() {
        if matches!(argument.as_str(), "-c" | "--command") {
            return arguments.get(index + 1).cloned();
        }
        if let Some(command) = argument.strip_prefix("--command=") {
            return (!command.is_empty()).then(|| command.to_owned());
        }
        if argument.starts_with('-') && !argument.starts_with("--") && argument[1..].contains('c') {
            return arguments.get(index + 1).cloned();
        }
    }
    None
}

pub(crate) fn executor_payloads(
    program: &str,
    arguments: &[Word],
    variables: &[(String, VariableValue)],
    visible_stdin: Option<&str>,
) -> Vec<(String, bool, bool, Option<String>)> {
    if matches!(program, "ssh" | "scp" | "rsync") {
        return crate::bash_network::executor_payloads(program, arguments)
            .into_iter()
            .map(|payload| (payload, false, false, None))
            .collect();
    }
    if program == "socat" {
        return crate::bash_socat::socat_executor_payloads(arguments, variables)
            .into_iter()
            .map(|(payload, unknown_cwd)| (payload, unknown_cwd, false, None))
            .collect();
    }
    if matches!(program, "tar" | "bsdtar") {
        return bash_tar::analyze(program, arguments)
            .map(|analysis| analysis.executor_payloads)
            .unwrap_or_default()
            .into_iter()
            .map(|payload| (payload, false, false, None))
            .collect();
    }
    if program == "xargs" {
        return xargs_command_start(arguments)
            .filter(|start| {
                arguments
                    .get(*start)
                    .and_then(static_argument)
                    .is_some_and(|argument| !argument.is_empty())
            })
            .map(|start| {
                let options = &arguments[..start];
                if xargs_no_run_if_empty(options) && xargs_input_is_empty(options, visible_stdin) {
                    return Vec::new();
                }
                let replacement = xargs_replacement(&arguments[..start]);
                let substitutes_command = replacement.as_deref().is_some_and(|replacement| {
                    arguments[start..].iter().any(|argument| {
                        static_argument(argument)
                            .is_some_and(|argument| argument.contains(replacement))
                    })
                }) || xargs_appends_code(&arguments[start..]);
                let exact_inputs = xargs_exact_inputs(options, visible_stdin);
                let exact_inputs =
                    exact_inputs.filter(|_| replacement.is_none() && !substitutes_command);
                let payload = exact_inputs.map_or_else(
                    || join_words(&arguments[start..]),
                    |inputs| {
                        std::iter::once(join_words(&arguments[start..]))
                            .chain(inputs.into_iter().map(|input| quote_shell_word(&input)))
                            .collect::<Vec<_>>()
                            .join(" ")
                    },
                );
                vec![(payload, false, substitutes_command, None)]
            })
            .unwrap_or_default();
    }
    if program != "find" {
        return Vec::new();
    }
    let Some(roots) = find_roots(arguments) else {
        return Vec::new();
    };
    let recursive_selector = find_recurses(arguments);
    let mut payloads = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments.get(index).and_then(static_argument) else {
            return Vec::new();
        };
        if !matches!(argument.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
            index += 1;
            continue;
        }
        let unknown_cwd = matches!(argument.as_str(), "-execdir" | "-okdir");
        let start = index + 1;
        let Some(end) = (start..arguments.len()).find(|candidate| {
            arguments
                .get(*candidate)
                .and_then(static_argument)
                .is_some_and(|argument| matches!(argument.as_str(), ";" | "+"))
        }) else {
            return Vec::new();
        };
        let terminator = static_argument(&arguments[end]).unwrap_or_default();
        if start == end
            || terminator == "+" && static_argument(&arguments[end - 1]).as_deref() != Some("{}")
        {
            return Vec::new();
        }
        let command = &arguments[start..end];
        if command.iter().any(|argument| {
            static_argument(argument)
                .is_none_or(|argument| argument != "{}" && argument.contains("{}"))
        }) {
            return Vec::new();
        }
        if command
            .iter()
            .any(|argument| static_argument(argument).as_deref() == Some("{}"))
        {
            payloads.extend(roots.iter().map(|root| {
                (
                    command
                        .iter()
                        .map(|argument| {
                            if static_argument(argument).as_deref() == Some("{}") {
                                root.as_str()
                            } else {
                                argument.raw()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                    unknown_cwd,
                    false,
                    (!unknown_cwd && recursive_selector).then(|| root.clone()),
                )
            }));
        } else {
            payloads.push((join_words(command), unknown_cwd, false, None));
        }
        index = end + 1;
    }
    payloads
}

pub(crate) fn crontab_payload(arguments: &[Word], visible_stdin: Option<&str>) -> Option<String> {
    if crate::bash_startup_persistence::crontab_mutation(arguments)
        != Some(crate::bash_startup_persistence::CrontabMutation::InstallStdin)
    {
        return None;
    }
    let mut commands = Vec::new();
    for line in visible_stdin?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if cron_assignment(line) {
            continue;
        }
        if line.starts_with('@') {
            let (schedule, command) = line.split_once(char::is_whitespace)?;
            if !matches!(
                schedule,
                "@reboot"
                    | "@yearly"
                    | "@annually"
                    | "@monthly"
                    | "@weekly"
                    | "@daily"
                    | "@midnight"
                    | "@hourly"
            ) || command.trim_start().is_empty()
            {
                return None;
            }
            commands.push(command.trim_start());
            continue;
        }
        let mut cursor = 0;
        for _ in 0..5 {
            cursor += line[cursor..].find(|character: char| !character.is_ascii_whitespace())?;
            let end = cursor
                + line[cursor..]
                    .find(char::is_whitespace)
                    .unwrap_or(line.len() - cursor);
            // Unknown cron dialects remain opaque rather than becoming code.
            if !line[cursor..end]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'*' | b',' | b'-' | b'/'))
            {
                return None;
            }
            cursor = end;
        }
        let command = line[cursor..].trim_start();
        if command.is_empty() {
            return None;
        }
        commands.push(command);
    }
    let payload = commands.join(" ; ");
    (!payload.is_empty() && payload.len() <= crate::INVOCATION_EVIDENCE_CAP).then_some(payload)
}

fn cron_assignment(line: &str) -> bool {
    line.split_once('=').is_some_and(|(name, _)| {
        let name = name.trim();
        name.as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn find_recurses(arguments: &[Word]) -> bool {
    let values = arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>();
    let Some(values) = values else {
        return false;
    };
    !values
        .windows(2)
        .any(|pair| pair[0] == "-maxdepth" && pair[1] == "0")
}

fn find_roots(arguments: &[Word]) -> Option<Vec<String>> {
    let values = arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()?;
    let mut index = 0;
    while values
        .get(index)
        .is_some_and(|value| matches!(value.as_str(), "-H" | "-L" | "-P"))
    {
        index += 1;
    }
    if values.get(index).is_some_and(|value| value == "-D") {
        index += 2;
    }
    if values
        .get(index)
        .is_some_and(|value| value.starts_with("-O"))
    {
        index += 1;
    }
    let mut roots = Vec::new();
    while let Some(value) = values.get(index) {
        if value.starts_with('-') || matches!(value.as_str(), "!" | "(" | ")") {
            break;
        }
        roots.push(value.clone());
        index += 1;
    }
    if roots.is_empty() {
        roots.push(".".to_owned());
    }
    Some(roots)
}

fn xargs_appends_code(command: &[Word]) -> bool {
    let Some(program) = command.first().and_then(static_argument) else {
        return false;
    };
    let program = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&program)
        .to_ascii_lowercase();
    let program = program.strip_suffix(".exe").unwrap_or(&program);
    let arguments = command[1..]
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>();
    let Some(arguments) = arguments else {
        return false;
    };
    if shell_program(program) {
        return arguments.iter().enumerate().any(|(index, argument)| {
            argument
                .strip_prefix('-')
                .is_some_and(|flags| !flags.starts_with('-') && flags.contains('c'))
                && (index + 1 == arguments.len()
                    || arguments
                        .get(index + 1)
                        .is_some_and(|argument| argument == "--")
                        && index + 2 == arguments.len())
        });
    }
    if matches!(
        program,
        "node"
            | "nodejs"
            | "perl"
            | "python"
            | "python3"
            | "ruby"
            | "php"
            | "lua"
            | "r"
            | "rscript"
            | "julia"
            | "swift"
    ) || program.strip_prefix("python3.").is_some_and(|version| {
        !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return arguments.len() == 1 && matches!(arguments[0].as_str(), "-c" | "-e" | "--eval");
    }
    matches!(program, "powershell" | "pwsh")
        && arguments.last().is_some_and(|argument| {
            matches!(argument.to_ascii_lowercase().as_str(), "-command" | "-c")
        })
        || program == "cmd"
            && arguments
                .last()
                .is_some_and(|argument| argument.eq_ignore_ascii_case("/c"))
}

fn xargs_replacement(arguments: &[Word]) -> Option<String> {
    let mut index = 0;
    while index < arguments.len() {
        let argument = static_argument(&arguments[index])?;
        if matches!(argument.as_str(), "-I" | "--replace") {
            return arguments.get(index + 1).and_then(static_argument);
        }
        if let Some(replacement) = argument.strip_prefix("--replace=").or_else(|| {
            argument
                .strip_prefix("-I")
                .filter(|value| !value.is_empty())
        }) {
            return Some(replacement.to_owned());
        }
        index += 1;
    }
    None
}

fn xargs_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &[
            "-0",
            "--null",
            "-o",
            "--open-tty",
            "-p",
            "--interactive",
            "-r",
            "--no-run-if-empty",
            "-t",
            "--verbose",
            "-x",
            "--exit",
        ],
        &[
            "-a",
            "--arg-file",
            "-d",
            "--delimiter",
            "-E",
            "-e",
            "--eof",
            "-I",
            "-i",
            "--replace",
            "-L",
            "-l",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
        ],
        &[
            "--arg-file=",
            "--delimiter=",
            "--eof=",
            "--replace=",
            "--max-lines=",
            "--max-args=",
            "--max-procs=",
            "--max-chars=",
        ],
        &[
            "-a", "-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s",
        ],
    )
}

fn xargs_exact_inputs(options: &[Word], visible_stdin: Option<&str>) -> Option<Vec<String>> {
    let mut null_delimited = false;
    for option in options {
        match static_argument(option)?.as_str() {
            "-0" | "--null" if !null_delimited => null_delimited = true,
            "-r" | "--no-run-if-empty" => {}
            _ => return None,
        }
    }
    let input = visible_stdin?;
    if !null_delimited && input.contains(['\\', '\'', '"']) {
        return None;
    }
    let values = if null_delimited {
        let input = input.strip_suffix('\0').unwrap_or(input);
        if input.is_empty() && visible_stdin == Some("") {
            Vec::new()
        } else {
            input.split('\0').map(str::to_owned).collect::<Vec<_>>()
        }
    } else {
        input
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    Some(values)
}

fn xargs_no_run_if_empty(options: &[Word]) -> bool {
    options.iter().any(|option| {
        static_argument(option)
            .is_some_and(|option| matches!(option.as_str(), "-r" | "--no-run-if-empty"))
    })
}

fn xargs_input_is_empty(options: &[Word], visible_stdin: Option<&str>) -> bool {
    let Some(input) = visible_stdin else {
        return false;
    };
    let null_delimited = options.iter().any(|option| {
        static_argument(option).is_some_and(|option| matches!(option.as_str(), "-0" | "--null"))
    });
    if null_delimited {
        input.is_empty()
    } else {
        input.split_ascii_whitespace().next().is_none()
    }
}

fn join_words(arguments: &[Word]) -> String {
    arguments
        .iter()
        .map(Word::raw)
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn exec_has_no_command(arguments: &[Word]) -> bool {
    exec_command_start(arguments) == Some(arguments.len())
}

pub(crate) fn command_exec_has_no_command(arguments: &[Word]) -> bool {
    let mut arguments = arguments;
    loop {
        let mut start = 0;
        while let Some(argument) = arguments.get(start).and_then(static_argument) {
            if argument == "--" {
                start += 1;
                break;
            }
            let Some(flags) = argument.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            if flags.chars().any(|flag| matches!(flag, 'v' | 'V'))
                || !flags.chars().all(|flag| flag == 'p')
            {
                return false;
            }
            start += 1;
        }
        let Some(program) = arguments.get(start).and_then(static_argument) else {
            return false;
        };
        arguments = &arguments[start + 1..];
        match program.as_str() {
            "exec" => return exec_has_no_command(arguments),
            "command" => {}
            _ => return false,
        }
    }
}

fn exec_command_start(arguments: &[Word]) -> Option<usize> {
    let mut start = 0;
    while let Some(argument) = arguments.get(start).map(Word::raw) {
        if argument == "--" {
            return Some(start + 1);
        }
        if let Some(flags) = argument.strip_prefix('-') {
            if flags.is_empty() {
                return None;
            }
            if let Some(argv0) = flags.find('a') {
                if !flags[..argv0].chars().all(|flag| matches!(flag, 'c' | 'l')) {
                    return None;
                }
                start += 1;
                if flags[argv0 + 1..].is_empty() {
                    start += 1;
                    if start > arguments.len() {
                        return None;
                    }
                }
                continue;
            }
            if flags.chars().all(|flag| matches!(flag, 'c' | 'l')) {
                start += 1;
                continue;
            }
            return None;
        }
        return Some(start);
    }
    Some(start)
}

fn nice_command_start(arguments: &[Word]) -> Option<usize> {
    let mut start = 0;
    while let Some(argument) = arguments.get(start).map(Word::raw) {
        if argument == "--" {
            return (start + 1 < arguments.len()).then_some(start + 1);
        }
        if matches!(argument, "-n" | "--adjustment") {
            start += 2;
            if start > arguments.len() {
                return None;
            }
            continue;
        }
        if argument.starts_with("--adjustment=")
            || argument.strip_prefix('-').is_some_and(|value| {
                !value.is_empty() && value.chars().all(|character| character.is_ascii_digit())
            })
        {
            start += 1;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(start);
    }
    None
}

fn time_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &["-p", "--portability", "-v", "--verbose", "--quiet"],
        &["-f", "--format", "-o", "--output"],
        &["--format=", "--output="],
        &["-f", "-o"],
    )
}

fn timeout_command_start(arguments: &[Word]) -> Option<usize> {
    let duration = options_command_start(
        arguments,
        &["--foreground", "--preserve-status", "-v", "--verbose"],
        &["-k", "--kill-after", "-s", "--signal"],
        &["--kill-after=", "--signal="],
        &["-k", "-s"],
    )?;
    (duration + 1 < arguments.len()).then_some(duration + 1)
}

fn stdbuf_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &[],
        &["-i", "--input", "-o", "--output", "-e", "--error"],
        &["--input=", "--output=", "--error="],
        &["-i", "-o", "-e"],
    )
}

fn setsid_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &["-c", "--ctty", "-f", "--fork", "-w", "--wait"],
        &[],
        &[],
        &[],
    )
}

fn ionice_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &["-t", "--ignore"],
        &["-c", "--class", "-n", "--classdata"],
        &["--class=", "--classdata="],
        &["-c", "-n"],
    )
}

fn taskset_command_start(arguments: &[Word]) -> Option<usize> {
    let affinity = options_command_start(
        arguments,
        &["-a", "--all-tasks", "-c", "--cpu-list"],
        &[],
        &[],
        &[],
    )?;
    let pid_mode = arguments[..affinity]
        .iter()
        .filter_map(static_argument)
        .any(|argument| matches!(argument.as_str(), "-p" | "--pid"));
    (!pid_mode && affinity + 1 < arguments.len()).then_some(affinity + 1)
}

fn chrt_command_start(arguments: &[Word]) -> Option<usize> {
    let priority = options_command_start(
        arguments,
        &[
            "-a",
            "--all-tasks",
            "-b",
            "--batch",
            "-d",
            "--deadline",
            "-f",
            "--fifo",
            "-i",
            "--idle",
            "-o",
            "--other",
            "-r",
            "--rr",
            "-R",
            "--reset-on-fork",
            "-v",
            "--verbose",
        ],
        &[
            "-T",
            "--sched-runtime",
            "-P",
            "--sched-period",
            "-D",
            "--sched-deadline",
        ],
        &["--sched-runtime=", "--sched-period=", "--sched-deadline="],
        &["-T", "-P", "-D"],
    )?;
    (priority + 1 < arguments.len()).then_some(priority + 1)
}

fn prlimit_command_start(arguments: &[Word]) -> Option<usize> {
    let mut start = 0;
    while let Some(argument) = arguments.get(start).and_then(static_argument) {
        if argument == "--" {
            return (start + 1 < arguments.len()).then_some(start + 1);
        }
        if matches!(argument.as_str(), "--noheadings" | "--raw" | "--verbose") {
            start += 1;
            continue;
        }
        if argument == "-o" || argument == "--output" {
            start += 2;
            if start > arguments.len() {
                return None;
            }
            continue;
        }
        if argument.starts_with("--output=") || prlimit_resource(&argument) {
            start += 1;
            continue;
        }
        if matches!(argument.as_str(), "-p" | "--pid") || argument.starts_with("--pid=") {
            return None;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(start);
    }
    None
}

fn prlimit_resource(argument: &str) -> bool {
    [
        "as",
        "core",
        "cpu",
        "data",
        "fsize",
        "locks",
        "memlock",
        "msgqueue",
        "nice",
        "nofile",
        "nproc",
        "rss",
        "rtprio",
        "rttime",
        "sigpending",
        "stack",
    ]
    .iter()
    .any(|resource| argument.starts_with(&format!("--{resource}=")))
}

fn doas_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(arguments, &["-n"], &["-u"], &[], &["-u"])
}

fn dbus_run_session_command_start(arguments: &[Word]) -> Option<usize> {
    match arguments.first().and_then(static_argument).as_deref() {
        Some("--") if arguments.len() > 1 => Some(1),
        Some(argument) if !argument.starts_with('-') => Some(0),
        _ => None,
    }
}

fn screen_command_start(arguments: &[Word]) -> Option<usize> {
    match arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()?
        .as_slice()
    {
        [option, _command, ..] if matches!(option.as_str(), "-dm" | "-Dm") => Some(1),
        [detach, mode, _command, ..] if matches!(detach.as_str(), "-d" | "-D") && mode == "-m" => {
            Some(2)
        }
        [option, _session, _command, ..] if matches!(option.as_str(), "-dmS" | "-DmS") => Some(2),
        _ => None,
    }
}

fn strace_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &["-f", "-ff", "--follow-forks", "-q", "-qq", "-qqq"],
        &["-o", "--output"],
        &["--output="],
        &["-o"],
    )
}

fn systemd_run_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &["--user", "--scope", "--wait", "--no-block", "--collect"],
        &["--unit"],
        &["--unit="],
        &[],
    )
}

fn tmux_payload(arguments: &[Word]) -> Option<String> {
    let [subcommand, rest @ ..] = arguments else {
        return None;
    };
    if !matches!(
        static_argument(subcommand).as_deref(),
        Some("new-session" | "new")
    ) {
        return None;
    }
    let start = options_command_start(rest, &["-d"], &["-s", "-ds"], &[], &["-s", "-ds"])?;
    let [command] = &rest[start..] else {
        return None;
    };
    static_argument(command)
}

fn unshare_command_start(arguments: &[Word]) -> Option<usize> {
    options_command_start(
        arguments,
        &[
            "-m",
            "--mount",
            "--mount-proc",
            "-u",
            "--uts",
            "-i",
            "--ipc",
            "-n",
            "--net",
            "-p",
            "--pid",
            "-U",
            "--user",
            "-C",
            "--cgroup",
            "-T",
            "--time",
            "-f",
            "--fork",
            "-r",
            "--map-root-user",
            "-c",
            "--map-current-user",
            "--map-auto",
            "--keep-caps",
        ],
        &[],
        &["--mount-proc="],
        &[],
    )
}

fn options_command_start(
    arguments: &[Word],
    flags: &[&str],
    value_options: &[&str],
    value_prefixes: &[&str],
    attached_short_values: &[&str],
) -> Option<usize> {
    let mut start = 0;
    while let Some(argument) = arguments.get(start).and_then(static_argument) {
        if argument == "--" {
            return (start + 1 < arguments.len()).then_some(start + 1);
        }
        if flags.contains(&argument.as_str()) {
            start += 1;
            continue;
        }
        if value_options.contains(&argument.as_str()) {
            start += 2;
            if start > arguments.len() {
                return None;
            }
            continue;
        }
        if value_prefixes
            .iter()
            .any(|prefix| argument.starts_with(prefix))
            || attached_short_values
                .iter()
                .any(|prefix| argument.starts_with(prefix) && argument.len() > prefix.len())
        {
            start += 1;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(start);
    }
    None
}

fn static_argument(argument: &Word) -> Option<String> {
    static_word(argument.raw(), argument.substitutions().is_empty())
}

fn watch_payload(arguments: &[Word]) -> Result<Option<(String, bool)>, ()> {
    let mut index = 0;
    let mut direct = false;
    while index < arguments.len() {
        let argument = static_argument(&arguments[index]).ok_or(())?;
        if argument == "--" {
            index += 1;
            break;
        }
        if !argument.starts_with('-') || argument == "-" {
            break;
        }
        if matches!(argument.as_str(), "-h" | "--help" | "-v" | "--version") {
            return Ok(None);
        }
        if let Some(option) = argument.strip_prefix("--") {
            match option {
                "beep" | "color" | "no-color" | "errexit" | "follow" | "chgexit" | "precise"
                | "no-rerun" | "no-terminal" | "no-title" | "no-wrap" | "differences" => {}
                "exec" => direct = true,
                option
                    if option.starts_with("differences=")
                        || option.starts_with("equexit=")
                        || option.starts_with("interval=")
                        || option.starts_with("shotsdir=") => {}
                "equexit" | "interval" | "shotsdir" => {
                    index += 1;
                    if index >= arguments.len() {
                        return Ok(None);
                    }
                }
                _ => return Err(()),
            }
            index += 1;
            continue;
        }

        let flags = argument.strip_prefix('-').expect("checked option");
        let mut flags = flags.char_indices().peekable();
        while let Some((offset, flag)) = flags.next() {
            match flag {
                'b' | 'c' | 'C' | 'e' | 'f' | 'g' | 'p' | 'r' | 'T' | 't' | 'w' => {}
                'x' => direct = true,
                'h' | 'v' => return Ok(None),
                'd' => break,
                'q' | 'n' | 's' => {
                    if flags.peek().is_none() {
                        index += 1;
                        if index >= arguments.len() {
                            return Ok(None);
                        }
                    } else {
                        let _value = &argument[offset + flag.len_utf8() + 1..];
                    }
                    break;
                }
                _ => return Err(()),
            }
        }
        index += 1;
    }

    if index >= arguments.len() {
        return Ok(None);
    }
    if direct {
        if arguments[index..]
            .first()
            .and_then(static_argument)
            .is_none_or(|program| program.is_empty())
        {
            return Err(());
        }
        return Ok(Some((join_words(&arguments[index..]), true)));
    }
    let payload = arguments[index..]
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()
        .ok_or(())?
        .join(" ");
    Ok((!payload.is_empty()).then_some((payload, false)))
}

fn account_shell_payload(program: &str, arguments: &[Word]) -> Result<Option<(String, bool)>, ()> {
    let mut index = 0;
    let mut carrier = None;
    let mut login = false;
    let mut custom_shell = false;
    let mut preserves_environment = false;
    let mut runuser_direct = false;
    let mut session_command = false;
    let mut operands = 0;
    while index < arguments.len() {
        let argument = static_argument(&arguments[index]).ok_or(())?;
        if matches!(argument.as_str(), "-h" | "--help" | "-V" | "--version") {
            return Ok(None);
        }
        if matches!(argument.as_str(), "-c" | "--command" | "--session-command") {
            session_command |= argument == "--session-command";
            index += 1;
            let Some(payload) = arguments.get(index).and_then(static_argument) else {
                return if index < arguments.len() {
                    Err(())
                } else {
                    Ok(None)
                };
            };
            carrier = Some(payload);
            index += 1;
            continue;
        }
        if let Some(payload) = argument
            .strip_prefix("--command=")
            .or_else(|| argument.strip_prefix("--session-command="))
        {
            session_command |= argument.starts_with("--session-command=");
            carrier = Some(payload.to_owned());
            index += 1;
            continue;
        }
        if argument == "--" {
            let tail = &arguments[index + 1..];
            if carrier.is_none() && post_user_shell_options(tail) {
                return Err(());
            }
            operands += tail.len();
            break;
        }
        if matches!(
            argument.as_str(),
            "--preserve-environment" | "--login" | "--fast" | "--pty"
        ) {
            login |= argument == "--login";
            preserves_environment |= argument == "--preserve-environment";
            index += 1;
            continue;
        }
        if matches!(
            argument.as_str(),
            "--whitelist-environment" | "--group" | "--supp-group" | "--shell" | "--user"
        ) {
            custom_shell |= argument == "--shell";
            runuser_direct |= argument == "--user";
            index += 2;
            if index > arguments.len() {
                return Ok(None);
            }
            continue;
        }
        if [
            "--whitelist-environment=",
            "--group=",
            "--supp-group=",
            "--shell=",
            "--user=",
        ]
        .iter()
        .any(|prefix| argument.starts_with(prefix))
        {
            custom_shell |= argument.starts_with("--shell=");
            runuser_direct |= argument.starts_with("--user=");
            index += 1;
            continue;
        }
        if argument.starts_with("--") {
            return Ok(None);
        }
        if let Some(flags) = argument.strip_prefix('-')
            && !flags.is_empty()
        {
            let mut flags = flags.char_indices().peekable();
            while let Some((offset, flag)) = flags.next() {
                match flag {
                    'm' | 'p' => preserves_environment = true,
                    'l' => login = true,
                    'f' | 'P' | 'T' => {}
                    'h' | 'V' => return Ok(None),
                    'c' => {
                        let payload = if flags.peek().is_some() {
                            argument[offset + flag.len_utf8() + 1..].to_owned()
                        } else {
                            let Some(payload) = arguments.get(index + 1).and_then(static_argument)
                            else {
                                return if index + 1 < arguments.len() {
                                    Err(())
                                } else {
                                    Ok(None)
                                };
                            };
                            payload
                        };
                        carrier = Some(payload);
                        break;
                    }
                    'w' | 'g' | 'G' | 's' | 'u' => {
                        custom_shell |= flag == 's';
                        runuser_direct |= flag == 'u';
                        if flags.peek().is_none() {
                            index += 1;
                            if index >= arguments.len() {
                                return Ok(None);
                            }
                        }
                        break;
                    }
                    _ => return Ok(None),
                }
            }
        } else if argument == "-" {
            login = true;
        } else {
            operands += 1;
        }
        index += 1;
    }
    if program == "runuser" && runuser_direct {
        return if operands == 0 { Ok(None) } else { Err(()) };
    }
    let Some(payload) = carrier else {
        return Ok(None);
    };
    if login
        || custom_shell
        || preserves_environment
        || session_command
        || operands > 1
        || !referenced_positional_names(&payload).is_empty()
    {
        return Err(());
    }
    Ok((!payload.is_empty()).then_some((payload, false)))
}

fn post_user_shell_options(arguments: &[Word]) -> bool {
    arguments
        .iter()
        .filter_map(static_argument)
        .any(|argument| {
            argument == "-c"
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| !flags.is_empty() && flags.contains('c'))
        })
}

fn sg_payload(arguments: &[Word]) -> Result<Option<(String, bool)>, ()> {
    let Some(first) = arguments.first().and_then(static_argument) else {
        return if arguments.is_empty() {
            Ok(None)
        } else {
            Err(())
        };
    };
    if matches!(first.as_str(), "-h" | "--help" | "-V" | "--version") {
        return Ok(None);
    }
    let group = usize::from(matches!(first.as_str(), "-" | "-l" | "--login"));
    let Some(group_name) = arguments.get(group) else {
        return Ok(None);
    };
    static_argument(group_name).ok_or(())?;
    let Some(command) = arguments.get(group + 1) else {
        return Ok(None);
    };
    let command = match static_argument(command) {
        Some(option) if option == "-c" => {
            let Some(command) = arguments.get(group + 2) else {
                return Ok(Some(("-c".to_owned(), false)));
            };
            static_argument(command).ok_or(())?
        }
        Some(command) => command,
        None => return Err(()),
    };
    Ok((!command.is_empty()).then_some((command, false)))
}

fn parallel_payload(arguments: &[Word]) -> Result<Option<(String, bool)>, ()> {
    let Some(first) = arguments.first().and_then(static_argument) else {
        return Err(());
    };
    if matches!(
        first.as_str(),
        "-h" | "--help" | "-V" | "--version" | "--citation"
    ) {
        return Ok(None);
    }
    let start = usize::from(first == "--");
    if start == 0 && first.starts_with('-') {
        return Err(());
    }
    let values = arguments[start..]
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()
        .ok_or(())?;
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "::::" | ":::+" | "::::+"))
    {
        return Err(());
    }
    let separators = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value == ":::").then_some(index))
        .collect::<Vec<_>>();
    let [separator] = separators.as_slice() else {
        return Err(());
    };
    let template = &values[..*separator];
    let inputs = &values[separator + 1..];
    if inputs.is_empty()
        || template
            .iter()
            .any(|value| value.contains('{') && value != "{}")
    {
        return if inputs.is_empty() { Ok(None) } else { Err(()) };
    }
    let mut jobs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let job = if template.is_empty() {
            input.clone()
        } else {
            let mut replaced = false;
            let mut words = Vec::with_capacity(template.len() + 1);
            for (index, word) in template.iter().enumerate() {
                if word == "{}" {
                    replaced = true;
                    words.push(if index == 0 {
                        input.clone()
                    } else {
                        quote_shell_word(input)
                    });
                } else {
                    words.push(word.clone());
                }
            }
            if !replaced {
                words.push(quote_shell_word(input));
            }
            words.join(" ")
        };
        jobs.push(job);
    }
    let payload = jobs.join(" ; ");
    if payload.len() > crate::INVOCATION_EVIDENCE_CAP {
        return Err(());
    }
    Ok((!payload.is_empty()).then_some((payload, false)))
}

fn quote_shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn sudo_command_start(arguments: &[Word]) -> Option<usize> {
    let mut start = 0;
    while let Some(argument) = arguments.get(start).map(Word::raw) {
        if argument == "--" {
            return (start + 1 < arguments.len()).then_some(start + 1);
        }
        if !argument.starts_with('-') && argument.contains('=') {
            start += 1;
            continue;
        }
        if matches!(
            argument,
            "--non-interactive" | "--preserve-env" | "--set-home"
        ) {
            start += 1;
            continue;
        }
        if matches!(
            argument,
            "--user" | "--group" | "--host" | "--prompt" | "--close-from" | "--command-timeout"
        ) {
            start += 2;
            if start > arguments.len() {
                return None;
            }
            continue;
        }
        if [
            "--user=",
            "--group=",
            "--host=",
            "--prompt=",
            "--close-from=",
            "--command-timeout=",
            "--preserve-env=",
        ]
        .iter()
        .any(|prefix| argument.starts_with(prefix))
        {
            start += 1;
            continue;
        }
        if matches!(argument, "--chdir" | "--chroot")
            || argument.starts_with("--chdir=")
            || argument.starts_with("--chroot=")
        {
            return None;
        }
        if let Some(flags) = argument.strip_prefix('-') {
            if flags.is_empty() {
                return None;
            }
            let bytes = flags.as_bytes();
            let mut index = 0;
            while index < bytes.len() {
                let flag = bytes[index] as char;
                if matches!(flag, 'n' | 'E' | 'H' | 'k' | 'K' | 'S') {
                    index += 1;
                    continue;
                }
                if matches!(flag, 'D' | 'R') {
                    return None;
                }
                if matches!(flag, 'u' | 'g' | 'h' | 'p' | 'C' | 'T' | 'D' | 'R') {
                    if index + 1 == bytes.len() {
                        start += 1;
                        if start >= arguments.len() {
                            return None;
                        }
                    }
                    start += 1;
                    break;
                }
                return None;
            }
            if index == bytes.len() {
                start += 1;
            }
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(start);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_command_extracts_static_pty_payloads() {
        for command in [
            "script -qec 'nah nap' /dev/null",
            "script --command 'nah nap --all' /dev/null",
            "script --command='nah nap' /dev/null",
        ] {
            let syntax = nah_parse::normalize(command).unwrap();
            let nah_parse::Statement::Command {
                name, arguments, ..
            } = syntax.statements().first().unwrap()
            else {
                panic!("expected command");
            };
            assert!(
                wrapper_payload(name, arguments)
                    .unwrap()
                    .starts_with("nah nap")
            );
        }
    }

    #[test]
    fn command_exec_only_persists_redirects_when_exec_has_no_command() {
        for (command, expected) in [
            ("command exec", true),
            ("command -- exec", true),
            ("command -p exec", true),
            ("command -p -- exec -cl", true),
            ("command exec --", true),
            ("command command exec", true),
            ("command -p command -- exec", true),
            ("command -v exec", false),
            ("command command -v exec", false),
            ("command -V exec", false),
            ("command echo", false),
            ("command exec echo", false),
        ] {
            let syntax = nah_parse::normalize(command).unwrap();
            let nah_parse::Statement::Command {
                name, arguments, ..
            } = syntax.statements().first().unwrap()
            else {
                panic!("expected command");
            };
            assert_eq!(name, "command");
            assert_eq!(
                command_exec_has_no_command(arguments),
                expected,
                "{command}"
            );
        }
    }
}
