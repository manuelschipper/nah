//! Lowers visible execution and artifact flow; it does not execute payloads.

use nah_parse::{Substitution, Word};
use nah_proto::action::{FilesystemOperation, SemanticCode};

use crate::bash_descriptor_paths::{arbitrary_process_descriptor_path, descriptor_reference_path};
use crate::bash_descriptor_state::{DescriptorPresence, DescriptorState, NetworkEndpoint};
use crate::bash_descriptors::descriptor_reference_binding_from_cwd;
use crate::bash_model::{FilesystemSpec, VariableValue};
use crate::bash_network::{lower as lower_network, shell_operation as network_shell_operation};
use crate::shell_word::static_filesystem_word;

pub(crate) struct Lowering {
    pub(crate) complete: bool,
    pub(crate) operation: Option<&'static str>,
    pub(crate) filesystems: Vec<FilesystemSpec>,
    pub(crate) network_outbound: bool,
    pub(crate) stdin_flows: bool,
    pub(crate) stdout_flows: bool,
    pub(crate) network_endpoints: Vec<NetworkEndpoint>,
    pub(crate) descriptor_sources: Vec<usize>,
    pub(crate) descriptor_sinks: Vec<usize>,
    pub(crate) descriptor_code: Option<String>,
}

pub(crate) fn lower(
    program: &str,
    arguments: &[Word],
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
    cwd: Option<&str>,
) -> Option<Lowering> {
    if let Some(operation) = network_shell_operation(program, arguments, descriptors, variables) {
        return Some(Lowering {
            complete: true,
            operation: Some(operation),
            filesystems: Vec::new(),
            // A listener can send stdin to its connected peer as well as
            // receive bytes from it.
            network_outbound: operation == "network-listener",
            stdin_flows: true,
            stdout_flows: true,
            network_endpoints: Vec::new(),
            descriptor_sources: Vec::new(),
            descriptor_sinks: Vec::new(),
            descriptor_code: None,
        });
    }
    if let Some(network) = lower_network(program, arguments, descriptors, variables) {
        let network_transfer = network.network || !network.network_endpoints.is_empty();
        return Some(Lowering {
            complete: network.complete,
            operation: Some(if network_transfer {
                "network-transfer"
            } else {
                "copy"
            }),
            filesystems: network.filesystems,
            network_outbound: network.network,
            stdin_flows: network.stdin_flows,
            stdout_flows: network.stdout_flows,
            network_endpoints: network.network_endpoints,
            descriptor_sources: network.descriptor_sources,
            descriptor_sinks: network.descriptor_sinks,
            descriptor_code: None,
        });
    }
    if let Some((complete, stdout_flows)) = decode(program, arguments) {
        return Some(Lowering {
            complete,
            operation: Some("decode"),
            filesystems: Vec::new(),
            network_outbound: false,
            stdin_flows: true,
            stdout_flows,
            network_endpoints: Vec::new(),
            descriptor_sources: Vec::new(),
            descriptor_sinks: Vec::new(),
            descriptor_code: None,
        });
    }
    let source = execution_source(program, arguments)?;
    let file_source =
        source == SemanticCode::SHELL_FILE || source == SemanticCode::INTERPRETER_FILE;
    let stdin_source =
        source == SemanticCode::SHELL_STDIN || source == SemanticCode::INTERPRETER_STDIN;
    let file_argument = execution_file_argument(program, arguments, source.as_str());
    let target = execution_file(program, arguments, source.as_str());
    let descriptor = target
        .as_deref()
        .and_then(|target| {
            descriptor_reference_binding_from_cwd(descriptors, target, variables, cwd).ok()
        })
        .flatten()
        .or_else(|| {
            (file_source
                && target.is_none()
                && !file_argument
                    .is_some_and(|argument| arbitrary_process_descriptor_path(argument.raw())))
            .then(|| descriptors.possible_facts().ok())
            .flatten()
            .filter(|facts| !facts.is_empty())
            .map(|facts| (DescriptorPresence::Maybe, facts))
        });
    let descriptor_complete = descriptor
        .as_ref()
        .is_none_or(|(presence, _)| *presence == DescriptorPresence::Present);
    let descriptor_code = if stdin_source {
        descriptors
            .binding("0")
            .and_then(|facts| facts.exact_content().map(str::to_owned))
    } else {
        descriptor
            .as_ref()
            .filter(|(presence, _)| *presence == DescriptorPresence::Present)
            .and_then(|(_, facts)| facts.exact_content().map(str::to_owned))
    };
    let mut network_endpoints = Vec::new();
    let mut descriptor_sources = Vec::new();
    if let Some((_, facts)) = &descriptor {
        network_endpoints.extend(
            facts
                .hosts()
                .iter()
                .cloned()
                .map(|host| (nah_proto::action::NetworkDirection::Inbound, host)),
        );
        descriptor_sources.extend(facts.producer_sources().iter().copied());
    }
    Some(Lowering {
        complete: (!file_source || target.is_some()) && descriptor_complete,
        operation: None,
        filesystems: target
            .into_iter()
            .map(|target| (target, FilesystemOperation::Read, false))
            .collect(),
        network_outbound: false,
        stdin_flows: stdin_source,
        stdout_flows: true,
        network_endpoints,
        descriptor_sources,
        descriptor_sinks: Vec::new(),
        descriptor_code,
    })
}

pub(crate) fn execution_source(program: &str, arguments: &[Word]) -> Option<SemanticCode> {
    if matches!(program, "." | "source") {
        return arguments.first().map(|argument| {
            if static_argument(argument)
                .as_deref()
                .is_some_and(is_stdin_path)
            {
                SemanticCode::SHELL_STDIN
            } else {
                SemanticCode::SHELL_FILE
            }
        });
    }
    if shell_program(program) {
        if shell_syntax_check(arguments) {
            return None;
        }
        return Some(shell_execution(arguments).0);
    }
    let first = arguments.first().and_then(static_argument);
    let lower_program = normalized_execution_program(program);
    if matches!(
        lower_program.as_str(),
        "node"
            | "nodejs"
            | "ruby"
            | "php"
            | "lua"
            | "R"
            | "Rscript"
            | "r"
            | "rscript"
            | "julia"
            | "swift"
    ) || is_python_interpreter(&lower_program)
        || is_perl_interpreter(&lower_program)
    {
        return Some(match first.as_deref() {
            Some("-c" | "-e") => SemanticCode::INTERPRETER_INLINE,
            Some("-") => SemanticCode::INTERPRETER_STDIN,
            Some("--") if arguments.len() == 1 => SemanticCode::INTERPRETER_STDIN,
            Some("--") => SemanticCode::INTERPRETER_FILE,
            None if arguments.is_empty() => SemanticCode::INTERPRETER_STDIN,
            None => SemanticCode::INTERPRETER_FILE,
            Some(argument) if argument.starts_with('-') => SemanticCode::INTERPRETER_INLINE,
            Some(_) => SemanticCode::INTERPRETER_FILE,
        });
    }
    if matches!(lower_program.as_str(), "powershell" | "pwsh") {
        return powershell_execution(arguments).map(|execution| execution.0);
    }
    if lower_program == "cmd" {
        return Some(if arguments.is_empty() {
            SemanticCode::INTERPRETER_STDIN
        } else {
            SemanticCode::INTERPRETER_INLINE
        });
    }
    None
}

pub(crate) fn execution_code(program: &str, arguments: &[Word], source: &str) -> Option<String> {
    if !matches!(
        source,
        "shell-inline" | "interpreter-inline" | "encoded-command"
    ) {
        return None;
    }
    let values = arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()?;
    let lower = normalized_execution_program(program);
    if shell_program(program) {
        let index = values.iter().position(|argument| {
            argument
                .strip_prefix('-')
                .is_some_and(|flags| !flags.starts_with('-') && flags.contains('c'))
        })?;
        return values.get(index + 1).cloned();
    }
    if is_python_interpreter(&lower) {
        return inline_option_code(&values, "-c", python_attached_code);
    }
    if is_perl_interpreter(&lower) {
        return inline_option_code(&values, "-e", perl_attached_code)
            .or_else(|| inline_option_code(&values, "-E", perl_attached_code));
    }
    if matches!(lower.as_str(), "node" | "nodejs") {
        return simple_inline_option(
            &values,
            &["-e", "--eval", "-p", "--print"],
            &["--eval=", "--print="],
        )
        .map(|(_, code)| code);
    }
    if lower == "ruby" {
        return simple_inline_option(&values, &["-e"], &["-e"]).map(|(_, code)| code);
    }
    if lower == "php" {
        return simple_inline_option(&values, &["-r"], &["-r"]).map(|(_, code)| code);
    }
    if matches!(lower.as_str(), "r" | "rscript") {
        return simple_inline_option(&values, &["-e"], &["-e"]).map(|(_, code)| code);
    }
    if lower == "julia" {
        return simple_inline_option(&values, &["-e", "--eval"], &["-e", "--eval="])
            .map(|(_, code)| code);
    }
    if matches!(lower.as_str(), "lua" | "swift") {
        let index = values
            .iter()
            .position(|argument| matches!(argument.as_str(), "-c" | "-e"))?;
        return values.get(index + 1).cloned();
    }
    if matches!(lower.as_str(), "powershell" | "pwsh") {
        let index = values
            .iter()
            .position(|argument| powershell_inline_option(argument))?;
        return values.get(index + 1).cloned();
    }
    if lower == "cmd" {
        let (index, attached) = values.iter().enumerate().find_map(|(index, argument)| {
            argument
                .get(..2)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/c"))
                .then(|| (index, &argument[2..]))
        })?;
        let mut code = Vec::new();
        if !attached.is_empty() {
            code.push(attached.to_owned());
        }
        code.extend_from_slice(&values[index + 1..]);
        return (!code.is_empty()).then(|| code.join(" "));
    }
    None
}

pub(crate) fn shell_program(program: &str) -> bool {
    matches!(
        normalized_execution_program(program).as_str(),
        "ash" | "bash" | "dash" | "ksh" | "mksh" | "sh" | "zsh"
    )
}

pub(crate) fn shell_syntax_check(arguments: &[Word]) -> bool {
    let mut noexec = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index).and_then(static_argument) {
        if argument == "--" || argument == "-" || !argument.starts_with(['-', '+']) {
            break;
        }
        if matches!(argument.as_str(), "--noexec") {
            noexec = true;
            index += 1;
            continue;
        }
        if argument.starts_with("--") {
            index += 1;
            continue;
        }
        let enabled = argument.starts_with('-');
        let flags = &argument[1..];
        if flags.contains('n') {
            noexec = enabled;
        }
        if flags.ends_with('o') || flags.ends_with('O') {
            if arguments
                .get(index + 1)
                .and_then(static_argument)
                .as_deref()
                == Some("noexec")
            {
                noexec = enabled;
            }
            index += 1;
        }
        if flags.contains('c') {
            break;
        }
        index += 1;
    }
    noexec
}

pub(crate) fn is_python_interpreter(program: &str) -> bool {
    if matches!(
        program,
        "py" | "python" | "python2" | "python3" | "pypy" | "pypy2" | "pypy3"
    ) {
        return true;
    }
    ["python2.", "python3.", "pypy2.", "pypy3."]
        .iter()
        .any(|prefix| {
            program.strip_prefix(prefix).is_some_and(|version| {
                let version = version.strip_suffix('t').unwrap_or(version);
                !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
}

pub(crate) fn is_perl_interpreter(program: &str) -> bool {
    if program == "perl" {
        return true;
    }
    program.strip_prefix("perl5.").is_some_and(|version| {
        let version = version.split('-').next().unwrap_or(version);
        !version.is_empty()
            && version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn inline_option_code(
    arguments: &[String],
    exact: &str,
    attached: fn(&str) -> Option<&str>,
) -> Option<String> {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .enumerate()
        .find_map(|(index, argument)| {
            if argument == exact {
                arguments.get(index + 1).cloned()
            } else {
                attached(argument).map(str::to_owned)
            }
        })
}

fn simple_inline_option(
    arguments: &[String],
    exact: &[&str],
    attached: &[&str],
) -> Option<(usize, String)> {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .enumerate()
        .find_map(|(index, argument)| {
            if exact.contains(&argument.as_str()) {
                arguments
                    .get(index + 1)
                    .cloned()
                    .map(|code| (index + 1, code))
            } else {
                attached.iter().find_map(|prefix| {
                    argument
                        .strip_prefix(prefix)
                        .filter(|code| !code.is_empty())
                        .map(|code| (index, code.to_owned()))
                })
            }
        })
}

fn python_attached_code(argument: &str) -> Option<&str> {
    let flags = argument.strip_prefix('-')?;
    if flags.starts_with('-') {
        return None;
    }
    let index = flags.find('c')?;
    flags[..index]
        .bytes()
        .all(|flag| b"bBdiIOqsSuvVx".contains(&flag))
        .then(|| &flags[index + 1..])
        .filter(|code| !code.is_empty())
}

fn perl_attached_code(argument: &str) -> Option<&str> {
    ["-e", "-E", "-we", "-wE", "-ne", "-nE", "-pe", "-pE"]
        .iter()
        .find_map(|prefix| argument.strip_prefix(prefix))
        .filter(|code| !code.is_empty())
}

fn normalized_execution_program(program: &str) -> String {
    let program = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|suffix| program.strip_suffix(suffix))
        .unwrap_or(&program)
        .to_owned()
}

pub(crate) fn execution_operand_index(
    program: &str,
    arguments: &[Word],
    source: &str,
) -> Option<usize> {
    if source.ends_with("-file") {
        let argument = execution_file_argument(program, arguments, source)?;
        if exact_process_substitution(argument)
            || descriptor_reference_path(argument.raw()).is_some()
        {
            return None;
        }
        return arguments
            .iter()
            .position(|candidate| std::ptr::eq(candidate, argument));
    }
    if !matches!(source, "shell-inline" | "interpreter-inline") {
        return None;
    }
    if shell_program(program) {
        let option = arguments.iter().position(|argument| {
            static_argument(argument)
                .as_deref()
                .and_then(|argument| argument.strip_prefix('-'))
                .is_some_and(|flags| !flags.starts_with('-') && flags.contains('c'))
        })?;
        let payload = option
            + 1
            + usize::from(
                arguments
                    .get(option + 1)
                    .and_then(static_argument)
                    .as_deref()
                    == Some("--"),
            );
        return (payload < arguments.len()).then_some(payload);
    }
    let lower = normalized_execution_program(program);
    if matches!(lower.as_str(), "powershell" | "pwsh") {
        return arguments
            .iter()
            .position(|argument| {
                static_argument(argument)
                    .is_some_and(|argument| powershell_inline_option(&argument))
            })
            .and_then(|index| (index + 1 < arguments.len()).then_some(index + 1));
    }
    if lower == "cmd" {
        return arguments.iter().enumerate().find_map(|(index, argument)| {
            let argument = static_argument(argument)?;
            let attached = argument
                .get(..2)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/c"));
            if !attached {
                None
            } else if argument.len() > 2 {
                Some(index)
            } else {
                (index + 1 < arguments.len()).then_some(index + 1)
            }
        });
    }
    if is_python_interpreter(&lower) {
        return arguments
            .iter()
            .take_while(|argument| static_argument(argument).as_deref() != Some("--"))
            .enumerate()
            .find_map(|(index, argument)| {
                let argument = static_argument(argument)?;
                if argument == "-c" {
                    (index + 1 < arguments.len()).then_some(index + 1)
                } else {
                    python_attached_code(&argument).map(|_| index)
                }
            });
    }
    if is_perl_interpreter(&lower) {
        return arguments
            .iter()
            .take_while(|argument| static_argument(argument).as_deref() != Some("--"))
            .enumerate()
            .find_map(|(index, argument)| {
                let argument = static_argument(argument)?;
                if matches!(argument.as_str(), "-e" | "-E") {
                    (index + 1 < arguments.len()).then_some(index + 1)
                } else {
                    perl_attached_code(&argument).map(|_| index)
                }
            });
    }
    let values = arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()?;
    let inline = match lower.as_str() {
        "node" | "nodejs" => simple_inline_option(
            &values,
            &["-e", "--eval", "-p", "--print"],
            &["--eval=", "--print="],
        ),
        "ruby" => simple_inline_option(&values, &["-e"], &["-e"]),
        "php" => simple_inline_option(&values, &["-r"], &["-r"]),
        "r" | "rscript" => simple_inline_option(&values, &["-e"], &["-e"]),
        "julia" => simple_inline_option(&values, &["-e", "--eval"], &["-e", "--eval="]),
        _ => None,
    };
    if let Some((index, _)) = inline {
        return Some(index);
    }
    if matches!(lower.as_str(), "lua" | "swift") {
        return arguments
            .iter()
            .position(|argument| matches!(static_argument(argument).as_deref(), Some("-c" | "-e")))
            .and_then(|index| (index + 1 < arguments.len()).then_some(index + 1));
    }
    None
}

fn exact_process_substitution(argument: &Word) -> bool {
    matches!(
        argument.substitutions(),
        [Substitution::ProcessInput { .. }] if argument.raw().starts_with("<(")
            && argument.raw().ends_with(')')
    ) || matches!(
        argument.substitutions(),
        [Substitution::ProcessOutput { .. }] if argument.raw().starts_with(">(")
            && argument.raw().ends_with(')')
    )
}

fn powershell_encoded_option(argument: &str) -> bool {
    matches!(
        argument.to_ascii_lowercase().as_str(),
        "-encodedcommand" | "-enc" | "-ec" | "-e"
    )
}

fn powershell_command_option(argument: &str) -> bool {
    let argument = argument.to_ascii_lowercase();
    matches!(argument.as_str(), "-c" | "-commandwithargs" | "-cwa")
        || argument.len() >= 4 && "-command".starts_with(&argument)
}

fn powershell_inline_option(argument: &str) -> bool {
    powershell_encoded_option(argument) || powershell_command_option(argument)
}

fn powershell_execution(arguments: &[Word]) -> Option<(SemanticCode, Option<usize>)> {
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments.get(index).and_then(static_argument) else {
            return Some((SemanticCode::INTERPRETER_FILE, Some(index)));
        };
        let option = argument.to_ascii_lowercase();
        match option.as_str() {
            "-help" | "-h" | "-?" | "/?" => return None,
            option if powershell_encoded_option(option) => {
                return Some((
                    if arguments
                        .get(index + 1)
                        .and_then(static_argument)
                        .is_some_and(|argument| base64_argument(&argument))
                    {
                        SemanticCode::ENCODED_COMMAND
                    } else {
                        SemanticCode::INTERPRETER_INLINE
                    },
                    None,
                ));
            }
            option if powershell_command_option(option) => {
                return Some((
                    if arguments
                        .get(index + 1)
                        .and_then(static_argument)
                        .as_deref()
                        == Some("-")
                    {
                        SemanticCode::INTERPRETER_STDIN
                    } else {
                        SemanticCode::INTERPRETER_INLINE
                    },
                    None,
                ));
            }
            "-file" | "-f" => {
                return Some((SemanticCode::INTERPRETER_FILE, Some(index + 1)));
            }
            "--" => {
                return if index + 1 < arguments.len() {
                    Some((SemanticCode::INTERPRETER_FILE, Some(index + 1)))
                } else {
                    Some((SemanticCode::INTERPRETER_STDIN, None))
                };
            }
            "-configurationfile" | "-configurationname" | "-config" | "-custompipename"
            | "-executionpolicy" | "-ex" | "-ep" | "-inputformat" | "-in" | "-if"
            | "-outputformat" | "-o" | "-of" | "-settingsfile" | "-settings" | "-version"
            | "-v" | "-windowstyle" | "-w" | "-workingdirectory" | "-wd" => index += 2,
            "-interactive" | "-i" | "-login" | "-l" | "-mta" | "-noexit" | "-noe" | "-nologo"
            | "-nol" | "-noninteractive" | "-noni" | "-noprofile" | "-nop"
            | "-noprofileloadtime" | "-sshservermode" | "-sshs" | "-sta" => index += 1,
            _ if argument.starts_with('-') => {
                return Some((SemanticCode::INTERPRETER_INLINE, None));
            }
            _ => return Some((SemanticCode::INTERPRETER_FILE, Some(index))),
        }
    }
    Some((SemanticCode::INTERPRETER_STDIN, None))
}

fn base64_argument(argument: &str) -> bool {
    let payload = argument.trim_end_matches('=');
    let padding = argument.len() - payload.len();
    !argument.is_empty()
        && argument.len().is_multiple_of(4)
        && padding <= 2
        && payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && argument
            .bytes()
            .skip_while(|byte| *byte != b'=')
            .all(|byte| byte == b'=')
}

fn execution_file(program: &str, arguments: &[Word], source: &str) -> Option<String> {
    execution_file_argument(program, arguments, source).and_then(file_argument)
}

fn execution_file_argument<'a>(
    program: &str,
    arguments: &'a [Word],
    source: &str,
) -> Option<&'a Word> {
    if !source.ends_with("-file") {
        return None;
    }
    if matches!(program, "." | "source") {
        return arguments.first();
    }
    if shell_program(program) {
        return shell_execution(arguments)
            .1
            .and_then(|index| arguments.get(index));
    }
    if matches!(
        normalized_execution_program(program).as_str(),
        "powershell" | "pwsh"
    ) {
        return powershell_execution(arguments)
            .and_then(|execution| execution.1)
            .and_then(|index| arguments.get(index));
    }
    if arguments.first().and_then(static_argument).as_deref() == Some("--") {
        arguments.get(1)
    } else {
        arguments.first()
    }
}

fn file_argument(argument: &Word) -> Option<String> {
    static_argument(argument).or_else(|| descriptor_reference_path(argument.raw()))
}

fn shell_execution(arguments: &[Word]) -> (SemanticCode, Option<usize>) {
    let mut index = 0;
    let mut interactive = false;
    while let Some(argument) = arguments.get(index).and_then(static_argument) {
        if argument == "--" {
            return if index + 1 < arguments.len() {
                (SemanticCode::SHELL_FILE, Some(index + 1))
            } else {
                (SemanticCode::SHELL_STDIN, None)
            };
        }
        if argument == "-" {
            return (SemanticCode::SHELL_STDIN, None);
        }
        if !argument.starts_with(['-', '+']) {
            if is_stdin_path(&argument) {
                return (SemanticCode::SHELL_STDIN, None);
            }
            return (SemanticCode::SHELL_FILE, Some(index));
        }
        if argument.starts_with("--") {
            index += 1;
            continue;
        }
        let enabled = argument.starts_with('-');
        let flags = &argument[1..];
        if flags.contains('i') {
            interactive = enabled;
        }
        if enabled && flags.contains('c') {
            return (SemanticCode::SHELL_INLINE, None);
        }
        if enabled && flags.contains('s') {
            return (SemanticCode::SHELL_STDIN, None);
        }
        index += 1;
        if flags.ends_with('o') || flags.ends_with('O') {
            index += 1;
        }
    }
    if index == arguments.len() {
        (
            if interactive {
                SemanticCode::SHELL_INTERACTIVE
            } else {
                SemanticCode::SHELL_STDIN
            },
            None,
        )
    } else {
        (
            SemanticCode::SHELL_FILE,
            (index < arguments.len()).then_some(index),
        )
    }
}

fn is_stdin_path(path: &str) -> bool {
    matches!(path, "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

fn static_argument(argument: &Word) -> Option<String> {
    static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
}

fn decode(program: &str, arguments: &[Word]) -> Option<(bool, bool)> {
    let values = arguments
        .iter()
        .filter_map(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
        })
        .collect::<Vec<_>>();
    let operands = values
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    let detected = match program {
        "base64" => values.iter().any(|argument| {
            argument == "--decode"
                || argument
                    .strip_prefix('-')
                    .filter(|argument| !argument.starts_with('-'))
                    .is_some_and(|flags| flags.contains('d') || flags.contains('D'))
        }),
        "xxd" => values.iter().any(|argument| {
            argument
                .strip_prefix('-')
                .filter(|argument| !argument.starts_with('-'))
                .is_some_and(|flags| flags.contains('r'))
        }),
        "zcat" | "bzcat" | "xzcat" => true,
        "gzip" | "bzip2" | "xz" => values.iter().any(|argument| {
            argument == "--decompress"
                || (argument.starts_with('-')
                    && !argument.starts_with("--")
                    && argument[1..].contains('d'))
        }),
        "openssl" => {
            values
                .first()
                .is_some_and(|argument| matches!(argument.as_str(), "enc" | "base64"))
                && values
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "-d" | "--decrypt"))
        }
        "unzip" => values.iter().any(|argument| argument == "-p"),
        "tar" | "bsdtar" => {
            values.iter().any(|argument| {
                argument == "--extract"
                    || argument
                        .strip_prefix('-')
                        .filter(|argument| !argument.starts_with('-'))
                        .is_some_and(|flags| flags.contains('x'))
            }) && values.iter().any(|argument| {
                argument == "--to-stdout"
                    || argument
                        .strip_prefix('-')
                        .filter(|argument| !argument.starts_with('-'))
                        .is_some_and(|flags| flags.contains('O'))
            })
        }
        _ => false,
    };
    if !detected {
        return None;
    }
    let stdout_flows = match program {
        "gzip" | "bzip2" | "xz" => {
            operands.is_empty()
                || values.iter().any(|argument| {
                    argument == "--stdout"
                        || (argument.starts_with('-')
                            && !argument.starts_with("--")
                            && argument[1..].contains('c'))
                })
        }
        "xxd" => operands.len() < 2,
        "openssl" => !values.iter().any(|argument| argument == "-out"),
        _ => true,
    };
    Some((operands.is_empty(), stdout_flows))
}
