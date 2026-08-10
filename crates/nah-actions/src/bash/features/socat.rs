//! Owns socat address parsing and transfer lowering.

use std::iter::Peekable;

use nah_parse::Word;
use nah_proto::action::{FilesystemOperation, NetworkDirection};

use crate::bash_descriptor_state::{
    DescriptorFacts, DescriptorPresence, DescriptorState, NetworkEndpoint,
};
use crate::bash_descriptors::exact_descriptor_alias_name;
use crate::bash_model::VariableValue;
use crate::shell_word::{shell_literal_prefix, static_word};

pub(crate) struct SocatLowering {
    pub(crate) complete: bool,
    pub(crate) filesystems: Vec<(String, FilesystemOperation, bool)>,
    pub(crate) stdin_flows: bool,
    pub(crate) stdout_flows: bool,
    pub(crate) network: bool,
    pub(crate) network_endpoints: Vec<NetworkEndpoint>,
    pub(crate) descriptor_sources: Vec<usize>,
    pub(crate) descriptor_sinks: Vec<usize>,
}

#[derive(Clone, Copy)]
enum SocatDirection {
    Both,
    Forward,
    Reverse,
}

#[derive(Clone)]
enum SocatAddress {
    Network,
    File {
        path: String,
        readable: bool,
        writable: bool,
        fifo: bool,
    },
    DynamicFile {
        readable: bool,
    },
    Stdin,
    Stdout {
        fd: String,
    },
    Stdio,
    Executor {
        payload: Option<String>,
        shell: bool,
        stderr: bool,
        chdir: Option<String>,
    },
    Descriptor {
        fd: String,
    },
    Other,
}

struct SocatOperand {
    read: SocatAddress,
    write: SocatAddress,
}

struct SocatAnalysis {
    complete: bool,
    direction: SocatDirection,
    operands: Vec<SocatOperand>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SocatExecutorFlows {
    pub(crate) outputs_to_parent: bool,
    pub(crate) parent_to_inputs: bool,
    pub(crate) all_stages_to_parent: bool,
}

struct ParsedAddress {
    keyword: String,
    parameters: Vec<String>,
    options: Vec<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SocatSeparator {
    Colon,
    Comma,
    Dual,
}

enum SocatLexContext {
    HardQuote,
    SoftQuote,
    Nest(char),
}

struct SocatLexer<'a> {
    chars: Peekable<std::str::Chars<'a>>,
}

pub(crate) fn socat(
    arguments: &[Word],
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> Option<SocatLowering> {
    let analysis = analyze_socat(arguments, variables)?;
    let mut network = false;
    let mut network_endpoints = Vec::new();
    let mut filesystems = Vec::new();
    let mut descriptors_complete = true;
    let mut stdin_flows = false;
    let mut stdout_flows = false;
    let mut descriptor_sources = Vec::new();
    let mut descriptor_sinks = Vec::new();

    for (index, operand) in analysis.operands.iter().enumerate() {
        if socat_address_is_source(analysis.direction, index) {
            network |= matches!(operand.read, SocatAddress::Network);
            add_descriptor_effects(
                &operand.read,
                NetworkDirection::Inbound,
                descriptors,
                variables,
                &mut network_endpoints,
                &mut descriptor_sources,
            );
            descriptors_complete &= descriptor_is_complete(&operand.read, descriptors, variables);
            stdin_flows |= address_reads_stdin(&operand.read, descriptors, variables);
            if let SocatAddress::File {
                path,
                readable: true,
                ..
            } = &operand.read
            {
                filesystems.push((path.clone(), FilesystemOperation::Read, false));
            }
        }
        if socat_address_is_sink(analysis.direction, index) {
            network |= matches!(operand.write, SocatAddress::Network);
            add_descriptor_effects(
                &operand.write,
                NetworkDirection::Outbound,
                descriptors,
                variables,
                &mut network_endpoints,
                &mut descriptor_sinks,
            );
            descriptors_complete &= descriptor_is_complete(&operand.write, descriptors, variables);
            stdout_flows |= address_writes_stdout(&operand.write, descriptors, variables);
            if let SocatAddress::File {
                path,
                writable: true,
                ..
            } = &operand.write
            {
                filesystems.push((path.clone(), FilesystemOperation::Write, false));
            }
        }
    }

    network_endpoints.sort();
    network_endpoints.dedup();
    descriptor_sources.sort_unstable();
    descriptor_sources.dedup();
    descriptor_sinks.sort_unstable();
    descriptor_sinks.dedup();
    Some(SocatLowering {
        complete: analysis.complete && descriptors_complete,
        filesystems,
        stdin_flows,
        stdout_flows,
        network,
        network_endpoints,
        descriptor_sources,
        descriptor_sinks,
    })
}

pub(crate) fn socat_shell_operation(
    arguments: &[Word],
    code_program: fn(&str) -> bool,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> Option<&'static str> {
    let analysis = analyze_socat(arguments, variables)?;
    let network = analysis
        .operands
        .iter()
        .enumerate()
        .any(|(index, operand)| {
            socat_address_is_source(analysis.direction, index)
                && address_is_network(&operand.read, descriptors, variables)
                || socat_address_is_sink(analysis.direction, index)
                    && address_is_network(&operand.write, descriptors, variables)
        });
    let code_exec = active_addresses(&analysis).any(|address| {
        let SocatAddress::Executor { payload, shell, .. } = address else {
            return false;
        };
        let Some(payload) = payload else {
            return *shell;
        };
        if *shell {
            return code_program(payload)
                || payload.trim_start().starts_with(['$', '`'])
                || payload.contains(['\n', '\r']);
        }
        socat_exec_argv(payload)
            .map(|arguments| arguments.join(" "))
            .is_some_and(|command| code_program(&command))
    });
    (network && code_exec).then_some("network-shell")
}

pub(crate) fn socat_executor_payloads(
    arguments: &[Word],
    variables: &[(String, VariableValue)],
) -> Vec<(String, bool)> {
    let Some(analysis) = analyze_socat(arguments, variables) else {
        return Vec::new();
    };
    let mut payloads = active_addresses(&analysis)
        .filter_map(|address| {
            let SocatAddress::Executor {
                payload: Some(payload),
                shell,
                chdir,
                ..
            } = address
            else {
                return None;
            };
            let payload = if *shell {
                payload.clone()
            } else {
                decoded_socat_exec_payload(payload)?
            };
            Some((
                chdir
                    .as_deref()
                    .map_or(payload.clone(), |cwd| command_in_directory(cwd, &payload)),
                false,
            ))
        })
        .collect::<Vec<_>>();
    payloads.sort();
    payloads.dedup();
    payloads
}

pub(crate) fn socat_executor_flows(
    arguments: &[Word],
    variables: &[(String, VariableValue)],
) -> SocatExecutorFlows {
    let Some(analysis) = analyze_socat(arguments, variables) else {
        return SocatExecutorFlows::default();
    };
    let mut flows = SocatExecutorFlows::default();
    for (index, operand) in analysis.operands.iter().enumerate() {
        if socat_address_is_source(analysis.direction, index)
            && let SocatAddress::Executor { stderr, .. } = &operand.read
        {
            flows.outputs_to_parent = true;
            flows.all_stages_to_parent |= *stderr;
        }
        if socat_address_is_sink(analysis.direction, index)
            && matches!(operand.write, SocatAddress::Executor { .. })
        {
            flows.parent_to_inputs = true;
        }
    }
    flows
}

pub(crate) fn socat_fifo_creations(
    arguments: &[Word],
    variables: &[(String, VariableValue)],
) -> Vec<String> {
    let Some(analysis) = analyze_socat(arguments, variables) else {
        return Vec::new();
    };
    let mut paths = active_addresses(&analysis)
        .filter_map(|address| match address {
            SocatAddress::File {
                path, fifo: true, ..
            } => Some(path.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

pub(crate) fn socat_has_dynamic_file_source(
    arguments: &[Word],
    variables: &[(String, VariableValue)],
) -> bool {
    let Some(analysis) = analyze_socat(arguments, variables) else {
        return false;
    };
    analysis
        .operands
        .iter()
        .enumerate()
        .any(|(index, operand)| {
            socat_address_is_source(analysis.direction, index)
                && matches!(
                    operand.read,
                    SocatAddress::DynamicFile { readable: true, .. }
                )
        })
}

fn analyze_socat(
    arguments: &[Word],
    variables: &[(String, VariableValue)],
) -> Option<SocatAnalysis> {
    let mut complete = true;
    let mut direction = SocatDirection::Both;
    let mut operands = Vec::new();
    let mut index = 0;
    let mut options = true;
    while index < arguments.len() {
        let value = known_socat_word(&arguments[index], variables);
        if options && operands.is_empty() {
            match value.as_deref() {
                Some(
                    "-h" | "-hh" | "-hhh" | "-?" | "-??" | "-???" | "-V" | "--help" | "--version",
                ) => return None,
                Some("--") => {
                    options = false;
                    index += 1;
                    continue;
                }
                Some("-u") => {
                    direction = SocatDirection::Forward;
                    index += 1;
                    continue;
                }
                Some("-U") => {
                    direction = SocatDirection::Reverse;
                    index += 1;
                    continue;
                }
                Some("-") => {}
                Some(option) if option.starts_with('-') => {
                    if socat_option_takes_value(option) {
                        if index + 1 == arguments.len() {
                            complete = false;
                        }
                        index += 2;
                    } else {
                        index += 1;
                    }
                    continue;
                }
                None if arguments[index].raw().starts_with('-') => {
                    complete = false;
                    index += 1;
                    continue;
                }
                _ => {}
            }
        }
        operands.push(classify_socat_operand(&arguments[index], variables));
        index += 1;
    }
    complete &= operands.len() == 2;
    for (_, operand_complete) in &operands {
        complete &= *operand_complete;
    }
    Some(SocatAnalysis {
        complete,
        direction,
        operands: operands
            .into_iter()
            .take(2)
            .map(|(operand, _)| operand)
            .collect(),
    })
}

fn socat_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "-r" | "-R" | "-b" | "-t" | "-T" | "-L" | "-W" | "-lf" | "-lp"
    )
}

fn classify_socat_operand(
    argument: &Word,
    variables: &[(String, VariableValue)],
) -> (SocatOperand, bool) {
    let Some(value) = known_socat_word(argument, variables) else {
        let (address, complete) = classify_dynamic_socat_address(argument.raw());
        return (
            SocatOperand {
                read: address.clone(),
                write: address,
            },
            complete,
        );
    };
    let Ok((read, write)) = parse_socat_operand(&value) else {
        return (
            SocatOperand {
                read: SocatAddress::Other,
                write: SocatAddress::Other,
            },
            false,
        );
    };
    let (read, read_complete) = classify_parsed_socat_address(read);
    let (write, write_complete) = write.map_or_else(
        || (read.clone(), read_complete),
        classify_parsed_socat_address,
    );
    (
        SocatOperand { read, write },
        read_complete && write_complete,
    )
}

fn classify_dynamic_socat_address(raw: &str) -> (SocatAddress, bool) {
    if visible_network_endpoint(raw) {
        return (SocatAddress::Network, false);
    }
    if visible_dynamic_executor(raw) {
        return (
            SocatAddress::Executor {
                payload: None,
                shell: true,
                stderr: false,
                chdir: None,
            },
            false,
        );
    }
    if let Some(fd) = dynamic_socat_descriptor(raw) {
        return (SocatAddress::Descriptor { fd }, true);
    }
    if let Some(readable) = visible_dynamic_file(raw) {
        return (SocatAddress::DynamicFile { readable }, false);
    }
    (SocatAddress::Other, false)
}

fn classify_parsed_socat_address(address: ParsedAddress) -> (SocatAddress, bool) {
    let lower = address.keyword.to_ascii_lowercase();
    if network_endpoint_kind(&lower)
        && (!address.parameters.is_empty() || lower == "tun")
        && (lower != "tun" || address.parameters.len() <= 1)
    {
        return (SocatAddress::Network, true);
    }
    if address.parameters.is_empty() {
        match lower.as_str() {
            "stdin" => return (SocatAddress::Stdin, true),
            "stdout" => return (SocatAddress::Stdout { fd: "1".into() }, true),
            "stderr" => return (SocatAddress::Stdout { fd: "2".into() }, true),
            "-" | "stdio" => return (SocatAddress::Stdio, true),
            "shell" => {
                return (
                    SocatAddress::Executor {
                        payload: None,
                        shell: true,
                        stderr: socat_option_enabled(&address.options, "stderr"),
                        chdir: socat_chdir(&address.options),
                    },
                    true,
                );
            }
            "pipe" | "fifo" => return (SocatAddress::Other, true),
            _ => {}
        }
        if address.keyword.len() == 1
            && let Some(fd) = parse_socat_fd(&address.keyword)
        {
            return (SocatAddress::Descriptor { fd }, true);
        }
        if address.keyword.contains('/') {
            let path = apply_socat_chdir(address.keyword, socat_chdir(&address.options).as_deref());
            return (
                SocatAddress::File {
                    path,
                    readable: !socat_option_enabled(&address.options, "wronly"),
                    writable: !socat_option_enabled(&address.options, "rdonly"),
                    fifo: false,
                },
                true,
            );
        }
        return (SocatAddress::Other, false);
    }
    match lower.as_str() {
        "exec" | "system" | "shell" if address.parameters.len() == 1 => {
            let shell = lower != "exec";
            let payload = address.parameters.into_iter().next();
            let complete = shell || payload.as_deref().and_then(socat_exec_argv).is_some();
            (
                SocatAddress::Executor {
                    payload,
                    shell,
                    stderr: socat_option_enabled(&address.options, "stderr"),
                    chdir: socat_chdir(&address.options),
                },
                complete,
            )
        }
        "fd" if address.parameters.len() == 1 => {
            let Some(fd) = parse_socat_fd(&address.parameters[0]) else {
                return (SocatAddress::Other, false);
            };
            (SocatAddress::Descriptor { fd }, true)
        }
        "open" | "file" | "gopen" | "create" | "creat" if address.parameters.len() == 1 => {
            let create_only = matches!(lower.as_str(), "create" | "creat");
            let path = apply_socat_chdir(
                address
                    .parameters
                    .into_iter()
                    .next()
                    .expect("one parameter"),
                socat_chdir(&address.options).as_deref(),
            );
            (
                SocatAddress::File {
                    path,
                    readable: !create_only && !socat_option_enabled(&address.options, "wronly"),
                    writable: create_only || !socat_option_enabled(&address.options, "rdonly"),
                    fifo: false,
                },
                true,
            )
        }
        "pipe" | "fifo" if address.parameters.len() == 1 => {
            let path = apply_socat_chdir(
                address
                    .parameters
                    .into_iter()
                    .next()
                    .expect("one parameter"),
                socat_chdir(&address.options).as_deref(),
            );
            (
                SocatAddress::File {
                    path,
                    readable: true,
                    writable: true,
                    fifo: true,
                },
                true,
            )
        }
        _ => (SocatAddress::Other, false),
    }
}

fn parse_socat_operand(value: &str) -> Result<(ParsedAddress, Option<ParsedAddress>), ()> {
    let mut lexer = SocatLexer::new(value);
    let (read, separator) = parse_socat_address(&mut lexer)?;
    match separator {
        None => Ok((read, None)),
        Some(SocatSeparator::Dual) => {
            let (write, separator) = parse_socat_address(&mut lexer)?;
            if separator.is_some() {
                return Err(());
            }
            Ok((read, Some(write)))
        }
        Some(_) => Err(()),
    }
}

fn parse_socat_address(
    lexer: &mut SocatLexer<'_>,
) -> Result<(ParsedAddress, Option<SocatSeparator>), ()> {
    let (keyword, mut separator) = lexer.token(true)?;
    if keyword.is_empty() {
        return Err(());
    }
    let mut parameters = Vec::new();
    while separator == Some(SocatSeparator::Colon) {
        let (parameter, next) = lexer.token(true)?;
        parameters.push(parameter);
        separator = next;
    }
    let mut options = Vec::new();
    if separator == Some(SocatSeparator::Comma) {
        loop {
            let (option, next) = lexer.token(false)?;
            if option.is_empty() {
                return Err(());
            }
            options.push(option);
            separator = next;
            if separator != Some(SocatSeparator::Comma) {
                break;
            }
        }
    }
    Ok((
        ParsedAddress {
            keyword,
            parameters,
            options,
        },
        separator,
    ))
}

impl<'a> SocatLexer<'a> {
    fn new(value: &'a str) -> Self {
        Self {
            chars: value.chars().peekable(),
        }
    }

    fn token(&mut self, colon_terminates: bool) -> Result<(String, Option<SocatSeparator>), ()> {
        let mut output = String::new();
        let mut contexts = Vec::new();
        while let Some(character) = self.chars.next() {
            if matches!(contexts.last(), Some(SocatLexContext::HardQuote)) {
                match character {
                    '\'' => {
                        contexts.pop();
                    }
                    '\\' => output.push(socat_escaped_character(&mut self.chars)?),
                    _ => output.push(character),
                }
                continue;
            }
            if matches!(contexts.last(), Some(SocatLexContext::SoftQuote)) && character == '"' {
                contexts.pop();
                continue;
            }
            if let Some(SocatLexContext::Nest(expected)) = contexts.last()
                && character == *expected
            {
                contexts.pop();
                output.push(character);
                continue;
            }
            if contexts.is_empty() {
                if character == '!' && self.chars.peek() == Some(&'!') {
                    self.chars.next();
                    return Ok((output, Some(SocatSeparator::Dual)));
                }
                if character == ',' {
                    return Ok((output, Some(SocatSeparator::Comma)));
                }
                if colon_terminates && character == ':' {
                    return Ok((output, Some(SocatSeparator::Colon)));
                }
            }
            match character {
                '\'' => contexts.push(SocatLexContext::HardQuote),
                '"' => contexts.push(SocatLexContext::SoftQuote),
                '(' => {
                    contexts.push(SocatLexContext::Nest(')'));
                    output.push(character);
                }
                '[' => {
                    contexts.push(SocatLexContext::Nest(']'));
                    output.push(character);
                }
                '{' => {
                    contexts.push(SocatLexContext::Nest('}'));
                    output.push(character);
                }
                '\\' => output.push(socat_escaped_character(&mut self.chars)?),
                _ => output.push(character),
            }
        }
        contexts.is_empty().then_some((output, None)).ok_or(())
    }
}

fn socat_escaped_character<I>(chars: &mut I) -> Result<char, ()>
where
    I: Iterator<Item = char>,
{
    Ok(match chars.next().ok_or(())? {
        '0' => return Err(()),
        'a' => '\u{7}',
        'b' => '\u{8}',
        'f' => '\u{c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\u{b}',
        character => character,
    })
}

fn parse_socat_fd(value: &str) -> Option<String> {
    let value = value.trim_start_matches(|character: char| character.is_ascii_whitespace());
    if value.starts_with('-') {
        return None;
    }
    let value = value.strip_prefix('+').unwrap_or(value);
    let (digits, radix) = if value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .is_some_and(|digits| digits.starts_with(|character: char| character.is_ascii_hexdigit()))
    {
        (
            value[2..]
                .split_at(
                    value[2..]
                        .find(|character: char| !character.is_ascii_hexdigit())
                        .unwrap_or(value.len() - 2),
                )
                .0,
            16,
        )
    } else if value.starts_with('0') {
        (
            value
                .split_at(
                    value
                        .find(|character: char| !matches!(character, '0'..='7'))
                        .unwrap_or(value.len()),
                )
                .0,
            8,
        )
    } else {
        (
            value
                .split_at(
                    value
                        .find(|character: char| !character.is_ascii_digit())
                        .unwrap_or(value.len()),
                )
                .0,
            10,
        )
    };
    if digits.is_empty() {
        return Some("0".into());
    }
    u32::from_str_radix(digits, radix)
        .ok()
        .map(|fd| fd.to_string())
}

fn dynamic_socat_descriptor(raw: &str) -> Option<String> {
    let raw = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    let address = raw.split_once(',').map_or(raw, |(address, _)| address);
    let (kind, fd) = address.split_once(':')?;
    let name = kind
        .eq_ignore_ascii_case("fd")
        .then(|| exact_descriptor_alias_name(fd))
        .flatten()?;
    Some(format!("{{{name}}}"))
}

fn known_socat_word(argument: &Word, variables: &[(String, VariableValue)]) -> Option<String> {
    if let Some(value) = static_word(argument.raw(), argument.substitutions().is_empty()) {
        return Some(value);
    }
    let expanded = expand_known_shell_variables(argument.raw(), variables)?;
    static_word(&expanded, true)
}

fn expand_known_shell_variables(
    raw: &str,
    variables: &[(String, VariableValue)],
) -> Option<String> {
    let mut output = String::new();
    let mut chars = raw.chars().peekable();
    let mut quote = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '\'') => {
                quote = Some('\'');
                output.push(character);
            }
            (None, '"') => {
                quote = Some('"');
                output.push(character);
            }
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                output.push(character);
            }
            (Some('\''), _) => output.push(character),
            (None | Some('"'), '\\') => {
                output.push(character);
                output.push(chars.next()?);
            }
            (None | Some('"'), '`') => return None,
            (None | Some('"'), '$') => {
                if chars.peek() == Some(&'(') {
                    return None;
                }
                let braced = chars.peek() == Some(&'{');
                if braced {
                    chars.next();
                }
                let mut name = String::new();
                while chars
                    .peek()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
                {
                    name.push(chars.next().expect("peeked variable name"));
                }
                if braced && chars.next() != Some('}') || name.is_empty() {
                    return None;
                }
                let value = variables
                    .iter()
                    .find_map(|(candidate, value)| (candidate == &name).then_some(value))
                    .and_then(VariableValue::as_static)?;
                if value.contains(['\0', '\n', '\r', '\'', '"', '`', '$', '*', '?', '[', ']'])
                    || quote.is_none() && value.contains(char::is_whitespace)
                {
                    return None;
                }
                output.push_str(value);
            }
            _ => output.push(character),
        }
    }
    quote.is_none().then_some(output)
}

fn visible_dynamic_executor(raw: &str) -> bool {
    let (prefix, dynamic) = shell_literal_prefix(raw);
    let kind = prefix
        .split_once(':')
        .map_or(prefix.as_str(), |(kind, _)| kind);
    dynamic
        && matches!(
            kind.to_ascii_lowercase().as_str(),
            "exec" | "system" | "shell"
        )
}

fn visible_dynamic_file(raw: &str) -> Option<bool> {
    let (prefix, dynamic) = shell_literal_prefix(raw);
    if !dynamic {
        return None;
    }
    let lower = prefix.to_ascii_lowercase();
    let create_only = lower.starts_with("create:") || lower.starts_with("creat:");
    let explicit = create_only
        || ["open:", "file:", "gopen:", "pipe:", "fifo:"]
            .iter()
            .any(|kind| lower.starts_with(kind));
    let implicit = lower
        .find('/')
        .is_some_and(|slash| slash < lower.find([':', ',']).unwrap_or(usize::MAX));
    if !explicit && !implicit {
        return None;
    }
    if create_only {
        return Some(false);
    }
    Some(!raw.to_ascii_lowercase().contains(",wronly"))
}

fn visible_network_endpoint(raw: &str) -> bool {
    let (prefix, dynamic) = shell_literal_prefix(raw);
    let endpoint = prefix.to_ascii_lowercase();
    let (kind, value) = endpoint
        .split_once(':')
        .map_or((endpoint.as_str(), ""), |(kind, value)| (kind, value));
    network_endpoint_kind(kind) && (kind == "tun" || !value.is_empty() || dynamic)
}

fn socat_chdir(options: &[String]) -> Option<String> {
    socat_option_value(options, &["chdir", "cd"])
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn socat_option_value<'a>(options: &'a [String], expected: &[&str]) -> Option<&'a str> {
    options.iter().rev().find_map(|option| {
        let (name, value) = option.split_once('=')?;
        expected
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected))
            .then_some(value)
    })
}

fn socat_option_enabled(options: &[String], expected: &str) -> bool {
    options.iter().rev().find_map(|option| {
        let (name, value) = option
            .split_once('=')
            .map_or((option.as_str(), None), |(name, value)| (name, Some(value)));
        name.eq_ignore_ascii_case(expected).then(|| {
            value.is_none_or(|value| {
                !matches!(
                    value.to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
        })
    }) == Some(true)
}

fn apply_socat_chdir(path: String, chdir: Option<&str>) -> String {
    let Some(chdir) = chdir else {
        return path;
    };
    if path.starts_with(['/', '\\'])
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
    {
        return path;
    }
    format!("{}/{path}", chdir.trim_end_matches(['/', '\\']))
}

fn command_in_directory(cwd: &str, payload: &str) -> String {
    let cwd = if cwd == "."
        || cwd == ".."
        || ["./", "../", "/", "\\"]
            .iter()
            .any(|prefix| cwd.starts_with(prefix))
        || cwd
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
    {
        cwd.to_owned()
    } else {
        format!("./{cwd}")
    };
    format!("cd {} && {payload}", shell_quote(&cwd))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn decoded_socat_exec_payload(payload: &str) -> Option<String> {
    socat_exec_argv(payload).map(|arguments| {
        arguments
            .iter()
            .map(|argument| shell_quote(argument))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn socat_exec_argv(payload: &str) -> Option<Vec<String>> {
    let mut arguments = Vec::new();
    let mut argument = String::new();
    let mut argument_started = false;
    let mut contexts = Vec::new();
    let mut chars = payload
        .trim_start_matches(char::is_whitespace)
        .chars()
        .peekable();
    while let Some(character) = chars.next() {
        if matches!(contexts.last(), Some(SocatLexContext::HardQuote)) {
            match character {
                '\'' => {
                    contexts.pop();
                }
                '\\' => argument.push(socat_escaped_character(&mut chars).ok()?),
                _ => argument.push(character),
            }
            argument_started = true;
            continue;
        }
        if matches!(contexts.last(), Some(SocatLexContext::SoftQuote)) && character == '"' {
            contexts.pop();
            argument_started = true;
            continue;
        }
        if let Some(SocatLexContext::Nest(expected)) = contexts.last()
            && character == *expected
        {
            contexts.pop();
            argument.push(character);
            argument_started = true;
            continue;
        }
        match character {
            '\'' => {
                contexts.push(SocatLexContext::HardQuote);
                argument_started = true;
            }
            '"' => {
                contexts.push(SocatLexContext::SoftQuote);
                argument_started = true;
            }
            '\\' => {
                argument.push(socat_escaped_character(&mut chars).ok()?);
                argument_started = true;
            }
            '(' => {
                contexts.push(SocatLexContext::Nest(')'));
                argument.push(character);
                argument_started = true;
            }
            '[' => {
                contexts.push(SocatLexContext::Nest(']'));
                argument.push(character);
                argument_started = true;
            }
            '{' => {
                contexts.push(SocatLexContext::Nest('}'));
                argument.push(character);
                argument_started = true;
            }
            ' ' if contexts.is_empty() => {
                if argument_started {
                    arguments.push(std::mem::take(&mut argument));
                    argument_started = false;
                }
            }
            _ => {
                argument.push(character);
                argument_started = true;
            }
        }
    }
    if !contexts.is_empty() {
        return None;
    }
    if argument_started {
        arguments.push(argument);
    }
    (!arguments.is_empty()).then_some(arguments)
}

fn network_endpoint_kind(kind: &str) -> bool {
    let (family, operation) = kind
        .split_once('-')
        .map_or((kind, ""), |(family, operation)| (family, operation));
    match family {
        "tcp" | "tcp4" | "tcp6" | "dccp" | "dccp4" | "dccp6" | "sctp" | "sctp4" | "sctp6"
        | "vsock" => matches!(operation, "" | "l" | "listen" | "connect"),
        "inet" | "inet4" | "inet6" => matches!(operation, "" | "l" | "listen"),
        "udp" | "udp4" | "udp6" | "udplite" | "udplite4" | "udplite6" => matches!(
            operation,
            "" | "connect"
                | "datagram"
                | "dgram"
                | "l"
                | "listen"
                | "recv"
                | "recvfrom"
                | "send"
                | "sendto"
        ),
        "ip" | "ip4" | "ip6" => matches!(
            operation,
            "" | "datagram" | "dgram" | "recv" | "recvfrom" | "send" | "sendto"
        ),
        "dtls" => matches!(
            operation,
            "" | "c" | "client" | "connect" | "l" | "listen" | "server"
        ),
        "openssl" => matches!(
            operation,
            "" | "connect"
                | "listen"
                | "dtls-client"
                | "dtls-connect"
                | "dtls-listen"
                | "dtls-server"
        ),
        "ssl" => matches!(operation, "" | "l"),
        "proxy" => matches!(operation, "" | "connect"),
        "accept" => matches!(operation, "" | "fd"),
        "socks" | "socks4" | "socks4a" => operation.is_empty(),
        "socks5" => matches!(operation, "" | "bind" | "connect" | "listen"),
        "socket" => matches!(
            operation,
            "connect" | "datagram" | "listen" | "recv" | "recvfrom" | "sendto"
        ),
        "datagram" | "dgram" | "sendto" | "if" | "interface" | "tun" => operation.is_empty(),
        _ => false,
    }
}

fn active_addresses(analysis: &SocatAnalysis) -> impl Iterator<Item = &SocatAddress> {
    analysis
        .operands
        .iter()
        .enumerate()
        .flat_map(|(index, operand)| {
            [
                socat_address_is_source(analysis.direction, index).then_some(&operand.read),
                socat_address_is_sink(analysis.direction, index).then_some(&operand.write),
            ]
            .into_iter()
            .flatten()
        })
}

fn add_descriptor_effects(
    address: &SocatAddress,
    direction: NetworkDirection,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
    endpoints: &mut Vec<NetworkEndpoint>,
    stages: &mut Vec<usize>,
) {
    let Some(fd) = address_descriptor_fd(address, direction) else {
        return;
    };
    let Some((_, facts)) = descriptor_binding(fd, descriptors, variables) else {
        return;
    };
    endpoints.extend(facts.hosts().iter().cloned().map(|host| (direction, host)));
    stages.extend(match direction {
        NetworkDirection::Inbound => facts.producer_sources(),
        NetworkDirection::Outbound => facts.consumer_sinks(),
    });
}

fn address_descriptor_fd(address: &SocatAddress, direction: NetworkDirection) -> Option<&str> {
    match address {
        SocatAddress::Descriptor { fd } | SocatAddress::Stdout { fd } => Some(fd),
        SocatAddress::Stdin => Some("0"),
        SocatAddress::Stdio if direction == NetworkDirection::Inbound => Some("0"),
        SocatAddress::Stdio => Some("1"),
        _ => None,
    }
}

fn descriptor_is_complete(
    address: &SocatAddress,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> bool {
    let SocatAddress::Descriptor { fd } = address else {
        return true;
    };
    descriptor_binding(fd, descriptors, variables)
        .is_some_and(|(presence, _)| presence == DescriptorPresence::Present)
}

fn address_is_network(
    address: &SocatAddress,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> bool {
    match address {
        SocatAddress::Network => true,
        SocatAddress::Descriptor { fd } | SocatAddress::Stdout { fd } => {
            descriptor_binding(fd, descriptors, variables)
                .is_some_and(|(_, facts)| !facts.hosts().is_empty())
        }
        SocatAddress::Stdin => descriptor_binding("0", descriptors, variables)
            .is_some_and(|(_, facts)| !facts.hosts().is_empty()),
        SocatAddress::Stdio => ["0", "1"].into_iter().any(|fd| {
            descriptor_binding(fd, descriptors, variables)
                .is_some_and(|(_, facts)| !facts.hosts().is_empty())
        }),
        _ => false,
    }
}

fn address_reads_stdin(
    address: &SocatAddress,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> bool {
    let fd = match address {
        SocatAddress::Stdin | SocatAddress::Stdio => Some("0"),
        SocatAddress::Descriptor { fd } if fd == "0" => Some("0"),
        _ => None,
    };
    fd.is_some_and(|fd| {
        descriptor_binding(fd, descriptors, variables).is_none_or(|(presence, facts)| {
            presence == DescriptorPresence::Maybe || facts.is_empty()
        })
    })
}

fn address_writes_stdout(
    address: &SocatAddress,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> bool {
    let fd = match address {
        SocatAddress::Stdout { fd } if fd == "1" => Some("1"),
        SocatAddress::Stdio => Some("1"),
        SocatAddress::Descriptor { fd } if fd == "1" => Some("1"),
        _ => None,
    };
    fd.is_some_and(|fd| {
        descriptor_binding(fd, descriptors, variables).is_none_or(|(presence, facts)| {
            presence == DescriptorPresence::Maybe || facts.is_empty()
        })
    })
}

fn descriptor_binding(
    fd: &str,
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> Option<(DescriptorPresence, DescriptorFacts)> {
    if let Ok(Some(binding)) = descriptors.reference_binding(fd) {
        return Some(binding);
    }
    let name = fd.strip_prefix('{')?.strip_suffix('}')?;
    if let Some(value) = variables
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .and_then(VariableValue::as_static)
        && let Ok(Some(binding)) = descriptors.reference_binding(value)
    {
        return Some(binding);
    }
    descriptors
        .possible_facts()
        .ok()
        .map(|facts| (DescriptorPresence::Maybe, facts))
}

fn socat_address_is_source(direction: SocatDirection, index: usize) -> bool {
    matches!(direction, SocatDirection::Both)
        || matches!(direction, SocatDirection::Forward) && index == 0
        || matches!(direction, SocatDirection::Reverse) && index == 1
}

fn socat_address_is_sink(direction: SocatDirection, index: usize) -> bool {
    matches!(direction, SocatDirection::Both)
        || matches!(direction, SocatDirection::Forward) && index == 1
        || matches!(direction, SocatDirection::Reverse) && index == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_lexer_decodes_quotes_escapes_options_and_dual_addresses() {
        let (read, write) =
            parse_socat_operand(r#"OPEN:".git/config",chdir=repo!!T\CP:host:443"#).unwrap();
        assert_eq!(read.keyword, "OPEN");
        assert_eq!(read.parameters, [".git/config"]);
        assert_eq!(read.options, ["chdir=repo"]);
        let write = write.unwrap();
        assert_eq!(write.keyword, "TCP");
        assert_eq!(write.parameters, ["host", "443"]);

        let (read, _) = parse_socat_operand(r#"SYSTEM:'echo ok\nrm -rf /'"#).unwrap();
        assert_eq!(read.parameters, ["echo ok\nrm -rf /"]);
    }

    #[test]
    fn descriptor_numbers_follow_socat_base_zero_parsing() {
        for (value, expected) in [
            ("3", "3"),
            ("+3", "3"),
            ("003", "3"),
            ("010", "8"),
            ("0x10", "16"),
            ("\t3", "3"),
            ("08", "0"),
            ("garbage", "0"),
        ] {
            assert_eq!(parse_socat_fd(value).as_deref(), Some(expected), "{value}");
        }
        assert!(parse_socat_fd("-1").is_none());
    }
}
