//! Lowers visible network transfer effects; it does not perform transport or exfiltration policy.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;

use crate::bash_descriptor_state::{DescriptorState, NetworkEndpoint};
use crate::bash_model::{FilesystemSpec, VariableValue};
use crate::bash_rsync_options::{rsync_argument_has_short_flag, rsync_option_takes_value};
use crate::bash_socat;
use crate::bash_tar;
use crate::shell_word::{shell_literal_prefix, static_filesystem_word, static_word};

pub(crate) struct Lowering {
    pub(crate) complete: bool,
    pub(crate) filesystems: Vec<FilesystemSpec>,
    pub(crate) stdin_flows: bool,
    pub(crate) stdout_flows: bool,
    pub(crate) network: bool,
    pub(crate) network_endpoints: Vec<NetworkEndpoint>,
    pub(crate) descriptor_sources: Vec<usize>,
    pub(crate) descriptor_sinks: Vec<usize>,
}

pub(crate) fn lower(
    program: &str,
    arguments: &[Word],
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> Option<Lowering> {
    match program {
        "curl" => curl(arguments),
        "wget" => wget(arguments),
        "http" | "https" => httpie(arguments),
        "nc" | "netcat" | "ncat" => netcat(arguments),
        "socat" => bash_socat::socat(arguments, descriptors, variables).map(|lowering| Lowering {
            complete: lowering.complete,
            filesystems: lowering.filesystems,
            stdin_flows: lowering.stdin_flows,
            stdout_flows: lowering.stdout_flows,
            network: lowering.network,
            network_endpoints: lowering.network_endpoints,
            descriptor_sources: lowering.descriptor_sources,
            descriptor_sinks: lowering.descriptor_sinks,
        }),
        "tar"
            if bash_tar::analyze(program, arguments)
                .is_some_and(|analysis| analysis.remote_archive) =>
        {
            Some(Lowering {
                complete: true,
                filesystems: Vec::new(),
                stdin_flows: false,
                stdout_flows: false,
                network: true,
                network_endpoints: Vec::new(),
                descriptor_sources: Vec::new(),
                descriptor_sinks: Vec::new(),
            })
        }
        "ssh" => ssh(arguments),
        "scp" => scp(arguments),
        "rsync" => rsync(arguments),
        _ => None,
    }
}

pub(crate) fn shell_operation(
    program: &str,
    arguments: &[Word],
    descriptors: &DescriptorState,
    variables: &[(String, VariableValue)],
) -> Option<&'static str> {
    if program == "socat" {
        return bash_socat::socat_shell_operation(arguments, code_program, descriptors, variables);
    }
    match program {
        "nc" | "netcat" | "ncat" => {
            let values = argument_values(arguments)
                .into_iter()
                .map(|argument| argument.unwrap_or_else(|| "?".into()))
                .collect::<Vec<_>>();
            netcat_shell_operation(&values)
        }
        _ => None,
    }
}

fn netcat_shell_operation(arguments: &[String]) -> Option<&'static str> {
    if arguments.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "-h" | "--help" | "-V" | "--version" | "-z" | "--zero"
        ) || short_flags(argument).is_some_and(|flags| flags.contains('z'))
    }) {
        return None;
    }
    let listener = arguments.iter().any(|argument| {
        matches!(argument.as_str(), "-l" | "--listen")
            || short_flags(argument).is_some_and(|flags| flags.contains('l'))
    });
    if !netcat_has_endpoint(arguments, listener) {
        return None;
    }
    if netcat_code_attachment(arguments) {
        Some("network-shell")
    } else if listener {
        Some("network-listener")
    } else {
        None
    }
}

fn netcat_code_attachment(arguments: &[String]) -> bool {
    arguments.iter().enumerate().any(|(index, argument)| {
        if matches!(argument.as_str(), "-c" | "--sh-exec") {
            return arguments
                .get(index + 1)
                .is_some_and(|value| code_program(value));
        }
        if argument
            .strip_prefix("--sh-exec=")
            .is_some_and(code_program)
        {
            return true;
        }
        if matches!(argument.as_str(), "-e" | "--exec") {
            return arguments
                .get(index + 1)
                .is_some_and(|command| code_program(command));
        }
        if argument.strip_prefix("--exec=").is_some_and(code_program) {
            return true;
        }
        short_flags(argument).is_some_and(|flags| {
            flags.find(['e', 'c']).is_some_and(|position| {
                let command = &flags[position + 1..];
                let command = if command.is_empty() {
                    arguments.get(index + 1).map(String::as_str)
                } else {
                    Some(command)
                };
                command.is_some_and(code_program)
            })
        })
    })
}

fn netcat_has_endpoint(arguments: &[String], listener: bool) -> bool {
    let mut positionals = 0;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "--" {
            positionals += arguments.len().saturating_sub(index + 1);
            break;
        }
        if listener && matches!(argument, "-p" | "--source-port") {
            if index + 1 < arguments.len() {
                positionals += 1;
            }
            index += 2;
            continue;
        }
        if matches!(
            argument,
            "-e" | "--exec" | "-c" | "--sh-exec" | "--lua-exec"
        ) || matches!(
            argument,
            "-i" | "-I"
                | "-M"
                | "-m"
                | "-O"
                | "-P"
                | "-p"
                | "-q"
                | "-s"
                | "-T"
                | "-W"
                | "-w"
                | "-X"
                | "-x"
                | "--idle-timeout"
                | "--max-conns"
                | "--proxy"
                | "--proxy-auth"
                | "--proxy-type"
                | "--source-port"
        ) {
            index += 2;
            continue;
        }
        if short_flags(argument).is_some_and(|flags| {
            flags
                .find(['e', 'c'])
                .is_some_and(|position| flags[position + 1..].is_empty())
        }) {
            index += 2;
            continue;
        }
        if listener
            && short_flags(argument).is_some_and(|flags| {
                flags
                    .find('p')
                    .is_some_and(|position| !flags[position + 1..].is_empty())
            })
        {
            positionals += 1;
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        positionals += 1;
        index += 1;
    }
    positionals >= if listener { 1 } else { 2 }
}

pub(super) fn code_program(command: &str) -> bool {
    let words = command
        .split([',', ' '])
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let mut index = 0;
    let mut program = words.get(index).copied().unwrap_or_default();
    loop {
        let wrapper = executable_basename(program).to_ascii_lowercase();
        match wrapper.strip_suffix(".exe").unwrap_or(&wrapper) {
            "exec" => {
                index += 1;
                while let Some(argument) = words.get(index).copied() {
                    if argument == "--" {
                        index += 1;
                        break;
                    }
                    if argument == "-a" {
                        index += 2;
                    } else if matches!(argument, "-c" | "-l") {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                index += 1;
                while let Some(argument) = words.get(index).copied() {
                    if argument == "--" {
                        index += 1;
                        break;
                    }
                    if matches!(
                        argument,
                        "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
                    ) {
                        index += 2;
                    } else if argument.starts_with('-') || argument.contains('=') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "command" => {
                index += 1;
                if words.get(index).is_some_and(|argument| *argument == "-p") {
                    index += 1;
                }
                if words.get(index).is_some_and(|argument| *argument == "--") {
                    index += 1;
                }
            }
            "busybox" | "toybox" => index += 1,
            "nice" => {
                index += 1;
                while let Some(argument) = words.get(index).copied() {
                    if argument == "--" {
                        index += 1;
                        break;
                    }
                    if matches!(argument, "-n" | "--adjustment") {
                        index += 2;
                    } else if argument.starts_with("--adjustment=")
                        || argument
                            .strip_prefix('-')
                            .is_some_and(|value| value.parse::<i32>().is_ok())
                    {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "nohup" => {
                index += 1;
                if words.get(index).is_some_and(|argument| *argument == "--") {
                    index += 1;
                }
            }
            "setsid" => {
                index += 1;
                while let Some(argument) = words.get(index).copied() {
                    if argument == "--" {
                        index += 1;
                        break;
                    }
                    if matches!(
                        argument,
                        "-c" | "--ctty" | "-f" | "--fork" | "-w" | "--wait"
                    ) {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            _ => break,
        }
        program = words.get(index).copied().unwrap_or_default();
    }
    let program = executable_basename(program).to_ascii_lowercase();
    let program = program.strip_suffix(".exe").unwrap_or(&program);
    matches!(
        program,
        "bash"
            | "ash"
            | "dash"
            | "ksh"
            | "sh"
            | "zsh"
            | "powershell"
            | "pwsh"
            | "cmd"
            | "node"
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
    ) || python3_version(program)
}

fn python3_version(program: &str) -> bool {
    program.strip_prefix("python3.").is_some_and(|version| {
        !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn executable_basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

fn short_flags(argument: &str) -> Option<&str> {
    argument
        .strip_prefix('-')
        .filter(|argument| !argument.starts_with('-'))
}

#[derive(Clone, Copy)]
enum ShortOptionValue<'a> {
    Separate,
    Attached(&'a str),
}

fn short_option_value<'a>(
    argument: &'a str,
    expected: char,
    options_with_values: &str,
) -> Option<ShortOptionValue<'a>> {
    let flags = short_flags(argument)?;
    for (index, flag) in flags.char_indices() {
        if !options_with_values.contains(flag) {
            continue;
        }
        if flag != expected {
            return None;
        }
        let value = &flags[index + flag.len_utf8()..];
        return Some(if value.is_empty() {
            ShortOptionValue::Separate
        } else {
            ShortOptionValue::Attached(value)
        });
    }
    None
}

fn short_option_consumes_next(argument: &str, options_with_values: &str) -> bool {
    let Some(flags) = short_flags(argument) else {
        return false;
    };
    for (index, flag) in flags.char_indices() {
        if options_with_values.contains(flag) {
            return index + flag.len_utf8() == flags.len();
        }
    }
    false
}

fn short_option_has_flag(argument: &str, expected: char, options_with_values: &str) -> bool {
    let Some(flags) = short_flags(argument) else {
        return false;
    };
    for flag in flags.chars() {
        if options_with_values.contains(flag) {
            return false;
        }
        if flag == expected {
            return true;
        }
    }
    false
}

fn curl(arguments: &[Word]) -> Option<Lowering> {
    let static_arguments = arguments
        .iter()
        .map(|argument| static_filesystem_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    if arguments.is_empty() || curl_terminal(&static_arguments) {
        return None;
    }

    let mut complete = static_arguments.iter().all(Option::is_some);
    let urls = curl_urls(&static_arguments);
    let local = urls
        .as_ref()
        .is_some_and(|urls| !urls.is_empty() && urls.iter().all(|url| url.starts_with("file://")));
    let mut filesystems = Vec::new();
    let mut stdin_flows = false;
    let mut stdout_flows = true;
    let mut output_seen = false;
    let mut remote_name = false;
    let mut remote_name_dynamic = false;
    let mut index = 0;
    while index < static_arguments.len() {
        let Some(argument) = static_arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        let output = if matches!(argument, "-o" | "--output") {
            static_arguments.get(index + 1).and_then(Option::as_deref)
        } else {
            argument
                .strip_prefix("--output=")
                .or_else(|| curl_short_output(argument, &static_arguments, index))
        };
        if let Some(target) = output {
            output_seen = true;
            stdout_flows = is_stdout_target(target);
            if !stdout_flows {
                filesystems.push((target.to_owned(), FilesystemOperation::Write, false));
            }
        } else if matches!(argument, "-O" | "--remote-name" | "--remote-name-all")
            || has_curl_short_flag(argument, 'O')
        {
            remote_name = true;
            stdout_flows = false;
        } else if matches!(argument, "-o" | "--output")
            || matches!(
                short_option_value(argument, 'o', CURL_SHORT_VALUE_OPTIONS),
                Some(ShortOptionValue::Separate)
            )
        {
            complete = false;
            stdout_flows = false;
        }
        remote_name_dynamic |= matches!(argument, "-J" | "--remote-header-name" | "--no-clobber")
            || short_option_has_flag(argument, 'J', CURL_SHORT_VALUE_OPTIONS);
        for target in curl_inputs(argument, &static_arguments, index) {
            filesystems.push((target, FilesystemOperation::Read, false));
        }
        if let Some(target) = curl_auxiliary_input(argument, &static_arguments, index) {
            filesystems.push((target, FilesystemOperation::Read, false));
        }
        stdin_flows |= curl_uses_stdin(argument, &static_arguments, index);
        index += 1 + usize::from(curl_option_consumes_next(argument));
    }
    if local {
        match urls
            .as_ref()
            .into_iter()
            .flatten()
            .map(|url| file_url_path(url))
            .collect::<Option<Vec<_>>>()
        {
            Some(inputs) => filesystems.extend(
                inputs
                    .into_iter()
                    .map(|input| (input, FilesystemOperation::Read, false)),
            ),
            None => complete = false,
        }
    }
    if remote_name {
        if output_seen || remote_name_dynamic {
            complete = false;
        } else if let Some(target) = urls
            .as_deref()
            .and_then(|urls| <&[String; 1]>::try_from(urls).ok())
            .and_then(|[url]| remote_output_name(url))
        {
            filesystems.push((target, FilesystemOperation::Write, false));
        } else {
            complete = false;
        }
    }

    Some(Lowering {
        complete,
        filesystems,
        stdin_flows,
        stdout_flows,
        network: !local,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

fn curl_urls(arguments: &[Option<String>]) -> Option<Vec<String>> {
    if arguments.iter().any(Option::is_none) {
        return None;
    }
    let values = arguments.iter().flatten().collect::<Vec<_>>();
    if values.iter().any(|argument| {
        matches!(argument.as_str(), "-K" | "--config")
            || argument.starts_with("--config=")
            || short_option_value(argument, 'K', CURL_SHORT_VALUE_OPTIONS).is_some()
    }) {
        return None;
    }
    let mut urls = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let argument = values[index].as_str();
        if argument == "--" {
            urls.extend(values[index + 1..].iter().map(|value| value.as_str()));
            break;
        }
        if argument == "--url" {
            if let Some(url) = values.get(index + 1) {
                urls.push(url.as_str());
            }
            index += 2;
            continue;
        }
        if let Some(url) = argument.strip_prefix("--url=") {
            urls.push(url);
            index += 1;
            continue;
        }
        if curl_option_takes_value(argument) {
            index += 2;
            continue;
        }
        if curl_short_option_takes_value(argument) {
            index += 2;
            continue;
        }
        if !argument.starts_with('-') {
            urls.push(argument);
        }
        index += 1;
    }
    Some(urls.into_iter().map(str::to_owned).collect())
}

fn file_url_path(url: &str) -> Option<String> {
    let path = url
        .strip_prefix("file://localhost")
        .or_else(|| url.strip_prefix("file://"))?;
    (!path.is_empty()
        && path.starts_with('/')
        && !path.contains(['%', '?', '#', '[', ']', '{', '}']))
    .then(|| path.to_owned())
}

fn remote_output_name(url: &str) -> Option<String> {
    let name = url.rsplit('/').next()?;
    (!name.is_empty()
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)))
    .then(|| name.to_owned())
}

fn curl_terminal(arguments: &[Option<String>]) -> bool {
    let values = arguments.iter().map(Option::as_deref).collect::<Vec<_>>();
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index] else {
            index += 1;
            continue;
        };
        if argument == "--" {
            return false;
        }
        if matches!(argument, "-V" | "-h" | "--version" | "--help" | "--manual")
            || short_option_has_flag(argument, 'V', CURL_SHORT_VALUE_OPTIONS)
            || short_option_value(argument, 'h', CURL_SHORT_VALUE_OPTIONS).is_some()
        {
            return true;
        }
        if long_option_may_take_terminal_value(&values, index) {
            return false;
        }
        if argument == "--url"
            || curl_option_takes_value(argument)
            || curl_short_option_takes_value(argument)
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    false
}

fn curl_short_option_takes_value(argument: &str) -> bool {
    short_option_consumes_next(argument, CURL_SHORT_VALUE_OPTIONS)
}

fn curl_option_consumes_next(argument: &str) -> bool {
    argument == "--url"
        || curl_option_takes_value(argument)
        || curl_short_option_takes_value(argument)
}

const CURL_SHORT_VALUE_OPTIONS: &str = "AbcCdDeEFhHKmoPQrtTuUwxXyYz";

fn curl_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "-A" | "--user-agent"
            | "-b"
            | "--cookie"
            | "-c"
            | "--cookie-jar"
            | "-d"
            | "--data"
            | "--data-ascii"
            | "--data-binary"
            | "--data-urlencode"
            | "--json"
            | "-e"
            | "--referer"
            | "-F"
            | "--form"
            | "--form-string"
            | "-H"
            | "--header"
            | "--proxy-header"
            | "-K"
            | "--config"
            | "--cacert"
            | "--cert"
            | "--key"
            | "--netrc-file"
            | "-o"
            | "--output"
            | "-T"
            | "--upload-file"
            | "-u"
            | "--user"
            | "-x"
            | "--proxy"
            | "-X"
            | "--request"
    )
}

fn curl_short_output<'a>(
    argument: &'a str,
    arguments: &'a [Option<String>],
    index: usize,
) -> Option<&'a str> {
    match short_option_value(argument, 'o', CURL_SHORT_VALUE_OPTIONS)? {
        ShortOptionValue::Separate => arguments.get(index + 1).and_then(Option::as_deref),
        ShortOptionValue::Attached(target) => Some(target),
    }
}

fn has_curl_short_flag(argument: &str, flag: char) -> bool {
    short_option_has_flag(argument, flag, CURL_SHORT_VALUE_OPTIONS)
}

fn curl_inputs(argument: &str, arguments: &[Option<String>], index: usize) -> Vec<String> {
    let next = || arguments.get(index + 1).and_then(Option::as_deref);
    let data = if matches!(
        argument,
        "-d" | "--data" | "--data-ascii" | "--data-binary" | "--data-urlencode" | "--json"
    ) {
        next()
    } else if let Some(value) = argument
        .strip_prefix("--data=")
        .or_else(|| argument.strip_prefix("--data-ascii="))
        .or_else(|| argument.strip_prefix("--data-binary="))
        .or_else(|| argument.strip_prefix("--data-urlencode="))
        .or_else(|| argument.strip_prefix("--json="))
    {
        Some(value)
    } else {
        short_option_argument(argument, 'd', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    };
    if let Some(target) = data
        .and_then(|value| value.strip_prefix('@'))
        .filter(|target| *target != "-")
    {
        return vec![target.to_owned()];
    }

    let upload = if matches!(argument, "-T" | "--upload-file") {
        next()
    } else if let Some(value) = argument.strip_prefix("--upload-file=") {
        Some(value)
    } else {
        short_option_argument(argument, 'T', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    };
    if let Some(target) = upload.filter(|target| *target != "-") {
        return vec![target.to_owned()];
    }

    let form = if matches!(argument, "-F" | "--form") {
        next()
    } else if let Some(value) = argument.strip_prefix("--form=") {
        Some(value)
    } else {
        short_option_argument(argument, 'F', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    };
    form.and_then(form_files).unwrap_or_default()
}

fn curl_uses_stdin(argument: &str, arguments: &[Option<String>], index: usize) -> bool {
    let next = || arguments.get(index + 1).and_then(Option::as_deref);
    let value = if matches!(
        argument,
        "-d" | "--data"
            | "--data-ascii"
            | "--data-binary"
            | "--data-urlencode"
            | "--json"
            | "-T"
            | "--upload-file"
            | "-F"
            | "--form"
    ) {
        next()
    } else if let Some(value) = argument
        .strip_prefix("--data=")
        .or_else(|| argument.strip_prefix("--data-ascii="))
        .or_else(|| argument.strip_prefix("--data-binary="))
        .or_else(|| argument.strip_prefix("--data-urlencode="))
        .or_else(|| argument.strip_prefix("--json="))
        .or_else(|| argument.strip_prefix("--upload-file="))
        .or_else(|| argument.strip_prefix("--form="))
    {
        Some(value)
    } else if let Some(value) =
        short_option_argument(argument, 'd', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    {
        Some(value)
    } else if let Some(value) =
        short_option_argument(argument, 'T', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    {
        Some(value)
    } else {
        short_option_argument(argument, 'F', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    };
    value.is_some_and(|value| {
        value == "-"
            || value == "@-"
            || value
                .split_once("=@")
                .or_else(|| value.split_once("=<"))
                .is_some_and(|(_, target)| target == "-")
    }) || curl_auxiliary_uses_stdin(argument, arguments, index)
}

fn form_files(value: &str) -> Option<Vec<String>> {
    let target = value
        .split_once("=@")
        .or_else(|| value.split_once("=<"))
        .map(|(_, target)| target.split(';').next().unwrap_or(target))?;
    if target == "-" {
        return Some(Vec::new());
    }
    if target.contains(['"', '\\']) {
        return None;
    }
    let files = target
        .split(',')
        .filter(|target| !target.is_empty() && *target != "-")
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (!files.is_empty()).then_some(files)
}

fn curl_auxiliary_input(
    argument: &str,
    arguments: &[Option<String>],
    index: usize,
) -> Option<String> {
    let next = || arguments.get(index + 1).and_then(Option::as_deref);
    if matches!(
        argument,
        "-K" | "--config" | "--cacert" | "--cert" | "--key" | "--netrc-file"
    ) {
        return next().filter(|target| *target != "-").map(str::to_owned);
    }
    if matches!(argument, "-n" | "--netrc" | "--netrc-optional") {
        return Some("~/.netrc".into());
    }
    if matches!(argument, "-H" | "--header" | "--proxy-header")
        && let Some(target) = next().and_then(|target| target.strip_prefix('@'))
    {
        return (target != "-").then(|| target.to_owned());
    }
    if matches!(argument, "-b" | "--cookie")
        && let Some(target) = next()
    {
        return (!target.is_empty() && target != "-" && !target.contains('='))
            .then(|| target.to_owned());
    }
    if let Some(target) =
        short_option_argument(argument, 'K', CURL_SHORT_VALUE_OPTIONS, arguments, index).or_else(
            || short_option_argument(argument, 'E', CURL_SHORT_VALUE_OPTIONS, arguments, index),
        )
    {
        return (target != "-").then(|| target.to_owned());
    }
    if let Some(target) =
        short_option_argument(argument, 'H', CURL_SHORT_VALUE_OPTIONS, arguments, index)
            .and_then(|target| target.strip_prefix('@'))
    {
        return (target != "-").then(|| target.to_owned());
    }
    if let Some(target) =
        short_option_argument(argument, 'b', CURL_SHORT_VALUE_OPTIONS, arguments, index)
    {
        return (!target.is_empty() && target != "-" && !target.contains('='))
            .then(|| target.to_owned());
    }
    if let Some(target) = argument
        .strip_prefix("--header=")
        .or_else(|| argument.strip_prefix("--proxy-header="))
        .and_then(|target| target.strip_prefix('@'))
    {
        return (target != "-").then(|| target.to_owned());
    }
    if let Some(target) = argument.strip_prefix("--cookie=") {
        return (!target.is_empty() && target != "-" && !target.contains('='))
            .then(|| target.to_owned());
    }
    argument
        .strip_prefix("--config=")
        .or_else(|| argument.strip_prefix("--cacert="))
        .or_else(|| argument.strip_prefix("--cert="))
        .or_else(|| argument.strip_prefix("--key="))
        .or_else(|| argument.strip_prefix("--netrc-file="))
        .filter(|target| !target.is_empty() && *target != "-")
        .map(str::to_owned)
}

fn curl_auxiliary_uses_stdin(argument: &str, arguments: &[Option<String>], index: usize) -> bool {
    for flag in ['K', 'H', 'b'] {
        if short_option_argument(argument, flag, CURL_SHORT_VALUE_OPTIONS, arguments, index)
            .is_some_and(|value| value == "-" || flag == 'H' && value == "@-")
        {
            return true;
        }
    }
    let next = || arguments.get(index + 1).and_then(Option::as_deref);
    if matches!(
        argument,
        "--config" | "--header" | "--proxy-header" | "--cookie"
    ) {
        return next().is_some_and(|value| value == "-" || value == "@-");
    }
    argument
        .strip_prefix("--config=")
        .or_else(|| argument.strip_prefix("--header="))
        .or_else(|| argument.strip_prefix("--proxy-header="))
        .or_else(|| argument.strip_prefix("--cookie="))
        .is_some_and(|value| value == "-" || value == "@-")
}

fn wget(arguments: &[Word]) -> Option<Lowering> {
    let values = arguments
        .iter()
        .map(|argument| static_filesystem_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    if values.is_empty() || wget_terminal(&values) {
        return None;
    }
    let mut complete = values.iter().all(Option::is_some);
    let mut filesystems = Vec::new();
    let mut stdin_flows = false;
    let mut stdout_flows = false;
    let mut output_seen = false;
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            index += 1;
            continue;
        };
        let long_output =
            abbreviated_long_option_value(argument, "--output-document", "--output-d");
        let output_separate = matches!(argument, "-O" | "--output-document")
            || matches!(long_output, Some(ShortOptionValue::Separate));
        let output = if output_separate {
            values.get(index + 1).and_then(Option::as_deref)
        } else if let Some(ShortOptionValue::Attached(target)) = long_output {
            Some(target)
        } else {
            argument.strip_prefix("-O").or_else(|| {
                argument
                    .strip_prefix('-')
                    .filter(|argument| !argument.starts_with('-'))
                    .and_then(|argument| argument.split_once('O'))
                    .filter(|(prefix, _)| {
                        prefix
                            .chars()
                            .all(|flag| matches!(flag, 'q' | 'n' | 'v' | 'c'))
                    })
                    .map(|(_, target)| target)
                    .filter(|target| !target.is_empty())
            })
        };
        if let Some(target) = output {
            output_seen = true;
            stdout_flows = is_stdout_target(target);
            if !stdout_flows {
                filesystems.push((target.to_owned(), FilesystemOperation::Write, false));
            }
        } else if output_separate {
            complete = false;
        }
        let input_option = abbreviated_long_option_value(argument, "--post-file", "--post-f")
            .or_else(|| abbreviated_long_option_value(argument, "--body-file", "--body-f"));
        let input = match input_option {
            Some(ShortOptionValue::Separate) => values.get(index + 1).and_then(Option::as_deref),
            Some(ShortOptionValue::Attached(target)) => Some(target),
            None => None,
        };
        if let Some(target) = input.filter(|target| *target != "-") {
            filesystems.push((target.to_owned(), FilesystemOperation::Read, false));
        }
        stdin_flows |= input == Some("-");
        index += 1 + usize::from(
            output_separate || matches!(input_option, Some(ShortOptionValue::Separate)),
        );
    }
    complete &= output_seen;
    Some(Lowering {
        complete,
        filesystems,
        stdin_flows,
        stdout_flows,
        network: true,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

fn wget_terminal(arguments: &[Option<String>]) -> bool {
    let values = arguments.iter().map(Option::as_deref).collect::<Vec<_>>();
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index] else {
            index += 1;
            continue;
        };
        if argument == "--" {
            return false;
        }
        if matches!(argument, "-V" | "--version" | "-h" | "--help" | "--usage") {
            return true;
        }
        if long_option_may_take_terminal_value(&values, index) {
            return false;
        }
        if matches!(argument, "-O")
            || matches!(
                abbreviated_long_option_value(argument, "--output-document", "--output-d"),
                Some(ShortOptionValue::Separate)
            )
            || matches!(
                abbreviated_long_option_value(argument, "--post-file", "--post-f"),
                Some(ShortOptionValue::Separate)
            )
            || matches!(
                abbreviated_long_option_value(argument, "--body-file", "--body-f"),
                Some(ShortOptionValue::Separate)
            )
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    false
}

fn abbreviated_long_option_value<'a>(
    argument: &'a str,
    full: &str,
    minimum: &str,
) -> Option<ShortOptionValue<'a>> {
    let (name, value) = argument
        .split_once('=')
        .map_or((argument, None), |(name, value)| (name, Some(value)));
    if name.len() < minimum.len() || !name.starts_with("--") || !full.starts_with(name) {
        return None;
    }
    Some(value.map_or(ShortOptionValue::Separate, ShortOptionValue::Attached))
}

fn is_stdout_target(target: &str) -> bool {
    matches!(
        target,
        "-" | "/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1"
    )
}

fn httpie(arguments: &[Word]) -> Option<Lowering> {
    let values = arguments
        .iter()
        .filter_map(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
        })
        .collect::<Vec<_>>();
    if values.is_empty() || httpie_terminal(arguments) {
        return None;
    }
    let mut complete = arguments.iter().all(|argument| {
        static_filesystem_word(argument.raw(), argument.substitutions().is_empty()).is_some()
    });
    let mut filesystems = Vec::new();
    let mut stdout_flows = true;
    let mut index = 0;
    while index < values.len() {
        let argument = values[index].as_str();
        let output = if matches!(argument, "-o" | "--output") {
            index += 1;
            values.get(index).map(String::as_str)
        } else {
            argument.strip_prefix("--output=")
        };
        if let Some(target) = output {
            stdout_flows = is_stdout_target(target);
            if !stdout_flows {
                filesystems.push((target.to_owned(), FilesystemOperation::Write, false));
            }
        } else if matches!(argument, "-d" | "--download") {
            complete = false;
            stdout_flows = false;
        }
        index += 1;
    }
    Some(Lowering {
        complete,
        filesystems,
        stdin_flows: !values.iter().any(|argument| argument == "--ignore-stdin"),
        stdout_flows,
        network: true,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

fn httpie_terminal(arguments: &[Word]) -> bool {
    let values = arguments
        .iter()
        .map(|argument| static_filesystem_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let static_values = values.iter().map(Option::as_deref).collect::<Vec<_>>();
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            index += 1;
            continue;
        };
        if argument == "--" {
            return false;
        }
        if matches!(argument, "--help" | "--version" | "--offline") {
            return true;
        }
        if long_option_may_take_terminal_value(&static_values, index) {
            return false;
        }
        if matches!(argument, "-o" | "--output") {
            index += 2;
        } else {
            index += 1;
        }
    }
    false
}

fn long_option_may_take_terminal_value(arguments: &[Option<&str>], index: usize) -> bool {
    arguments[index].is_some_and(|argument| {
        argument.starts_with("--")
            && !argument.contains('=')
            && arguments
                .get(index + 1)
                .copied()
                .flatten()
                .is_some_and(|next| {
                    matches!(
                        next,
                        "-V" | "--version" | "-h" | "--help" | "--manual" | "--usage" | "--offline"
                    )
                })
    })
}

fn netcat(arguments: &[Word]) -> Option<Lowering> {
    let values = argument_values(arguments);
    if values.is_empty()
        || values.iter().flatten().any(|argument| {
            matches!(
                argument.as_str(),
                "-h" | "--help" | "-V" | "--version" | "-l" | "--listen" | "-z" | "--zero"
            ) || argument
                .strip_prefix('-')
                .filter(|argument| !argument.starts_with('-'))
                .is_some_and(|flags| flags.contains('l') || flags.contains('z'))
        })
    {
        return None;
    }
    let operands = values
        .iter()
        .filter(|argument| {
            argument
                .as_deref()
                .is_none_or(|argument| !argument.starts_with('-'))
        })
        .count();
    (operands >= 2).then_some(Lowering {
        complete: values.iter().all(Option::is_some),
        filesystems: Vec::new(),
        stdin_flows: true,
        stdout_flows: true,
        network: true,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

pub(crate) fn has_dynamic_file_source(
    program: &str,
    arguments: &[Word],
    variables: &[(String, VariableValue)],
) -> bool {
    match program {
        "curl" => curl_has_dynamic_file_source(arguments),
        "wget" => wget_has_dynamic_file_source(arguments),
        "socat" => bash_socat::socat_has_dynamic_file_source(arguments, variables),
        _ => false,
    }
}

fn curl_has_dynamic_file_source(arguments: &[Word]) -> bool {
    for (index, argument) in arguments.iter().enumerate() {
        let value = static_filesystem_word(argument.raw(), argument.substitutions().is_empty());
        if value.as_deref().is_some_and(|value| {
            matches!(value, "-T" | "--upload-file")
                || matches!(
                    short_option_value(value, 'T', CURL_SHORT_VALUE_OPTIONS),
                    Some(ShortOptionValue::Separate)
                )
        }) && arguments.get(index + 1).is_some_and(dynamic_word)
        {
            return true;
        }
        if value.as_deref().is_some_and(|value| {
            matches!(
                value,
                "-d" | "--data" | "--data-ascii" | "--data-binary" | "--data-urlencode" | "--json"
            ) || matches!(
                short_option_value(value, 'd', CURL_SHORT_VALUE_OPTIONS),
                Some(ShortOptionValue::Separate)
            )
        }) && arguments.get(index + 1).is_some_and(dynamic_at_file_word)
        {
            return true;
        }
        if let Some(value) = value.as_deref() {
            let separate_form = matches!(value, "-F" | "--form")
                || matches!(
                    short_option_value(value, 'F', CURL_SHORT_VALUE_OPTIONS),
                    Some(ShortOptionValue::Separate)
                );
            if separate_form
                && arguments
                    .get(index + 1)
                    .is_some_and(form_word_needs_unresolved_read)
            {
                return true;
            }
            let attached_form =
                value.strip_prefix("--form=").or_else(|| {
                    match short_option_value(value, 'F', CURL_SHORT_VALUE_OPTIONS) {
                        Some(ShortOptionValue::Attached(value)) => Some(value),
                        _ => None,
                    }
                });
            if attached_form
                .is_some_and(|value| form_file_prefix(value) && form_files(value).is_none())
            {
                return true;
            }
        }
        let (prefix, dynamic) = shell_literal_prefix(argument.raw());
        let short_upload = short_option_value(&prefix, 'T', CURL_SHORT_VALUE_OPTIONS);
        let short_data = short_option_value(&prefix, 'd', CURL_SHORT_VALUE_OPTIONS);
        let short_form = short_option_value(&prefix, 'F', CURL_SHORT_VALUE_OPTIONS);
        if dynamic
            && (matches!(
                short_upload,
                Some(ShortOptionValue::Separate | ShortOptionValue::Attached(_))
            ) || prefix == "--upload-file="
                || prefix.starts_with("--data=") && prefix.ends_with('@')
                || prefix.starts_with("--data-ascii=") && prefix.ends_with('@')
                || prefix.starts_with("--data-binary=") && prefix.ends_with('@')
                || prefix.starts_with("--data-urlencode=") && prefix.ends_with('@')
                || prefix.starts_with("--json=") && prefix.ends_with('@')
                || matches!(short_data, Some(ShortOptionValue::Attached(value)) if value.ends_with('@'))
                || prefix.strip_prefix("--form=").is_some_and(form_file_prefix)
                || matches!(short_form, Some(ShortOptionValue::Attached(value)) if form_file_prefix(value)))
        {
            return true;
        }
    }
    false
}

fn form_word_needs_unresolved_read(argument: &Word) -> bool {
    let (prefix, dynamic) = shell_literal_prefix(argument.raw());
    form_file_prefix(&prefix)
        && (dynamic
            || static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
                .is_none_or(|value| form_files(&value).is_none()))
}

fn wget_has_dynamic_file_source(arguments: &[Word]) -> bool {
    for (index, argument) in arguments.iter().enumerate() {
        let value = static_filesystem_word(argument.raw(), argument.substitutions().is_empty());
        if value.as_deref().is_some_and(|value| {
            matches!(
                abbreviated_long_option_value(value, "--post-file", "--post-f").or_else(|| {
                    abbreviated_long_option_value(value, "--body-file", "--body-f")
                }),
                Some(ShortOptionValue::Separate)
            )
        }) && arguments.get(index + 1).is_some_and(dynamic_word)
        {
            return true;
        }
        let (prefix, dynamic) = shell_literal_prefix(argument.raw());
        if dynamic
            && matches!(
                abbreviated_long_option_value(&prefix, "--post-file", "--post-f").or_else(|| {
                    abbreviated_long_option_value(&prefix, "--body-file", "--body-f")
                }),
                Some(ShortOptionValue::Attached(_))
            )
        {
            return true;
        }
    }
    false
}

fn dynamic_word(argument: &Word) -> bool {
    static_filesystem_word(argument.raw(), argument.substitutions().is_empty()).is_none()
}

fn dynamic_at_file_word(argument: &Word) -> bool {
    let (prefix, dynamic) = shell_literal_prefix(argument.raw());
    dynamic && prefix == "@"
}

fn form_file_prefix(value: &str) -> bool {
    value
        .split_once('=')
        .is_some_and(|(_, target)| target.starts_with(['@', '<']))
}

pub(crate) fn executor_payloads(program: &str, arguments: &[Word]) -> Vec<String> {
    match program {
        "ssh" if ssh(arguments).is_some() => openssh_executor_payloads(arguments, false),
        "scp" if scp(arguments).is_some() => openssh_executor_payloads(arguments, true),
        "rsync" if rsync(arguments).is_some() => rsync_executor_payloads(arguments),
        _ => Vec::new(),
    }
}

fn openssh_executor_payloads(arguments: &[Word], scp_mode: bool) -> Vec<String> {
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let mut payloads = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            break;
        };
        if argument == "--" || !argument.starts_with('-') {
            break;
        }
        let value_options = if scp_mode {
            SCP_SHORT_VALUE_OPTIONS
        } else {
            SSH_SHORT_VALUE_OPTIONS
        };
        if let Some(option) = short_option_argument(argument, 'o', value_options, &values, index) {
            if let Some(payload) = openssh_config_executor(option) {
                payloads.push(payload);
            }
            index += 1 + usize::from(matches!(
                short_option_value(argument, 'o', value_options),
                Some(ShortOptionValue::Separate)
            ));
            continue;
        }
        if scp_mode
            && let Some(program) =
                short_option_argument(argument, 'S', value_options, &values, index)
        {
            if !program.is_empty() {
                payloads.push(shell_literal(program));
            }
            index += 1 + usize::from(matches!(
                short_option_value(argument, 'S', value_options),
                Some(ShortOptionValue::Separate)
            ));
            continue;
        }
        index += 1 + usize::from(short_option_consumes_next(argument, value_options));
    }
    payloads
}

fn short_option_argument<'a>(
    argument: &'a str,
    expected: char,
    options_with_values: &str,
    arguments: &'a [Option<String>],
    index: usize,
) -> Option<&'a str> {
    match short_option_value(argument, expected, options_with_values)? {
        ShortOptionValue::Separate => arguments.get(index + 1).and_then(Option::as_deref),
        ShortOptionValue::Attached(value) => Some(value),
    }
}

fn openssh_config_executor(option: &str) -> Option<String> {
    let separator = option.find(|character: char| character == '=' || character.is_whitespace())?;
    let name = &option[..separator];
    if !matches!(
        name.to_ascii_lowercase().as_str(),
        "proxycommand" | "localcommand" | "knownhostscommand"
    ) {
        return None;
    }
    let payload = option[separator..]
        .trim_start_matches(|character: char| character == '=' || character.is_whitespace());
    (!payload.is_empty()).then(|| payload.to_owned())
}

fn rsync_executor_payloads(arguments: &[Word]) -> Vec<String> {
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let mut payloads = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            index += 1;
            continue;
        };
        if argument == "--" {
            break;
        }
        if !argument.starts_with('-') {
            index += 1;
            continue;
        }
        if argument == "--rsh" {
            if let Some(payload) = values.get(index + 1).and_then(Option::as_deref)
                && !payload.is_empty()
            {
                payloads.push(payload.to_owned());
            }
            index += 2;
            continue;
        }
        if let Some(payload) = argument
            .strip_prefix("--rsh=")
            .filter(|payload| !payload.is_empty())
        {
            payloads.push(payload.to_owned());
            index += 1;
            continue;
        }
        if let Some(payload) =
            short_option_argument(argument, 'e', RSYNC_SHORT_VALUE_OPTIONS, &values, index)
        {
            if !payload.is_empty() {
                payloads.push(payload.to_owned());
            }
            index += 1 + usize::from(matches!(
                short_option_value(argument, 'e', RSYNC_SHORT_VALUE_OPTIONS),
                Some(ShortOptionValue::Separate)
            ));
            continue;
        }
        index += 1 + usize::from(
            rsync_option_takes_value(argument)
                || short_option_consumes_next(argument, RSYNC_SHORT_VALUE_OPTIONS),
        );
    }
    payloads
}

fn shell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn ssh(arguments: &[Word]) -> Option<Lowering> {
    let values = argument_values(arguments);
    if values.is_empty() {
        return None;
    }
    let mut stdin_flows = true;
    let mut target = false;
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            target = true;
            break;
        };
        if argument == "--" {
            target = index + 1 < values.len();
            break;
        }
        if !argument.starts_with('-') {
            target = true;
            break;
        }
        if matches!(argument, "-V" | "--version" | "-h" | "--help")
            || short_option_has_flag(argument, 'V', SSH_SHORT_VALUE_OPTIONS)
            || short_option_has_flag(argument, 'h', SSH_SHORT_VALUE_OPTIONS)
        {
            return None;
        }
        stdin_flows &= !argument
            .strip_prefix('-')
            .filter(|argument| !argument.starts_with('-'))
            .is_some_and(|flags| flags.contains('n'));
        index += 1 + usize::from(short_option_consumes_next(
            argument,
            SSH_SHORT_VALUE_OPTIONS,
        ));
    }
    target.then_some(Lowering {
        complete: values.iter().all(Option::is_some),
        filesystems: Vec::new(),
        stdin_flows,
        stdout_flows: true,
        network: true,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

const SSH_SHORT_VALUE_OPTIONS: &str = "BbcDEeFIiJLlmOopQRSWw";
const SCP_SHORT_VALUE_OPTIONS: &str = "DFiJloPSXc";
const RSYNC_SHORT_VALUE_OPTIONS: &str = "BefMT@";

fn scp(arguments: &[Word]) -> Option<Lowering> {
    let values = argument_values(arguments);
    let operands = positional_scp_arguments(&values)?;
    if operands.len() < 2 {
        return None;
    }
    let locations = operands
        .iter()
        .map(|index| remote_location(&arguments[*index], values[*index].as_deref()))
        .collect::<Vec<_>>();
    if locations
        .iter()
        .all(|location| *location == RemoteLocation::Local)
    {
        return None;
    }
    let recursive = scp_recursive(&values);
    let destination = *operands.last()?;
    let destination_location = *locations.last()?;
    let mut filesystems = Vec::new();
    if destination_location != RemoteLocation::Local {
        filesystems.extend(
            operands[..operands.len() - 1]
                .iter()
                .zip(&locations[..locations.len() - 1])
                .filter_map(|(source, location)| {
                    (*location == RemoteLocation::Local)
                        .then(|| values[*source].as_deref())
                        .flatten()
                        .map(|source| (source.to_owned(), FilesystemOperation::Read, recursive))
                }),
        );
    } else if let Some(destination) = values[destination].as_deref() {
        filesystems.push((destination.to_owned(), FilesystemOperation::Write, false));
    }
    Some(Lowering {
        complete: values.iter().all(Option::is_some),
        filesystems,
        stdin_flows: false,
        stdout_flows: false,
        network: true,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

/// Uploads to a remote rsync destination are the same visible transport as
/// `scp`. Local-only copies keep their filesystem lowering in `bash_filesystem`,
/// so returning `None` here leaves that path untouched.
fn rsync(arguments: &[Word]) -> Option<Lowering> {
    let values = argument_values(arguments);
    let mut operands = Vec::<usize>::new();
    let mut dry_run = false;
    let mut recursive = false;
    let mut after_options = false;
    let mut index = 0;
    while index < values.len() {
        let Some(argument) = values[index].as_deref() else {
            operands.push(index);
            index += 1;
            continue;
        };
        if !after_options {
            if matches!(argument, "--no-r" | "--no-recursive") {
                recursive = false;
            } else if matches!(argument, "-r" | "--recursive" | "-a" | "--archive")
                || rsync_argument_has_short_flag(argument, 'r')
                || rsync_argument_has_short_flag(argument, 'a')
            {
                recursive = true;
            }
        }
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "--help" | "--version") {
            return None;
        } else if !after_options
            && (rsync_option_takes_value(argument)
                || short_option_consumes_next(argument, RSYNC_SHORT_VALUE_OPTIONS))
        {
            index += 2;
            continue;
        } else if !after_options
            && (matches!(argument, "--dry-run" | "--list-only")
                || rsync_argument_has_short_flag(argument, 'n'))
        {
            dry_run = true;
        } else if !after_options && argument.starts_with('-') {
        } else {
            operands.push(index);
        }
        index += 1;
    }
    let (destination, sources) = operands.split_last()?;
    if sources.is_empty() || dry_run {
        return None;
    }
    let destination_location =
        remote_location(&arguments[*destination], values[*destination].as_deref());
    let source_locations = sources
        .iter()
        .map(|source| remote_location(&arguments[*source], values[*source].as_deref()))
        .collect::<Vec<_>>();
    if destination_location == RemoteLocation::Local
        && source_locations
            .iter()
            .all(|source| *source == RemoteLocation::Local)
        || destination_location == RemoteLocation::Remote
            && source_locations.contains(&RemoteLocation::Remote)
    {
        return None;
    }
    let mut filesystems = Vec::new();
    if destination_location != RemoteLocation::Local {
        filesystems.extend(
            sources
                .iter()
                .zip(&source_locations)
                .filter_map(|(source, location)| {
                    (*location == RemoteLocation::Local)
                        .then(|| values[*source].as_deref())
                        .flatten()
                })
                .map(|source| {
                    let normalized = source.trim_end_matches(['/', '\\']);
                    (
                        if normalized.is_empty() {
                            source.to_owned()
                        } else {
                            normalized.to_owned()
                        },
                        FilesystemOperation::Read,
                        recursive,
                    )
                }),
        );
    } else if let Some(destination) = values[*destination].as_deref() {
        filesystems.push((destination.to_owned(), FilesystemOperation::Write, false));
    }
    Some(Lowering {
        complete: values.iter().all(Option::is_some),
        filesystems,
        stdin_flows: false,
        stdout_flows: false,
        network: true,
        network_endpoints: Vec::new(),
        descriptor_sources: Vec::new(),
        descriptor_sinks: Vec::new(),
    })
}

fn scp_recursive(arguments: &[Option<String>]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_deref() != Some("--"))
        .flatten()
        .any(|argument| {
            let Some(flags) = short_flags(argument) else {
                return false;
            };
            for flag in flags.chars() {
                if flag == 'r' {
                    return true;
                }
                if "DFiJloPSX".contains(flag) {
                    break;
                }
            }
            false
        })
}

fn positional_scp_arguments(arguments: &[Option<String>]) -> Option<Vec<usize>> {
    let mut operands = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            operands.push(index);
            index += 1;
            continue;
        };
        if argument == "--" {
            operands.extend(index + 1..arguments.len());
            break;
        }
        if matches!(argument, "-V" | "--version" | "-h" | "--help" | "--usage")
            || short_option_has_flag(argument, 'V', SCP_SHORT_VALUE_OPTIONS)
            || short_option_has_flag(argument, 'h', SCP_SHORT_VALUE_OPTIONS)
        {
            return None;
        }
        if short_option_consumes_next(argument, SCP_SHORT_VALUE_OPTIONS) {
            index += 2;
            continue;
        }
        if !argument.starts_with('-') {
            operands.push(index);
        }
        index += 1;
    }
    Some(operands)
}

fn remote_path(argument: &str) -> bool {
    argument
        .split_once(':')
        .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/'))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RemoteLocation {
    Local,
    Remote,
    Unknown,
}

fn remote_location(argument: &Word, value: Option<&str>) -> RemoteLocation {
    match value {
        Some(value) if remote_path(value) => RemoteLocation::Remote,
        Some(_) => RemoteLocation::Local,
        None if remote_path(argument.raw()) => RemoteLocation::Remote,
        None => RemoteLocation::Unknown,
    }
}

fn argument_values(arguments: &[Word]) -> Vec<Option<String>> {
    arguments
        .iter()
        .map(|argument| static_filesystem_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}
