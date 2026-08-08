//! Preserves exact, bounded shell output; it never reads or guesses file content.

use std::collections::BTreeSet;

use nah_parse::{Redirect, Statement, Substitution, Word};
use nah_proto::action::{FilesystemOperation, NetworkDirection, SemanticCode};

use crate::INVOCATION_EVIDENCE_CAP;
use crate::bash_model::{InvocationDraft, StageDraft, StdoutDraft};
use crate::shell_word::static_word;

pub(crate) struct Producer {
    pub(crate) stdout: StdoutDraft,
    pub(crate) complete: bool,
}

pub(crate) fn producer(program: &str, arguments: &[Word], redirects: &[Redirect]) -> Producer {
    let stdout = match program {
        "echo" => echo(arguments).map(StdoutDraft::Exact),
        "printf" => printf(arguments).map(StdoutDraft::Exact),
        "cat" => cat(arguments, redirects),
        "tee" => tee(arguments),
        _ => Some(StdoutDraft::Unknown),
    };
    let complete = stdout
        .as_ref()
        .is_none_or(|stdout| content_len(stdout) <= INVOCATION_EVIDENCE_CAP);
    Producer {
        stdout: stdout
            .filter(|stdout| content_len(stdout) <= INVOCATION_EVIDENCE_CAP)
            .unwrap_or(StdoutDraft::Unknown),
        complete,
    }
}

pub(crate) fn eval_payload(arguments: &[Word]) -> Option<String> {
    arguments
        .iter()
        .map(|argument| {
            if argument.substitutions().is_empty() {
                return static_word(argument.raw(), true);
            }
            let [substitution] = argument.substitutions() else {
                return None;
            };
            if !pure_substitution_word(argument.raw()) {
                return None;
            }
            substitution_output(substitution)
        })
        .collect::<Option<Vec<_>>>()
        .map(|arguments| arguments.join(" "))
}

pub(crate) fn printf_variable_assignment(arguments: &[Word]) -> Option<(String, String)> {
    let mut values = static_arguments(arguments)?;
    if values.first().is_some_and(|value| value == "--") {
        values.remove(0);
    }
    if values.first().is_none_or(|value| value != "-v") || values.len() < 3 {
        return None;
    }
    let name = values[1].clone();
    let value = render_printf(&values[2], &values[3..])?;
    Some((name, value))
}

pub(crate) fn mapfile_descriptor(arguments: &[Word]) -> Option<String> {
    parse_mapfile_options(arguments).map(|options| options.descriptor)
}

pub(crate) fn mapfile_has_callback(arguments: &[Word]) -> bool {
    parse_mapfile_option_prefix(arguments)
        .is_some_and(|options| options.callback && arguments[options.next_argument..].len() <= 1)
}

pub(crate) fn mapfile_variable_assignment(
    arguments: &[Word],
    input: &str,
) -> Option<(String, String)> {
    let options = parse_mapfile_options(arguments)?;
    if !options.exact_assignment {
        return None;
    }
    let end = input.find('\n').map_or(input.len(), |index| index + 1);
    let mut value = input[..end].to_owned();
    if options.trim {
        value.truncate(value.trim_end_matches('\n').len());
    }
    Some((options.target, value))
}

struct MapfileOptions {
    descriptor: String,
    target: String,
    trim: bool,
    exact_assignment: bool,
}

struct MapfileOptionPrefix {
    descriptor: String,
    trim: bool,
    callback: bool,
    exact_assignment: bool,
    next_argument: usize,
}

fn parse_mapfile_option_prefix(arguments: &[Word]) -> Option<MapfileOptionPrefix> {
    let mut descriptor = "0".to_owned();
    let mut trim = false;
    let mut callback = false;
    let mut exact_assignment = true;
    let mut index = 0;
    while index < arguments.len() {
        let raw = arguments[index].raw();
        if static_word(raw, arguments[index].substitutions().is_empty()).as_deref() == Some("--") {
            index += 1;
            break;
        }
        if !raw.starts_with('-') || raw == "-" {
            break;
        }
        for (offset, option) in raw[1..].char_indices() {
            match option {
                't' => trim = true,
                'd' | 'n' | 'O' | 's' | 'u' | 'C' | 'c' => {
                    let argument_offset = offset + option.len_utf8();
                    let value = if argument_offset < raw[1..].len() {
                        raw[1 + argument_offset..].to_owned()
                    } else {
                        index += 1;
                        arguments.get(index)?.raw().to_owned()
                    };
                    if option == 'u' {
                        descriptor = value;
                    } else {
                        exact_assignment = false;
                        callback |= option == 'C';
                    }
                    break;
                }
                _ => return None,
            }
        }
        index += 1;
    }
    Some(MapfileOptionPrefix {
        descriptor,
        trim,
        callback,
        exact_assignment,
        next_argument: index,
    })
}

fn parse_mapfile_options(arguments: &[Word]) -> Option<MapfileOptions> {
    let options = parse_mapfile_option_prefix(arguments)?;
    let remaining = &arguments[options.next_argument..];
    let target = match remaining {
        [] => "MAPFILE".to_owned(),
        [target] => static_word(target.raw(), target.substitutions().is_empty())?,
        _ => return None,
    };
    Some(MapfileOptions {
        descriptor: options.descriptor,
        target,
        trim: options.trim,
        exact_assignment: options.exact_assignment,
    })
}

pub(crate) fn substitution_output(substitution: &Substitution) -> Option<String> {
    let statements = match substitution {
        Substitution::Command { statements } | Substitution::Backtick { statements } => statements,
        Substitution::ProcessInput { .. } | Substitution::ProcessOutput { .. } => return None,
    };
    straight_line_output(statements).map(|output| output.trim_end_matches('\n').to_owned())
}

pub(crate) fn redirect_content_target(redirects: &[Redirect]) -> Option<String> {
    let candidates = redirects
        .iter()
        .filter(|redirect| {
            matches!(redirect.fd(), None | Some("1"))
                && matches!(redirect.operator(), ">" | ">|" | ">&" | "&>")
        })
        .collect::<Vec<_>>();
    let [redirect] = candidates.as_slice() else {
        return None;
    };
    let raw = redirect.target().filter(|target| {
        !matches!(
            *target,
            "1" | "2" | "-" | "/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1"
        )
    })?;
    let target = static_word(raw, redirect.target_substitutions().is_empty())?;
    (!target.starts_with("/dev/tcp/") && !target.starts_with("/dev/udp/")).then_some(target)
}

pub(crate) fn exact_redirect_input(redirect: &Redirect) -> Option<String> {
    match redirect.operator() {
        "<<<" => {
            let mut content = static_word(
                redirect.target()?,
                redirect.target_substitutions().is_empty(),
            )?;
            content.push('\n');
            Some(content)
        }
        "<<" | "<<-" => {
            let delimiter = redirect.target()?;
            let quoted = delimiter.contains(['\'', '"', '\\']);
            let body = redirect.body()?;
            if !quoted
                && (body.contains(['\\', '$', '`']) || !redirect.body_substitutions().is_empty())
            {
                return None;
            }
            if redirect.operator() != "<<-" {
                return Some(body.to_owned());
            }
            let mut stripped = body
                .lines()
                .map(|line| line.trim_start_matches('\t'))
                .collect::<Vec<_>>()
                .join("\n");
            if body.ends_with('\n') {
                stripped.push('\n');
            }
            Some(stripped)
        }
        _ => None,
    }
}

pub(crate) fn tee_content_targets(arguments: &[Word]) -> Option<Vec<String>> {
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    let mut targets = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < values.len() {
        let value = &values[index];
        if !after_options && value == "--" {
            after_options = true;
        } else if !after_options && matches!(value.as_str(), "-a" | "--append") {
            return None;
        } else if !after_options
            && (matches!(
                value.as_str(),
                "-i" | "--ignore-interrupts" | "-p" | "--output-error"
            ) || value.starts_with("--output-error="))
        {
        } else if !after_options && value.starts_with('-') {
            return None;
        } else if value != "-" {
            targets.push(value.clone());
        }
        index += 1;
    }
    Some(targets)
}

pub(crate) fn visible_payloads(
    stages: &[StageDraft],
    flows: &[(usize, usize)],
    seen: &BTreeSet<usize>,
) -> Vec<(usize, String)> {
    let output = visible_outputs(stages, flows);
    let mut payloads = Vec::new();
    for (index, stage) in stages.iter().enumerate() {
        let incoming = unique_incoming(index, flows, &output);
        if seen.contains(&index) {
            continue;
        }
        let Some(payload) = visible_payload(index, stage, stages, &output, flows, incoming) else {
            continue;
        };
        if !payload.is_empty() && payload.len() <= INVOCATION_EVIDENCE_CAP {
            payloads.push((index, payload));
        }
    }
    payloads
}

fn visible_outputs(stages: &[StageDraft], flows: &[(usize, usize)]) -> Vec<Option<String>> {
    let mut output = stages
        .iter()
        .map(|stage| match &stage.stdout {
            StdoutDraft::Exact(content) => Some(content.clone()),
            StdoutDraft::Unknown | StdoutDraft::Stdin => None,
        })
        .collect::<Vec<_>>();
    for _ in 0..=stages.len() {
        let mut next = output.clone();
        for (index, stage) in stages.iter().enumerate() {
            if matches!(stage.stdout, StdoutDraft::Stdin) {
                next[index] = unique_incoming(index, flows, &output);
            }
        }
        if next == output {
            return output;
        }
        output = next;
    }
    for (index, stage) in stages.iter().enumerate() {
        if matches!(stage.stdout, StdoutDraft::Stdin) {
            output[index] = None;
        }
    }
    output
}

pub(crate) fn has_unresolved_execution(
    stages: &[StageDraft],
    flows: &[(usize, usize)],
    resolved: &BTreeSet<usize>,
) -> bool {
    stages.iter().enumerate().any(|(index, stage)| {
        let InvocationDraft::CodeExecution { code, .. } = &stage.invocation else {
            return false;
        };
        code.is_none()
            && !resolved.contains(&index)
            && !guarded_unknown_source(index, stages, flows)
    })
}

pub(crate) fn guarded_unknown_source(
    sink: usize,
    stages: &[StageDraft],
    flows: &[(usize, usize)],
) -> bool {
    if stages[sink]
        .network_endpoints
        .iter()
        .any(|(direction, _)| *direction == NetworkDirection::Inbound)
    {
        return true;
    }
    let mut pending = vec![sink];
    let mut visited = BTreeSet::new();
    while let Some(stage) = pending.pop() {
        if !visited.insert(stage) {
            continue;
        }
        if matches!(
            &stages[stage].invocation,
            InvocationDraft::Known { operation, .. }
                if operation == &SemanticCode::NETWORK_TRANSFER
                    || operation == &SemanticCode::DECODE
        ) {
            return true;
        }
        pending.extend(
            flows
                .iter()
                .filter_map(|(source, target)| (*target == stage).then_some(*source)),
        );
    }
    false
}

fn visible_payload(
    index: usize,
    stage: &StageDraft,
    stages: &[StageDraft],
    output: &[Option<String>],
    flows: &[(usize, usize)],
    incoming: Option<String>,
) -> Option<String> {
    let InvocationDraft::CodeExecution {
        program,
        source,
        code,
        words,
        ..
    } = &stage.invocation
    else {
        return None;
    };
    if let Some(code) = code {
        return (source == &SemanticCode::SHELL_FILE || source == &SemanticCode::SHELL_STDIN)
            .then(|| code.clone());
    }
    if source.as_str().ends_with("-stdin")
        || (program == "eval" && pure_substitution_argument(words))
    {
        return incoming;
    }
    if !source.as_str().ends_with("-file") {
        return None;
    }
    let target = stage
        .filesystems
        .iter()
        .find(|filesystem| filesystem.operation == FilesystemOperation::Read)?
        .requested
        .as_str();
    (0..stages.len())
        .rev()
        .filter(|source| flows.contains(&(*source, index)))
        .find_map(|source| {
            stages[source]
                .content_writes
                .iter()
                .any(|written| written == target)
                .then(|| output[source].clone())
                .flatten()
        })
}

fn unique_incoming(
    sink: usize,
    flows: &[(usize, usize)],
    output: &[Option<String>],
) -> Option<String> {
    let mut values = flows.iter().filter_map(|(source, target)| {
        (*target == sink).then(|| output[*source].clone()).flatten()
    });
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

fn pure_substitution_argument(words: &[String]) -> bool {
    let [_, argument] = words else {
        return false;
    };
    pure_substitution_word(argument)
}

fn pure_substitution_word(argument: &str) -> bool {
    let argument = argument
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(argument);
    (argument.starts_with("$(") && argument.ends_with(')'))
        || (argument.starts_with('`') && argument.ends_with('`'))
}

fn straight_line_output(statements: &[Statement]) -> Option<String> {
    let mut output = String::new();
    for statement in statements {
        match statement {
            Statement::Command {
                name,
                name_substitutions,
                assignments,
                unmodeled_assignments,
                arguments,
                redirects,
            } => {
                if !assignments.is_empty() || !unmodeled_assignments.is_empty() {
                    return None;
                }
                if redirects.iter().any(|redirect| {
                    matches!(redirect.fd(), None | Some("1"))
                        && matches!(redirect.operator(), ">" | ">>" | ">|" | ">&" | "&>" | "&>>")
                }) {
                    return None;
                }
                let program = static_word(name, name_substitutions.is_empty())?;
                let Producer {
                    stdout: StdoutDraft::Exact(content),
                    ..
                } = producer(&program, arguments, redirects)
                else {
                    return None;
                };
                output.push_str(&content);
            }
            Statement::Subshell { statements } | Statement::Group { statements } => {
                output.push_str(&straight_line_output(statements)?);
            }
            _ => return None,
        }
        if output.len() > INVOCATION_EVIDENCE_CAP {
            return None;
        }
    }
    Some(output)
}

fn echo(arguments: &[Word]) -> Option<String> {
    let mut values = static_arguments(arguments)?;
    let newline = if values.first().is_some_and(|value| value == "-n") {
        values.remove(0);
        false
    } else {
        if values.first().is_some_and(|value| {
            value.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty() && flags.chars().all(|flag| "neE".contains(flag))
            })
        }) {
            return None;
        }
        true
    };
    if values.iter().any(|value| value.contains('\\'))
        || values
            .first()
            .is_some_and(|value| matches!(value.as_str(), "-e" | "-E"))
    {
        return None;
    }
    let mut output = values.join(" ");
    if newline {
        output.push('\n');
    }
    Some(output)
}

fn printf(arguments: &[Word]) -> Option<String> {
    let mut values = static_arguments(arguments)?;
    if values.first().is_some_and(|value| value == "--") {
        values.remove(0);
    }
    let format = values.first()?;
    if format == "-v" || format.starts_with('-') {
        return None;
    }
    render_printf(format, &values[1..])
}

fn render_printf(format: &str, arguments: &[String]) -> Option<String> {
    let mut output = String::new();
    let mut offset = 0;
    loop {
        let consumed = render_printf_once(format, &arguments[offset..], &mut output)?;
        if output.len() > INVOCATION_EVIDENCE_CAP {
            return None;
        }
        if consumed == 0 || offset + consumed >= arguments.len() {
            return Some(output);
        }
        offset += consumed;
    }
}

fn render_printf_once(format: &str, arguments: &[String], output: &mut String) -> Option<usize> {
    let mut chars = format.chars().peekable();
    let mut consumed = 0;
    while let Some(character) = chars.next() {
        match character {
            '%' => match chars.next()? {
                '%' => output.push('%'),
                's' => {
                    output.push_str(arguments.get(consumed).map_or("", String::as_str));
                    consumed += 1;
                }
                'b' => {
                    let argument = arguments.get(consumed).map_or("", String::as_str);
                    if argument.contains('\\') {
                        return None;
                    }
                    output.push_str(argument);
                    consumed += 1;
                }
                _ => return None,
            },
            '\\' => output.push(decode_escape(&mut chars)?),
            character => output.push(character),
        }
    }
    Some(consumed)
}

fn cat(arguments: &[Word], redirects: &[Redirect]) -> Option<StdoutDraft> {
    if !arguments.is_empty() {
        return Some(StdoutDraft::Unknown);
    }
    let stdin = redirects.iter().rev().find(|redirect| {
        matches!(redirect.fd(), None | Some("0"))
            && matches!(redirect.operator(), "<<" | "<<-" | "<<<")
    });
    match stdin {
        Some(redirect) => exact_redirect_input(redirect).map(StdoutDraft::Exact),
        None => Some(StdoutDraft::Stdin),
    }
}

fn tee(arguments: &[Word]) -> Option<StdoutDraft> {
    tee_content_targets(arguments).map(|_| StdoutDraft::Stdin)
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}

fn content_len(stdout: &StdoutDraft) -> usize {
    match stdout {
        StdoutDraft::Exact(content) => content.len(),
        StdoutDraft::Unknown | StdoutDraft::Stdin => 0,
    }
}

fn decode_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<char> {
    Some(match chars.next()? {
        'a' => '\u{7}',
        'b' => '\u{8}',
        'e' | 'E' => '\u{1b}',
        'f' => '\u{c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\u{b}',
        '0' => {
            let mut value = 0;
            for _ in 0..3 {
                let Some(digit) = chars.peek().and_then(|character| character.to_digit(8)) else {
                    break;
                };
                chars.next();
                value = value * 8 + digit;
            }
            char::from_u32(value)?
        }
        '\\' => '\\',
        '\'' => '\'',
        '"' => '"',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash_model::ProgramDraft;

    fn words(source: &str) -> Vec<Word> {
        let syntax = nah_parse::normalize(&format!("mapfile {source}")).unwrap();
        let [Statement::Command { arguments, .. }] = syntax.statements() else {
            panic!("expected one command");
        };
        arguments.clone()
    }

    fn stage(stdout: StdoutDraft) -> StageDraft {
        StageDraft {
            invocation: InvocationDraft::Opaque {
                program: ProgramDraft::Static("test".into()),
                words: vec!["test".into()],
                argv: Some(vec!["test".into()]),
            },
            invocation_cwd: Some("/repo".into()),
            child_cwd_keys: Vec::new(),
            filesystems: Vec::new(),
            git_operations: Vec::new(),
            git_project_scoped: false,
            network_outbound: false,
            network_endpoints: Vec::new(),
            system_states: Vec::new(),
            fifo_creations: Vec::new(),
            stdout,
            content_writes: Vec::new(),
            payload_depth: 0,
            conditional_depth: 0,
            execution_dominators: Vec::new(),
        }
    }

    #[test]
    fn visible_outputs_follow_backward_edges_and_identical_cycles() {
        let backward = vec![
            stage(StdoutDraft::Stdin),
            stage(StdoutDraft::Exact("payload".into())),
        ];
        assert_eq!(
            visible_outputs(&backward, &[(1, 0)]),
            vec![Some("payload".into()), Some("payload".into())]
        );

        let cycle = vec![
            stage(StdoutDraft::Stdin),
            stage(StdoutDraft::Stdin),
            stage(StdoutDraft::Exact("payload".into())),
        ];
        assert_eq!(
            visible_outputs(&cycle, &[(2, 0), (0, 1), (1, 0)]),
            vec![
                Some("payload".into()),
                Some("payload".into()),
                Some("payload".into())
            ]
        );
    }

    #[test]
    fn conflicting_cycles_never_publish_an_exact_payload() {
        let stages = vec![
            stage(StdoutDraft::Stdin),
            stage(StdoutDraft::Stdin),
            stage(StdoutDraft::Exact("left".into())),
            stage(StdoutDraft::Exact("right".into())),
        ];
        let output = visible_outputs(&stages, &[(2, 0), (0, 1), (3, 1), (1, 0)]);
        assert_eq!(output[0], None);
        assert_eq!(output[1], None);
        assert_eq!(output[2], Some("left".into()));
        assert_eq!(output[3], Some("right".into()));
    }

    #[test]
    fn mapfile_options_preserve_clustered_descriptors_and_exact_first_entry() {
        assert_eq!(
            mapfile_descriptor(&words(r#"-tu"$fd" rows"#)).as_deref(),
            Some("\"$fd\"")
        );
        assert_eq!(
            mapfile_descriptor(&words("-tn 1 -u 3 rows")).as_deref(),
            Some("3")
        );
        assert_eq!(
            mapfile_variable_assignment(&words("-tu 3 rows"), "rm -rf /\nnext\n"),
            Some(("rows".into(), "rm -rf /".into()))
        );
        assert!(mapfile_has_callback(&words("-tC callback -c 1 rows")));
        assert!(mapfile_has_callback(&words(
            r#"-tC callback -c 1 "$ARRAY""#
        )));
        assert!(!mapfile_has_callback(&words("-tc 1 rows")));
        assert!(!mapfile_has_callback(&words("-C callback --bad rows")));
        assert!(mapfile_variable_assignment(&words("-n 1 -u3 rows"), "rm -rf /\nnext\n").is_none());
    }

    #[test]
    fn printf_octal_nul_is_exact() {
        assert_eq!(
            render_printf("%s\\0", &["path".into()]),
            Some("path\0".into())
        );
    }
}
