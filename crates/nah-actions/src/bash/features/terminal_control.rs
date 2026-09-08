//! Recognizes bounded terminal delivery without receiver state or host observations.

use crate::bash_self_protection::{normalized_program, operation_for_values};
use crate::bash_wrappers::{
    executor_payloads, shell_payload, shell_string_wrapper_payload, wrapper_payload,
};
use crate::shell_word::static_word;
use nah_parse::Statement;
use nah_proto::action::{
    EffectKind, InvocationEffect, InvocationInput, NahProtectionTier, ProtectedNahOperation,
    TerminalCandidate, TerminalCarrier, TerminalContent, TerminalControl, TerminalOperation,
};

const CONTENT_CAP: usize = 16_384;

/// Converts only recognized carriers; the invocation's cwd remains the caller's.
pub(crate) fn invocation(effect: EffectKind, complete: &mut bool) -> EffectKind {
    let EffectKind::Invocation {
        invocation:
            InvocationEffect::Opaque {
                program,
                input,
                cwd,
            },
    } = &effect
    else {
        return effect;
    };
    let control = match input {
        InvocationInput::Shell {
            argv: Some(argv), ..
        } => {
            let name = program.rsplit('/').next().unwrap_or(program);
            match name {
                "herdr" => herdr(&argv[1..], complete),
                "tmux" => {
                    if argv
                        .get(1)
                        .is_some_and(|argument| argument.starts_with('-'))
                    {
                        *complete = false;
                    }
                    tmux_input(&argv[1..])
                }
                _ => None,
            }
        }
        InvocationInput::Native { value, .. } if program == "process" => {
            let operation = match value.get("action").and_then(|value| value.as_str()) {
                Some("write" | "send-keys") => TerminalOperation::Input,
                Some("submit") => TerminalOperation::Submit,
                Some("paste") => TerminalOperation::PasteUnknownBuffer,
                _ => return effect,
            };
            Some(unknown(TerminalCarrier::OpenclawProcess, operation))
        }
        _ => None,
    };
    let Some(mut control) = control else {
        return effect;
    };
    for selector in [&mut control.target, &mut control.selector] {
        if selector
            .as_ref()
            .is_some_and(|value| value.len() > CONTENT_CAP || value.contains('\0'))
        {
            *selector = None;
            *complete = false;
        }
    }
    if let TerminalContent::Literal { text } = &control.content {
        if text.len() > CONTENT_CAP || text.contains('\0') {
            control.content = TerminalContent::Unknown;
        } else if matches!(
            control.operation,
            TerminalOperation::Input | TerminalOperation::InputAndSubmit
        ) {
            let (candidate, understood) = candidate(text, 0);
            control.candidate = candidate;
            *complete &= understood;
        }
    }
    if matches!(control.content, TerminalContent::Unknown) {
        *complete = false;
    }
    EffectKind::Invocation {
        invocation: InvocationEffect::TerminalControl {
            program: program.clone(),
            input: input.clone(),
            cwd: cwd.clone(),
            control,
        },
    }
}

fn unknown(carrier: TerminalCarrier, operation: TerminalOperation) -> TerminalControl {
    TerminalControl {
        carrier,
        operation,
        target: None,
        selector: None,
        content: TerminalContent::Unknown,
        candidate: None,
    }
}

fn herdr(arguments: &[String], complete: &mut bool) -> Option<TerminalControl> {
    let mut args = Vec::new();
    let mut selector = None;
    let mut index = 0;
    // Session selection is transport routing, never receiver authority.
    while index < arguments.len() {
        if arguments[index] == "--session" {
            selector = Some(arguments.get(index + 1)?.clone());
            index += 2;
        } else if args.len() < 2 && arguments[index].starts_with('-') {
            *complete = false;
            return None;
        } else {
            args.push(arguments[index].as_str());
            index += 1;
        }
    }
    let [group, action, rest @ ..] = args.as_slice() else {
        return None;
    };
    let operation = match (*group, *action) {
        ("pane", "run") => TerminalOperation::InputAndSubmit,
        ("pane", "send-text" | "send-keys") | ("agent", "send-keys") => TerminalOperation::Input,
        ("agent", "prompt") => TerminalOperation::AgentPrompt,
        _ => return None,
    };
    let mut control = unknown(TerminalCarrier::Herdr, operation);
    control.selector = selector;
    let [target, payload @ ..] = rest else {
        return Some(control);
    };
    if target.starts_with('-') {
        return Some(control);
    }
    control.target = Some((*target).to_owned());
    if *action == "send-keys" {
        decode_keys(payload, false, &mut control);
    } else {
        let [text, options @ ..] = payload else {
            return Some(control);
        };
        let mut index = 0;
        while index < options.len() {
            if operation == TerminalOperation::AgentPrompt && options[index] == "--wait" {
                index += 1;
            } else if operation == TerminalOperation::AgentPrompt
                && options[index] == "--timeout"
                && options
                    .get(index + 1)
                    .is_some_and(|value| value.parse::<u64>().is_ok())
            {
                index += 2;
            } else {
                return Some(control);
            }
        }
        control.content = TerminalContent::Literal {
            text: (*text).to_owned(),
        };
    }
    Some(control)
}

fn tmux_input(arguments: &[String]) -> Option<TerminalControl> {
    let [command, rest @ ..] = arguments else {
        return None;
    };
    let paste = matches!(command.as_str(), "paste-buffer" | "pasteb");
    if !paste && !matches!(command.as_str(), "send-keys" | "send") {
        return None;
    }
    let mut control = unknown(
        TerminalCarrier::Tmux,
        if paste {
            TerminalOperation::PasteUnknownBuffer
        } else {
            TerminalOperation::Input
        },
    );
    let mut literal = false;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "-t" => {
                control.target = Some(rest.get(index + 1)?.clone());
                index += 2;
            }
            "-l" if !paste => {
                literal = true;
                index += 1;
            }
            "-b" | "-s" if paste => {
                rest.get(index + 1)?;
                index += 2;
            }
            "-d" | "-p" | "-r" if paste => {
                index += 1;
            }
            "--" => {
                index += 1;
                break;
            }
            arg if arg.starts_with('-') => return Some(control),
            _ => break,
        }
    }
    if !paste {
        let keys = rest[index..].iter().map(String::as_str).collect::<Vec<_>>();
        decode_keys(&keys, literal, &mut control);
    }
    Some(control)
}

fn decode_keys(keys: &[&str], literal: bool, control: &mut TerminalControl) {
    if keys.is_empty() {
        return;
    }
    let mut text = String::new();
    let mut submit = false;
    for key in keys {
        if literal {
            text.push_str(key);
            continue;
        }
        match *key {
            "Enter" | "enter" | "Return" | "C-m" | "ctrl+m" | "\r" | "\n" => {
                submit = true;
                text.push('\n');
            }
            "Space" | "space" => text.push(' '),
            key if key.starts_with("C-")
                || key.starts_with("M-")
                || key.starts_with("ctrl+")
                || matches!(
                    key,
                    "Escape" | "esc" | "BSpace" | "Tab" | "Up" | "Down" | "Left" | "Right"
                )
                || key.chars().any(char::is_control) =>
            {
                return;
            }
            key => text.push_str(key),
        }
    }
    control.operation = if submit && text.trim().is_empty() {
        TerminalOperation::Submit
    } else if submit {
        TerminalOperation::InputAndSubmit
    } else {
        TerminalOperation::Input
    };
    control.content = TerminalContent::Literal { text };
}

/// Restricted executable positions share Nah CLI semantics but import no receiver facts.
fn candidate(source: &str, depth: usize) -> (Option<TerminalCandidate>, bool) {
    if depth >= 8 || source.len() > CONTENT_CAP {
        return (None, false);
    }
    let Ok(syntax) = nah_parse::normalize(source) else {
        return (None, false);
    };
    if !syntax.syntactically_valid() {
        return (None, false);
    }
    let (candidate, complete) = statements_candidate(syntax.statements().iter(), depth);
    (candidate, complete && syntax.complete())
}

fn statement_candidate(statement: &Statement, depth: usize) -> (Option<TerminalCandidate>, bool) {
    match statement {
        Statement::Command {
            name,
            name_substitutions,
            arguments,
            assignments,
            ..
        } => {
            let Some(program) = static_word(name, name_substitutions.is_empty()) else {
                return (None, false);
            };
            let values = arguments
                .iter()
                .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
                .collect::<Vec<_>>();
            let complete = values.iter().all(Option::is_some)
                && assignments.iter().all(|(_, value)| {
                    static_word(value.raw(), value.substitutions().is_empty()).is_some()
                });
            // Only the literal prefix can establish the operation. Later known words
            // can still veto it (notably --help), but cannot fill an unknown verb.
            if normalized_program(&program) == "nah" {
                let prefix = values
                    .iter()
                    .cloned()
                    .take_while(Option::is_some)
                    .flatten()
                    .collect::<Vec<_>>();
                let known = values.into_iter().flatten().collect::<Vec<_>>();
                let operation = operation_for_values(&program, &prefix)
                    .filter(|operation| operation_for_values(&program, &known) == Some(*operation));
                let operation = match operation {
                    Some("permanent-mutation") => Some(TerminalCandidate {
                        operation: ProtectedNahOperation::Nap,
                        tier: NahProtectionTier::Permanent,
                    }),
                    Some("critical-mutation") => Some(TerminalCandidate {
                        operation: ProtectedNahOperation::Maintenance,
                        tier: NahProtectionTier::Critical,
                    }),
                    _ => None,
                };
                return (operation, complete);
            }
            // Reuse reviewed operand decoders and standard POSIX executable identity;
            // their payloads establish syntax, never receiver cwd or environment.
            let program =
                crate::bash_semantics::normalize_program(&program, nah_proto::ctx::Platform::Linux)
                    .unwrap_or(program);
            if let Some(payload) = shell_payload(&program, arguments, &[])
                .or_else(|| wrapper_payload(&program, arguments))
                .or_else(|| {
                    shell_string_wrapper_payload(&program, arguments)
                        .ok()
                        .flatten()
                        .map(|(payload, _)| payload)
                })
            {
                let (found, understood) = candidate(&payload, depth + 1);
                return (found, complete && understood);
            }
            // These local executors expose explicit operands. Remote executors and
            // commands supplied only by unknown stdin remain outside input matching.
            if matches!(program.as_str(), "xargs" | "find" | "tar" | "bsdtar") {
                let mut best = None;
                for executor in executor_payloads(&program, arguments, &[], None) {
                    let (found, _) = candidate(&executor.payload, depth + 1);
                    if found.is_some_and(|found| found.tier == NahProtectionTier::Permanent)
                        || best.is_none()
                    {
                        best = found;
                    }
                }
                return (best, false);
            }
            // Unmodeled executable positions may themselves carry a command.
            (None, false)
        }
        Statement::Chain { items, .. }
        | Statement::Pipeline { stages: items, .. }
        | Statement::Subshell { statements: items }
        | Statement::Group { statements: items }
        | Statement::For { body: items, .. } => statements_candidate(items.iter(), depth),
        Statement::Coprocess { body, .. } | Statement::Redirected { body, .. } => {
            statement_candidate(body, depth)
        }
        Statement::If {
            branches,
            else_body,
        } => statements_candidate(
            branches
                .iter()
                .flat_map(|branch| branch.condition().iter().chain(branch.body()))
                .chain(else_body),
            depth,
        ),
        Statement::Loop {
            condition, body, ..
        } => statements_candidate(condition.iter().chain(body), depth),
        Statement::Case { arms, .. } => {
            statements_candidate(arms.iter().flat_map(|arm| arm.body()), depth)
        }
        Statement::Unsupported { statements, .. }
        | Statement::UnmodeledStateMutation { statements, .. } => {
            // The parser retains executable descendants even when surrounding semantics
            // are unknown, such as negation or a C-style loop header.
            let (candidate, _) = statements_candidate(statements.iter(), depth);
            (candidate, false)
        }
        Statement::Assignments { .. }
        | Statement::FunctionDefinition { .. }
        | Statement::LoopControl { .. }
        | Statement::RedirectOnly { .. } => (None, false),
    }
}

// Visit executable positions only: function definitions and quoted data are not input candidates.
fn statements_candidate<'a>(
    statements: impl Iterator<Item = &'a Statement>,
    depth: usize,
) -> (Option<TerminalCandidate>, bool) {
    let mut best = None;
    let mut complete = true;
    for statement in statements {
        let (found, understood) = statement_candidate(statement, depth);
        complete &= understood;
        if found.is_some_and(|found| found.tier == NahProtectionTier::Permanent) || best.is_none() {
            best = found;
        }
    }
    (best, complete)
}

/// Tmux launches carry exact argv or shell source, with no inherited receiver context.
pub(crate) fn tmux_launch(arguments: &[nah_parse::Word]) -> Option<String> {
    let values = arguments
        .iter()
        .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    let [command, rest @ ..] = values.as_slice() else {
        return None;
    };
    let (flags, options) = match command.as_str() {
        "new-session" | "new" => ("d", "sntce"),
        "new-window" | "neww" => ("dk", "ntce"),
        "split-window" | "splitw" => ("dhv", "tce"),
        "respawn-pane" | "respawnp" | "respawn-window" | "respawnw" => ("k", "tce"),
        _ => return None,
    };
    let mut index = 0;
    while index < rest.len() && rest[index].starts_with('-') {
        if rest[index] == "--" {
            index += 1;
            break;
        }
        let mut chars = rest[index][1..].char_indices();
        while let Some((offset, flag)) = chars.next() {
            if options.contains(flag) {
                let value = if chars.next().is_some() {
                    &rest[index][offset + 2..]
                } else {
                    index += 1;
                    rest.get(index)?
                };
                if value.contains(['#', '\0']) {
                    return Some(String::new());
                }
                break;
            }
            if !flags.contains(flag) {
                return Some(String::new());
            }
        }
        index += 1;
    }
    let payload = &rest[index..];
    if payload.is_empty() || payload.iter().any(|value| value.contains('#')) {
        return Some(String::new());
    }
    let source = if payload.len() == 1 {
        payload[0].clone()
    } else {
        payload
            .iter()
            .map(|value| format!("'{}'", value.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ")
    };
    Some(source)
}
