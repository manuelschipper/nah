//! `osascript [-l language] [-i] [-s flags] [-e statement]... [programfile]
//! [argument...]` runs AppleScript. Its `do shell script "..."` command runs
//! the string as `sh -c` source, so a literal one is analyzed as nested shell
//! source. Every other AppleScript command (Apple events sent to applications,
//! `run script`, raw «event» codes) is unmodeled, so the program always keeps
//! a boundary, as does a program file, stdin, or another OSA language.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
    RequestAssurance, Subject,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{arg_node, code_execution, operand_effect};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

pub(crate) struct Osascript;

impl CommandModel for Osascript {
    fn id(&self) -> &'static str {
        "apple/osascript@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["osascript"]
    }

    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut statements: Vec<(u32, Word)> = Vec::new();
        let mut applescript = true;
        let mut interactive = false;
        let mut i = 1;
        while let Some(word) = ctx.argv.get(i) {
            let Some(text) = word.as_literal() else {
                osascript_boundary(
                    builder,
                    model_node,
                    BoundaryClass::Unresolved,
                    "osascript option is not a literal",
                );
                return;
            };
            if text == "--" {
                i += 1;
                break;
            }
            if !text.starts_with('-') || text == "-" {
                break;
            }
            let Some((flag, attached)) = text.split_at_checked(2) else {
                osascript_boundary(
                    builder,
                    model_node,
                    BoundaryClass::Unresolved,
                    &format!("osascript option {text:?} is not modeled"),
                );
                return;
            };
            let value = if matches!(flag, "-e" | "-l" | "-s") && attached.is_empty() {
                i += 1;
                ctx.argv.get(i).map(|word| (i as u32, word.clone()))
            } else {
                Some((i as u32, Word::literal(attached)))
            };
            match (flag, value) {
                ("-e", Some(statement)) => statements.push(statement),
                ("-l", Some((_, language))) => {
                    applescript = language
                        .as_literal()
                        .is_some_and(|language| language.eq_ignore_ascii_case("AppleScript"));
                }
                ("-s", Some(_)) => {}
                ("-i", _) if attached.is_empty() => interactive = true,
                _ => {
                    osascript_boundary(
                        builder,
                        model_node,
                        BoundaryClass::Unresolved,
                        &format!("osascript option {text:?} is not modeled"),
                    );
                    return;
                }
            }
            i += 1;
        }

        let Some((first, _)) = statements.first() else {
            // Without `-e` the program is the file operand, or stdin.
            let file = ctx
                .argv
                .get(i)
                .filter(|word| word.as_literal() != Some("-"));
            if let Some(file) = file {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    i as u32,
                    file,
                    "filesystem.read",
                    Default::default(),
                );
            }
            code_execution(
                RequestAssurance::Conservative,
                builder,
                ctx,
                model_node,
                file.map(|_| i as u32),
                if file.is_some() { "file" } else { "stdin" },
                Default::default(),
            );
            osascript_boundary(
                builder,
                model_node,
                BoundaryClass::Unresolved,
                if file.is_some() {
                    "osascript program file is not inspected"
                } else {
                    "osascript reads its program from stdin"
                },
            );
            return;
        };
        code_execution(
            RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            Some(*first),
            "argument",
            Default::default(),
        );
        let arg = arg_node(builder, ctx, *first);
        // Each `-e` is one line of the program.
        let source = statements
            .iter()
            .map(|(_, word)| word.as_literal())
            .collect::<Option<Vec<_>>>()
            .map(|lines| lines.join("\n"));
        let detail = match source {
            None => "osascript -e statement is not a literal",
            Some(_) if !applescript => "osascript program in a language other than AppleScript",
            Some(_) if interactive => "osascript -i reads more statements from stdin",
            Some(source) => {
                let mut dynamic = false;
                for command in shell_scripts(&source) {
                    match command {
                        Some(command) => ctx.nest_subject(
                            builder,
                            Subject::Shell {
                                source: command,
                                cwd: ctx.cwd.map(str::to_string),
                                context: Default::default(),
                            },
                            &[model_node, arg],
                        ),
                        None => dynamic = true,
                    }
                }
                if dynamic {
                    osascript_boundary(
                        builder,
                        model_node,
                        BoundaryClass::Unresolved,
                        "AppleScript do shell script command is not a literal",
                    );
                }
                "AppleScript commands other than do shell script are not modeled"
            }
        };
        osascript_boundary(builder, model_node, BoundaryClass::Unsupported, detail);
    }
}

fn osascript_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    class: BoundaryClass,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNPARSED_SCRIPT,
        class,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

/// The command string of each `do shell script` in AppleScript source, or
/// None where it is not one string literal (a variable, `&` concatenation).
/// Strings and comments are skipped, so their text is never taken for a
/// command.
fn shell_scripts(source: &str) -> Vec<Option<String>> {
    let mut commands = Vec::new();
    let mut rest = source;
    let mut word_start = true;
    while let Some(c) = rest.chars().next() {
        if rest.starts_with('"') {
            (_, rest) = string_literal(rest);
            word_start = true;
            continue;
        }
        if rest.starts_with("--") || rest.starts_with('#') {
            rest = rest.find('\n').map_or("", |end| &rest[end..]);
            continue;
        }
        if rest.starts_with("(*") {
            rest = block_comment_end(rest);
            word_start = true;
            continue;
        }
        if word_start && let Some(after) = do_shell_script(rest) {
            let argument = skip_space(after);
            let (command, after) = if argument.starts_with('"') {
                string_literal(argument)
            } else {
                (None, argument)
            };
            let joined = skip_space(after).starts_with('&');
            commands.push(command.filter(|_| !joined));
            rest = after;
            word_start = true;
            continue;
        }
        word_start = !(c.is_alphanumeric() || c == '_');
        rest = &rest[c.len_utf8()..];
    }
    commands
}

/// `rest` without its leading spaces. A `¬` continues the line, so it and
/// the line break after it are spacing too.
fn skip_space(mut rest: &str) -> &str {
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        match rest.strip_prefix('¬') {
            Some(after) => rest = after.trim_start_matches([' ', '\t', '\r', '\n']),
            None => return rest,
        }
    }
}

/// The text after `do shell script` when `rest` starts with it (case- and
/// spacing-insensitive, as AppleScript reads it).
fn do_shell_script(rest: &str) -> Option<&str> {
    let mut rest = rest;
    for word in ["do", "shell", "script"] {
        rest = skip_space(rest);
        let head = rest.get(..word.len())?;
        if !head.eq_ignore_ascii_case(word) {
            return None;
        }
        rest = &rest[word.len()..];
        if !rest.starts_with([' ', '\t', '"', '\n', '¬']) && !rest.is_empty() {
            return None;
        }
    }
    Some(rest)
}

/// Decode the string literal `rest` starts with, returning its value (None
/// for an escape AppleScript does not define, or an unterminated string) and
/// the text after it.
fn string_literal(rest: &str) -> (Option<String>, &str) {
    let mut value = Some(String::new());
    let mut chars = rest.char_indices().skip(1);
    while let Some((index, c)) = chars.next() {
        let decoded = match c {
            '"' => return (value, &rest[index + 1..]),
            '\\' => match chars.next() {
                Some((_, '"')) => Some('"'),
                Some((_, '\\')) => Some('\\'),
                Some((_, 'n')) => Some('\n'),
                Some((_, 'r')) => Some('\r'),
                Some((_, 't')) => Some('\t'),
                _ => None,
            },
            c => Some(c),
        };
        match (decoded, value.as_mut()) {
            (Some(c), Some(value)) => value.push(c),
            _ => value = None,
        }
    }
    (None, "")
}

/// The text after the `(* ... *)` comment `rest` starts with; they nest.
fn block_comment_end(rest: &str) -> &str {
    let mut depth = 0usize;
    let mut index = 0;
    while index < rest.len() {
        if rest[index..].starts_with("(*") {
            depth += 1;
            index += 2;
        } else if rest[index..].starts_with("*)") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return &rest[index..];
            }
        } else {
            index += rest[index..].chars().next().map_or(1, char::len_utf8);
        }
    }
    ""
}
