//! `osascript [-l language] [-i] [-s flags] [-e statement]... [programfile]
//! [argument...]` runs AppleScript. Its `do shell script` command runs the
//! string as `sh -c` source. A command built from string literals, `set`
//! bindings of those pieces, and `(system attribute "NAME")` is nested shell
//! source; any other argument stays a boundary. JavaScript for Automation
//! (`-l JavaScript`) nests a literal `$.system(...)` the same way. Every other
//! command stays unmodeled, so the program always keeps a boundary, as does a
//! program file or stdin.

use std::collections::HashMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
    RequestAssurance, ResourceExpr, Subject,
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
            Some(_) if interactive => "osascript -i reads more statements from stdin",
            Some(source) if !applescript => {
                let mut dynamic = false;
                for command in jxa_system_commands(&source) {
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
                        "JavaScript for Automation system command is not a literal",
                    );
                }
                "osascript program in a language other than AppleScript"
            }
            Some(source) => {
                let mut dynamic = false;
                for command in shell_scripts(&source, ctx) {
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

/// The command string of each `do shell script`. A command is recovered when
/// it is built from string literals, names bound with `set name to` from those
/// same pieces, and `(system attribute "NAME")`. Anything else stays None so
/// the program keeps the non-literal boundary.
fn shell_scripts(source: &str, ctx: &InvocationCtx) -> Vec<Option<String>> {
    let mut commands = Vec::new();
    let mut bindings = HashMap::new();
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
        if word_start
            && let Some(after_set) = keyword_at(rest, "set")
            && let Some(after) = bind_set(after_set, &mut bindings, ctx)
        {
            rest = after;
            word_start = true;
            continue;
        }
        if word_start && let Some(after) = do_shell_script(rest) {
            let argument = skip_space(after);
            if let Some((command, after)) = parse_concat(argument, &bindings, ctx) {
                commands.push(Some(command));
                rest = after;
            } else {
                // A failed argument still has to be left behind whole. Skipping
                // only its first character, when that character is `"`, makes
                // the scanner treat the rest of the string as source and hide
                // a later `do shell script`.
                commands.push(None);
                if argument.is_empty() {
                    break;
                }
                rest = skip_first_term(argument);
            }
            word_start = true;
            continue;
        }
        word_start = !(c.is_alphanumeric() || c == '_');
        rest = &rest[c.len_utf8()..];
    }
    commands
}

/// `$.system("...")` in a JavaScript for Automation program, including a `+`
/// join of string literals. A `$.system` whose argument is not that stays None.
fn jxa_system_commands(source: &str) -> Vec<Option<String>> {
    let mut commands = Vec::new();
    let mut rest = source;
    while !rest.is_empty() {
        if rest.starts_with('"') || rest.starts_with('\'') {
            let quote = rest.chars().next().unwrap_or('"');
            (_, rest) = js_quoted(rest, quote);
            continue;
        }
        if rest.starts_with("//") {
            rest = rest.find('\n').map_or("", |end| &rest[end..]);
            continue;
        }
        if let Some(after) = rest.strip_prefix("$.system")
            && after
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
        {
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix('(') {
                let after = after.trim_start();
                if let Some((command, tail)) = js_concat(after)
                    && let Some(tail) = tail.trim_start().strip_prefix(')')
                {
                    commands.push(Some(command));
                    rest = tail;
                    continue;
                }
                commands.push(None);
                rest = after;
                continue;
            }
        }
        let skip = rest.chars().next().map_or(1, char::len_utf8);
        rest = &rest[skip..];
    }
    commands
}

fn bind_set<'a>(
    rest: &'a str,
    bindings: &mut HashMap<String, String>,
    ctx: &InvocationCtx,
) -> Option<&'a str> {
    let rest = skip_space(rest);
    let (name, rest) = applescript_name(rest)?;
    let rest = keyword_at(skip_space(rest), "to")?;
    let key = name.to_ascii_lowercase();
    match parse_concat(skip_space(rest), bindings, ctx) {
        Some((value, rest)) => {
            bindings.insert(key, value);
            Some(rest)
        }
        // A later `set` that this scan cannot read drops the previous value.
        // Keeping it would run a command the program no longer holds.
        None => {
            bindings.remove(&key);
            None
        }
    }
}

/// The text after the first term of a `do shell script` argument: a string
/// literal, a parenthesized expression, or a name. The caller has already
/// failed to read the whole concatenation, and must not resume inside that term.
fn skip_first_term(rest: &str) -> &str {
    let rest = skip_space(rest);
    if rest.starts_with('"') {
        return string_literal(rest).1;
    }
    if let Some(inner) = rest.strip_prefix('(') {
        return skip_group(inner);
    }
    if let Some((_, after)) = applescript_name(rest) {
        return after;
    }
    match rest.chars().next() {
        Some(c) => &rest[c.len_utf8()..],
        None => rest,
    }
}

/// The text after the `)` that closes a group starting at depth 1. Strings
/// and block comments inside it are not parentheses.
fn skip_group(mut rest: &str) -> &str {
    let mut depth = 1usize;
    while depth > 0 && !rest.is_empty() {
        if rest.starts_with('"') {
            rest = string_literal(rest).1;
            continue;
        }
        if rest.starts_with("(*") {
            rest = block_comment_end(rest);
            continue;
        }
        let Some(c) = rest.chars().next() else {
            break;
        };
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        }
        rest = &rest[c.len_utf8()..];
    }
    rest
}

/// One `&` concatenation. `&&` is not an operator here, so it ends the value.
fn parse_concat<'a>(
    mut rest: &'a str,
    bindings: &HashMap<String, String>,
    ctx: &InvocationCtx,
) -> Option<(String, &'a str)> {
    let mut value = String::new();
    loop {
        let (piece, after) = parse_term(rest, bindings, ctx)?;
        value.push_str(&piece);
        rest = skip_space(after);
        if rest.starts_with('&') && !rest.starts_with("&&") {
            rest = skip_space(&rest[1..]);
            continue;
        }
        return Some((value, rest));
    }
}

fn parse_term<'a>(
    rest: &'a str,
    bindings: &HashMap<String, String>,
    ctx: &InvocationCtx,
) -> Option<(String, &'a str)> {
    let rest = skip_space(rest);
    if let Some(inner) = rest.strip_prefix('(') {
        let inner = skip_space(inner);
        if let Some(after) = keyword_at(inner, "system")
            && let Some(after) = keyword_at(skip_space(after), "attribute")
        {
            let (name, after) = string_literal(skip_space(after));
            let name = name?;
            let after = skip_space(after).strip_prefix(')')?;
            return Some((attribute_value(&name, ctx)?, after));
        }
        let (value, after) = parse_concat(inner, bindings, ctx)?;
        let after = skip_space(after).strip_prefix(')')?;
        return Some((value, after));
    }
    if rest.starts_with('"') {
        let (value, after) = string_literal(rest);
        return Some((value?, after));
    }
    let (name, after) = applescript_name(rest)?;
    Some((bindings.get(&name.to_ascii_lowercase())?.clone(), after))
}

/// AppleScript reads the attribute before the shell runs, so a known value is
/// the text that was concatenated. An unknown shell name stays `$NAME`.
fn attribute_value(name: &str, ctx: &InvocationCtx) -> Option<String> {
    match ctx.environment_value(name) {
        Some(ResourceExpr::Literal { value }) => Some(value),
        _ if shell_ident(name) => Some(format!("${name}")),
        _ => None,
    }
}

fn applescript_name(rest: &str) -> Option<(&str, &str)> {
    let mut chars = rest.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    let mut len = first.len_utf8();
    for c in chars {
        if c.is_ascii_alphanumeric() || c == '_' {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    Some((&rest[..len], &rest[len..]))
}

fn keyword_at<'a>(rest: &'a str, keyword: &str) -> Option<&'a str> {
    let head = rest.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let after = &rest[keyword.len()..];
    if after
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(after)
}

fn shell_ident(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn js_concat(mut rest: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    loop {
        let (piece, after) = js_string(rest)?;
        value.push_str(&piece);
        rest = after.trim_start();
        if let Some(after) = rest.strip_prefix('+') {
            rest = after.trim_start();
            continue;
        }
        return Some((value, rest));
    }
}

fn js_string(rest: &str) -> Option<(String, &str)> {
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let (value, after) = js_quoted(rest, quote);
    Some((value?, after))
}

fn js_quoted(rest: &str, quote: char) -> (Option<String>, &str) {
    let mut value = Some(String::new());
    let mut chars = rest.char_indices().skip(1);
    while let Some((index, c)) = chars.next() {
        let decoded = match c {
            c if c == quote => return (value, &rest[index + c.len_utf8()..]),
            '\\' => match chars.next() {
                Some((_, escaped @ ('\\' | '\'' | '"'))) => Some(escaped),
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
