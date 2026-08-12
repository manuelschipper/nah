use std::borrow::Cow;

use tree_sitter::{Node, ParseOptions, Parser};

use crate::{
    InlineInput, InlineRefusal, InlineReport, LanguageAnalysis, LanguageDraft, ProtectionInput,
};

const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 512;
const MAX_PARSE_CALLBACKS: usize = 16 * 1024 * 1024;

enum Prepared<'a> {
    Python {
        code: Cow<'a, str>,
        syntax_intrinsics: bool,
    },
    Shell {
        program: &'static str,
        line: Cow<'a, str>,
        code: Cow<'a, str>,
    },
    Wrapper {
        code: Cow<'a, str>,
        partial: bool,
    },
    Opaque,
}

pub(super) fn interpret_effects(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    interpret_effects_with_state(
        program,
        input,
        protection,
        depth,
        super::python::InitialState::Fresh,
        false,
    )
}

pub(super) fn interpret_persistent_effects(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    interpret_effects_with_state(
        program,
        input,
        protection,
        depth,
        super::python::InitialState::Persistent,
        false,
    )
}

fn interpret_effects_with_state(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
    initial_state: super::python::InitialState,
    capture_ipython_output: bool,
) -> LanguageAnalysis {
    let prepared = match prepare(input.code) {
        Ok(prepared) => prepared,
        Err(refusal) => return LanguageAnalysis::refused(refusal),
    };
    match prepared {
        Prepared::Python {
            code,
            syntax_intrinsics,
        } => {
            let input = InlineInput {
                code: code.as_ref(),
                ..*input
            };
            if syntax_intrinsics {
                super::python::interpret_ipython_syntax_with_state(
                    program,
                    &input,
                    protection,
                    depth,
                    initial_state,
                    capture_ipython_output,
                )
            } else {
                super::python::interpret_effects_with_state(
                    program,
                    &input,
                    protection,
                    depth,
                    initial_state,
                    capture_ipython_output,
                )
            }
        }
        Prepared::Shell {
            program: shell_program,
            line,
            code,
        } => {
            let mut transformed = String::new();
            if code.contains('\0')
                || !push_literal_call(
                    &mut transformed,
                    super::python::IPYTHON_CELL_INTRINSIC,
                    &[shell_program, line.as_ref(), code.as_ref()],
                )
            {
                return opaque_interpretation();
            }
            super::python::interpret_ipython_syntax_with_state(
                program,
                &InlineInput {
                    code: &transformed,
                    ..*input
                },
                protection,
                depth,
                initial_state,
                capture_ipython_output,
            )
        }
        Prepared::Wrapper { code, partial } => {
            if depth >= 16 {
                return LanguageAnalysis::refused(InlineRefusal::RecursionLimit);
            }
            let interpretation = interpret_effects_with_state(
                program,
                &InlineInput {
                    code: code.as_ref(),
                    ..*input
                },
                protection,
                depth + 1,
                initial_state,
                capture_ipython_output || partial,
            );
            if partial {
                let (report, mut draft) = interpretation.into_parts();
                draft.set_partial();
                LanguageAnalysis::new(report, draft)
            } else {
                interpretation
            }
        }
        Prepared::Opaque => opaque_interpretation(),
    }
}

fn opaque_interpretation() -> LanguageAnalysis {
    LanguageAnalysis::new(InlineReport::default(), LanguageDraft::partial())
}

fn prepare(code: &str) -> Result<Prepared<'_>, InlineRefusal> {
    if unsupported_line_control(code) {
        return Ok(Prepared::Opaque);
    }
    if let Some(prepared) = cell_magic(code) {
        return Ok(prepared);
    }
    let (inert, contains_intrinsic) = inert_bytes(code)?;
    let mut transformed = String::with_capacity(code.len());
    let mut changed = false;
    let mut syntax_intrinsics = false;
    let mut delimiters = Vec::new();
    let mut continued = false;
    let mut offset = 0usize;
    for line in code.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let mut body = line.strip_suffix('\n').unwrap_or(line);
        if body.ends_with('\r') {
            body = &body[..body.len() - 1];
        }
        let top_level = delimiters.is_empty() && !continued;
        let trimmed = body.trim_start_matches([' ', '\t']);
        let indentation = body.len() - trimmed.len();
        let active_marker = !trimmed.is_empty() && !inert[offset + indentation];
        let shell_escape = active_marker && trimmed.starts_with('!') && !trimmed.starts_with("!=");
        if shell_escape && (!top_level || indentation != 0) {
            return Ok(Prepared::Opaque);
        }
        if shell_escape {
            let (intrinsic, command) = if let Some(command) = body.strip_prefix("!!") {
                (super::python::IPYTHON_GETOUTPUT_INTRINSIC, command)
            } else {
                (super::python::IPYTHON_SYSTEM_INTRINSIC, &body[1..])
            };
            if !push_interpolated_call(&mut transformed, intrinsic, command) {
                return Ok(Prepared::Opaque);
            }
            if has_newline {
                transformed.push('\n');
            }
            changed = true;
            syntax_intrinsics = true;
        } else if active_marker
            && top_level
            && indentation == 0
            && let Some(expression) = time_line(trimmed)
        {
            if expression.is_empty() || expression.starts_with('-') {
                return Ok(Prepared::Opaque);
            }
            if let Some(command) = expression.strip_prefix("!!") {
                if !push_interpolated_call(
                    &mut transformed,
                    super::python::IPYTHON_GETOUTPUT_INTRINSIC,
                    command,
                ) {
                    return Ok(Prepared::Opaque);
                }
                syntax_intrinsics = true;
            } else if let Some(command) = expression.strip_prefix('!') {
                if !push_interpolated_call(
                    &mut transformed,
                    super::python::IPYTHON_SYSTEM_INTRINSIC,
                    command,
                ) {
                    return Ok(Prepared::Opaque);
                }
                syntax_intrinsics = true;
            } else {
                transformed.push_str(expression);
            }
            if has_newline {
                transformed.push('\n');
            }
            changed = true;
        } else {
            if active_marker && magic_line(trimmed) {
                return Ok(Prepared::Opaque);
            }
            transformed.push_str(line);
            continued = scan_structure(body, offset, &inert, &mut delimiters);
        }
        if transformed.len() > crate::SOURCE_LIMIT {
            return Err(InlineRefusal::WorkLimit);
        }
        offset += line.len();
    }
    if changed {
        if syntax_intrinsics && contains_intrinsic {
            return Ok(Prepared::Opaque);
        }
        Ok(Prepared::Python {
            code: Cow::Owned(transformed),
            syntax_intrinsics,
        })
    } else {
        Ok(Prepared::Python {
            code: Cow::Borrowed(code),
            syntax_intrinsics: false,
        })
    }
}

fn time_line(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("%time")?;
    (rest.is_empty() || rest.starts_with([' ', '\t'])).then(|| rest.trim_start())
}

pub(super) fn exact_shell_command(command: &str) -> bool {
    !unsupported_line_control(command)
        && !command.contains(['{', '}', '\0'])
        && !has_dollar_expansion(command)
        && !command.trim_end().ends_with(['\\', '&'])
}

pub(super) fn exact_prepared_shell_command(command: &str) -> bool {
    !unsupported_line_control(command)
        && !command.contains('\0')
        && !command.trim_end().ends_with(['\\', '&'])
}

pub(super) fn reviewed_bash_magic_line(line: &str) -> bool {
    let mut short_option = false;
    let mut arguments = line.split_ascii_whitespace();
    let mut present = false;
    for argument in &mut arguments {
        present = true;
        match argument {
            "--no-raise-error" => {}
            "--noprofile" | "--norc" | "--verbose" if !short_option => {}
            "-v" | "-vx" | "-x" | "-xv" => short_option = true,
            _ => return false,
        }
    }
    present
}

fn unsupported_line_control(code: &str) -> bool {
    let mut characters = code.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\n' | '\t' => {}
            '\r' if characters.peek() == Some(&'\n') => {}
            '\r' | '\u{2028}' | '\u{2029}' => return true,
            character if character.is_control() => return true,
            _ => {}
        }
    }
    false
}

fn has_dollar_expansion(command: &str) -> bool {
    let characters = command.chars().collect::<Vec<_>>();
    let mut single_quoted = false;
    for (index, character) in characters.iter().enumerate() {
        if *character == '\'' {
            single_quoted = !single_quoted;
            continue;
        }
        if *character != '$' || single_quoted {
            continue;
        }
        let mut next = index + 1;
        if characters.get(next) == Some(&'$') {
            next += 1;
        }
        if characters.get(next).is_some_and(|character| {
            *character == '_'
                || *character == '.'
                || character.is_alphanumeric()
                || !character.is_ascii()
        }) {
            return true;
        }
    }
    false
}

fn cell_magic(code: &str) -> Option<Prepared<'_>> {
    let mut normalized = code.to_owned();
    if !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    let leading = normalized
        .split_inclusive('\n')
        .take_while(|line| line.trim().is_empty())
        .map(str::len)
        .sum::<usize>();
    let cell = dedent_cell(&normalized[leading..]);
    let first = cell.split_inclusive('\n').next()?;
    let first_line = first
        .strip_suffix('\n')
        .unwrap_or(first)
        .strip_suffix('\r')
        .unwrap_or(first.strip_suffix('\n').unwrap_or(first));
    let header = first_line.strip_prefix("%%")?;
    let name_end = header.find([' ', '\t']).unwrap_or(header.len());
    let name = &header[..name_end];
    let line = header[name_end..].trim();
    let body = Cow::Owned(cell[first.len()..].to_owned());
    match name {
        "bash" if line.is_empty() || reviewed_bash_magic_line(line) => Some(Prepared::Shell {
            program: "bash",
            line: Cow::Owned(line.to_owned()),
            code: body,
        }),
        "sh" if line.is_empty() => Some(Prepared::Shell {
            program: "sh",
            line: Cow::Borrowed(""),
            code: body,
        }),
        "time" if line.is_empty() => Some(Prepared::Wrapper {
            code: body,
            partial: false,
        }),
        "capture" if line.is_empty() => Some(Prepared::Wrapper {
            code: body,
            partial: true,
        }),
        _ => Some(Prepared::Opaque),
    }
}

fn dedent_cell(cell: &str) -> String {
    let indent = cell
        .split_inclusive('\n')
        .filter_map(|line| {
            let body = line
                .strip_suffix('\n')
                .unwrap_or(line)
                .strip_suffix('\r')
                .unwrap_or(line.strip_suffix('\n').unwrap_or(line));
            (!body.trim().is_empty()).then(|| {
                body.get(
                    ..body
                        .bytes()
                        .take_while(|byte| matches!(byte, b' ' | b'\t'))
                        .count(),
                )
                .expect("ASCII indentation ends on a UTF-8 boundary")
            })
        })
        .reduce(common_prefix)
        .unwrap_or("");
    let mut output = String::with_capacity(cell.len());
    for line in cell.split_inclusive('\n') {
        let (body, ending) = if let Some(body) = line.strip_suffix("\r\n") {
            (body, "\r\n")
        } else if let Some(body) = line.strip_suffix('\n') {
            (body, "\n")
        } else {
            (line, "")
        };
        if body.trim().is_empty() {
            output.push_str(ending);
        } else {
            output.push_str(body.strip_prefix(indent).unwrap_or(body));
            output.push_str(ending);
        }
    }
    output
}

fn common_prefix<'a>(left: &'a str, right: &str) -> &'a str {
    let length = left
        .bytes()
        .zip(right.bytes())
        .take_while(|(left, right)| left == right)
        .count();
    &left[..length]
}

fn magic_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('%') else {
        return false;
    };
    rest.starts_with('%')
        || rest
            .chars()
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
}

fn push_literal_call(output: &mut String, function: &str, arguments: &[&str]) -> bool {
    output.push_str(function);
    output.push('(');
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('"');
        for character in argument.chars() {
            match character {
                '"' => output.push_str("\\\""),
                '\\' => output.push_str("\\\\"),
                '\t' => output.push_str("\\t"),
                character if character.is_control() => {
                    let value = character as u32;
                    if value > u32::from(u8::MAX) {
                        return false;
                    }
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    output.push_str("\\x");
                    output.push(HEX[(value >> 4) as usize] as char);
                    output.push(HEX[(value & 0xf) as usize] as char);
                }
                character => output.push(character),
            }
            if output.len() > crate::SOURCE_LIMIT {
                return false;
            }
        }
        output.push('"');
    }
    output.push(')');
    output.len() <= crate::SOURCE_LIMIT
}

fn push_interpolated_call(output: &mut String, function: &str, command: &str) -> bool {
    if unsupported_line_control(command) || command.contains('\0') {
        return false;
    }
    output.push_str(function);
    output.push_str("(f\"");
    let bytes = command.as_bytes();
    let mut offset = 0usize;
    let mut single_quoted = false;
    while offset < bytes.len() {
        match bytes[offset] {
            b'\'' => {
                single_quoted = !single_quoted;
                if !push_fstring_literal(output, '\'') {
                    return false;
                }
                offset += 1;
            }
            b'{' => {
                if bytes.get(offset + 1) == Some(&b'{') {
                    if !push_fstring_literal(output, '{') {
                        return false;
                    }
                    offset += 2;
                    continue;
                }
                let Some(end) = bytes[offset + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|end| offset + end + 1)
                else {
                    return false;
                };
                let name = &command[offset + 1..end];
                if !python_identifier(name) {
                    return false;
                }
                output.push('{');
                output.push_str(name);
                output.push('}');
                offset = end + 1;
            }
            b'}' => {
                if bytes.get(offset + 1) != Some(&b'}') || !push_fstring_literal(output, '}') {
                    return false;
                }
                offset += 2;
            }
            b'$' if !single_quoted => {
                if bytes.get(offset + 1) == Some(&b'$') {
                    if !push_fstring_literal(output, '$') {
                        return false;
                    }
                    offset += 2;
                    continue;
                }
                let start = offset + 1;
                if bytes.get(start).is_some_and(|byte| identifier_start(*byte)) {
                    let mut end = start + 1;
                    while bytes
                        .get(end)
                        .is_some_and(|byte| identifier_continue(*byte))
                    {
                        end += 1;
                    }
                    if bytes.get(end) == Some(&b'.') {
                        return false;
                    }
                    output.push('{');
                    output.push_str(&command[start..end]);
                    output.push('}');
                    offset = end;
                } else {
                    if !push_fstring_literal(output, '$') {
                        return false;
                    }
                    offset += 1;
                }
            }
            _ => {
                let Some(character) = command[offset..].chars().next() else {
                    return false;
                };
                if !push_fstring_literal(output, character) {
                    return false;
                }
                offset += character.len_utf8();
            }
        }
    }
    output.push_str("\")");
    output.len() <= crate::SOURCE_LIMIT
}

fn python_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(identifier_start) && bytes.all(identifier_continue)
}

fn identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

fn push_fstring_literal(output: &mut String, character: char) -> bool {
    match character {
        '"' => output.push_str("\\\""),
        '\\' => output.push_str("\\\\"),
        '{' => output.push_str("{{"),
        '}' => output.push_str("}}"),
        '\t' => output.push_str("\\t"),
        character if character.is_control() => {
            let value = character as u32;
            if value > u32::from(u8::MAX) {
                return false;
            }
            const HEX: &[u8; 16] = b"0123456789abcdef";
            output.push_str("\\x");
            output.push(HEX[(value >> 4) as usize] as char);
            output.push(HEX[(value & 0xf) as usize] as char);
        }
        character => output.push(character),
    }
    output.len() <= crate::SOURCE_LIMIT
}

fn scan_structure(line: &str, offset: usize, inert: &[bool], delimiters: &mut Vec<u8>) -> bool {
    let mut last = None;
    for (index, byte) in line.bytes().enumerate() {
        if inert[offset + index] {
            continue;
        }
        if !byte.is_ascii_whitespace() {
            last = Some(byte);
        }
        match byte {
            b'(' | b'[' | b'{' => delimiters.push(byte),
            b')' | b']' | b'}'
                if matches!(
                    (delimiters.last(), byte),
                    (Some(b'('), b')') | (Some(b'['), b']') | (Some(b'{'), b'}')
                ) =>
            {
                delimiters.pop();
            }
            _ => {}
        }
    }
    last == Some(b'\\')
}

fn inert_bytes(code: &str) -> Result<(Vec<bool>, bool), InlineRefusal> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("the pinned Python grammar matches tree-sitter");
    let mut callbacks = 0usize;
    let mut progress = |_: &tree_sitter::ParseState| {
        callbacks += 1;
        callbacks > MAX_PARSE_CALLBACKS
    };
    let mut read = |offset: usize, _| &code.as_bytes()[offset..];
    let tree = parser
        .parse_with_options(
            &mut read,
            None,
            Some(ParseOptions::new().progress_callback(&mut progress)),
        )
        .ok_or(InlineRefusal::WorkLimit)?;
    mark_inert(tree.root_node(), code)
}

fn mark_inert(root: Node<'_>, source: &str) -> Result<(Vec<bool>, bool), InlineRefusal> {
    let mut inert = vec![false; source.len()];
    let mut contains_intrinsic = false;
    let mut nodes = 0usize;
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(InlineRefusal::WorkLimit);
        }
        if node.kind() == "identifier"
            && matches!(
                &source[node.byte_range()],
                super::python::IPYTHON_CELL_INTRINSIC
                    | super::python::IPYTHON_GETOUTPUT_INTRINSIC
                    | super::python::IPYTHON_SYSTEM_INTRINSIC
            )
        {
            contains_intrinsic = true;
        }
        if matches!(node.kind(), "string" | "comment") {
            inert[node.byte_range()].fill(true);
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, depth + 1));
            }
        }
    }
    Ok((inert, contains_intrinsic))
}
