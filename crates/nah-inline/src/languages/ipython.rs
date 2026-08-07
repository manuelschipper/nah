use std::borrow::Cow;

use tree_sitter::{Node, ParseOptions, Parser};

use crate::{
    InlineInput, InlineRefusal, InlineReport, LanguageAnalysis, LanguageDraft, ProtectionInput,
};

const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 512;
const MAX_PARSE_CALLBACKS: usize = 16 * 1024 * 1024;

enum Prepared<'a> {
    Python(Cow<'a, str>),
    Shell {
        program: &'static str,
        code: Cow<'a, str>,
    },
    Opaque,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    analyze_with_state(
        program,
        input,
        protection,
        depth,
        super::python::InitialState::Fresh,
    )
}

pub(super) fn analyze_persistent(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    analyze_with_state(
        program,
        input,
        protection,
        depth,
        super::python::InitialState::Persistent,
    )
}

fn analyze_with_state(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
    initial_state: super::python::InitialState,
) -> LanguageAnalysis {
    let prepared = match prepare(input.code) {
        Ok(prepared) => prepared,
        Err(refusal) => return LanguageAnalysis::refused(refusal),
    };
    match prepared {
        Prepared::Python(code) => super::python::analyze_language_with_state(
            program,
            &InlineInput {
                code: code.as_ref(),
                ..*input
            },
            protection,
            depth,
            initial_state,
        ),
        Prepared::Shell {
            program: shell_program,
            code,
        } => {
            let mut transformed = String::new();
            if code.contains('\0')
                || !push_ipython_call(
                    &mut transformed,
                    "run_cell_magic",
                    &[shell_program, "", code.as_ref()],
                )
            {
                return opaque_analysis();
            }
            super::python::analyze_language_with_state(
                program,
                &InlineInput {
                    code: &transformed,
                    ..*input
                },
                protection,
                depth,
                initial_state,
            )
        }
        Prepared::Opaque => opaque_analysis(),
    }
}

fn opaque_analysis() -> LanguageAnalysis {
    LanguageAnalysis::new(InlineReport::default(), LanguageDraft::partial())
}

fn prepare(code: &str) -> Result<Prepared<'_>, InlineRefusal> {
    if unsupported_line_control(code) {
        return Ok(Prepared::Opaque);
    }
    if let Some(prepared) = cell_magic(code) {
        return Ok(prepared);
    }
    let inert = inert_bytes(code)?;
    let mut transformed = String::with_capacity(code.len());
    let mut changed = false;
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
            let (method, command) = if let Some(command) = body.strip_prefix("!!") {
                ("getoutput", command)
            } else {
                ("system", &body[1..])
            };
            if !exact_shell_command(command)
                || !push_ipython_call(&mut transformed, method, &[command])
            {
                return Ok(Prepared::Opaque);
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
        Ok(Prepared::Python(Cow::Owned(transformed)))
    } else {
        Ok(Prepared::Python(Cow::Borrowed(code)))
    }
}

pub(super) fn exact_shell_command(command: &str) -> bool {
    !unsupported_line_control(command)
        && !command.contains(['{', '}', '\0'])
        && !has_dollar_expansion(command)
        && !command.trim_end().ends_with(['\\', '&'])
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
    if matches!(first_line.trim_end(), "%%bash" | "%%sh") && first_line.starts_with("%%") {
        return Some(Prepared::Shell {
            program: if first_line.trim_end() == "%%bash" {
                "bash"
            } else {
                "sh"
            },
            code: Cow::Owned(cell[first.len()..].to_owned()),
        });
    }
    first_line.starts_with("%%").then_some(Prepared::Opaque)
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

fn push_ipython_call(output: &mut String, method: &str, arguments: &[&str]) -> bool {
    output.push_str("get_ipython().");
    output.push_str(method);
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

fn inert_bytes(code: &str) -> Result<Vec<bool>, InlineRefusal> {
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
    mark_inert(tree.root_node(), code.len())
}

fn mark_inert(root: Node<'_>, source_len: usize) -> Result<Vec<bool>, InlineRefusal> {
    let mut inert = vec![false; source_len];
    let mut nodes = 0usize;
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(InlineRefusal::WorkLimit);
        }
        if matches!(node.kind(), "string" | "comment") {
            inert[node.byte_range()].fill(true);
            continue;
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, depth + 1));
            }
        }
    }
    Ok(inert)
}
