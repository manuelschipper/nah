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
        code: &'a str,
    },
    Opaque,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    let prepared = match prepare(input.code) {
        Ok(prepared) => prepared,
        Err(refusal) => return LanguageAnalysis::refused(refusal),
    };
    match prepared {
        Prepared::Python(code) => super::python::analyze_language(
            program,
            &InlineInput {
                code: code.as_ref(),
                ..*input
            },
            protection,
            depth,
        ),
        Prepared::Shell { program, code } => {
            let code = if code.ends_with('\n') {
                Cow::Borrowed(code)
            } else {
                Cow::Owned(format!("{code}\n"))
            };
            let mut transformed = String::new();
            if code.contains('\0')
                || !push_ipython_call(
                    &mut transformed,
                    "run_cell_magic",
                    &[program, "", code.as_ref()],
                )
            {
                return opaque_analysis();
            }
            super::python::analyze_language(
                program,
                &InlineInput {
                    code: &transformed,
                    ..*input
                },
                protection,
                depth,
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
            *character == '_' || *character == '.' || character.is_alphanumeric() || !character.is_ascii()
        }) {
            return true;
        }
    }
    false
}

fn cell_magic(code: &str) -> Option<Prepared<'_>> {
    let mut offset = 0usize;
    for line in code.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        if body.trim().is_empty() {
            offset += line.len();
            continue;
        }
        if matches!(body.trim_end(), "%%bash" | "%%sh") && body.starts_with("%%") {
            return Some(Prepared::Shell {
                program: if body.trim_end() == "%%bash" {
                    "bash"
                } else {
                    "sh"
                },
                code: &code[offset + line.len()..],
            });
        }
        return body.starts_with("%%").then_some(Prepared::Opaque);
    }
    None
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
