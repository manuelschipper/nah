//! Lexical scanning and bounded static-call parsing for inline interpreters.

use crate::is_python_interpreter;

const MAX_VISIBLE_DELIMITERS: usize = 4_096;

fn starts_line_comment(bytes: &[u8], index: usize, program: &str) -> bool {
    if bytes[index] == b'#'
        && (is_python_interpreter(program)
            || matches!(
                program,
                "perl" | "ruby" | "php" | "r" | "rscript" | "julia" | "powershell" | "pwsh"
            ))
    {
        return true;
    }
    if bytes[index] == b'/'
        && bytes.get(index + 1) == Some(&b'/')
        && matches!(program, "php" | "swift")
    {
        return true;
    }
    if bytes[index] == b'-' && bytes.get(index + 1) == Some(&b'-') && program == "lua" {
        return true;
    }
    false
}

fn mark_comment(mask: &mut [bool], start: usize, end: usize) {
    mask[start..end].fill(true);
}

fn fixed_block_comment(
    bytes: &[u8],
    index: usize,
    program: &str,
) -> Option<(&'static [u8], &'static [u8], bool)> {
    if matches!(program, "php" | "swift") && bytes[index..].starts_with(b"/*") {
        return Some((b"/*", b"*/", program == "swift"));
    }
    if program == "julia" && bytes[index..].starts_with(b"#=") {
        return Some((b"#=", b"=#", true));
    }
    if matches!(program, "powershell" | "pwsh") && bytes[index..].starts_with(b"<#") {
        return Some((b"<#", b"#>", false));
    }
    None
}

fn mark_fixed_block_comment(
    mask: &mut [bool],
    bytes: &[u8],
    start: usize,
    opening: &[u8],
    closing: &[u8],
    nested: bool,
) -> (usize, bool) {
    let mut index = start + opening.len();
    let mut depth = 1usize;
    while index < bytes.len() {
        if nested && bytes[index..].starts_with(opening) {
            depth += 1;
            index += opening.len();
        } else if bytes[index..].starts_with(closing) {
            depth -= 1;
            index += closing.len();
            if depth == 0 {
                break;
            }
        } else {
            index += 1;
        }
    }
    mark_comment(mask, start, index);
    (index, depth == 0)
}

fn lua_long_bracket(bytes: &[u8], index: usize, delimiter: u8) -> Option<(usize, usize)> {
    if bytes.get(index) != Some(&delimiter) {
        return None;
    }
    let mut cursor = index + 1;
    while bytes.get(cursor) == Some(&b'=') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&delimiter)).then_some((cursor + 1, cursor - index - 1))
}

fn mark_lua_block_comment(mask: &mut [bool], bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    if !bytes[start..].starts_with(b"--") {
        return None;
    }
    let (mut index, equals) = lua_long_bracket(bytes, start + 2, b'[')?;
    while index < bytes.len() {
        if let Some((end, closing_equals)) = lua_long_bracket(bytes, index, b']')
            && closing_equals == equals
        {
            mark_comment(mask, start, end);
            return Some((end, true));
        }
        index += 1;
    }
    mark_comment(mask, start, bytes.len());
    Some((bytes.len(), false))
}

fn directive_at_line_start(bytes: &[u8], index: usize, directive: &[u8]) -> bool {
    (index == 0 || bytes[index - 1] == b'\n')
        && bytes[index..].starts_with(directive)
        && bytes
            .get(index + directive.len())
            .is_none_or(u8::is_ascii_whitespace)
}

fn mark_directive_comment(
    mask: &mut [bool],
    bytes: &[u8],
    start: usize,
    closing: &[u8],
) -> (usize, bool) {
    let mut line_start = start;
    loop {
        let line_end = bytes[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| line_start + offset + 1);
        mark_comment(mask, line_start, line_end);
        if directive_at_line_start(bytes, line_start, closing) {
            return (line_end, true);
        }
        if line_end == bytes.len() {
            return (line_end, false);
        }
        line_start = line_end;
    }
}

fn starts_perl_pod(bytes: &[u8], index: usize) -> bool {
    [
        b"=pod".as_slice(),
        b"=head1",
        b"=head2",
        b"=head3",
        b"=head4",
        b"=over",
        b"=item",
        b"=back",
        b"=begin",
        b"=for",
        b"=encoding",
    ]
    .iter()
    .any(|directive| directive_at_line_start(bytes, index, directive))
}

fn comment_mask(code: &str, program: &str) -> (Vec<bool>, bool) {
    let bytes = code.as_bytes();
    let mut mask = vec![false; bytes.len()];
    let mut index = 0;
    let mut quote = None;
    let mut complete = true;
    while index < bytes.len() {
        if let Some(active_quote) = quote {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                index += 2;
            } else {
                if bytes[index] == active_quote {
                    quote = None;
                }
                index += 1;
            }
            continue;
        }
        if program == "ruby" && directive_at_line_start(bytes, index, b"=begin") {
            let (end, closed) = mark_directive_comment(&mut mask, bytes, index, b"=end");
            index = end;
            complete &= closed;
            continue;
        }
        if program == "perl" && starts_perl_pod(bytes, index) {
            let (end, closed) = mark_directive_comment(&mut mask, bytes, index, b"=cut");
            index = end;
            complete &= closed;
            continue;
        }
        if program == "lua"
            && let Some((end, closed)) = mark_lua_block_comment(&mut mask, bytes, index)
        {
            index = end;
            complete &= closed;
            continue;
        }
        if let Some((opening, closing, nested)) = fixed_block_comment(bytes, index, program) {
            let (end, closed) =
                mark_fixed_block_comment(&mut mask, bytes, index, opening, closing, nested);
            index = end;
            complete &= closed;
            continue;
        }
        if starts_line_comment(bytes, index, program) {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset);
            mark_comment(&mut mask, index, end);
            index = end;
            continue;
        }
        let candidate = bytes[index];
        if matches!(candidate, b'\'' | b'"')
            || candidate == b'`' && matches!(program, "perl" | "ruby" | "php")
        {
            quote = Some(candidate);
        }
        index += 1;
    }
    (mask, complete && quote.is_none())
}

pub fn code_segments<'a>(code: &'a str, program: &str) -> Vec<&'a str> {
    let bytes = code.as_bytes();
    let comments = comment_mask(code, program).0;
    let mut segments = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut quote = None;
    let mut expression_depth = 0usize;
    while index < bytes.len() {
        if comments[index] {
            index += 1;
            continue;
        }
        if let Some(active_quote) = quote {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                index += 2;
            } else {
                if bytes[index] == active_quote {
                    quote = None;
                }
                index += 1;
            }
            continue;
        }
        let candidate = bytes[index];
        if matches!(candidate, b'\'' | b'"')
            || candidate == b'`' && matches!(program, "perl" | "ruby")
        {
            quote = Some(candidate);
            index += 1;
            continue;
        }
        if matches!(candidate, b'(' | b'[') {
            expression_depth += 1;
        } else if matches!(candidate, b')' | b']') {
            expression_depth = expression_depth.saturating_sub(1);
        } else if expression_depth == 0 && matches!(candidate, b';' | b'\n') {
            segments.push(&code[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    segments.push(&code[start..]);
    segments
        .into_iter()
        .filter(|segment| !segment.trim().is_empty())
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn fixed_hex_escape(bytes: &[u8], index: usize, digits: usize) -> Option<(u8, usize)> {
    let mut value = 0u32;
    for offset in 0..digits {
        value = value
            .checked_mul(16)?
            .checked_add(u32::from(hex_digit(*bytes.get(index + 2 + offset)?)?))?;
    }
    u8::try_from(value)
        .ok()
        .filter(u8::is_ascii)
        .map(|value| (value, digits + 2))
}

fn braced_hex_escape(bytes: &[u8], index: usize) -> Option<(u8, usize)> {
    if bytes.get(index + 2) != Some(&b'{') {
        return None;
    }
    let mut cursor = index + 3;
    let mut value = 0u32;
    let mut digits = 0usize;
    while let Some(byte) = bytes.get(cursor).copied() {
        if byte == b'}' {
            return (digits > 0)
                .then_some(value)
                .and_then(|value| u8::try_from(value).ok())
                .filter(u8::is_ascii)
                .map(|value| (value, cursor + 1 - index));
        }
        value = value
            .checked_mul(16)?
            .checked_add(u32::from(hex_digit(byte)?))?;
        digits += 1;
        if digits > 8 {
            return None;
        }
        cursor += 1;
    }
    None
}

fn decoded_ascii_escape(
    bytes: &[u8],
    index: usize,
    quote: u8,
    program: &str,
) -> Option<(u8, usize)> {
    let quoted_escape = is_python_interpreter(program)
        || matches!(program, "lua" | "r" | "rscript" | "julia" | "swift")
        || quote == b'"' && matches!(program, "perl" | "ruby" | "php");
    if !quoted_escape || bytes.get(index) != Some(&b'\\') {
        return None;
    }
    match bytes.get(index + 1)? {
        b'x' => braced_hex_escape(bytes, index).or_else(|| fixed_hex_escape(bytes, index, 2)),
        b'u' if is_python_interpreter(program)
            || matches!(
                program,
                "ruby" | "php" | "r" | "rscript" | "julia" | "swift"
            ) =>
        {
            braced_hex_escape(bytes, index).or_else(|| fixed_hex_escape(bytes, index, 4))
        }
        b'U' if is_python_interpreter(program) => fixed_hex_escape(bytes, index, 8),
        b'0'..=b'7' if program != "lua" => {
            let mut value = 0u16;
            let mut digits = 0usize;
            while digits < 3 {
                let Some(byte @ b'0'..=b'7') = bytes.get(index + 1 + digits).copied() else {
                    break;
                };
                value = value * 8 + u16::from(byte - b'0');
                digits += 1;
            }
            u8::try_from(value)
                .ok()
                .filter(u8::is_ascii)
                .map(|value| (value, digits + 1))
        }
        b'0'..=b'9' if program == "lua" => {
            let mut value = 0u16;
            let mut digits = 0usize;
            while digits < 3 {
                let Some(byte @ b'0'..=b'9') = bytes.get(index + 1 + digits).copied() else {
                    break;
                };
                value = value * 10 + u16::from(byte - b'0');
                digits += 1;
            }
            u8::try_from(value)
                .ok()
                .filter(u8::is_ascii)
                .map(|value| (value, digits + 1))
        }
        _ => None,
    }
}

fn raw_python_string(bytes: &[u8], quote_index: usize, program: &str) -> bool {
    if !is_python_interpreter(program) {
        return false;
    }
    let mut start = quote_index;
    while start > 0 && bytes[start - 1].is_ascii_alphabetic() {
        start -= 1;
    }
    let prefix = bytes[start..quote_index]
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    !prefix.is_empty()
        && prefix.len() <= 3
        && prefix.contains(&b'r')
        && prefix
            .iter()
            .all(|byte| matches!(byte, b'b' | b'f' | b'r' | b't' | b'u'))
        && (start == 0
            || !matches!(
                bytes[start - 1],
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'
            ))
}

fn formatted_python_string(bytes: &[u8], quote_index: usize, program: &str) -> bool {
    if !is_python_interpreter(program) {
        return false;
    }
    let mut start = quote_index;
    while start > 0 && bytes[start - 1].is_ascii_alphabetic() {
        start -= 1;
    }
    bytes[start..quote_index]
        .iter()
        .any(|byte| matches!(byte, b'f' | b'F'))
}

fn interpolation_at(bytes: &[u8], index: usize, quote: u8, program: &str) -> bool {
    match program {
        "ruby" => {
            matches!(quote, b'"' | b'`')
                && (bytes[index..].starts_with(b"#{")
                    || bytes[index..].starts_with(b"#$")
                    || bytes[index..].starts_with(b"#@"))
        }
        "perl" => matches!(quote, b'"' | b'`') && matches!(bytes[index], b'$' | b'@'),
        "php" | "powershell" | "pwsh" => matches!(quote, b'"' | b'`') && bytes[index] == b'$',
        "julia" => quote == b'"' && bytes[index] == b'$',
        "swift" => quote == b'"' && bytes[index..].starts_with(b"\\("),
        _ => false,
    }
}

fn braced_literal(bytes: &[u8], index: usize, prefix: &[u8]) -> Option<(usize, String)> {
    if !bytes[index..].starts_with(prefix) {
        return None;
    }
    let mut cursor = index + prefix.len();
    let content_start = cursor;
    let mut depth = 1usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
            cursor += 2;
            continue;
        }
        match bytes[cursor] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((
                        cursor + 1,
                        String::from_utf8_lossy(&bytes[content_start..cursor]).into_owned(),
                    ));
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn lua_bracket_literal(bytes: &[u8], index: usize) -> Option<(usize, String)> {
    if !bytes[index..].starts_with(b"[[") {
        return None;
    }
    let content_start = index + 2;
    let relative_end = bytes[content_start..]
        .windows(2)
        .position(|window| window == b"]]")?;
    let content_end = content_start + relative_end;
    Some((
        content_end + 2,
        String::from_utf8_lossy(&bytes[content_start..content_end]).into_owned(),
    ))
}

pub fn lexical_code(code: &str, program: &str) -> (String, Vec<String>, Vec<usize>, bool) {
    let (outside, strings, string_offsets, _, backtick_exec) = lexical_code_cased(code, program);
    (
        outside.to_ascii_lowercase(),
        strings,
        string_offsets,
        backtick_exec,
    )
}

pub fn structurally_bounded(code: &str, program: &str) -> Result<(), crate::InlineRefusal> {
    let (outside, _, _, _, _, complete) = lexical_code_exact_with_status(code, program);
    if !complete {
        return Err(crate::InlineRefusal::StructureIncomplete);
    }
    let mut stack = Vec::new();
    let mut delimiters = 0usize;
    for byte in outside.bytes() {
        match byte {
            b'(' | b'[' | b'{' => {
                delimiters += 1;
                if delimiters > MAX_VISIBLE_DELIMITERS {
                    return Err(crate::InlineRefusal::DelimiterLimit);
                }
                stack.push(byte);
            }
            b')' | b']' | b'}' => {
                if !matches!(
                    (stack.pop(), byte),
                    (Some(b'('), b')') | (Some(b'['), b']') | (Some(b'{'), b'}')
                ) {
                    return Err(crate::InlineRefusal::StructureMismatch);
                }
            }
            _ => {}
        }
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(crate::InlineRefusal::StructureMismatch)
    }
}

pub fn lexical_code_exact(code: &str, program: &str) -> (String, Vec<String>, Vec<usize>, bool) {
    let (outside, strings, offsets, _, backtick_exec, _) =
        lexical_code_exact_with_status(code, program);
    (outside, strings, offsets, backtick_exec)
}

pub fn lexical_code_cased(
    code: &str,
    program: &str,
) -> (String, Vec<String>, Vec<usize>, Vec<bool>, bool) {
    let (outside, strings, offsets, static_strings, backtick_exec, _) =
        lexical_code_exact_with_status(code, program);
    (outside, strings, offsets, static_strings, backtick_exec)
}

fn lexical_code_exact_with_status(
    code: &str,
    program: &str,
) -> (String, Vec<String>, Vec<usize>, Vec<bool>, bool, bool) {
    let bytes = code.as_bytes();
    let (comments, mut complete) = comment_mask(code, program);
    let mut outside = String::with_capacity(code.len());
    let mut strings = Vec::new();
    let mut string_offsets = Vec::new();
    let mut static_strings = Vec::new();
    let mut index = 0;
    let mut backtick_exec = false;
    while index < bytes.len() {
        if comments[index] {
            outside.push(' ');
            index += 1;
            continue;
        }
        let alternative = match program {
            "ruby" => braced_literal(bytes, index, b"%q{"),
            "perl" => braced_literal(bytes, index, b"q{"),
            "lua" => lua_bracket_literal(bytes, index),
            _ => None,
        };
        if alternative.is_none()
            && ((program == "ruby" && bytes[index..].starts_with(b"%q{"))
                || (program == "perl" && bytes[index..].starts_with(b"q{"))
                || (program == "lua" && bytes[index..].starts_with(b"[[")))
        {
            complete = false;
        }
        if let Some((end, value)) = alternative {
            strings.push(value);
            string_offsets.push(index);
            static_strings.push(true);
            outside.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        let quote = bytes[index];
        let quoted = (quote == b'"'
            || quote == b'\'' && !matches!(program, "cmd" | "julia" | "swift"))
            || quote == b'`' && matches!(program, "perl" | "ruby" | "php");
        if quoted {
            let raw_string = raw_python_string(bytes, index, program);
            let mut static_string = !formatted_python_string(bytes, index, program);
            let string_offset = index;
            let executable_backtick = quote == b'`' && matches!(program, "perl" | "ruby" | "php");
            outside.push(' ');
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < bytes.len() {
                static_string &= !interpolation_at(bytes, index, quote, program);
                if raw_string && bytes[index] == b'\\' && index + 1 < bytes.len() {
                    value.push('\\');
                    value.push(bytes[index + 1] as char);
                    outside.push_str("  ");
                    index += 2;
                } else if let Some((decoded, consumed)) =
                    decoded_ascii_escape(bytes, index, quote, program).filter(|_| !raw_string)
                {
                    value.push(decoded as char);
                    outside.extend(std::iter::repeat_n(' ', consumed));
                    index += consumed;
                } else if bytes[index] == b'\\'
                    && index + 1 < bytes.len()
                    && !matches!(program, "powershell" | "pwsh" | "cmd")
                {
                    value.push(bytes[index + 1] as char);
                    outside.push_str("  ");
                    index += 2;
                } else if bytes[index] == quote {
                    outside.push(' ');
                    index += 1;
                    closed = true;
                    break;
                } else {
                    let Some(character) = code[index..].chars().next() else {
                        break;
                    };
                    value.push(character);
                    outside.extend(std::iter::repeat_n(' ', character.len_utf8()));
                    index += character.len_utf8();
                }
            }
            strings.push(value);
            string_offsets.push(string_offset);
            static_strings.push(static_string);
            backtick_exec |= executable_backtick;
            complete &= closed;
            continue;
        }
        let Some(character) = code[index..].chars().next() else {
            break;
        };
        outside.push(character);
        index += character.len_utf8();
    }
    (
        outside,
        strings,
        string_offsets,
        static_strings,
        backtick_exec,
        complete,
    )
}

pub fn contains_call(source: &str, name: &str, _bare: bool) -> bool {
    source.match_indices(name).any(|(index, _)| {
        let after = source[index + name.len()..].trim_start();
        (name.starts_with('.') || call_prefix_boundary(source, index)) && after.starts_with('(')
    })
}

fn call_prefix_boundary(source: &str, index: usize) -> bool {
    let before = source[..index].chars().next_back();
    match before {
        Some(character) if character.is_ascii_alphanumeric() || character == '_' => false,
        Some('.' | '$' | '@' | '%' | '&' | '\\') => false,
        Some(':') => !source[..index - 1].ends_with(':'),
        Some('>') => !source[..index - 1].ends_with('-'),
        _ => true,
    }
}

#[derive(Default)]
pub struct StaticCallArgument {
    pub outside: String,
    pub strings: Vec<String>,
    pub string_offsets: Vec<usize>,
    pub static_strings: Vec<bool>,
}

pub fn named_call_argument(argument: &StaticCallArgument, names: &[&str]) -> bool {
    let outside = argument.outside.trim_start();
    names.iter().any(|name| {
        outside.strip_prefix(name).is_some_and(|rest| {
            let rest = rest.trim_start();
            rest.starts_with('=') || rest.starts_with(':')
        })
    })
}

pub fn static_call_arguments(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    name: &str,
    _bare: bool,
) -> Vec<Vec<StaticCallArgument>> {
    let static_strings = vec![true; strings.len()];
    static_call_arguments_cased(
        outside,
        outside,
        strings,
        string_offsets,
        &static_strings,
        name,
        _bare,
    )
}

pub fn static_call_arguments_cased(
    matching_outside: &str,
    exact_outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    static_strings: &[bool],
    name: &str,
    _bare: bool,
) -> Vec<Vec<StaticCallArgument>> {
    if matching_outside.len() != exact_outside.len() || strings.len() != static_strings.len() {
        return Vec::new();
    }
    let mut calls = Vec::new();
    for (index, _) in matching_outside.match_indices(name) {
        if !name.starts_with('.') && !call_prefix_boundary(matching_outside, index) {
            continue;
        }
        let suffix = &matching_outside[index + name.len()..];
        let whitespace = suffix.len() - suffix.trim_start().len();
        let open = index + name.len() + whitespace;
        if matching_outside.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        if let Some(arguments) = static_call_arguments_at_cased(
            matching_outside,
            exact_outside,
            strings,
            string_offsets,
            static_strings,
            open,
        ) {
            calls.push(arguments);
        }
    }
    calls
}

pub fn static_call_arguments_at_cased(
    matching_outside: &str,
    exact_outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    static_strings: &[bool],
    open: usize,
) -> Option<Vec<StaticCallArgument>> {
    if matching_outside.len() != exact_outside.len()
        || strings.len() != static_strings.len()
        || matching_outside.as_bytes().get(open) != Some(&b'(')
    {
        return None;
    }
    let mut ranges = Vec::new();
    let mut start = open + 1;
    let mut depth = 0usize;
    let mut end = None;
    for (offset, byte) in matching_outside.as_bytes()[open + 1..]
        .iter()
        .copied()
        .enumerate()
    {
        let cursor = open + 1 + offset;
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' if depth == 0 => {
                let has_content = !matching_outside[start..cursor].trim().is_empty()
                    || string_offsets
                        .iter()
                        .any(|offset| *offset >= start && *offset < cursor);
                if has_content {
                    ranges.push((start, cursor));
                } else if ranges.is_empty() {
                    ranges.clear();
                }
                end = Some(cursor);
                break;
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                let has_content = !matching_outside[start..cursor].trim().is_empty()
                    || string_offsets
                        .iter()
                        .any(|offset| *offset >= start && *offset < cursor);
                if !has_content {
                    return None;
                }
                ranges.push((start, cursor));
                start = cursor + 1;
            }
            _ => {}
        }
    }
    end?;
    Some(
        ranges
            .into_iter()
            .map(|(start, end)| StaticCallArgument {
                outside: exact_outside[start..end].to_owned(),
                strings: {
                    let first = string_offsets.partition_point(|offset| *offset < start);
                    let last = string_offsets.partition_point(|offset| *offset < end);
                    strings[first..last].to_vec()
                },
                string_offsets: {
                    let first = string_offsets.partition_point(|offset| *offset < start);
                    let last = string_offsets.partition_point(|offset| *offset < end);
                    string_offsets[first..last]
                        .iter()
                        .map(|offset| offset - start)
                        .collect()
                },
                static_strings: {
                    let first = string_offsets.partition_point(|offset| *offset < start);
                    let last = string_offsets.partition_point(|offset| *offset < end);
                    static_strings[first..last].to_vec()
                },
            })
            .collect(),
    )
}
