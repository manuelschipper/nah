use crate::syntax::lexical_code_exact;

pub(super) fn mask(code: &str, program: &str) -> String {
    let visible = lexical_code_exact(code, program).0;
    let matching = if program == "php" {
        visible.to_ascii_lowercase()
    } else {
        visible.clone()
    };
    let mut masked = code.as_bytes().to_vec();
    match program {
        program if crate::is_python_interpreter(program) => {
            mask_python_generators(&matching, &mut masked);
        }
        "ruby" => mask_ruby_callables(&matching, &mut masked),
        "perl" => mask_perl_callables(&matching, &mut masked),
        "php" => mask_php_callables(&matching, &mut masked),
        "julia" => mask_arrows(&matching, &mut masked, false),
        "swift" => mask_swift_closures(&matching, &mut masked),
        _ => {}
    }
    String::from_utf8(masked).unwrap_or_else(|_| code.to_owned())
}

fn mask_python_generators(visible: &str, masked: &mut [u8]) {
    let bytes = visible.as_bytes();
    let mut cursor = 0usize;
    while let Some(keyword) = find_token(visible, "for", cursor) {
        let Some(open) = unmatched_open_before(bytes, keyword, b'(', b')') else {
            cursor = keyword + 3;
            continue;
        };
        let end = matching_delimiter(bytes, open, b'(', b')').unwrap_or(bytes.len());
        mask_range(masked, open + 1, end);
        cursor = end.saturating_add(1).max(keyword + 3);
    }
}

fn mask_ruby_callables(visible: &str, masked: &mut [u8]) {
    let bytes = visible.as_bytes();
    for token in ["proc", "lambda", "->"] {
        let mut cursor = 0usize;
        while let Some(start) = if token == "->" {
            visible[cursor..].find(token).map(|offset| cursor + offset)
        } else {
            find_token(visible, token, cursor)
        } {
            let after = next_non_whitespace(bytes, start + token.len());
            if let Some(open) = visible[after..].find('{').map(|offset| after + offset)
                && !visible[after..open].contains(['\n', ';'])
            {
                let end = matching_delimiter(bytes, open, b'{', b'}').unwrap_or(bytes.len());
                mask_range(masked, open + 1, end);
                cursor = end.saturating_add(1).max(start + token.len());
                continue;
            }
            if let Some(body) = find_token(visible, "do", after)
                && !visible[after..body].contains(['\n', ';'])
            {
                mask_range(masked, body + 2, bytes.len());
                cursor = bytes.len();
                continue;
            }
            cursor = start + token.len();
        }
    }
}

fn mask_perl_callables(visible: &str, masked: &mut [u8]) {
    let bytes = visible.as_bytes();
    let mut cursor = 0usize;
    while let Some(start) = find_token(visible, "sub", cursor) {
        let next = next_non_whitespace(bytes, start + 3);
        let anonymous = matches!(bytes.get(next), Some(b'{' | b'('));
        let Some(open) = visible[next..].find('{').map(|offset| next + offset) else {
            break;
        };
        let end = matching_delimiter(bytes, open, b'{', b'}').unwrap_or(bytes.len());
        if anonymous {
            mask_range(masked, open + 1, end);
        }
        cursor = end.saturating_add(1).max(start + 3);
    }
}

fn mask_php_callables(visible: &str, masked: &mut [u8]) {
    let bytes = visible.as_bytes();
    let mut cursor = 0usize;
    while let Some(start) = find_token(visible, "function", cursor) {
        let mut next = next_non_whitespace(bytes, start + "function".len());
        if bytes.get(next) == Some(&b'&') {
            next = next_non_whitespace(bytes, next + 1);
        }
        let anonymous = bytes.get(next) == Some(&b'(');
        let Some(open) = visible[next..].find('{').map(|offset| next + offset) else {
            break;
        };
        let end = matching_delimiter(bytes, open, b'{', b'}').unwrap_or(bytes.len());
        if anonymous {
            mask_range(masked, open + 1, end);
        }
        cursor = end.saturating_add(1).max(start + "function".len());
    }
    mask_arrows_after_token(visible, masked, "fn");
}

fn mask_arrows_after_token(visible: &str, masked: &mut [u8], token: &str) {
    let bytes = visible.as_bytes();
    let mut cursor = 0usize;
    while let Some(start) = find_token(visible, token, cursor) {
        let Some(relative) = visible[start + token.len()..].find("=>") else {
            break;
        };
        let body = next_non_whitespace(bytes, start + token.len() + relative + 2);
        let end = expression_end(bytes, body);
        mask_range(masked, body, end);
        cursor = end.max(start + token.len());
    }
}

fn mask_arrows(visible: &str, masked: &mut [u8], preserve_iife: bool) {
    let bytes = visible.as_bytes();
    let mut cursor = 0usize;
    while let Some(offset) = visible[cursor..].find("->") {
        let arrow = cursor + offset;
        let body = next_non_whitespace(bytes, arrow + 2);
        let end = if visible[body..].starts_with("begin")
            && !identifier_character(visible[body + "begin".len()..].chars().next())
        {
            bytes.len()
        } else {
            expression_end(bytes, body)
        };
        if !preserve_iife {
            mask_range(masked, body, end);
        }
        cursor = end.max(arrow + 2);
    }
}

fn mask_swift_closures(visible: &str, masked: &mut [u8]) {
    let bytes = visible.as_bytes();
    let mut cursor = 0usize;
    while let Some(relative) = visible[cursor..].find('{') {
        let open = cursor + relative;
        let statement_start = visible[..open]
            .rfind([';', '\n', '{', '}'])
            .map_or(0, |index| index + 1);
        let prefix = visible[statement_start..open].trim_start();
        let executable_block = [
            "if",
            "else",
            "for",
            "while",
            "switch",
            "do",
            "catch",
            "guard",
            "defer",
            "func",
            "class",
            "struct",
            "enum",
            "extension",
            "protocol",
            "actor",
            "init",
            "deinit",
            "subscript",
        ]
        .iter()
        .any(|keyword| starts_keyword(prefix, keyword));
        if executable_block {
            cursor = open + 1;
            continue;
        }
        let end = matching_delimiter(bytes, open, b'{', b'}').unwrap_or(bytes.len());
        mask_range(masked, open + 1, end);
        cursor = end.saturating_add(1).max(open + 1);
    }
}

fn find_token(source: &str, token: &str, from: usize) -> Option<usize> {
    source[from..].match_indices(token).find_map(|(offset, _)| {
        let start = from + offset;
        let before = source[..start].chars().next_back();
        let after = source[start + token.len()..].chars().next();
        (!identifier_character(before) && !identifier_character(after)).then_some(start)
    })
}

fn identifier_character(character: Option<char>) -> bool {
    character.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn starts_keyword(source: &str, keyword: &str) -> bool {
    source.strip_prefix(keyword).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

fn next_non_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn matching_delimiter(bytes: &[u8], open: usize, opening: u8, closing: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in bytes.get(open..)?.iter().copied().enumerate() {
        if byte == opening {
            depth += 1;
        } else if byte == closing {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn unmatched_open_before(bytes: &[u8], end: usize, opening: u8, closing: u8) -> Option<usize> {
    let mut stack = Vec::new();
    for (index, byte) in bytes[..end].iter().copied().enumerate() {
        if byte == opening {
            stack.push(index);
        } else if byte == closing {
            stack.pop();
        }
    }
    stack.pop()
}

fn expression_end(bytes: &[u8], start: usize) -> usize {
    let mut stack = Vec::new();
    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        let index = start + offset;
        match byte {
            b'(' | b'[' | b'{' => stack.push(byte),
            b')' | b']' | b'}' if stack.is_empty() => return index,
            b')' | b']' | b'}' => {
                stack.pop();
            }
            b',' | b';' | b'\n' if stack.is_empty() => return index,
            _ => {}
        }
    }
    bytes.len()
}

fn mask_range(masked: &mut [u8], start: usize, end: usize) {
    let length = masked.len();
    for byte in &mut masked[start.min(length)..end.min(length)] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}
