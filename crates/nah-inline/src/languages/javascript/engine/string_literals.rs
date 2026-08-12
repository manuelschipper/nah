//! JavaScript number/string decoding, literal holes, and absolute paths.

use super::*;

pub(super) fn parse_number(source: &str) -> Option<i64> {
    let source = source.replace('_', "");
    if let Some(hex) = source
        .strip_prefix("0x")
        .or_else(|| source.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = source
        .strip_prefix("0b")
        .or_else(|| source.strip_prefix("0B"))
    {
        i64::from_str_radix(binary, 2).ok()
    } else if let Some(octal) = source
        .strip_prefix("0o")
        .or_else(|| source.strip_prefix("0O"))
    {
        i64::from_str_radix(octal, 8).ok()
    } else {
        source.parse().ok()
    }
}

pub(super) fn decode_js_string(source: &str) -> Option<String> {
    let quote = source.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || source.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    decode_escaped(&source[1..source.len() - 1])
}

pub(super) fn decode_escape(source: &str) -> Option<String> {
    source.strip_prefix('\\').and_then(|source| {
        let wrapped = format!("\\{source}");
        decode_escaped(&wrapped)
    })
}

pub(super) fn decode_escaped(source: &str) -> Option<String> {
    let mut value = String::new();
    let mut chars = source.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            '\n' => {}
            '\r' => {
                if chars.clone().next() == Some('\n') {
                    chars.next();
                }
            }
            'b' => value.push('\u{0008}'),
            'f' => value.push('\u{000c}'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            'v' => value.push('\u{000b}'),
            '0' if !chars
                .clone()
                .next()
                .is_some_and(|next| next.is_ascii_digit()) =>
            {
                value.push('\0');
            }
            'x' => {
                let code = take_hex(&mut chars, 2)?;
                value.push(char::from_u32(code)?);
            }
            'u' if chars.clone().next() == Some('{') => {
                chars.next();
                let mut hex = String::new();
                for next in chars.by_ref() {
                    if next == '}' {
                        break;
                    }
                    if !next.is_ascii_hexdigit() || hex.len() >= 6 {
                        return None;
                    }
                    hex.push(next);
                }
                if hex.is_empty() {
                    return None;
                }
                value.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            'u' => {
                let code = take_hex(&mut chars, 4)?;
                value.push(char::from_u32(code)?);
            }
            '\\' | '\'' | '"' | '`' | '$' => value.push(escaped),
            character if !character.is_ascii_digit() => value.push(character),
            _ => return None,
        }
    }
    Some(value)
}

pub(super) fn take_hex(chars: &mut impl Iterator<Item = char>, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for _ in 0..count {
        value = value.checked_mul(16)?;
        value = value.checked_add(chars.next()?.to_digit(16)?)?;
    }
    Some(value)
}

pub(super) fn delimited_has_hole(node: &HirNode, source: &str) -> bool {
    let Some(source) = source.get(node.span().start()..node.span().end()) else {
        return true;
    };
    let mut depth = 0usize;
    let mut previous_comma = true;
    let mut quote = None;
    let mut escaped = false;
    for character in source.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                if depth == 1 {
                    previous_comma = false;
                }
                quote = Some(character);
            }
            '[' | '(' | '{' => {
                if depth == 1 {
                    previous_comma = false;
                }
                depth += 1;
            }
            ']' | ')' | '}' => {
                depth = depth.saturating_sub(1);
                if depth == 1 {
                    previous_comma = false;
                }
            }
            ',' if depth == 1 => {
                if previous_comma {
                    return true;
                }
                previous_comma = true;
            }
            character if depth == 1 && !character.is_whitespace() => previous_comma = false,
            _ => {}
        }
    }
    false
}

pub(super) fn delimited_holes(
    source: &str,
    start: usize,
    end: usize,
    follows_element: bool,
) -> Option<usize> {
    let mut characters = source.get(start..end)?.chars().peekable();
    let mut commas = 0usize;
    while let Some(character) = characters.next() {
        match character {
            ',' => commas += 1,
            character if character.is_whitespace() => {}
            '/' => match characters.next()? {
                '/' => {
                    for character in characters.by_ref() {
                        if matches!(character, '\n' | '\r') {
                            break;
                        }
                    }
                }
                '*' => {
                    let mut previous = '\0';
                    let mut closed = false;
                    for character in characters.by_ref() {
                        if previous == '*' && character == '/' {
                            closed = true;
                            break;
                        }
                        previous = character;
                    }
                    if !closed {
                        return None;
                    }
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    Some(commas.saturating_sub(usize::from(follows_element)))
}

pub(super) fn is_absolute(path: &str, platform: Platform) -> bool {
    path.starts_with('/')
        || platform == Platform::Windows
            && (path.starts_with("\\\\")
                || path.as_bytes().get(1) == Some(&b':')
                    && path
                        .as_bytes()
                        .get(2)
                        .is_some_and(|byte| matches!(byte, b'/' | b'\\')))
}
