//! Python string decoding, bounded construction, and path composition.

use super::*;

pub(super) fn decode_string_fragment(value: &str, raw: bool) -> Option<String> {
    if raw {
        return Some(value.to_owned());
    }
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            let character = value[index..].chars().next()?;
            output.push(character);
            index += character.len_utf8();
            continue;
        }
        index += 1;
        let escape = *bytes.get(index)?;
        index += 1;
        match escape {
            b'\\' => output.push('\\'),
            b'\'' => output.push('\''),
            b'"' => output.push('"'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'a' => output.push('\x07'),
            b'b' => output.push('\x08'),
            b'f' => output.push('\x0c'),
            b'v' => output.push('\x0b'),
            b'\n' => {}
            b'x' => {
                let value = parse_hex(bytes.get(index..index + 2)?)?;
                output.push(char::from(value as u8));
                index += 2;
            }
            b'u' => {
                let value = parse_hex(bytes.get(index..index + 4)?)?;
                output.push(char::from_u32(value)?);
                index += 4;
            }
            b'U' => {
                let value = parse_hex(bytes.get(index..index + 8)?)?;
                output.push(char::from_u32(value)?);
                index += 8;
            }
            b'0'..=b'7' => {
                let mut value = u32::from(escape - b'0');
                let mut digits = 1;
                while digits < 3
                    && bytes
                        .get(index)
                        .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
                {
                    value = value * 8 + u32::from(bytes[index] - b'0');
                    index += 1;
                    digits += 1;
                }
                output.push(char::from_u32(value)?);
            }
            other => {
                output.push('\\');
                output.push(char::from(other));
            }
        }
    }
    Some(output)
}

pub(super) fn parse_hex(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => return None,
        };
        Some(value * 16 + digit)
    })
}

pub(super) fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0usize;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

pub(super) fn bounded_owned(value: &str, budget: &mut Budget) -> Option<String> {
    budget
        .admit_value_bytes(Some(value.len()))
        .then(|| value.to_owned())
}

pub(super) fn bounded_push_str(output: &mut String, value: &str, budget: &mut Budget) -> bool {
    if !budget.admit_value_bytes(output.len().checked_add(value.len())) {
        return false;
    }
    output.push_str(value);
    true
}

pub(super) fn join_path(mut base: String, relative: &str, budget: &mut Budget) -> Option<String> {
    if base.is_empty() {
        return bounded_owned(relative, budget);
    }
    let separator = usize::from(!base.ends_with(['/', '\\']));
    let relative = relative.trim_start_matches(['/', '\\']);
    if !budget.admit_value_bytes(
        base.len()
            .checked_add(separator)
            .and_then(|bytes| bytes.checked_add(relative.len())),
    ) {
        return None;
    }
    if !base.ends_with(['/', '\\']) {
        base.push('/');
    }
    base.push_str(relative);
    Some(base)
}

pub(super) fn expand_home(path: &str, home: &str, budget: &mut Budget) -> Option<String> {
    if path == "~" {
        bounded_owned(home, budget)
    } else if let Some(relative) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        join_path(home.to_owned(), relative, budget)
    } else {
        bounded_owned(path, budget)
    }
}

pub(super) fn is_absolute(path: &str, platform: Platform) -> bool {
    if platform == Platform::Windows {
        path.starts_with(['/', '\\'])
            || path.as_bytes().get(1) == Some(&b':')
                && path
                    .as_bytes()
                    .get(2)
                    .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
    } else {
        path.starts_with('/')
    }
}

pub(super) fn compose_cwd(
    parent: &NestedExecutionCwd,
    child: &NestedExecutionCwd,
    platform: Platform,
) -> NestedExecutionCwd {
    match child {
        NestedExecutionCwd::Inherited => parent.clone(),
        NestedExecutionCwd::Path(path) => parent.changed(path, platform),
        NestedExecutionCwd::Unknown => NestedExecutionCwd::Unknown,
    }
}

pub(super) fn normalize_path(path: &str, platform: Platform) -> String {
    let absolute = path.starts_with(['/', '\\']);
    let mut components = Vec::new();
    for component in path.split(['/', '\\']) {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(if platform == Platform::Windows {
                component.to_ascii_lowercase()
            } else {
                component.to_owned()
            }),
        }
    }
    let normalized = components.join("/");
    if absolute && platform != Platform::Windows {
        format!("/{normalized}")
    } else {
        normalized
    }
}
