//! Coverage, filesystem operations and lexical path helpers shared by the
//! effect evidence and the label classifiers.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    Full,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemOperation {
    Read,
    Write,
    Delete,
}

/// The literal prefix of a shell pattern. Expansion can only add text to it, so
/// every path the shell can select here starts with this string.
pub fn pattern_bound(target: &str) -> &str {
    let bytes = target.as_bytes();
    let index = bytes.iter().enumerate().find_map(|(index, byte)| {
        (matches!(byte, b'*' | b'?' | b'[' | b'{')
            || matches!(byte, b'@' | b'+' | b'!') && bytes.get(index + 1) == Some(&b'('))
        .then_some(index)
    });
    index.map_or(target, |index| &target[..index])
}

pub(crate) fn is_path_descendant(target: &str, root: &str) -> bool {
    let windows = root.starts_with("\\\\") || root.as_bytes().get(1) == Some(&b':');
    let is_separator = |byte| byte == b'/' || (windows && byte == b'\\');
    let Some(suffix) = target.strip_prefix(root) else {
        return false;
    };
    !suffix.is_empty()
        && (root
            .as_bytes()
            .last()
            .is_some_and(|byte| is_separator(*byte))
            || suffix
                .as_bytes()
                .first()
                .is_some_and(|byte| is_separator(*byte)))
}
pub(crate) fn is_lexically_normalized_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    if let Some(device) = path.strip_prefix(r"\\.\") {
        return !device.is_empty() && !device.contains(['/', '\\']);
    }
    let windows = path.starts_with("\\\\") || path.as_bytes().get(1) == Some(&b':');
    let is_separator = |byte| byte == b'/' || (windows && byte == b'\\');
    let root_len = if path.starts_with("\\\\") {
        2
    } else if path.as_bytes().get(1) == Some(&b':') {
        3
    } else {
        1
    };
    if path.len() == root_len {
        return windows && !path.starts_with("\\\\");
    }
    let remainder = &path[root_len..];
    let mut component_count = 0;
    let components_valid = remainder
        .split(|character| character == '/' || (windows && character == '\\'))
        .all(|component| {
            component_count += 1;
            !component.is_empty() && !matches!(component, "." | "..")
        });
    !remainder.is_empty()
        && !remainder
            .as_bytes()
            .last()
            .is_some_and(|byte| is_separator(*byte))
        && components_valid
        && (!path.starts_with("\\\\") || component_count >= 2)
}
