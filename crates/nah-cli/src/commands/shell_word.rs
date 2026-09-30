//! POSIX shell-word quoting for generated hook commands and Cline MCP arguments.

/// Quotes one POSIX shell word by wrapping it in single quotes and rewriting
/// each embedded apostrophe as `'"'"'`. Generated hook command bytes depend on
/// this exact form. Never apply it to Windows command paths.
pub(crate) fn quote_posix_shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
