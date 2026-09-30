//! What an expanded shell pattern can select, read component by component
//! against a known path's spelling. Nothing here reads the host.

use crate::ctx::Platform;

/// Whether an expanded `pattern` can select `known`, a directory above it, or,
/// for a `directory`, a path inside it. Each component matches only the names
/// its glob matches: `/tmp/*.log` cannot select `/tmp` itself, and
/// `~/.*.swp` cannot select `~/.ssh`.
///
/// `None` where this reading is not exact, so the caller keeps its
/// literal-prefix rule: on Windows, and for a pattern with `**`, braces or an
/// extglob.
pub fn pattern_reaches(
    pattern: &str,
    known: &str,
    directory: bool,
    platform: Platform,
) -> Option<bool> {
    if platform == Platform::Windows || pattern.contains(['{', '(']) {
        return None;
    }
    let pattern = pattern.trim_end_matches('/').split('/').collect::<Vec<_>>();
    let known = known.trim_end_matches('/').split('/').collect::<Vec<_>>();
    if pattern.iter().any(|component| component.contains("**")) {
        return None;
    }
    if pattern.len() > known.len() && !directory {
        return Some(false);
    }
    let shared = pattern.len().min(known.len());
    effinterp_proto::glob_match(&pattern[..shared].join("/"), &known[..shared].join("/")).ok()
}

/// Whether a pattern's last component may match every entry of its
/// directory, or every hidden one: past an optional leading `.` it names no
/// literal character outside a bracket expression. A bracket can list every
/// name's first character (`[a-zA-Z]*`), so it never narrows. `*`, `.*`, `?*`,
/// `.[!.]*` and `[0-9]*` may select every entry; `*.log` and `a*` do not.
/// Braces and extglobs are read as selecting every entry.
pub fn selects_every_entry(name: &str) -> bool {
    if name.contains(['{', '(']) {
        return true;
    }
    let mut characters = name.strip_prefix('.').unwrap_or(name).chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '*' | '?' => {}
            '[' => {
                characters.next_if(|member| matches!(member, '!' | '^'));
                // A `]` first in the class is one of its members.
                characters.next_if_eq(&']');
                while let Some(member) = characters.next() {
                    if member == ']' {
                        break;
                    }
                    // `[:alpha:]`, `[=a=]` and `[.a.]` end at their own `:]`,
                    // `=]` or `.]`, not at the class's first `]`.
                    if member == '['
                        && let Some(delimiter) =
                            characters.next_if(|next| matches!(next, ':' | '=' | '.'))
                    {
                        while let Some(inner) = characters.next() {
                            if inner == delimiter && characters.next_if_eq(&']').is_some() {
                                break;
                            }
                        }
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_select_only_the_names_their_globs_match() {
        for (pattern, known, directory, expected) in [
            // Selecting inside `/tmp` is not selecting `/tmp` itself.
            ("/tmp/*.log", "/tmp", false, false),
            ("/tmp/*.log", "/tmp", true, true),
            ("/tmp/*", "/tmp/x", true, true),
            (
                "/home/test/.*.swp",
                "/home/test/.ssh/authorized_keys",
                false,
                false,
            ),
            (
                "/home/test/.*",
                "/home/test/.ssh/authorized_keys",
                false,
                true,
            ),
            (
                "/home/test/.ss*",
                "/home/test/.ssh/authorized_keys",
                false,
                true,
            ),
            // `*` does not select a hidden name.
            (
                "/home/test/*",
                "/home/test/.ssh/authorized_keys",
                false,
                false,
            ),
            (
                "/home/test/.config/*",
                "/home/test/.config/autostart",
                true,
                true,
            ),
            (
                "/home/test/.config/*/Cache",
                "/home/test/.config/systemd/user",
                true,
                false,
            ),
            // A pattern longer than a directory selects inside it.
            (
                "/home/test/.config/*/Cache",
                "/home/test/.config/autostart",
                true,
                true,
            ),
            ("/etc/*.bak", "/etc/passwd", false, false),
            ("/etc/*.bak", "/etc/sudoers.d", true, false),
            ("/etc/sudoers.d/*", "/etc/sudoers.d", true, true),
        ] {
            assert_eq!(
                pattern_reaches(pattern, known, directory, Platform::Linux),
                Some(expected),
                "{pattern} {known}"
            );
        }
        for pattern in [
            "/home/test/**/.ssh",
            "/home/test/{a,.ssh}",
            "/home/test/@(x)",
        ] {
            assert_eq!(
                pattern_reaches(pattern, "/home/test/.ssh", true, Platform::Linux),
                None,
                "{pattern}"
            );
        }
    }

    #[test]
    fn every_entry_names_no_literal() {
        for name in [
            "*",
            ".*",
            "?*",
            "*?",
            ".[!.]*",
            "[!a]*",
            "[0-9]*",
            "[a-zA-Z]*",
            "*[a-z]*",
            "[!]]*",
            "[]a-z]*",
            "[[:alpha:]]*",
            ".[[:alpha:]]*",
            "[[:upper:][:digit:]]*",
            "{*,.*}",
            "!(x)",
        ] {
            assert!(selects_every_entry(name), "{name}");
        }
        for name in [
            "*.log",
            ".*.swp",
            "a*",
            "[]]x",
            "[[:alpha:]]x",
            ".*_history",
            "*-test-output",
        ] {
            assert!(!selects_every_entry(name), "{name}");
        }
    }
}
