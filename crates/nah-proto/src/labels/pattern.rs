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

/// Whether an expanded pattern holds an extglob group: `@(`, `?(`, `!(`, `+(`
/// or `*(`. A shell without extglob rejects an unquoted `(` there, so the
/// spelling is never a plain glob followed by literal text.
pub fn holds_extglob(pattern: &str) -> bool {
    extglob_groups(pattern).is_none_or(|groups| !groups.is_empty())
}

/// Whether an expanded `pattern` holding extglob groups selects `path`.
/// `effinterp_proto::glob_match` has no extglob grammar and reads a group as
/// literal text, so this tries each reading of the groups as a plain glob.
///
/// `@(a|b)` stands for one of its alternatives, and `?(a|b)` for one of them
/// or nothing. `!(a|b)` selects what `*` would in its place, less what an
/// alternative would. That is exact only where the rest of its component is
/// literal, which fixes the text the group stands for.
///
/// `+(a|b)` and `*(a|b)` repeat their alternatives, which cannot be listed, so
/// they are read as one alternative (or, for `*`, nothing): a match is certain
/// and a miss is not.
///
/// `None` where this reading is not exact: on Windows; for a repetition no
/// single alternative matches; for a nested group, a brace list, or a second
/// negation; and past `MAX_EXTGLOB_READINGS` readings.
pub fn extglob_selects(pattern: &str, path: &str, platform: Platform) -> Option<bool> {
    if platform == Platform::Windows || pattern.contains('{') {
        return None;
    }
    let groups = extglob_groups(pattern)?;
    if groups.iter().filter(|group| group.kind == b'!').count() > 1 {
        return None;
    }
    let repetition = groups.iter().any(|group| matches!(group.kind, b'+' | b'*'));
    // Each reading is the pattern with every group but the negation replaced
    // by one alternative: the text before the negation, and the text after.
    let mut readings = vec![(String::new(), None::<String>)];
    let mut negation = None;
    let mut at = 0;
    for group in &groups {
        let literal = &pattern[at..group.start];
        at = group.end;
        let mut alternatives = group.alternatives.clone();
        if matches!(group.kind, b'?' | b'*') {
            alternatives.push("");
        }
        if group.kind == b'!' {
            negation = Some(&group.alternatives);
            for (before, after) in &mut readings {
                before.push_str(literal);
                *after = Some(String::new());
            }
            continue;
        }
        if readings.len() * alternatives.len() > MAX_EXTGLOB_READINGS {
            return None;
        }
        readings = readings
            .iter()
            .flat_map(|(before, after)| {
                alternatives.iter().map(move |alternative| {
                    let (mut before, mut after) = (before.clone(), after.clone());
                    let text = after.as_mut().unwrap_or(&mut before);
                    text.push_str(literal);
                    text.push_str(alternative);
                    (before, after)
                })
            })
            .collect();
    }
    for (before, after) in &mut readings {
        after.as_mut().unwrap_or(before).push_str(&pattern[at..]);
    }
    let matches = |glob: &str| effinterp_proto::glob_match(glob, path).ok();
    let mut selects = false;
    for (before, after) in &readings {
        let Some((after, excluded)) = after.as_ref().zip(negation) else {
            selects |= matches(before)?;
            continue;
        };
        let wildcard = |text: &str| text.contains(['*', '?', '[']);
        if wildcard(before.rsplit('/').next().unwrap_or(before))
            || wildcard(after.split('/').next().unwrap_or(after))
            || excluded.iter().any(|alternative| alternative.contains('/'))
        {
            return None;
        }
        if matches(&format!("{before}*{after}"))? {
            let mut excludes = false;
            for alternative in excluded {
                excludes |= matches(&format!("{before}{alternative}{after}"))?;
            }
            selects |= !excludes;
        }
    }
    (selects || !repetition).then_some(selects)
}

/// The most plain-glob readings `extglob_selects` tries for one pattern.
const MAX_EXTGLOB_READINGS: usize = 64;

/// One extglob group: the byte range it spans in its pattern, its operator
/// and its `|`-separated alternatives.
struct ExtglobGroup<'a> {
    start: usize,
    end: usize,
    kind: u8,
    alternatives: Vec<&'a str>,
}

/// The extglob groups of `pattern` in order, skipping backslash-escaped
/// characters. `None` for a group that is unclosed or holds another group.
fn extglob_groups(pattern: &str) -> Option<Vec<ExtglobGroup<'_>>> {
    let bytes = pattern.as_bytes();
    let mut groups = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' {
            at += 2;
            continue;
        }
        if matches!(bytes[at], b'@' | b'?' | b'!' | b'+' | b'*') && bytes.get(at + 1) == Some(&b'(')
        {
            let inner = &pattern[at + 2..];
            let close = inner.find(')')?;
            let inner = &inner[..close];
            if inner.contains('(') {
                return None;
            }
            let end = at + 2 + close + 1;
            groups.push(ExtglobGroup {
                start: at,
                end,
                kind: bytes[at],
                alternatives: inner.split('|').collect(),
            });
            at = end;
            continue;
        }
        at += 1;
    }
    Some(groups)
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
    fn extglob_groups_select_the_names_their_readings_match() {
        for (pattern, path, expected) in [
            ("/h/.ssh/!(config)", "/h/.ssh/id_ed25519", Some(true)),
            ("/h/.ssh/!(config)", "/h/.ssh/config", Some(false)),
            ("/h/.ssh/!(config|id_*)", "/h/.ssh/id_ed25519", Some(false)),
            // A negation selects no hidden name, as `*` does not.
            ("/h/!(x)", "/h/.ssh", Some(false)),
            ("/h/.ssh/@(id_*)", "/h/.ssh/id_ed25519", Some(true)),
            ("/h/.ssh/@(id_*)", "/h/.ssh/config", Some(false)),
            ("/h/@(a|.ssh)/id_?(rsa|dsa)", "/h/.ssh/id_", Some(true)),
            ("/h/certs/!(README).pem", "/h/certs/server.pem", Some(true)),
            ("/h/certs/!(server).pem", "/h/certs/server.pem", Some(false)),
            ("/h/+(a|b)", "/h/a", Some(true)),
            ("/h/*(a|b)c", "/h/c", Some(true)),
            // Not exact: the text a negation stands for is not fixed, a
            // repetition is not listed, and a group holds a group.
            ("/h/*!(x)", "/h/ax", None),
            ("/h/+(a|b)", "/h/ab", None),
            ("/h/!(a|@(b))", "/h/c", None),
            ("/h/!(a)/!(b)", "/h/c/d", None),
        ] {
            assert_eq!(
                extglob_selects(pattern, path, Platform::Linux),
                expected,
                "{pattern} {path}"
            );
        }
        assert!(holds_extglob("/h/!(x)"));
        assert!(!holds_extglob(r"/h/a\!(x"));
        assert!(!holds_extglob("/h/*.log"));
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
