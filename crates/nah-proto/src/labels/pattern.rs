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

/// How the shell reads one path component's parentheses. A `(` opens an
/// extglob group only after `?`, `*`, `+`, `@` or `!` and only where its
/// `)` closes it, nesting counted; an unclosed group, a bare `(` and a `)`
/// with nothing to close are text. Pathname expansion matches each
/// component on its own, so a group cannot span a `/`.
///
/// `None` for a component with no group, which is matched as literal text.
/// Otherwise whether a reading with extglob on may leave the component only
/// dots, `.` or `..`: its text outside the groups is dots, and a group may
/// stand for dots (`.@(|.)`, `!(x)`) or, beside dots, for nothing. A
/// component is never empty, so `*(1)` alone is not `.`.
pub(crate) fn extglob_component_may_be_dots(component: &str) -> Option<bool> {
    let bytes = component.as_bytes();
    let mut rest = String::new();
    let mut groups = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        // An escaped character is text, but an escaped dot is still a dot.
        if bytes[at] == b'\\' {
            rest.push(if bytes.get(at + 1) == Some(&b'.') {
                '.'
            } else {
                '\\'
            });
            at += 2;
            continue;
        }
        if matches!(bytes[at], b'?' | b'*' | b'+' | b'@' | b'!')
            && bytes.get(at + 1) == Some(&b'(')
            && let Some(close) = closing_parenthesis(bytes, at + 1)
        {
            groups.push((bytes[at], &component[at + 2..close]));
            at = close + 1;
            continue;
        }
        // Only whether the rest is all dots is read, so a byte of a longer
        // character stands for it.
        rest.push(char::from(bytes[at]));
        at += 1;
    }
    if groups.is_empty() {
        return None;
    }
    let dots = |text: &str| text.chars().all(|character| character == '.');
    // An alternative's own groups and operators may vanish, so only its dots
    // and its other characters count.
    let may_be_dots = |alternative: &str| {
        alternative.contains('.')
            && alternative.chars().all(|character| {
                matches!(
                    character,
                    '.' | '(' | ')' | '|' | '?' | '*' | '+' | '@' | '!'
                )
            })
    };
    let may_be_empty = |kind: u8, inner: &str| {
        matches!(kind, b'?' | b'*' | b'!')
            || top_level_alternatives(inner).iter().any(|alternative| {
                alternative.chars().all(|character| {
                    matches!(character, '(' | ')' | '|' | '?' | '*' | '+' | '@' | '!')
                })
            })
    };
    Some(
        dots(&rest)
            && groups.iter().any(|(kind, inner)| {
                *kind == b'!'
                    || top_level_alternatives(inner)
                        .iter()
                        .any(|alternative| may_be_dots(alternative))
                    || !rest.is_empty() && may_be_empty(*kind, inner)
            }),
    )
}

/// The `)` closing the `(` at `open`, nesting counted and past escapes.
fn closing_parenthesis(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = open;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

/// A group's alternatives, split at its `|`s outside nested groups.
fn top_level_alternatives(inner: &str) -> Vec<&str> {
    let bytes = inner.as_bytes();
    let (mut alternatives, mut depth, mut start, mut at) = (Vec::new(), 0usize, 0, 0);
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 1,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'|' if depth == 0 => {
                alternatives.push(&inner[start..at]);
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    alternatives.push(&inner[start..]);
    alternatives
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

/// The spellings a glob may stand for under each brace reading a producer
/// may give it: as written, with every brace literal, as a shell file glob
/// reaches it after Bash's brace expansion; Bash's expansion itself, where
/// only a comma list or a valid sequence (`{1..3}`, `{a..c}`) expands and
/// any other group (`{archive}`, `{archive..old}`, an open `{`) stays as it
/// is; and an alternation reading, where every closed group is a comma list
/// and one with a single item is that item. A brace left in a spelling is a
/// literal character.
///
/// Bash's brace expansion does not see bracket expressions, so `x[{]a,b}`
/// holds the group `{]a,b}`, while a glob syntax that reads them keeps a
/// brace inside one literal (`[{]archive` names `{archive`). Both are read.
///
/// `None` past `limit` spellings.
pub(crate) fn brace_readings(glob: &str, limit: usize) -> Option<Vec<String>> {
    let characters = glob.chars().collect::<Vec<_>>();
    let mut readings = vec![glob.to_owned()];
    for classes in [true, false] {
        let parts = brace_parts(&characters, classes);
        for bash in [true, false] {
            for reading in expand_brace_parts(&parts, bash, limit)? {
                if !readings.contains(&reading) {
                    readings.push(reading);
                }
            }
        }
    }
    (readings.len() <= limit).then_some(readings)
}

/// One piece of a glob read for braces: text, or a closed brace group, by
/// its items between top-level commas and its text between the braces.
enum BracePart {
    Text(String),
    Group(Vec<Vec<BracePart>>, String),
}

/// `characters` read for braces; with `classes`, a bracket expression is
/// text whose braces are literal.
fn brace_parts(characters: &[char], classes: bool) -> Vec<BracePart> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut at = 0;
    while at < characters.len() {
        match characters[at] {
            '\\' => {
                text.push('\\');
                if let Some(next) = characters.get(at + 1) {
                    text.push(*next);
                }
                at += 2;
            }
            '[' if classes => {
                let end = bracket_end(characters, at);
                text.extend(&characters[at..end]);
                at = end;
            }
            '{' => match group_end(characters, at, classes) {
                Some(end) => {
                    if !text.is_empty() {
                        parts.push(BracePart::Text(std::mem::take(&mut text)));
                    }
                    let inner = &characters[at + 1..end];
                    let items = split_top_level_commas(inner, classes)
                        .into_iter()
                        .map(|item| brace_parts(item, classes))
                        .collect();
                    parts.push(BracePart::Group(items, inner.iter().collect()));
                    at = end + 1;
                }
                None => {
                    text.push('{');
                    at += 1;
                }
            },
            character => {
                text.push(character);
                at += 1;
            }
        }
    }
    if !text.is_empty() {
        parts.push(BracePart::Text(text));
    }
    parts
}

/// Where a bracket expression opened at `start` ends, one past its `]`; a
/// `[` that never closes is a literal character.
fn bracket_end(characters: &[char], start: usize) -> usize {
    let mut at = start + 1;
    if matches!(characters.get(at), Some('!' | '^')) {
        at += 1;
    }
    // A `]` first in the expression is one of its members.
    if characters.get(at) == Some(&']') {
        at += 1;
    }
    match characters[at.min(characters.len())..]
        .iter()
        .position(|c| *c == ']')
    {
        Some(offset) => at + offset + 1,
        None => start + 1,
    }
}

/// The `}` closing the group opened at `start`, past escapes, nested groups
/// and, with `classes`, bracket expressions.
fn group_end(characters: &[char], start: usize, classes: bool) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = start;
    while at < characters.len() {
        match characters[at] {
            '\\' => at += 1,
            '[' if classes => {
                at = bracket_end(characters, at);
                continue;
            }
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

fn split_top_level_commas(characters: &[char], classes: bool) -> Vec<&[char]> {
    let mut items = Vec::new();
    let (mut depth, mut start, mut at) = (0usize, 0, 0);
    while at < characters.len() {
        match characters[at] {
            '\\' => at += 1,
            '[' if classes => {
                at = bracket_end(characters, at);
                continue;
            }
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(&characters[start..at]);
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    items.push(&characters[start..]);
    items
}

fn expand_brace_parts(parts: &[BracePart], bash: bool, limit: usize) -> Option<Vec<String>> {
    let mut spellings = vec![String::new()];
    for part in parts {
        let choices = match part {
            BracePart::Text(text) => vec![text.clone()],
            BracePart::Group(items, _) if items.len() > 1 || !bash => {
                let mut choices = Vec::new();
                for item in items {
                    choices.extend(expand_brace_parts(item, bash, limit)?);
                }
                choices
            }
            BracePart::Group(items, inner) => match bash_sequence(inner, limit) {
                Some(sequence) => sequence?,
                None => expand_brace_parts(&items[0], bash, limit)?
                    .into_iter()
                    .map(|item| format!("{{{item}}}"))
                    .collect(),
            },
        };
        if spellings.len().saturating_mul(choices.len()) > limit {
            return None;
        }
        spellings = spellings
            .iter()
            .flat_map(|spelling| {
                choices
                    .iter()
                    .map(move |choice| format!("{spelling}{choice}"))
            })
            .collect();
    }
    Some(spellings)
}

/// The words a Bash sequence expression (`1..3`, `a..e..2`) stands for,
/// `Some(None)` past `limit` of them, `None` when `inner` is not one.
fn bash_sequence(inner: &str, limit: usize) -> Option<Option<Vec<String>>> {
    let bounds = inner.split("..").collect::<Vec<_>>();
    let step = match bounds.as_slice() {
        [_, _] => 1,
        [_, _, step] => step.parse::<i64>().ok()?.unsigned_abs().max(1),
        _ => return None,
    };
    let count = |first: i64, last: i64| first.abs_diff(last) / step + 1;
    let within = |count: u64| usize::try_from(count).is_ok_and(|count| count <= limit);
    let walk = |first: i64, last: i64| {
        let ascending = first <= last;
        (0..count(first, last)).map(move |index| {
            let offset = i64::try_from(index * step).unwrap_or(i64::MAX);
            if ascending {
                first + offset
            } else {
                first - offset
            }
        })
    };
    if let (Ok(first), Ok(last)) = (bounds[0].parse::<i64>(), bounds[1].parse::<i64>()) {
        // A bound written with a leading zero pads every word to the wider
        // bound's width.
        let padded = |bound: &str| {
            let digits = bound.strip_prefix(['-', '+']).unwrap_or(bound);
            digits.len() > 1 && digits.starts_with('0')
        };
        let width = if padded(bounds[0]) || padded(bounds[1]) {
            bounds[0].len().max(bounds[1].len())
        } else {
            0
        };
        return Some(within(count(first, last)).then(|| {
            walk(first, last)
                .map(|number| format!("{number:0width$}"))
                .collect()
        }));
    }
    let letter = |bound: &str| {
        let mut characters = bound.chars();
        match (characters.next(), characters.next()) {
            (Some(letter), None) if letter.is_ascii_alphabetic() => Some(letter as i64),
            _ => None,
        }
    };
    let (first, last) = (letter(bounds[0])?, letter(bounds[1])?);
    Some(within(count(first, last)).then(|| {
        walk(first, last)
            .filter_map(|code| {
                u8::try_from(code)
                    .ok()
                    .map(|code| char::from(code).to_string())
            })
            .collect()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_readings_cover_literal_bash_and_alternation_spellings() {
        let readings = |glob| brace_readings(glob, 256);
        for (glob, spelling) in [
            // Bash leaves a group without a comma or valid sequence as it is;
            // alternation takes its one item.
            ("a{archive}", "a{archive}"),
            ("a{archive}", "aarchive"),
            ("a{archive..old}", "aarchive..old"),
            ("a{{x,y}}", "a{x}"),
            ("a{{x,y}}", "ay"),
            ("a{x", "a{x"),
            ("{a,b}c", "bc"),
            ("d{r..t}", "ds"),
            ("{a..e..2}", "c"),
            // A padded bound pads every word.
            ("{001..010}", "007"),
        ] {
            assert!(
                readings(glob)
                    .unwrap()
                    .iter()
                    .any(|reading| reading == spelling),
                "{glob} reads as {spelling}"
            );
        }
        assert!(
            !readings("{001..010}")
                .unwrap()
                .iter()
                .any(|reading| reading == "7")
        );
        // Bash's expansion does not see a bracket expression; a glob syntax
        // that reads one keeps its braces literal.
        for (glob, spelling) in [("x[{]a,b}", "x[b"), ("x[{]a,b}", "x[{]a,b}")] {
            assert!(
                readings(glob)
                    .unwrap()
                    .iter()
                    .any(|reading| reading == spelling),
                "{glob} reads as {spelling}"
            );
        }
        // Too many spellings are left unread.
        assert_eq!(readings("{1..300}"), None);
        assert_eq!(
            readings("{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p}{q,r}"),
            None
        );
    }

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
