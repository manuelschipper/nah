//! PowerShell wildcards (about_Wildcards) and the `-Include`, `-Exclude` and
//! `-Filter` parameters, matched over the host's listed entries.

use effinterp_proto::ListedEntry;

use super::path_resolution::drive_rooted;

/// Whether -Include, -Exclude and -Filter (`filters`, in that order) admit
/// an entry `name`, matched without regard to case under `fold`; `None`
/// where a pattern cannot be matched.
pub(super) fn filters_admit(
    filters: &[Option<&[String]>; 3],
    name: &str,
    fold: bool,
) -> Option<bool> {
    let matches = |patterns: &[String]| -> Option<bool> {
        for pattern in patterns {
            if wildcard_match(pattern, name, fold)? {
                return Some(true);
            }
        }
        Some(false)
    };
    let [include, exclude, filter] = filters;
    Some(
        include.map_or(Some(true), matches)?
            && !exclude.map_or(Some(false), matches)?
            && filter.map_or(Some(true), matches)?,
    )
}

/// Whether the wildcard `glob`, which selects beneath `root`, and the filters
/// select a listed entry: `Some(None)` where they do not, and otherwise
/// whether they do only under one reading of PowerShell's case or hidden-item
/// rule on this host. `None` where the wildcard or a filter cannot be matched.
///
/// A drive-rooted wildcard is matched as Windows matches it: without regard
/// to case, and with hidden items marked by an attribute the listing does not
/// carry. Elsewhere a dot name is hidden unless `force`, and whether case is
/// folded is not established, so both readings are asked.
pub(super) fn wildcard_selects(
    glob: &str,
    root: &str,
    entry: &ListedEntry,
    force: bool,
    admits: &dyn Fn(&str, bool) -> Option<bool>,
) -> Option<Option<bool>> {
    let windows = drive_rooted(glob);
    let root_components = glob_components_below(glob, root) as usize;
    let patterns = glob.split('/').collect::<Vec<_>>();
    let patterns = &patterns[patterns.len() - root_components.min(patterns.len())..];
    let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
    let components = entry.path.split('/').collect::<Vec<_>>();
    if components.len() != patterns.len() {
        return Some(None);
    }
    // Whether a component a wildcard selects is a dot name, the pattern
    // itself starting with a `.` or not.
    let dotted = |spelled: bool| {
        !force
            && components.iter().zip(patterns).any(|(component, pattern)| {
                component.starts_with('.')
                    && pattern.contains(['*', '?', '['])
                    && pattern.starts_with('.') == spelled
            })
    };
    let reading = |fold: bool| -> Option<bool> {
        for (component, pattern) in components.iter().zip(patterns) {
            if !wildcard_match(pattern, component, fold)? {
                return Some(false);
            }
        }
        admits(name, fold)
    };
    let (folded, exact) = (reading(true)?, reading(windows)?);
    // Off Windows a wildcard hides dot names; whether a pattern that spells
    // the dot, as `.*`, still hides them is not established, so such an entry
    // is selected and marked uncertain.
    let hidden = dotted(false);
    if !(folded || exact) || hidden && !windows {
        return Some(None);
    }
    Some(Some(folded != exact || dotted(true) || hidden && windows))
}

/// Most entries a filtered wildcard departs as one by one. Past it the
/// departure names the wildcard itself.
const MAX_ADMITTED_ENTRIES: usize = 64;

/// The paths of the listed `entries` that the wildcard `glob` matches and the
/// filters admit. `None` where that is not established: a reading of the
/// wildcard, the filters or the host's case or hidden-item rule is open, or
/// more entries are admitted than depart one by one.
pub(super) fn admitted_entries(
    glob: &str,
    entries: &[ListedEntry],
    force: bool,
    admits: &dyn Fn(&str, bool) -> Option<bool>,
) -> Option<Vec<String>> {
    let root = wildcard_root(glob);
    let mut paths = Vec::new();
    for entry in entries {
        match wildcard_selects(glob, root, entry, force, admits)? {
            None => {}
            Some(true) => return None,
            Some(false) if paths.len() == MAX_ADMITTED_ENTRIES => return None,
            Some(false) => paths.push(format!("{}/{}", root.trim_end_matches('/'), entry.path)),
        }
    }
    Some(paths)
}

/// How many path components `glob` has below its wildcard root `root`.
pub(super) fn glob_components_below(glob: &str, root: &str) -> u32 {
    glob[root.len().min(glob.len())..]
        .trim_start_matches('/')
        .split('/')
        .count() as u32
}

/// PowerShell's wildcard language (about_Wildcards) over one path
/// component: `*` any run, `?` one character, `[abc]` and `[a-c]` one of a
/// set, and a backtick escaping the next character. A bracket set has no
/// negation: `[!e]` is `!` or `e`. `fold` compares without regard to case.
/// `None` for an unterminated set, which PowerShell rejects.
pub(super) fn wildcard_match(pattern: &str, text: &str, fold: bool) -> Option<bool> {
    enum WildcardToken {
        Any,
        One,
        Set(Vec<(char, char)>),
        Literal(char),
    }
    let same = |a: char, b: char| {
        if fold {
            a.to_lowercase().eq(b.to_lowercase())
        } else {
            a == b
        }
    };
    let mut tokens = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        tokens.push(match c {
            '*' => WildcardToken::Any,
            '?' => WildcardToken::One,
            '`' => WildcardToken::Literal(chars.next().unwrap_or('`')),
            '[' => {
                // Each member, and whether it was escaped.
                let mut members = Vec::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        ']' => {
                            closed = true;
                            break;
                        }
                        '`' => members.push((chars.next()?, true)),
                        c => members.push((c, false)),
                    }
                }
                if !closed {
                    return None;
                }
                let mut set = Vec::new();
                let mut index = 0;
                while index < members.len() {
                    // An unescaped `-` between two members is a range.
                    if members.get(index + 1) == Some(&('-', false)) && index + 2 < members.len() {
                        set.push((members[index].0, members[index + 2].0));
                        index += 3;
                    } else {
                        set.push((members[index].0, members[index].0));
                        index += 1;
                    }
                }
                WildcardToken::Set(set)
            }
            c => WildcardToken::Literal(c),
        });
    }
    let text = text.chars().collect::<Vec<_>>();
    // matched[j]: the tokens so far can match the first j characters.
    let mut matched = vec![false; text.len() + 1];
    matched[0] = true;
    for token in &tokens {
        let mut next = vec![false; text.len() + 1];
        for j in 0..=text.len() {
            match token {
                WildcardToken::Any => next[j] = matched[j] || j > 0 && next[j - 1],
                _ if j == 0 => {}
                WildcardToken::One => next[j] = matched[j - 1],
                WildcardToken::Literal(c) => next[j] = matched[j - 1] && same(*c, text[j - 1]),
                WildcardToken::Set(set) => {
                    let c = text[j - 1];
                    next[j] = matched[j - 1]
                        && set.iter().any(|&(low, high)| {
                            same(low, c)
                                || same(high, c)
                                || (low..=high).contains(&c)
                                || fold
                                    && c.to_lowercase()
                                        .chain(c.to_uppercase())
                                        .any(|c| (low..=high).contains(&c))
                        });
                }
            }
        }
        matched = next;
    }
    Some(matched[text.len()])
}

/// The directory a wildcard selects entries beneath: the path up to the
/// component holding its first wildcard.
pub(super) fn wildcard_root(glob: &str) -> &str {
    let first = glob.find(['*', '?', '[']).unwrap_or(glob.len());
    match glob[..first].rfind('/') {
        Some(0) | None => "/",
        Some(end) => &glob[..end],
    }
}
