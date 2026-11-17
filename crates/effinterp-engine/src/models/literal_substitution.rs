//! The shared literal `s/pattern/replacement/[g]` subset of sed and Perl.
//! Regex syntax and replacement expansions never establish output bytes.

pub(crate) struct LiteralSubstitution<'a> {
    pattern: &'a str,
    replacement: &'a str,
    global: bool,
}

pub(crate) fn parse(script: &str) -> Option<LiteralSubstitution<'_>> {
    let rest = script.trim().strip_prefix('s')?;
    let delimiter = rest.chars().next()?;
    if delimiter == '\\' || delimiter.is_alphanumeric() || delimiter.is_whitespace() {
        return None;
    }
    let mut parts = rest[delimiter.len_utf8()..].split(delimiter);
    let pattern = parts.next()?;
    let replacement = parts.next()?;
    let flags = parts.next()?.trim();
    let flags = flags.strip_suffix(';').unwrap_or(flags).trim_end();
    if parts.next().is_some()
        || !matches!(flags, "" | "g")
        || pattern.is_empty()
        || pattern.contains([
            '.', '[', ']', '*', '^', '$', '\\', '\n', '(', ')', '+', '?', '{', '}', '|',
        ])
        || replacement.contains(['&', '\\', '\n'])
    {
        return None;
    }
    Some(LiteralSubstitution {
        pattern,
        replacement,
        global: flags == "g",
    })
}

impl LiteralSubstitution<'_> {
    pub(crate) fn apply(&self, source: &str, max_bytes: u64) -> Option<String> {
        let matches = source.matches(self.pattern).count();
        let bytes = source
            .len()
            .saturating_add(matches.saturating_mul(self.replacement.len()));
        if bytes as u64 > max_bytes {
            return None;
        }
        Some(
            source
                .split_inclusive('\n')
                .map(|line| {
                    line.replacen(
                        self.pattern,
                        self.replacement,
                        if self.global { usize::MAX } else { 1 },
                    )
                })
                .collect(),
        )
    }
}
