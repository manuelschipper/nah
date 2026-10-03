//! Non-code masking: blank out string literals and comments before the
//! lexical entrypoint scan, so a `main` named inside either is not mistaken
//! for code.

/// Per-language lexical shape used to mask string literals and comments.
struct Syntax {
    /// Line-comment starters (`//` or `#`).
    line: &'static [&'static str],
    /// Whether `/* ... */` block comments apply.
    block: bool,
    /// Double-quoted, backslash-escapable strings.
    dquote: bool,
    /// Single-quoted, backslash-escapable strings (JS/Python).
    squote_string: bool,
    /// Single-quoted char/rune literals, bounded (Rust/Go/Java).
    squote_char: bool,
    /// Backtick raw strings/templates (Go/JS).
    backtick: bool,
    /// Rust raw strings `r#"..."#`.
    rust_raw: bool,
    /// Python triple-quoted strings.
    triple: bool,
}

fn syntax_for(ext: Option<&str>) -> Option<Syntax> {
    Some(match ext? {
        "rs" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: false,
            squote_char: true,
            backtick: false,
            rust_raw: true,
            triple: false,
        },
        "go" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: false,
            squote_char: true,
            backtick: true,
            rust_raw: false,
            triple: false,
        },
        "java" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: false,
            squote_char: true,
            backtick: false,
            rust_raw: false,
            triple: false,
        },
        "js" | "mjs" | "cjs" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: true,
            squote_char: false,
            backtick: true,
            rust_raw: false,
            triple: false,
        },
        "rb" => Syntax {
            line: &["#"],
            block: false,
            dquote: true,
            squote_string: true,
            squote_char: false,
            backtick: false,
            rust_raw: false,
            triple: false,
        },
        "py" => Syntax {
            line: &["#"],
            block: false,
            dquote: true,
            squote_string: true,
            squote_char: false,
            backtick: false,
            rust_raw: false,
            triple: true,
        },
        _ => return None,
    })
}

/// Replace string-literal and comment content with spaces (newlines preserved,
/// so line/column structure survives) for the source languages we scan. A file
/// whose extension has no syntax entry is returned unchanged. This is a
/// lightweight lexer, not a parser: enough to keep code-only text for the
/// substring/line checks that detect a program entry.
pub(super) fn mask_noncode(content: &str, ext: Option<&str>) -> String {
    let Some(syn) = syntax_for(ext) else {
        return content.to_string();
    };
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < chars.len() {
        if syn.line.iter().any(|lc| starts_with_str(&chars, i, lc)) {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if syn.block && starts_with_str(&chars, i, "/*") {
            out.push_str("  ");
            i += 2;
            while i < chars.len() && !starts_with_str(&chars, i, "*/") {
                out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            if i < chars.len() {
                out.push_str("  ");
                i += 2;
            }
            continue;
        }
        if syn.rust_raw
            && chars[i] == 'r'
            && let Some(next) = mask_rust_raw(&chars, i, &mut out)
        {
            i = next;
            continue;
        }
        if syn.triple
            && let Some(q) = triple_quote_at(&chars, i)
        {
            i = mask_triple(&chars, i, q, &mut out);
            continue;
        }
        if syn.backtick && chars[i] == '`' {
            i = mask_raw_until(&chars, i, '`', &mut out);
            continue;
        }
        if syn.dquote && chars[i] == '"' {
            i = mask_escapable(&chars, i, '"', &mut out);
            continue;
        }
        if syn.squote_string && chars[i] == '\'' {
            i = mask_escapable(&chars, i, '\'', &mut out);
            continue;
        }
        if syn.squote_char
            && chars[i] == '\''
            && let Some(len) = char_lit_len(&chars, i)
        {
            for _ in 0..len {
                out.push(' ');
            }
            i += len;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn starts_with_str(chars: &[char], i: usize, pat: &str) -> bool {
    pat.chars()
        .enumerate()
        .all(|(k, c)| chars.get(i + k) == Some(&c))
}

/// Mask a backslash-escapable string starting at the opening `quote`. Returns
/// the index just past the closing quote (or end of input).
fn mask_escapable(chars: &[char], i: usize, quote: char, out: &mut String) -> usize {
    out.push(' ');
    let mut j = i + 1;
    while j < chars.len() {
        let c = chars[j];
        if c == '\\' {
            out.push(' ');
            j += 1;
            if j < chars.len() {
                out.push(if chars[j] == '\n' { '\n' } else { ' ' });
                j += 1;
            }
            continue;
        }
        out.push(if c == '\n' { '\n' } else { ' ' });
        j += 1;
        if c == quote {
            break;
        }
    }
    j
}

/// Mask a raw (no-escape) string/template delimited by `quote` (a backtick).
fn mask_raw_until(chars: &[char], i: usize, quote: char, out: &mut String) -> usize {
    out.push(' ');
    let mut j = i + 1;
    while j < chars.len() {
        let c = chars[j];
        out.push(if c == '\n' { '\n' } else { ' ' });
        j += 1;
        if c == quote {
            break;
        }
    }
    j
}

fn triple_quote_at(chars: &[char], i: usize) -> Option<char> {
    ['"', '\''].into_iter().find(|&q| {
        chars.get(i) == Some(&q) && chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q)
    })
}

fn mask_triple(chars: &[char], i: usize, q: char, out: &mut String) -> usize {
    out.push_str("   ");
    let mut j = i + 3;
    while j < chars.len() {
        if chars[j] == '\\' {
            out.push(' ');
            j += 1;
            if j < chars.len() {
                out.push(if chars[j] == '\n' { '\n' } else { ' ' });
                j += 1;
            }
            continue;
        }
        if chars[j] == q && chars.get(j + 1) == Some(&q) && chars.get(j + 2) == Some(&q) {
            out.push_str("   ");
            return j + 3;
        }
        out.push(if chars[j] == '\n' { '\n' } else { ' ' });
        j += 1;
    }
    j
}

/// Mask a Rust raw string `r#*"..."#*` starting at `r`. Returns the index past
/// the close, or None if `r` does not begin a raw string (an ordinary
/// identifier such as `return`).
fn mask_rust_raw(chars: &[char], i: usize, out: &mut String) -> Option<usize> {
    let mut j = i + 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    if chars.get(j) != Some(&'"') {
        return None;
    }
    // Blank `r`, the hashes, and the opening quote.
    for _ in i..=j {
        out.push(' ');
    }
    j += 1;
    while j < chars.len() {
        if chars[j] == '"' {
            let mut k = j + 1;
            let mut h = 0;
            while h < hashes && chars.get(k) == Some(&'#') {
                h += 1;
                k += 1;
            }
            if h == hashes {
                for _ in j..k {
                    out.push(' ');
                }
                return Some(k);
            }
        }
        out.push(if chars[j] == '\n' { '\n' } else { ' ' });
        j += 1;
    }
    Some(j)
}

/// Length of a well-formed char/rune literal starting at `'`, or None. Bounded
/// so a Rust lifetime (`'a`) is left as code rather than swallowing the line.
fn char_lit_len(chars: &[char], i: usize) -> Option<usize> {
    if chars.get(i + 1) == Some(&'\\') {
        ((i + 2)..(i + 6).min(chars.len()))
            .find(|&j| chars[j] == '\'')
            .map(|j| j - i + 1)
    } else if chars.get(i + 2) == Some(&'\'')
        && chars.get(i + 1).is_some_and(|&c| c != '\'' && c != '\n')
    {
        Some(3)
    } else {
        None
    }
}
