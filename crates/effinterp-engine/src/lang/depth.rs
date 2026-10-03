//! Conservative pre-parse nesting guards for the frontends whose third-party
//! or hand-written parsers recurse once per nesting level.
//!
//! oxc (JS/TS) and lib-ruby-parser build their ASTs by recursive descent, and
//! the PowerShell script-block reader recurses once per grouping parenthesis.
//! A source nested past the native stack overflows and aborts the whole hook,
//! which skips every guard — worse than any boundary. These scans bound an
//! upper estimate of parse-recursion depth from the raw bytes before the
//! parser runs. Above [`super::frontend::MAX_WALK_DEPTH`] the caller emits the
//! partial-analysis boundary the walkers already raise at that depth, so the
//! segment reads as partial coverage and the rest of the command is still
//! analyzed. The estimate only ever over-counts: unusually deep but legitimate
//! source may hit the boundary, but no crashing source slips through.

use super::frontend::MAX_WALK_DEPTH;

/// Whether JS/TS source nests deeper than the walk limit anywhere.
///
/// The scan tracks three quantities whose sum bounds the parser's stack depth
/// within one statement: unmatched brackets (`([{`), a run of chained infix
/// and prefix operators, and a run of nested control-flow keywords. Brackets
/// nest through a stack; operator and keyword runs accumulate along one
/// expression or statement spine and reset at the separators that end it, so a
/// flat list (`[1, 2, ...]`) or a sequence of short statements stays shallow
/// while a right-leaning chain (`a = b = ...`, `!!!...`, `if (a) if (b) ...`)
/// grows without bound.
pub(crate) fn js_nesting_exceeds(source: &str) -> bool {
    scan_nesting(source.as_bytes(), Syntax::JsTs)
}

/// Whether Ruby source nests deeper than the walk limit anywhere.
///
/// lib-ruby-parser descends recursively and even dropping its `Box<Node>`
/// recurses once per level, so a source nested past the native stack overflows
/// the hook. Its lexer cannot be driven standalone without the parser's own
/// setup, so this is the same conservative byte scan as JS, tuned for Ruby's
/// operators and block keywords. It never skips strings or comments — Ruby
/// interpolation (`#{...}`) is live code whose brackets must be counted — so it
/// over-counts brackets inside string and comment text, which only ever trips
/// the boundary early.
pub(crate) fn ruby_nesting_exceeds(source: &str) -> bool {
    scan_nesting(source.as_bytes(), Syntax::Ruby)
}

#[derive(Clone, Copy, PartialEq)]
enum Syntax {
    JsTs,
    Ruby,
}

fn scan_nesting(bytes: &[u8], syntax: Syntax) -> bool {
    let mut i = 0;
    let mut bracket: u32 = 0;
    let mut op_run: u32 = 0;
    let mut stmt_run: u32 = 0;
    let mut prev_ends_expr = false;
    let limit = MAX_WALK_DEPTH;

    macro_rules! bump_op {
        () => {{
            op_run += 1;
            if bracket + op_run + stmt_run > limit {
                return true;
            }
        }};
    }
    macro_rules! bump_stmt {
        () => {{
            stmt_run += 1;
            if bracket + op_run + stmt_run > limit {
                return true;
            }
        }};
    }

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'/' if syntax == Syntax::JsTs && bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if syntax == Syntax::JsTs && bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i += 2;
            }
            // JS string literals cannot span brackets that matter, so skipping
            // them avoids counting bracket characters in string data. Ruby
            // strings are not skipped: `#{...}` interpolation nests live code.
            b'\'' | b'"' if syntax == Syntax::JsTs => {
                let quote = c;
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
                prev_ends_expr = true;
            }
            b'(' | b'[' | b'{' => {
                bracket += 1;
                op_run = 0;
                if c == b'{' {
                    stmt_run = 0;
                }
                if bracket + stmt_run > limit {
                    return true;
                }
                prev_ends_expr = false;
                i += 1;
            }
            b')' | b']' | b'}' => {
                bracket = bracket.saturating_sub(1);
                op_run = 0;
                if c == b'}' {
                    stmt_run = 0;
                }
                prev_ends_expr = true;
                i += 1;
            }
            b';' => {
                op_run = 0;
                // In JS `;` terminates a statement; in Ruby it only separates
                // statements that may still sit inside an open `if`/`begin`
                // block closed by `end`, so it must not drop the block spine.
                if syntax == Syntax::JsTs {
                    stmt_run = 0;
                }
                prev_ends_expr = false;
                i += 1;
            }
            b',' => {
                op_run = 0;
                prev_ends_expr = false;
                i += 1;
            }
            b'\n' | b'\r' => {
                if prev_ends_expr {
                    op_run = 0;
                }
                i += 1;
            }
            b'!' | b'~' | b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'<' | b'>' | b'&' | b'|'
            | b'^' | b'?' | b':' | b'.' => {
                bump_op!();
                prev_ends_expr = false;
                i += 1;
            }
            _ if c.is_ascii_whitespace() => i += 1,
            _ if c == b'_' || c == b'$' || c == b'@' || c.is_ascii_alphabetic() || c >= 0x80 => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i] == b'_'
                        || bytes[i] == b'$'
                        || bytes[i] == b'@'
                        || bytes[i].is_ascii_alphanumeric()
                        || bytes[i] >= 0x80)
                {
                    i += 1;
                }
                let word = &bytes[start..i];
                let is_stmt_keyword = match syntax {
                    Syntax::JsTs => matches!(
                        word,
                        b"if"
                            | b"else"
                            | b"for"
                            | b"while"
                            | b"do"
                            | b"switch"
                            | b"try"
                            | b"catch"
                            | b"finally"
                            | b"with"
                            | b"case"
                    ),
                    Syntax::Ruby => matches!(
                        word,
                        b"if"
                            | b"unless"
                            | b"while"
                            | b"until"
                            | b"for"
                            | b"begin"
                            | b"case"
                            | b"do"
                            | b"elsif"
                            | b"when"
                            | b"and"
                            | b"or"
                            | b"not"
                    ),
                };
                let is_op_keyword = match syntax {
                    Syntax::JsTs => matches!(
                        word,
                        b"new"
                            | b"typeof"
                            | b"void"
                            | b"delete"
                            | b"await"
                            | b"yield"
                            | b"instanceof"
                            | b"in"
                            | b"of"
                    ),
                    Syntax::Ruby => false,
                };
                if is_stmt_keyword {
                    bump_stmt!();
                    prev_ends_expr = false;
                } else if is_op_keyword {
                    bump_op!();
                    prev_ends_expr = false;
                } else if syntax == Syntax::Ruby && word == b"end" {
                    // `end` closes a block, so a following construct starts a
                    // fresh spine rather than nesting under this one.
                    stmt_run = 0;
                    prev_ends_expr = true;
                } else {
                    prev_ends_expr = true;
                }
            }
            _ => {
                // A digit or any other expression byte ends a spine element.
                prev_ends_expr = true;
                i += 1;
            }
        }
    }
    false
}
