//! The Perl lexer: tokens, quoted strings and POD. Lexing stops at the first
//! construct whose extent it cannot establish.

use super::PerlFailure;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum PerlToken {
    Text(String),
    Name(String),
    Variable(String),
    Number(String),
    Punct(char),
    /// A backtick string: its interpolated text runs as shell source.
    Command(String),
    /// A string or variable whose value is runtime-selected, and why.
    Unknown(String),
    /// A punctuation variable such as `$/`.
    Special(char),
    /// A `qw` word list.
    Words(Vec<String>),
}

/// The refusal reason for a Perl special variable (`$/`, `$1`) or one the
/// run selects by name, which the frontend does not model.
pub(super) const SPECIAL_VARIABLE_UNMODELED: &str =
    "Perl special or runtime-selected variable is not modeled";

/// Words that declare code which runs at compile time, or subs and imports
/// that take effect for the whole unit, before any of its statements run.
const COMPILE_TIME: [&str; 12] = [
    "BEGIN",
    "CHECK",
    "INIT",
    "UNITCHECK",
    "END",
    "use",
    "no",
    "sub",
    "require",
    "package",
    "__DATA__",
    "__END__",
];

/// Whether `text` holds a word that could start compile-time code.
fn compile_time_word(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| COMPILE_TIME.contains(&word))
}

/// Lex `source`. Lexing stops at the first construct whose extent it cannot
/// establish, such as a pattern, heredoc, quote-like operator or unterminated
/// string: the tokens then keep only the statements completed before it, and
/// the reason stands for the rest. A construct that can change the meaning of
/// the whole program at compile time refuses it outright, and so does any word
/// in the unlexed rest that could start one.
pub(super) fn tokenize(
    source: &str,
    max_bytes: usize,
    env: &mut impl FnMut(&str) -> Option<String>,
) -> Result<(Vec<PerlToken>, Option<String>), PerlFailure> {
    if source.starts_with("#!") {
        return Err("Perl shebang switches can change inline execution semantics".into());
    }
    let mut tokens = Vec::new();
    let mut rest = source;
    let mut string_bytes = 0;
    let mut unlexed;
    let stop = loop {
        unlexed = rest;
        let Some(c) = rest.chars().next() else {
            break None;
        };
        if c.is_whitespace() {
            rest = &rest[c.len_utf8()..];
        } else if c == '#' {
            rest = rest.find('\n').map_or("", |end| &rest[end..]);
        } else if c == '='
            && (rest.len() == source.len()
                || source.as_bytes()[source.len() - rest.len() - 1] == b'\n')
        {
            match pod_tail(rest) {
                Ok(tail) => rest = tail,
                Err(detail) => break Some(detail),
            }
        } else if matches!(c, '`' | '\'' | '"') {
            rest = &rest[1..];
            match quoted(&mut rest, c, max_bytes - string_bytes, env) {
                Ok(Ok(text)) => {
                    string_bytes += text.len();
                    tokens.push(if c == '`' {
                        PerlToken::Command(text)
                    } else {
                        PerlToken::Text(text)
                    });
                }
                Ok(Err(detail)) => {
                    // Interpolation can hold code, compiled with the program.
                    if c != '\'' && compile_time_word(&unlexed[..unlexed.len() - rest.len()]) {
                        return Err(
                            "Perl interpolated code may declare compile-time code or subs".into(),
                        );
                    }
                    tokens.push(PerlToken::Unknown(detail));
                }
                Err(PerlFailure::Refused(detail)) => break Some(detail),
                Err(failure) => return Err(failure),
            }
        } else if c == '$' {
            rest = &rest[1..];
            if let Some(key) = rest.strip_prefix("ENV{") {
                // `$ENV{NAME}` with a bare or plainly quoted key reads the
                // environment like its interpolated form.
                let Some(end) = key.find('}') else {
                    break Some("Perl environment subscript is unterminated".into());
                };
                let name = match &key.as_bytes()[..end] {
                    [b'"' | b'\'', .., b'"' | b'\'']
                        if key.as_bytes()[0] == key.as_bytes()[end - 1] =>
                    {
                        &key[1..end - 1]
                    }
                    _ => &key[..end],
                };
                rest = &key[end + 1..];
                if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                {
                    tokens.push(PerlToken::Unknown(
                        "Perl environment key is not a literal name".into(),
                    ));
                    continue;
                }
                let Some(value) = env(name) else {
                    tokens.push(PerlToken::Unknown(format!(
                        "Perl environment value {name:?} is not supplied"
                    )));
                    continue;
                };
                if value.len() > max_bytes - string_bytes {
                    return Err(PerlFailure::SourceBytes);
                }
                string_bytes += value.len();
                tokens.push(PerlToken::Text(value));
                continue;
            }
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            if end == 0 || rest.as_bytes()[0].is_ascii_digit() {
                // Skip a special variable's name, so `$'`, `$"` or `$#` does
                // not open a string or comment.
                let skip = match rest.chars().next() {
                    Some(c) if c.is_ascii_digit() => end,
                    Some(c)
                        if c.is_ascii_punctuation()
                            && !matches!(c, '{' | '$' | ';' | '(' | ')' | ',') =>
                    {
                        1
                    }
                    _ => 0,
                };
                tokens.push(match rest.chars().next() {
                    Some(c) if skip == 1 => PerlToken::Special(c),
                    _ => PerlToken::Unknown(SPECIAL_VARIABLE_UNMODELED.into()),
                });
                rest = &rest[skip..];
                continue;
            }
            tokens.push(PerlToken::Variable(rest[..end].into()));
            rest = &rest[end..];
        } else if c.is_ascii_alphabetic() || c == '_' {
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != ':')
                .unwrap_or(rest.len());
            let name = &rest[..end];
            // `require "FILE"` loads a file when the statement runs; a
            // bareword module can change what the program means.
            let loads_file = name == "require" && rest[end..].trim_start().starts_with(['"', '\'']);
            if !loads_file
                && matches!(
                    name,
                    "BEGIN"
                        | "CHECK"
                        | "INIT"
                        | "UNITCHECK"
                        | "END"
                        | "require"
                        | "package"
                        | "__DATA__"
                        | "__END__"
                )
            {
                return Err(format!(
                    "Perl {name} construct is outside the bounded literal grammar"
                )
                .into());
            }
            rest = &rest[end..];
            // A quote-like operator's delimiters can enclose any text.
            if matches!(
                name,
                "q" | "qq" | "qw" | "qx" | "qr" | "m" | "s" | "tr" | "y"
            ) {
                let next = rest.trim_start();
                let delimited = match next.chars().next() {
                    None => false,
                    Some('=') => !next[1..].starts_with('>'),
                    Some(c) => !(c.is_alphanumeric() || matches!(c, '_' | ',' | ';' | ')' | '}')),
                };
                // A word list is data: one token, never statements. So is a
                // `q` or `qq` string in bracketing delimiters.
                if delimited
                    && (name == "qw"
                        || matches!(name, "q" | "qq") && next.starts_with(['(', '{', '[', '<']))
                {
                    let open = next.chars().next().unwrap();
                    let close = match open {
                        '(' => ')',
                        '[' => ']',
                        '{' => '}',
                        '<' => '>',
                        other => other,
                    };
                    let body = &next[open.len_utf8()..];
                    let mut depth = 0u32;
                    let mut escaped = false;
                    let end = body.char_indices().find(|&(_, c)| {
                        // A backslash escapes a delimiter or another backslash.
                        if std::mem::take(&mut escaped) {
                            return false;
                        }
                        if c == '\\' {
                            escaped = true;
                            return false;
                        }
                        if c == close && depth == 0 {
                            return true;
                        }
                        if c == close {
                            depth -= 1;
                        } else if c == open && open != close {
                            depth += 1;
                        }
                        false
                    });
                    let Some((end, _)) = end else {
                        break Some(if name == "qw" {
                            "Perl qw word list is unterminated".into()
                        } else {
                            format!("Perl {name} string is unterminated")
                        });
                    };
                    let text = &body[..end];
                    if name == "qw" {
                        tokens.push(PerlToken::Words(
                            text.split_whitespace().map(str::to_string).collect(),
                        ));
                    // The text is literal when nothing in it is an escape
                    // and, under `qq`, nothing interpolates; otherwise it is
                    // a string of unknown value, as an interpolated `"..."`.
                    } else if text.contains('\\') || name == "qq" && text.contains(['$', '@']) {
                        if name == "qq" && compile_time_word(text) {
                            return Err(
                                "Perl interpolated code may declare compile-time code or subs"
                                    .into(),
                            );
                        }
                        tokens.push(PerlToken::Unknown(format!(
                            "Perl {name} string is not literal text"
                        )));
                    } else {
                        if text.len() > max_bytes - string_bytes {
                            return Err(PerlFailure::SourceBytes);
                        }
                        string_bytes += text.len();
                        tokens.push(PerlToken::Text(text.into()));
                    }
                    rest = &body[end + close.len_utf8()..];
                    continue;
                }
                if delimited {
                    break Some(format!(
                        "Perl {name} quote-like operator is outside the bounded literal grammar"
                    ));
                }
            }
            tokens.push(PerlToken::Name(name.into()));
        } else if c.is_ascii_digit() {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            tokens.push(PerlToken::Number(rest[..end].into()));
            rest = &rest[end..];
        } else if rest.starts_with("//") {
            // Only defined-or; a lone slash may start a pattern.
            tokens.extend([PerlToken::Punct('/'), PerlToken::Punct('/')]);
            rest = &rest[2..];
        } else if matches!(
            c,
            '(' | ')'
                | ','
                | ';'
                | '='
                | '|'
                | '{'
                | '}'
                | '.'
                | '-'
                | '+'
                | '*'
                | '!'
                | '>'
                | '&'
                | '%'
                | '@'
                | '['
                | ']'
                | '\\'
                | '?'
                | ':'
                | '~'
                | '^'
        ) || (c == '<' && !rest.starts_with("<<"))
        {
            tokens.push(PerlToken::Punct(c));
            rest = &rest[1..];
        } else {
            break Some(format!(
                "Perl token {c:?} is outside the bounded literal grammar"
            ));
        }
    };
    if stop.is_some() {
        if compile_time_word(unlexed) {
            return Err("Perl source Nah cannot lex may declare compile-time code or subs".into());
        }
        let mut depth = 0i64;
        let mut complete = 0;
        for (index, token) in tokens.iter().enumerate() {
            match token {
                PerlToken::Punct('{') => depth += 1,
                PerlToken::Punct('}') => depth -= 1,
                PerlToken::Punct(';') if depth == 0 => complete = index + 1,
                _ => {}
            }
        }
        tokens.truncate(complete);
    }
    Ok((tokens, stop))
}

fn pod_tail(source: &str) -> Result<&str, String> {
    let first_end = source.find('\n').map_or(source.len(), |index| index + 1);
    let first = source[..first_end].trim_end_matches(['\r', '\n']);
    let directive = first
        .strip_prefix('=')
        .and_then(|line| line.split_whitespace().next())
        .filter(|directive| {
            !directive.is_empty() && directive.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
        .ok_or("Perl line-leading equals syntax is outside the bounded literal grammar")?;
    if directive == "cut" {
        return Err("Perl POD terminator has no opening directive".into());
    }
    let mut consumed = first_end;
    while consumed < source.len() {
        let line_len = source[consumed..]
            .find('\n')
            .map_or(source.len() - consumed, |index| index + 1);
        let line = source[consumed..consumed + line_len].trim_end_matches(['\r', '\n']);
        consumed += line_len;
        if line
            .strip_prefix("=cut")
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))
        {
            return Ok(&source[consumed..]);
        }
    }
    Err("Perl POD section is unterminated".into())
}

/// The string up to the closing `quote`, or why its value is runtime-selected.
/// Only an unterminated string or the byte limit fails.
fn quoted(
    rest: &mut &str,
    quote: char,
    max_bytes: usize,
    env: &mut impl FnMut(&str) -> Option<String>,
) -> Result<Result<String, String>, PerlFailure> {
    // Without `use utf8`, Perl source strings and hex escapes are bytes.
    // Upgrade-to-Unicode operations remain outside this grammar.
    let mut value = Vec::new();
    let mut unknown = None;
    while let Some(c) = rest.chars().next() {
        *rest = &rest[c.len_utf8()..];
        if value.len() > max_bytes {
            return Err(PerlFailure::SourceBytes);
        }
        if c == quote {
            return Ok(match unknown {
                Some(detail) => Err(detail),
                None => String::from_utf8(value)
                    .map_err(|_| "Perl path contains non-UTF-8 bytes".to_string()),
            });
        }
        if c == '\\' {
            let escape = rest
                .chars()
                .next()
                .ok_or("Perl string escape is unterminated")?;
            *rest = &rest[escape.len_utf8()..];
            if quote == '\'' {
                if !matches!(escape, '\\' | '\'') {
                    value.push(b'\\');
                }
                value.extend_from_slice(escape.encode_utf8(&mut [0; 4]).as_bytes());
                continue;
            }
            let byte = match escape {
                '\\' | '"' | '`' | '$' | '@' => Ok(escape as u8),
                'n' => Ok(b'\n'),
                'r' => Ok(b'\r'),
                't' => Ok(b'\t'),
                'f' => Ok(12),
                'b' => Ok(8),
                'a' => Ok(7),
                'e' => Ok(27),
                'x' => {
                    let digits = if rest.starts_with('{') {
                        rest.find('}').map(|end| {
                            let digits = &rest[1..end];
                            *rest = &rest[end + 1..];
                            digits
                        })
                    } else {
                        let end = rest
                            .bytes()
                            .take(2)
                            .take_while(u8::is_ascii_hexdigit)
                            .count();
                        let digits = &rest[..end];
                        *rest = &rest[end..];
                        Some(digits)
                    };
                    digits
                        .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                        .ok_or_else(|| {
                            "Perl hex escape requires unmodeled Unicode upgrade semantics".into()
                        })
                }
                _ => Err(format!("Perl string escape \\{escape} is not modeled")),
            };
            match byte {
                Ok(byte) => value.push(byte),
                Err(detail) => {
                    unknown.get_or_insert(detail);
                }
            }
        } else if quote != '\'' && c == '$' {
            let Some(end) = rest.strip_prefix("ENV{").and_then(|_| rest.find('}')) else {
                unknown.get_or_insert_with(|| {
                    "Perl interpolated variable has no proven environment value".into()
                });
                continue;
            };
            let name = &rest[4..end];
            *rest = &rest[end + 1..];
            if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                unknown.get_or_insert_with(|| "Perl environment key is not a literal name".into());
                continue;
            }
            let Some(expansion) = env(name) else {
                unknown.get_or_insert_with(|| {
                    format!("Perl environment value {name:?} is not supplied")
                });
                continue;
            };
            if expansion.len() > max_bytes.saturating_sub(value.len()) {
                return Err(PerlFailure::SourceBytes);
            }
            value.extend_from_slice(expansion.as_bytes());
        } else if quote != '\'' && c == '@' {
            unknown.get_or_insert_with(|| "Perl array interpolation is runtime-selected".into());
        } else {
            value.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
    Err("Perl quoted string is unterminated".into())
}
