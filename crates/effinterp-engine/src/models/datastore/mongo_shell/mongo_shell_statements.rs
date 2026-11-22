//! Mongo shell statement boundaries for the script recognizer.

/// A token in the Mongo shell recognizer's subset of JavaScript.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum MongoJsTok {
    Ident(String),
    /// A string literal; None when an escape leaves its value uncertain.
    Str(Option<String>),
    Num,
    Regex,
    Punct(char),
}

/// ECMAScript line terminators: each ends a line comment and can end a
/// statement.
pub(super) fn is_ecmascript_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// Tokens with a flag recording whether a line break preceded each one.
/// None when the text has an unterminated string or comment, or a template
/// literal with substitutions, whose extent the lexer cannot establish.
pub(super) fn lex_mongo_shell_script(source: &str) -> Option<Vec<(MongoJsTok, bool)>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens: Vec<(MongoJsTok, bool)> = Vec::new();
    let mut newline = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if is_ecmascript_line_terminator(c) {
            newline = true;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && !is_ecmascript_line_terminator(chars[i]) {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let end = (i + 2..chars.len().saturating_sub(1))
                .find(|&j| chars[j] == '*' && chars[j + 1] == '/')?;
            if chars[i..end]
                .iter()
                .any(|c| is_ecmascript_line_terminator(*c))
            {
                newline = true;
            }
            i = end + 2;
            continue;
        }
        let token = if c == '\'' || c == '"' || c == '`' {
            let mut value = String::new();
            let mut exact = true;
            i += 1;
            loop {
                let next = *chars.get(i)?;
                if next == c {
                    break;
                }
                if next == '\\' {
                    exact = false;
                    i += 1;
                } else if (c == '`' && next == '$' && chars.get(i + 1) == Some(&'{'))
                    || (c != '`' && is_ecmascript_line_terminator(next))
                {
                    return None;
                }
                value.push(*chars.get(i)?);
                i += 1;
            }
            i += 1;
            MongoJsTok::Str(exact.then_some(value))
        } else if c == '/' && regex_allowed(tokens.last().map(|(token, _)| token)) {
            let mut class = false;
            i += 1;
            loop {
                let next = *chars.get(i)?;
                if is_ecmascript_line_terminator(next) {
                    return None;
                }
                match next {
                    '\\' => i += 1,
                    '[' => class = true,
                    ']' => class = false,
                    '/' if !class => break,
                    _ => {}
                }
                i += 1;
            }
            i += 1;
            while chars.get(i).is_some_and(|c| c.is_ascii_alphabetic()) {
                i += 1;
            }
            MongoJsTok::Regex
        } else if c.is_ascii_digit() {
            while chars
                .get(i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
            {
                i += 1;
            }
            MongoJsTok::Num
        } else if c.is_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while chars
                .get(i)
                .is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            {
                i += 1;
            }
            MongoJsTok::Ident(chars[start..i].iter().collect())
        } else {
            i += 1;
            MongoJsTok::Punct(c)
        };
        tokens.push((token, newline));
        newline = false;
    }
    Some(tokens)
}

/// Whether a `/` after `previous` starts a regular expression literal
/// rather than a division.
fn regex_allowed(previous: Option<&MongoJsTok>) -> bool {
    match previous {
        None => true,
        Some(MongoJsTok::Punct(c)) => !matches!(c, ')' | ']' | '}'),
        Some(MongoJsTok::Ident(word)) => matches!(
            word.as_str(),
            "return"
                | "typeof"
                | "case"
                | "do"
                | "else"
                | "in"
                | "of"
                | "new"
                | "delete"
                | "void"
                | "throw"
                | "await"
                | "yield"
        ),
        Some(_) => false,
    }
}

/// Split tokens into top-level statements at `;` and at line breaks where
/// neither side continues an expression. None when brackets do not balance.
pub(super) fn split_mongo_shell_statements(
    tokens: Vec<(MongoJsTok, bool)>,
) -> Option<Vec<Vec<MongoJsTok>>> {
    let mut statements = Vec::new();
    let mut current: Vec<MongoJsTok> = Vec::new();
    let mut stack = Vec::new();
    for (token, newline) in tokens {
        if stack.is_empty() && newline && !current.is_empty() {
            let continues_before = matches!(
                current.last(),
                Some(MongoJsTok::Punct(
                    '.' | ','
                        | '('
                        | '['
                        | '{'
                        | '='
                        | '+'
                        | '-'
                        | '*'
                        | '/'
                        | '%'
                        | '&'
                        | '|'
                        | '?'
                        | ':'
                        | '<'
                        | '>'
                        | '!'
                        | '^'
                        | '~'
                ))
            );
            let continues_after = matches!(
                token,
                MongoJsTok::Punct(
                    '.' | ','
                        | ')'
                        | ']'
                        | '}'
                        | '('
                        | '['
                        | '?'
                        | ':'
                        | '='
                        | '+'
                        | '*'
                        | '/'
                        | '%'
                        | '&'
                        | '|'
                        | '<'
                        | '>'
                        | '^'
                )
            );
            if !continues_before && !continues_after {
                statements.push(std::mem::take(&mut current));
            }
        }
        match token {
            MongoJsTok::Punct(open @ ('(' | '[' | '{')) => stack.push(open),
            MongoJsTok::Punct(close @ (')' | ']' | '}')) => {
                let open = stack.pop()?;
                if !matches!((open, close), ('(', ')') | ('[', ']') | ('{', '}')) {
                    return None;
                }
            }
            MongoJsTok::Punct(';') if stack.is_empty() => {
                statements.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(token);
    }
    if !stack.is_empty() {
        return None;
    }
    statements.push(current);
    Some(
        statements
            .into_iter()
            .filter(|statement| !statement.is_empty())
            .collect(),
    )
}
