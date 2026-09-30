/// Filesystem glob syntax failures and deterministic matching budget exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlobError {
    InvalidPattern,
    Limit,
}

#[derive(Debug)]
enum Token {
    Literal(char),
    Star,
    Any,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
        classes: Vec<NamedClass>,
    },
}

/// A POSIX character class (`[:alpha:]`) inside a bracket expression. A
/// member outside ASCII is classified as a UTF-8 locale would, by its Unicode
/// properties.
#[derive(Debug, Clone, Copy)]
enum NamedClass {
    Alnum,
    Alpha,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Word,
    Xdigit,
}

impl NamedClass {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "alnum" => Self::Alnum,
            "alpha" => Self::Alpha,
            "blank" => Self::Blank,
            "cntrl" => Self::Cntrl,
            "digit" => Self::Digit,
            "graph" => Self::Graph,
            "lower" => Self::Lower,
            "print" => Self::Print,
            "punct" => Self::Punct,
            "space" => Self::Space,
            "upper" => Self::Upper,
            "word" => Self::Word,
            "xdigit" => Self::Xdigit,
            _ => return None,
        })
    }

    fn contains(self, c: char) -> bool {
        match self {
            Self::Alnum => c.is_alphanumeric(),
            Self::Alpha => c.is_alphabetic(),
            Self::Blank => matches!(c, ' ' | '\t'),
            Self::Cntrl => c.is_control(),
            Self::Digit => c.is_ascii_digit(),
            Self::Graph => !c.is_whitespace() && !c.is_control(),
            Self::Lower => c.is_lowercase(),
            Self::Print => !c.is_control(),
            Self::Punct => {
                c.is_ascii_punctuation()
                    || !c.is_ascii()
                        && !c.is_alphanumeric()
                        && !c.is_whitespace()
                        && !c.is_control()
            }
            Self::Space => c.is_whitespace(),
            Self::Upper => c.is_uppercase(),
            Self::Word => c.is_alphanumeric() || c == '_',
            Self::Xdigit => c.is_ascii_hexdigit(),
        }
    }
}

/// Whether a bracket expression's members include `c`, before negation.
fn class_contains(
    ranges: &[(char, char)],
    classes: &[NamedClass],
    c: char,
    work: &mut usize,
) -> Result<bool, GlobError> {
    let mut contained = false;
    for (start, end) in ranges {
        step(work)?;
        contained |= *start <= c && c <= *end;
    }
    for class in classes {
        step(work)?;
        contained |= class.contains(c);
    }
    Ok(contained)
}

/// The rest of a `[.c.]` collating symbol or `[=c=]` equivalence class after
/// its opening `[.` or `[=`: the one character it names. Each names only
/// itself, as in the C locale; a multi-character name is rejected.
fn bracket_symbol(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    delimiter: char,
) -> Result<char, GlobError> {
    let symbol = chars.next().ok_or(GlobError::InvalidPattern)?;
    if chars.next() != Some(delimiter) || chars.next() != Some(']') {
        return Err(GlobError::InvalidPattern);
    }
    Ok(symbol)
}

#[derive(Debug)]
enum Segment {
    Descendants,
    Tokens(Vec<Token>),
}

fn parse(pattern: &str, allow_parents: bool) -> Result<Vec<Segment>, GlobError> {
    parse_namespace(pattern, allow_parents, Some('/'), true)
}

fn parse_namespace(
    pattern: &str,
    allow_parents: bool,
    separator: Option<char>,
    recursive: bool,
) -> Result<Vec<Segment>, GlobError> {
    let mut segments = Vec::new();
    let mut fragments = pattern.split(|c| Some(c) == separator).peekable();
    while let Some(mut segment) = fragments.next() {
        // An escaped slash is still a literal filesystem separator.
        if fragments.peek().is_some()
            && segment
                .bytes()
                .rev()
                .take_while(|byte| *byte == b'\\')
                .count()
                % 2
                == 1
        {
            segment = &segment[..segment.len() - 1];
        }
        if segment == "**" {
            if !recursive {
                return Err(GlobError::InvalidPattern);
            }
            segments.push(Segment::Descendants);
            continue;
        }
        let mut chars = segment.chars().peekable();
        let mut tokens = Vec::new();
        while let Some(c) = chars.next() {
            tokens.push(match c {
                '\\' => Token::Literal(chars.next().ok_or(GlobError::InvalidPattern)?),
                '*' => {
                    if chars.peek() == Some(&'*') {
                        return Err(GlobError::InvalidPattern);
                    }
                    Token::Star
                }
                '?' => Token::Any,
                '[' => {
                    let negated = matches!(chars.peek(), Some('!' | '^'));
                    if negated {
                        chars.next();
                    }
                    let mut ranges = Vec::new();
                    let mut classes = Vec::new();
                    // A `]` first in the expression is one of its members.
                    let mut first = true;
                    loop {
                        let start = chars.next().ok_or(GlobError::InvalidPattern)?;
                        if start == ']' && !first {
                            break;
                        }
                        first = false;
                        let start = match (start, chars.peek()) {
                            ('[', Some(':')) => {
                                chars.next();
                                let mut name = String::new();
                                while !(name.ends_with(':') && chars.peek() == Some(&']')) {
                                    name.push(chars.next().ok_or(GlobError::InvalidPattern)?);
                                }
                                chars.next();
                                name.pop();
                                classes.push(
                                    NamedClass::parse(&name).ok_or(GlobError::InvalidPattern)?,
                                );
                                continue;
                            }
                            ('[', Some('=')) => {
                                chars.next();
                                let symbol = bracket_symbol(&mut chars, '=')?;
                                ranges.push((symbol, symbol));
                                continue;
                            }
                            ('[', Some('.')) => {
                                chars.next();
                                bracket_symbol(&mut chars, '.')?
                            }
                            ('\\', _) => chars.next().ok_or(GlobError::InvalidPattern)?,
                            (start, _) => start,
                        };
                        let end = if chars.peek() == Some(&'-') {
                            chars.next();
                            let end = chars.next().ok_or(GlobError::InvalidPattern)?;
                            match (end, chars.peek()) {
                                (']', _) => {
                                    ranges.push((start, start));
                                    ranges.push(('-', '-'));
                                    break;
                                }
                                ('[', Some('.')) => {
                                    chars.next();
                                    bracket_symbol(&mut chars, '.')?
                                }
                                ('\\', _) => chars.next().ok_or(GlobError::InvalidPattern)?,
                                (end, _) => end,
                            }
                        } else {
                            start
                        };
                        if start > end {
                            return Err(GlobError::InvalidPattern);
                        }
                        ranges.push((start, end));
                    }
                    Token::Class {
                        negated,
                        ranges,
                        classes,
                    }
                }
                ']' => return Err(GlobError::InvalidPattern),
                c => Token::Literal(c),
            });
        }
        if !allow_parents
            && matches!(
                tokens.as_slice(),
                [Token::Literal('.'), Token::Literal('.')]
            )
        {
            return Err(GlobError::InvalidPattern);
        }
        segments.push(Segment::Tokens(tokens));
    }
    Ok(segments)
}

/// Validate the filesystem glob grammar in linear time, independently of match budgets.
pub(crate) fn validate_glob(pattern: &str) -> Result<(), GlobError> {
    parse(pattern, false).map(|_| ())
}

/// Split a literal parent prefix from a valid glob tail, decoding prefix escapes.
/// Reject malformed syntax and parents after wildcards throughout the operand.
pub fn glob_parent_prefix(pattern: &str) -> Option<(String, &str)> {
    let segments = parse(pattern, true).ok()?;
    let mut prefix = Vec::new();
    let mut parent = false;
    let mut offset = 0;
    for (segment, raw) in segments.iter().zip(pattern.split_inclusive('/')) {
        let Segment::Tokens(tokens) = segment else {
            break;
        };
        let literal: Option<String> = tokens
            .iter()
            .map(|token| match token {
                Token::Literal(c) => Some(*c),
                _ => None,
            })
            .collect();
        let Some(literal) = literal else { break };
        parent |= literal == "..";
        prefix.push(literal);
        offset += raw.len();
    }
    let tail = &pattern[offset..];
    if !parent || tail.is_empty() || validate_glob(tail).is_err() {
        return None;
    }
    Some((format!("{}/", prefix.join("/")), tail))
}

// Collapse literal prefix parents, separators and current-directory segments. Keep
// wildcard tokens and escapes verbatim; never traverse a wildcard with a parent.
pub(crate) fn normalize_glob(pattern: &str) -> String {
    collapse_parents(pattern, false)
}

/// `pattern` normalized with each parent after a wildcard segment collapsed
/// too, or `None` when no parent follows a wildcard. The collapse is lexical:
/// `X/*/..` reads as `X`, which is right for a match that is a directory. A
/// match that is a symlink to a directory resolves `..` at its target's
/// parent, which the pattern cannot express, so a caller that uses this
/// reading must state that gap beside it. A parent after `**`, which may
/// select no directory, or after a segment that may name `.` or `..` itself
/// (`.*`) is never collapsed.
pub fn collapse_wildcard_parents(pattern: &str) -> Option<String> {
    let collapsed = collapse_parents(pattern, true);
    (collapsed != normalize_glob(pattern)).then_some(collapsed)
}

fn collapse_parents(pattern: &str, across_wildcards: bool) -> String {
    let Ok(segments) = parse(pattern, true) else {
        return pattern.to_string();
    };
    let mut wildcard = false;
    let mut starts: Vec<(usize, usize, bool)> = Vec::new();
    let mut result = String::new();
    let mut root_len = 0;
    let mut trailing_separator_len = 0;
    for (index, (fragment, parsed)) in pattern.split_inclusive('/').zip(segments).enumerate() {
        let (mut segment, mut separator) = fragment
            .strip_suffix('/')
            .map_or((fragment, ""), |segment| (segment, "/"));
        if !separator.is_empty()
            && segment
                .bytes()
                .rev()
                .take_while(|byte| *byte == b'\\')
                .count()
                % 2
                == 1
        {
            segment = &segment[..segment.len() - 1];
            separator = r"\/";
        }
        let parent = matches!(&parsed, Segment::Tokens(tokens)
            if matches!(tokens.as_slice(), [Token::Literal('.'), Token::Literal('.') ]));
        wildcard |= !matches!(&parsed, Segment::Tokens(tokens)
            if tokens.iter().all(|token| matches!(token, Token::Literal(_))));
        if parent {
            if wildcard && !across_wildcards {
                return pattern.to_string();
            }
            if let Some((start, separator_len, collapsible)) = starts.pop() {
                if !collapsible {
                    return pattern.to_string();
                }
                result.truncate(start);
                trailing_separator_len = separator_len;
            } else if root_len == 0 {
                return pattern.to_string();
            }
        } else if index == 0 && segment.is_empty() {
            result.push_str(separator);
            root_len = result.len();
        } else if !matches!(segment, "" | "." | r"\.") {
            let collapsible = match &parsed {
                Segment::Descendants => false,
                Segment::Tokens(tokens) => [".", ".."]
                    .iter()
                    .all(|name| segment_match(tokens, name, true, &mut 0) == Ok(false)),
            };
            starts.push((result.len(), trailing_separator_len, collapsible));
            result.push_str(segment);
            result.push_str(separator);
            trailing_separator_len = separator.len();
        }
    }
    if result.len() > root_len {
        result.truncate(result.len() - trailing_separator_len);
    }
    if result.is_empty() && !pattern.is_empty() {
        result.push('.');
    }
    result
}

fn step(work: &mut usize) -> Result<(), GlobError> {
    *work += 1;
    if *work > crate::RELATION_WORK_LIMIT {
        Err(GlobError::Limit)
    } else {
        Ok(())
    }
}

fn segment_match(
    tokens: &[Token],
    text: &str,
    hidden: bool,
    work: &mut usize,
) -> Result<bool, GlobError> {
    if tokens.is_empty() {
        return Ok(text.is_empty());
    }
    if hidden && text.starts_with('.') && !matches!(tokens.first(), Some(Token::Literal('.'))) {
        return Ok(false);
    }
    let chars: Vec<_> = text.chars().collect();
    let mut row = vec![false; chars.len() + 1];
    row[0] = true;
    for token in tokens {
        let mut next = vec![false; row.len()];
        step(work)?;
        next[0] = matches!(token, Token::Star) && row[0];
        for (i, c) in chars.iter().enumerate() {
            step(work)?;
            let wildcard_allowed = !hidden || i != 0 || *c != '.';
            next[i + 1] = match token {
                Token::Literal(expected) => row[i] && expected == c,
                Token::Star => row[i + 1] || wildcard_allowed && next[i],
                Token::Any => wildcard_allowed && row[i],
                Token::Class {
                    negated,
                    ranges,
                    classes,
                } => {
                    wildcard_allowed
                        && row[i]
                        && class_contains(ranges, classes, *c, work)? != *negated
                }
            };
        }
        row = next;
    }
    Ok(row[chars.len()])
}

/// Match a whole filesystem path. Ordinary wildcards stay inside segments and
/// exclude leading dots; whole-segment `**` includes hidden descendants.
/// One call permits 65,536 combined input bytes and 1,048,576 state transitions.
pub(crate) fn glob_match(pattern: &str, text: &str) -> Result<bool, GlobError> {
    if pattern.len().saturating_add(text.len()) > 65_536 {
        return Err(GlobError::Limit);
    }
    match_namespace(pattern, text, Some('/'), true, true, &mut 0)
}

pub(crate) fn glob_match_hidden(pattern: &str, text: &str) -> Result<bool, GlobError> {
    if pattern.len().saturating_add(text.len()) > 65_536 {
        return Err(GlobError::Limit);
    }
    match_namespace(pattern, text, Some('/'), false, true, &mut 0)
}

pub(crate) fn validate_namespace(
    pattern: &str,
    separator: Option<char>,
    recursive: bool,
) -> Result<(), GlobError> {
    parse_namespace(pattern, true, separator, recursive).map(|_| ())
}

pub(crate) fn match_namespace(
    pattern: &str,
    text: &str,
    separator: Option<char>,
    hidden: bool,
    recursive: bool,
    work: &mut usize,
) -> Result<bool, GlobError> {
    let segments = parse_namespace(pattern, false, separator, recursive)?;
    let text: Vec<_> = text.split(|c| Some(c) == separator).collect();
    let mut row = vec![false; text.len() + 1];
    row[0] = true;
    for segment in segments {
        let mut next = vec![false; row.len()];
        step(work)?;
        match segment {
            Segment::Descendants => {
                next[0] = row[0];
                for i in 0..text.len() {
                    step(work)?;
                    next[i + 1] = row[i + 1] || next[i];
                }
            }
            Segment::Tokens(tokens) => {
                for i in 0..text.len() {
                    step(work)?;
                    if row[i] {
                        next[i + 1] = segment_match(&tokens, text[i], hidden, work)?;
                    }
                }
            }
        }
        row = next;
    }
    Ok(row[text.len()])
}

pub(crate) fn glob_witness(pattern: &str, work: &mut usize) -> Result<Option<String>, GlobError> {
    let segments = parse(pattern, false)?;
    let mut result = Vec::new();
    for segment in segments {
        step(work)?;
        let Segment::Tokens(tokens) = segment else {
            continue;
        };
        let mut text = String::new();
        for token in tokens {
            step(work)?;
            match token {
                Token::Literal(c) => text.push(c),
                Token::Star => (),
                Token::Any => text.push('x'),
                Token::Class {
                    negated,
                    ranges,
                    classes,
                } => {
                    let mut selected = None;
                    for code in 33..=255 {
                        step(work)?;
                        let c = char::from_u32(code).unwrap();
                        if c == '/' || text.is_empty() && c == '.' {
                            continue;
                        }
                        if class_contains(&ranges, &classes, c, work)? != negated {
                            selected = Some(c);
                            break;
                        }
                    }
                    let Some(c) = selected else {
                        return Ok(None);
                    };
                    text.push(c);
                }
            }
        }
        result.push(text);
    }
    let candidate = result.join("/");
    Ok(Some(if candidate.is_empty() && pattern.starts_with('/') {
        "/".to_string()
    } else {
        candidate
    }))
}

pub(crate) fn validate_contextual_glob(pattern: &str) -> Result<(), GlobError> {
    let segments = parse(pattern, true)?;
    let mut wildcard = false;
    for segment in segments {
        match segment {
            Segment::Descendants => wildcard = true,
            Segment::Tokens(tokens) => {
                if wildcard
                    && matches!(
                        tokens.as_slice(),
                        [Token::Literal('.'), Token::Literal('.')]
                    )
                {
                    return Err(GlobError::InvalidPattern);
                }
                wildcard |= tokens
                    .iter()
                    .any(|token| !matches!(token, Token::Literal(_)));
            }
        }
    }
    Ok(())
}
