//! The PowerShell lexer: a script's statements, each statement's words and
//! redirections, and the variable a `$` names.

/// The commands of the source: its statements and each element of their
/// pipelines, with comments removed and line continuations joined.
/// Each command is returned with whether it pipes into the next one.
pub(super) fn statements(source: &str) -> Result<Vec<(String, bool)>, &'static str> {
    if source.contains(['\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}']) {
        return Err("PowerShell smart-quote delimiters are not modeled");
    }
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    // A `#` opens a comment only where a token can start.
    let mut token_start = true;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(open) = quote {
            current.push(character);
            if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                current.push(character);
                token_start = false;
            }
            '`' => {
                if characters
                    .next_if(|next| matches!(next, '\n' | '\r'))
                    .is_some()
                {
                    while characters
                        .next_if(|next| matches!(next, '\n' | '\r'))
                        .is_some()
                    {}
                } else {
                    // An escaped character is literal, so an escaped `;` or
                    // `|` stays inside its statement.
                    current.push('`');
                    current.extend(characters.next());
                    token_start = false;
                }
            }
            '#' if token_start => {
                while characters
                    .next_if(|next| !matches!(next, '\n' | '\r'))
                    .is_some()
                {}
            }
            // `<# … #>` comments out everything between its delimiters, across
            // as many lines as it spans, and does not nest.
            '<' if token_start && characters.peek() == Some(&'#') => {
                characters.next();
                let mut previous = None;
                let mut closed = false;
                for character in characters.by_ref() {
                    if previous == Some('#') && character == '>' {
                        closed = true;
                        break;
                    }
                    previous = Some(character);
                }
                if !closed {
                    return Err("PowerShell block comment is unterminated");
                }
            }
            // `||` chains pipelines conditionally, which is not modeled; the
            // word grammar refuses it.
            '|' if characters.peek() == Some(&'|') => {
                current.push('|');
                current.extend(characters.next());
                token_start = false;
            }
            // Each element of a pipeline is a command of its own; what one
            // passes to the next adds input, not a different command.
            ';' | '|' | '\n' | '\r' => {
                statements.push((std::mem::take(&mut current), character == '|'));
                token_start = true;
            }
            character if character.is_whitespace() => {
                current.push(character);
                token_start = true;
            }
            character => {
                current.push(character);
                token_start = false;
            }
        }
    }
    if quote.is_some() {
        return Err("PowerShell quoted argument is unterminated");
    }
    statements.push((current, false));
    statements.retain(|(statement, _)| !statement.trim().is_empty());
    Ok(statements)
}

pub(super) struct PsWord {
    pub(super) text: String,
    pub(super) quoted: bool,
    /// Whether the word starts with a quoted segment. `-Name:'value'` quotes
    /// only its value, so it still names a parameter.
    pub(super) leading_quote: bool,
    pub(super) expandable: bool,
    /// The elements of a comma collection; empty for a single value.
    pub(super) elements: Vec<String>,
}

impl PsWord {
    /// The values the word binds to a parameter.
    pub(super) fn values(&self) -> Vec<String> {
        if self.elements.is_empty() {
            vec![self.text.clone()]
        } else {
            self.elements.clone()
        }
    }
}

/// One statement's command words and the files its redirections write.
#[derive(Default)]
pub(super) struct PsStatement {
    pub(super) words: Vec<PsWord>,
    pub(super) redirections: Vec<PsRedirection>,
}

pub(super) struct PsRedirection {
    /// `>>` adds to the file; `>` replaces it.
    pub(super) append: bool,
    /// The file the stream writes, or `None` where the operator merges the
    /// stream into another one instead (`2>&1`).
    pub(super) target: Option<PsWord>,
}

/// Split one statement into its words and redirections, refusing any expansion
/// or expression operator whose value the literal grammar cannot recover.
pub(super) fn words(statement: &str) -> Result<PsStatement, &'static str> {
    let mut parsed = PsStatement::default();
    let mut rest = statement.trim();
    while !rest.is_empty() {
        if let Some((redirection, remainder)) = redirection(rest)? {
            parsed.redirections.push(redirection);
            rest = remainder.trim_start();
            continue;
        }
        let (word, remainder) = word(rest)?;
        parsed.words.push(word);
        rest = remainder.trim_start();
    }
    Ok(parsed)
}

/// A redirection operator: a stream selector (`1`-`6`, or `*` for every
/// stream) that only counts where a token starts, `>` or `>>`, and then either
/// `&1`/`&2` — which names no file — or the file the stream writes. The
/// operator also ends the word it runs into, so `Write-Output x>file`
/// redirects rather than naming a word `x>file`.
fn redirection(rest: &str) -> Result<Option<(PsRedirection, &str)>, &'static str> {
    let stream_selected = matches!(rest.as_bytes().first(), Some(b'*' | b'1'..=b'6'));
    let Some(after) = rest[usize::from(stream_selected)..].strip_prefix('>') else {
        return Ok(None);
    };
    let (append, after) = match after.strip_prefix('>') {
        Some(after) => (true, after),
        None => (false, after),
    };
    if let Some(merged) = after.strip_prefix('&') {
        // Only `>&1` and `>&2` merge streams; `>>&` is not an operator.
        let Some(stream) = merged.strip_prefix(['1', '2']).filter(|_| !append) else {
            return Err("PowerShell redirection merges an unrecognized stream");
        };
        return Ok(Some((
            PsRedirection {
                append,
                target: None,
            },
            stream,
        )));
    }
    let after = after.trim_start();
    if after.is_empty() {
        return Err("PowerShell redirection names no file");
    }
    let (target, after) = word(after)?;
    if !target.elements.is_empty() {
        return Err("PowerShell redirection names a collection");
    }
    Ok(Some((
        PsRedirection {
            append,
            target: Some(target),
        },
        after,
    )))
}

/// One word. Segments that touch concatenate into one argument
/// (about_parsing), so `"C:\Users\test"$rest` is a single word; the word ends
/// at whitespace or at the redirection operator that follows it. Elements
/// joined by commas form one collection argument.
pub(super) fn word(rest: &str) -> Result<(PsWord, &str), &'static str> {
    let mut text = String::new();
    let mut elements = Vec::new();
    let mut quoted = false;
    let mut expandable = false;
    // A single-quoted segment keeps its `$` literal, so a word that also has
    // an expandable segment cannot be expanded as one string.
    let mut literal_dollar = false;
    let leading_quote = rest.starts_with(['\'', '"']);
    let mut rest = rest;
    let mut first = true;
    loop {
        match rest.chars().next() {
            Some(quote @ ('\'' | '"')) => {
                let body = &rest[1..];
                let Some(end) = body.find(quote) else {
                    return Err("PowerShell quoted argument is unterminated");
                };
                let segment = &body[..end];
                if quote == '"' && segment.contains('`') {
                    return Err("PowerShell expandable string contains an escape");
                }
                rest = &body[end + 1..];
                if rest.starts_with(quote) {
                    // A doubled delimiter escapes the quote character itself.
                    return Err("PowerShell quoted argument escapes its delimiter");
                }
                text.push_str(segment);
                quoted = true;
                if segment.contains('$') {
                    if quote == '"' {
                        expandable = true;
                    } else {
                        literal_dollar = true;
                    }
                }
            }
            Some(',') if !first => {
                elements.push(std::mem::take(&mut text));
                rest = rest[1..].trim_start();
                if rest.is_empty() {
                    return Err("PowerShell collection has no element after its comma");
                }
                continue;
            }
            _ => {
                let end = rest
                    .find(|character: char| {
                        character.is_whitespace() || matches!(character, '>' | '\'' | '"' | ',')
                    })
                    .unwrap_or(rest.len());
                let segment = &rest[..end];
                if segment.is_empty() {
                    return Err(
                        "PowerShell argument contains an expansion, comment, or expression operator",
                    );
                }
                let mut scan = segment;
                while let Some(index) =
                    scan.find(['$', '`', '|', '&', '(', ')', '{', '}', '@', '<'])
                {
                    let after = &scan[index + 1..];
                    let Some((_, length)) =
                        variable(after).filter(|_| scan[index..].starts_with('$'))
                    else {
                        return Err(
                            "PowerShell argument contains an expansion, comment, or expression operator",
                        );
                    };
                    scan = &after[length..];
                }
                text.push_str(segment);
                expandable |= segment.contains('$');
                rest = &rest[end..];
            }
        }
        first = false;
        if rest.is_empty() || rest.starts_with(char::is_whitespace) || rest.starts_with('>') {
            break;
        }
    }
    if literal_dollar && expandable {
        return Err("PowerShell argument concatenates a literal and an expandable dollar");
    }
    if !elements.is_empty() {
        if expandable {
            return Err("PowerShell collection element contains an expansion");
        }
        elements.push(std::mem::take(&mut text));
        text = elements.join(",");
    }
    Ok((
        PsWord {
            text,
            quoted,
            leading_quote,
            expandable,
            elements,
        },
        rest,
    ))
}

pub(super) enum Variable<'a> {
    Home,
    Environment(&'a str),
    /// `$true` or `$false`.
    Boolean,
    /// A variable the script itself assigns. Its value is known only where
    /// the session recorded the assignment.
    Session,
}

/// The variable named after a `$`, and how many bytes name it: `HOME`, an
/// environment variable `env:NAME`, `true` or `false`, or a session variable,
/// each optionally in braces. Any other drive-qualified name is not read.
pub(super) fn variable(text: &str) -> Option<(Variable<'_>, usize)> {
    let identifier = |text: &str| {
        text.find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(text.len())
    };
    let (name, length) = match text.strip_prefix('{') {
        Some(braced) => {
            let end = braced.find('}')?;
            (&braced[..end], end + 2)
        }
        None => {
            let mut end = identifier(text);
            if text[..end].eq_ignore_ascii_case("env") && text[end..].starts_with(':') {
                end += 1 + identifier(&text[end + 1..]);
            }
            (&text[..end], end)
        }
    };
    let found = match name.split_once(':') {
        Some((drive, name))
            if drive.eq_ignore_ascii_case("env")
                && !name.is_empty()
                && identifier(name) == name.len() =>
        {
            Variable::Environment(name)
        }
        Some(_) => return None,
        None if name.eq_ignore_ascii_case("HOME") => Variable::Home,
        None if name.eq_ignore_ascii_case("true") || name.eq_ignore_ascii_case("false") => {
            Variable::Boolean
        }
        None if !name.is_empty() && identifier(name) == name.len() => Variable::Session,
        None => return None,
    };
    Some((found, length))
}
