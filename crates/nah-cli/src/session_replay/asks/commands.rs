//! The simple commands of shell text, for reading an `rm` alias from a
//! profile and the head word of a call: words after quote removal, split at
//! the operators and newlines that end a command, with each command placed
//! inside or outside every block and subshell. Comments and here-document
//! bodies are no commands, and a keyword counts only where a command
//! starts, so `echo 'fi'` closes nothing. Command substitutions are skipped
//! whole: they run in a subshell. Text that does not lex, such as an
//! unterminated quote or here-document, has no commands.

/// One word, after quote removal.
pub(super) struct Word {
    /// The word with its quotes and escapes removed.
    pub(super) text: String,
    /// The word as written.
    pub(super) raw: String,
    /// Nothing in it is quoted or escaped.
    pub(super) plain: bool,
    /// It holds an expansion or a substitution.
    pub(super) computed: bool,
}

/// One simple command.
pub(super) struct Command {
    pub(super) words: Vec<Word>,
    /// It starts outside every block, subshell and function body.
    pub(super) top_level: bool,
    /// It runs in the shell that reads it, whatever came before: no `&&` or
    /// `||` precedes it, and it is in no pipeline or background job.
    pub(super) unconditional: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Op {
    /// `;` or a newline.
    End,
    /// `;;`, which ends a `case` arm.
    EndArm,
    Background,
    AndOr,
    Pipe,
    Open,
    Close,
    /// A redirection, whose next word is its target.
    Redirect,
    /// `<<` or `<<-` (`true`), whose next word is its delimiter.
    HereDoc(bool),
}

enum Token {
    Word(Word),
    Op(Op),
}

/// The simple commands of `text`, or `None` where it does not lex.
pub(super) fn commands(text: &str) -> Option<Vec<Command>> {
    let mut commands = Vec::new();
    // The blocks open around the next command; `lost` once one closes that
    // was never opened, after which no command is known to be top level.
    let mut blocks: Vec<&'static str> = Vec::new();
    let mut lost = false;
    let mut words: Vec<Word> = Vec::new();
    let mut top_level = true;
    let mut follows = false;
    // The words of a `for` or `case` header, which are no command.
    let mut header: Option<&'static str> = None;
    let mut in_pattern = false;
    let mut skip_word = false;
    let mut function_parens = false;
    let mut finish = |words: &mut Vec<Word>, follows: &mut bool, top_level: bool, op: Op| {
        if !words.is_empty() {
            commands.push(Command {
                words: std::mem::take(words),
                top_level,
                unconditional: !*follows && !matches!(op, Op::Pipe | Op::Background),
            });
        }
        *follows = matches!(op, Op::AndOr | Op::Pipe);
    };
    let close = |blocks: &mut Vec<&'static str>, lost: &mut bool, opened: &[&str]| {
        if blocks.last().is_some_and(|block| opened.contains(block)) {
            blocks.pop();
        } else {
            blocks.clear();
            *lost = true;
        }
    };
    for token in lex(text)? {
        match token {
            Token::Word(word) => {
                if std::mem::take(&mut skip_word) {
                    continue;
                }
                let keyword = (words.is_empty() && word.plain).then_some(word.text.as_str());
                if in_pattern {
                    if keyword == Some("esac") {
                        in_pattern = false;
                        close(&mut blocks, &mut lost, &["case"]);
                    }
                    continue;
                }
                if let Some(kind) = header {
                    if kind == "case" && word.plain && word.text == "in" {
                        header = None;
                        in_pattern = true;
                    }
                    continue;
                }
                match keyword {
                    Some("if") => blocks.push("if"),
                    Some("while") => blocks.push("while"),
                    Some("until") => blocks.push("until"),
                    Some("{") => blocks.push("{"),
                    Some("for" | "select") => {
                        blocks.push("for");
                        header = Some("for");
                    }
                    Some("case") => {
                        blocks.push("case");
                        header = Some("case");
                    }
                    Some("fi") => close(&mut blocks, &mut lost, &["if"]),
                    Some("done") => close(&mut blocks, &mut lost, &["while", "until", "for"]),
                    Some("}") => close(&mut blocks, &mut lost, &["{"]),
                    Some("then" | "do" | "else" | "elif" | "!" | "time") => {}
                    Some("function") => skip_word = true,
                    _ => {
                        if words.is_empty() {
                            top_level = blocks.is_empty() && !lost;
                        }
                        words.push(word);
                    }
                }
            }
            Token::Op(op) => match op {
                Op::Redirect | Op::HereDoc(_) => skip_word = true,
                Op::End | Op::EndArm | Op::Background | Op::AndOr | Op::Pipe => {
                    finish(&mut words, &mut follows, top_level, op);
                    if header == Some("for") {
                        header = None;
                    }
                    if op == Op::EndArm {
                        in_pattern = true;
                    }
                }
                Op::Open if in_pattern => {}
                // `name ()` defines a function, whose body is a block.
                Op::Open if words.len() == 1 => {
                    words.clear();
                    function_parens = true;
                }
                Op::Open => blocks.push("("),
                Op::Close if std::mem::take(&mut function_parens) => {}
                Op::Close if in_pattern => in_pattern = false,
                Op::Close => {
                    finish(&mut words, &mut follows, top_level, Op::End);
                    close(&mut blocks, &mut lost, &["("]);
                }
            },
        }
    }
    finish(&mut words, &mut follows, top_level, Op::End);
    Some(commands)
}

/// The tokens of `text`, or `None` where a quote, substitution or
/// here-document does not end.
fn lex(text: &str) -> Option<Vec<Token>> {
    let chars: Vec<char> = text.chars().collect();
    let at = |index: usize| chars.get(index).copied();
    let mut tokens = Vec::new();
    // Here-documents whose bodies start after the next newline, each with
    // its delimiter and whether leading tabs are stripped.
    let mut bodies: Vec<(String, bool)> = Vec::new();
    let mut delimiter: Option<bool> = None;
    let mut index = 0;
    while let Some(character) = at(index) {
        let op = match character {
            ' ' | '\t' => {
                index += 1;
                continue;
            }
            '#' => {
                while at(index).is_some_and(|character| character != '\n') {
                    index += 1;
                }
                continue;
            }
            '\n' => {
                index += 1;
                tokens.push(Token::Op(Op::End));
                for (end, strip) in bodies.drain(..) {
                    loop {
                        let start = index;
                        while at(index).is_some_and(|character| character != '\n') {
                            index += 1;
                        }
                        let line: String = chars.get(start..index)?.iter().collect();
                        if at(index).is_none() && line.is_empty() {
                            return None;
                        }
                        index += 1;
                        let line = if strip {
                            line.trim_start_matches('\t')
                        } else {
                            &line
                        };
                        if line == end {
                            break;
                        }
                    }
                }
                continue;
            }
            '\\' if at(index + 1) == Some('\n') => {
                index += 2;
                continue;
            }
            ';' if at(index + 1) == Some(';') => (2, Op::EndArm),
            ';' => (1, Op::End),
            '&' if at(index + 1) == Some('&') => (2, Op::AndOr),
            '&' if at(index + 1) == Some('>') => (2, Op::Redirect),
            '&' => (1, Op::Background),
            '|' if at(index + 1) == Some('|') => (2, Op::AndOr),
            '|' => (1 + usize::from(at(index + 1) == Some('&')), Op::Pipe),
            '(' => (1, Op::Open),
            ')' => (1, Op::Close),
            '<' if at(index + 1) == Some('<') && at(index + 2) == Some('<') => (3, Op::Redirect),
            '<' if at(index + 1) == Some('<') && at(index + 2) == Some('-') => {
                (3, Op::HereDoc(true))
            }
            '<' if at(index + 1) == Some('<') => (2, Op::HereDoc(false)),
            '<' | '>' => (
                1 + usize::from(at(index + 1).is_some_and(|next| matches!(next, '>' | '&' | '|'))),
                Op::Redirect,
            ),
            _ => {
                let word = word(&chars, &mut index)?;
                // A number written against a redirection is its descriptor.
                if word.raw.chars().all(|character| character.is_ascii_digit())
                    && matches!(at(index), Some('<' | '>'))
                {
                    continue;
                }
                if let Some(strip) = delimiter.take() {
                    bodies.push((word.text.clone(), strip));
                }
                tokens.push(Token::Word(word));
                continue;
            }
        };
        index += op.0;
        if let Op::HereDoc(strip) = op.1 {
            delimiter = Some(strip);
        }
        tokens.push(Token::Op(op.1));
    }
    bodies.is_empty().then_some(tokens)
}

/// The word starting at `index`, which it moves past.
fn word(chars: &[char], index: &mut usize) -> Option<Word> {
    let start = *index;
    let mut text = String::new();
    let mut plain = true;
    let mut computed = false;
    while let Some(&character) = chars.get(*index) {
        match character {
            ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>' => break,
            '\\' => {
                if chars.get(*index + 1) != Some(&'\n') {
                    plain = false;
                    text.extend(chars.get(*index + 1));
                }
                *index += 2;
            }
            '\'' => {
                plain = false;
                let end = *index + 1 + chars[*index + 1..].iter().position(|&c| c == '\'')?;
                text.extend(&chars[*index + 1..end]);
                *index = end + 1;
            }
            '"' => {
                plain = false;
                *index += 1;
                loop {
                    match *chars.get(*index)? {
                        '"' => {
                            *index += 1;
                            break;
                        }
                        '\\' => {
                            let next = *chars.get(*index + 1)?;
                            if !matches!(next, '$' | '`' | '"' | '\\' | '\n') {
                                text.push('\\');
                            }
                            if next != '\n' {
                                text.push(next);
                            }
                            *index += 2;
                        }
                        '$' | '`' => {
                            computed = true;
                            skip_expansion(chars, index)?;
                        }
                        other => {
                            text.push(other);
                            *index += 1;
                        }
                    }
                }
            }
            '$' | '`' => {
                plain = false;
                computed = true;
                skip_expansion(chars, index)?;
            }
            other => {
                text.push(other);
                *index += 1;
            }
        }
    }
    Some(Word {
        text,
        raw: chars[start..*index].iter().collect(),
        plain,
        computed,
    })
}

/// Moves `index` past the expansion or substitution starting there.
fn skip_expansion(chars: &[char], index: &mut usize) -> Option<()> {
    match (chars[*index], chars.get(*index + 1)) {
        ('`', _) => {
            *index += 1;
            loop {
                match *chars.get(*index)? {
                    '\\' => *index += 2,
                    '`' => break,
                    _ => *index += 1,
                }
            }
            *index += 1;
        }
        ('$', Some(&open @ ('(' | '{'))) => {
            let close = if open == '(' { ')' } else { '}' };
            *index += 1;
            let mut depth = 0;
            loop {
                match *chars.get(*index)? {
                    '\\' => *index += 1,
                    '\'' => {
                        *index += 1 + chars[*index + 1..].iter().position(|&c| c == '\'')?;
                    }
                    character if character == open => depth += 1,
                    character if character == close => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                *index += 1;
            }
            *index += 1;
        }
        _ => {
            *index += 1;
            while chars
                .get(*index)
                .is_some_and(|character| character.is_ascii_alphanumeric() || *character == '_')
            {
                *index += 1;
            }
        }
    }
    Some(())
}
