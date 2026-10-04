//! Shell tokenizer: source bytes to words, operators, and redirections.
//! Words keep their expansion structure (quoting, $VAR, substitutions) and
//! byte spans so the interpreter can build symbolic values and provenance.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShellSpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParamDefault {
    pub colon: bool,
    pub assign: bool,
    /// `+`/`:+`: the word replaces a set value instead of an unset one.
    pub alternate: bool,
    /// `?`/`:?`: an unset (or, with the colon, empty) value aborts the
    /// command instead of expanding. The message is never a value, so `word`
    /// stays empty.
    pub error: bool,
    pub word: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParamTransform {
    RemovePrefix {
        pattern: String,
    },
    RemoveSuffix {
        pattern: String,
    },
    Replace {
        pattern: String,
        replacement: String,
        all: bool,
    },
    /// `^`/`,` uppercase/lowercase the first character when it matches
    /// `pattern`, `^^`/`,,` every matching character; no pattern matches any.
    CaseModify {
        upper: bool,
        all: bool,
        pattern: Option<String>,
    },
    /// `:offset` or `:offset:length` with plain decimal or octal operands.
    /// A negative length counts back from the end of the value.
    Substring {
        offset: usize,
        length: Option<i64>,
    },
    /// `${!NAME}`: the value of the variable NAME names.
    Indirect,
}

/// One segment of a word. `quoted` on literals records whether any quoting
/// or escaping applied: only unquoted literal text is eligible for glob and
/// tilde interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seg {
    ScriptSource {
        quoted: bool,
        indexed: bool,
    },
    Literal {
        text: String,
        quoted: bool,
    },
    /// $NAME or ${NAME}.
    Env {
        name: String,
        quoted: bool,
    },
    /// ${NAME<modifier>}: a read of NAME with a statically recoverable simple
    /// `:-`/`-` or `:=`/`=` default when present.
    Param {
        name: String,
        default: Option<ParamDefault>,
        transform: Option<ParamTransform>,
        unwalked_substitution: bool,
        quoted: bool,
    },
    /// $@, $*, ${@}, ${*}: the positional parameters.
    AllArgs {
        quoted: bool,
    },
    /// $N or ${N}: one positional parameter.
    Positional {
        index: u32,
        quoted: bool,
    },
    /// ${NAME[@]} or ${NAME[*]}: every element of array NAME.
    ArrayAll {
        name: String,
        quoted: bool,
    },
    /// ${NAME[N]}: one element of array NAME by literal index.
    ArrayIndex {
        name: String,
        index: u32,
        quoted: bool,
    },
    /// The `(...)` of a NAME=(...) array assignment. `source` is the text
    /// between the parens (re-lexed into element words at binding time);
    /// `span` locates that text in the outer source.
    ArrayLit {
        source: String,
        span: ShellSpan,
    },
    /// $?, ${x@Q}, ... — statically unresolvable value.
    Special,
    /// `$$` or `${$}`: the shell's process ID. Its value is unknown, but a
    /// `/proc/$$/...` path names the shell's own process entry.
    ShellPid,
    /// An opaque parameter or array expansion containing a possible command substitution.
    UnwalkedParamSub,
    /// $(...) or `...`.
    CommandSub {
        source: String,
        span: ShellSpan,
        quoted: bool,
    },
    /// $((...)).
    Arith {
        span: ShellSpan,
    },
    /// <(...) or >(...).
    ProcSub {
        span: ShellSpan,
    },
}

/// The literal subscript of `[N]`, when it is a plain decimal index.
fn literal_index(modifier: &str) -> Option<u32> {
    modifier
        .strip_prefix('[')
        .and_then(|modifier| modifier.strip_suffix(']'))
        .and_then(|index| index.parse().ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WordTok {
    pub segs: Vec<Seg>,
    pub span: ShellSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Semi,
    /// `;;` ends a `case` arm.
    DSemi,
    /// `;&` ends a `case` arm and runs the next arm's body.
    SemiAmp,
    /// `;;&` ends a `case` arm and tests the patterns after it.
    DSemiAmp,
    Amp,
    AndIf,
    OrIf,
    Pipe,
    /// `|&`: pipe that also routes the left command's stderr into the pipe
    /// (shorthand for `2>&1 |`).
    PipeBoth,
    Newline,
    LParen,
    RParen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirKind {
    In,
    Out,
    Append,
    ReadWrite,
    HereDoc,
    HereString,
    /// >&N or <&N: fd duplication, no filesystem resource.
    Dup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HereDoc {
    /// Delimiter after quote removal; shell expansions are literal here.
    pub delimiter: String,
    /// Whether any byte of the delimiter was quoted or escaped.
    pub quoted: bool,
    /// Whether `<<-` strips leading tabs from body and terminator lines.
    pub strip_tabs: bool,
    /// The bytes delivered on stdin, with leading tabs already stripped for `<<-`.
    pub body: String,
    /// Raw source bytes of the body before tab stripping.
    pub body_span: ShellSpan,
    /// The terminator line without its newline, or `None` at end of input.
    pub terminator_span: Option<ShellSpan>,
}

pub(crate) struct ExpansionBudget {
    pub remaining: u64,
}

/// The target of an fd duplication: another fd, or a close (`n>&-`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellDupTarget {
    Fd(u32),
    Move(u32),
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tok {
    Word(WordTok),
    Op(Op, ShellSpan),
    /// A redirection with its ordered fd semantics preserved. `fd` is the source
    /// descriptor (defaulted: 0 for input forms, 1 for output forms); `dup` is
    /// the duplication target for `Dup`; `both` marks `&>`/`>&file` which affect
    /// stdout and stderr together.
    Redir {
        kind: RedirKind,
        fd: Option<u32>,
        dup: Option<ShellDupTarget>,
        both: bool,
        heredoc: Option<HereDoc>,
        span: ShellSpan,
    },
}

pub(crate) struct LexOutput {
    pub toks: Vec<Tok>,
    /// Tokenization stopped here; `toks` covers only the source before it.
    pub error: Option<(String, u32)>,
}

struct Cursor<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn eat(&mut self, prefix: &str) -> bool {
        if self.src[self.pos..].starts_with(prefix) {
            self.pos += prefix.len();
            true
        } else {
            false
        }
    }

    fn starts(&self, prefix: &str) -> bool {
        self.src[self.pos..].starts_with(prefix)
    }

    fn span_from(&self, start: usize) -> ShellSpan {
        ShellSpan {
            start: start as u32,
            end: self.pos as u32,
        }
    }
}

fn is_word_terminator(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
    )
}

pub(super) fn is_name_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

pub(super) fn is_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

pub(crate) fn lex(src: &str) -> LexOutput {
    let mut c = Cursor { src, pos: 0 };
    let mut toks = Vec::new();
    let mut pending = Vec::new();
    let error = loop {
        loop {
            if c.eat("\\\n") {
                continue;
            }
            match c.peek() {
                Some(' ' | '\t' | '\r') => {
                    c.bump();
                }
                _ => break,
            }
        }
        let start = c.pos;
        let Some(ch) = c.peek() else { break None };
        match ch {
            '\n' => {
                c.bump();
                toks.push(Tok::Op(Op::Newline, c.span_from(start)));
                if !pending.is_empty() {
                    drain_heredocs(&mut c, &mut toks, &mut pending);
                }
            }
            '#' => {
                while c.peek().is_some_and(|ch| ch != '\n') {
                    c.bump();
                }
            }
            ';' => {
                if c.eat(";;&") {
                    toks.push(Tok::Op(Op::DSemiAmp, c.span_from(start)));
                } else if c.eat(";&") {
                    toks.push(Tok::Op(Op::SemiAmp, c.span_from(start)));
                } else if c.eat(";;") {
                    toks.push(Tok::Op(Op::DSemi, c.span_from(start)));
                } else {
                    c.bump();
                    toks.push(Tok::Op(Op::Semi, c.span_from(start)));
                }
            }
            '&' => {
                if c.eat("&&") {
                    toks.push(Tok::Op(Op::AndIf, c.span_from(start)));
                } else if c.eat("&>>") {
                    toks.push(Tok::Redir {
                        kind: RedirKind::Append,
                        fd: None,
                        dup: None,
                        both: true,
                        heredoc: None,
                        span: c.span_from(start),
                    });
                } else if c.eat("&>") {
                    toks.push(Tok::Redir {
                        kind: RedirKind::Out,
                        fd: None,
                        dup: None,
                        both: true,
                        heredoc: None,
                        span: c.span_from(start),
                    });
                } else {
                    c.bump();
                    toks.push(Tok::Op(Op::Amp, c.span_from(start)));
                }
            }
            '|' => {
                if c.eat("||") {
                    toks.push(Tok::Op(Op::OrIf, c.span_from(start)));
                } else if c.eat("|&") {
                    toks.push(Tok::Op(Op::PipeBoth, c.span_from(start)));
                } else {
                    c.bump();
                    toks.push(Tok::Op(Op::Pipe, c.span_from(start)));
                }
            }
            '(' => {
                c.bump();
                toks.push(Tok::Op(Op::LParen, c.span_from(start)));
            }
            ')' => {
                c.bump();
                toks.push(Tok::Op(Op::RParen, c.span_from(start)));
            }
            '<' | '>' => match lex_redirect(&mut c, start, None) {
                Ok(tok) => {
                    if matches!(
                        &tok,
                        Tok::Redir {
                            kind: RedirKind::HereDoc,
                            heredoc: Some(_),
                            ..
                        }
                    ) {
                        pending.push(toks.len());
                    }
                    toks.push(tok);
                }
                Err(e) => break Some(e),
            },
            '0'..='9' => {
                // A digit run directly followed by < or > is an fd redirect.
                let save = c.pos;
                while c.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                    c.bump();
                }
                if matches!(c.peek(), Some('<' | '>')) {
                    let fd = c.src[start..c.pos].parse::<u32>().ok();
                    match lex_redirect(&mut c, start, fd) {
                        Ok(tok) => {
                            if matches!(
                                &tok,
                                Tok::Redir {
                                    kind: RedirKind::HereDoc,
                                    heredoc: Some(_),
                                    ..
                                }
                            ) {
                                pending.push(toks.len());
                            }
                            toks.push(tok);
                        }
                        Err(e) => break Some(e),
                    }
                } else {
                    c.pos = save;
                    match lex_word(&mut c) {
                        Ok(word) => toks.push(Tok::Word(word)),
                        Err(e) => break Some(e),
                    }
                }
            }
            _ => match lex_word(&mut c) {
                Ok(word) => toks.push(Tok::Word(word)),
                Err(e) => break Some(e),
            },
        }
    };
    LexOutput { toks, error }
}

fn lex_redirect(c: &mut Cursor, start: usize, fd: Option<u32>) -> Result<Tok, (String, u32)> {
    // Process substitution is a word form, not a redirect.
    if c.starts("<(") || c.starts(">(") {
        return lex_procsub(c, start);
    }
    // (kind, dup target, default source fd for dups, both stdout+stderr, heredoc).
    let (kind, dup, dup_fd, both, heredoc) = if c.eat("<<<") {
        (RedirKind::HereString, None, None, false, None)
    } else if c.starts("<<-") || c.starts("<<") {
        c.eat("<<");
        let strip_tabs = c.eat("-");
        while matches!(c.peek(), Some(' ' | '\t')) {
            c.bump();
        }
        let heredoc = lex_heredoc_delimiter(c)?.map(|(delimiter, quoted)| HereDoc {
            delimiter,
            quoted,
            strip_tabs,
            body: String::new(),
            body_span: ShellSpan {
                start: c.pos as u32,
                end: c.pos as u32,
            },
            terminator_span: None,
        });
        (RedirKind::HereDoc, None, None, false, heredoc)
    } else if c.eat("<&") {
        (RedirKind::Dup, eat_dup_target(c), Some(0), false, None)
    } else if c.eat("<>") {
        (RedirKind::ReadWrite, None, None, false, None)
    } else if c.eat("<") {
        (RedirKind::In, None, None, false, None)
    } else if c.eat(">>") {
        (RedirKind::Append, None, None, false, None)
    } else if c.eat(">&") {
        // >&N duplicates fd1 onto N; >&- closes; >&file redirects both
        // stdout and stderr like `&>`.
        match eat_dup_target(c) {
            Some(target) => (RedirKind::Dup, Some(target), Some(1), false, None),
            None if fd.is_some() || matches!(c.peek(), Some('$' | '\'' | '"')) => {
                (RedirKind::Dup, None, Some(1), false, None)
            }
            None => (RedirKind::Out, None, None, true, None),
        }
    } else {
        c.eat(">|");
        c.eat(">");
        (RedirKind::Out, None, None, false, None)
    };
    let fd = fd.or(if matches!(kind, RedirKind::Dup) {
        dup_fd
    } else {
        None
    });
    Ok(Tok::Redir {
        kind,
        fd,
        dup,
        both,
        heredoc,
        span: c.span_from(start),
    })
}

fn lex_heredoc_delimiter(c: &mut Cursor) -> Result<Option<(String, bool)>, (String, u32)> {
    let start = c.pos;
    let mut delimiter = String::new();
    let mut quoted = false;
    while let Some(ch) = c.peek() {
        if is_word_terminator(ch) {
            break;
        }
        match ch {
            '$' if c.starts("$'") => {
                quoted = true;
                c.bump();
                let quote_start = c.pos;
                let inner = c.pos + 1;
                scan_ansi_quoted(c)?;
                // The delimiter decides where source parsing resumes. Refuse
                // unaudited escapes rather than guessing that boundary.
                let value = ansi_literal(&c.src[inner..c.pos - 1]).ok_or_else(|| {
                    (
                        "unsupported ANSI-C heredoc delimiter".into(),
                        quote_start as u32,
                    )
                })?;
                delimiter.push_str(&value);
            }
            '\'' => {
                quoted = true;
                c.bump();
                while let Some(inner) = c.peek() {
                    c.bump();
                    if inner == '\'' {
                        break;
                    }
                    delimiter.push(inner);
                }
            }
            '"' => {
                quoted = true;
                c.bump();
                while let Some(inner) = c.peek() {
                    if inner == '"' {
                        c.bump();
                        break;
                    }
                    if inner == '\\' {
                        c.bump();
                        if let Some(escaped) = c.bump() {
                            match escaped {
                                '\\' | '"' | '$' | '`' => delimiter.push(escaped),
                                '\n' => {}
                                _ => {
                                    delimiter.push('\\');
                                    delimiter.push(escaped);
                                }
                            }
                        } else {
                            delimiter.push('\\');
                        }
                    } else {
                        delimiter.push(inner);
                        c.bump();
                    }
                }
            }
            '\\' => {
                quoted = true;
                c.bump();
                if let Some(escaped) = c.bump() {
                    delimiter.push(escaped);
                }
            }
            _ => {
                delimiter.push(ch);
                c.bump();
            }
        }
    }
    Ok((c.pos > start).then_some((delimiter, quoted)))
}

fn drain_heredocs(c: &mut Cursor<'_>, toks: &mut [Tok], pending: &mut Vec<usize>) {
    for idx in pending.drain(..) {
        let (delimiter, strip_tabs) = match &toks[idx] {
            Tok::Redir {
                heredoc: Some(heredoc),
                ..
            } => (heredoc.delimiter.clone(), heredoc.strip_tabs),
            _ => continue,
        };
        let body_start = c.pos;
        let mut body = String::new();
        let mut terminator_span = None;
        while c.pos < c.src.len() {
            let line_start = c.pos;
            let newline = c.src[c.pos..].find('\n').map(|offset| c.pos + offset);
            let line_end = newline.unwrap_or(c.src.len());
            let raw = &c.src[line_start..line_end];
            let cmp = if strip_tabs {
                raw.trim_start_matches('\t')
            } else {
                raw
            };
            c.pos = newline.map_or(line_end, |pos| pos + 1);
            let delimiter_cmp = if newline.is_some() {
                cmp.strip_suffix('\r').unwrap_or(cmp)
            } else {
                cmp
            };
            if delimiter_cmp == delimiter {
                terminator_span = Some(ShellSpan {
                    start: line_start as u32,
                    end: line_end as u32,
                });
                break;
            }
            body.push_str(cmp);
            if newline.is_some() {
                body.push('\n');
            }
        }
        if let Tok::Redir {
            heredoc: Some(heredoc),
            ..
        } = &mut toks[idx]
        {
            heredoc.body = body;
            heredoc.body_span = ShellSpan {
                start: body_start as u32,
                end: terminator_span
                    .map(|span| span.start)
                    .unwrap_or(c.pos as u32),
            };
            heredoc.terminator_span = terminator_span;
        }
    }
}

pub(crate) fn lex_heredoc_body(
    source: &str,
    heredoc: &HereDoc,
    budget: &mut ExpansionBudget,
) -> (WordTok, bool) {
    if heredoc.quoted {
        return (
            WordTok {
                segs: vec![Seg::Literal {
                    text: heredoc.body.clone(),
                    quoted: true,
                }],
                span: heredoc.body_span,
            },
            false,
        );
    }
    if budget.remaining == 0 {
        return (
            WordTok {
                segs: Vec::new(),
                span: heredoc.body_span,
            },
            true,
        );
    }

    let end = heredoc.body_span.end as usize;
    let mut c = Cursor {
        src: &source[..end],
        pos: heredoc.body_span.start as usize,
    };
    let mut w = WordBuilder {
        segs: Vec::new(),
        lit: String::new(),
        lit_quoted: true,
        saw_quote: false,
    };
    let mut line_start = true;
    while c.pos < end {
        if line_start && heredoc.strip_tabs {
            while c.peek() == Some('\t') {
                c.bump();
            }
        }
        line_start = false;
        let Some(ch) = c.peek() else { break };
        match ch {
            '$' | '`' => {
                let saved = w.clone();
                let saved_pos = c.pos;
                let result = if ch == '$' {
                    lex_dollar_quoted(&mut c, &mut w)
                } else {
                    lex_backtick(&mut c, &mut w, true)
                };
                if result.is_err() {
                    w = saved;
                    c.pos = saved_pos;
                    w.push(ch, true);
                    c.bump();
                    continue;
                }
                let added = w.segs[saved.segs.len()..]
                    .iter()
                    .filter(|seg| !matches!(seg, Seg::Literal { .. }))
                    .count() as u64;
                if added > budget.remaining {
                    w = saved;
                    w.flush();
                    return (
                        WordTok {
                            segs: w.segs,
                            span: heredoc.body_span,
                        },
                        true,
                    );
                }
                budget.remaining -= added;
            }
            '\\' => {
                c.bump();
                match c.peek() {
                    Some('\n') => {
                        c.bump();
                        line_start = true;
                    }
                    Some(escaped @ ('$' | '`' | '\\')) => {
                        w.push(escaped, true);
                        c.bump();
                    }
                    Some(other) => {
                        w.push('\\', true);
                        w.push(other, true);
                        c.bump();
                    }
                    None => w.push('\\', true),
                }
            }
            '\n' => {
                w.push(ch, true);
                c.bump();
                line_start = true;
            }
            _ => {
                w.push(ch, true);
                c.bump();
            }
        }
    }
    w.flush();
    (
        WordTok {
            segs: w.segs,
            span: heredoc.body_span,
        },
        false,
    )
}

/// Read the target of an fd duplication after `>&`/`<&`: a fd number (an
/// optional trailing `-` marks a move), a bare `-` for close, or nothing
/// (the following word must be expanded before selecting a target).
fn eat_dup_target(c: &mut Cursor) -> Option<ShellDupTarget> {
    let digits_start = c.pos;
    while c.peek().is_some_and(|ch| ch.is_ascii_digit()) {
        c.bump();
    }
    if c.pos == digits_start {
        return if c.eat("-") {
            Some(ShellDupTarget::Close)
        } else {
            None
        };
    }
    let n = c.src[digits_start..c.pos].parse::<u32>().ok();
    let moving = c.eat("-");
    n.map(|fd| {
        if moving {
            ShellDupTarget::Move(fd)
        } else {
            ShellDupTarget::Fd(fd)
        }
    })
}

fn scan_substitution_body(c: &mut Cursor, start: usize) -> Result<String, (String, u32)> {
    let inner_start = c.pos;
    let mut depth = 1u32;
    let mut pending: Vec<(String, bool)> = Vec::new();
    let mut comment_start = true;
    loop {
        match c.peek() {
            None => {
                return Err(("unterminated command substitution".into(), start as u32));
            }
            Some('$') if c.starts("$'") => {
                c.bump();
                scan_ansi_quoted(c)?;
                comment_start = false;
            }
            Some('\'') => {
                c.bump();
                while c.peek().is_some_and(|ch| ch != '\'') {
                    c.bump();
                }
                c.bump();
                comment_start = false;
            }
            Some('"') => {
                c.bump();
                loop {
                    match c.bump() {
                        None => {
                            return Err(("unterminated command substitution".into(), start as u32));
                        }
                        Some('\\') => {
                            c.bump();
                        }
                        Some('"') => break,
                        Some(_) => {}
                    }
                }
                comment_start = false;
            }
            Some('\\') => {
                c.bump();
                c.bump();
                comment_start = false;
            }
            // Arithmetic shifts are not heredoc redirects.
            Some('$') if c.starts("$((") => {
                c.eat("$((");
                let mut arithmetic_depth = 2u32;
                while arithmetic_depth > 0 {
                    match c.bump() {
                        None => {
                            return Err(("unterminated command substitution".into(), start as u32));
                        }
                        Some('(') => arithmetic_depth += 1,
                        Some(')') => arithmetic_depth -= 1,
                        Some(_) => {}
                    }
                }
                comment_start = false;
            }
            // A comment is opaque to heredoc detection through its newline.
            Some('#') if comment_start => {
                while c.peek().is_some_and(|ch| ch != '\n') {
                    c.bump();
                }
            }
            Some('<') if c.starts("<<") && !c.starts("<<<") => {
                c.eat("<<");
                let strip_tabs = c.eat("-");
                while matches!(c.peek(), Some(' ' | '\t')) {
                    c.bump();
                }
                if let Some((delimiter, _)) = lex_heredoc_delimiter(c)? {
                    pending.push((delimiter, strip_tabs));
                }
                comment_start = false;
            }
            Some(' ' | '\t' | '\r') => {
                c.bump();
                comment_start = true;
            }
            Some('\n') => {
                c.bump();
                if !pending.is_empty() {
                    skip_heredoc_bodies(c, &mut pending);
                }
                comment_start = true;
            }
            Some(';' | '&' | '|') => {
                c.bump();
                comment_start = true;
            }
            Some('(') => {
                depth += 1;
                c.bump();
                comment_start = true;
            }
            Some(')') => {
                depth -= 1;
                c.bump();
                if depth == 0 {
                    break;
                }
                comment_start = true;
            }
            Some(_) => {
                c.bump();
                comment_start = false;
            }
        }
    }
    let inner_end = c.pos - 1;
    Ok(c.src[inner_start..inner_end].to_string())
}

fn lex_procsub(c: &mut Cursor, start: usize) -> Result<Tok, (String, u32)> {
    c.bump(); // < or >
    c.bump(); // (
    scan_substitution_body(c, start)?;
    let span = c.span_from(start);
    Ok(Tok::Word(WordTok {
        segs: vec![Seg::ProcSub { span }],
        span,
    }))
}

#[derive(Clone)]
struct WordBuilder {
    segs: Vec<Seg>,
    lit: String,
    lit_quoted: bool,
    saw_quote: bool,
}

impl WordBuilder {
    fn flush(&mut self) {
        if !self.lit.is_empty() {
            self.segs.push(Seg::Literal {
                text: std::mem::take(&mut self.lit),
                quoted: self.lit_quoted,
            });
        }
    }

    fn push(&mut self, ch: char, quoted: bool) {
        if self.lit_quoted != quoted && !self.lit.is_empty() {
            self.flush();
        }
        self.lit_quoted = quoted;
        self.lit.push(ch);
    }

    fn seg(&mut self, seg: Seg) {
        self.flush();
        self.segs.push(seg);
    }
}

/// An extended glob group, from its opening parenthesis through the matching
/// close. Groups nest, so the alternatives may hold further groups.
fn lex_extglob(c: &mut Cursor, w: &mut WordBuilder) -> Result<(), (String, u32)> {
    let start = c.pos;
    let mut depth = 0usize;
    loop {
        let Some(ch) = c.bump() else {
            return Err(("unterminated extended glob".into(), start as u32));
        };
        w.push(ch, false);
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
}

fn lex_word(c: &mut Cursor) -> Result<WordTok, (String, u32)> {
    let start = c.pos;
    let mut w = WordBuilder {
        segs: Vec::new(),
        lit: String::new(),
        lit_quoted: false,
        saw_quote: false,
    };
    loop {
        let Some(ch) = c.peek() else { break };
        match ch {
            // `NAME=(...)` / `NAME+=(...)`: an array assignment's element
            // list, not a subshell.
            '(' if w.segs.is_empty() && !w.lit_quoted && is_array_assign_prefix(&w.lit) => {
                lex_array_literal(c, &mut w)?;
            }
            // `?(…)`, `*(…)`, `+(…)`, `@(…)`, `!(…)`: an extended glob group
            // belongs to the word as pattern text, not a subshell.
            '(' if !w.lit_quoted && w.lit.ends_with(['?', '*', '+', '@', '!']) => {
                lex_extglob(c, &mut w)?;
            }
            // `--input=<(…)`: a process substitution after other text is
            // part of the same word.
            '<' | '>'
                if (c.starts("<(") || c.starts(">("))
                    && !(w.segs.is_empty() && w.lit.is_empty()) =>
            {
                let start = c.pos;
                c.bump();
                c.bump();
                scan_substitution_body(c, start)?;
                w.seg(Seg::ProcSub {
                    span: c.span_from(start),
                });
            }
            _ if is_word_terminator(ch) => break,
            '\'' => {
                w.saw_quote = true;
                let qstart = c.pos;
                c.bump();
                loop {
                    match c.bump() {
                        None => return Err(("unterminated single quote".into(), qstart as u32)),
                        Some('\'') => break,
                        Some(inner) => w.push(inner, true),
                    }
                }
            }
            '"' => {
                w.saw_quote = true;
                let qstart = c.pos;
                c.bump();
                lex_double_quoted(c, &mut w, qstart)?;
            }
            '\\' => {
                c.bump();
                match c.peek() {
                    None => w.push('\\', true),
                    Some('\n') => {
                        c.bump();
                    }
                    Some(escaped) => {
                        w.push(escaped, true);
                        c.bump();
                    }
                }
            }
            '$' => lex_dollar(c, &mut w)?,
            '`' => lex_backtick(c, &mut w, false)?,
            _ => {
                w.push(ch, false);
                c.bump();
            }
        }
    }
    w.flush();
    if w.segs.is_empty() && w.saw_quote {
        w.segs.push(Seg::Literal {
            text: String::new(),
            quoted: true,
        });
    }
    Ok(WordTok {
        segs: w.segs,
        span: c.span_from(start),
    })
}

/// Whether unquoted word text so far is exactly `NAME=` or `NAME+=`, making
/// a following `(` open an array assignment's element list.
fn is_array_assign_prefix(lit: &str) -> bool {
    let Some(name) = lit.strip_suffix('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    name.chars().next().is_some_and(is_name_start) && name.chars().all(is_name_char)
}

/// Capture `(...)` after `NAME=` as one segment, honoring quotes, escapes,
/// and nested parens (command substitutions) while finding the closer.
fn lex_array_literal(c: &mut Cursor, w: &mut WordBuilder) -> Result<(), (String, u32)> {
    let open = c.pos;
    c.bump(); // (
    let inner_start = c.pos;
    let mut depth = 1u32;
    loop {
        match c.peek() {
            None => return Err(("unterminated array assignment".into(), open as u32)),
            Some('$') if c.starts("$'") => {
                c.bump();
                scan_ansi_quoted(c)?;
            }
            Some('\'') => {
                c.bump();
                while c.peek().is_some_and(|ch| ch != '\'') {
                    c.bump();
                }
                c.bump();
            }
            Some('"') => {
                c.bump();
                loop {
                    match c.bump() {
                        None => {
                            return Err(("unterminated array assignment".into(), open as u32));
                        }
                        Some('\\') => {
                            c.bump();
                        }
                        Some('"') => break,
                        Some(_) => {}
                    }
                }
            }
            Some('\\') => {
                c.bump();
                c.bump();
            }
            Some('(') => {
                depth += 1;
                c.bump();
            }
            Some(')') => {
                depth -= 1;
                c.bump();
                if depth == 0 {
                    break;
                }
            }
            Some(_) => {
                c.bump();
            }
        }
    }
    let inner_end = c.pos - 1;
    w.seg(Seg::ArrayLit {
        source: c.src[inner_start..inner_end].to_string(),
        span: ShellSpan {
            start: inner_start as u32,
            end: inner_end as u32,
        },
    });
    Ok(())
}

fn lex_double_quoted(
    c: &mut Cursor,
    w: &mut WordBuilder,
    qstart: usize,
) -> Result<(), (String, u32)> {
    loop {
        match c.peek() {
            None => return Err(("unterminated double quote".into(), qstart as u32)),
            Some('"') => {
                c.bump();
                return Ok(());
            }
            Some('\\') => {
                c.bump();
                match c.peek() {
                    None => return Err(("unterminated double quote".into(), qstart as u32)),
                    Some(esc @ ('"' | '\\' | '$' | '`')) => {
                        w.push(esc, true);
                        c.bump();
                    }
                    Some('\n') => {
                        c.bump();
                    }
                    Some(other) => {
                        w.push('\\', true);
                        w.push(other, true);
                        c.bump();
                    }
                }
            }
            Some('$') => lex_dollar_quoted(c, w)?,
            Some('`') => lex_backtick(c, w, true)?,
            Some(ch) => {
                w.push(ch, true);
                c.bump();
            }
        }
    }
}

fn lex_dollar(c: &mut Cursor, w: &mut WordBuilder) -> Result<(), (String, u32)> {
    lex_dollar_inner(c, w, false)
}

fn lex_dollar_quoted(c: &mut Cursor, w: &mut WordBuilder) -> Result<(), (String, u32)> {
    lex_dollar_inner(c, w, true)
}

// ANSI-C quoting produces one quoted literal, never another expansion pass.
// Numeric escapes remain bounded to ASCII bytes: non-ASCII encoding and NUL
// truncation require semantics that the string-valued word carrier cannot prove.
fn ansi_literal(source: &str) -> Option<String> {
    let mut chars = source.chars().peekable();
    let mut output = String::new();
    while let Some(ch) = chars.next() {
        let ch = if ch == '\\' {
            match chars.next()? {
                'a' => '\u{7}',
                'b' => '\u{8}',
                'e' | 'E' => '\u{1b}',
                'f' => '\u{c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\u{b}',
                escaped @ ('\\' | '\'' | '"' | '?') => escaped,
                digit @ '0'..='7' => {
                    let value = ansi_digits(&mut chars, 8, 3, Some(digit))? as u8;
                    if value == 0 || !value.is_ascii() {
                        return None;
                    }
                    char::from(value)
                }
                escape @ ('x' | 'u' | 'U') => {
                    let width = match escape {
                        'x' => 2,
                        'u' => 4,
                        _ => 8,
                    };
                    let value = ansi_digits(&mut chars, 16, width, None)?;
                    if !(1..=127).contains(&value) {
                        return None;
                    }
                    char::from(value as u8)
                }
                _ => return None,
            }
        } else {
            ch
        };
        if ch == '\0' {
            return None;
        }
        output.push(ch);
    }
    Some(output)
}

fn ansi_digits(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    width: usize,
    first: Option<char>,
) -> Option<u32> {
    let mut count = usize::from(first.is_some());
    let mut value = first.and_then(|digit| digit.to_digit(radix)).unwrap_or(0);
    while count < width && chars.peek().is_some_and(|digit| digit.is_digit(radix)) {
        value = value * radix + chars.next()?.to_digit(radix)?;
        count += 1;
    }
    (count > 0).then_some(value)
}

fn scan_ansi_quoted(c: &mut Cursor) -> Result<(), (String, u32)> {
    let start = c.pos;
    c.bump();
    loop {
        match c.bump() {
            Some('\'') => return Ok(()),
            Some('\\') => {
                if c.bump().is_none() {
                    return Err(("unterminated ANSI-C quote".into(), start as u32));
                }
            }
            Some(_) => {}
            None => return Err(("unterminated ANSI-C quote".into(), start as u32)),
        }
    }
}

fn lex_ansi_quoted(c: &mut Cursor, w: &mut WordBuilder) -> Result<(), (String, u32)> {
    let inner = c.pos + 1;
    scan_ansi_quoted(c)?;
    w.saw_quote = true;
    match ansi_literal(&c.src[inner..c.pos - 1]) {
        Some(text) => w.seg(Seg::Literal { text, quoted: true }),
        None => w.seg(Seg::Special),
    }
    Ok(())
}

fn lex_dollar_inner(
    c: &mut Cursor,
    w: &mut WordBuilder,
    quoted: bool,
) -> Result<(), (String, u32)> {
    let dstart = c.pos;
    c.bump(); // $
    match c.peek() {
        Some('\'') if !quoted => lex_ansi_quoted(c, w)?,
        Some('(') if c.starts("((") => {
            c.bump();
            c.bump();
            let mut depth = 2u32;
            while depth > 0 {
                match c.bump() {
                    None => {
                        return Err(("unterminated arithmetic expansion".into(), dstart as u32));
                    }
                    Some('(') => depth += 1,
                    Some(')') => depth -= 1,
                    Some(_) => {}
                }
            }
            w.seg(Seg::Arith {
                span: c.span_from(dstart),
            });
        }
        Some('(') => {
            c.bump();
            let source = scan_substitution_body(c, dstart)?;
            w.seg(Seg::CommandSub {
                source,
                span: c.span_from(dstart),
                quoted,
            });
        }
        Some('{') => {
            c.bump();
            let inner_start = c.pos;
            let mut depth = 1u32;
            loop {
                match c.bump() {
                    None => return Err(("unterminated parameter expansion".into(), dstart as u32)),
                    Some('{') => depth += 1,
                    Some('}') => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    Some(_) => {}
                }
            }
            let inner = &c.src[inner_start..c.pos - 1];
            w.seg(braced_seg(inner, quoted));
        }
        Some(ch) if is_name_start(ch) => {
            let name_start = c.pos;
            while c.peek().is_some_and(is_name_char) {
                c.bump();
            }
            if &c.src[name_start..c.pos] == "BASH_SOURCE" {
                w.seg(Seg::ScriptSource {
                    quoted,
                    indexed: false,
                });
            } else {
                w.seg(Seg::Env {
                    name: c.src[name_start..c.pos].to_string(),
                    quoted,
                });
            }
        }
        Some(ch) if ch.is_ascii_digit() => {
            c.bump();
            w.seg(Seg::Positional {
                index: ch as u32 - '0' as u32,
                quoted,
            });
        }
        Some('@' | '*') => {
            c.bump();
            w.seg(Seg::AllArgs { quoted });
        }
        Some('$') => {
            c.bump();
            w.seg(Seg::ShellPid);
        }
        Some(ch) if "#?!-".contains(ch) => {
            c.bump();
            w.seg(Seg::Special);
        }
        _ => w.push('$', quoted),
    }
    Ok(())
}

fn skip_heredoc_bodies(c: &mut Cursor<'_>, pending: &mut Vec<(String, bool)>) {
    for (delimiter, strip_tabs) in pending.drain(..) {
        while c.pos < c.src.len() {
            let newline = c.src[c.pos..].find('\n').map(|offset| c.pos + offset);
            let line_end = newline.unwrap_or(c.src.len());
            let raw = &c.src[c.pos..line_end];
            let cmp = if strip_tabs {
                raw.trim_start_matches('\t')
            } else {
                raw
            };
            c.pos = newline.map_or(line_end, |pos| pos + 1);
            let delimiter_cmp = if newline.is_some() {
                cmp.strip_suffix('\r').unwrap_or(cmp)
            } else {
                cmp
            };
            if delimiter_cmp == delimiter {
                break;
            }
        }
    }
}

/// Classify the inner text of a `${...}` expansion.
fn braced_seg(inner: &str, quoted: bool) -> Seg {
    let unwalked_substitution = inner.contains("$(") || inner.contains('`');
    let special = || {
        if unwalked_substitution {
            Seg::UnwalkedParamSub
        } else {
            Seg::Special
        }
    };
    if !inner.is_empty() && inner.chars().all(|ch| ch.is_ascii_digit()) {
        return match inner.parse() {
            Ok(index) => Seg::Positional { index, quoted },
            Err(_) => Seg::Special,
        };
    }
    if inner == "@" || inner == "*" {
        return Seg::AllArgs { quoted };
    }
    if inner == "$" {
        return Seg::ShellPid;
    }
    // `${#NAME}` (length) and `${!NAME}` (indirection) still read NAME.
    let (rest, prefixed) = match inner.strip_prefix(['#', '!']) {
        Some(rest) => (rest, true),
        None => (inner, false),
    };
    let indirect = inner.starts_with('!');
    let positional = rest.chars().next().is_some_and(|ch| ch.is_ascii_digit());
    if !positional && !rest.chars().next().is_some_and(is_name_start) {
        return special();
    }
    let name_len = rest
        .chars()
        .take_while(|ch| {
            if positional {
                ch.is_ascii_digit()
            } else {
                is_name_char(*ch)
            }
        })
        .count();
    let (name, modifier) = rest.split_at(name_len);
    if !prefixed && name == "BASH_SOURCE" && matches!(modifier, "" | "[0]") {
        return Seg::ScriptSource {
            quoted,
            indexed: modifier == "[0]",
        };
    }
    match modifier {
        "" if !prefixed => Seg::Env {
            name: name.to_string(),
            quoted,
        },
        // Array forms: elements come from the script, not the environment.
        "[@]" | "[*]" if !prefixed => Seg::ArrayAll {
            name: name.to_string(),
            quoted,
        },
        m if !prefixed && literal_index(m).is_some() => Seg::ArrayIndex {
            name: name.to_string(),
            index: literal_index(m).unwrap(),
            quoted,
        },
        // Element 0 is the scalar, so `${NAME[0]:=WORD}` reads and assigns
        // the same value as `${NAME:=WORD}`, and `${NAME[0]:?}` rejects what
        // `${NAME:?}` does.
        m if !prefixed
            && m.strip_prefix("[0]").is_some_and(|rest| {
                ["-", "=", ":-", ":=", "?", ":?"]
                    .iter()
                    .any(|operator| rest.starts_with(operator))
            }) =>
        {
            braced_seg(&format!("{name}{}", &m[3..]), quoted)
        }
        m if m.starts_with('[') => special(),
        _ => {
            let default = (!prefixed)
                .then(|| {
                    modifier
                        .strip_prefix(":-")
                        .map(|word| (true, false, false, word))
                        .or_else(|| {
                            modifier
                                .strip_prefix('-')
                                .map(|word| (false, false, false, word))
                        })
                        .or_else(|| {
                            modifier
                                .strip_prefix(":=")
                                .map(|word| (true, true, false, word))
                        })
                        .or_else(|| {
                            modifier
                                .strip_prefix('=')
                                .map(|word| (false, true, false, word))
                        })
                        .or_else(|| {
                            modifier
                                .strip_prefix(":+")
                                .map(|word| (true, false, true, word))
                        })
                        .or_else(|| {
                            modifier
                                .strip_prefix('+')
                                .map(|word| (false, false, true, word))
                        })
                })
                .flatten()
                .filter(|(_, _, _, word)| {
                    !word.contains("$(")
                        && !word.chars().any(|ch| matches!(ch, '`' | '\\' | '\'' | '"'))
                })
                .map(|(colon, assign, alternate, word)| ParamDefault {
                    colon,
                    assign,
                    alternate,
                    error: false,
                    word: word.to_string(),
                })
                .or_else(|| {
                    let colon = modifier.starts_with(':');
                    ((!prefixed || indirect) && modifier[usize::from(colon)..].starts_with('?'))
                        .then_some(ParamDefault {
                            colon,
                            assign: false,
                            alternate: false,
                            error: true,
                            word: String::new(),
                        })
                });
            let transform = if indirect
                && (modifier.is_empty() || default.as_ref().is_some_and(|default| default.error))
            {
                Some(ParamTransform::Indirect)
            } else {
                (!prefixed && default.is_none())
                    .then(|| literal_param_transform(modifier))
                    .flatten()
            };
            Seg::Param {
                name: name.to_string(),
                default,
                transform,
                // Expansion words are not walked; possible substitutions need a gap.
                unwalked_substitution,
                quoted,
            }
        }
    }
}

fn literal_param_transform(modifier: &str) -> Option<ParamTransform> {
    if let Some(operands) = modifier.strip_prefix(':') {
        let (offset, length) = match operands.split_once(':') {
            Some((offset, length)) => (
                offset,
                Some(match length.strip_prefix('-') {
                    Some(magnitude) => -i64::try_from(literal_number(magnitude)?).ok()?,
                    None => i64::try_from(literal_number(length)?).ok()?,
                }),
            ),
            None => (operands, None),
        };
        return Some(ParamTransform::Substring {
            offset: literal_number(offset)?,
            length,
        });
    }
    for (operator, upper) in [('^', true), (',', false)] {
        if let Some(rest) = modifier.strip_prefix(operator) {
            let (all, pattern) = match rest.strip_prefix(operator) {
                Some(pattern) => (true, pattern),
                None => (false, rest),
            };
            return Some(ParamTransform::CaseModify {
                upper,
                all,
                pattern: if pattern.is_empty() {
                    None
                } else {
                    Some(literal_param_piece(pattern)?.to_string())
                },
            });
        }
    }
    if let Some(pattern) = modifier
        .strip_prefix("%%")
        .or_else(|| modifier.strip_prefix('%'))
    {
        return Some(ParamTransform::RemoveSuffix {
            pattern: literal_param_piece(pattern)?.to_string(),
        });
    }
    if let Some(pattern) = modifier
        .strip_prefix("##")
        .or_else(|| modifier.strip_prefix('#'))
    {
        return Some(ParamTransform::RemovePrefix {
            pattern: literal_param_piece(pattern)?.to_string(),
        });
    }
    let (all, replacement) = if let Some(rest) = modifier.strip_prefix("//") {
        (true, rest)
    } else {
        (false, modifier.strip_prefix('/')?)
    };
    let (pattern, replacement) = replacement.split_once('/')?;
    Some(ParamTransform::Replace {
        pattern: literal_param_piece(pattern)?.to_string(),
        replacement: if replacement.is_empty() {
            String::new()
        } else {
            literal_param_piece(replacement)?.to_string()
        },
        all,
    })
}

/// A substring operand is an arithmetic expression; only a plain number is
/// taken. As in shell arithmetic, a leading zero makes it octal.
fn literal_number(operand: &str) -> Option<usize> {
    if operand.is_empty() || !operand.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let radix = if operand.len() > 1 && operand.starts_with('0') {
        8
    } else {
        10
    };
    usize::from_str_radix(operand, radix).ok()
}

fn literal_param_piece(value: &str) -> Option<&str> {
    (!value.is_empty()
        && !value
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '$' | '`' | '\\' | '\'' | '"')))
    .then_some(value)
}

fn lex_backtick(c: &mut Cursor, w: &mut WordBuilder, quoted: bool) -> Result<(), (String, u32)> {
    let bstart = c.pos;
    c.bump(); // `
    let mut inner = String::new();
    loop {
        match c.bump() {
            None => return Err(("unterminated backtick substitution".into(), bstart as u32)),
            Some('\\') => match c.bump() {
                None => return Err(("unterminated backtick substitution".into(), bstart as u32)),
                Some(esc @ ('`' | '\\' | '$')) => inner.push(esc),
                Some(other) => {
                    inner.push('\\');
                    inner.push(other);
                }
            },
            Some('`') => break,
            Some(ch) => inner.push(ch),
        }
    }
    w.seg(Seg::CommandSub {
        source: inner,
        span: c.span_from(bstart),
        quoted,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<WordTok> {
        let out = lex(src);
        assert!(out.error.is_none(), "{:?}", out.error);
        out.toks
            .into_iter()
            .filter_map(|t| match t {
                Tok::Word(w) => Some(w),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn plain_words_and_operators() {
        let out = lex("ls -la; echo hi && cat|wc");
        assert!(out.error.is_none());
        let ops: Vec<Op> = out
            .toks
            .iter()
            .filter_map(|t| match t {
                Tok::Op(op, _) => Some(*op),
                _ => None,
            })
            .collect();
        assert_eq!(ops, vec![Op::Semi, Op::AndIf, Op::Pipe]);
    }

    #[test]
    fn quoting_merges_and_marks() {
        let w = &words(r#"foo"bar baz"'qux'"#)[0];
        assert_eq!(
            w.segs,
            vec![
                Seg::Literal {
                    text: "foo".into(),
                    quoted: false
                },
                Seg::Literal {
                    text: "bar bazqux".into(),
                    quoted: true
                },
            ]
        );
    }

    #[test]
    fn env_inside_and_outside_quotes() {
        let w = &words(r#""$HOME/x"$Y"#)[0];
        assert_eq!(
            w.segs,
            vec![
                Seg::Env {
                    name: "HOME".into(),
                    quoted: true,
                },
                Seg::Literal {
                    text: "/x".into(),
                    quoted: true
                },
                Seg::Env {
                    name: "Y".into(),
                    quoted: false,
                },
            ]
        );
    }

    #[test]
    fn braced_env_and_complex_expansion() {
        let expanded = words(r#"${A} "${A}""#);
        assert_eq!(
            expanded[0].segs[0],
            Seg::Env {
                name: "A".into(),
                quoted: false,
            }
        );
        assert_eq!(
            expanded[1].segs[0],
            Seg::Env {
                name: "A".into(),
                quoted: true,
            }
        );
        let w = &words("${A}/${B:-x}")[0];
        assert!(matches!(
            &w.segs[2],
            Seg::Param {
                name,
                default: Some(ParamDefault { colon: true, assign: false, alternate: false, error: false, word }),
                quoted: false,
                ..
            } if name == "B" && word == "x"
        ));

        let defaults = words(r#"${A-x} "${B:-y}" ${C:-$D}"#);
        assert!(matches!(
            &defaults[0].segs[0],
            Seg::Param {
                default: Some(ParamDefault { colon: false, assign: false, alternate: false, error: false, word }),
                quoted: false,
                ..
            } if word == "x"
        ));
        assert!(matches!(
            &defaults[1].segs[0],
            Seg::Param {
                default: Some(ParamDefault { colon: true, assign: false, alternate: false, error: false, word }),
                quoted: true,
                ..
            } if word == "y"
        ));
        assert!(matches!(
            &defaults[2].segs[0],
            Seg::Param {
                default: Some(ParamDefault { word, .. }),
                ..
            } if word == "$D"
        ));
    }

    #[test]
    fn positional_args_and_array_expansions() {
        let w = &words(r#""$1"$2${11}"#)[0];
        assert_eq!(
            w.segs,
            vec![
                Seg::Positional {
                    index: 1,
                    quoted: true
                },
                Seg::Positional {
                    index: 2,
                    quoted: false
                },
                Seg::Positional {
                    index: 11,
                    quoted: false
                },
            ]
        );
        let w = &words(r#""$@"${*}"#)[0];
        assert_eq!(
            w.segs,
            vec![
                Seg::AllArgs { quoted: true },
                Seg::AllArgs { quoted: false }
            ]
        );
        let w = &words(r#""${args[@]}""#)[0];
        assert!(matches!(&w.segs[0], Seg::ArrayAll { name, quoted: true } if name == "args"));
        // Length and symbolic subscripts stay opaque; a literal index selects
        // one element, and `${#VAR}` still reads VAR.
        assert!(matches!(&words("${#arr[@]}")[0].segs[0], Seg::Special));
        assert!(matches!(&words("${arr[i]}")[0].segs[0], Seg::Special));
        assert!(matches!(
            &words("${arr[0]}")[0].segs[0],
            Seg::ArrayIndex { name, index: 0, quoted: false } if name == "arr"
        ));
        assert!(matches!(
            &words("${#VAR}")[0].segs[0],
            Seg::Param {
                name,
                default: None,
                ..
            } if name == "VAR"
        ));
    }

    #[test]
    fn array_assignment_is_one_word() {
        let toks = words(r#"args=("-A" "${args[@]}") next"#);
        assert_eq!(toks.len(), 2);
        assert!(matches!(
            &toks[0].segs[..],
            [
                Seg::Literal { text, .. },
                Seg::ArrayLit { source, .. },
            ] if text == "args=" && source == r#""-A" "${args[@]}""#
        ));
        // A plain `(` still terminates a word.
        let out = lex("foo (bar)");
        assert!(out.toks.iter().any(|t| matches!(t, Tok::Op(Op::LParen, _))));
    }

    #[test]
    fn command_substitution_captures_inner() {
        let w = &words("$(ls -l \"a)b\")")[0];
        assert!(matches!(&w.segs[0], Seg::CommandSub { source, .. } if source == "ls -l \"a)b\""));
    }

    #[test]
    fn backtick_substitution() {
        let w = &words("`date +%s`")[0];
        assert!(matches!(&w.segs[0], Seg::CommandSub { source, .. } if source == "date +%s"));
    }

    #[test]
    fn fd_redirects_and_dups() {
        let out = lex("cmd 2>err >>log <in 2>&1");
        let kinds: Vec<RedirKind> = out
            .toks
            .iter()
            .filter_map(|t| match t {
                Tok::Redir { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                RedirKind::Out,
                RedirKind::Append,
                RedirKind::In,
                RedirKind::Dup
            ]
        );
    }

    #[test]
    fn fd_numbers_and_dup_targets_are_preserved() {
        let out = lex("cat 2>&1 >&2 |& wc");
        let redirs: Vec<(RedirKind, Option<u32>, Option<ShellDupTarget>, bool)> = out
            .toks
            .iter()
            .filter_map(|t| match t {
                Tok::Redir {
                    kind,
                    fd,
                    dup,
                    both,
                    ..
                } => Some((*kind, *fd, *dup, *both)),
                _ => None,
            })
            .collect();
        assert_eq!(
            redirs,
            vec![
                // 2>&1 : source fd 2 duplicates fd 1.
                (RedirKind::Dup, Some(2), Some(ShellDupTarget::Fd(1)), false),
                // >&2 : source fd defaults to 1, duplicates fd 2.
                (RedirKind::Dup, Some(1), Some(ShellDupTarget::Fd(2)), false),
            ]
        );
        // `|&` is a distinct operator, not a plain pipe.
        assert!(
            out.toks
                .iter()
                .any(|t| matches!(t, Tok::Op(Op::PipeBoth, _)))
        );
    }

    #[test]
    fn ampersand_redirect_marks_both_streams() {
        let out = lex("run &> log");
        let both = out.toks.iter().any(|t| {
            matches!(
                t,
                Tok::Redir {
                    kind: RedirKind::Out,
                    both: true,
                    ..
                }
            )
        });
        assert!(both);
    }

    #[test]
    fn unterminated_quote_is_error_not_panic() {
        let out = lex("echo 'oops");
        assert!(out.error.is_some());
    }

    #[test]
    fn escaped_glob_is_quoted() {
        let w = &words(r"\*")[0];
        assert_eq!(
            w.segs,
            vec![Seg::Literal {
                text: "*".into(),
                quoted: true
            }]
        );
    }

    #[test]
    fn comment_is_skipped() {
        let out = lex("ls # rm -rf /");
        assert_eq!(
            out.toks
                .iter()
                .filter(|t| matches!(t, Tok::Word(_)))
                .count(),
            1
        );
    }

    fn heredocs(toks: &[Tok]) -> Vec<&HereDoc> {
        toks.iter()
            .filter_map(|tok| match tok {
                Tok::Redir {
                    heredoc: Some(heredoc),
                    ..
                } => Some(heredoc),
                _ => None,
            })
            .collect()
    }

    fn literal_words(toks: &[Tok]) -> Vec<String> {
        toks.iter()
            .filter_map(|tok| match tok {
                Tok::Word(word) => {
                    let mut text = String::new();
                    for seg in &word.segs {
                        let Seg::Literal { text: part, .. } = seg else {
                            return None;
                        };
                        text.push_str(part);
                    }
                    Some(text)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn heredoc_delimiters_apply_quote_removal_only() {
        for (operator, delimiter, quoted) in [
            ("<<EOF", "EOF", false),
            ("<<'EOF'", "EOF", true),
            ("<<\"EOF\"", "EOF", true),
            ("<< EOF", "EOF", false),
            ("<<E\\OF", "EOF", true),
            ("<<\"E\"OF", "EOF", true),
            ("<<\"E\\OF\"", "E\\OF", true),
            (r#"<<$'E\x4fF'"#, "EOF", true),
            (r#"<<E$'\117'"F""#, "EOF", true),
            (r#"<<-$'E\u004fF'"#, "EOF", true),
            ("<<$X", "$X", false),
        ] {
            let source = format!("cat {operator}\nbody\n{delimiter}\nnext");
            let out = lex(&source);
            assert!(out.error.is_none(), "{operator}: {:?}", out.error);
            let heredoc = heredocs(&out.toks)[0];
            assert_eq!(heredoc.delimiter, delimiter, "{operator}");
            assert_eq!(heredoc.quoted, quoted, "{operator}");
            assert_eq!(heredoc.body, "body\n", "{operator}");
            assert!(heredoc.terminator_span.is_some(), "{operator}");
            assert_eq!(literal_words(&out.toks).last().unwrap(), "next");
        }
    }

    #[test]
    fn heredoc_strip_tabs_preserves_raw_span() {
        let source = "cat <<-EOF\n\tone\n \tEOF\n\tEOF\nnext";
        let out = lex(source);
        assert!(out.error.is_none(), "{:?}", out.error);
        let heredoc = heredocs(&out.toks)[0];
        assert!(heredoc.strip_tabs);
        assert_eq!(heredoc.body, "one\n \tEOF\n");
        assert_eq!(
            &source[heredoc.body_span.start as usize..heredoc.body_span.end as usize],
            "\tone\n \tEOF\n"
        );
        let terminator = heredoc.terminator_span.unwrap();
        assert_eq!(
            &source[terminator.start as usize..terminator.end as usize],
            "\tEOF"
        );
        assert_eq!(literal_words(&out.toks).last().unwrap(), "next");
    }

    #[test]
    fn heredoc_queues_are_drained_in_redirect_order() {
        for source in [
            "cat <<A; cat <<B\na\nA\nb\nB\nnext",
            "cmd <<A <<B\na\nA\nb\nB\nnext",
        ] {
            let out = lex(source);
            assert!(out.error.is_none(), "{:?}", out.error);
            let heredocs = heredocs(&out.toks);
            assert_eq!(heredocs.len(), 2);
            assert_eq!(heredocs[0].body, "a\n");
            assert_eq!(heredocs[1].body, "b\n");
            assert_eq!(
                out.toks
                    .iter()
                    .filter(|tok| matches!(tok, Tok::Op(Op::Newline, _)))
                    .count(),
                1
            );
            assert_eq!(literal_words(&out.toks).last().unwrap(), "next");
        }
    }

    #[test]
    fn heredoc_keeps_same_line_redirects_and_pipes() {
        let redirected = lex("cat <<EOF > /etc/motd\nbody\nEOF");
        assert!(redirected.error.is_none());
        assert!(redirected.toks.iter().any(|tok| matches!(
            tok,
            Tok::Redir {
                kind: RedirKind::Out,
                ..
            }
        )));
        assert!(
            literal_words(&redirected.toks)
                .iter()
                .any(|word| word == "/etc/motd")
        );

        let piped = lex("cat <<EOF | sh\nbody\nEOF");
        assert!(piped.error.is_none());
        assert!(
            piped
                .toks
                .iter()
                .any(|tok| matches!(tok, Tok::Op(Op::Pipe, _)))
        );
        assert_eq!(literal_words(&piped.toks), ["cat", "sh"]);
    }

    #[test]
    fn heredoc_body_is_never_tokenized_as_shell() {
        let source = "cat <<EOF\n' \" ` $( ) # \\ <<\nEOF \nEOF\nrm -rf /tmp/x";
        let out = lex(source);
        assert!(out.error.is_none(), "{:?}", out.error);
        assert_eq!(heredocs(&out.toks)[0].body, "' \" ` $( ) # \\ <<\nEOF \n");
        assert_eq!(
            &literal_words(&out.toks)[literal_words(&out.toks).len() - 3..],
            ["rm", "-rf", "/tmp/x"]
        );
    }

    #[test]
    fn heredoc_empty_missing_and_unterminated_shapes() {
        let empty = lex("cat <<EOF\nEOF\nnext");
        let heredoc = heredocs(&empty.toks)[0];
        assert_eq!(heredoc.body, "");
        assert_eq!(heredoc.body_span.start, heredoc.body_span.end);
        assert!(heredoc.terminator_span.is_some());

        for (source, body) in [("cat <<EOF", ""), ("cat <<EOF\nline", "line")] {
            let out = lex(source);
            assert!(out.error.is_none(), "{:?}", out.error);
            let heredoc = heredocs(&out.toks)[0];
            assert_eq!(heredoc.body, body);
            assert!(heredoc.terminator_span.is_none());
        }

        let missing = lex("cat <<\nrm x");
        assert!(missing.error.is_none(), "{:?}", missing.error);
        assert!(missing.toks.iter().any(|tok| matches!(
            tok,
            Tok::Redir {
                kind: RedirKind::HereDoc,
                heredoc: None,
                ..
            }
        )));
        assert_eq!(literal_words(&missing.toks), ["cat", "rm", "x"]);
    }

    #[test]
    fn heredoc_inside_command_substitution_ignores_body_syntax() {
        let source = "x=\"$(cat <<EOF\n')\nEOF\n)\"; rm -rf /tmp/x";
        let out = lex(source);
        assert!(out.error.is_none(), "{:?}", out.error);
        let command_source = out.toks.iter().find_map(|tok| match tok {
            Tok::Word(word) => word.segs.iter().find_map(|seg| match seg {
                Seg::CommandSub { source, .. } => Some(source.as_str()),
                _ => None,
            }),
            _ => None,
        });
        assert_eq!(command_source, Some("cat <<EOF\n')\nEOF\n"));
        assert_eq!(
            &literal_words(&out.toks)[literal_words(&out.toks).len() - 3..],
            ["rm", "-rf", "/tmp/x"]
        );
    }

    #[test]
    fn command_substitution_only_skips_real_heredoc_bodies() {
        for source in [
            "x=\"$(echo $((1<<2)))\"; rm -rf /tmp/x",
            "x=\"$(true # <<EOF\n)\"; rm -rf /tmp/x",
            "x=\"$(cat<<EOF\n)\nEOF\n)\"; rm -rf /tmp/x",
            "x=\"$(cat<<EOF\r\n)\r\nEOF\r\n)\"; rm -rf /tmp/x",
        ] {
            let out = lex(source);
            assert!(out.error.is_none(), "{source:?}: {:?}", out.error);
            let words = literal_words(&out.toks);
            assert_eq!(&words[words.len() - 3..], ["rm", "-rf", "/tmp/x"]);
        }
    }

    #[test]
    fn heredoc_crlf_terminator_preserves_raw_body_and_following_command() {
        let source = "cat <<EOF\r\nline\r\nEOF\r\nnext";
        let out = lex(source);
        assert!(out.error.is_none(), "{:?}", out.error);
        let heredoc = heredocs(&out.toks)[0];
        assert_eq!(heredoc.body, "line\r\n");
        assert_eq!(
            &source[heredoc.body_span.start as usize..heredoc.body_span.end as usize],
            "line\r\n"
        );
        let terminator = heredoc.terminator_span.unwrap();
        assert_eq!(
            &source[terminator.start as usize..terminator.end as usize],
            "EOF\r"
        );
        assert_eq!(literal_words(&out.toks), ["cat", "next"]);
    }

    struct HeredocRng(u64);

    impl HeredocRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545f4914f6cdd1d)
        }
    }

    fn generated_heredoc_body(seed: u64) -> String {
        const PARTS: &[&str] = &[
            "'", "\"", "`", "$", "(", ")", "{", "}", "#", "\\", "\n", "EOF", " ", "\t",
        ];
        let mut rng = HeredocRng(seed ^ 0x9e3779b97f4a7c15);
        loop {
            let mut body = String::new();
            for _ in 0..(rng.next() % 32) {
                body.push_str(PARTS[(rng.next() as usize) % PARTS.len()]);
            }
            if !body
                .lines()
                .any(|line| line.trim_start_matches('\t') == "EOF")
            {
                return body;
            }
        }
    }

    fn assert_heredoc_span_accountability(source: &str, toks: &[Tok]) {
        let mut covered = vec![false; source.len()];
        for tok in toks {
            let span = match tok {
                Tok::Word(word) => word.span,
                Tok::Op(_, span) | Tok::Redir { span, .. } => *span,
            };
            covered[span.start as usize..span.end as usize].fill(true);
            if let Tok::Redir {
                heredoc: Some(heredoc),
                ..
            } = tok
            {
                covered[heredoc.body_span.start as usize..heredoc.body_span.end as usize]
                    .fill(true);
                if let Some(span) = heredoc.terminator_span {
                    covered[span.start as usize..span.end as usize].fill(true);
                    if source.as_bytes().get(span.end as usize) == Some(&b'\n') {
                        covered[span.end as usize] = true;
                    }
                }
            }
        }
        for (offset, byte) in source.bytes().enumerate() {
            assert!(
                covered[offset] || matches!(byte, b' ' | b'\t'),
                "unaccounted byte {byte:?} at {offset} in {source:?}"
            );
        }
    }

    #[test]
    fn generated_heredocs_never_swallow_following_words() {
        for seed in 0..2_000 {
            let body = generated_heredoc_body(seed);
            let tabbed = body.replace('\n', "\n\t");
            for source in [
                format!("cat <<EOF\n{body}\nEOF\nrm -rf /tmp/x\n"),
                format!("cat <<'EOF'\n{body}\nEOF\nrm -rf /tmp/x\n"),
                format!("cat <<-EOF\n\t{tabbed}\n\tEOF\nrm -rf /tmp/x\n"),
                format!("x=\"$(cat <<EOF\n{body}\nEOF\n)\"; rm -rf /tmp/x\n"),
            ] {
                let out = lex(&source);
                assert!(out.error.is_none(), "seed {seed}: {:?}", out.error);
                assert_heredoc_span_accountability(&source, &out.toks);
                let words = literal_words(&out.toks);
                assert_eq!(&words[words.len() - 3..], ["rm", "-rf", "/tmp/x"]);
            }
        }
    }
}
