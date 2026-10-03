//! SQL lexing: split source into statements and tokenize each one under a
//! dialect's lexical rules. Purely lexical and linear-time; no grammar is
//! built here.
//!
//! Where a server setting Nah cannot observe changes how text lexes
//! (Postgres `standard_conforming_strings`, MySQL `NO_BACKSLASH_ESCAPES` and
//! `ANSI_QUOTES`), or where a dialect's rule is not established (whether
//! block comments nest), [`readings`] returns one [`Lexing`] per possibility.
//! The caller lexes under each and analyzes the union, so a statement one
//! reading hides behind a string or comment another reading executes is
//! never lost.

use effinterp_proto::SqlDialect;

/// A byte span in the original SQL source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct SqlSpan {
    pub start: u32,
    pub end: u32,
}

/// A lexical token of a statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SqlTok {
    /// A bare word: keyword, identifier, or number (case kept).
    Word(String),
    /// A quoted identifier (quotes stripped). Never a keyword.
    Ident(String),
    /// A string literal's inner text (quotes stripped).
    Str(String),
    /// A client variable, template, or bind placeholder (`:v`, `&v`, `$1`,
    /// `?`, `@v`, `$(v)`, `<% v %>`): text the server never sees as written.
    Param,
    Punct(char),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Lexeme {
    pub tok: SqlTok,
    pub span: SqlSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum StatementKind {
    /// SQL sent to the server.
    Sql,
    /// A client-side command (psql `\x`, mysql `source`, sqlite `.x`, sqlcmd
    /// `:r`, snowsql `!x`), with its full line text.
    Client(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SqlStatement {
    pub kind: StatementKind,
    pub span: SqlSpan,
    pub toks: Vec<Lexeme>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    None,
    /// `#` starts a comment (MySQL, BigQuery).
    Any,
    /// `# ` and `#!` start a comment (ClickHouse).
    SpaceOrBang,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dollar {
    None,
    /// Only `$$ … $$` (Snowflake, CQL).
    Bare,
    /// `$tag$ … $tag$` (Postgres, ClickHouse heredocs).
    Tagged,
}

/// The client whose line-level commands the source may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Client {
    None,
    Psql,
    Mysql,
    Sqlite,
    Sqlcmd,
    Snowsql,
}

/// One set of lexical rules.
#[derive(Debug, Clone, Copy)]
pub(super) struct Lexing {
    /// `'…'` honors backslash escapes.
    single_backslash: bool,
    /// `"…"` is a string literal rather than a quoted identifier.
    double_string: bool,
    /// `"…"` honors backslash escapes.
    double_backslash: bool,
    /// `` `…` `` quotes identifiers; the flag says whether backslash escapes.
    backtick: Option<bool>,
    /// `[…]` quotes identifiers.
    brackets: bool,
    /// `]]` inside `[…]` is an escaped `]` (T-SQL); SQLite ends at the first.
    bracket_doubling: bool,
    hash: Hash,
    /// `--` starts a comment only before whitespace or end of input (MySQL).
    dash_needs_space: bool,
    /// `//` starts a line comment.
    slash_comment: bool,
    nested_comments: bool,
    /// `/*! … */` and `/*!NNNNN … */` bodies execute (MySQL, MariaDB).
    exec_comments: bool,
    dollar: Dollar,
    /// `E'…'` honors backslash escapes (Postgres).
    e_strings: bool,
    /// `'''…'''` and `"""…"""` (BigQuery).
    triple_quotes: bool,
    /// `:name`, `:'name'`, `:"name"`, `:1` are placeholders.
    colon_params: bool,
    /// `&name`, `&{name}`, `<% name %>` are placeholders (Snowflake clients).
    amp_params: bool,
    /// `{name:Type}` is a placeholder (ClickHouse query parameters).
    brace_params: bool,
    /// `-` joins words, as in BigQuery `my-project.dataset.table`.
    dash_words: bool,
    client: Client,
}

const BASE: Lexing = Lexing {
    single_backslash: false,
    double_string: false,
    double_backslash: false,
    backtick: None,
    brackets: false,
    bracket_doubling: false,
    hash: Hash::None,
    dash_needs_space: false,
    slash_comment: false,
    nested_comments: false,
    exec_comments: false,
    dollar: Dollar::None,
    e_strings: false,
    triple_quotes: false,
    colon_params: false,
    amp_params: false,
    brace_params: false,
    dash_words: false,
    client: Client::None,
};

const MYSQL: Lexing = Lexing {
    single_backslash: true,
    double_string: true,
    double_backslash: true,
    backtick: Some(false),
    hash: Hash::Any,
    dash_needs_space: true,
    exec_comments: true,
    client: Client::Mysql,
    ..BASE
};

/// Every lexical reading of `dialect` whose differences Nah cannot resolve.
/// The first reading is the dialect's default.
pub(super) fn readings(dialect: SqlDialect) -> Vec<Lexing> {
    // Whether block comments nest is not established for these dialects, so
    // both answers are read.
    let nesting = |base: Lexing| {
        vec![
            base,
            Lexing {
                nested_comments: true,
                ..base
            },
        ]
    };
    match dialect {
        SqlDialect::Postgres => {
            let on = Lexing {
                nested_comments: true,
                dollar: Dollar::Tagged,
                e_strings: true,
                colon_params: true,
                client: Client::Psql,
                ..BASE
            };
            // `standard_conforming_strings = off` makes `'…'` honor backslash.
            vec![
                on,
                Lexing {
                    single_backslash: true,
                    ..on
                },
            ]
        }
        SqlDialect::Mysql => vec![
            MYSQL,
            // NO_BACKSLASH_ESCAPES.
            Lexing {
                single_backslash: false,
                double_backslash: false,
                ..MYSQL
            },
            // ANSI_QUOTES: `"…"` quotes identifiers, which never escape.
            Lexing {
                double_string: false,
                double_backslash: false,
                ..MYSQL
            },
        ],
        SqlDialect::Sqlite => vec![Lexing {
            backtick: Some(false),
            brackets: true,
            colon_params: true,
            client: Client::Sqlite,
            ..BASE
        }],
        SqlDialect::TSql => vec![Lexing {
            brackets: true,
            bracket_doubling: true,
            nested_comments: true,
            client: Client::Sqlcmd,
            ..BASE
        }],
        SqlDialect::Snowflake => nesting(Lexing {
            single_backslash: true,
            slash_comment: true,
            dollar: Dollar::Bare,
            colon_params: true,
            amp_params: true,
            client: Client::Snowsql,
            ..BASE
        }),
        SqlDialect::BigQuery => nesting(Lexing {
            single_backslash: true,
            double_string: true,
            double_backslash: true,
            backtick: Some(true),
            hash: Hash::Any,
            triple_quotes: true,
            dash_words: true,
            ..BASE
        }),
        SqlDialect::ClickHouse => nesting(Lexing {
            single_backslash: true,
            double_backslash: true,
            backtick: Some(true),
            hash: Hash::SpaceOrBang,
            dollar: Dollar::Tagged,
            brace_params: true,
            ..BASE
        }),
        SqlDialect::Cql => nesting(Lexing {
            slash_comment: true,
            dollar: Dollar::Bare,
            colon_params: true,
            ..BASE
        }),
        // An unknown engine: the standard doubling convention, its nesting
        // variant, SQL Server's `[…]` identifiers, Snowflake's `//` comments,
        // and MySQL's backslash, `#`, and executable comments.
        SqlDialect::Generic => {
            let standard = Lexing {
                backtick: Some(false),
                dollar: Dollar::Tagged,
                colon_params: true,
                ..BASE
            };
            vec![
                standard,
                Lexing {
                    nested_comments: true,
                    ..standard
                },
                Lexing {
                    brackets: true,
                    bracket_doubling: true,
                    ..standard
                },
                Lexing {
                    slash_comment: true,
                    ..standard
                },
                Lexing {
                    colon_params: true,
                    client: Client::None,
                    ..MYSQL
                },
            ]
        }
    }
}

/// Split `source` into statements under `lexing` and tokenize each.
/// Comment-only and empty statements are dropped.
pub(super) fn lex(source: &str, lexing: &Lexing) -> Vec<SqlStatement> {
    let mut scanner = Scanner {
        src: source,
        b: source.as_bytes(),
        lx: *lexing,
        i: 0,
        line_start: true,
        delimiter: ";".to_string(),
        delimiter_at: 0,
        in_exec_comment: false,
        cur: Vec::new(),
        out: Vec::new(),
    };
    scanner.run();
    scanner.out
}

struct Scanner<'a> {
    src: &'a str,
    b: &'a [u8],
    lx: Lexing,
    i: usize,
    /// Only whitespace precedes `i` on its line.
    line_start: bool,
    /// The statement terminator; MySQL's `DELIMITER` changes it.
    delimiter: String,
    /// The next custom delimiter at or after the current token, cached so
    /// each token does not rescan the rest of the source.
    delimiter_at: usize,
    /// Inside a MySQL `/*! … */` body, whose `*/` is inert.
    in_exec_comment: bool,
    cur: Vec<Lexeme>,
    out: Vec<SqlStatement>,
}

impl Scanner<'_> {
    fn run(&mut self) {
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if c.is_ascii_whitespace() {
                if c == b'\n' {
                    self.line_start = true;
                }
                self.i += 1;
                continue;
            }
            if self.line_start && self.client_line() {
                continue;
            }
            self.line_start = false;
            if self.client_inline() {
                continue;
            }
            if self.delimiter != ";" && self.src[self.i..].starts_with(self.delimiter.as_str()) {
                self.i += self.delimiter.len();
                self.flush();
                continue;
            }
            // Under a custom DELIMITER the client sends `a; b` as one query,
            // and the server still runs each statement. A stored-program
            // body's `;` splits too; its statements are analyzed as if run.
            if c == b';' {
                self.i += 1;
                self.flush();
                continue;
            }
            if let Some(end) = self.comment(self.i) {
                self.i = end;
                continue;
            }
            self.token();
        }
        self.flush();
    }

    fn push(&mut self, tok: SqlTok, start: usize, end: usize) {
        self.cur.push(Lexeme {
            tok,
            span: span(start, end),
        });
    }

    /// End the current statement.
    fn flush(&mut self) {
        if self.cur.is_empty() {
            return;
        }
        let toks = std::mem::take(&mut self.cur);
        let parts = if self.lx.client == Client::Sqlcmd {
            tsql_split(toks)
        } else {
            vec![toks]
        };
        for toks in parts {
            let start = toks[0].span.start;
            let end = toks[toks.len() - 1].span.end;
            self.out.push(SqlStatement {
                kind: StatementKind::Sql,
                span: SqlSpan { start, end },
                toks,
            });
        }
    }

    fn line_end(&self, from: usize) -> usize {
        self.src[from..]
            .find('\n')
            .map(|offset| from + offset)
            .unwrap_or(self.b.len())
    }

    /// Record `from..line end` as a client command and move past it. With
    /// `to_semicolon`, a `;` ends the command early and the rest of the line
    /// is lexed again, so a statement after it is never hidden.
    fn client_command(&mut self, from: usize, to_semicolon: bool) {
        let mut end = self.line_end(from);
        if to_semicolon && let Some(offset) = self.src[from..end].find(';') {
            end = from + offset + 1;
        }
        self.client_command_to(from, end);
    }

    /// Record `from..end` as a client command and move past it.
    fn client_command_to(&mut self, from: usize, end: usize) {
        let text = self.src[from..end].trim_end().to_string();
        self.out.push(SqlStatement {
            kind: StatementKind::Client(text.clone()),
            span: span(from, from + text.len()),
            toks: Vec::new(),
        });
        self.i = end;
    }

    /// Commands a client recognizes only at the start of a line.
    fn client_line(&mut self) -> bool {
        let i = self.i;
        let rest = &self.src[i..];
        match self.lx.client {
            Client::Sqlcmd => {
                if is_go_line(&self.src[i..self.line_end(i)]) {
                    self.flush();
                    self.i = self.line_end(i);
                    return true;
                }
                let colon_command = rest.starts_with(':')
                    && rest.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic);
                if colon_command || rest.starts_with("!!") {
                    self.client_command(i, false);
                    return true;
                }
                false
            }
            Client::Sqlite if self.cur.is_empty() && rest.starts_with('.') => {
                self.client_command(i, false);
                true
            }
            Client::Snowsql
                if self.cur.is_empty()
                    && rest.starts_with('!')
                    && rest.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic) =>
            {
                self.client_command(i, false);
                true
            }
            Client::Mysql if self.cur.is_empty() => {
                let word: String = rest
                    .bytes()
                    .take_while(|b| b.is_ascii_alphabetic() || *b == b'_')
                    .map(|b| b.to_ascii_lowercase() as char)
                    .collect();
                let follows = rest.as_bytes().get(word.len());
                if !follows.is_none_or(|b| b.is_ascii_whitespace() || *b == b';') {
                    return false;
                }
                if word == "delimiter" {
                    let end = self.line_end(i);
                    if let Some(delimiter) = self.src[i + word.len()..end].split_whitespace().next()
                    {
                        self.delimiter = delimiter.to_string();
                        self.delimiter_at = 0;
                    }
                    self.i = end;
                    return true;
                }
                if MYSQL_LINE_COMMANDS.contains(&word.as_str()) {
                    self.client_command(i, true);
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Backslash commands, which psql and mysql recognize anywhere outside
    /// literals and comments.
    fn client_inline(&mut self) -> bool {
        let i = self.i;
        if self.b[i] != b'\\' {
            return false;
        }
        let next = self.b.get(i + 1).copied();
        match self.lx.client {
            Client::Psql => {
                match next {
                    // `\\` separates a meta-command from the SQL after it.
                    Some(b'\\') => {
                        self.i = i + 2;
                        return true;
                    }
                    // `\;` puts a `;` in the buffer: the server still runs
                    // the text on each side as its own statement.
                    Some(b';') => {
                        self.i = i + 2;
                        self.flush();
                        return true;
                    }
                    _ => {}
                }
                let name: String = self.src[i + 1..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '!' | '?' | '+'))
                    .collect();
                // The `\g` family sends the query buffer; `\gexec` then runs
                // each result value as SQL, which stays a client boundary.
                let sends =
                    name.starts_with('g') || matches!(name.as_str(), "watch" | "crosstabview");
                if sends {
                    self.flush();
                }
                let end = self.meta_end(i);
                let bare = self.src[i + 1 + name.len()..end].trim().is_empty();
                if name.starts_with('g') && name != "gexec" && bare {
                    self.i = end;
                } else {
                    self.client_command_to(i, end);
                }
                true
            }
            Client::Mysql => {
                match next {
                    // `\g`/`\G` send the buffer; `\c` discards it, but the
                    // buffer is analyzed as sent rather than guessed away.
                    Some(b'g' | b'G' | b'c') => {
                        self.i = i + 2;
                        self.flush();
                    }
                    Some(b'd') => {
                        let end = self.line_end(i);
                        if let Some(delimiter) = self.src[i + 2..end].split_whitespace().next() {
                            self.delimiter = delimiter.to_string();
                            self.delimiter_at = 0;
                        }
                        self.i = end;
                    }
                    // Commands that take the rest of the line as arguments.
                    Some(b'u' | b'.' | b'!' | b'C' | b'T' | b'P' | b'R' | b'r' | b'q') => {
                        self.client_command(i, false)
                    }
                    // Argument-less commands act on the client alone.
                    Some(b'?' | b'e' | b'h' | b'n' | b'p' | b's' | b't' | b'w' | b'W' | b'#') => {
                        self.i = i + 2;
                    }
                    // Not a client command (`\N` is NULL); the byte is inert.
                    _ => return false,
                }
                true
            }
            _ => false,
        }
    }

    /// The end of a psql meta-command's arguments at `i`: the line end, or a
    /// `\\` outside quotes, after which SQL resumes. Inside `'…'` a backslash
    /// escapes the next byte; `"…"` quotes too.
    fn meta_end(&self, i: usize) -> usize {
        let end = self.line_end(i);
        let mut quote: Option<u8> = None;
        let mut j = i + 1;
        while j < end {
            match (quote, self.b[j]) {
                (Some(b'\''), b'\\') => j += 1,
                (Some(q), c) if c == q => quote = None,
                (None, q @ (b'\'' | b'"')) => quote = Some(q),
                (None, b'\\') if self.b.get(j + 1) == Some(&b'\\') => return j,
                _ => {}
            }
            j += 1;
        }
        end
    }

    /// If `i` begins a comment, the index just past it.
    fn comment(&mut self, i: usize) -> Option<usize> {
        let b = self.b;
        let at = |k: usize| b.get(k).copied();
        if at(i) == Some(b'-') && at(i + 1) == Some(b'-') {
            let dash_comment =
                !self.lx.dash_needs_space || at(i + 2).is_none_or(|c| c.is_ascii_whitespace());
            if dash_comment {
                return Some(self.line_end(i));
            }
        }
        if at(i) == Some(b'#') {
            let hash_comment = match self.lx.hash {
                Hash::None => false,
                Hash::Any => true,
                Hash::SpaceOrBang => at(i + 1).is_none_or(|c| c == b'!' || c.is_ascii_whitespace()),
            };
            if hash_comment {
                return Some(self.line_end(i));
            }
        }
        if self.lx.slash_comment && at(i) == Some(b'/') && at(i + 1) == Some(b'/') {
            return Some(self.line_end(i));
        }
        if self.in_exec_comment && at(i) == Some(b'*') && at(i + 1) == Some(b'/') {
            self.in_exec_comment = false;
            return Some(i + 2);
        }
        if at(i) == Some(b'/') && at(i + 1) == Some(b'*') {
            if self.lx.exec_comments && !self.in_exec_comment {
                // `/*!`, `/*!NNNNN`, and MariaDB's `/*M!`, `/*M!NNNNNN`.
                let bang = match (at(i + 2), at(i + 3)) {
                    (Some(b'!'), _) => Some(i + 3),
                    (Some(b'M'), Some(b'!')) => Some(i + 4),
                    _ => None,
                };
                if let Some(mut j) = bang {
                    while at(j).is_some_and(|c| c.is_ascii_digit()) {
                        j += 1;
                    }
                    self.in_exec_comment = true;
                    return Some(j);
                }
            }
            return Some(self.block_comment_end(i));
        }
        None
    }

    fn block_comment_end(&self, i: usize) -> usize {
        let b = self.b;
        let mut depth = 0usize;
        let mut j = i;
        while j < b.len() {
            if b[j] == b'/'
                && b.get(j + 1) == Some(&b'*')
                && (depth == 0 || self.lx.nested_comments)
            {
                depth += 1;
                j += 2;
            } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                depth -= 1;
                j += 2;
                if depth == 0 {
                    return j;
                }
            } else {
                j += 1;
            }
        }
        b.len()
    }

    /// Scan one token at `self.i`.
    fn token(&mut self) {
        let i = self.i;
        let full = self.b;
        // The mysql client ends a statement at its custom delimiter even
        // glued to a word (`DROP TABLE a$$`), so unquoted scans stop there;
        // quoted scans use `full`.
        let stop = self.delimiter_stop(i);
        let b = &full[..stop];
        let c = b[i];
        let at = |k: usize| b.get(k).copied();
        let prev_word = i > 0 && is_word_byte(b[i - 1]);

        if self.lx.e_strings && matches!(c, b'e' | b'E') && at(i + 1) == Some(b'\'') && !prev_word {
            let end = quoted_end(full, i + 1, b'\'', true);
            self.push(SqlTok::Str(inner(self.src, i + 1, end)), i, end);
            self.i = end;
            return;
        }
        if self.lx.triple_quotes
            && (c == b'\'' || c == b'"')
            && at(i + 1) == Some(c)
            && at(i + 2) == Some(c)
        {
            let end = triple_end(full, i, c);
            let body_end = if end >= i + 6 && full[end - 1] == c {
                end - 3
            } else {
                end
            };
            self.push(SqlTok::Str(self.src[i + 3..body_end].to_string()), i, end);
            self.i = end;
            return;
        }
        match c {
            b'\'' => {
                let end = quoted_end(full, i, c, self.lx.single_backslash);
                self.push(SqlTok::Str(inner(self.src, i, end)), i, end);
                self.i = end;
                return;
            }
            b'"' => {
                let end = quoted_end(full, i, c, self.lx.double_backslash);
                let text = inner(self.src, i, end);
                let tok = if self.lx.double_string {
                    SqlTok::Str(text)
                } else {
                    SqlTok::Ident(text)
                };
                self.push(tok, i, end);
                self.i = end;
                return;
            }
            b'`' => {
                if let Some(backslash) = self.lx.backtick {
                    let end = quoted_end(full, i, c, backslash);
                    self.push(SqlTok::Ident(inner(self.src, i, end)), i, end);
                    self.i = end;
                    return;
                }
            }
            b'[' if self.lx.brackets => {
                let end = bracket_end(full, i, self.lx.bracket_doubling);
                let body_end = if end > i + 1 && full[end - 1] == b']' {
                    end - 1
                } else {
                    end
                };
                let mut text = self.src[i + 1..body_end].to_string();
                if self.lx.bracket_doubling {
                    text = text.replace("]]", "]");
                }
                self.push(SqlTok::Ident(text), i, end);
                self.i = end;
                return;
            }
            b'$' => {
                if let Some((end, text)) = self.dollar_quote(i, stop) {
                    self.push(SqlTok::Str(text), i, end);
                    self.i = end;
                    return;
                }
                let end = match at(i + 1) {
                    // sqlcmd `$(var)`.
                    Some(b'(') if self.lx.client == Client::Sqlcmd => closing(b, i + 2, b')'),
                    Some(n) if is_word_byte(n) => Some(word_end(b, i + 1, &self.lx)),
                    _ => None,
                };
                // A `$` that opens nothing is inert, never a name.
                self.param_or_inert(i, end);
                return;
            }
            b':' if self.lx.colon_params => {
                if at(i + 1) == Some(b':') {
                    self.i = i + 2;
                    return;
                }
                let end = match at(i + 1) {
                    Some(q @ (b'\'' | b'"')) => closing(b, i + 2, q),
                    Some(b'{') => closing(b, i + 2, b'}'),
                    // psql interpolates `:v` even glued to an identifier
                    // (`app_:v`); elsewhere `a:b` is a path, not a bind.
                    Some(n)
                        if is_word_byte(n) && (!prev_word || self.lx.client == Client::Psql) =>
                    {
                        Some(word_end(b, i + 1, &self.lx))
                    }
                    _ => None,
                };
                self.param_or_inert(i, end);
                return;
            }
            b'&' if self.lx.amp_params => {
                let end = match at(i + 1) {
                    Some(b'{') => closing(b, i + 2, b'}'),
                    Some(n) if is_word_byte(n) => Some(word_end(b, i + 1, &self.lx)),
                    _ => None,
                };
                self.param_or_inert(i, end);
                return;
            }
            b'<' if self.lx.amp_params && at(i + 1) == Some(b'%') => {
                let end = closing(b, i + 2, b'%').filter(|&end| at(end) == Some(b'>'));
                self.param_or_inert(i, end.map(|end| end + 1));
                return;
            }
            b'{' if self.lx.brace_params => {
                self.param_or_inert(i, closing(b, i + 1, b'}'));
                return;
            }
            b'?' => {
                let end = word_end(b, i + 1, &self.lx);
                self.push(SqlTok::Param, i, end);
                self.i = end;
                return;
            }
            b'@' => {
                let mut end = i + 1;
                while at(end) == Some(b'@') {
                    end += 1;
                }
                let end = word_end(b, end, &self.lx);
                self.push(SqlTok::Param, i, end);
                self.i = end;
                return;
            }
            _ => {}
        }
        if is_word_byte(c) && word_end(b, i, &self.lx) > i {
            let end = word_end(b, i, &self.lx);
            self.push(SqlTok::Word(self.src[i..end].to_string()), i, end);
            self.i = end;
            return;
        }
        if matches!(c, b'.' | b',' | b'(' | b')' | b'*' | b'=') {
            self.push(SqlTok::Punct(c as char), i, i + 1);
        }
        // Any other operator byte is not structurally relevant.
        self.i = i + 1;
    }

    /// Where unquoted scanning from `i` must stop: the next custom
    /// delimiter after `i`, or the end of the source.
    fn delimiter_stop(&mut self, i: usize) -> usize {
        if self.delimiter == ";" {
            return self.b.len();
        }
        if self.delimiter_at <= i {
            let d = self.delimiter.as_bytes();
            self.delimiter_at = self.b[i + 1..]
                .windows(d.len())
                .position(|w| w == d)
                .map_or(self.b.len(), |k| i + 1 + k);
        }
        self.delimiter_at
    }

    /// Push a placeholder spanning `i..end`, or, when its opener at `i` has no
    /// closer (`end` is `None`), step over the opener as one inert byte so the
    /// text after it still lexes.
    fn param_or_inert(&mut self, i: usize, end: Option<usize>) {
        match end {
            Some(end) => {
                self.push(SqlTok::Param, i, end);
                self.i = end;
            }
            None => self.i = i + 1,
        }
    }

    /// A dollar-quoted string at `i`: the index past its closer and its body.
    /// Its opening tag must end before `stop`.
    fn dollar_quote(&self, i: usize, stop: usize) -> Option<(usize, String)> {
        let b = &self.b[..stop];
        // `a$b$` continues an identifier; it does not open a quote.
        if i > 0 && is_word_byte(b[i - 1]) {
            return None;
        }
        let tag_end = match self.lx.dollar {
            Dollar::None => return None,
            Dollar::Bare => (b.get(i + 1) == Some(&b'$')).then_some(i + 1)?,
            Dollar::Tagged => {
                let mut j = i + 1;
                if b.get(j).is_some_and(u8::is_ascii_digit) {
                    return None;
                }
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] >= 0x80)
                {
                    j += 1;
                }
                (b.get(j) == Some(&b'$')).then_some(j)?
            }
        };
        let b = self.b;
        let tag = &self.src[i..=tag_end];
        let body = tag_end + 1;
        Some(match self.src[body..].find(tag) {
            Some(offset) => (
                body + offset + tag.len(),
                self.src[body..body + offset].to_string(),
            ),
            None => (b.len(), self.src[body..].to_string()),
        })
    }
}

/// Long-form mysql client commands, recognized at the start of a statement.
const MYSQL_LINE_COMMANDS: &[&str] = &[
    "charset",
    "clear",
    "connect",
    "edit",
    "ego",
    "exit",
    "go",
    "help",
    "nopager",
    "notee",
    "nowarning",
    "pager",
    "print",
    "prompt",
    "query_attributes",
    "quit",
    "rehash",
    "resetconnection",
    "source",
    "ssl_session_data_print",
    "status",
    "system",
    "tee",
    "use",
    "warnings",
];

fn span(start: usize, end: usize) -> SqlSpan {
    SqlSpan {
        start: start as u32,
        end: end as u32,
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'#') || b >= 0x80
}

/// The index past a word starting at `j`. A `#` that starts a comment in
/// this dialect ends the word, as the server's lexer does.
fn word_end(b: &[u8], mut j: usize, lx: &Lexing) -> usize {
    while j < b.len() {
        let hash_comment = b[j] == b'#'
            && match lx.hash {
                Hash::None => false,
                Hash::Any => true,
                Hash::SpaceOrBang => b
                    .get(j + 1)
                    .is_none_or(|c| *c == b'!' || c.is_ascii_whitespace()),
            };
        // sqlcmd `users_$(env)` glues a variable to the word.
        let variable = lx.client == Client::Sqlcmd && b[j] == b'$' && b.get(j + 1) == Some(&b'(');
        let word = is_word_byte(b[j]) && !hash_comment && !variable;
        let joining_dash = lx.dash_words
            && b[j] == b'-'
            && b.get(j + 1).is_some_and(u8::is_ascii_alphanumeric)
            && j > 0
            && is_word_byte(b[j - 1]);
        if !(word || joining_dash) {
            break;
        }
        j += 1;
    }
    j
}

/// The index past a quote opened at `i`. A doubled quote always escapes; a
/// backslash escapes the next byte when `backslash` is set. Unterminated
/// quoting runs to the end of input.
fn quoted_end(b: &[u8], i: usize, quote: u8, backslash: bool) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        if backslash && b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == quote {
            if b.get(j + 1) == Some(&quote) {
                j += 2;
                continue;
            }
            return j + 1;
        }
        j += 1;
    }
    b.len()
}

/// The index past a BigQuery triple-quoted string opened at `i`.
fn triple_end(b: &[u8], i: usize, quote: u8) -> usize {
    let mut j = i + 3;
    while j < b.len() {
        if b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == quote && b.get(j + 1) == Some(&quote) && b.get(j + 2) == Some(&quote) {
            return j + 3;
        }
        j += 1;
    }
    b.len()
}

fn bracket_end(b: &[u8], i: usize, doubling: bool) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        if b[j] == b']' {
            if doubling && b.get(j + 1) == Some(&b']') {
                j += 2;
                continue;
            }
            return j + 1;
        }
        j += 1;
    }
    b.len()
}

/// The index past the first `close` at or after `from` on the same line and
/// before any `;`. A placeholder never spans lines or statements.
fn closing(b: &[u8], from: usize, close: u8) -> Option<usize> {
    for (offset, &c) in b.get(from..)?.iter().enumerate() {
        if c == close {
            return Some(from + offset + 1);
        }
        if c == b'\n' || c == b';' {
            return None;
        }
    }
    None
}

/// A quoted token's inner text, with doubled quotes collapsed.
fn inner(src: &str, start: usize, end: usize) -> String {
    let quote = src.as_bytes()[start] as char;
    let body_end = if end > start + 1 && src.as_bytes()[end - 1] as char == quote {
        end - 1
    } else {
        end
    };
    let doubled: String = [quote, quote].iter().collect();
    src[start + 1..body_end.max(start + 1)].replace(&doubled, &quote.to_string())
}

/// A sqlcmd batch separator: `GO`, an optional repeat count, and nothing else
/// but a trailing `--` comment.
fn is_go_line(line: &str) -> bool {
    let mut words = line.split_whitespace();
    if !words.next().is_some_and(|w| w.eq_ignore_ascii_case("go")) {
        return false;
    }
    match words.next() {
        None => true,
        Some(w) if w.starts_with("--") => true,
        Some(w) => {
            w.bytes().all(|b| b.is_ascii_digit())
                && words.next().is_none_or(|w| w.starts_with("--"))
        }
    }
}

/// T-SQL runs consecutive statements without a `;` between them, so a batch
/// segment splits again before each keyword that starts a statement in that
/// position. A procedure, function, trigger, or view body is not executed by
/// its CREATE and is left whole.
fn tsql_split(toks: Vec<Lexeme>) -> Vec<Vec<Lexeme>> {
    let mut parts: Vec<Vec<Lexeme>> = Vec::new();
    let mut cur: Vec<Lexeme> = Vec::new();
    let mut depth = 0usize;
    // Open `CASE … END` expressions, whose `ELSE` and `END` end no statement.
    let mut cases = 0usize;
    for lexeme in toks {
        let kw = upper_word(&lexeme);
        let starts = depth == 0
            && !cur.is_empty()
            && kw
                .as_deref()
                .is_some_and(|kw| tsql_starts_statement(kw, &cur, cases));
        if starts {
            parts.push(std::mem::take(&mut cur));
            cases = 0;
        }
        match (&lexeme.tok, kw.as_deref()) {
            (SqlTok::Punct('('), _) => depth += 1,
            (SqlTok::Punct(')'), _) => depth = depth.saturating_sub(1),
            (_, Some("CASE")) if depth == 0 => cases += 1,
            (_, Some("END")) if depth == 0 && cases > 0 => cases -= 1,
            _ => {}
        }
        cur.push(lexeme);
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

fn upper_word(lexeme: &Lexeme) -> Option<String> {
    match &lexeme.tok {
        SqlTok::Word(w) => Some(w.to_ascii_uppercase()),
        _ => None,
    }
}

/// Whether `kw` starts a new T-SQL statement after the tokens `cur`.
fn tsql_starts_statement(kw: &str, cur: &[Lexeme], cases: usize) -> bool {
    const STARTS: &[&str] = &[
        "DROP",
        "TRUNCATE",
        "DELETE",
        "UPDATE",
        "INSERT",
        "MERGE",
        "CREATE",
        "ALTER",
        "EXEC",
        "EXECUTE",
        "USE",
        "SELECT",
        "PRINT",
        "SET",
        "DECLARE",
        "IF",
        "WHILE",
        "BEGIN",
        "END",
        "ELSE",
        "RETURN",
        "RAISERROR",
        "THROW",
        "COMMIT",
        "ROLLBACK",
    ];
    // Words after which `IF` is `IF [NOT] EXISTS`, not a statement.
    const OBJECT_KINDS: &[&str] = &[
        "TABLE",
        "DATABASE",
        "SCHEMA",
        "VIEW",
        "INDEX",
        "PROCEDURE",
        "PROC",
        "FUNCTION",
        "TRIGGER",
        "SEQUENCE",
        "TYPE",
        "USER",
        "ROLE",
        "SYNONYM",
        "COLUMN",
        "CONSTRAINT",
        "DEFAULT",
        "RULE",
        "ASSEMBLY",
        "AGGREGATE",
        "STATISTICS",
    ];
    if !STARTS.contains(&kw) {
        return false;
    }
    let head = upper_word(&cur[0]).unwrap_or_default();
    let second = cur.iter().skip(1).find_map(upper_word).unwrap_or_default();
    let prev = upper_word(&cur[cur.len() - 1]).unwrap_or_default();
    // A privilege list names statements without running them; T-SQL has no
    // DROP, TRUNCATE, or USE permission, so those always start one.
    if matches!(head.as_str(), "GRANT" | "REVOKE" | "DENY") {
        return matches!(kw, "DROP" | "TRUNCATE" | "USE");
    }
    let ddl = matches!(head.as_str(), "CREATE" | "ALTER");
    let body = ddl
        && matches!(
            second.as_str(),
            "PROC" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "VIEW" | "OR"
        );
    if body {
        return false;
    }
    // `WITH x AS (…) DELETE FROM x` is one statement over the CTE.
    if head == "WITH" && matches!(kw, "DELETE" | "UPDATE" | "INSERT" | "MERGE" | "SELECT") {
        return false;
    }
    match kw {
        // ALTER's own action follows the object name; any later DROP or
        // ALTER starts a statement (a DROP list continues only through `,`).
        "DROP" | "ALTER" if head == "ALTER" => cur.len() != alter_action_index(cur),
        // `ON DELETE CASCADE`, `FOR UPDATE`, `INSTEAD OF INSERT`, MERGE arms.
        "DELETE" | "UPDATE" | "INSERT" => {
            head != "MERGE"
                && !matches!(prev.as_str(), "THEN" | "FOR")
                && !(ddl && matches!(prev.as_str(), "ON" | "OF"))
        }
        "EXEC" | "EXECUTE" => head != "INSERT",
        // `INSERT … SELECT`, set operators, `CURSOR FOR SELECT`.
        "SELECT" => {
            head != "INSERT"
                && !matches!(
                    prev.as_str(),
                    "UNION" | "ALL" | "EXCEPT" | "INTERSECT" | "AS" | "FOR"
                )
        }
        // UPDATE's first SET, MERGE arms, ALTER … SET, `ON DELETE SET NULL`.
        "SET" => match head.as_str() {
            "UPDATE" => cur.iter().any(|t| upper_word(t).as_deref() == Some("SET")),
            "MERGE" => false,
            // `ALTER TABLE t SET (…)` only directly after the name.
            "ALTER" => cur.len() != alter_action_index(cur),
            _ => !(ddl && matches!(prev.as_str(), "DELETE" | "UPDATE")),
        },
        "IF" => !OBJECT_KINDS.contains(&prev.as_str()) && prev != "ADD",
        "END" | "ELSE" => cases == 0,
        _ => true,
    }
}

/// The index of an `ALTER kind name` statement's action: just past the
/// (dotted) object name and an optional `WITH CHECK|NOCHECK`.
fn alter_action_index(cur: &[Lexeme]) -> usize {
    let mut j = 2;
    while j < cur.len()
        && matches!(
            cur[j].tok,
            SqlTok::Word(_) | SqlTok::Ident(_) | SqlTok::Param
        )
    {
        j += 1;
        while matches!(cur.get(j).map(|t| &t.tok), Some(SqlTok::Punct('.'))) {
            j += 1;
        }
        if !matches!(cur.get(j - 1).map(|t| &t.tok), Some(SqlTok::Punct('.'))) {
            break;
        }
    }
    if cur.get(j).and_then(upper_word).as_deref() == Some("WITH")
        && matches!(
            cur.get(j + 1).and_then(upper_word).as_deref(),
            Some("CHECK" | "NOCHECK")
        )
    {
        j += 2;
    }
    j
}
