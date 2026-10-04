//! SQL client input segmentation: the lexical scan of a client's input
//! (quotes, comments, dollar quoting, the statement delimiter) and its split
//! into SQL and the client commands between it, in execution order.

use effinterp_proto::SqlDialect;

use super::sql_client_commands::{
    ClientInputSegment, MYSQL_NAMED, Meta, cql_command, dot_command, is_go, is_sqlcmd_exit,
    leading_word_chars, mysql_command, psql_meta, snow_command, sqlcmd_command,
};

/// Lexical facts at one byte of client input: whether it is outside every
/// literal and comment, and whether a statement is partly buffered.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Position {
    pub(super) code: bool,
    pub(super) pending: bool,
}

#[derive(Clone, PartialEq, Eq)]
enum LexState {
    Code,
    Quote(u8),
    Bracket,
    LineComment,
    Block(u32),
    /// Inside a dollar-quoted literal whose opening tag is `len` bytes at `start`.
    Dollar {
        start: usize,
        len: usize,
    },
}

/// The lexical position of every byte of `text` (and one past its end),
/// reading string literals with or without backslash escapes. `delimiter`
/// ends a statement: `;`, or what a mysql `DELIMITER` command set.
pub(super) fn positions(
    text: &str,
    dialect: SqlDialect,
    backslash_escapes: bool,
    delimiter: &str,
) -> Vec<Position> {
    let bytes = text.as_bytes();
    let hash_comments = matches!(
        dialect,
        SqlDialect::Mysql | SqlDialect::BigQuery | SqlDialect::ClickHouse
    );
    let nested_comments = matches!(dialect, SqlDialect::Postgres | SqlDialect::TSql);
    let mut out = Vec::with_capacity(bytes.len() + 1);
    let mut state = LexState::Code;
    let mut pending = false;
    let mut i = 0;
    while i < bytes.len() {
        out.push(Position {
            code: state == LexState::Code,
            pending,
        });
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();
        let mut width = 1;
        match state {
            LexState::Code => match c {
                _ if bytes[i..].starts_with(delimiter.as_bytes()) => {
                    pending = false;
                    width = delimiter.len();
                }
                b'\'' | b'"' | b'`' => {
                    state = LexState::Quote(c);
                    pending = true;
                }
                b'[' if matches!(dialect, SqlDialect::TSql | SqlDialect::Sqlite) => {
                    state = LexState::Bracket;
                    pending = true;
                }
                // MySQL needs whitespace (or the end) after `--`.
                b'-' if next == Some(b'-')
                    && (dialect != SqlDialect::Mysql
                        || bytes
                            .get(i + 2)
                            .is_none_or(|c| c.is_ascii_whitespace() || c.is_ascii_control())) =>
                {
                    state = LexState::LineComment
                }
                b'#' if hash_comments => state = LexState::LineComment,
                b'/' if next == Some(b'/')
                    && matches!(dialect, SqlDialect::Snowflake | SqlDialect::Cql) =>
                {
                    state = LexState::LineComment
                }
                b'/' if next == Some(b'*') => {
                    state = LexState::Block(1);
                    width = 2;
                }
                b'$' => {
                    pending = true;
                    if let Some(len) = dollar_tag(bytes, i, dialect) {
                        state = LexState::Dollar { start: i, len };
                        width = len;
                    }
                }
                c if !c.is_ascii_whitespace() => pending = true,
                _ => {}
            },
            LexState::Quote(quote) => {
                if backslash_escapes && c == b'\\' {
                    width = 2;
                } else if c == quote {
                    if next == Some(quote) {
                        width = 2;
                    } else {
                        state = LexState::Code;
                    }
                }
            }
            LexState::Bracket => {
                if c == b']' {
                    // T-SQL doubles `]` to escape it; SQLite ends at the first.
                    if next == Some(b']') && dialect == SqlDialect::TSql {
                        width = 2;
                    } else {
                        state = LexState::Code;
                    }
                }
            }
            LexState::LineComment => {
                if c == b'\n' {
                    state = LexState::Code;
                }
            }
            LexState::Block(depth) => {
                if c == b'*' && next == Some(b'/') {
                    width = 2;
                    state = if depth == 1 {
                        LexState::Code
                    } else {
                        LexState::Block(depth - 1)
                    };
                } else if nested_comments && c == b'/' && next == Some(b'*') {
                    width = 2;
                    state = LexState::Block(depth + 1);
                }
            }
            LexState::Dollar { start, len } => {
                if bytes[i..].starts_with(&bytes[start..start + len]) {
                    width = len;
                    state = LexState::Code;
                }
            }
        }
        let width = width.min(bytes.len() - i);
        for _ in 1..width {
            out.push(Position {
                code: false,
                pending,
            });
        }
        i += width;
    }
    out.push(Position {
        code: state == LexState::Code,
        pending,
    });
    out
}

/// Whether a Postgres server certainly rejects `text`, a psql `-c` request
/// psql sends as written: a byte outside literals and comments that its
/// lexer or grammar accepts nowhere there. psql's own syntax is the usual
/// cause: `\;`, a `:name` variable, `:{?name}`.
pub(super) fn psql_request_rejected(text: &str) -> bool {
    let bytes = text.as_bytes();
    let readings = escape_readings(SqlDialect::Postgres)
        .iter()
        .map(|escapes| positions(text, SqlDialect::Postgres, *escapes, ";"))
        .collect::<Vec<_>>();
    // Where literals end must not depend on the server's string escaping.
    if readings.iter().any(|reading| *reading != readings[0]) {
        return false;
    }
    let is_word = |c: &u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$') || *c >= 0x80;
    let (mut parens, mut brackets) = (0usize, 0usize);
    for i in (0..bytes.len()).filter(|i| readings[0][*i].code) {
        let previous = i.checked_sub(1).map(|at| &bytes[at]);
        let next = bytes.get(i + 1);
        match bytes[i] {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b'\\' => return true,
            // A colon is an array slice bound inside `[…]`, a JSON key
            // separator inside `(…)`, or part of `::` and `:=`.
            b':' if parens == 0
                && brackets == 0
                && previous != Some(&b':')
                && !matches!(next, Some(b':' | b'=')) =>
            {
                return true;
            }
            // A `$` that continues no identifier and opens no `$n`
            // parameter or dollar quote.
            b'$' if !previous.is_some_and(is_word)
                && !next.is_some_and(u8::is_ascii_digit)
                && dollar_tag(bytes, i, SqlDialect::Postgres).is_none() =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// The leading statements of a sqlite3 SQL argument that run: sqlite3
/// prepares one statement at a time and stops at the first whose text holds
/// a byte its tokenizer rejects (a stray `]`, `\`, a `$` naming no parameter).
pub(super) fn sqlite_argument_runs(text: &str) -> &str {
    let bytes = text.as_bytes();
    let lexed = positions(text, SqlDialect::Sqlite, false, ";");
    let is_word = |c: &u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$') || *c >= 0x80;
    let mut statement = 0;
    for i in (0..bytes.len()).filter(|i| lexed[*i].code) {
        match bytes[i] {
            b';' => statement = i + 1,
            b']' | b'\\' => return &text[..statement],
            b'$' if !i.checked_sub(1).is_some_and(|at| is_word(&bytes[at]))
                && !bytes.get(i + 1).is_some_and(is_word) =>
            {
                return &text[..statement];
            }
            _ => {}
        }
    }
    text
}

/// Length of a dollar-quote opening tag at `i` (`$$`, `$tag$`), where the
/// dialect has dollar quoting and `$` does not continue an identifier.
fn dollar_tag(bytes: &[u8], i: usize, dialect: SqlDialect) -> Option<usize> {
    if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'_' | b'$')) {
        return None;
    }
    match dialect {
        SqlDialect::Snowflake | SqlDialect::Cql => (bytes.get(i + 1) == Some(&b'$')).then_some(2),
        SqlDialect::Postgres => {
            let mut end = i + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let tag = &bytes[i + 1..end];
            (bytes.get(end) == Some(&b'$') && tag.first().is_none_or(|c| !c.is_ascii_digit()))
                .then_some(end - i + 1)
        }
        _ => None,
    }
}

/// Whether a dialect's string literals take backslash escapes: always, never,
/// or under a server setting we cannot see (both readings).
pub(super) fn escape_readings(dialect: SqlDialect) -> &'static [bool] {
    match dialect {
        SqlDialect::TSql | SqlDialect::Cql | SqlDialect::Sqlite => &[false],
        SqlDialect::Snowflake | SqlDialect::BigQuery | SqlDialect::ClickHouse => &[true],
        // MySQL's NO_BACKSLASH_ESCAPES and Postgres's
        // standard_conforming_strings (and its E'' literals) decide it.
        SqlDialect::Mysql | SqlDialect::Postgres | SqlDialect::Generic => &[false, true],
    }
}

/// Split client input into its SQL and the client commands between it,
/// reading string literals with or without backslash escapes.
pub(super) fn client_segments(
    text: &str,
    meta: Meta,
    dialect: SqlDialect,
    backslash_escapes: bool,
    delimiter: &str,
) -> Vec<ClientInputSegment> {
    if meta == Meta::None {
        return vec![ClientInputSegment::Sql(text.to_string())];
    }
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    // Lexical positions are relative to `base`, where lexing last restarted:
    // a client command's arguments are not SQL, so lexing resumes after it.
    let mut base = 0;
    // The mysql statement delimiter in effect, and the one in effect where
    // the SQL being collected starts.
    let mut delimiter = delimiter.to_string();
    let mut start_delimiter = delimiter.clone();
    let mut lexed = positions(text, dialect, backslash_escapes, &delimiter);
    let mut i = 0;
    let mut line_start = true;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\n' {
            line_start = true;
            i += 1;
            continue;
        }
        if line_start && (c == b' ' || c == b'\t' || c == b'\r') {
            i += 1;
            continue;
        }
        let at_line_start = std::mem::replace(&mut line_start, false);
        let eol = text[i..].find('\n').map_or(text.len(), |n| i + n);
        let Some(needs_idle) = command_start(meta, &text[i..eol], at_line_start) else {
            i += 1;
            continue;
        };
        let position = lexed[i - base];
        if !position.code || needs_idle && position.pending {
            i += 1;
            continue;
        }
        let (segments, end) = match meta {
            Meta::Psql => psql_meta(text, i, eol),
            Meta::Mysql | Meta::MysqlNamed => {
                if let Some(new) = mysql_delimiter(&text[i..eol]) {
                    // The command stays in the SQL: the SQL frontend switches
                    // its statement terminator there, as the client does.
                    delimiter = new;
                    i = eol;
                    base = eol;
                    lexed = positions(&text[eol..], dialect, backslash_escapes, &delimiter);
                    continue;
                }
                let (segment, end) = mysql_command(text, i, eol, &delimiter);
                (segment.into_iter().collect(), end)
            }
            Meta::Sqlite => (dot_command(&text[i..eol]).into_iter().collect(), eol),
            Meta::Sqlcmd => (sqlcmd_command(&text[i..eol]), eol),
            Meta::Snow => (snow_command(&text[i..eol]).into_iter().collect(), eol),
            Meta::Cql => {
                let end = (i..eol)
                    .find(|&j| bytes[j] == b';' && lexed[j - base].code)
                    .map_or(eol, |j| j + 1);
                (cql_command(&text[i..end]).into_iter().collect(), end)
            }
            Meta::None => unreachable!(),
        };
        push_sql_segment(&mut out, &text[start..i], &start_delimiter);
        for segment in segments {
            let stop = matches!(
                segment,
                ClientInputSegment::Stop(_) | ClientInputSegment::Quit
            );
            out.push(segment);
            if stop {
                return out;
            }
        }
        start = end;
        i = end;
        base = end;
        start_delimiter = delimiter.clone();
        lexed = positions(&text[end..], dialect, backslash_escapes, &delimiter);
    }
    if out.is_empty() && start == 0 && start_delimiter == ";" {
        return vec![ClientInputSegment::Sql(text.to_string())];
    }
    push_sql_segment(&mut out, &text[start..], &start_delimiter);
    out
}

/// SQL the client sends, collected while `delimiter` ended its statements.
fn push_sql_segment(out: &mut Vec<ClientInputSegment>, sql: &str, delimiter: &str) {
    if sql.trim().is_empty() {
        return;
    }
    out.push(ClientInputSegment::Sql(if delimiter == ";" {
        sql.to_string()
    } else {
        // SQL cut from after a DELIMITER command still splits by it.
        format!("DELIMITER {delimiter}\n{sql}")
    }));
}

/// The delimiter a mysql `DELIMITER x` or `\d x` line sets. None when the
/// line is another command, or the client would unquote or reject the
/// argument (a quoted or missing delimiter, one holding a backslash).
fn mysql_delimiter(line: &str) -> Option<String> {
    let args = match line.strip_prefix("\\d") {
        Some(args) => args,
        None => {
            let word = leading_word_chars(line);
            if !word.eq_ignore_ascii_case("delimiter") {
                return None;
            }
            &line[word.len()..]
        }
    };
    mysql_delimiter_word(args)
}

/// The delimiter `text` names, as a `DELIMITER` argument or a `--delimiter`
/// value. None when the client would unquote or reject it.
pub(super) fn mysql_delimiter_word(text: &str) -> Option<String> {
    let delimiter = text.split_whitespace().next()?;
    (!delimiter.starts_with(['\'', '"', '`']) && !delimiter.contains('\\'))
        .then(|| delimiter.to_string())
}

/// Whether `line` (the rest of a line from a non-blank byte) begins a client
/// command, and if so whether that command needs no statement partly
/// buffered before it.
fn command_start(meta: Meta, line: &str, at_line_start: bool) -> Option<bool> {
    let word = leading_word_chars(line);
    match meta {
        // `\;` puts a `;` in the query buffer; the SQL frontend splits there.
        Meta::Psql => (line.starts_with('\\') && !line.starts_with("\\;")).then_some(false),
        Meta::Mysql | Meta::MysqlNamed => {
            if line.starts_with('\\') {
                Some(false)
            } else {
                (at_line_start && MYSQL_NAMED.contains(&word.to_ascii_lowercase().as_str()))
                    .then_some(meta == Meta::Mysql)
            }
        }
        Meta::Sqlite => (at_line_start && line.starts_with('.')).then_some(true),
        Meta::Sqlcmd => (at_line_start
            && (line.starts_with(':')
                || line.starts_with("!!")
                || is_go(line)
                || is_sqlcmd_exit(line)))
        .then_some(false),
        Meta::Snow => (at_line_start && line.starts_with('!')).then_some(true),
        Meta::Cql => (at_line_start
            && ["SOURCE", "CAPTURE", "COPY"]
                .iter()
                .any(|name| word.eq_ignore_ascii_case(name)))
        .then_some(true),
        Meta::None => None,
    }
}
