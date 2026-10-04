//! The client commands each SQL client layers over its SQL input: psql
//! meta-commands (`\i`, `\c`), mysql commands (`SOURCE`, `USE`), sqlite3 and
//! duckdb dot-commands (`.read`, `.shell`), sqlcmd commands (`:r`, `GO`),
//! SnowSQL `!commands` and cqlsh shell commands. `ClientMetaGrammar` names a client's
//! command grammar, and each parser turns one command into the
//! `ClientInputSegment` it contributes.

use super::{PG_SCHEMES, parse_conn_url, parse_conninfo};

/// The client-command grammar layered over a client's SQL input.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientMetaGrammar {
    None,
    /// psql and cockroach: `\cmd args` anywhere outside a literal, to end of line.
    Psql,
    /// mysql: `\x` anywhere; named commands (`source`, `use`) starting a statement.
    Mysql,
    /// mysql with `-G`: named commands also start any line mid-statement.
    MysqlNamed,
    /// sqlite3 and duckdb: `.cmd args` lines between statements.
    Sqlite,
    /// sqlcmd: `GO` batch separators and `:cmd` lines.
    Sqlcmd,
    /// snowsql and snow sql: `!cmd` lines between statements.
    Snow,
    /// cqlsh: `SOURCE`, `CAPTURE`, `COPY` starting a statement.
    Cql,
}

/// One piece of client input, in execution order.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ClientInputSegment {
    Sql(String),
    /// Run a script file: relative to the including script for `\ir`.
    Include {
        path: String,
        relative: bool,
    },
    /// Later statements run against another connection. `file` is a
    /// database file the client opens (sqlite `.open`).
    Connect {
        database: ConnectionSwitch,
        server: ConnectionSwitch,
        file: Option<String>,
    },
    /// A shell command the client runs (psql `\!`, `.shell`).
    Shell(String),
    /// psql backquoted argument text: a shell command, once psql has
    /// interpolated its variables into it.
    Backquote(String),
    /// psql `\set name value`; `None` is a value Nah cannot name.
    Bind {
        name: String,
        value: Option<String>,
    },
    /// psql `\unset name`.
    Unbind(String),
    /// psql binds variables Nah cannot name (`\gset`).
    BindUnknown,
    /// psql `\if` (true) or `\endif` (false).
    Conditional(bool),
    /// sqlite `.restore ?DB? FILE`: replaces the contents of the connected
    /// database, or of the attached schema `DB`, with FILE's.
    Restore(Option<String>),
    /// A client command this model does not interpret.
    Opaque(String),
    /// Nothing after this command can be analyzed.
    Stop(String),
    /// The client quits here; no later input runs.
    Quit,
}

/// How a connection switch changes one part of the connection.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ConnectionSwitch {
    Keep,
    Set(String),
    /// The client names a value we cannot recover (a variable, a named
    /// connection from its configuration).
    Unknown,
}

impl ConnectionSwitch {
    /// A command word naming a value, where `-` or absence keeps it.
    pub(super) fn word(word: Option<&&str>) -> Self {
        match word {
            None | Some(&"-") => ConnectionSwitch::Keep,
            Some(word) if word.contains(['`', '\'', '"', '$']) || word.starts_with(':') => {
                ConnectionSwitch::Unknown
            }
            Some(word) => ConnectionSwitch::Set(word.trim_matches('`').to_string()),
        }
    }
}

/// The leading run of word characters, if a word boundary follows it.
pub(super) fn leading_word_chars(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(text.len());
    let rest = &text[end..];
    if rest.is_empty() || rest.starts_with([' ', '\t', '\r', ';']) {
        &text[..end]
    } else {
        ""
    }
}

/// A command's first argument: a quoted string, or text up to whitespace.
/// None when it is absent or the client would expand it (variables,
/// backquoted commands, escapes).
fn first_arg(args: &str) -> Option<String> {
    let args = args.trim_start();
    let arg = match args.as_bytes().first()? {
        quote @ (b'\'' | b'"') => {
            let body = &args[1..];
            let close = body.find(*quote as char)?;
            &body[..close]
        }
        _ => args
            .split(|c: char| c.is_whitespace() || c == ';')
            .next()
            .unwrap_or_default(),
    };
    (!arg.is_empty() && !arg.contains(['`', '\\']) && !arg.starts_with(':') && !arg.contains("$("))
        .then(|| arg.to_string())
}

/// A script include command (`\i`, `SOURCE`, `.read`, `:r`): the include of
/// its first argument, or opaque input when no path is written. `client`
/// names the command in that boundary detail.
pub(super) fn include_segment(args: &str, relative: bool, client: &str) -> ClientInputSegment {
    match first_arg(args) {
        Some(path) => ClientInputSegment::Include { path, relative },
        None => ClientInputSegment::Opaque(format!(
            "{client} include path is not statically recoverable"
        )),
    }
}

/// The host a server argument names first: sqlcmd's `tcp:host,port` and
/// `host\instance`, or the first of a libpq host list (`a,b`).
pub(super) fn host_name(text: &str) -> String {
    let text = ["tcp:", "np:", "lpc:"]
        .iter()
        .find_map(|prefix| text.strip_prefix(prefix))
        .unwrap_or(text);
    text.split([',', '\\']).next().unwrap_or(text).to_string()
}

/// psql meta-commands whose argument is the whole rest of the line.
const PSQL_LINE_COMMANDS: &[&str] = &["!", "copy", "ef", "ev", "h", "help", "sf", "sv"];

/// A psql (or cockroach sql) meta-command starting at `text[i]`, a
/// backslash, with `eol` the end of its line: its segments, and where input
/// resumes. Arguments end at the next unquoted backslash, which starts
/// another command; `\\` returns to SQL.
pub(super) fn psql_meta(text: &str, i: usize, eol: usize) -> (Vec<ClientInputSegment>, usize) {
    let rest = &text[i + 1..eol];
    if rest.starts_with('\\') {
        return (Vec::new(), i + 2);
    }
    let name_len = if rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
        rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '+'))
            .unwrap_or(rest.len())
    } else {
        rest.chars().next().map_or(0, char::len_utf8)
    };
    let name = rest[..name_len].trim_end_matches('+');
    let start = i + 1 + name_len;
    let (end, shells) = if PSQL_LINE_COMMANDS.contains(&name) {
        (eol, Vec::new())
    } else {
        psql_arguments(text, start, eol)
    };
    let resume = if text[end..].starts_with("\\\\") {
        end + 2
    } else {
        end
    };
    // psql runs backquoted argument text as a shell command first.
    let mut segments = shells
        .into_iter()
        .map(ClientInputSegment::Backquote)
        .collect::<Vec<_>>();
    segments.extend(psql_command(name, text[start..end].trim()));
    (segments, resume)
}

/// Where a psql meta-command's arguments starting at `start` end (the next
/// backslash outside quotes, or `eol`), and the backquoted shell commands
/// among them.
fn psql_arguments(text: &str, start: usize, eol: usize) -> (usize, Vec<String>) {
    let bytes = text.as_bytes();
    let mut shells = Vec::new();
    let mut quote = None;
    let mut open = 0;
    let mut i = start;
    while i < eol {
        match (quote, bytes[i]) {
            (None, b'\\') => break,
            (None, c @ (b'\'' | b'"' | b'`')) => {
                quote = Some(c);
                open = i + 1;
            }
            (Some(b'\''), b'\\') => i += 1,
            (Some(b'`'), b'`') => {
                shells.push(text[open..i].to_string());
                quote = None;
            }
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
        i += 1;
    }
    let end = i.min(eol);
    if quote == Some(b'`') {
        shells.push(text[open..end].to_string());
    }
    (end, shells)
}

/// The segment a psql meta-command `name` with arguments `args` contributes.
fn psql_command(name: &str, args: &str) -> Option<ClientInputSegment> {
    match name {
        "i" | "include" => Some(include_segment(args, false, "psql")),
        "ir" | "include_relative" => Some(include_segment(args, true, "psql")),
        "c" | "connect" => Some(psql_connect(args)),
        "cd" => Some(ClientInputSegment::Stop(
            "psql \\cd changes the directory later scripts resolve against".into(),
        )),
        "g" | "gx" | "s" if !args.is_empty() => Some(ClientInputSegment::Opaque(format!(
            "psql \\{name} writes to a file or command"
        ))),
        "!" if args.is_empty() => Some(ClientInputSegment::Opaque(
            "psql \\! starts an interactive shell".into(),
        )),
        "!" => Some(ClientInputSegment::Shell(args.to_string())),
        "set" => psql_set(args),
        "unset" => args
            .split_whitespace()
            .next()
            .map(|name| ClientInputSegment::Unbind(name.to_string())),
        // These bind variables to a query result, typed input or the
        // environment.
        "gset" | "prompt" | "getenv" => Some(ClientInputSegment::BindUnknown),
        "if" => Some(ClientInputSegment::Conditional(true)),
        "endif" => Some(ClientInputSegment::Conditional(false)),
        _ if PSQL_INERT.contains(&name) || name.starts_with('d') => None,
        _ => Some(ClientInputSegment::Opaque(format!(
            "psql meta-command \\{name} is not modeled"
        ))),
    }
}

/// psql `\\c [dbname [username [host [port]]]]`, or a connection string.
fn psql_connect(args: &str) -> ClientInputSegment {
    let words = args
        .split_whitespace()
        .filter(|word| !word.starts_with("-reuse-previous"))
        .collect::<Vec<_>>();
    let Some(first) = words.first() else {
        return connect_segment(ConnectionSwitch::Keep, ConnectionSwitch::Keep);
    };
    if !first.contains(['=', ':']) {
        return connect_segment(
            ConnectionSwitch::word(words.first()),
            ConnectionSwitch::word(words.get(2)),
        );
    }
    let conninfo = words.join(" ");
    let conninfo = conninfo.trim_matches(['\'', '"']);
    match parse_conn_url(conninfo, PG_SCHEMES).or_else(|| parse_conninfo(conninfo)) {
        Some((server, database)) => connect_segment(
            database.map_or(ConnectionSwitch::Keep, ConnectionSwitch::Set),
            server.map_or(ConnectionSwitch::Keep, ConnectionSwitch::Set),
        ),
        None => connect_segment(ConnectionSwitch::Unknown, ConnectionSwitch::Unknown),
    }
}

/// psql `\set name [value ...]`, which concatenates its values. A value psql
/// would expand or unescape (a backquoted command, another variable, a
/// backslash) binds the name to a value Nah cannot name; a bare `\set` only
/// lists the variables.
fn psql_set(args: &str) -> Option<ClientInputSegment> {
    let name = args.split_whitespace().next()?;
    let mut rest = args[name.len()..].trim_start();
    let mut value = String::new();
    while !rest.is_empty() {
        // One word: text up to whitespace, or a single-quoted string.
        let (word, after) = match rest.strip_prefix('\'') {
            Some(quoted) => match quoted.split_once('\'') {
                Some(split) => split,
                None => (quoted, ""),
            },
            None => {
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == '\'')
                    .unwrap_or(rest.len());
                rest.split_at(end)
            }
        };
        if word.contains(['"', '`', '\\', ':']) {
            return Some(ClientInputSegment::Bind {
                name: name.to_string(),
                value: None,
            });
        }
        value.push_str(word);
        rest = after.trim_start();
    }
    Some(ClientInputSegment::Bind {
        name: name.to_string(),
        value: Some(value),
    })
}

/// A connection switch that opens no database file.
fn connect_segment(database: ConnectionSwitch, server: ConnectionSwitch) -> ClientInputSegment {
    ClientInputSegment::Connect {
        database,
        server,
        file: None,
    }
}

/// psql commands that change only client display or variables, or read the
/// catalog (`\d...`).
const PSQL_INERT: &[&str] = &[
    "echo",
    "qecho",
    "warn",
    "pset",
    "timing",
    "x",
    "a",
    "t",
    "q",
    "quit",
    "conninfo",
    "encoding",
    "f",
    "H",
    "html",
    "T",
    "C",
    "errverbose",
    "elif",
    "else",
    "p",
    "print",
    "r",
    "reset",
    "g",
    "gx",
    "s",
    "gdesc",
    "crosstabview",
    "l",
    "list",
    "z",
    "h",
    "help",
    "?",
    "copyright",
    "sf",
    "sv",
    "watch",
    "\\",
];

/// mysql commands named by a word at the start of a statement.
pub(super) const MYSQL_NAMED: &[&str] = &[
    "source",
    "use",
    "delimiter",
    "system",
    "connect",
    "tee",
    "pager",
    "edit",
    "exit",
    "quit",
    "go",
    "ego",
    "print",
    "status",
    "help",
    "warnings",
    "nowarning",
    "charset",
    "rehash",
    "clear",
    "prompt",
    "notee",
    "nopager",
    "resetconnection",
    "query_attributes",
    "ssl_session_data_print",
];

/// A mysql client command at `i`, and where its text ends. Short forms
/// (`\.`) may appear mid-line; most take arguments up to the statement
/// `delimiter` or end of line.
pub(super) fn mysql_command(
    text: &str,
    i: usize,
    eol: usize,
    delimiter: &str,
) -> (Option<ClientInputSegment>, usize) {
    // A command's parameters end at the delimiter; mysql reads the rest of
    // the line as SQL.
    let delimited = text[i..eol]
        .find(delimiter)
        .map_or(eol, |n| i + n + delimiter.len());
    let line = &text[i..eol];
    let backslash = line.starts_with('\\');
    let (name, args) = match line.strip_prefix('\\') {
        Some(rest) => {
            let Some(short) = rest.chars().next() else {
                return (None, delimited);
            };
            let name = match short {
                '.' => "source",
                'u' => "use",
                'd' => "delimiter",
                '!' => "system",
                'r' => "connect",
                'T' => "tee",
                'P' => "pager",
                'e' => "edit",
                'C' | 'R' | 'h' | '?' => "help",
                'g' | 'G' | 'c' | 'p' | 'q' | 's' | 't' | 'n' | 'W' | 'w' | '#' | 'x' => {
                    return (None, i + 1 + short.len_utf8());
                }
                _ => {
                    return (
                        Some(ClientInputSegment::Opaque(format!(
                            "mysql client command \\{short} is not modeled"
                        ))),
                        delimited,
                    );
                }
            };
            (name.to_string(), &rest[short.len_utf8()..])
        }
        None => {
            let word = leading_word_chars(line);
            (word.to_ascii_lowercase(), &line[word.len()..])
        }
    };
    if name == "system" {
        // The shell gets the whole rest of the line, `;` included. After
        // `\\!` mysql resumes SQL past the delimiter; `system` takes the line.
        let command = args.trim();
        let segment = if command.is_empty() {
            ClientInputSegment::Opaque("mysql system without a command".into())
        } else {
            ClientInputSegment::Shell(command.to_string())
        };
        return (Some(segment), if backslash { delimited } else { eol });
    }
    let args = args.split(delimiter).next().unwrap_or_default().trim();
    let segment = match name.as_str() {
        "source" => Some(include_segment(args, false, "mysql")),
        "use" | "connect" => {
            // `use db`, `connect [db [host]]`.
            let words = args.split_whitespace().collect::<Vec<_>>();
            let host = if name == "connect" {
                ConnectionSwitch::word(words.get(1))
            } else {
                ConnectionSwitch::Keep
            };
            Some(connect_segment(ConnectionSwitch::word(words.first()), host))
        }
        "delimiter" => Some(ClientInputSegment::Stop(
            "mysql DELIMITER changes how later statements split".into(),
        )),
        "tee" | "pager" | "edit" => Some(ClientInputSegment::Opaque(format!(
            "mysql {name} sends output to a file or command"
        ))),
        _ => None,
    };
    (segment, delimited)
}

/// A sqlite3 (or duckdb) dot-command line.
pub(super) fn dot_command(line: &str) -> Option<ClientInputSegment> {
    let rest = &line[1..];
    let name_len = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, args) = (dot_name(&rest[..name_len]), rest[name_len..].trim());
    match name {
        "read" if args.starts_with('|') || args.starts_with("'|") => Some(
            ClientInputSegment::Opaque("dot-command .read runs a shell command".into()),
        ),
        "read" => Some(include_segment(args, false, "dot-command .read")),
        "open" => {
            let file = args
                .split_whitespace()
                .rfind(|word| !word.starts_with('-'))
                .map(|word| word.trim_matches(['\'', '"']).to_string());
            Some(ClientInputSegment::Connect {
                database: file
                    .clone()
                    .map_or(ConnectionSwitch::Unknown, ConnectionSwitch::Set),
                server: ConnectionSwitch::Keep,
                file,
            })
        }
        "connection" if !args.is_empty() => Some(connect_segment(
            ConnectionSwitch::Unknown,
            ConnectionSwitch::Keep,
        )),
        "shell" | "system" if !args.is_empty() => Some(match sqlite_dot_shell_command(args) {
            Some(command) => ClientInputSegment::Shell(command),
            None => ClientInputSegment::Opaque(format!(
                "dot-command .{name} runs a shell command sqlite rebuilds from escaped arguments"
            )),
        }),
        "cd" => Some(ClientInputSegment::Stop(
            "dot-command .cd changes the directory later scripts resolve against".into(),
        )),
        // sqlite unquotes the arguments, so only plain words are read.
        "restore" if !args.contains(['\'', '"', '\\']) => {
            match args.split_whitespace().collect::<Vec<_>>()[..] {
                [_] => Some(ClientInputSegment::Restore(None)),
                [schema, _] => Some(ClientInputSegment::Restore(Some(schema.to_string()))),
                _ => Some(ClientInputSegment::Opaque(
                    "dot-command .restore arguments are not modeled".into(),
                )),
            }
        }
        _ if DOT_INERT.contains(&name) => None,
        _ => Some(ClientInputSegment::Opaque(format!(
            "dot-command .{name} is not modeled"
        ))),
    }
}

/// The dot-command an abbreviated name runs, among those this model
/// interprets: sqlite3 compares only the letters given, in a fixed order
/// that leaves each of these a shortest prefix.
fn dot_name(name: &str) -> &str {
    [
        ("shell", 2),
        ("system", 2),
        ("read", 3),
        ("restore", 3),
        ("open", 2),
    ]
    .into_iter()
    .find(|(full, shortest)| name.len() >= *shortest && full.starts_with(name))
    .map_or(name, |(full, _)| full)
}

/// The command line `.shell` hands the shell: sqlite3 splits the arguments
/// at whitespace, strips one level of `'…'` or `"…"` from each, and joins
/// them with spaces, wrapping an argument that holds a space in double
/// quotes. None when a `"…"` argument holds a backslash escape, which
/// sqlite3 resolves first.
fn sqlite_dot_shell_command(args: &str) -> Option<String> {
    let mut words = Vec::new();
    let mut rest = args.trim_start();
    while let Some(first) = rest.chars().next() {
        let (word, after) = if first == '\'' || first == '"' {
            let body = &rest[1..];
            let close = body.find(first).unwrap_or(body.len());
            if first == '"' && body[..close].contains('\\') {
                return None;
            }
            (&body[..close], body.get(close + 1..).unwrap_or_default())
        } else {
            rest.split_at(rest.find(char::is_whitespace).unwrap_or(rest.len()))
        };
        words.push(if word.contains(' ') {
            format!("\"{word}\"")
        } else {
            word.to_string()
        });
        rest = after.trim_start();
    }
    Some(words.join(" "))
}

/// Dot-commands that change only display or settings, or read the schema.
const DOT_INERT: &[&str] = &[
    "mode",
    "headers",
    "header",
    "tables",
    "table",
    "schema",
    "indexes",
    "indices",
    "timer",
    "print",
    "quit",
    "exit",
    "bail",
    "echo",
    "width",
    "separator",
    "nullvalue",
    "databases",
    "dump",
    "show",
    "help",
    "changes",
    "eqp",
    "explain",
    "fullschema",
    "stats",
    "lint",
    "sha3sum",
    "prompt",
    "timeout",
    "limit",
    "scanstats",
    "binary",
    "crnl",
    "connection",
    "progress",
    "dbinfo",
    "parameter",
    "maxrows",
    "maxwidth",
    "columns",
    "rows",
    "highlight",
];

/// A line that is sqlcmd's batch separator: `GO [count]`.
pub(super) fn is_go(line: &str) -> bool {
    let line = line.split("--").next().unwrap_or_default().trim();
    let Some(rest) = line.get(..2).filter(|go| go.eq_ignore_ascii_case("go")) else {
        return false;
    };
    let count = line[rest.len()..].trim();
    (line.len() == 2 || line[2..].starts_with([' ', '\t']))
        && count.chars().all(|c| c.is_ascii_digit())
}

/// A line that is sqlcmd's `EXIT` or `QUIT`, which need no colon: bare, or
/// with a parenthesized argument.
pub(super) fn is_sqlcmd_exit(line: &str) -> bool {
    line.get(..4)
        .is_some_and(|word| word.eq_ignore_ascii_case("exit") || word.eq_ignore_ascii_case("quit"))
        && (line[4..].trim().is_empty() || line[4..].trim_start().starts_with('('))
}

/// A sqlcmd command line: `GO`, `:r file`, `:setvar`, `!! cmd`, and so on.
pub(super) fn sqlcmd_command(line: &str) -> Vec<ClientInputSegment> {
    if is_go(line) {
        return Vec::new();
    }
    let rest = line
        .strip_prefix(':')
        .unwrap_or(line)
        .trim_start_matches(' ');
    if let Some(command) = rest.strip_prefix("!!") {
        return vec![match command.trim() {
            "" => ClientInputSegment::Opaque("sqlcmd !! without a command".into()),
            command => ClientInputSegment::Shell(command.to_string()),
        }];
    }
    let name_len = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let (name, args) = (
        rest[..name_len].to_ascii_lowercase(),
        rest[name_len..].trim(),
    );
    let segment = match name.as_str() {
        "r" => include_segment(args, false, "sqlcmd :r"),
        // `:connect server[\\instance] [-l timeout] [-U user [-P password]]`
        // logs in to that server's default database.
        "connect" => connect_segment(
            ConnectionSwitch::Unknown,
            match ConnectionSwitch::word(args.split_whitespace().next().as_ref()) {
                ConnectionSwitch::Set(server) => ConnectionSwitch::Set(host_name(&server)),
                _ => ConnectionSwitch::Unknown,
            },
        ),
        "out" | "error" | "perftrace"
            if !["stdout", "stderr"].contains(&args.to_ascii_lowercase().as_str()) =>
        {
            ClientInputSegment::Opaque(format!("sqlcmd :{name} writes to a file"))
        }
        // `EXIT(query)` runs the query, then quits with its result.
        "exit" if args.starts_with('(') && args != "()" => {
            return match args.strip_prefix('(').and_then(|q| q.strip_suffix(')')) {
                Some(query) => vec![
                    ClientInputSegment::Sql(query.to_string()),
                    ClientInputSegment::Quit,
                ],
                None => vec![ClientInputSegment::Stop("sqlcmd :exit runs a query".into())],
            };
        }
        // `QUIT` is documented without a query, and go-sqlcmd rejects one;
        // what the ODBC sqlcmd does with an argument is not established.
        "quit" if !args.is_empty() => {
            ClientInputSegment::Stop("sqlcmd quit with an argument is not modeled".into())
        }
        "exit" | "quit" => ClientInputSegment::Quit,
        "setvar" | "on" | "out" | "error" | "perftrace" | "reset" | "list" | "listvar"
        | "serverlist" | "xml" | "help" => return Vec::new(),
        _ => ClientInputSegment::Opaque(format!("sqlcmd command :{name} is not modeled")),
    };
    vec![segment]
}

/// A SnowSQL or Snowflake CLI `!command` line.
pub(super) fn snow_command(line: &str) -> Option<ClientInputSegment> {
    let rest = &line[1..];
    let name_len = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let (name, args) = (
        rest[..name_len].to_ascii_lowercase(),
        rest[name_len..].trim().trim_end_matches(';'),
    );
    match name.as_str() {
        "source" | "load" => Some(include_segment(args, false, "!source")),
        "system" if args.is_empty() => Some(ClientInputSegment::Opaque(
            "!system without a command".into(),
        )),
        "system" => Some(ClientInputSegment::Shell(args.to_string())),
        "spool" | "edit" => Some(ClientInputSegment::Opaque(format!(
            "!{name} writes to a file or runs an editor"
        ))),
        // A named connection from the client's configuration.
        "connect" => Some(connect_segment(
            ConnectionSwitch::Unknown,
            ConnectionSwitch::Unknown,
        )),
        "set" | "print" | "define" | "variables" | "options" | "queries" | "result" | "abort"
        | "quit" | "exit" | "disconnect" | "help" | "rehash" | "pause" => None,
        _ => Some(ClientInputSegment::Opaque(format!(
            "!{name} is not modeled"
        ))),
    }
}

/// A cqlsh shell command that starts a statement.
pub(super) fn cql_command(statement: &str) -> Option<ClientInputSegment> {
    let word = leading_word_chars(statement);
    let args = statement[word.len()..].trim().trim_end_matches(';');
    if word.eq_ignore_ascii_case("SOURCE") {
        return Some(include_segment(args, false, "cqlsh SOURCE"));
    }
    Some(ClientInputSegment::Opaque(format!(
        "cqlsh {} reads or writes a file",
        word.to_ascii_uppercase()
    )))
}
