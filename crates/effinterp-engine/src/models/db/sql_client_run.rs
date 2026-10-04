//! Running one SQL client invocation: scanning its argv against a
//! `ClientSpec`, recovering the connection, then executing its SQL input in
//! client order, following includes and connection switches.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, Effect, Modality, Operation, ProvenanceRef, ResourceExpr,
    ResourceIdentity, SqlConnection, SqlDialect, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_node, opaque_source_with_provenance, unrecognized_arguments_boundary,
};
use crate::models::{InvocationCtx, source_refusal_detail};
use crate::nest::SourceResolution;
use crate::paths::parent_dir;
use crate::value::unresolved_resource;
use crate::word::Word;

use super::sql_client_commands::{
    ClientInputSegment, Meta, Switch, dot_command, host_name, psql_meta,
};
use super::sql_client_input::{
    client_segments, escape_readings, mysql_delimiter_word, positions, psql_request_rejected,
    sqlite_argument_runs,
};
use super::sql_client_spec::{CLIENT, ClientSpec, Operands, Substitution};
use super::{
    CLIENT_DOMAINS, MAX_INCLUDE_DEPTH, client_file_operand_effect, connect_effect, database_effect,
    db_gap, endpoint_effect, parse_conn_url, parse_conninfo, unrecognized_operands,
};

/// A unit of SQL input, in the order the client runs it.
pub(in crate::models) enum SqlClientInput {
    Sql(Word, usize),
    File(Word, usize),
    Stdin,
}

/// The argv words a client scans, with attached-only values folded into the
/// bare flag so the scanner does not read `-pSECRET` (or `-BpSECRET`) as a
/// cluster.
pub(super) fn client_words(argv: &[Word], spec: &ClientSpec) -> Vec<Word> {
    let switches = spec.known_flags();
    argv.iter()
        .map(|word| {
            let head = word.literal_prefix();
            if let Some(flag) = spec.attached_only.iter().find(|flag| {
                flag.starts_with("--") && (head == **flag || head.starts_with(&format!("{flag}=")))
            }) {
                return Word::literal(*flag);
            }
            let Some(cluster) = head.strip_prefix('-').filter(|rest| !rest.starts_with('-')) else {
                return word.clone();
            };
            // Switches may precede the attached-only flag in a short cluster.
            for (at, c) in cluster.char_indices() {
                let flag = format!("-{c}");
                if spec.attached_only.contains(&flag.as_str()) {
                    return Word::literal(&head[..at + 2]);
                }
                if !switches.contains(&flag.as_str()) {
                    break;
                }
            }
            word.clone()
        })
        .collect()
}

/// A spec's value flags and valueless flags, as the scanner takes them.
type FlagLists = (Vec<&'static str>, Vec<&'static str>);

pub(super) fn flag_lists(spec: &ClientSpec) -> FlagLists {
    (spec.value_flags(), spec.known_flags())
}

pub(super) fn scan_client<'w>(
    words: &'w [Word],
    flags: &'w FlagLists,
    spec: &ClientSpec,
) -> Scanned<'w> {
    let mut scanned = scan_with_value_indices(
        words,
        &FlagSpec {
            allow_abbreviation: false,
            value_flags: &flags.0,
            known_flags: &flags.1,
        },
        true,
    );
    if spec.setting_options {
        scanned.unknown_flags.retain(|(index, name)| {
            !(name.starts_with("--")
                && words[*index as usize]
                    .as_literal()
                    .is_some_and(|text| text.contains('=')))
        });
    }
    scanned
}

/// Run one SQL client whose options start after `argv[offset]`.
pub(super) fn sql_client(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    spec: &ClientSpec,
    offset: usize,
) {
    let words = client_words(&ctx.argv[offset..], spec);
    let flags = flag_lists(spec);
    let scanned = scan_client(&words, &flags, spec);
    let at = |index: u32| index as usize + offset;
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    if scanned.has(spec.help) && scanned.unknown_flags.is_empty() {
        return;
    }
    if !scanned.unknown_flags.is_empty() {
        for domain in CLIENT_DOMAINS {
            builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
        }
        let unknown = scanned
            .unknown_flags
            .iter()
            .map(|(index, name)| (at(*index) as u32, name.clone()))
            .collect::<Vec<_>>();
        unrecognized_arguments_boundary(builder, model_node, CLIENT_DOMAINS, &unknown);
    }

    let mut conn = SqlConnection::default();
    let mut port: Option<u16> = None;
    let (mut server_index, mut database_index, mut port_index) = (None, None, None);
    // Programs with their rank: the client runs startup files, then startup
    // SQL, then the rest, each group in argv order.
    let mut programs = Vec::new();
    let mut account = None;
    let mut region = None;
    let mut named_connection = None;
    let mut outputs = Vec::new();
    let mut exits = scanned.has(spec.no_stdin);
    let mut substitute = true;
    let mut variables = BTreeMap::new();
    let mut variables_unknown = false;
    let mut delimiter = ";".to_string();
    for flag in &scanned.flags {
        if flag.name == "-x" && spec.substitution == Substitution::Sqlcmd {
            substitute = false;
        }
        if spec.substitution == Substitution::Psql
            && ["-v", "--set", "--variable"].contains(&flag.name)
        {
            // `-v name=value` binds a variable; `-v name` unsets it.
            match flag.value.as_ref().and_then(|value| value.as_literal()) {
                Some(binding) => match binding.split_once('=') {
                    Some((name, value)) => {
                        variables.insert(name.to_string(), Some(value.to_string()));
                    }
                    None => {
                        variables.remove(binding);
                    }
                },
                None => variables_unknown = true,
            }
        }
        let (Some(value), Some(index)) = (&flag.value, flag.value_index) else {
            continue;
        };
        let index = at(index);
        let name = flag.name;
        let literal = value.as_literal();
        if spec.sql.contains(&name) || spec.startup_sql.contains(&name) {
            exits |= spec.sql.contains(&name);
            let rank = if spec.sql.contains(&name) { 2 } else { 1 };
            programs.push((rank, SqlClientInput::Sql(value.clone(), index)));
        } else if spec.files.contains(&name) || spec.startup_files.contains(&name) {
            exits |= spec.files.contains(&name);
            let rank = if spec.files.contains(&name) { 2 } else { 0 };
            match literal {
                Some("-") if spec.dash_is_stdin => programs.push((rank, SqlClientInput::Stdin)),
                Some(list) if spec.comma_files => programs.extend(
                    list.split(',')
                        .map(|path| (rank, SqlClientInput::File(Word::literal(path), index))),
                ),
                _ => programs.push((rank, SqlClientInput::File(value.clone(), index))),
            }
        } else if spec.account.contains(&name) {
            account = Some((index, literal));
        } else if spec.region.contains(&name) {
            region = Some(literal);
        } else if spec.named_connection.contains(&name) {
            named_connection = Some(index);
        } else if spec.host.contains(&name) {
            conn.server = literal.map(host_name);
            server_index = Some(index);
        } else if spec.port.contains(&name) {
            port = literal.and_then(|value| value.parse().ok());
            port_index = Some(index);
        } else if spec.db.contains(&name) {
            database_index = Some(index);
            conn.database = literal.map(str::to_string);
            if let Some((server, database)) = literal.and_then(|text| {
                parse_conn_url(text, spec.url_schemes).or_else(|| {
                    (spec.dialect == SqlDialect::Postgres)
                        .then(|| parse_conninfo(text))
                        .flatten()
                })
            }) {
                conn.database = database;
                if server.is_some() {
                    conn.server = server;
                    server_index = Some(index);
                }
            }
        } else if spec.url.contains(&name) {
            if let Some((server, database)) =
                literal.and_then(|text| parse_conn_url(text, spec.url_schemes))
            {
                conn.server = server;
                conn.database = database;
            }
            server_index = Some(index);
            database_index = Some(index);
        } else if spec.output.contains(&name) {
            outputs.push((index, value.clone()));
        } else if spec.delimiter.contains(&name) {
            match literal.and_then(mysql_delimiter_word) {
                Some(word) => delimiter = word,
                None => db_gap(
                    builder,
                    &[model_node],
                    CLIENT_DOMAINS,
                    "mysql --delimiter changes how statements split",
                ),
            }
        } else if let Some((_, detail)) =
            spec.unmodeled_values.iter().find(|(flag, _)| *flag == name)
        {
            db_gap(builder, &[model_node], CLIENT_DOMAINS, detail);
        } else if name == "--enable-templating" && literal == Some("NONE") {
            substitute = false;
        }
    }

    let mut db_file = None;
    let mut extra = Vec::new();
    let mut symbolic = false;
    for (n, (index, word)) in scanned.operands.iter().enumerate() {
        let index = at(*index);
        let literal = word.as_literal();
        symbolic |= literal.is_none();
        match spec.operands {
            Operands::Database { max } => {
                if let Some((server, database)) =
                    literal.and_then(|text| parse_conn_url(text, spec.url_schemes))
                {
                    conn.server = server.or(conn.server);
                    conn.database = database;
                    server_index = Some(index);
                    database_index = Some(index);
                } else if n == 0 && database_index.is_none() {
                    database_index = Some(index);
                    conn.database = literal.map(str::to_string);
                    if let Some((server, database)) = literal
                        .filter(|_| spec.dialect == SqlDialect::Postgres)
                        .and_then(parse_conninfo)
                    {
                        conn.database = database;
                        if server.is_some() {
                            conn.server = server;
                            server_index = Some(index);
                        }
                    }
                } else if n >= max {
                    extra.push(literal.unwrap_or("?"));
                }
            }
            Operands::FileThenSql if n == 0 => db_file = Some((index, *word)),
            Operands::FileThenSql => {
                exits = true;
                programs.push((2, SqlClientInput::Sql((*word).clone(), index)));
            }
            Operands::HostPort if n == 0 => {
                conn.server = literal.map(str::to_string);
                server_index = Some(index);
            }
            Operands::HostPort if n == 1 => {
                port = literal.and_then(|value| value.parse().ok());
                port_index = Some(index);
            }
            Operands::Url => {
                match literal.and_then(|text| parse_conn_url(text, spec.url_schemes)) {
                    Some((server, database)) => {
                        conn.server = server;
                        conn.database = database;
                        server_index = Some(index);
                        database_index = Some(index);
                    }
                    None => extra.push(literal.unwrap_or("?")),
                }
            }
            Operands::HostPort | Operands::None => extra.push(literal.unwrap_or("?")),
        }
    }
    if symbolic {
        db_gap(
            builder,
            &[model_node],
            CLIENT_DOMAINS,
            "unresolved SQL client option or connection operand",
        );
    }
    unrecognized_operands(builder, model_node, &extra);
    if let Some((index, account)) = account.filter(|_| server_index.is_none()) {
        // An account identifier with a dot already names its region.
        // An empty or unexpanded account or region leaves the server
        // unresolved; snowsql then falls back to its configured account.
        let account = account.filter(|account| !account.is_empty());
        conn.server = match (account, region) {
            (Some(account), None) => Some(format!("{account}.snowflakecomputing.com")),
            (Some(account), Some(_)) if account.contains('.') => {
                Some(format!("{account}.snowflakecomputing.com"))
            }
            (Some(account), Some(Some(region))) if !region.is_empty() => {
                Some(format!("{account}.{region}.snowflakecomputing.com"))
            }
            _ => None,
        };
        server_index = Some(index);
    }
    if let Some(index) = named_connection.filter(|_| server_index.is_none()) {
        // The configuration file names the account we cannot read.
        db_gap(
            builder,
            &[model_node],
            &["database", "network"],
            "named connection from the client's configuration",
        );
        conn.server = None;
        server_index = Some(index);
    }

    let endpoint_source_indices = [server_index, port_index]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let symbolic_endpoint = server_index.is_some() && conn.server.is_none()
        || port_index.is_some_and(|index| ctx.argv[index].as_literal().is_none());
    let endpoint = if symbolic_endpoint {
        None
    } else if server_index.is_none() {
        spec.default_host.map(str::to_string)
    } else {
        conn.server.clone()
    };
    connect_effect(
        builder,
        ctx,
        model_node,
        &endpoint,
        port,
        spec.scheme,
        &endpoint_source_indices,
    );
    if let Some((index, word)) = db_file {
        // The client opens the database file first; any statement may then
        // write it (below, after the scripts it reads).
        client_file_operand_effect(
            builder,
            ctx,
            model_node,
            index as u32,
            word,
            "filesystem.read",
        );
        conn.database = word.as_literal().map(str::to_string);
        database_index = Some(index);
    }
    for (index, word) in outputs {
        if word.literal_prefix().starts_with('|') {
            db_gap(
                builder,
                &[model_node],
                CLIENT_DOMAINS,
                "client output is piped to a command",
            );
        } else {
            client_file_operand_effect(
                builder,
                ctx,
                model_node,
                index as u32,
                &word,
                "filesystem.write",
            );
        }
    }

    let context = if ctx.tracks_host_context_environment() {
        [server_index, database_index]
            .into_iter()
            .flatten()
            .collect()
    } else {
        Vec::new()
    };
    // mysql -G recognizes named commands even with a statement buffered;
    // the last of -G and --skip-named-commands wins.
    let named_commands = scanned
        .flags
        .iter()
        .rev()
        .find_map(|flag| match flag.name {
            "-G" | "--named-commands" => Some(true),
            "--skip-named-commands" => Some(false),
            _ => None,
        })
        .unwrap_or(false);
    let mut run = Run {
        ctx,
        model_node,
        spec,
        meta: if spec.meta == Meta::Mysql && named_commands {
            Meta::MysqlNamed
        } else {
            spec.meta
        },
        conn,
        context,
        substitute,
        variables,
        variables_unknown,
        conditionals: 0,
        delimiter,
        includes: Vec::new(),
        stopped: false,
    };
    let reads_stdin = programs
        .iter()
        .any(|(_, program)| matches!(program, SqlClientInput::Stdin));
    programs.sort_by_key(|(rank, _)| *rank);
    for (_, program) in programs {
        run.program(builder, program);
    }
    if !(reads_stdin || exits) {
        if spec.stdin_flags.is_empty() || scanned.has(spec.stdin_flags) {
            run.stdin(builder);
        } else {
            db_gap(
                builder,
                &[model_node],
                &["database"],
                "interactive SQL session",
            );
        }
    }
    if let Some((index, word)) = db_file {
        client_file_operand_effect(
            builder,
            ctx,
            model_node,
            index as u32,
            word,
            "filesystem.write",
        );
    }
}

/// Run SQL input of a CLI a model document owns, where the document cannot
/// read it (a script file). It runs as the document nests inline SQL: in no
/// particular dialect, on a connection the document does not name.
pub(in crate::models) fn document_sql(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    program: SqlClientInput,
) {
    let mut run = Run {
        ctx,
        model_node,
        spec: &CLIENT,
        meta: CLIENT.meta,
        conn: SqlConnection::default(),
        context: Vec::new(),
        substitute: false,
        variables: BTreeMap::new(),
        variables_unknown: false,
        conditionals: 0,
        delimiter: ";".to_string(),
        includes: Vec::new(),
        stopped: false,
    };
    run.program(builder, program);
}

/// Executes one client's SQL input against its current connection.
pub(super) struct Run<'r, 'a> {
    pub(super) ctx: &'r InvocationCtx<'a>,
    pub(super) model_node: ProvenanceRef,
    pub(super) spec: &'r ClientSpec,
    /// The client-command grammar in effect, which options can change.
    pub(super) meta: Meta,
    pub(super) conn: SqlConnection,
    /// Connection arguments that inline SQL inherits as provenance.
    pub(super) context: Vec<usize>,
    pub(super) substitute: bool,
    /// psql variables bound by `-v` and `\set`; `None` is a value Nah
    /// cannot name (a command's output).
    pub(super) variables: BTreeMap<String, Option<String>>,
    /// A command bound variables Nah cannot name (`\gset`), so no reference
    /// resolves any more.
    pub(super) variables_unknown: bool,
    /// Open psql `\if` blocks: a `\set` inside one may not run.
    pub(super) conditionals: usize,
    /// The statement delimiter the client starts each input with.
    pub(super) delimiter: String,
    /// Origins of the scripts being run, outermost first.
    pub(super) includes: Vec<String>,
    /// A client command made the rest of the input unanalyzable.
    pub(super) stopped: bool,
}

impl Run<'_, '_> {
    pub(super) fn program(&mut self, builder: &mut PlanBuilder, program: SqlClientInput) {
        match program {
            SqlClientInput::Sql(word, index) => {
                let arg = arg_node(builder, self.ctx, index as u32);
                let Some(source) = word.as_literal() else {
                    db_gap(
                        builder,
                        &[arg],
                        &["database"],
                        "SQL text not statically recoverable",
                    );
                    return;
                };
                let mut provenance = vec![self.model_node, arg];
                for index in &self.context {
                    let node = arg_node(builder, self.ctx, *index as u32);
                    if !provenance.contains(&node) {
                        provenance.push(node);
                    }
                }
                if self.spec.single_command_args {
                    self.argument(builder, source, &provenance);
                } else {
                    self.text(builder, source, None, &provenance);
                }
            }
            SqlClientInput::File(word, index) => {
                let read = client_file_operand_effect(
                    builder,
                    self.ctx,
                    self.model_node,
                    index as u32,
                    &word,
                    "filesystem.read",
                );
                let arg = arg_node(builder, self.ctx, index as u32);
                match word.as_literal() {
                    Some(path) => {
                        // The client runs the selected file as its program, as
                        // it does a `< FILE` redirect. This read stands in for
                        // the selection's own program-input read, which the
                        // builder skips once the resource is already read.
                        if self.script(builder, path, &[self.model_node, arg])
                            && let Some(read) = read
                        {
                            builder.set_effect_string_attribute(
                                read as usize,
                                "access_purpose",
                                "program_input",
                            );
                        }
                    }
                    None => db_gap(
                        builder,
                        &[self.model_node],
                        &["database"],
                        "SQL script file contents are unavailable",
                    ),
                }
            }
            SqlClientInput::Stdin => self.stdin(builder),
        }
    }

    pub(super) fn stdin(&mut self, builder: &mut PlanBuilder) {
        // `< FILE` and `cat FILE |` run the file as a script; the shell's
        // redirection or `cat` already records reading it.
        if let Some(stdin) = self.ctx.stdin
            && let Some(file) = &stdin.file
        {
            let mut provenance = vec![self.model_node];
            provenance.extend(stdin.provenance.iter().copied());
            match file.as_literal() {
                Some(path) => {
                    self.script(builder, path, &provenance);
                }
                None => db_gap(
                    builder,
                    &provenance,
                    &["database"],
                    "SQL script file contents are unavailable",
                ),
            }
        } else if let Some(source) = self.ctx.stdin_literal() {
            let mut provenance = vec![self.model_node];
            provenance.extend(self.ctx.stdin.unwrap().provenance.iter().copied());
            self.text(builder, source, None, &provenance);
        } else if self.ctx.stdin.is_some() {
            db_gap(
                builder,
                &[self.model_node],
                &["database"],
                "stdin SQL not statically recoverable after expansion",
            );
        } else {
            db_gap(
                builder,
                &[self.model_node],
                &["database"],
                "interactive or stdin SQL session",
            );
        }
    }

    /// A SQL argument of a client that takes it as one client command or
    /// else verbatim SQL (psql `-c`, sqlite3 and duckdb arguments).
    fn argument(&mut self, builder: &mut PlanBuilder, text: &str, provenance: &[ProvenanceRef]) {
        if self.stopped {
            return;
        }
        let command = text.trim_start();
        let at = text.len() - command.len();
        let segments = match self.meta {
            Meta::Psql if command.starts_with('\\') => {
                let (mut segments, end) = psql_meta(text, at, text.len());
                if !text[end..].trim().is_empty() {
                    segments.push(ClientInputSegment::Opaque(
                        "psql runs one meta-command from a -c string".into(),
                    ));
                }
                segments
            }
            Meta::Sqlite if command.starts_with('.') => dot_command(command).into_iter().collect(),
            // psql sends `-c` SQL as one request, which the server parses
            // whole before it runs any of it.
            _ if self.spec.substitution == Substitution::Psql && psql_request_rejected(text) => {
                return;
            }
            // sqlite3 stops at the first statement it cannot prepare, and
            // runs no later argument either.
            _ if self.spec.dialect == SqlDialect::Sqlite => {
                let runs = sqlite_argument_runs(text);
                self.nest_sql(builder, runs.to_string(), None, provenance);
                self.stopped = runs.len() < text.len();
                return;
            }
            _ => {
                self.nest_sql(builder, text.to_string(), None, provenance);
                return;
            }
        };
        self.segments(builder, segments, None, provenance);
    }

    /// Run client input: its SQL, and the client commands between it.
    /// `origin` is the script file the text came from.
    fn text(
        &mut self,
        builder: &mut PlanBuilder,
        text: &str,
        origin: Option<&str>,
        provenance: &[ProvenanceRef],
    ) {
        if self.stopped {
            return;
        }
        let mut readings = escape_readings(self.spec.dialect)
            .iter()
            .map(|escapes| {
                client_segments(
                    text,
                    self.meta,
                    self.spec.dialect,
                    *escapes,
                    &self.delimiter,
                )
            })
            .collect::<Vec<_>>();
        readings.dedup();
        if readings.len() > 1 {
            // Each reading is what some server configuration runs; analyze
            // them all from the same starting connection.
            db_gap(
                builder,
                provenance,
                CLIENT_DOMAINS,
                "client command position depends on the server's string escaping",
            );
        }
        let (conn, stopped) = (self.conn.clone(), self.stopped);
        let mut ends = Vec::new();
        for segments in readings {
            self.conn = conn.clone();
            self.stopped = stopped;
            self.segments(builder, segments, origin, provenance);
            ends.push((self.conn.clone(), self.stopped));
        }
        // Later input runs after whichever reading the server takes: on
        // their shared connection, or on one we cannot name.
        if ends.iter().any(|(conn, _)| *conn != ends[0].0) {
            self.conn = SqlConnection::default();
        }
        self.stopped = ends.iter().all(|(_, stopped)| *stopped);
    }

    fn segments(
        &mut self,
        builder: &mut PlanBuilder,
        segments: Vec<ClientInputSegment>,
        origin: Option<&str>,
        provenance: &[ProvenanceRef],
    ) {
        for segment in segments {
            match segment {
                ClientInputSegment::Sql(sql) => self.sql(builder, sql, origin, provenance),
                ClientInputSegment::Include { path, relative } => {
                    let path = match (relative, origin) {
                        (true, Some(origin)) => {
                            match relative_include(origin, self.ctx.runtime_cwd, &path) {
                                Some(path) => path,
                                None => {
                                    db_gap(
                                        builder,
                                        provenance,
                                        &["database"],
                                        "relative SQL include is outside the working directory",
                                    );
                                    continue;
                                }
                            }
                        }
                        _ => path,
                    };
                    self.include(builder, &path, provenance);
                }
                ClientInputSegment::Connect {
                    database,
                    server,
                    file,
                } => self.connect(builder, database, server, file, provenance),
                ClientInputSegment::Shell(command) => self.shell(builder, command, provenance),
                ClientInputSegment::Backquote(command) => match self.psql_backquote(&command) {
                    Some(command) => self.shell(builder, command, provenance),
                    None => opaque_source_with_provenance(
                        builder,
                        provenance,
                        &["environment", "filesystem", "network", "process"],
                        "client variable substitution leaves a shell command unresolved",
                    ),
                },
                ClientInputSegment::Bind { name, value } => {
                    let value = value.filter(|_| self.conditionals == 0);
                    self.variables.insert(name, value);
                }
                ClientInputSegment::Unbind(name) if self.conditionals == 0 => {
                    self.variables.remove(&name);
                }
                ClientInputSegment::Unbind(name) => {
                    self.variables.insert(name, None);
                }
                ClientInputSegment::BindUnknown => self.variables_unknown = true,
                ClientInputSegment::Conditional(true) => self.conditionals += 1,
                ClientInputSegment::Conditional(false) => {
                    self.conditionals = self.conditionals.saturating_sub(1)
                }
                // duckdb shares the dot-command reader but not sqlite's .restore.
                ClientInputSegment::Restore(_) if self.spec.dialect != SqlDialect::Sqlite => {
                    db_gap(
                        builder,
                        provenance,
                        CLIENT_DOMAINS,
                        "dot-command .restore is not modeled",
                    )
                }
                ClientInputSegment::Restore(schema) => {
                    let resource = match (schema.as_deref(), self.conn.database.as_deref()) {
                        // An in-memory main database holds nothing that outlives
                        // the session.
                        (None | Some("main"), Some(":memory:")) => continue,
                        (None | Some("main"), Some(_)) => ResourceExpr::Concrete {
                            identity: ResourceIdentity::DatabaseSchema {
                                server: self.conn.server.clone(),
                                database: self.conn.database.clone(),
                                schema: None,
                            },
                        },
                        _ => unresolved_resource("db"),
                    };
                    database_effect(
                        builder,
                        "database.write",
                        resource,
                        Attrs::from([(
                            "action".to_string(),
                            AttrValue::String("overwrite".into()),
                        )]),
                        provenance.to_vec(),
                    );
                }
                ClientInputSegment::Opaque(detail) => {
                    db_gap(builder, provenance, CLIENT_DOMAINS, &detail)
                }
                ClientInputSegment::Stop(detail) => {
                    db_gap(builder, provenance, CLIENT_DOMAINS, &detail);
                    self.stopped = true;
                    return;
                }
                ClientInputSegment::Quit => {
                    self.stopped = true;
                    return;
                }
            }
        }
    }

    /// A connection switch: later input runs on the new connection.
    fn connect(
        &mut self,
        builder: &mut PlanBuilder,
        database: Switch,
        server: Switch,
        file: Option<String>,
        provenance: &[ProvenanceRef],
    ) {
        if let Some(file) = file {
            // `.open` opens or creates the file; statements may write it.
            for operation in ["filesystem.read", "filesystem.write"] {
                builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new(operation),
                    resource: self.ctx.resolve_fs_word(&Word::literal(&file)),
                    attributes: Default::default(),
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: provenance.to_vec(),
                });
            }
        }
        match server {
            Switch::Keep => {}
            Switch::Set(host) => {
                let host = host_name(&host);
                endpoint_effect(
                    builder,
                    &Some(host.clone()),
                    None,
                    self.spec.scheme,
                    provenance.to_vec(),
                );
                self.conn.server = Some(host);
            }
            Switch::Unknown => {
                endpoint_effect(builder, &None, None, self.spec.scheme, provenance.to_vec());
                self.conn.server = None;
            }
        }
        match database {
            Switch::Keep => {}
            Switch::Set(database) => self.conn.database = Some(database),
            Switch::Unknown => {
                db_gap(
                    builder,
                    provenance,
                    &["database"],
                    "client switches to a connection that is not statically recoverable",
                );
                self.conn.database = None;
            }
        }
    }

    /// A shell command the client runs, analyzed as the shell would run it.
    fn shell(&mut self, builder: &mut PlanBuilder, command: String, provenance: &[ProvenanceRef]) {
        if self.substitute && self.spec.substitution.applies(&command) {
            opaque_source_with_provenance(
                builder,
                provenance,
                &["environment", "filesystem", "network", "process"],
                "client variable substitution leaves a shell command unresolved",
            );
            return;
        }
        let subject = Subject::Shell {
            source: command,
            cwd: self.ctx.cwd.map(str::to_string),
            context: Default::default(),
        };
        self.ctx.nest_subject(builder, subject, provenance);
    }

    fn sql(
        &mut self,
        builder: &mut PlanBuilder,
        source: String,
        origin: Option<&str>,
        provenance: &[ProvenanceRef],
    ) {
        let (source, unresolved) = match self.spec.substitution {
            Substitution::Psql => self.psql_sql(source),
            substitution => {
                let unresolved = self.substitute && substitution.applies(&source);
                (source, unresolved)
            }
        };
        if unresolved {
            // The statement is still read: the SQL frontend takes each
            // reference as a placeholder, so `DROP TABLE $(t)` keeps its drop
            // with an unnamed target. What the value itself adds is the gap.
            db_gap(
                builder,
                provenance,
                &["database"],
                "client variable substitution leaves the SQL unresolved",
            );
        }
        self.nest_sql(builder, source, origin, provenance);
    }

    /// The value psql interpolates for `name`, when Nah can name it.
    fn psql_variable(&self, name: &str) -> Option<&str> {
        if self.variables_unknown {
            return None;
        }
        self.variables.get(name)?.as_deref()
    }

    /// Script SQL as psql sends it: `:name`, `:'name'` and `:"name"` outside
    /// literals replaced by their bound values. True when a reference stays,
    /// or the server's string escaping decides where the references are.
    fn psql_sql(&self, source: String) -> (String, bool) {
        let mut readings = escape_readings(SqlDialect::Postgres)
            .iter()
            .map(|escapes| {
                let lexed = positions(&source, SqlDialect::Postgres, *escapes, ";");
                self.psql_interpolate(&source, |i| lexed[i].code, true)
            })
            .collect::<Vec<_>>();
        readings.dedup();
        match readings.pop() {
            Some(reading) if readings.is_empty() => reading,
            _ => (source, true),
        }
    }

    /// Backquoted command text as psql hands it to the shell, or None when a
    /// variable it references is not bound to a value Nah can name. psql
    /// interpolates there whatever the shell quoting, and `:'name'` as one
    /// shell-quoted word.
    fn psql_backquote(&self, command: &str) -> Option<String> {
        if self.spec.substitution != Substitution::Psql {
            return Some(command.to_string());
        }
        let (command, unresolved) = self.psql_interpolate(command, |_| true, false);
        (!unresolved).then_some(command)
    }

    /// Replace the psql variable references of `text` at the bytes `code`
    /// admits; true when one stays. `sql` selects SQL quoting for the quoted
    /// forms, else shell quoting, which has no `:"name"`.
    fn psql_interpolate(
        &self,
        text: &str,
        code: impl Fn(usize) -> bool,
        sql: bool,
    ) -> (String, bool) {
        let bytes = text.as_bytes();
        let mut out = String::new();
        let mut unresolved = false;
        let mut copied = 0;
        let mut i = 0;
        while i < bytes.len() {
            // `::` is a cast in SQL; in a shell command psql rescans the
            // second colon.
            if sql && bytes[i..].starts_with(b"::") {
                i += 2;
                continue;
            }
            if !(bytes[i] == b':' && code(i)) {
                i += 1;
                continue;
            }
            let quote = bytes
                .get(i + 1)
                .copied()
                .filter(|c| *c == b'\'' || (sql && *c == b'"'));
            let name_start = i + 1 + usize::from(quote.is_some());
            let name_len = bytes[name_start..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .count();
            let name_end = name_start + name_len;
            let end = match quote {
                Some(quote) if name_len > 0 && bytes.get(name_end) == Some(&quote) => name_end + 1,
                // `a[1:2]` is an array slice, not a variable named `2`.
                None if name_len > 0 && !bytes[name_start].is_ascii_digit() => name_end,
                // Not a reference (`:=`, an unclosed `:'name`), except
                // `:{?name}`, which tests a variable.
                _ => {
                    unresolved |= sql && bytes[i..].starts_with(b":{?");
                    i += 1;
                    continue;
                }
            };
            let value =
                self.psql_variable(&text[name_start..name_end])
                    .and_then(|value| match quote {
                        None => Some(value.to_string()),
                        // psql writes a value holding a backslash as E'…', and
                        // refuses to shell-quote a line break.
                        Some(_) if value.contains(['\\', '\n', '\r']) => None,
                        Some(b'"') => Some(format!("\"{}\"", value.replace('"', "\"\""))),
                        Some(_) if sql => Some(format!("'{}'", value.replace('\'', "''"))),
                        Some(_) => Some(format!("'{}'", value.replace('\'', "'\\''"))),
                    });
            match value {
                Some(value) => {
                    out.push_str(&text[copied..i]);
                    out.push_str(&value);
                    copied = end;
                }
                None => unresolved = true,
            }
            i = end;
        }
        out.push_str(&text[copied..]);
        (out, unresolved)
    }

    fn nest_sql(
        &mut self,
        builder: &mut PlanBuilder,
        source: String,
        origin: Option<&str>,
        provenance: &[ProvenanceRef],
    ) {
        let subject = Subject::Sql {
            source,
            dialect: self.spec.dialect,
            connection: self.conn.clone(),
        };
        match origin {
            Some(origin) => {
                self.ctx
                    .nest_file_subject(builder, subject, provenance, origin.to_string())
            }
            None => self.ctx.nest_subject(builder, subject, provenance),
        }
    }

    /// A script a client command includes: the client reads the file, then
    /// runs it as input.
    fn include(&mut self, builder: &mut PlanBuilder, path: &str, provenance: &[ProvenanceRef]) {
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        let read = builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("filesystem.read"),
            resource: self.ctx.resolve_fs_word(&Word::literal(path)),
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: provenance.to_vec(),
        });
        // As with `-f`, this read stands in for the selection's own
        // program-input read, which the builder skips once the resource is
        // already read.
        if self.script(builder, path, provenance)
            && let Some(read) = read
        {
            builder.set_effect_string_attribute(read as usize, "access_purpose", "program_input");
        }
    }

    /// Runs the script at `path`; true when its source was selected.
    fn script(
        &mut self,
        builder: &mut PlanBuilder,
        path: &str,
        provenance: &[ProvenanceRef],
    ) -> bool {
        if self.includes.len() >= MAX_INCLUDE_DEPTH {
            db_gap(
                builder,
                provenance,
                &["database"],
                "SQL script includes nest too deeply",
            );
            return false;
        }
        let unavailable = "SQL script file contents are unavailable";
        match self
            .ctx
            .resolve_source_operand(builder, path, SourcePurpose::InvocationInput)
        {
            SourceResolution::Source { origin, source } => {
                if self.includes.contains(&origin) {
                    db_gap(
                        builder,
                        provenance,
                        &["database"],
                        "SQL script includes itself",
                    );
                    return true;
                }
                self.includes.push(origin.clone());
                self.text(builder, &source, Some(&origin), provenance);
                self.includes.pop();
                return true;
            }
            SourceResolution::Refused(refusal) => {
                if let Some(detail) = source_refusal_detail(builder, refusal, unavailable) {
                    db_gap(builder, provenance, &["database"], &detail);
                }
            }
            SourceResolution::UnsupportedEncoding => db_gap(
                builder,
                provenance,
                &["database"],
                "SQL script file is not valid UTF-8",
            ),
            SourceResolution::AlreadySelected => {}
            SourceResolution::Unavailable => {
                db_gap(builder, provenance, &["database"], unavailable)
            }
        }
        false
    }
}

/// `\ir path` from a script: `path` under the script's directory, as a path
/// relative to the invocation's working directory.
fn relative_include(origin: &str, runtime_cwd: Option<&str>, path: &str) -> Option<String> {
    if path.starts_with('/') {
        return Some(path.to_string());
    }
    let dir = parent_dir(origin);
    if dir.starts_with('/') {
        return Some(format!("{dir}/{path}"));
    }
    let cwd = runtime_cwd?;
    let under = if cwd.is_empty() {
        dir.as_str()
    } else if dir == cwd {
        ""
    } else {
        dir.strip_prefix(cwd)?.strip_prefix('/')?
    };
    Some(if under.is_empty() {
        path.to_string()
    } else {
        format!("{under}/{path}")
    })
}
