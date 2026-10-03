//! Database client models. They recover a connection scope (server/database)
//! from argv, then run the client's SQL input as a `Subject::Sql` in the
//! client's dialect, in the order the client executes it: inline SQL flags,
//! script files, stdin, and the files a script includes through client
//! commands (`\i`, `.read`, `SOURCE`, `:r`, `!source`). Input the client would
//! run but we cannot hold (an interactive session, an unreadable script, a
//! shell escape) is a boundary, never a silently empty plan.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceRef, ResourceExpr, ResourceFamily, ResourceIdentity,
    SqlConnection, SqlDialect, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_node, boundary, opaque_source_with_provenance, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx, source_refusal_detail};
use crate::nest::SourceResolution;
use crate::paths::parent_dir;
use crate::word::Word;

pub(super) fn db_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Psql),
        Box::new(Mysql),
        Box::new(Sqlite),
        Box::new(Duckdb),
        Box::new(Cockroach),
        Box::new(Cqlsh),
        Box::new(Clickhouse),
        Box::new(Sqlcmd),
        Box::new(Snowsql),
        Box::new(Snow),
        Box::new(Dropdb),
        Box::new(Mysqladmin),
        Box::new(PgRestore),
        Box::new(PgDump),
        Box::new(MysqlDump),
    ]
}

/// Domains an unmodeled client option or client command may reach.
const CLIENT_DOMAINS: &[&str] = &["database", "network", "filesystem", "process"];

/// Nested script includes deeper than this are left as a boundary.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Emit `network.connect` when a database endpoint is selected, even if symbolic.
fn connect_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    server: &Option<String>,
    port: Option<u16>,
    scheme: Option<&str>,
    source_indices: &[usize],
) {
    if server.is_none() && source_indices.is_empty() {
        return;
    }
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    let mut provenance = Vec::new();
    if ctx.tracks_host_context_environment() || server.is_none() {
        for index in source_indices {
            let node = arg_node(builder, ctx, *index as u32);
            if !provenance.contains(&node) {
                provenance.push(node);
            }
        }
    }
    provenance.push(model_node);
    endpoint_effect(builder, server, port, scheme, provenance);
}

/// `network.connect` to `server`, or to an unresolved endpoint.
fn endpoint_effect(
    builder: &mut PlanBuilder,
    server: &Option<String>,
    port: Option<u16>,
    scheme: Option<&str>,
    provenance: Vec<ProvenanceRef>,
) {
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("network.connect"),
        resource: server
            .as_ref()
            .map(|host| ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: host.clone(),
                    scheme: scheme.map(str::to_string),
                    port,
                    path: None,
                },
            })
            .unwrap_or(ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("network"),
            }),
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}

/// A file operand's effect (for `-f script.sql`: reading the script file),
/// as its slot in the effect list.
fn file_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    file: &Word,
    operation: &str,
) -> Option<u32> {
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    let arg = crate::models::common::fs_arg_node(builder, ctx, index, file);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource: ctx.resolve_fs_word(file),
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: vec![arg, model_node],
    })
}

/// A `database.*` effect this model states itself, outside nested SQL.
fn database_effect(
    builder: &mut PlanBuilder,
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
    provenance: Vec<ProvenanceRef>,
) {
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}

fn object_kind(kind: &str) -> Attrs {
    Attrs::from([("object_kind".to_string(), AttrValue::String(kind.into()))])
}

/// A gap with explicit provenance; the affected domains become partial.
fn gap(builder: &mut PlanBuilder, provenance: &[ProvenanceRef], domains: &[&str], detail: &str) {
    for domain in domains {
        builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
        provenance: provenance.to_vec(),
        limit: None,
        detail: Some(detail.to_string()),
    });
}

fn unmodeled_subcommand(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    for domain in CLIENT_DOMAINS {
        builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNMODELED_SUBCOMMAND,
        BoundaryClass::Unmodeled,
        CLIENT_DOMAINS,
        detail,
    );
}

fn unrecognized_operands(builder: &mut PlanBuilder, model_node: ProvenanceRef, operands: &[&str]) {
    if operands.is_empty() {
        return;
    }
    for domain in CLIENT_DOMAINS {
        builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        BoundaryClass::Unmodeled,
        CLIENT_DOMAINS,
        &format!("unrecognized operands: {}", operands.join(", ")),
    );
}

/// Parse a `scheme://[user@]host[:port]/db` connection string.
fn parse_conn_url(text: &str, schemes: &[&str]) -> Option<(Option<String>, Option<String>)> {
    let (scheme, rest) = text.split_once("://")?;
    if !schemes.contains(&scheme) {
        return None;
    }
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port.split(':').next().unwrap_or(host_port);
    let db = path
        .map(|p| p.split(['?', '/']).next().unwrap_or(p).to_string())
        .filter(|s| !s.is_empty());
    Some(((!host.is_empty()).then(|| host.to_string()), db))
}

/// Parse a libpq `key=value` connection string (`host=db dbname=app`).
/// Quoted values are left unresolved.
fn parse_conninfo(text: &str) -> Option<(Option<String>, Option<String>)> {
    if !text.contains('=') || text.contains('\'') {
        return None;
    }
    let (mut host, mut database) = (None, None);
    for pair in text.split_whitespace() {
        let (key, value) = pair.split_once('=')?;
        match key {
            "host" | "hostaddr" => host = Some(value.to_string()),
            "dbname" => database = Some(value.to_string()),
            _ => {}
        }
    }
    Some((host, database))
}

const PG_SCHEMES: &[&str] = &["postgres", "postgresql"];
const MYSQL_SCHEMES: &[&str] = &["mysql", "mariadb"];

/// How a client reads its non-option operands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operands {
    /// A database name (or connection string), then up to `max - 1` more
    /// operands the client accepts but this model does not track (psql's user).
    Database {
        max: usize,
    },
    /// A database file, then SQL arguments each run in turn (sqlite3, duckdb).
    FileThenSql,
    /// `[host [port]]` (cqlsh).
    HostPort,
    /// A connection URL at most (clickhouse-client).
    Url,
    None,
}

/// Client-side text substitution that rewrites SQL before the server sees it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Substitution {
    None,
    /// sqlcmd scripting variables, `$(name)`.
    Sqlcmd,
    /// SnowSQL variables, `&name` and `&{name}`, when a config enables them.
    Snowsql,
    /// Snowflake CLI templates, `&{ name }` and `<% name %>`.
    SnowCli,
    /// psql variables, `:name`, `:'name'` and `:"name"`, outside literals.
    /// psql does not interpolate `-c` SQL.
    Psql,
}

impl Substitution {
    fn applies(self, sql: &str) -> bool {
        match self {
            Substitution::None => false,
            Substitution::Sqlcmd => sql.contains("$("),
            Substitution::Snowsql => sql.as_bytes().windows(2).any(|pair| {
                pair[0] == b'&'
                    && (pair[1] == b'{' || pair[1].is_ascii_alphabetic() || pair[1] == b'_')
            }),
            Substitution::SnowCli => sql.contains("&{") || sql.contains("<%"),
            Substitution::Psql => {
                let bytes = sql.as_bytes();
                escape_readings(SqlDialect::Postgres).iter().any(|escapes| {
                    let lexed = positions(sql, SqlDialect::Postgres, *escapes);
                    (0..bytes.len()).any(|i| lexed[i].code && psql_variable_at(bytes, i))
                })
            }
        }
    }

    /// Whether the client substitutes into shell command text. psql
    /// interpolates backquoted text regardless of shell quoting.
    fn applies_to_shell(self, command: &str) -> bool {
        match self {
            Substitution::Psql => {
                (0..command.len()).any(|i| psql_variable_at(command.as_bytes(), i))
            }
            other => other.applies(command),
        }
    }
}

/// Whether a psql variable reference (`:name`, `:'name'`, `:"name"`)
/// starts at `bytes[i]`; `::` is a cast.
fn psql_variable_at(bytes: &[u8], i: usize) -> bool {
    bytes[i] == b':'
        && (i == 0 || bytes[i - 1] != b':')
        && bytes
            .get(i + 1)
            .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, b'_' | b'\'' | b'"'))
}

/// The option vocabulary and input grammar of one SQL client.
struct ClientSpec {
    dialect: SqlDialect,
    meta: Meta,
    /// Flags whose value is SQL the client runs, and then exits.
    sql: &'static [&'static str],
    /// Flags whose value is SQL run before the client goes on to stdin.
    startup_sql: &'static [&'static str],
    /// Flags naming a script file the client runs, and then exits.
    files: &'static [&'static str],
    /// Flags naming a script run before the client goes on to stdin.
    startup_files: &'static [&'static str],
    /// A script flag's value may list several files separated by commas.
    comma_files: bool,
    /// `-f -` reads the script from stdin.
    dash_is_stdin: bool,
    db: &'static [&'static str],
    host: &'static [&'static str],
    port: &'static [&'static str],
    /// Flags whose value is a connection URL.
    url: &'static [&'static str],
    url_schemes: &'static [&'static str],
    /// Flags naming a file the client writes output to (`|cmd` pipes it).
    output: &'static [&'static str],
    /// Other value flags; they select nothing this model tracks.
    values: &'static [&'static str],
    switches: &'static [&'static str],
    /// Flags that print usage or a version, and exit.
    help: &'static [&'static str],
    /// Flags whose value may only be attached (`-pSECRET`, `--password=x`).
    attached_only: &'static [&'static str],
    /// Switches after which the client does not read stdin.
    no_stdin: &'static [&'static str],
    /// When non-empty, stdin is SQL only when one of these switches is given.
    stdin_flags: &'static [&'static str],
    /// Unknown `--name=value` options are server settings (clickhouse-client).
    setting_options: bool,
    /// Options whose effect on the SQL input is not modeled, with why.
    unmodeled_values: &'static [(&'static str, &'static str)],
    operands: Operands,
    scheme: Option<&'static str>,
    /// Endpoint the client connects to when argv selects none.
    default_host: Option<&'static str>,
    substitution: Substitution,
    /// Each SQL argument is one client command (when it starts with the
    /// command prefix) or else SQL the client sends verbatim.
    single_command_args: bool,
    /// Flags naming a Snowflake account, which selects the server.
    account: &'static [&'static str],
    /// Flags naming the account's region, part of its server name.
    region: &'static [&'static str],
    /// Flags selecting a named connection from the client's configuration.
    named_connection: &'static [&'static str],
}

const CLIENT: ClientSpec = ClientSpec {
    dialect: SqlDialect::Generic,
    meta: Meta::None,
    sql: &[],
    startup_sql: &[],
    files: &[],
    startup_files: &[],
    comma_files: false,
    dash_is_stdin: false,
    db: &[],
    host: &[],
    port: &[],
    url: &[],
    url_schemes: &[],
    output: &[],
    values: &[],
    switches: &[],
    help: &[],
    attached_only: &[],
    no_stdin: &[],
    stdin_flags: &[],
    setting_options: false,
    unmodeled_values: &[],
    operands: Operands::None,
    scheme: None,
    default_host: None,
    substitution: Substitution::None,
    single_command_args: false,
    account: &[],
    region: &[],
    named_connection: &[],
};

impl ClientSpec {
    fn value_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        for group in [
            self.sql,
            self.startup_sql,
            self.files,
            self.startup_files,
            self.db,
            self.host,
            self.port,
            self.url,
            self.output,
            self.values,
        ] {
            flags.extend_from_slice(group);
        }
        flags.extend_from_slice(self.account);
        flags.extend_from_slice(self.region);
        flags.extend_from_slice(self.named_connection);
        flags.extend(self.unmodeled_values.iter().map(|(flag, _)| *flag));
        flags
    }

    fn known_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        for group in [
            self.switches,
            self.help,
            self.attached_only,
            self.no_stdin,
            self.stdin_flags,
        ] {
            flags.extend_from_slice(group);
        }
        flags
    }
}

const PSQL: ClientSpec = ClientSpec {
    dialect: SqlDialect::Postgres,
    meta: Meta::Psql,
    sql: &["-c", "--command"],
    files: &["-f", "--file"],
    dash_is_stdin: true,
    db: &["-d", "--dbname"],
    host: &["-h", "--host"],
    port: &["-p", "--port"],
    output: &["-o", "--output", "-L", "--log-file"],
    values: &[
        "-v",
        "--set",
        "--variable",
        "-U",
        "--username",
        "-P",
        "--pset",
        "-F",
        "--field-separator",
        "-R",
        "--record-separator",
        "-T",
        "--table-attr",
    ],
    switches: &[
        "-a",
        "--echo-all",
        "-A",
        "--no-align",
        "-b",
        "--echo-errors",
        "--csv",
        "-e",
        "--echo-queries",
        "-E",
        "--echo-hidden",
        "-H",
        "--html",
        "-l",
        "--list",
        "-n",
        "--no-readline",
        "-q",
        "--quiet",
        "-s",
        "--single-step",
        "-S",
        "--single-line",
        "-t",
        "--tuples-only",
        "-x",
        "--expanded",
        "-X",
        "--no-psqlrc",
        "-z",
        "--field-separator-zero",
        "-0",
        "--record-separator-zero",
        "-1",
        "--single-transaction",
        "-w",
        "--no-password",
        "-W",
        "--password",
    ],
    help: &["-?", "--help", "-V", "--version"],
    url_schemes: PG_SCHEMES,
    operands: Operands::Database { max: 2 },
    scheme: Some("postgresql"),
    substitution: Substitution::Psql,
    single_command_args: true,
    ..CLIENT
};

const MYSQL: ClientSpec = ClientSpec {
    dialect: SqlDialect::Mysql,
    meta: Meta::Mysql,
    sql: &["-e", "--execute"],
    startup_sql: &["--init-command"],
    db: &["-D", "--database"],
    host: &["-h", "--host"],
    port: &["-P", "--port"],
    output: &["--tee"],
    values: &[
        "-u",
        "--user",
        "-S",
        "--socket",
        "--default-character-set",
        "--defaults-file",
        "--defaults-extra-file",
        "--defaults-group-suffix",
        "--login-path",
        "--protocol",
        "--connect-timeout",
        "--max-allowed-packet",
        "--net-buffer-length",
        "--select-limit",
        "--max-join-size",
        "--prompt",
        "--ssl-ca",
        "--ssl-capath",
        "--ssl-cert",
        "--ssl-cipher",
        "--ssl-crl",
        "--ssl-crlpath",
        "--ssl-key",
        "--ssl-mode",
        "--tls-version",
        "--tls-ciphersuites",
        "--plugin-dir",
        "--default-auth",
        "--character-sets-dir",
        "--bind-address",
        "--compression-algorithms",
        "--zstd-compression-level",
        "--server-public-key-path",
        "--load-data-local-dir",
        "--histignore",
    ],
    switches: &[
        "-B",
        "--batch",
        "-N",
        "--skip-column-names",
        "--column-names",
        "-s",
        "--silent",
        "-v",
        "--verbose",
        "-t",
        "--table",
        "-H",
        "--html",
        "-X",
        "--xml",
        "-E",
        "--vertical",
        "-f",
        "--force",
        "-q",
        "--quick",
        "-r",
        "--raw",
        "-n",
        "--unbuffered",
        "-A",
        "--no-auto-rehash",
        "--auto-rehash",
        "--skip-auto-rehash",
        "-b",
        "--no-beep",
        "-c",
        "--comments",
        "--skip-comments",
        "-C",
        "--compress",
        "-G",
        "--named-commands",
        "--skip-named-commands",
        "-i",
        "--ignore-spaces",
        "-j",
        "--syslog",
        "-L",
        "--skip-line-numbers",
        "--line-numbers",
        "-o",
        "--one-database",
        "-U",
        "--safe-updates",
        "--i-am-a-dummy",
        "-w",
        "--wait",
        "-T",
        "--debug-info",
        "--binary-mode",
        "--binary-as-hex",
        "--skip-binary-as-hex",
        "--local-infile",
        "--no-defaults",
        "--print-defaults",
        "--show-warnings",
        "--sigint-ignore",
        "--reconnect",
        "--skip-reconnect",
        "--ssl",
        "--skip-ssl",
        "--ssl-verify-server-cert",
        "--enable-cleartext-plugin",
        "--get-server-public-key",
        "--skip-pager",
        "--no-pager",
        "--no-tee",
        "--skip-system-command",
        "-W",
        "--pipe",
    ],
    help: &["-?", "--help", "-V", "--version", "-I"],
    attached_only: &["-p", "--password"],
    unmodeled_values: &[
        (
            "--delimiter",
            "mysql --delimiter changes how statements split",
        ),
        ("--pager", "mysql --pager sends query output to a command"),
    ],
    url_schemes: MYSQL_SCHEMES,
    operands: Operands::Database { max: 1 },
    ..CLIENT
};

/// sqlite3 accepts each option with one or two leading dashes.
const SQLITE: ClientSpec = ClientSpec {
    dialect: SqlDialect::Sqlite,
    meta: Meta::Sqlite,
    startup_sql: &["-cmd", "--cmd"],
    startup_files: &["-init", "--init"],
    values: &[
        "-separator",
        "--separator",
        "-newline",
        "--newline",
        "-nullvalue",
        "--nullvalue",
        "-escape",
        "--escape",
        "-lookaside",
        "--lookaside",
        "-maxsize",
        "--maxsize",
        "-mmap",
        "--mmap",
        "-pagecache",
        "--pagecache",
        "-heap",
        "--heap",
        "-vfs",
        "--vfs",
    ],
    switches: &[
        "-append",
        "--append",
        "-ascii",
        "--ascii",
        "-bail",
        "--bail",
        "-batch",
        "--batch",
        "-box",
        "--box",
        "-column",
        "--column",
        "-csv",
        "--csv",
        "-deserialize",
        "--deserialize",
        "-echo",
        "--echo",
        "-header",
        "--header",
        "-noheader",
        "--noheader",
        "-html",
        "--html",
        "-interactive",
        "--interactive",
        "-json",
        "--json",
        "-line",
        "--line",
        "-list",
        "--list",
        "-markdown",
        "--markdown",
        "-memtrace",
        "--memtrace",
        "-nofollow",
        "--nofollow",
        "-quote",
        "--quote",
        "-readonly",
        "--readonly",
        "-safe",
        "--safe",
        "-stats",
        "--stats",
        "-table",
        "--table",
        "-tabs",
        "--tabs",
        "-zip",
        "--zip",
    ],
    help: &["-help", "--help", "-version", "--version"],
    operands: Operands::FileThenSql,
    single_command_args: true,
    ..CLIENT
};

const DUCKDB: ClientSpec = ClientSpec {
    dialect: SqlDialect::Postgres,
    meta: Meta::Sqlite,
    sql: &["-c", "--c", "-s", "--s"],
    startup_sql: &["-cmd", "--cmd"],
    files: &["-f", "--f"],
    startup_files: &["-init", "--init"],
    values: &[
        "-separator",
        "--separator",
        "-newline",
        "--newline",
        "-nullvalue",
        "--nullvalue",
        "-storage-version",
        "--storage-version",
    ],
    switches: &[
        "-append",
        "--append",
        "-ascii",
        "--ascii",
        "-bail",
        "--bail",
        "-batch",
        "--batch",
        "-box",
        "--box",
        "-column",
        "--column",
        "-csv",
        "--csv",
        "-echo",
        "--echo",
        "-header",
        "--header",
        "-noheader",
        "--noheader",
        "-html",
        "--html",
        "-interactive",
        "--interactive",
        "-json",
        "--json",
        "-line",
        "--line",
        "-list",
        "--list",
        "-markdown",
        "--markdown",
        "-quote",
        "--quote",
        "-readonly",
        "--readonly",
        "-safe",
        "--safe",
        "-table",
        "--table",
        "-unredacted",
        "--unredacted",
        "-unsigned",
        "--unsigned",
    ],
    help: &["-help", "--help", "-version", "--version"],
    no_stdin: &["-no-stdin", "--no-stdin"],
    operands: Operands::FileThenSql,
    single_command_args: true,
    ..CLIENT
};

const COCKROACH_SQL: ClientSpec = ClientSpec {
    dialect: SqlDialect::Postgres,
    meta: Meta::Psql,
    sql: &["-e", "--execute"],
    files: &["-f", "--file"],
    db: &["-d", "--database"],
    host: &["--host"],
    port: &["--port", "-p"],
    url: &["--url"],
    url_schemes: PG_SCHEMES,
    values: &[
        "-u",
        "--user",
        "--certs-dir",
        "--format",
        "--set",
        "--watch",
        "--cluster-name",
    ],
    switches: &[
        "--insecure",
        "--echo-sql",
        "--safe-updates",
        "--debug-sql-cli",
        "--no-line-editor",
        "--read-only",
        "--embedded",
    ],
    help: &["-h", "--help"],
    scheme: Some("postgresql"),
    default_host: Some("localhost"),
    ..CLIENT
};

const CQLSH: ClientSpec = ClientSpec {
    dialect: SqlDialect::Cql,
    meta: Meta::Cql,
    sql: &["-e", "--execute"],
    files: &["-f", "--file"],
    db: &["-k", "--keyspace"],
    values: &[
        "-u",
        "--username",
        "-p",
        "--password",
        "--cqlshrc",
        "--encoding",
        "--cqlversion",
        "--protocol-version",
        "--connect-timeout",
        "--request-timeout",
        "-b",
        "--secure-connect-bundle",
        "--consistency-level",
        "--serial-consistency-level",
    ],
    switches: &[
        "--ssl",
        "--no-color",
        "-C",
        "--color",
        "--debug",
        "--no-file-io",
        "--disable-history",
        "-t",
        "--tty",
        "--insecure-password-without-warning",
    ],
    help: &["-h", "--help", "--version"],
    operands: Operands::HostPort,
    default_host: Some("127.0.0.1"),
    ..CLIENT
};

const CLICKHOUSE: ClientSpec = ClientSpec {
    dialect: SqlDialect::ClickHouse,
    sql: &["-q", "--query"],
    files: &["--queries-file"],
    db: &["-d", "--database"],
    host: &["-h", "--host"],
    port: &["--port"],
    url_schemes: &["clickhouse"],
    values: &[
        "-u",
        "--user",
        "--password",
        "-C",
        "--config-file",
        "-f",
        "--format",
        "--connection",
        "--history_file",
        "--jwt",
    ],
    switches: &[
        "-m",
        "--multiline",
        "-n",
        "--multiquery",
        "-s",
        "--secure",
        "-t",
        "--time",
        "--stacktrace",
        "--progress",
        "--echo",
        "-E",
        "--vertical",
        "--ask-password",
        "--disable_suggestion",
        "-A",
    ],
    help: &["--help", "-V", "--version"],
    setting_options: true,
    operands: Operands::Url,
    ..CLIENT
};

const SQLCMD: ClientSpec = ClientSpec {
    dialect: SqlDialect::TSql,
    meta: Meta::Sqlcmd,
    sql: &["-Q"],
    startup_sql: &["-q"],
    files: &["-i"],
    comma_files: true,
    db: &["-d"],
    host: &["-S"],
    output: &["-o"],
    values: &[
        "-U", "-P", "-v", "-f", "-h", "-s", "-w", "-t", "-l", "-a", "-m", "-V", "-H", "-K", "-z",
        "-Z", "-y", "-Y", "-F",
    ],
    switches: &[
        "-E", "-C", "-b", "-e", "-I", "-k", "-r", "-W", "-X", "-x", "-p", "-u", "-N", "-A", "-G",
        "-M", "-j",
    ],
    help: &["-?", "--help", "--version"],
    unmodeled_values: &[("-c", "sqlcmd -c changes the batch terminator")],
    substitution: Substitution::Sqlcmd,
    ..CLIENT
};

const SNOWSQL: ClientSpec = ClientSpec {
    dialect: SqlDialect::Snowflake,
    meta: Meta::Snow,
    sql: &["-q", "--query"],
    files: &["-f", "--filename"],
    db: &["-d", "--dbname"],
    host: &["-h", "--host"],
    port: &["-p", "--port"],
    account: &["-a", "--accountname"],
    region: &["--region"],
    named_connection: &["-c", "--connection"],
    values: &[
        "-u",
        "--username",
        "-s",
        "--schemaname",
        "-r",
        "--rolename",
        "-w",
        "--warehouse",
        "-o",
        "--option",
        "-D",
        "--variable",
        "--config",
        "--authenticator",
        "--private-key-path",
        "--token",
        "--query_tag",
        "--mfa-passcode",
    ],
    switches: &[
        "-P",
        "--prompt",
        "-M",
        "--mfa-prompt",
        "-x",
        "--noup",
        "--abort-detached-query",
        "--generate-jwt",
    ],
    help: &["-?", "--help", "-v", "--version"],
    substitution: Substitution::Snowsql,
    ..CLIENT
};

const SNOW_SQL: ClientSpec = ClientSpec {
    dialect: SqlDialect::Snowflake,
    meta: Meta::Snow,
    sql: &["-q", "--query"],
    files: &["-f", "--filename"],
    db: &["--database", "--dbname"],
    host: &["--host"],
    port: &["--port"],
    values: &[
        "-D",
        "--variable",
        "--environment",
        "--user",
        "--username",
        "--password",
        "--authenticator",
        "--workload-identity-provider",
        "--private-key-file",
        "--private-key-path",
        "--token",
        "--token-file-path",
        "--schema",
        "--schemaname",
        "--role",
        "--rolename",
        "--warehouse",
        "--mfa-passcode",
        "--format",
        "--diag-log-path",
        "--diag-allowlist-path",
        "-p",
        "--project",
        "--env",
        "--master-token",
        "--session-token",
        "--enable-templating",
    ],
    switches: &[
        "--retain-comments",
        "--single-transaction",
        "--no-single-transaction",
        "-x",
        "--temporary-connection",
        "--enable-diag",
        "-v",
        "--verbose",
        "--debug",
        "--silent",
        "--enhanced-exit-codes",
    ],
    help: &["-h", "--help"],
    stdin_flags: &["-i", "--stdin"],
    account: &["--account", "--accountname"],
    region: &["--region"],
    named_connection: &["-c", "--connection"],
    substitution: Substitution::SnowCli,
    ..CLIENT
};

/// A unit of SQL input, in the order the client runs it.
enum Program {
    Sql(Word, usize),
    File(Word, usize),
    Stdin,
}

/// The argv words a client scans, with attached-only values folded into the
/// bare flag so the scanner does not read `-pSECRET` (or `-BpSECRET`) as a
/// cluster.
fn client_words(argv: &[Word], spec: &ClientSpec) -> Vec<Word> {
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

fn flag_lists(spec: &ClientSpec) -> FlagLists {
    (spec.value_flags(), spec.known_flags())
}

fn scan_client<'w>(words: &'w [Word], flags: &'w FlagLists, spec: &ClientSpec) -> Scanned<'w> {
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
fn sql_client(
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
    for flag in &scanned.flags {
        if flag.name == "-x" && spec.substitution == Substitution::Sqlcmd {
            substitute = false;
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
            programs.push((rank, Program::Sql(value.clone(), index)));
        } else if spec.files.contains(&name) || spec.startup_files.contains(&name) {
            exits |= spec.files.contains(&name);
            let rank = if spec.files.contains(&name) { 2 } else { 0 };
            match literal {
                Some("-") if spec.dash_is_stdin => programs.push((rank, Program::Stdin)),
                Some(list) if spec.comma_files => programs.extend(
                    list.split(',')
                        .map(|path| (rank, Program::File(Word::literal(path), index))),
                ),
                _ => programs.push((rank, Program::File(value.clone(), index))),
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
        } else if let Some((_, detail)) =
            spec.unmodeled_values.iter().find(|(flag, _)| *flag == name)
        {
            gap(builder, &[model_node], CLIENT_DOMAINS, detail);
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
                programs.push((2, Program::Sql((*word).clone(), index)));
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
        gap(
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
        gap(
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
        file_effect(
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
            gap(
                builder,
                &[model_node],
                CLIENT_DOMAINS,
                "client output is piped to a command",
            );
        } else {
            file_effect(
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
        includes: Vec::new(),
        stopped: false,
    };
    let reads_stdin = programs
        .iter()
        .any(|(_, program)| matches!(program, Program::Stdin));
    programs.sort_by_key(|(rank, _)| *rank);
    for (_, program) in programs {
        run.program(builder, program);
    }
    if !(reads_stdin || exits) {
        if spec.stdin_flags.is_empty() || scanned.has(spec.stdin_flags) {
            run.stdin(builder);
        } else {
            gap(
                builder,
                &[model_node],
                &["database"],
                "interactive SQL session",
            );
        }
    }
    if let Some((index, word)) = db_file {
        file_effect(
            builder,
            ctx,
            model_node,
            index as u32,
            word,
            "filesystem.write",
        );
    }
}

/// The host a server argument names first: sqlcmd's `tcp:host,port` and
/// `host\instance`, or the first of a libpq host list (`a,b`).
fn host_name(text: &str) -> String {
    let text = ["tcp:", "np:", "lpc:"]
        .iter()
        .find_map(|prefix| text.strip_prefix(prefix))
        .unwrap_or(text);
    text.split([',', '\\']).next().unwrap_or(text).to_string()
}

/// Executes one client's SQL input against its current connection.
struct Run<'r, 'a> {
    ctx: &'r InvocationCtx<'a>,
    model_node: ProvenanceRef,
    spec: &'r ClientSpec,
    /// The client-command grammar in effect, which options can change.
    meta: Meta,
    conn: SqlConnection,
    /// Connection arguments that inline SQL inherits as provenance.
    context: Vec<usize>,
    substitute: bool,
    /// Origins of the scripts being run, outermost first.
    includes: Vec<String>,
    /// A client command made the rest of the input unanalyzable.
    stopped: bool,
}

impl Run<'_, '_> {
    fn program(&mut self, builder: &mut PlanBuilder, program: Program) {
        match program {
            Program::Sql(word, index) => {
                let arg = arg_node(builder, self.ctx, index as u32);
                let Some(source) = word.as_literal() else {
                    gap(
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
            Program::File(word, index) => {
                let read = file_effect(
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
                    None => gap(
                        builder,
                        &[self.model_node],
                        &["database"],
                        "SQL script file contents are unavailable",
                    ),
                }
            }
            Program::Stdin => self.stdin(builder),
        }
    }

    fn stdin(&mut self, builder: &mut PlanBuilder) {
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
                None => gap(
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
            gap(
                builder,
                &[self.model_node],
                &["database"],
                "stdin SQL not statically recoverable after expansion",
            );
        } else {
            gap(
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
                    segments.push(Segment::Opaque(
                        "psql runs one meta-command from a -c string".into(),
                    ));
                }
                segments
            }
            Meta::Sqlite if command.starts_with('.') => dot_command(command).into_iter().collect(),
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
            .map(|escapes| client_segments(text, self.meta, self.spec.dialect, *escapes))
            .collect::<Vec<_>>();
        readings.dedup();
        if readings.len() > 1 {
            // Each reading is what some server configuration runs; analyze
            // them all from the same starting connection.
            gap(
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
        segments: Vec<Segment>,
        origin: Option<&str>,
        provenance: &[ProvenanceRef],
    ) {
        for segment in segments {
            match segment {
                Segment::Sql(sql) => self.sql(builder, sql, origin, provenance),
                Segment::Include { path, relative } => {
                    let path = match (relative, origin) {
                        (true, Some(origin)) => {
                            match relative_include(origin, self.ctx.runtime_cwd, &path) {
                                Some(path) => path,
                                None => {
                                    gap(
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
                Segment::Connect {
                    database,
                    server,
                    file,
                } => self.connect(builder, database, server, file, provenance),
                Segment::Shell(command) => self.shell(builder, command, provenance),
                // duckdb shares the dot-command reader but not sqlite's .restore.
                Segment::Restore(_) if self.spec.dialect != SqlDialect::Sqlite => gap(
                    builder,
                    provenance,
                    CLIENT_DOMAINS,
                    "dot-command .restore is not modeled",
                ),
                Segment::Restore(schema) => {
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
                        _ => ResourceExpr::Unresolved {
                            family: ResourceFamily::new("db"),
                        },
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
                Segment::Opaque(detail) => gap(builder, provenance, CLIENT_DOMAINS, &detail),
                Segment::Stop(detail) => {
                    gap(builder, provenance, CLIENT_DOMAINS, &detail);
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
                gap(
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
        if self.substitute && self.spec.substitution.applies_to_shell(&command) {
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
        if self.substitute && self.spec.substitution.applies(&source) {
            gap(
                builder,
                provenance,
                &["database"],
                "client variable substitution leaves the SQL unresolved",
            );
            return;
        }
        self.nest_sql(builder, source, origin, provenance);
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
            gap(
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
                    gap(
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
                    gap(builder, provenance, &["database"], &detail);
                }
            }
            SourceResolution::UnsupportedEncoding => gap(
                builder,
                provenance,
                &["database"],
                "SQL script file is not valid UTF-8",
            ),
            SourceResolution::AlreadySelected => {}
            SourceResolution::Unavailable => gap(builder, provenance, &["database"], unavailable),
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

/// The client-command grammar layered over a client's SQL input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Meta {
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
enum Segment {
    Sql(String),
    /// Run a script file: relative to the including script for `\ir`.
    Include {
        path: String,
        relative: bool,
    },
    /// Later statements run against another connection. `file` is a
    /// database file the client opens (sqlite `.open`).
    Connect {
        database: Switch,
        server: Switch,
        file: Option<String>,
    },
    /// A shell command the client runs (psql backquotes and `\!`, `.shell`).
    Shell(String),
    /// sqlite `.restore ?DB? FILE`: replaces the contents of the connected
    /// database, or of the attached schema `DB`, with FILE's.
    Restore(Option<String>),
    /// A client command this model does not interpret.
    Opaque(String),
    /// Nothing after this command can be analyzed.
    Stop(String),
}

/// How a connection switch changes one part of the connection.
#[derive(Debug, PartialEq, Eq)]
enum Switch {
    Keep,
    Set(String),
    /// The client names a value we cannot recover (a variable, a named
    /// connection from its configuration).
    Unknown,
}

impl Switch {
    /// A command word naming a value, where `-` or absence keeps it.
    fn word(word: Option<&&str>) -> Self {
        match word {
            None | Some(&"-") => Switch::Keep,
            Some(word) if word.contains(['`', '\'', '"', '$']) || word.starts_with(':') => {
                Switch::Unknown
            }
            Some(word) => Switch::Set(word.trim_matches('`').to_string()),
        }
    }
}

/// Lexical facts at one byte of client input: whether it is outside every
/// literal and comment, and whether a statement is partly buffered.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Position {
    code: bool,
    pending: bool,
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
/// reading string literals with or without backslash escapes.
fn positions(text: &str, dialect: SqlDialect, backslash_escapes: bool) -> Vec<Position> {
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
                b'\'' | b'"' | b'`' => {
                    state = LexState::Quote(c);
                    pending = true;
                }
                b'[' if dialect == SqlDialect::TSql => {
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
                b';' => pending = false,
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
                    if next == Some(b']') {
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
fn escape_readings(dialect: SqlDialect) -> &'static [bool] {
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
fn client_segments(
    text: &str,
    meta: Meta,
    dialect: SqlDialect,
    backslash_escapes: bool,
) -> Vec<Segment> {
    if meta == Meta::None {
        return vec![Segment::Sql(text.to_string())];
    }
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    // Lexical positions are relative to `base`, where lexing last restarted:
    // a client command's arguments are not SQL, so lexing resumes after it.
    let mut base = 0;
    let mut lexed = positions(text, dialect, backslash_escapes);
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
                let (segment, end) = mysql_command(text, i, eol);
                (segment.into_iter().collect(), end)
            }
            Meta::Sqlite => (dot_command(&text[i..eol]).into_iter().collect(), eol),
            Meta::Sqlcmd => (sqlcmd_command(&text[i..eol]).into_iter().collect(), eol),
            Meta::Snow => (snow_command(&text[i..eol]).into_iter().collect(), eol),
            Meta::Cql => {
                let end = (i..eol)
                    .find(|&j| bytes[j] == b';' && lexed[j - base].code)
                    .map_or(eol, |j| j + 1);
                (cql_command(&text[i..end]).into_iter().collect(), end)
            }
            Meta::None => unreachable!(),
        };
        push_sql(&mut out, &text[start..i]);
        for segment in segments {
            let stop = matches!(segment, Segment::Stop(_));
            out.push(segment);
            if stop {
                return out;
            }
        }
        start = end;
        i = end;
        base = end;
        lexed = positions(&text[end..], dialect, backslash_escapes);
    }
    if out.is_empty() && start == 0 {
        return vec![Segment::Sql(text.to_string())];
    }
    push_sql(&mut out, &text[start..]);
    out
}

fn push_sql(out: &mut Vec<Segment>, sql: &str) {
    if !sql.trim().is_empty() {
        out.push(Segment::Sql(sql.to_string()));
    }
}

/// Whether `line` (the rest of a line from a non-blank byte) begins a client
/// command, and if so whether that command needs no statement partly
/// buffered before it.
fn command_start(meta: Meta, line: &str, at_line_start: bool) -> Option<bool> {
    let word = leading_word(line);
    match meta {
        Meta::Psql => line.starts_with('\\').then_some(false),
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
            && (line.starts_with(':') || line.starts_with("!!") || is_go(line)))
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

/// The leading run of word characters, if a word boundary follows it.
fn leading_word(text: &str) -> &str {
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

fn include(args: &str, relative: bool, client: &str) -> Segment {
    match first_arg(args) {
        Some(path) => Segment::Include { path, relative },
        None => Segment::Opaque(format!(
            "{client} include path is not statically recoverable"
        )),
    }
}

/// psql meta-commands whose argument is the whole rest of the line.
const PSQL_LINE_COMMANDS: &[&str] = &["!", "copy", "ef", "ev", "h", "help", "sf", "sv"];

/// A psql (or cockroach sql) meta-command starting at `text[i]`, a
/// backslash, with `eol` the end of its line: its segments, and where input
/// resumes. Arguments end at the next unquoted backslash, which starts
/// another command; `\\` returns to SQL.
fn psql_meta(text: &str, i: usize, eol: usize) -> (Vec<Segment>, usize) {
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
    let mut segments = shells.into_iter().map(Segment::Shell).collect::<Vec<_>>();
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
fn psql_command(name: &str, args: &str) -> Option<Segment> {
    match name {
        "i" | "include" => Some(include(args, false, "psql")),
        "ir" | "include_relative" => Some(include(args, true, "psql")),
        "c" | "connect" => Some(psql_connect(args)),
        "cd" => Some(Segment::Stop(
            "psql \\cd changes the directory later scripts resolve against".into(),
        )),
        "g" | "gx" | "s" if !args.is_empty() => Some(Segment::Opaque(format!(
            "psql \\{name} writes to a file or command"
        ))),
        "!" if args.is_empty() => Some(Segment::Opaque(
            "psql \\! starts an interactive shell".into(),
        )),
        "!" => Some(Segment::Shell(args.to_string())),
        _ if PSQL_INERT.contains(&name) || name.starts_with('d') => None,
        _ => Some(Segment::Opaque(format!(
            "psql meta-command \\{name} is not modeled"
        ))),
    }
}

/// psql `\\c [dbname [username [host [port]]]]`, or a connection string.
fn psql_connect(args: &str) -> Segment {
    let words = args
        .split_whitespace()
        .filter(|word| !word.starts_with("-reuse-previous"))
        .collect::<Vec<_>>();
    let Some(first) = words.first() else {
        return connect(Switch::Keep, Switch::Keep);
    };
    if !first.contains(['=', ':']) {
        return connect(Switch::word(words.first()), Switch::word(words.get(2)));
    }
    let conninfo = words.join(" ");
    let conninfo = conninfo.trim_matches(['\'', '"']);
    match parse_conn_url(conninfo, PG_SCHEMES).or_else(|| parse_conninfo(conninfo)) {
        Some((server, database)) => connect(
            database.map_or(Switch::Keep, Switch::Set),
            server.map_or(Switch::Keep, Switch::Set),
        ),
        None => connect(Switch::Unknown, Switch::Unknown),
    }
}

fn connect(database: Switch, server: Switch) -> Segment {
    Segment::Connect {
        database,
        server,
        file: None,
    }
}

/// psql commands that change only client display or variables, or read the
/// catalog (`\d...`).
const PSQL_INERT: &[&str] = &[
    "set",
    "unset",
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
    "prompt",
    "errverbose",
    "if",
    "elif",
    "else",
    "endif",
    "p",
    "print",
    "r",
    "reset",
    "g",
    "gx",
    "s",
    "gset",
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
const MYSQL_NAMED: &[&str] = &[
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
/// (`\.`) may appear mid-line; most take arguments up to `;` or end of line.
fn mysql_command(text: &str, i: usize, eol: usize) -> (Option<Segment>, usize) {
    // A command's parameters end at the delimiter; mysql reads the rest of
    // the line as SQL.
    let delimited = text[i..eol].find(';').map_or(eol, |n| i + n + 1);
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
                        Some(Segment::Opaque(format!(
                            "mysql client command \\{short} is not modeled"
                        ))),
                        delimited,
                    );
                }
            };
            (name.to_string(), &rest[short.len_utf8()..])
        }
        None => {
            let word = leading_word(line);
            (word.to_ascii_lowercase(), &line[word.len()..])
        }
    };
    if name == "system" {
        // The shell gets the whole rest of the line, `;` included. After
        // `\\!` mysql resumes SQL past the delimiter; `system` takes the line.
        let command = args.trim();
        let segment = if command.is_empty() {
            Segment::Opaque("mysql system without a command".into())
        } else {
            Segment::Shell(command.to_string())
        };
        return (Some(segment), if backslash { delimited } else { eol });
    }
    let args = args.split(';').next().unwrap_or_default().trim();
    let segment = match name.as_str() {
        "source" => Some(include(args, false, "mysql")),
        "use" | "connect" => {
            // `use db`, `connect [db [host]]`.
            let words = args.split_whitespace().collect::<Vec<_>>();
            let host = if name == "connect" {
                Switch::word(words.get(1))
            } else {
                Switch::Keep
            };
            Some(connect(Switch::word(words.first()), host))
        }
        "delimiter" => Some(Segment::Stop(
            "mysql DELIMITER changes how later statements split".into(),
        )),
        "tee" | "pager" | "edit" => Some(Segment::Opaque(format!(
            "mysql {name} sends output to a file or command"
        ))),
        _ => None,
    };
    (segment, delimited)
}

/// A sqlite3 (or duckdb) dot-command line.
fn dot_command(line: &str) -> Option<Segment> {
    let rest = &line[1..];
    let name_len = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, args) = (&rest[..name_len], rest[name_len..].trim());
    match name {
        "read" if args.starts_with('|') || args.starts_with("'|") => Some(Segment::Opaque(
            "dot-command .read runs a shell command".into(),
        )),
        "read" => Some(include(args, false, "dot-command .read")),
        "open" => {
            let file = args
                .split_whitespace()
                .rfind(|word| !word.starts_with('-'))
                .map(|word| word.trim_matches(['\'', '"']).to_string());
            Some(Segment::Connect {
                database: file.clone().map_or(Switch::Unknown, Switch::Set),
                server: Switch::Keep,
                file,
            })
        }
        "connection" if !args.is_empty() => Some(connect(Switch::Unknown, Switch::Keep)),
        // sqlite unquotes the arguments and rebuilds the command line, which
        // matches the text only when it has no quoting.
        "shell" | "system" if args.contains(['\'', '"', '\\']) => Some(Segment::Opaque(format!(
            "dot-command .{name} runs a shell command sqlite rebuilds from quoted arguments"
        ))),
        "shell" | "system" if !args.is_empty() => Some(Segment::Shell(args.to_string())),
        "cd" => Some(Segment::Stop(
            "dot-command .cd changes the directory later scripts resolve against".into(),
        )),
        // sqlite unquotes the arguments, so only plain words are read.
        "restore" if !args.contains(['\'', '"', '\\']) => {
            match args.split_whitespace().collect::<Vec<_>>()[..] {
                [_] => Some(Segment::Restore(None)),
                [schema, _] => Some(Segment::Restore(Some(schema.to_string()))),
                _ => Some(Segment::Opaque(
                    "dot-command .restore arguments are not modeled".into(),
                )),
            }
        }
        _ if DOT_INERT.contains(&name) => None,
        _ => Some(Segment::Opaque(format!(
            "dot-command .{name} is not modeled"
        ))),
    }
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
fn is_go(line: &str) -> bool {
    let line = line.split("--").next().unwrap_or_default().trim();
    let Some(rest) = line.get(..2).filter(|go| go.eq_ignore_ascii_case("go")) else {
        return false;
    };
    let count = line[rest.len()..].trim();
    (line.len() == 2 || line[2..].starts_with([' ', '\t']))
        && count.chars().all(|c| c.is_ascii_digit())
}

/// A sqlcmd command line: `GO`, `:r file`, `:setvar`, `!! cmd`, and so on.
fn sqlcmd_command(line: &str) -> Option<Segment> {
    if is_go(line) {
        return None;
    }
    let rest = line
        .strip_prefix(':')
        .unwrap_or(line)
        .trim_start_matches(' ');
    if let Some(command) = rest.strip_prefix("!!") {
        return Some(match command.trim() {
            "" => Segment::Opaque("sqlcmd !! without a command".into()),
            command => Segment::Shell(command.to_string()),
        });
    }
    let name_len = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let (name, args) = (
        rest[..name_len].to_ascii_lowercase(),
        rest[name_len..].trim(),
    );
    match name.as_str() {
        "r" => Some(include(args, false, "sqlcmd :r")),
        // `:connect server[\\instance] [-l timeout] [-U user [-P password]]`
        // logs in to that server's default database.
        "connect" => Some(connect(
            Switch::Unknown,
            match Switch::word(args.split_whitespace().next().as_ref()) {
                Switch::Set(server) => Switch::Set(host_name(&server)),
                _ => Switch::Unknown,
            },
        )),
        "out" | "error" | "perftrace"
            if !["stdout", "stderr"].contains(&args.to_ascii_lowercase().as_str()) =>
        {
            Some(Segment::Opaque(format!("sqlcmd :{name} writes to a file")))
        }
        "exit" if args.starts_with('(') && args != "()" => {
            Some(Segment::Opaque("sqlcmd :exit runs a query".into()))
        }
        "setvar" | "on" | "out" | "error" | "perftrace" | "exit" | "quit" | "reset" | "list"
        | "listvar" | "serverlist" | "xml" | "help" => None,
        _ => Some(Segment::Opaque(format!(
            "sqlcmd command :{name} is not modeled"
        ))),
    }
}

/// A SnowSQL or Snowflake CLI `!command` line.
fn snow_command(line: &str) -> Option<Segment> {
    let rest = &line[1..];
    let name_len = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let (name, args) = (
        rest[..name_len].to_ascii_lowercase(),
        rest[name_len..].trim().trim_end_matches(';'),
    );
    match name.as_str() {
        "source" | "load" => Some(include(args, false, "!source")),
        "system" if args.is_empty() => Some(Segment::Opaque("!system without a command".into())),
        "system" => Some(Segment::Shell(args.to_string())),
        "spool" | "edit" => Some(Segment::Opaque(format!(
            "!{name} writes to a file or runs an editor"
        ))),
        // A named connection from the client's configuration.
        "connect" => Some(connect(Switch::Unknown, Switch::Unknown)),
        "set" | "print" | "define" | "variables" | "options" | "queries" | "result" | "abort"
        | "quit" | "exit" | "disconnect" | "help" | "rehash" | "pause" => None,
        _ => Some(Segment::Opaque(format!("!{name} is not modeled"))),
    }
}

/// A cqlsh shell command that starts a statement.
fn cql_command(statement: &str) -> Option<Segment> {
    let word = leading_word(statement);
    let args = statement[word.len()..].trim().trim_end_matches(';');
    if word.eq_ignore_ascii_case("SOURCE") {
        return Some(include(args, false, "cqlsh SOURCE"));
    }
    Some(Segment::Opaque(format!(
        "cqlsh {} reads or writes a file",
        word.to_ascii_uppercase()
    )))
}

macro_rules! client_model {
    ($model:ident, $id:literal, [$($name:literal),+], $apply:expr) => {
        struct $model;

        impl CommandModel for $model {
            fn domains(&self) -> &'static [&'static str] {
                &crate::builder::KNOWN_DOMAINS
            }

            fn id(&self) -> &'static str {
                $id
            }

            fn command_names(&self) -> &'static [&'static str] {
                &[$($name),+]
            }

            fn apply(
                &self,
                builder: &mut PlanBuilder,
                ctx: &InvocationCtx,
                model_node: ProvenanceRef,
            ) {
                let apply: fn(&mut PlanBuilder, &InvocationCtx, ProvenanceRef) = $apply;
                apply(builder, ctx, model_node);
            }
        }
    };
}

client_model!(Psql, "postgres/psql@v0", ["psql"], |builder, ctx, node| {
    sql_client(builder, ctx, node, &PSQL, 0)
});

client_model!(
    Mysql,
    "mysql/mysql@v0",
    ["mysql", "mariadb"],
    |builder, ctx, node| sql_client(builder, ctx, node, &MYSQL, 0)
);

client_model!(
    Sqlite,
    "sqlite/sqlite3@v0",
    ["sqlite3"],
    |builder, ctx, node| { sql_client(builder, ctx, node, &SQLITE, 0) }
);

client_model!(
    Duckdb,
    "duckdb/duckdb@v0",
    ["duckdb"],
    |builder, ctx, node| { sql_client(builder, ctx, node, &DUCKDB, 0) }
);

client_model!(
    Cockroach,
    "cockroach/cockroach@v0",
    ["cockroach"],
    |builder, ctx, node| subcommand_client(builder, ctx, node, "sql", &COCKROACH_SQL)
);

client_model!(
    Cqlsh,
    "cassandra/cqlsh@v0",
    ["cqlsh"],
    |builder, ctx, node| { sql_client(builder, ctx, node, &CQLSH, 0) }
);

client_model!(
    Clickhouse,
    "clickhouse/client@v0",
    ["clickhouse-client", "clickhouse"],
    |builder, ctx, node| {
        if ctx.argv[0].as_literal() == Some("clickhouse-client") {
            sql_client(builder, ctx, node, &CLICKHOUSE, 0)
        } else {
            subcommand_client(builder, ctx, node, "client", &CLICKHOUSE)
        }
    }
);

client_model!(
    Sqlcmd,
    "mssql/sqlcmd@v0",
    ["sqlcmd"],
    |builder, ctx, node| { sql_client(builder, ctx, node, &SQLCMD, 0) }
);

client_model!(
    Snowsql,
    "snowflake/snowsql@v0",
    ["snowsql"],
    |builder, ctx, node| { sql_client(builder, ctx, node, &SNOWSQL, 0) }
);

client_model!(Snow, "snowflake/snow@v0", ["snow"], |builder, ctx, node| {
    subcommand_client(builder, ctx, node, "sql", &SNOW_SQL)
});

/// A multi-command tool whose SQL client is one subcommand (`cockroach sql`).
fn subcommand_client(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    subcommand: &str,
    spec: &ClientSpec,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    match ctx.argv.get(1).map(Word::as_literal) {
        Some(Some(name)) if name == subcommand => sql_client(builder, ctx, model_node, spec, 1),
        None | Some(Some("help" | "--help" | "-h" | "--version")) => {}
        Some(name) => unmodeled_subcommand(
            builder,
            model_node,
            &format!("subcommand {} is not modeled", name.unwrap_or("(dynamic)")),
        ),
    }
}

/// `bq` global options that take a value.
const BQ_VALUES: &[&str] = &[
    "--project_id",
    "--dataset_id",
    "--location",
    "--api",
    "--api_version",
    "--format",
    "--apilog",
    "--bigqueryrc",
    "--credential_file",
    "--service_account",
    "--service_account_credential_file",
    "--service_account_private_key_file",
    "--service_account_private_key_password",
    "--discovery_file",
    "--job_property",
    "--max_rows_per_request",
    "--trace",
    "--httplib2_debuglevel",
    "--ca_certificates_file",
    "--proxy_address",
    "--proxy_port",
    "--proxy_username",
    "--proxy_password",
    "--universe_domain",
    "--job_id",
];

/// `bq query` options that take a value.
const BQ_QUERY_VALUES: &[&str] = &[
    "--destination_table",
    "--parameter",
    "--max_rows",
    "-n",
    "--maximum_bytes_billed",
    "--label",
    "--job_timeout",
    "--destination_kms_key",
    "--time_partitioning_field",
    "--time_partitioning_type",
    "--time_partitioning_expiration",
    "--clustering_fields",
    "--range_partitioning",
    "--schema_update_option",
    "--external_table_definition",
    "--udf_resource",
    "--connection_property",
    "--session_id",
    "--reservation_id",
    "--script_statement_timeout_ms",
    "--script_statement_byte_budget",
    "--min_completion_ratio",
    "--start_row",
    "-s",
    "--destination_schema",
];

/// `bq` boolean options, each also spelled `--noNAME` and `--NAME=BOOL`.
const BQ_BOOLS: &[&str] = &[
    "--use_legacy_sql",
    "--dry_run",
    "--replace",
    "--append_table",
    "--batch",
    "--use_cache",
    "--allow_large_results",
    "--flatten_results",
    "--require_cache",
    "--rpc",
    "--sync",
    "--continuous",
    "--create_session",
    "--headless",
    "--quiet",
    "-q",
    "--enable_gdrive",
    "--fingerprint_job_id",
    "--synchronous_mode",
    "--debug_mode",
    "--use_gce_service_account",
    "--disable_ssl_validation",
    "--mtls",
];

/// One parsed `bq` option.
enum BqOption<'w> {
    Value(&'static str, &'w Word, usize),
    Bool(&'static str, bool),
    Unknown(String),
}

/// Parse a `bq` option at `i`, and how many argv words it used. bq accepts
/// `--name value`, `--name=value`, `--flag`, `--noflag` and `--flag=false`.
fn bq_option<'w>(argv: &'w [Word], i: usize, values: &[&'static str]) -> (BqOption<'w>, usize) {
    let text = argv[i].literal_prefix();
    let (name, attached) = match text.split_once('=') {
        Some((name, _)) => (name, true),
        None => (text, false),
    };
    if let Some(flag) = values.iter().chain(BQ_VALUES).find(|flag| **flag == name) {
        // An attached value stays in its word; callers strip `--name=`.
        return if attached {
            (BqOption::Value(flag, &argv[i], i), 1)
        } else if i + 1 < argv.len() {
            (BqOption::Value(flag, &argv[i + 1], i + 1), 2)
        } else {
            (BqOption::Unknown(name.to_string()), 1)
        };
    }
    let negated = name.strip_prefix("--no").map(|rest| format!("--{rest}"));
    for flag in BQ_BOOLS {
        if name == *flag {
            // absl reads `false`, `f`, `0`, `no` and `n` (any case) as off;
            // anything else it does not reject is on.
            let on = text.split_once('=').is_none_or(|(_, value)| {
                !["false", "f", "0", "no", "n"]
                    .iter()
                    .any(|off| value.eq_ignore_ascii_case(off))
            });
            return (BqOption::Bool(flag, on), 1);
        }
        if !attached && negated.as_deref() == Some(*flag) {
            return (BqOption::Bool(flag, false), 1);
        }
    }
    (BqOption::Unknown(name.to_string()), 1)
}

const BQ: ClientSpec = ClientSpec {
    dialect: SqlDialect::BigQuery,
    ..CLIENT
};

/// `bq query`: the `bq` command model dispatches its `query` subcommand here
/// with the whole argv, global options included.
pub(crate) fn bq_query(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    let argv = ctx.argv;
    let mut project = None;
    let mut unknown = Vec::new();
    let mut i = 1;
    while i < argv.len() && argv[i].literal_prefix().starts_with('-') {
        let (option, used) = bq_option(argv, i, &[]);
        match option {
            BqOption::Value("--project_id", value, _) => {
                project = value.as_literal().map(|text| {
                    text.split_once('=')
                        .map_or(text, |(_, value)| value)
                        .to_string()
                })
            }
            BqOption::Unknown(name) => unknown.push((i as u32, name)),
            _ => {}
        }
        i += used;
    }
    // The caller dispatched here on this word, `query`.
    let mut sql = Vec::new();
    let (mut dry_run, mut replace) = (false, false);
    let mut destination = None;
    let mut help = false;
    i += 1;
    while i < argv.len() {
        let text = argv[i].literal_prefix();
        if !text.starts_with('-') || text == "-" {
            sql.push(i);
            i += 1;
            continue;
        }
        if text == "--help" {
            help = true;
        }
        let (option, used) = bq_option(argv, i, BQ_QUERY_VALUES);
        match option {
            BqOption::Value("--destination_table", value, index) => {
                destination = Some((value, index))
            }
            BqOption::Value("--project_id", value, _) => {
                project = value.as_literal().map(|text| {
                    text.split_once('=')
                        .map_or(text, |(_, value)| value)
                        .to_string()
                })
            }
            BqOption::Bool("--dry_run", on) => dry_run = on,
            BqOption::Bool("--replace", on) => replace = on,
            BqOption::Unknown(name) => unknown.push((i as u32, name)),
            _ => {}
        }
        i += used;
    }
    if help && unknown.is_empty() {
        return;
    }
    if !unknown.is_empty() {
        for domain in CLIENT_DOMAINS {
            builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
        }
        unrecognized_arguments_boundary(builder, model_node, CLIENT_DOMAINS, &unknown);
    }
    // A dry run validates the query and runs nothing.
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    if dry_run {
        return;
    }
    if let Some((word, index)) = destination {
        let text = word
            .as_literal()
            .map(|text| text.split_once('=').map_or(text, |(_, value)| value));
        let arg = arg_node(builder, ctx, index as u32);
        let resource = match text.and_then(|text| bq_table(text, project.as_deref())) {
            Some(identity) => ResourceExpr::Concrete { identity },
            None => ResourceExpr::Unresolved {
                family: ResourceFamily::new("db"),
            },
        };
        let action = if replace { "overwrite" } else { "insert" };
        database_effect(
            builder,
            "database.write",
            resource,
            Attrs::from([("action".to_string(), AttrValue::String(action.into()))]),
            vec![model_node, arg],
        );
    }
    let mut run = Run {
        ctx,
        model_node,
        spec: &BQ,
        meta: BQ.meta,
        conn: SqlConnection {
            server: None,
            database: project,
        },
        context: Vec::new(),
        substitute: false,
        includes: Vec::new(),
        stopped: false,
    };
    match sql.as_slice() {
        [] => run.stdin(builder),
        [index] => run.program(builder, Program::Sql(argv[*index].clone(), *index)),
        indices => {
            // bq joins its query operands with spaces.
            let words = indices
                .iter()
                .map(|index| argv[*index].as_literal())
                .collect::<Option<Vec<_>>>();
            let query = words.map_or_else(
                || Word::new(vec![crate::word::WordPart::Unknown]),
                |words| Word::literal(words.join(" ")),
            );
            run.program(builder, Program::Sql(query, indices[0]));
        }
    }
}

/// A BigQuery table id, `[project:]dataset.table` or `project.dataset.table`.
fn bq_table(text: &str, project: Option<&str>) -> Option<ResourceIdentity> {
    let (project, rest) = match text.split_once(':') {
        Some((project, rest)) => (Some(project), rest),
        None => (project, text),
    };
    let parts = rest.split('.').collect::<Vec<_>>();
    let (project, dataset, table) = match parts.as_slice() {
        [dataset, table] => (project, *dataset, *table),
        [project, dataset, table] => (Some(*project), *dataset, *table),
        _ => return None,
    };
    Some(ResourceIdentity::DatabaseTable {
        server: None,
        database: project.map(str::to_string),
        schema: Some(dataset.to_string()),
        table: table.to_string(),
    })
}

/// A database a client drops by name (`dropdb app`, `mysqladmin drop app`).
fn drop_database(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    server: &Option<String>,
    name: (usize, &Word),
    context: &[usize],
) {
    let mut provenance = vec![model_node, arg_node(builder, ctx, name.0 as u32)];
    if ctx.tracks_host_context_environment() {
        provenance.extend(
            context
                .iter()
                .map(|index| arg_node(builder, ctx, *index as u32)),
        );
    }
    let resource = match name.1.as_literal() {
        Some(database) => ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseSchema {
                server: server.clone(),
                database: Some(database.to_string()),
                schema: None,
            },
        },
        None => ResourceExpr::Unresolved {
            family: ResourceFamily::new("db"),
        },
    };
    database_effect(
        builder,
        "database.schema_drop",
        resource,
        object_kind("database"),
        provenance,
    );
}

struct Dropdb;

impl CommandModel for Dropdb {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "postgres/dropdb@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["dropdb"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let scanned = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &[
                    "-h",
                    "--host",
                    "-p",
                    "--port",
                    "-U",
                    "--username",
                    "--maintenance-db",
                ],
                known_flags: &[
                    "-e",
                    "--echo",
                    "-i",
                    "--interactive",
                    "--if-exists",
                    "-f",
                    "--force",
                    "-w",
                    "--no-password",
                    "-W",
                    "--password",
                    "-V",
                    "--version",
                    "-?",
                    "--help",
                ],
            },
            true,
        );
        if scanned.has(&["-V", "--version", "-?", "--help"]) && scanned.unknown_flags.is_empty() {
            return;
        }
        if !scanned.unknown_flags.is_empty() {
            for domain in CLIENT_DOMAINS {
                builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
            }
            unrecognized_arguments_boundary(
                builder,
                model_node,
                CLIENT_DOMAINS,
                &scanned.unknown_flags,
            );
        }
        let (server, server_index, port, port_index) =
            endpoint(&scanned, &["-h", "--host"], &["-p", "--port"]);
        connect_effect(
            builder,
            ctx,
            model_node,
            &server,
            port,
            Some("postgresql"),
            &[server_index, port_index]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        );
        let Some(&(index, name)) = scanned.operands.first() else {
            return;
        };
        let extra = scanned.operands[1..]
            .iter()
            .map(|(_, word)| word.as_literal().unwrap_or("?"))
            .collect::<Vec<_>>();
        unrecognized_operands(builder, model_node, &extra);
        drop_database(
            builder,
            ctx,
            model_node,
            &server,
            (index as usize, name),
            &server_index.into_iter().collect::<Vec<_>>(),
        );
    }
}

/// The host and port a scanned client selects, with their argv positions.
fn endpoint(
    scanned: &Scanned,
    host: &[&str],
    port: &[&str],
) -> (Option<String>, Option<usize>, Option<u16>, Option<usize>) {
    let host = scanned.values_of(host).last().copied();
    let port = scanned.values_of(port).last().copied();
    (
        host.and_then(|(_, word)| word.as_literal().map(str::to_string)),
        host.map(|(index, _)| index as usize),
        port.and_then(|(_, word)| word.as_literal()?.parse().ok()),
        port.map(|(index, _)| index as usize),
    )
}

/// mysqladmin commands that only report server state.
const MYSQLADMIN_READS: &[&str] = &[
    "ping",
    "status",
    "extended-status",
    "processlist",
    "variables",
    "version",
];

/// Every mysqladmin command; a command may be abbreviated to a unique prefix.
const MYSQLADMIN_COMMANDS: &[&str] = &[
    "create",
    "debug",
    "drop",
    "extended-status",
    "flush-hosts",
    "flush-logs",
    "flush-privileges",
    "flush-status",
    "flush-tables",
    "flush-threads",
    "kill",
    "password",
    "ping",
    "processlist",
    "purge",
    "reload",
    "refresh",
    "shutdown",
    "start-replica",
    "start-slave",
    "status",
    "stop-replica",
    "stop-slave",
    "variables",
    "version",
];

const MYSQLADMIN: ClientSpec = ClientSpec {
    host: &["-h", "--host"],
    port: &["-P", "--port"],
    values: &[
        "-u",
        "--user",
        "-S",
        "--socket",
        "-c",
        "--count",
        "-i",
        "--sleep",
        "--connect-timeout",
        "--shutdown-timeout",
        "--defaults-file",
        "--defaults-extra-file",
        "--defaults-group-suffix",
        "--login-path",
        "--protocol",
        "--default-auth",
        "--plugin-dir",
        "--character-sets-dir",
        "--default-character-set",
        "--bind-address",
        "--compression-algorithms",
        "--zstd-compression-level",
        "--ssl-ca",
        "--ssl-capath",
        "--ssl-cert",
        "--ssl-cipher",
        "--ssl-crl",
        "--ssl-crlpath",
        "--ssl-key",
        "--ssl-mode",
        "--tls-version",
        "--tls-ciphersuites",
        "--server-public-key-path",
    ],
    switches: &[
        "-f",
        "--force",
        "-s",
        "--silent",
        "-v",
        "--verbose",
        "-r",
        "--relative",
        "-E",
        "--vertical",
        "-C",
        "--compress",
        "-b",
        "--no-beep",
        "-T",
        "--debug-info",
        "--no-defaults",
        "--print-defaults",
        "--enable-cleartext-plugin",
        "--get-server-public-key",
        "--show-warnings",
        "--ssl",
        "--skip-ssl",
        "-w",
        "--wait",
    ],
    help: &["-?", "--help", "-V", "--version"],
    attached_only: &["-p", "--password"],
    ..CLIENT
};

struct Mysqladmin;

impl CommandModel for Mysqladmin {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "mysql/mysqladmin@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mysqladmin"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let words = client_words(ctx.argv, &MYSQLADMIN);
        let flags = flag_lists(&MYSQLADMIN);
        let scanned = scan_client(&words, &flags, &MYSQLADMIN);
        if scanned.has(MYSQLADMIN.help) && scanned.unknown_flags.is_empty() {
            return;
        }
        if !scanned.unknown_flags.is_empty() {
            for domain in CLIENT_DOMAINS {
                builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
            }
            unrecognized_arguments_boundary(
                builder,
                model_node,
                CLIENT_DOMAINS,
                &scanned.unknown_flags,
            );
        }
        let (server, server_index, port, port_index) =
            endpoint(&scanned, MYSQLADMIN.host, MYSQLADMIN.port);
        connect_effect(
            builder,
            ctx,
            model_node,
            &server,
            port,
            None,
            &[server_index, port_index]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        );
        let context = server_index.into_iter().collect::<Vec<_>>();
        let mut operands = scanned.operands.iter();
        let mut unmodeled = Vec::new();
        while let Some(&(_, word)) = operands.next() {
            let Some(text) = word.as_literal() else {
                unmodeled.push("?".to_string());
                continue;
            };
            let mut matches = MYSQLADMIN_COMMANDS
                .iter()
                .filter(|command| **command == text || command.starts_with(text));
            let command = match (matches.next(), matches.next()) {
                (Some(command), None) => *command,
                _ if MYSQLADMIN_COMMANDS.contains(&text) => text,
                _ => {
                    unmodeled.push(text.to_string());
                    continue;
                }
            };
            match command {
                "create" | "drop" => {
                    let Some(&(name_index, name)) = operands.next() else {
                        continue;
                    };
                    if command == "drop" {
                        drop_database(
                            builder,
                            ctx,
                            model_node,
                            &server,
                            (name_index as usize, name),
                            &context,
                        );
                        continue;
                    }
                    let resource = match name.as_literal() {
                        Some(database) => ResourceExpr::Concrete {
                            identity: ResourceIdentity::DatabaseSchema {
                                server: server.clone(),
                                database: Some(database.to_string()),
                                schema: None,
                            },
                        },
                        None => ResourceExpr::Unresolved {
                            family: ResourceFamily::new("db"),
                        },
                    };
                    let arg = arg_node(builder, ctx, name_index);
                    database_effect(
                        builder,
                        "database.write",
                        resource,
                        Attrs::from([("action".to_string(), AttrValue::String("create".into()))]),
                        vec![model_node, arg],
                    );
                }
                command if MYSQLADMIN_READS.contains(&command) => {}
                command => unmodeled.push(command.to_string()),
            }
        }
        if !unmodeled.is_empty() {
            unmodeled_subcommand(
                builder,
                model_node,
                &format!("mysqladmin commands not modeled: {}", unmodeled.join(", ")),
            );
        }
    }
}

struct PgRestore;

impl CommandModel for PgRestore {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "postgres/pg_restore@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["pg_restore"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let scanned = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &[
                    "-d",
                    "--dbname",
                    "-f",
                    "--file",
                    "-F",
                    "--format",
                    "-h",
                    "--host",
                    "-p",
                    "--port",
                    "-U",
                    "--username",
                    "-j",
                    "--jobs",
                    "-L",
                    "--use-list",
                    "-n",
                    "--schema",
                    "-N",
                    "--exclude-schema",
                    "-t",
                    "--table",
                    "-I",
                    "--index",
                    "-P",
                    "--function",
                    "-T",
                    "--trigger",
                    "-S",
                    "--superuser",
                    "--role",
                    "--section",
                    "--filter",
                    "--transaction-size",
                    "--exclude-database",
                ],
                known_flags: &[
                    "-a",
                    "--data-only",
                    "-c",
                    "--clean",
                    "-C",
                    "--create",
                    "-e",
                    "--exit-on-error",
                    "-l",
                    "--list",
                    "-O",
                    "--no-owner",
                    "-s",
                    "--schema-only",
                    "-v",
                    "--verbose",
                    "-x",
                    "--no-privileges",
                    "--no-acl",
                    "-1",
                    "--single-transaction",
                    "--disable-triggers",
                    "--enable-row-security",
                    "--if-exists",
                    "--no-comments",
                    "--no-data",
                    "--no-data-for-failed-tables",
                    "--no-policies",
                    "--no-publications",
                    "--no-schema",
                    "--no-security-labels",
                    "--no-statistics",
                    "--no-subscriptions",
                    "--no-table-access-method",
                    "--no-tablespaces",
                    "--statistics",
                    "--strict-names",
                    "--use-set-session-authorization",
                    "-w",
                    "--no-password",
                    "-W",
                    "--password",
                    "-V",
                    "--version",
                    "-?",
                    "--help",
                ],
            },
            true,
        );
        if scanned.has(&["-V", "--version", "-?", "--help"]) && scanned.unknown_flags.is_empty() {
            return;
        }
        if !scanned.unknown_flags.is_empty() {
            for domain in CLIENT_DOMAINS {
                builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
            }
            unrecognized_arguments_boundary(
                builder,
                model_node,
                CLIENT_DOMAINS,
                &scanned.unknown_flags,
            );
        }
        let mut operands = scanned.operands.iter();
        if let Some(&(index, archive)) = operands.next() {
            file_effect(builder, ctx, model_node, index, archive, "filesystem.read");
        }
        let extra = operands
            .map(|(_, word)| word.as_literal().unwrap_or("?"))
            .collect::<Vec<_>>();
        unrecognized_operands(builder, model_node, &extra);
        let Some(&(database_index, database)) = scanned.values_of(&["-d", "--dbname"]).last()
        else {
            // Without a database, pg_restore writes a SQL script instead.
            if let Some(&(index, file)) = scanned.values_of(&["-f", "--file"]).last() {
                file_effect(builder, ctx, model_node, index, file, "filesystem.write");
            }
            return;
        };
        let (mut server, mut server_index, port, port_index) =
            endpoint(&scanned, &["-h", "--host"], &["-p", "--port"]);
        let mut database = database.as_literal().map(str::to_string);
        if let Some((host, name)) = database
            .as_deref()
            .and_then(|text| parse_conn_url(text, PG_SCHEMES).or_else(|| parse_conninfo(text)))
        {
            database = name;
            if host.is_some() {
                server = host;
                server_index = Some(database_index as usize);
            }
        }
        connect_effect(
            builder,
            ctx,
            model_node,
            &server,
            port,
            Some("postgresql"),
            &[server_index, port_index]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        );
        let mut provenance = vec![model_node, arg_node(builder, ctx, database_index)];
        if ctx.tracks_host_context_environment()
            && let Some(index) = server_index
        {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
        let target = ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseSchema {
                server: server.clone(),
                database,
                schema: None,
            },
        };
        database_effect(
            builder,
            "database.write",
            target.clone(),
            Default::default(),
            provenance.clone(),
        );
        if !scanned.has(&["-c", "--clean"]) {
            return;
        }
        // --clean drops each archived object before recreating it. With
        // --create it drops and recreates the archive's own database, whose
        // name only the archive holds; -d is then just the first connection.
        if scanned.has(&["-C", "--create"]) {
            database_effect(
                builder,
                "database.schema_drop",
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new("db"),
                },
                object_kind("database"),
                provenance,
            );
        } else {
            database_effect(
                builder,
                "database.schema_drop",
                target,
                object_kind("database_objects"),
                provenance,
            );
        }
    }
}

/// A flag's value with its provenance argv index, and how many argv slots it
/// consumed. Handles `-x VALUE`, `-xVALUE`, `--long VALUE`, `--long=VALUE`.
struct FlagHit {
    value: Word,
    index: usize,
    consumed: usize,
}

/// Try to read one of `flags` (short like `-c`, long like `--command`) at
/// position `i`. A short flag may carry an attached value (`-cSQL`); a long
/// flag may use `=`. Detached values are taken from the next argv word.
fn read_flag(argv: &[Word], i: usize, flags: &'static [&'static str]) -> Option<FlagHit> {
    let scanned = crate::models::args::scan_with_value_indices(
        &argv[i - 1..(i + 2).min(argv.len())],
        &crate::models::args::FlagSpec {
            allow_abbreviation: false,
            value_flags: flags,
            known_flags: &[],
        },
        true,
    );
    let flag = scanned.flags.into_iter().find(|flag| flag.index == 1)?;
    let index = flag.value_index? as usize + i - 1;
    Some(FlagHit {
        value: flag.value?,
        index,
        consumed: if index == i { 1 } else { 2 },
    })
}

struct PgDump;

impl CommandModel for PgDump {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "postgres/pg_dump@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["pg_dump", "pg_dumpall"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        dump(
            builder,
            ctx,
            model_node,
            &["-d", "--dbname"],
            &["-h", "--host"],
            &["-f", "--file"],
            &[
                "-U",
                "--username",
                "-p",
                "--port",
                "-F",
                "--format",
                "-n",
                "--schema",
                "-t",
                "--table",
            ],
        );
    }
}

struct MysqlDump;

impl CommandModel for MysqlDump {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "mysql/mysqldump@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mysqldump"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        dump(
            builder,
            ctx,
            model_node,
            &["-B", "--databases"],
            &["-h", "--host"],
            &["-r", "--result-file"],
            &[
                "-u",
                "--user",
                "-P",
                "--port",
                "-S",
                "--socket",
                "--default-character-set",
            ],
        );
    }
}

/// A dump reads the whole database and, given `-f/-r file`, writes the file.
fn dump(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    db_flags: &'static [&'static str],
    host_flags: &'static [&'static str],
    out_flags: &'static [&'static str],
    value_flags: &'static [&'static str],
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    let mut server = None;
    let mut server_index = None;
    let mut database = None;
    let mut database_index = None;
    let mut out: Option<(usize, Word)> = None;
    let argv = ctx.argv;
    let mut i = 1;
    while i < argv.len() {
        if let Some(hit) = read_flag(argv, i, host_flags) {
            server = hit.value.as_literal().map(str::to_string);
            server_index = Some(hit.index);
            i += hit.consumed;
            continue;
        }
        if let Some(hit) = read_flag(argv, i, db_flags) {
            database = hit.value.as_literal().map(str::to_string);
            database_index = Some(hit.index);
            i += hit.consumed;
            continue;
        }
        if let Some(hit) = read_flag(argv, i, out_flags) {
            out = Some((hit.index, hit.value));
            i += hit.consumed;
            continue;
        }
        if let Some(hit) = read_flag(argv, i, value_flags) {
            i += hit.consumed;
            continue;
        }
        if let Some(text) = argv[i].as_literal()
            && !text.starts_with('-')
            && database_index.is_none()
        {
            database = Some(text.to_string());
            database_index = Some(i);
        }
        i += 1;
    }
    let endpoint_source_indices = server_index.into_iter().collect::<Vec<_>>();
    connect_effect(
        builder,
        ctx,
        model_node,
        &server,
        None,
        None,
        &endpoint_source_indices,
    );
    // Read the whole database's tables: an unresolved table under the scope.
    let mut provenance = Vec::new();
    if ctx.tracks_host_context_environment() {
        for index in [server_index, database_index].into_iter().flatten() {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
    }
    provenance.push(model_node);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("database.read"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseSchema {
                server,
                database,
                schema: None,
            },
        },
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
    if let Some((idx, word)) = out {
        file_effect(
            builder,
            ctx,
            model_node,
            idx as u32,
            &word,
            "filesystem.write",
        );
    }
}
