//! Data-store clients outside SQL: Redis keyspace flushes (reached from the
//! redis-cli messaging model), the Mongo shell, mongorestore, BigQuery's `bq
//! rm`, Bigtable's `cbt`, and the Firebase CLI's Firestore and Realtime
//! Database commands. Each emits `database.*` effects only for the forms it
//! recognizes; a whole-object removal carries the `object_kind`, `action`,
//! and `filtered` attributes a database-destruction query reads. Anything
//! unrecognized is a boundary, never a guessed effect.

use std::collections::HashMap;

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ProvenanceRef, ResourceExpr, ResourceIdentity, SourceDialect, Subject,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{Attrs, arg_node, boundary};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

pub(super) fn datastore_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Mongo),
        Box::new(Mongorestore),
        Box::new(Bq),
        Box::new(Cbt),
        Box::new(Firebase),
    ]
}

fn datastore_effect(
    builder: &mut PlanBuilder,
    provenance: Vec<ProvenanceRef>,
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) {
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

fn text_attrs(pairs: &[(&str, &str)]) -> Attrs {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), AttrValue::String(value.to_string())))
        .collect()
}

/// A database-level resource; with neither server nor database known it
/// names nothing, so it stays unresolved.
fn db_schema(server: Option<String>, database: Option<String>) -> ResourceExpr {
    if server.is_none() && database.is_none() {
        return unresolved_resource("db");
    }
    ResourceExpr::Concrete {
        identity: ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema: None,
        },
    }
}

fn db_table(
    server: Option<String>,
    database: Option<String>,
    schema: Option<String>,
    table: String,
) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::DatabaseTable {
            server,
            database,
            schema,
            table,
        },
    }
}

fn datastore_connect_effect(
    builder: &mut PlanBuilder,
    provenance: Vec<ProvenanceRef>,
    host: &str,
    scheme: &str,
) {
    let (host, port) = split_host_port(host);
    datastore_effect(
        builder,
        provenance,
        "network.connect",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme.to_string()),
                port,
                path: None,
            },
        },
        Attrs::new(),
    );
}

fn split_host_port(text: &str) -> (String, Option<u16>) {
    match text.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => match port.parse() {
            Ok(port) => (host.to_string(), Some(port)),
            Err(_) => (text.to_string(), None),
        },
        _ => (text.to_string(), None),
    }
}

/// An unmodeled subcommand of a newly modeled CLI receives no more analysis
/// than an unmodeled command did: every domain stays uncovered.
fn unmodeled_rest(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    for domain in KNOWN_DOMAINS {
        if domain != "process" {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
        }
    }
    let domains = KNOWN_DOMAINS
        .iter()
        .copied()
        .chain(["dataflow"])
        .collect::<Vec<_>>();
    boundary(
        builder,
        model_node,
        BoundaryReason::UNMODELED_SUBCOMMAND,
        BoundaryClass::Unmodeled,
        &domains,
        detail,
    );
}

/// Coverage for a recognized cloud-database command: the call reaches the
/// service over an endpoint the invocation does not name.
fn cloud_database_coverage(builder: &mut PlanBuilder, provenance: Vec<ProvenanceRef>) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    datastore_effect(
        builder,
        provenance,
        "network.connect",
        unresolved_resource("network"),
        Attrs::new(),
    );
}

// ---- Redis: FLUSHALL / FLUSHDB (dispatched from the redis-cli model) ----
//
// redis-cli rewrites and reroutes commands in many ways (tagged stdin
// arguments, quoted input, special modes, cluster fan-out, the REPL's own
// commands). The model states an exact flush target only for invocations it
// recognizes completely. Any other invocation that mentions a flush gets a
// truncate on an unresolved database with a boundary, so a flush is never
// missed and a concrete target is never guessed.

/// Options that consume a value and change nothing but connection details
/// or output; the target options (-h -p -s -n -u) are handled separately.
const REDIS_VALUE_OPTIONS: &[&str] = &[
    "-a",
    "--pass",
    "--user",
    "-r",
    "-i",
    "-t",
    "-d",
    "-D",
    "--pattern",
    "--quoted-pattern",
    "--count",
    "--cursor",
    "--top",
    "--pipe-timeout",
    "--sni",
    "--cacertdir",
    "--cacert",
    "--cert",
    "--key",
    "--tls-ciphers",
    "--tls-ciphersuites",
    "--show-pushes",
];

const REDIS_FLAG_OPTIONS: &[&str] = &[
    "-c",
    "-e",
    "-2",
    "-3",
    "-4",
    "-6",
    "--no-auth-warning",
    "--askpass",
    "--raw",
    "--no-raw",
    "--csv",
    "--json",
    "--quoted-json",
    "--mono",
    "--verbose",
    "--tls",
    "--insecure",
];

/// The connection redis-cli's options select: the server host and the
/// logical database a FLUSHDB would clear.
#[derive(Clone, Debug, PartialEq)]
struct RedisTarget {
    server: Option<String>,
    database: RedisDatabase,
    indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq)]
enum RedisDatabase {
    Number(String),
    Unknown,
}

/// Where a flush with an established target came from, for provenance.
#[derive(Debug, PartialEq)]
enum RedisFlushSource {
    Argv { command: usize },
    Cluster { node: usize, command: usize },
    Stdin,
}

#[derive(Debug, PartialEq)]
struct RedisFlush {
    flushall: bool,
    target: RedisTarget,
    source: RedisFlushSource,
}

/// What a redis-cli invocation does to keyspaces, and which argv command,
/// if any, the messaging model should read.
#[derive(Debug, Default, PartialEq)]
pub(super) struct RedisPlan {
    pub(super) help: bool,
    flushes: Vec<RedisFlush>,
    /// Some flush may run whose target is not established.
    unresolved_flush: bool,
    /// A server-side script runs and may issue a flush.
    script: bool,
    /// The invocation is not fully modeled.
    boundary: Option<&'static str>,
    /// An ordinary non-flush command after a fully recognized prefix.
    pub(super) command: Option<usize>,
}

fn redis_uri(uri: &str) -> Option<(Option<String>, Option<String>)> {
    let (scheme, rest) = uri.split_once("://")?;
    if !matches!(scheme, "redis" | "rediss" | "valkey" | "valkeys") {
        return None;
    }
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = split_host_port(host_port).0;
    let database = path
        .map(|path| path.split(['?', '#']).next().unwrap_or(path).to_string())
        .filter(|path| !path.is_empty());
    Some(((!host.is_empty()).then_some(host), database))
}

/// A database index written the way Redis accepts one: a canonical
/// non-negative integer (no sign, no leading zero) that fits an i32.
fn redis_database(text: Option<&str>) -> RedisDatabase {
    match text {
        Some(number)
            if (number == "0" || !number.starts_with('0'))
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && number.parse::<i32>().is_ok() =>
        {
            RedisDatabase::Number(number.to_string())
        }
        _ => RedisDatabase::Unknown,
    }
}

/// FLUSHALL or FLUSHDB with only its documented argument, in any case.
fn exact_flush(words: &[&str]) -> Option<bool> {
    let (name, arguments) = words.split_first()?;
    let flushall = if name.eq_ignore_ascii_case("FLUSHALL") {
        true
    } else if name.eq_ignore_ascii_case("FLUSHDB") {
        false
    } else {
        return None;
    };
    match arguments {
        [] => Some(flushall),
        [mode] if mode.eq_ignore_ascii_case("ASYNC") || mode.eq_ignore_ascii_case("SYNC") => {
            Some(flushall)
        }
        _ => None,
    }
}

/// Text with quote characters removed, `\xHH` escapes decoded, and other
/// backslashes dropped, as a way to see through redis-cli's quoting.
fn unquoted(text: &str) -> String {
    let mut plain = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {}
            '\\' if chars.peek() == Some(&'x') => {
                chars.next();
                let hex: String = [chars.next(), chars.next()].into_iter().flatten().collect();
                match u8::from_str_radix(&hex, 16) {
                    Ok(byte) => plain.push(char::from(byte)),
                    Err(_) => plain.push_str(&hex),
                }
            }
            '\\' => {}
            c => plain.push(c),
        }
    }
    plain
}

/// Whether text may name a flush once quoting and escapes are undone.
fn mentions_flush(text: &str) -> bool {
    let plain = unquoted(text).to_ascii_lowercase();
    plain.contains("flushall") || plain.contains("flushdb")
}

/// Commands that run a server-side script, which can build and issue a
/// flush from text no static reading establishes.
const REDIS_SCRIPT_COMMANDS: &[&str] = &[
    "EVAL",
    "EVAL_RO",
    "EVALSHA",
    "EVALSHA_RO",
    "FCALL",
    "FCALL_RO",
    "FUNCTION",
    "SCRIPT",
];

fn is_script_command(text: &str) -> bool {
    let plain = unquoted(text);
    REDIS_SCRIPT_COMMANDS
        .iter()
        .any(|command| plain.eq_ignore_ascii_case(command))
}

/// Whether any word of a piped line may run a script. A line can start with
/// a repeat count, so the command word is not assumed to come first.
fn script_line(line: &str) -> bool {
    line.split_ascii_whitespace().any(is_script_command)
}

/// Plan one redis-cli invocation. `stdin` is None without stdin, and
/// Some(None) when stdin is present but its bytes are not recovered.
pub(super) fn redis_plan(argv: &[Word], stdin: Option<Option<&str>>) -> RedisPlan {
    let mut plan = RedisPlan::default();
    let mut target = RedisTarget {
        server: None,
        database: RedisDatabase::Number("0".into()),
        indices: Vec::new(),
    };
    let mut socket = false;
    // Whether every option so far is one whose effect the model knows.
    let mut exact = true;
    let mut command = None;
    let mut index = 1;
    while index < argv.len() {
        let Some(text) = argv[index].as_literal() else {
            exact = false;
            break;
        };
        let value = argv.get(index + 1);
        match (text, value) {
            ("--help" | "-v" | "--version", _) | ("-h", None) => {
                plan.help = true;
                return plan;
            }
            ("-h", Some(value)) => {
                target.server = value.as_literal().map(str::to_string);
                target.indices.push(index + 1);
            }
            ("-s", Some(_)) => {
                // A Unix socket takes precedence over any host.
                socket = true;
                target.indices.push(index + 1);
            }
            ("-n", Some(value)) => {
                target.database = redis_database(value.as_literal());
                target.indices.push(index + 1);
            }
            ("-u", Some(value)) => {
                match value.as_literal().and_then(redis_uri) {
                    Some((host, path)) => {
                        target.server = host;
                        if let Some(path) = path {
                            target.database = redis_database(Some(&path));
                        }
                    }
                    None => {
                        target.server = None;
                        target.database = RedisDatabase::Unknown;
                    }
                }
                target.indices.push(index + 1);
            }
            ("-p", Some(_)) => {}
            (option, Some(_)) if REDIS_VALUE_OPTIONS.contains(&option) => {}
            (option, _) if REDIS_FLAG_OPTIONS.contains(&option) => {
                index += 1;
                continue;
            }
            // Everything else leaves the command or its dispatch
            // unestablished: special modes (--scan, --pipe, --rdb, --eval,
            // --memkeys-samples, --keystats-samples, ...), -x/-X stdin
            // arguments, --quoted-input, --cluster and its options, and
            // unknown options.
            (option, _) if option.starts_with('-') => {
                exact = false;
                break;
            }
            _ => {
                command = Some(index);
                break;
            }
        }
        index += 2;
    }
    if socket {
        target.server = None;
    }
    let words = || {
        argv.iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()
    };

    // Exact: a fully recognized prefix and a flush with documented arguments.
    if exact {
        match command {
            Some(command) => {
                if let Some(flushall) = words().and_then(|words| exact_flush(&words[command..])) {
                    plan.flushes.push(RedisFlush {
                        flushall,
                        target,
                        source: RedisFlushSource::Argv { command },
                    });
                    return plan;
                }
                let name = argv[command].as_literal().unwrap_or_default();
                plan.script = argv[command..]
                    .iter()
                    .any(|word| is_script_command(&word.render_raw()));
                if !mentions_flush(name) {
                    plan.command = Some(command);
                }
            }
            None => match stdin {
                Some(Some(script)) => {
                    redis_stdin(&mut plan, script, target);
                    return plan;
                }
                Some(None) => plan.boundary = Some("Redis commands on stdin are not recovered"),
                None => plan.boundary = Some("interactive Redis session"),
            },
        }
    } else if let Some(words) = words()
        && let ["--cluster", "call", node, rest @ ..] = &words[1..]
        && let Some(flushall) = exact_flush(rest).filter(|_| rest.len() == 1)
        && !node.starts_with('-')
    {
        // `--cluster call NODE FLUSH*` runs the flush on every node of the
        // cluster reached through NODE, where only database 0 exists.
        plan.flushes.push(RedisFlush {
            flushall,
            target: RedisTarget {
                server: Some(split_host_port(node).0),
                database: RedisDatabase::Number("0".into()),
                indices: Vec::new(),
            },
            source: RedisFlushSource::Cluster {
                node: 3,
                command: 4,
            },
        });
        plan.boundary = Some("redis-cli cluster mode");
        return plan;
    }
    if !exact {
        plan.boundary = Some("redis-cli options, mode, or input rewriting are not modeled");
    }

    // Fallback: any mention of a flush or a script in argv or stdin. The
    // command word is not established here, so any word counts.
    if !exact {
        plan.script |= argv.iter().skip(1).any(|word| {
            matches!(
                word.as_literal(),
                Some("--eval" | "--ldb" | "--ldb-sync-mode")
            ) || is_script_command(&word.render_raw())
        }) || matches!(stdin, Some(Some(script)) if script.split('\n').any(script_line));
    }
    let stdin_mentions = matches!(stdin, Some(Some(script)) if mentions_flush(script));
    if argv
        .iter()
        .skip(1)
        .any(|word| mentions_flush(&word.render_raw()))
        || (!exact && stdin_mentions)
    {
        plan.unresolved_flush = true;
    }
    plan
}

/// Piped commands with no command operand run one per line. Only lines of
/// plain words that are `SELECT n` or a documented flush are modeled. The
/// server may reject a SELECT, so it leaves the database unresolved; any
/// other line may change the connection too, so it leaves both unresolved.
/// Nothing restores a target once it is unresolved.
fn redis_stdin(plan: &mut RedisPlan, script: &str, mut target: RedisTarget) {
    for line in script.split('\n') {
        let plain = line.is_ascii() && !line.contains(['\\', '"', '\'']);
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        if plain && words.is_empty() {
            continue;
        }
        match words.as_slice() {
            [select, number]
                if plain
                    && select.eq_ignore_ascii_case("SELECT")
                    && matches!(redis_database(Some(number)), RedisDatabase::Number(_)) =>
            {
                target.database = RedisDatabase::Unknown;
                plan.boundary.get_or_insert(
                    "the database a piped SELECT leaves selected is not established",
                );
            }
            _ if plain && exact_flush(&words).is_some() => plan.flushes.push(RedisFlush {
                flushall: exact_flush(&words).unwrap(),
                target: target.clone(),
                source: RedisFlushSource::Stdin,
            }),
            _ => {
                plan.boundary = Some("Redis commands on stdin are not all modeled");
                plan.unresolved_flush |= mentions_flush(line);
                plan.script |= script_line(line);
                target.server = None;
                target.database = RedisDatabase::Unknown;
            }
        }
    }
}

fn emit_redis_flush(
    builder: &mut PlanBuilder,
    provenance: Vec<ProvenanceRef>,
    flushall: bool,
    server: Option<String>,
    database: &RedisDatabase,
) {
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    match &server {
        Some(server) => datastore_connect_effect(builder, provenance.clone(), server, "redis"),
        None => datastore_effect(
            builder,
            provenance.clone(),
            "network.connect",
            unresolved_resource("network"),
            Attrs::new(),
        ),
    }
    // FLUSHALL clears every logical database on the server; FLUSHDB clears
    // the selected one.
    let resource = match (flushall, database) {
        (true, _) => db_schema(server, None),
        (false, RedisDatabase::Number(number)) => db_schema(server, Some(number.clone())),
        (false, RedisDatabase::Unknown) => unresolved_resource("db"),
    };
    datastore_effect(
        builder,
        provenance,
        "database.truncate",
        resource,
        text_attrs(&[("object_kind", "keyspace")]),
    );
}

/// Emit a planned invocation's keyspace effects and its boundary.
pub(super) fn emit_redis_plan(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    plan: &RedisPlan,
) {
    let stdin_provenance = || {
        let mut provenance = vec![model_node];
        if let Some(stdin) = ctx.stdin {
            provenance.extend(stdin.provenance.iter().copied());
        }
        provenance
    };
    for flush in &plan.flushes {
        let provenance = match flush.source {
            RedisFlushSource::Argv { command } => {
                let mut provenance = vec![arg_node(builder, ctx, command as u32), model_node];
                for index in &flush.target.indices {
                    provenance.push(arg_node(builder, ctx, *index as u32));
                }
                provenance
            }
            RedisFlushSource::Cluster { node, command } => vec![
                arg_node(builder, ctx, command as u32),
                arg_node(builder, ctx, node as u32),
                model_node,
            ],
            RedisFlushSource::Stdin => stdin_provenance(),
        };
        emit_redis_flush(
            builder,
            provenance,
            flush.flushall,
            flush.target.server.clone(),
            &flush.target.database,
        );
    }
    if plan.unresolved_flush || plan.script {
        emit_redis_flush(
            builder,
            stdin_provenance(),
            false,
            None,
            &RedisDatabase::Unknown,
        );
    }
    if plan.script {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_DYNAMIC_CODE,
            BoundaryClass::Unmodeled,
            &["database", "messaging", "network"],
            "Redis script may issue a flush",
        );
    }
    let detail = if plan.unresolved_flush {
        Some("redis-cli flush could not be established exactly")
    } else {
        plan.boundary
    };
    if let Some(detail) = detail {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["database", "messaging", "network"],
            detail,
        );
    }
}

// ---- Mongo shell: a statement-level recognizer, not JS evaluation ----

struct Mongo;

impl CommandModel for Mongo {
    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "mongo/mongosh@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mongo", "mongosh"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let argv = ctx.argv;
        let mut evals = Vec::new();
        let mut files = false;
        let mut shell = false;
        let mut nodb = false;
        let mut unknown = Vec::new();
        let mut address: Option<(usize, &Word)> = None;
        let mut host: Option<(usize, &Word)> = None;
        let mut index = 1;
        while index < argv.len() {
            let word = &argv[index];
            let Some(text) = word.as_literal() else {
                if address.is_none() {
                    address = Some((index, word));
                } else {
                    files = true;
                }
                index += 1;
                continue;
            };
            let (name, attached) = match text.split_once('=') {
                Some((name, value)) if name.starts_with("--") => (name, Some(value)),
                _ => (text, None),
            };
            match name {
                "-h" | "--help" | "--version" | "--build-info" => return,
                "--eval" | "--host" | "-f" | "--file" => {
                    let (value_index, value) = match attached {
                        Some(_) => (index, None),
                        None => (index + 1, argv.get(index + 1)),
                    };
                    match name {
                        "--eval" => evals.push((value_index, value.cloned(), attached)),
                        "--host" => {
                            if let Some(value) = value {
                                host = Some((value_index, value));
                            }
                        }
                        _ => files = true,
                    }
                    index = value_index + 1;
                }
                "--json" => {
                    if attached.is_none()
                        && matches!(
                            argv.get(index + 1).and_then(Word::as_literal),
                            Some("canonical" | "relaxed")
                        )
                    {
                        index += 1;
                    }
                    index += 1;
                }
                "--shell" => {
                    shell = true;
                    index += 1;
                }
                "--nodb" => {
                    nodb = true;
                    index += 1;
                }
                _ if MONGO_VALUE_FLAGS.contains(&name) => {
                    index += if attached.is_some() { 1 } else { 2 };
                }
                _ if MONGO_BOOL_FLAGS.contains(&name) => index += 1,
                _ if text.starts_with('-') && text != "-" => {
                    unknown.push((index as u32, text.to_string()));
                    index += 1;
                }
                _ if text.ends_with(".js") => {
                    files = true;
                    index += 1;
                }
                _ => {
                    if address.is_none() {
                        address = Some((index, word));
                    } else {
                        files = true;
                    }
                    index += 1;
                }
            }
        }

        // The target: server and database the shell's `db` starts bound to.
        let mut target = MongoTarget::default();
        let mut scope_indices = Vec::new();
        if let Some((index, word)) = address {
            scope_indices.push(index);
            // mongosh connects to `test` when the address names no database.
            match word.as_literal().map(parse_mongo_address) {
                Some((server, database)) => {
                    target.server = server;
                    target.database = Some(database.unwrap_or_else(|| "test".into()));
                }
                None => target.database = None,
            }
        } else {
            target.database = Some("test".into());
        }
        if let Some((index, word)) = host {
            scope_indices.push(index);
            target.server = word.as_literal().and_then(mongo_host);
        }
        // Unknown options may consume the operand read as the address, and
        // --nodb leaves `db` unbound until the script connects.
        target.known = unknown.is_empty() && !nodb;
        crate::models::common::unrecognized_arguments_boundary(
            builder,
            model_node,
            &["database", "network"],
            &unknown,
        );
        if let Some(server) = &target.server {
            let mut provenance = vec![model_node];
            for index in &scope_indices {
                provenance.push(arg_node(builder, ctx, *index as u32));
            }
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
            datastore_connect_effect(builder, provenance, server, "mongodb");
        }

        let mut scripts = Vec::new();
        for (value_index, value, attached) in evals {
            let source = match (attached, &value) {
                (Some(text), _) => Some(text.to_string()),
                (None, Some(word)) => word.as_literal().map(str::to_string),
                (None, None) => None,
            };
            match source {
                Some(source) => {
                    let arg = arg_node(builder, ctx, value_index as u32);
                    scripts.push((source, vec![arg, model_node], true));
                }
                None => mongo_opaque(builder, model_node, "mongo shell --eval is not literal"),
            }
        }
        if files {
            mongo_opaque(
                builder,
                model_node,
                "mongo shell script files are not modeled",
            );
        }
        if scripts.is_empty() && !files {
            if let Some(source) = ctx.stdin_literal() {
                let mut provenance = vec![model_node];
                provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
                // The shell reads piped input line by line, not as one
                // evaluation.
                scripts.push((source.to_string(), provenance, false));
            } else if ctx.stdin.is_some() {
                mongo_opaque(
                    builder,
                    model_node,
                    "stdin mongo shell script is not statically recoverable",
                );
            } else {
                mongo_opaque(builder, model_node, "interactive mongo shell session");
            }
        } else if shell {
            mongo_opaque(builder, model_node, "interactive mongo shell session");
        }
        for (source, provenance, evaluation) in scripts {
            builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
            if evaluation && let Some((command, arguments)) = direct_shell_command(&source) {
                shell_command(
                    builder,
                    model_node,
                    &provenance,
                    &mut target,
                    command,
                    &arguments,
                );
                continue;
            }
            analyze_mongo_script(builder, ctx, model_node, &source, &provenance, &mut target);
        }
    }
}

const MONGO_VALUE_FLAGS: &[&str] = &[
    "--port",
    "-u",
    "--username",
    "-p",
    "--password",
    "--authenticationDatabase",
    "--authenticationMechanism",
    "--awsIamSessionToken",
    "--gssapiServiceName",
    "--gssapiHostName",
    "--sspiHostnameCanonicalization",
    "--sspiRealmOverride",
    "--tlsCAFile",
    "--tlsCertificateKeyFile",
    "--tlsCertificateKeyFilePassword",
    "--tlsCRLFile",
    "--tlsCertificateSelector",
    "--tlsDisabledProtocols",
    "--sslCAFile",
    "--sslPEMKeyFile",
    "--sslPEMKeyPassword",
    "--sslCRLFile",
    "--awsAccessKeyId",
    "--awsSecretAccessKey",
    "--awsSessionToken",
    "--keyVaultNamespace",
    "--kmsURL",
    "--apiVersion",
    "--cryptSharedLibPath",
    "--csfleLibraryPath",
    "--oidcFlows",
    "--oidcRedirectUri",
    "--browser",
];

const MONGO_BOOL_FLAGS: &[&str] = &[
    "--quiet",
    "--norc",
    "--verbose",
    "--tls",
    "--ssl",
    "--retryWrites",
    "--tlsAllowInvalidCertificates",
    "--tlsAllowInvalidHostnames",
    "--tlsFIPSMode",
    "--tlsUseSystemCA",
    "--sslAllowInvalidCertificates",
    "--sslAllowInvalidHostnames",
    "--apiStrict",
    "--apiDeprecationErrors",
    "--ipv6",
    "--oidcDumpTokens",
    "--oidcTrustedEndpoint",
    "--oidcNoNonce",
    "--deepInspect",
];

fn mongo_opaque(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    for domain in ["database", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNRECOVERABLE_SOURCE,
        BoundaryClass::Unresolved,
        &["database", "network"],
        detail,
    );
}

/// The server and database the shell's `db` is bound to. `known` turns
/// false once a statement the recognizer cannot read may have rebound it.
#[derive(Default)]
struct MongoTarget {
    server: Option<String>,
    database: Option<String>,
    known: bool,
}

/// A `mongodb://` URI, `host[:port]/db`, `host:port`, or a bare database
/// name, as its host and the database it names, if any.
fn parse_mongo_address(text: &str) -> (Option<String>, Option<String>) {
    let (hosts, database) = match text
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "mongodb" | "mongodb+srv"))
    {
        Some((_, rest)) => rest.split_once('/').unwrap_or((rest, "")),
        None => match text.split_once('/') {
            Some(split) => split,
            None if text.contains(':') => (text, ""),
            None => return (None, Some(text.to_string())),
        },
    };
    let database = database.split(['?', '#']).next().unwrap_or_default();
    (
        mongo_host(hosts),
        (!database.is_empty()).then(|| database.to_string()),
    )
}

/// The first host of a `[user@]host[:port][,host...]` list or `rs/host` seed.
fn mongo_host(text: &str) -> Option<String> {
    if text.contains("://") {
        return parse_mongo_address(text).0;
    }
    let seeds = text.rsplit_once('/').map_or(text, |(_, seeds)| seeds);
    let first = seeds.split(',').next()?;
    let first = first.rsplit('@').next().unwrap_or(first);
    let host = split_host_port(first).0;
    (!host.is_empty()).then_some(host)
}

#[derive(Clone, Debug, PartialEq)]
enum MongoJsTok {
    Ident(String),
    /// A string literal; None when an escape leaves its value uncertain.
    Str(Option<String>),
    Num,
    Regex,
    Punct(char),
}

/// ECMAScript line terminators: each ends a line comment and can end a
/// statement.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// Tokens with a flag recording whether a line break preceded each one.
/// None when the text has an unterminated string or comment, or a template
/// literal with substitutions, whose extent the lexer cannot establish.
fn lex_js(source: &str) -> Option<Vec<(MongoJsTok, bool)>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens: Vec<(MongoJsTok, bool)> = Vec::new();
    let mut newline = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if is_line_terminator(c) {
            newline = true;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && !is_line_terminator(chars[i]) {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let end = (i + 2..chars.len().saturating_sub(1))
                .find(|&j| chars[j] == '*' && chars[j + 1] == '/')?;
            if chars[i..end].iter().any(|c| is_line_terminator(*c)) {
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
                    || (c != '`' && is_line_terminator(next))
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
                if is_line_terminator(next) {
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
fn js_statements(tokens: Vec<(MongoJsTok, bool)>) -> Option<Vec<Vec<MongoJsTok>>> {
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

#[derive(Clone, Debug, PartialEq)]
enum MongoDb {
    /// The database `db` is bound to.
    Current,
    /// `db.getSiblingDB(name)`; None when the name is not a plain string.
    Named(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
enum MongoOpKind {
    DropDatabase,
    DropCollection,
    /// `deleteMany`/`remove` over all documents the filter selects;
    /// `filtered` is None when the filter is absent or not a literal.
    DeleteMany {
        filtered: Option<bool>,
    },
    DeleteOne,
    Insert,
    Update {
        filtered: Option<bool>,
    },
    /// Replacement of the whole collection's contents.
    Overwrite,
    Read,
    CreateIndex,
    DropIndex,
}

#[derive(Clone, Debug, PartialEq)]
struct MongoOp {
    kind: MongoOpKind,
    database: MongoDb,
    /// The collection name; None for a database-level operation. The inner
    /// None is a collection whose name is not a plain string.
    collection: Option<Option<String>>,
    /// The filter or `justOne` argument is a variable, missing, or not a
    /// literal, so the selection is not established.
    uncertain_filter: bool,
}

#[derive(Debug, PartialEq)]
enum MongoStatement {
    Use(String),
    Ops(Vec<MongoOp>),
    /// A `child_process` call with literal arguments, as JavaScript source
    /// for the JavaScript frontend.
    ChildProcess(String),
    Unknown,
}

const CURSOR_METHODS: &[&str] = &[
    "limit",
    "skip",
    "sort",
    "toArray",
    "pretty",
    "count",
    "size",
    "itcount",
    "batchSize",
    "projection",
    "hint",
    "explain",
    "maxTimeMS",
    "collation",
    "comment",
    "readPref",
    "allowDiskUse",
    "noCursorTimeout",
    "next",
    "hasNext",
];

/// Value constructors a literal argument may call; none has side effects.
const LITERAL_CALLS: &[&str] = &[
    "ObjectId",
    "ISODate",
    "Date",
    "NumberLong",
    "NumberInt",
    "NumberDecimal",
    "UUID",
    "Timestamp",
    "BinData",
    "MinKey",
    "MaxKey",
    "Long",
    "Int32",
    "Double",
    "Decimal128",
    "RegExp",
];

fn recognize_mongo(tokens: &[MongoJsTok]) -> MongoStatement {
    let tokens = match tokens.first() {
        Some(MongoJsTok::Ident(word)) if word == "await" => &tokens[1..],
        _ => tokens,
    };
    match tokens {
        [MongoJsTok::Ident(keyword), MongoJsTok::Ident(name)] if keyword == "use" => {
            return MongoStatement::Use(name.clone());
        }
        [MongoJsTok::Ident(keyword), MongoJsTok::Ident(what)]
            if keyword == "show"
                && matches!(
                    what.as_str(),
                    "dbs" | "databases" | "collections" | "tables"
                ) =>
        {
            return MongoStatement::Ops(vec![MongoOp {
                kind: MongoOpKind::Read,
                database: MongoDb::Current,
                collection: None,
                uncertain_filter: false,
            }]);
        }
        [MongoJsTok::Ident(word)] if matches!(word.as_str(), "quit" | "exit") => {
            return MongoStatement::Ops(Vec::new());
        }
        _ => {}
    }
    // print(...), printjson(...), console.log(...) around one expression.
    let inner = match tokens {
        [
            MongoJsTok::Ident(name),
            MongoJsTok::Punct('('),
            inner @ ..,
            MongoJsTok::Punct(')'),
        ] if matches!(name.as_str(), "print" | "printjson" | "quit" | "sleep") => Some(inner),
        [
            MongoJsTok::Ident(console),
            MongoJsTok::Punct('.'),
            MongoJsTok::Ident(log),
            MongoJsTok::Punct('('),
            inner @ ..,
            MongoJsTok::Punct(')'),
        ] if console == "console" && log == "log" => Some(inner),
        _ => None,
    };
    if let Some(inner) = inner {
        if inner.is_empty() || is_literal(inner) {
            return MongoStatement::Ops(Vec::new());
        }
        return expression_statement(inner);
    }
    expression_statement(tokens)
}

fn expression_statement(tokens: &[MongoJsTok]) -> MongoStatement {
    if let Some(ops) = mongo_expression(tokens) {
        return MongoStatement::Ops(ops);
    }
    match child_process_call(tokens) {
        Some(source) => MongoStatement::ChildProcess(source),
        None => MongoStatement::Unknown,
    }
}

/// `require("child_process").FN(...)` for the functions that run a command
/// line or a program, with only string arguments (and an argument array for
/// the program forms), rebuilt as JavaScript source. Options, callbacks, and
/// any other argument leave the call unrecognized.
fn child_process_call(tokens: &[MongoJsTok]) -> Option<String> {
    let ("require", module, [MongoJsTok::Punct('.'), after @ ..]) = mongo_call(tokens)? else {
        return None;
    };
    let [[MongoJsTok::Str(Some(module))]] = module.as_slice() else {
        return None;
    };
    if !matches!(module.as_str(), "child_process" | "node:child_process") {
        return None;
    }
    let (function, args, []) = mongo_call(after)? else {
        return None;
    };
    let strings = |tokens: &[MongoJsTok]| -> Option<Vec<String>> {
        match tokens {
            [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] => {
                balanced_arguments(inner)?
                    .into_iter()
                    .map(|element| match element {
                        [MongoJsTok::Str(Some(value))] => Some(value.clone()),
                        _ => None,
                    })
                    .collect()
            }
            _ => None,
        }
    };
    let arguments = match (function, args.as_slice()) {
        ("exec" | "execSync", [[MongoJsTok::Str(Some(command))]]) => {
            vec![serde_json::json!(command)]
        }
        (
            "spawn" | "spawnSync" | "execFile" | "execFileSync",
            [[MongoJsTok::Str(Some(file))], rest @ ..],
        ) => match rest {
            [] => vec![serde_json::json!(file)],
            [array] => vec![serde_json::json!(file), serde_json::json!(strings(array)?)],
            _ => return None,
        },
        _ => return None,
    };
    let arguments = arguments
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "require({}).{function}({arguments});",
        serde_json::json!(module)
    ))
}

/// Split the tokens inside a call's parentheses into top-level arguments.
/// None when brackets do not balance.
fn balanced_arguments(tokens: &[MongoJsTok]) -> Option<Vec<&[MongoJsTok]>> {
    if tokens.is_empty() {
        return Some(Vec::new());
    }
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            MongoJsTok::Punct('(' | '[' | '{') => depth += 1,
            MongoJsTok::Punct(')' | ']' | '}') => depth = depth.checked_sub(1)?,
            MongoJsTok::Punct(',') if depth == 0 => {
                args.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    (depth == 0).then_some(())?;
    args.push(&tokens[start..]);
    Some(args)
}

/// Whether tokens form a literal value: objects, arrays, strings, numbers,
/// regular expressions, and the BSON value constructors. Any other name or
/// operator could run code when the argument is evaluated.
fn is_literal(tokens: &[MongoJsTok]) -> bool {
    tokens.iter().enumerate().all(|(index, token)| match token {
        MongoJsTok::Str(_) | MongoJsTok::Num | MongoJsTok::Regex => true,
        MongoJsTok::Punct(c) => matches!(c, '{' | '}' | '[' | ']' | ',' | ':' | '-' | '(' | ')'),
        MongoJsTok::Ident(name) => {
            matches!(
                name.as_str(),
                "true" | "false" | "null" | "undefined" | "new"
            ) || LITERAL_CALLS.contains(&name.as_str())
                && matches!(tokens.get(index + 1), Some(MongoJsTok::Punct('(')))
                || matches!(tokens.get(index + 1), Some(MongoJsTok::Punct(':')))
                    && matches!(
                        index.checked_sub(1).map(|previous| &tokens[previous]),
                        Some(MongoJsTok::Punct('{' | ','))
                    )
        }
    }) && tokens.windows(2).all(|pair| {
        // A parenthesis only follows a value constructor's name.
        !matches!(pair[1], MongoJsTok::Punct('('))
            || matches!(&pair[0], MongoJsTok::Ident(name) if LITERAL_CALLS.contains(&name.as_str()))
    })
}

/// A filter argument: `{}`, or a literal whose every condition holds for any
/// document, selects every document; any other object literal has a
/// condition. A single name is a variable whose value is unknown.
fn filter_of(argument: Option<&[MongoJsTok]>) -> Option<(Option<bool>, bool)> {
    match argument {
        None | Some([]) => Some((None, true)),
        Some(tokens) if is_literal(tokens) && matches_all(tokens) => Some((Some(false), false)),
        Some(tokens @ [MongoJsTok::Punct('{'), ..]) if is_literal(tokens) => {
            Some((Some(true), false))
        }
        Some([MongoJsTok::Ident(name)]) if !matches!(name.as_str(), "true" | "false" | "null") => {
            Some((None, true))
        }
        Some(tokens) if is_literal(tokens) => Some((None, true)),
        Some(_) => None,
    }
}

/// Whether a filter object selects every document: each condition is
/// `_id: {$exists: true}` (every document has an `_id`), `$expr: true`, an
/// `$or` with such a filter among its operands, or an `$and` of only such
/// filters. Any other condition may exclude a document.
fn matches_all(tokens: &[MongoJsTok]) -> bool {
    fn filters(value: &[MongoJsTok]) -> Option<Vec<&[MongoJsTok]>> {
        match value {
            [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] => {
                balanced_arguments(inner)
            }
            _ => None,
        }
    }
    let [MongoJsTok::Punct('{'), inner @ .., MongoJsTok::Punct('}')] = tokens else {
        return false;
    };
    balanced_arguments(inner).is_some_and(|properties| {
        properties.iter().all(|property| match property {
            [] => true,
            [
                MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)),
                MongoJsTok::Punct(':'),
                value @ ..,
            ] => match key.as_str() {
                "_id" => matches!(
                    value,
                    [
                        MongoJsTok::Punct('{'),
                        MongoJsTok::Ident(operator) | MongoJsTok::Str(Some(operator)),
                        MongoJsTok::Punct(':'),
                        MongoJsTok::Ident(exists),
                        MongoJsTok::Punct('}'),
                    ] if operator == "$exists" && exists == "true"
                ),
                "$expr" => matches!(value, [MongoJsTok::Ident(value)] if value == "true"),
                "$or" => filters(value)
                    .is_some_and(|operands| operands.iter().any(|operand| matches_all(operand))),
                "$and" => filters(value).is_some_and(|operands| {
                    !operands.is_empty() && operands.iter().all(|operand| matches_all(operand))
                }),
                _ => false,
            },
            _ => false,
        })
    })
}

/// The `justOne` selection of `remove`'s second argument: a boolean, or an
/// options object whose last `justOne` property (quoted or not) decides.
/// None when the value is not a boolean literal or a key is not a plain
/// string, since that key may be `justOne`.
fn just_one(argument: Option<&[MongoJsTok]>) -> Option<bool> {
    let tokens = match argument {
        None => return Some(false),
        Some([MongoJsTok::Ident(value)]) if value == "true" => return Some(true),
        Some([MongoJsTok::Ident(value)]) if value == "false" => return Some(false),
        Some([MongoJsTok::Punct('{'), inner @ .., MongoJsTok::Punct('}')]) => inner,
        Some(_) => return None,
    };
    for property in balanced_arguments(tokens)?.into_iter().rev() {
        let key = match property {
            [] => continue,
            [
                MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)),
                MongoJsTok::Punct(':'),
                ..,
            ] => key,
            [MongoJsTok::Num, MongoJsTok::Punct(':'), ..] => continue,
            _ => return None,
        };
        if key == "justOne" {
            return match &property[2..] {
                [MongoJsTok::Ident(value)] if value == "true" => Some(true),
                [MongoJsTok::Ident(value)] if value == "false" => Some(false),
                _ => None,
            };
        }
    }
    Some(false)
}

/// A parsed `NAME ( args )`: the name, the argument list, and the tokens after it.
type Call<'a> = (&'a str, Vec<&'a [MongoJsTok]>, &'a [MongoJsTok]);

/// Parse `NAME ( args )` at the start of `tokens`.
fn mongo_call(tokens: &[MongoJsTok]) -> Option<Call<'_>> {
    let [MongoJsTok::Ident(name), MongoJsTok::Punct('('), rest @ ..] = tokens else {
        return None;
    };
    let mut depth = 1usize;
    let close = rest.iter().position(|token| {
        match token {
            MongoJsTok::Punct('(' | '[' | '{') => depth += 1,
            MongoJsTok::Punct(')' | ']' | '}') => depth -= 1,
            _ => {}
        }
        depth == 0
    })?;
    let args = balanced_arguments(&rest[..close])?;
    Some((name, args, &rest[close + 1..]))
}

fn string_arg(args: &[&[MongoJsTok]]) -> Option<Option<String>> {
    match args {
        [[MongoJsTok::Str(value)]] => Some(value.clone()),
        _ => None,
    }
}

/// Recognize one `db`-rooted expression statement.
fn mongo_expression(tokens: &[MongoJsTok]) -> Option<Vec<MongoOp>> {
    let [MongoJsTok::Ident(root), rest @ ..] = tokens else {
        return None;
    };
    if root != "db" {
        return None;
    }
    let mut database = MongoDb::Current;
    let mut rest = rest;
    if let [MongoJsTok::Punct('.'), after @ ..] = rest
        && let Some(("getSiblingDB", args, tail)) = mongo_call(after)
    {
        database = MongoDb::Named(string_arg(&args)?);
        rest = tail;
    }
    let database_op = |kind| MongoOp {
        kind,
        database: database.clone(),
        collection: None,
        uncertain_filter: false,
    };
    // Database methods.
    if let [MongoJsTok::Punct('.'), after @ ..] = rest
        && let Some((name, args, [])) = mongo_call(after)
        && args.iter().all(|arg| is_literal(arg))
    {
        match name {
            "dropDatabase" => return Some(vec![database_op(MongoOpKind::DropDatabase)]),
            "getCollectionNames" | "getCollectionInfos" | "stats" | "getName" | "version"
            | "serverStatus" | "listCommands" => {
                return Some(vec![database_op(MongoOpKind::Read)]);
            }
            "runCommand" => return run_command(&args, database).map(|op| vec![op]),
            _ => {}
        }
    }
    // Collection selection: db.NAME, db.getCollection("NAME"), db["NAME"].
    let (collection, rest) = match rest {
        [
            MongoJsTok::Punct('['),
            MongoJsTok::Str(name),
            MongoJsTok::Punct(']'),
            rest @ ..,
        ] => (name.clone(), rest),
        [MongoJsTok::Punct('.'), after @ ..] => match mongo_call(after) {
            Some(("getCollection", args, tail)) => (string_arg(&args)?, tail),
            Some(_) => return None,
            None => match after {
                [MongoJsTok::Ident(name), rest @ ..] => (Some(name.clone()), rest),
                _ => return None,
            },
        },
        _ => return None,
    };
    let [MongoJsTok::Punct('.'), rest @ ..] = rest else {
        return None;
    };
    let (method, args, mut chain) = mongo_call(rest)?;
    let op = |kind, uncertain_filter| MongoOp {
        kind,
        database: database.clone(),
        collection: Some(collection.clone()),
        uncertain_filter,
    };
    let first = args.first().copied();
    let literal_args = args.iter().all(|arg| is_literal(arg));
    match method {
        "bulkWrite" if chain.is_empty() && literal_args => {
            let kinds = bulk_write(&args)?;
            return Some(
                kinds
                    .into_iter()
                    .map(|(kind, uncertain)| op(kind, uncertain))
                    .collect(),
            );
        }
        "initializeOrderedBulkOp" | "initializeUnorderedBulkOp" if literal_args => {
            let kinds = bulk_builder(chain)?;
            return Some(
                kinds
                    .into_iter()
                    .map(|(kind, uncertain)| op(kind, uncertain))
                    .collect(),
            );
        }
        "aggregate"
            if chain.is_empty()
                && literal_args
                && args.iter().flat_map(|arg| arg.iter()).any(|token| {
                    matches!(token, MongoJsTok::Ident(name) | MongoJsTok::Str(Some(name))
                        if matches!(name.as_str(), "$out" | "$merge"))
                }) =>
        {
            let (kind, target_database, target) = aggregate_write(first?, &database)?;
            // `$out` loses data only when its target already exists, which the
            // command establishes only when the target is the source itself.
            // Replacing a collection of unknown existence stays a boundary.
            if kind == MongoOpKind::Overwrite
                && (target_database != database || collection.as_ref() != Some(&target))
            {
                return None;
            }
            return Some(vec![
                op(MongoOpKind::Read, false),
                MongoOp {
                    kind,
                    database: target_database,
                    collection: Some(Some(target)),
                    uncertain_filter: false,
                },
            ]);
        }
        _ => {}
    }
    let kind = match method {
        "drop" if args.iter().all(|arg| is_literal(arg)) => (MongoOpKind::DropCollection, false),
        "deleteMany" | "remove" => {
            let (filtered, uncertain) = filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            // remove(filter, justOne) deletes at most one document when
            // justOne is true; an unestablished value keeps the bulk
            // effect without a filter classification.
            match (method, just_one(args.get(1).copied())) {
                ("remove", Some(true)) => (MongoOpKind::DeleteOne, false),
                ("remove", None) => (MongoOpKind::DeleteMany { filtered: None }, true),
                _ => (MongoOpKind::DeleteMany { filtered }, uncertain),
            }
        }
        "deleteOne" | "findOneAndDelete" => {
            filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            (MongoOpKind::DeleteOne, false)
        }
        "insertOne" | "insertMany" | "insert" if args.iter().all(|arg| is_literal(arg)) => {
            (MongoOpKind::Insert, false)
        }
        "updateMany" => {
            let (filtered, uncertain) = filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            (MongoOpKind::Update { filtered }, uncertain)
        }
        // Legacy update() changes one document unless {multi: true}.
        "updateOne" | "update" | "replaceOne" | "findOneAndUpdate" | "findOneAndReplace" => {
            filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            (MongoOpKind::Update { filtered: None }, false)
        }
        "find"
        | "findOne"
        | "countDocuments"
        | "estimatedDocumentCount"
        | "count"
        | "distinct"
        | "getIndexes"
        | "stats"
        | "dataSize"
        | "storageSize"
        | "totalSize"
        | "totalIndexSize"
            if args.iter().all(|arg| is_literal(arg)) =>
        {
            (MongoOpKind::Read, false)
        }
        // An aggregation with $out or $merge writes a collection.
        "aggregate"
            if args.iter().all(|arg| is_literal(arg))
                && !args.iter().flat_map(|arg| arg.iter()).any(|token| {
                    matches!(token, MongoJsTok::Ident(name) | MongoJsTok::Str(Some(name))
                        if matches!(name.as_str(), "$out" | "$merge"))
                        || matches!(token, MongoJsTok::Str(None))
                }) =>
        {
            (MongoOpKind::Read, false)
        }
        "createIndex" | "createIndexes" | "ensureIndex"
            if args.iter().all(|arg| is_literal(arg)) =>
        {
            (MongoOpKind::CreateIndex, false)
        }
        "dropIndex" | "dropIndexes" if args.iter().all(|arg| is_literal(arg)) => {
            (MongoOpKind::DropIndex, false)
        }
        _ => return None,
    };
    // Only a read returns a cursor whose chained methods stay reads.
    while !chain.is_empty() {
        if kind.0 != MongoOpKind::Read {
            return None;
        }
        let [MongoJsTok::Punct('.'), after @ ..] = chain else {
            return None;
        };
        let (name, args, tail) = mongo_call(after)?;
        if !CURSOR_METHODS.contains(&name) || !args.iter().all(|arg| is_literal(arg)) {
            return None;
        }
        chain = tail;
    }
    Some(vec![op(kind.0, kind.1)])
}

/// The properties of an object literal as `(key, value tokens)`, with plain
/// or quoted keys. None when the tokens are not an object or a key is
/// computed.
fn object_properties(tokens: &[MongoJsTok]) -> Option<Vec<(&str, &[MongoJsTok])>> {
    let [MongoJsTok::Punct('{'), inner @ .., MongoJsTok::Punct('}')] = tokens else {
        return None;
    };
    balanced_arguments(inner)?
        .into_iter()
        .filter(|property| !property.is_empty())
        .map(|property| match property {
            [
                MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)),
                MongoJsTok::Punct(':'),
                value @ ..,
            ] => Some((key.as_str(), value)),
            _ => None,
        })
        .collect()
}

/// `bulkWrite([{deleteMany: {filter: F}}, ...])`: the operation each
/// element requests, with whether its selection is uncertain. None when an
/// element is not one of the driver's write models.
fn bulk_write(args: &[&[MongoJsTok]]) -> Option<Vec<(MongoOpKind, bool)>> {
    let [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] = *args.first()? else {
        return None;
    };
    balanced_arguments(inner)?
        .into_iter()
        .filter(|element| !element.is_empty())
        .map(|element| {
            let [(model, body)] = object_properties(element)?[..] else {
                return None;
            };
            let properties = object_properties(body)?;
            let (filtered, uncertain) = filter_of(
                properties
                    .iter()
                    .rev()
                    .find(|(key, _)| *key == "filter")
                    .map(|(_, value)| *value),
            )?;
            Some(match model {
                "insertOne" => (MongoOpKind::Insert, false),
                "deleteMany" => (MongoOpKind::DeleteMany { filtered }, uncertain),
                "deleteOne" => (MongoOpKind::DeleteOne, false),
                "updateMany" => (MongoOpKind::Update { filtered }, uncertain),
                "updateOne" | "replaceOne" => (MongoOpKind::Update { filtered: None }, false),
                _ => return None,
            })
        })
        .collect()
}

/// The chain after `initializeOrderedBulkOp()` or
/// `initializeUnorderedBulkOp()`: queued `insert(doc)` and `find(F)` writes,
/// run by a final `execute()`. A chain that does not end in `execute`, or
/// executes nothing, is left unrecognized: a builder bound to a name would
/// otherwise lose the writes queued on it in another statement.
fn bulk_builder(mut chain: &[MongoJsTok]) -> Option<Vec<(MongoOpKind, bool)>> {
    let mut kinds = Vec::new();
    let mut selection = None;
    loop {
        let [MongoJsTok::Punct('.'), after @ ..] = chain else {
            return None;
        };
        let (name, args, tail) = mongo_call(after)?;
        if !args.iter().all(|arg| is_literal(arg)) {
            return None;
        }
        chain = tail;
        let kind = match (name, selection) {
            ("execute", None) if chain.is_empty() && !kinds.is_empty() => return Some(kinds),
            ("insert", None) => (MongoOpKind::Insert, false),
            ("find", None) => {
                selection = Some(filter_of(args.first().copied())?);
                continue;
            }
            ("upsert" | "collation" | "arrayFilters" | "hint", Some(_)) => continue,
            ("remove" | "delete", Some((filtered, uncertain))) => {
                (MongoOpKind::DeleteMany { filtered }, uncertain)
            }
            ("removeOne" | "deleteOne", Some(_)) => (MongoOpKind::DeleteOne, false),
            ("update", Some((filtered, uncertain))) => {
                (MongoOpKind::Update { filtered }, uncertain)
            }
            ("updateOne" | "replaceOne", Some(_)) => {
                (MongoOpKind::Update { filtered: None }, false)
            }
            _ => return None,
        };
        selection = None;
        kinds.push(kind);
    }
}

/// The final `$out` or `$merge` stage of an aggregation pipeline: the write
/// it makes and the collection it writes. `$out` replaces the whole target
/// collection when it exists; `$merge` inserts or updates documents in it.
/// None when the stage is not last or its target is not a plain name.
fn aggregate_write(
    pipeline: &[MongoJsTok],
    database: &MongoDb,
) -> Option<(MongoOpKind, MongoDb, String)> {
    let [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] = pipeline else {
        return None;
    };
    let stages = balanced_arguments(inner)?
        .into_iter()
        .filter(|stage| !stage.is_empty())
        .collect::<Vec<_>>();
    let (last, earlier) = stages.split_last()?;
    let is_write = |stage: &[MongoJsTok]| {
        matches!(stage, [_, MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)), ..]
            if matches!(key.as_str(), "$out" | "$merge"))
    };
    if earlier.iter().any(|stage| is_write(stage)) {
        return None;
    }
    let [(stage, value)] = object_properties(last)?[..] else {
        return None;
    };
    let target = match (stage, value) {
        ("$merge", _) => match object_properties(value) {
            Some(properties) => {
                properties
                    .into_iter()
                    .rev()
                    .find(|(key, _)| *key == "into")?
                    .1
            }
            None => value,
        },
        ("$out", _) => value,
        _ => return None,
    };
    let (target_database, collection) = match target {
        [MongoJsTok::Str(Some(name))] => (database.clone(), name.clone()),
        _ => {
            let properties = object_properties(target)?;
            let text = |name: &str| match properties.iter().rev().find(|(key, _)| *key == name) {
                Some((_, [MongoJsTok::Str(Some(value))])) => Some(value.clone()),
                _ => None,
            };
            (MongoDb::Named(Some(text("db")?)), text("coll")?)
        }
    };
    let kind = match stage {
        "$out" => MongoOpKind::Overwrite,
        _ => MongoOpKind::Update { filtered: None },
    };
    Some((kind, target_database, collection))
}

/// `db.runCommand({dropDatabase: 1})` and `db.runCommand({drop: "NAME"})`.
fn run_command(args: &[&[MongoJsTok]], database: MongoDb) -> Option<MongoOp> {
    let [
        [
            MongoJsTok::Punct('{'),
            MongoJsTok::Ident(key),
            MongoJsTok::Punct(':'),
            value,
            MongoJsTok::Punct('}'),
        ],
    ] = args
    else {
        return None;
    };
    match (key.as_str(), value) {
        ("dropDatabase", MongoJsTok::Num) => Some(MongoOp {
            kind: MongoOpKind::DropDatabase,
            database,
            collection: None,
            uncertain_filter: false,
        }),
        ("drop", MongoJsTok::Str(name)) => Some(MongoOp {
            kind: MongoOpKind::DropCollection,
            database,
            collection: Some(name.clone()),
            uncertain_filter: false,
        }),
        _ => None,
    }
}

/// mongosh's `ShellEvaluator.innerEval` splits a whole evaluation (one
/// `--eval` text, or a `load()`ed file) on whitespace after trimming it and
/// dropping one trailing `;`. When the first word names a shell command and
/// the next word does not start with `(`, it runs only that command with the
/// other words as its arguments; none of them is evaluated as JavaScript.
/// https://github.com/mongodb-js/mongosh/blob/87266a2d7ed9eb060e5823e3e9dc823899e2b7be/packages/shell-evaluator/src/shell-evaluator.ts#L76-L94
///
/// Only a plain-ASCII prefix through the second word qualifies: any other
/// character there is left to the JavaScript reading, since a whitespace
/// set that differs from mongosh's could turn a call into a command.
fn direct_shell_command(source: &str) -> Option<(&str, Vec<&str>)> {
    let word_end = |text: &str| text.find(is_js_space).unwrap_or(text.len());
    let first = source.trim_start_matches(is_js_space);
    let second = first[word_end(first)..].trim_start_matches(is_js_space);
    let prefix = source.len() - second.len() + word_end(second);
    if !source[..prefix].is_ascii() {
        return None;
    }
    let trimmed = source.trim_matches(is_js_space);
    let mut words = trimmed
        .strip_suffix(';')
        .unwrap_or(trimmed)
        .split(is_js_space)
        .filter(|word| !word.is_empty());
    // The `@directShellCommand` methods of mongosh's `ShellApi`.
    let command = words
        .next()
        .filter(|word| matches!(*word, "use" | "show" | "exit" | "quit" | "it" | "cls"))?;
    let arguments = words.collect::<Vec<_>>();
    if arguments.first().is_some_and(|word| word.starts_with('(')) {
        return None;
    }
    Some((command, arguments))
}

/// ECMAScript `\s`, which `String.prototype.trim` also strips: WhiteSpace
/// (tab, vertical tab, form feed, U+FEFF, and the Unicode space separators)
/// and LineTerminator. Unlike `char::is_whitespace`, it includes U+FEFF and
/// excludes U+0085.
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    ) || is_line_terminator(c)
}

/// The effects of a shell command `direct_shell_command` recognized.
fn shell_command(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    provenance: &[ProvenanceRef],
    target: &mut MongoTarget,
    command: &str,
    arguments: &[&str],
) {
    match (command, arguments) {
        // `use(db)` switches to its first argument and ignores the rest.
        ("use", [database, ..]) => target.database = Some((*database).to_string()),
        ("show", [what]) if matches!(*what, "dbs" | "databases" | "collections" | "tables") => {
            let op = MongoOp {
                kind: MongoOpKind::Read,
                database: MongoDb::Current,
                collection: None,
                uncertain_filter: false,
            };
            emit_mongo_op(builder, provenance, target, op);
        }
        ("show", _) => {
            mongo_statement_boundary(builder, model_node, "mongo shell command is not modeled")
        }
        // `use` without a name fails; `exit`, `quit`, `it`, and `cls` touch
        // no database state.
        _ => {}
    }
}

/// `const|let|var NAME = VALUE` whose value is `db`, `db.getSiblingDB("NAME")`,
/// `require("child_process")`, or a literal: a binding later statements
/// may read in place of the name.
fn mongo_binding(statement: &[MongoJsTok]) -> Option<(&str, &[MongoJsTok])> {
    let [
        MongoJsTok::Ident(keyword),
        MongoJsTok::Ident(name),
        MongoJsTok::Punct('='),
        value @ ..,
    ] = statement
    else {
        return None;
    };
    if !matches!(keyword.as_str(), "const" | "let" | "var") || name == "db" || value.is_empty() {
        return None;
    }
    let bound = match value {
        [MongoJsTok::Ident(root)] => root == "db",
        [MongoJsTok::Ident(root), MongoJsTok::Punct('.'), after @ ..] if root == "db" => matches!(
            mongo_call(after),
            Some(("getSiblingDB", args, [])) if matches!(args.as_slice(), [[MongoJsTok::Str(_)]])
        ),
        _ => {
            is_literal(value)
                || matches!(mongo_call(value), Some(("require", args, []))
                    if matches!(args.as_slice(), [[MongoJsTok::Str(Some(module))]]
                        if matches!(module.as_str(), "child_process" | "node:child_process")))
        }
    };
    bound.then_some((name.as_str(), value))
}

/// The statement with each bound name read as a value replaced by its
/// binding. A name after `.` is a property and a name before `:` in an
/// object literal is a key; neither is a read of the binding.
fn substitute(
    statement: &[MongoJsTok],
    bindings: &HashMap<String, Vec<MongoJsTok>>,
) -> Vec<MongoJsTok> {
    let mut out = Vec::with_capacity(statement.len());
    for (index, token) in statement.iter().enumerate() {
        let previous = index.checked_sub(1).map(|previous| &statement[previous]);
        let property = matches!(previous, Some(MongoJsTok::Punct('.')));
        let key = matches!(previous, Some(MongoJsTok::Punct('{' | ',')))
            && matches!(statement.get(index + 1), Some(MongoJsTok::Punct(':')));
        let value = match token {
            MongoJsTok::Ident(name) if !property && !key => bindings.get(name),
            _ => None,
        };
        match value {
            Some(value) => out.extend(value.iter().cloned()),
            None => out.push(token.clone()),
        }
    }
    out
}

fn analyze_mongo_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    source: &str,
    provenance: &[ProvenanceRef],
    target: &mut MongoTarget,
) {
    let Some(statements) = lex_js(source).and_then(js_statements) else {
        mongo_statement_boundary(builder, model_node, "mongo shell script does not tokenize");
        target.known = false;
        return;
    };
    let mut unknown = false;
    let mut uncertain = false;
    let mut bindings: HashMap<String, Vec<MongoJsTok>> = HashMap::new();
    for statement in statements {
        let statement = substitute(&statement, &bindings);
        if let Some((name, value)) = mongo_binding(&statement) {
            bindings.insert(name.to_string(), value.to_vec());
            continue;
        }
        match recognize_mongo(&statement) {
            MongoStatement::Use(name) => {
                target.database = Some(name);
                // An alias still names the database `db` was bound to.
                bindings.clear();
            }
            MongoStatement::Ops(ops) => {
                for op in ops {
                    uncertain |= op.uncertain_filter;
                    // An insert adds `_id` to the documents it is given, and
                    // an update's arguments may be those bound objects.
                    if matches!(op.kind, MongoOpKind::Insert | MongoOpKind::Update { .. }) {
                        bindings.clear();
                    }
                    emit_mongo_op(builder, provenance, target, op);
                }
            }
            MongoStatement::ChildProcess(source) => ctx.nest_subject(
                builder,
                Subject::Source {
                    language: "js".into(),
                    source,
                    dialect: Some(SourceDialect::Js),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                provenance,
            ),
            MongoStatement::Unknown => {
                unknown = true;
                // The statement may rebind `db` to another database or
                // server, or reassign or mutate a bound name.
                target.known = false;
                bindings.clear();
            }
        }
    }
    if unknown {
        mongo_statement_boundary(builder, model_node, "mongo shell statement is not modeled");
    }
    if uncertain {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unresolved,
            &["database"],
            "mongo shell delete selection is not a literal",
        );
    }
}

fn mongo_statement_boundary(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    for domain in ["database", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNMODELED_INLINE_CODE,
        BoundaryClass::Unmodeled,
        &["database", "network"],
        detail,
    );
}

fn emit_mongo_op(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    target: &MongoTarget,
    op: MongoOp,
) {
    let database = match &op.database {
        MongoDb::Current => target.database.clone(),
        MongoDb::Named(name) => name.clone(),
    };
    let resource = match (target.known, database, op.collection) {
        (true, Some(database), None) => db_schema(target.server.clone(), Some(database)),
        (true, Some(database), Some(Some(collection))) => {
            db_table(target.server.clone(), Some(database), None, collection)
        }
        _ => unresolved_resource("db"),
    };
    let (operation, attributes) = match op.kind {
        MongoOpKind::DropDatabase => (
            "database.schema_drop",
            text_attrs(&[("object_kind", "database")]),
        ),
        MongoOpKind::DropCollection => (
            "database.schema_drop",
            text_attrs(&[("object_kind", "collection")]),
        ),
        MongoOpKind::DeleteMany { filtered } => {
            let mut attributes = text_attrs(&[("action", "delete")]);
            if let Some(filtered) = filtered {
                attributes.insert("filtered".into(), AttrValue::Bool(filtered));
            }
            ("database.write", attributes)
        }
        MongoOpKind::DeleteOne => ("database.write", text_attrs(&[("action", "delete")])),
        MongoOpKind::Insert => ("database.write", text_attrs(&[("action", "insert")])),
        MongoOpKind::Update { filtered } => {
            let mut attributes = text_attrs(&[("action", "update")]);
            if let Some(filtered) = filtered {
                attributes.insert("filtered".into(), AttrValue::Bool(filtered));
            }
            ("database.write", attributes)
        }
        MongoOpKind::Overwrite => ("database.write", text_attrs(&[("action", "overwrite")])),
        MongoOpKind::Read => ("database.read", Attrs::new()),
        MongoOpKind::CreateIndex => ("database.schema_write", Attrs::new()),
        MongoOpKind::DropIndex => (
            "database.schema_drop",
            text_attrs(&[("object_kind", "index")]),
        ),
    };
    datastore_effect(
        builder,
        provenance.to_vec(),
        operation,
        resource,
        attributes,
    );
}

// ---- mongorestore ----

struct Mongorestore;

const MONGORESTORE_VALUE_FLAGS: &[&str] = &[
    "--uri",
    "-h",
    "--host",
    "--port",
    "-u",
    "--username",
    "-p",
    "--password",
    "--authenticationDatabase",
    "--authenticationMechanism",
    "--awsSessionToken",
    "--gssapiServiceName",
    "--gssapiHostName",
    "-d",
    "--db",
    "-c",
    "--collection",
    "--nsInclude",
    "--nsExclude",
    "--nsFrom",
    "--nsTo",
    "--dir",
    "-j",
    "--numParallelCollections",
    "--numInsertionWorkersPerCollection",
    "--writeConcern",
    "--oplogLimit",
    "--oplogFile",
    "--config",
    "--sslCAFile",
    "--sslPEMKeyFile",
    "--sslPEMKeyPassword",
    "--sslCRLFile",
    "--tlsCAFile",
    "--tlsCertificateKeyFile",
    "--tlsCertificateKeyFilePassword",
    "--tlsCRLFile",
    "--readPreference",
];

const MONGORESTORE_BOOL_FLAGS: &[&str] = &[
    "--drop",
    "--dryRun",
    "--gzip",
    "--objcheck",
    "--oplogReplay",
    "--preserveUUID",
    "--noIndexRestore",
    "--noOptionsRestore",
    "--keepIndexVersion",
    "--maintainInsertionOrder",
    "--stopOnError",
    "--bypassDocumentValidation",
    "--convertLegacyIndexes",
    "--fixDottedHashIndex",
    "--restoreDbUsersAndRoles",
    "--ssl",
    "--tls",
    "--sslAllowInvalidCertificates",
    "--sslAllowInvalidHostnames",
    "--tlsInsecure",
    "-v",
    "--verbose",
    "--quiet",
    "--archive",
];

impl CommandModel for Mongorestore {
    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "mongo/mongorestore@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mongorestore"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let argv = ctx.argv;
        if argv
            .iter()
            .skip(1)
            .any(|word| matches!(word.as_literal(), Some("--help" | "--version")))
        {
            return;
        }
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
        let scanned = crate::models::args::scan_with_value_indices(
            argv,
            &crate::models::args::FlagSpec {
                allow_abbreviation: false,
                value_flags: MONGORESTORE_VALUE_FLAGS,
                known_flags: MONGORESTORE_BOOL_FLAGS,
            },
            true,
        );
        crate::models::common::unrecognized_arguments_boundary(
            builder,
            model_node,
            &["database", "filesystem", "network"],
            &scanned.unknown_flags,
        );
        let value = |names: &[&str]| scanned.values_of(names).last().copied();
        let mut scope_indices = Vec::new();
        let mut server = None;
        let mut database = None;
        if let Some((index, uri)) = value(&["--uri"]) {
            scope_indices.push(index);
            if let Some((host, path)) = uri.as_literal().map(parse_mongo_address) {
                server = host;
                database = path;
            }
        }
        if let Some((index, host)) = value(&["-h", "--host"]) {
            scope_indices.push(index);
            server = host.as_literal().and_then(mongo_host);
        }
        let mut database_known = true;
        if let Some((index, name)) = value(&["-d", "--db"]) {
            scope_indices.push(index);
            database = name.as_literal().map(str::to_string);
            database_known = database.is_some();
        }
        let collection = value(&["-c", "--collection"]).map(|(index, name)| {
            scope_indices.push(index);
            name.as_literal().map(str::to_string)
        });
        // Namespace remapping and filtering select targets the model does
        // not resolve; the database is then unknown.
        if scanned.has(&["--nsInclude", "--nsFrom", "--nsTo"]) {
            database = None;
            database_known = false;
        }
        let mut provenance = vec![model_node];
        for index in &scope_indices {
            provenance.push(arg_node(builder, ctx, *index));
        }
        if let Some(server) = &server {
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
            datastore_connect_effect(builder, provenance.clone(), server, "mongodb");
        }
        let resource = match (&database, &collection, database_known) {
            (Some(database), Some(Some(collection)), true) => db_table(
                server.clone(),
                Some(database.clone()),
                None,
                collection.clone(),
            ),
            (_, Some(None), _) | (_, _, false) => unresolved_resource("db"),
            (database, _, true) => db_schema(server.clone(), database.clone()),
        };
        let dry_run = scanned.has(&["--dryRun"]);
        let with_dry_run = |mut attributes: Attrs| {
            if dry_run {
                attributes.insert("dry_run".into(), AttrValue::Bool(true));
            }
            attributes
        };
        // --drop drops each collection it restores before inserting.
        if scanned.has(&["--drop"]) {
            datastore_effect(
                builder,
                provenance.clone(),
                "database.schema_drop",
                resource.clone(),
                with_dry_run(text_attrs(&[("object_kind", "collection")])),
            );
        }
        datastore_effect(
            builder,
            provenance,
            "database.write",
            resource,
            with_dry_run(text_attrs(&[("action", "insert")])),
        );
        // The dump is read from --dir, an --archive=FILE, or the positional
        // path, which defaults to ./dump; a bare --archive reads stdin.
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        let archive = argv.iter().enumerate().find_map(|(index, word)| {
            let file = word.as_literal()?.strip_prefix("--archive=")?;
            Some((index as u32, Word::literal(file)))
        });
        let dump = match (value(&["--dir"]), archive) {
            (Some((index, word)), _) => Some((Some(index), word.clone())),
            (None, Some((index, word))) => Some((Some(index), word)),
            (None, None) if scanned.has(&["--archive"]) => None,
            (None, None) => Some(match scanned.operands.first() {
                Some((index, word)) => (Some(*index), (*word).clone()),
                None => (None, Word::literal("dump")),
            }),
        };
        if let Some((index, word)) = dump {
            let mut provenance = vec![model_node];
            if let Some(index) = index {
                provenance.insert(
                    0,
                    crate::models::common::fs_arg_node(builder, ctx, index, &word),
                );
            }
            datastore_effect(
                builder,
                provenance,
                "filesystem.read",
                ctx.resolve_fs_word(&word),
                Attrs::new(),
            );
        }
    }
}

// ---- BigQuery: bq rm ----

struct Bq;

/// bq global flags that take a value when written without `=`.
const BQ_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "--project_id",
    "--dataset_id",
    "--location",
    "--format",
    "--api",
    "--api_version",
    "--apilog",
    "--bigqueryrc",
    "--ca_certificates_file",
    "--credential_file",
    "--job_id",
    "--job_property",
    "--max_rows_per_request",
    "--proxy_address",
    "--proxy_port",
    "--proxy_username",
    "--proxy_password",
    "--service_account",
    "--service_account_credential_file",
    "--service_account_private_key_file",
    "--trace",
    "--httplib2_debuglevel",
    "--universe_domain",
    "--quota_project_id",
    "--flagfile",
];

const BQ_GLOBAL_BOOL_FLAGS: &[&str] = &[
    "-q",
    "--quiet",
    "--noquiet",
    "--headless",
    "--noheadless",
    "--synchronous_mode",
    "--nosynchronous_mode",
    "--sync",
    "--nosync",
    "--enable_gdrive",
    "--noenable_gdrive",
    "--debug_mode",
    "--nodebug_mode",
    "--use_gce_service_account",
    "--nouse_gce_service_account",
    "--disable_ssl_validation",
    "--nodisable_ssl_validation",
    "--fingerprint_job_id",
    "--nofingerprint_job_id",
    "--use_regional_endpoints",
    "--nouse_regional_endpoints",
];

/// The position of a gcloud-style CLI's command word after its global
/// flags, or None when an unknown flag leaves it uncertain.
fn command_after_globals(
    argv: &[Word],
    value_flags: &[&str],
    bool_flags: &[&str],
) -> Option<usize> {
    let mut index = 1;
    while index < argv.len() {
        let text = argv[index].as_literal()?;
        if !text.starts_with('-') {
            return Some(index);
        }
        let name = text.split_once('=').map_or(text, |(name, _)| name);
        if value_flags.contains(&name) {
            index += if text.contains('=') { 1 } else { 2 };
        } else if bool_flags.contains(&name) || text.contains('=') {
            index += 1;
        } else {
            return None;
        }
    }
    Some(index)
}

impl CommandModel for Bq {
    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "gcp/bq@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["bq"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let argv = ctx.argv;
        let Some(command) =
            command_after_globals(argv, BQ_GLOBAL_VALUE_FLAGS, BQ_GLOBAL_BOOL_FLAGS)
        else {
            unmodeled_rest(builder, model_node, "bq global flags are not recognized");
            return;
        };
        match argv.get(command).and_then(Word::as_literal) {
            Some("rm") => {}
            Some("query") => return super::db::bq_query(builder, ctx, model_node),
            Some("help" | "version") => return,
            _ => {
                unmodeled_rest(builder, model_node, "bq subcommand");
                return;
            }
        }
        let project = (1..command).find_map(|index| {
            let text = argv[index].as_literal()?;
            match text.strip_prefix("--project_id") {
                Some("") => Some(argv.get(index + 1).and_then(Word::as_literal)),
                Some(rest) => rest.strip_prefix('=').map(Some),
                None => None,
            }
        });
        // -r removes a dataset's tables with it; without it bq refuses a
        // non-empty dataset, which still drops the (empty) dataset.
        let mut kind = None;
        let mut operands = Vec::new();
        for (index, word) in argv.iter().enumerate().skip(command + 1) {
            match word.as_literal() {
                Some("-f" | "--force" | "--noforce" | "-r" | "--recursive" | "--norecursive") => {}
                Some("-d" | "--dataset") => kind = Some(kind.map_or("dataset", |_| "conflict")),
                Some("-t" | "--table") => kind = Some(kind.map_or("table", |_| "conflict")),
                // Models, routines, connections, and the like hold no table data.
                Some(text) if text.starts_with('-') && text != "-" => {
                    kind = Some(kind.map_or("other", |_| "conflict"));
                }
                _ => operands.push((index, word)),
            }
        }
        let [(index, identifier)] = operands[..] else {
            unmodeled_rest(builder, model_node, "bq rm operands");
            return;
        };
        let parsed = identifier.as_literal().map(parse_bq_identifier);
        let is_table = match (kind, &parsed) {
            (Some("table"), _) => true,
            (Some("dataset"), _) => false,
            (None, Some(Some(parsed))) => parsed.table.is_some(),
            (None, _) => {
                // The object kind depends on text the model cannot read.
                unmodeled_rest(builder, model_node, "bq rm identifier is not literal");
                return;
            }
            _ => {
                unmodeled_rest(builder, model_node, "bq rm of a non-data object");
                return;
            }
        };
        let mut provenance = vec![arg_node(builder, ctx, index as u32), model_node];
        provenance.push(arg_node(builder, ctx, command as u32));
        cloud_database_coverage(builder, vec![model_node]);
        let project = |parsed: &BqIdentifier| {
            parsed
                .project
                .clone()
                .or(project.flatten().map(str::to_string))
        };
        let (resource, object_kind) = match (&parsed, is_table) {
            (Some(Some(parsed)), true) => match &parsed.table {
                Some(table) => (
                    db_table(
                        None,
                        project(parsed),
                        Some(parsed.dataset.clone()),
                        table.clone(),
                    ),
                    "table",
                ),
                None => (unresolved_resource("db"), "table"),
            },
            (Some(Some(parsed)), false) if parsed.table.is_none() => (
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::DatabaseSchema {
                        server: None,
                        database: project(parsed),
                        schema: Some(parsed.dataset.clone()),
                    },
                },
                "schema",
            ),
            (_, true) => (unresolved_resource("db"), "table"),
            (_, false) => (unresolved_resource("db"), "schema"),
        };
        datastore_effect(
            builder,
            provenance,
            "database.schema_drop",
            resource,
            text_attrs(&[("object_kind", object_kind)]),
        );
    }
}

struct BqIdentifier {
    project: Option<String>,
    dataset: String,
    table: Option<String>,
}

/// `[PROJECT:]DATASET[.TABLE]` or `PROJECT.DATASET.TABLE`. None when the
/// text fits neither shape.
fn parse_bq_identifier(text: &str) -> Option<BqIdentifier> {
    let (project, rest) = match text.rsplit_once(':') {
        Some((project, rest)) => (Some(project.to_string()), rest),
        None => (None, text),
    };
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    match (project, parts.as_slice()) {
        (project, [dataset]) => Some(BqIdentifier {
            project,
            dataset: dataset.to_string(),
            table: None,
        }),
        (project, [dataset, table]) => Some(BqIdentifier {
            project,
            dataset: dataset.to_string(),
            table: Some(table.to_string()),
        }),
        (None, [project, dataset, table]) => Some(BqIdentifier {
            project: Some(project.to_string()),
            dataset: dataset.to_string(),
            table: Some(table.to_string()),
        }),
        _ => None,
    }
}

// ---- Bigtable: cbt ----

struct Cbt;

const CBT_VALUE_FLAGS: &[&str] = &[
    "project",
    "instance",
    "creds",
    "admin-endpoint",
    "data-endpoint",
    "auth-token",
    "cert-file",
    "timeout",
];

impl CommandModel for Cbt {
    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "gcp/cbt@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["cbt"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let argv = ctx.argv;
        // Go flags: -name value, -name=value, and the same with two dashes.
        let mut instance = None;
        let mut instance_index = None;
        let mut index = 1;
        let command = loop {
            let Some(word) = argv.get(index) else {
                break None;
            };
            let Some(text) = word.as_literal() else {
                break None;
            };
            let Some(flag) = text.strip_prefix("--").or_else(|| text.strip_prefix('-')) else {
                break Some(index);
            };
            let (name, attached) = match flag.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (flag, None),
            };
            if !CBT_VALUE_FLAGS.contains(&name) {
                break None;
            }
            let value = match attached {
                Some(value) => Some(value.to_string()),
                None => {
                    index += 1;
                    argv.get(index)
                        .and_then(Word::as_literal)
                        .map(str::to_string)
                }
            };
            if name == "instance" {
                instance = value;
                instance_index = Some(index);
            }
            index += 1;
        };
        let Some(command) = command else {
            unmodeled_rest(builder, model_node, "cbt flags are not recognized");
            return;
        };
        let operand = |offset: usize| argv.get(command + offset).and_then(Word::as_literal);
        let name = operand(0).unwrap_or_default();
        let (operation, attributes, table) = match name {
            "deletetable" => (
                "database.schema_drop",
                text_attrs(&[("object_kind", "table")]),
                true,
            ),
            "deleteallrows" => ("database.truncate", Attrs::new(), true),
            "deletefamily" => {
                let mut attributes = Attrs::new();
                attributes.insert("drops_column".into(), AttrValue::Bool(true));
                ("database.schema_write", attributes, true)
            }
            "deleterow" | "deletecolumn" => {
                let mut attributes = text_attrs(&[("action", "delete")]);
                attributes.insert("filtered".into(), AttrValue::Bool(true));
                ("database.write", attributes, true)
            }
            "read" | "lookup" | "count" => ("database.read", Attrs::new(), true),
            "ls" if argv.len() == command + 1 => ("database.read", Attrs::new(), false),
            "ls" => ("database.read", Attrs::new(), true),
            "deleteinstance" => {
                let Some((id, index)) = operand(1).map(|id| (id, command + 1)) else {
                    unmodeled_rest(builder, model_node, "cbt deleteinstance operand");
                    return;
                };
                cloud_database_coverage(builder, vec![model_node]);
                builder.declare_coverage(Domain::new("cloud"), CoverageLevel::Full);
                let provenance = vec![arg_node(builder, ctx, index as u32), model_node];
                datastore_effect(
                    builder,
                    provenance,
                    "cloud.resource.delete",
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::CloudResource {
                            scope: Box::new(effinterp_proto::cloud_scope(
                                Some("gcp"),
                                "bigtable",
                                "instance",
                            )),
                            provider: Some("gcp".into()),
                            service: "bigtable".into(),
                            kind: "instance".into(),
                            id: Some(id.to_string()),
                        },
                    },
                    Attrs::new(),
                );
                return;
            }
            _ => {
                unmodeled_rest(builder, model_node, "cbt subcommand");
                return;
            }
        };
        cloud_database_coverage(builder, vec![model_node]);
        let mut provenance = vec![arg_node(builder, ctx, command as u32), model_node];
        if let Some(index) = instance_index {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
        let resource = if table {
            provenance.push(arg_node(builder, ctx, (command + 1) as u32));
            match operand(1) {
                Some(table) => db_table(None, instance.clone(), None, table.to_string()),
                None => unresolved_resource("db"),
            }
        } else {
            db_schema(None, instance.clone())
        };
        datastore_effect(builder, provenance, operation, resource, attributes);
    }
}

// ---- Firebase CLI: Firestore and Realtime Database ----

struct Firebase;

const FIREBASE_VALUE_FLAGS: &[&str] = &[
    "-P",
    "--project",
    "--account",
    "--token",
    "-c",
    "--config",
    "--database",
    "--instance",
    "-d",
    "--data",
];

const FIREBASE_BOOL_FLAGS: &[&str] = &[
    "--json",
    "--non-interactive",
    "--interactive",
    "--debug",
    "-r",
    "--recursive",
    "--shallow",
    "--all-collections",
    "-f",
    "--force",
    "-y",
    "--yes",
    "--disable-triggers",
];

impl CommandModel for Firebase {
    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "firebase/firebase@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["firebase"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let argv = ctx.argv;
        let scanned = crate::models::args::scan_with_value_indices(
            argv,
            &crate::models::args::FlagSpec {
                allow_abbreviation: false,
                value_flags: FIREBASE_VALUE_FLAGS,
                known_flags: FIREBASE_BOOL_FLAGS,
            },
            true,
        );
        let Some(&(command_index, command)) = scanned.operands.first() else {
            unmodeled_rest(builder, model_node, "firebase without a command");
            return;
        };
        let command = command.as_literal().unwrap_or_default();
        if !matches!(
            command,
            "firestore:delete" | "firestore:databases:delete" | "database:remove" | "database:set"
        ) {
            unmodeled_rest(builder, model_node, "firebase command");
            return;
        }
        if argv
            .iter()
            .any(|word| matches!(word.as_literal(), Some("-h" | "--help")))
        {
            return;
        }
        // An unknown option may consume the operand read as the path.
        if !scanned.unknown_flags.is_empty() {
            unmodeled_rest(builder, model_node, "firebase options are not recognized");
            return;
        }
        let path = scanned.operands.get(1).copied();
        let mut provenance = vec![arg_node(builder, ctx, command_index), model_node];
        if let Some((index, _)) = path {
            provenance.push(arg_node(builder, ctx, index));
        }
        let text = |names: &[&str]| scanned.value_of(names).and_then(Word::as_literal);
        let path_text = path.and_then(|(_, word)| word.as_literal());
        let segments = path_text.map(|path| {
            path.split('/')
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>()
        });
        let (operation, resource, attributes) = match command {
            "firestore:databases:delete" => {
                let Some(database) = path_text else {
                    unmodeled_rest(builder, model_node, "firebase database operand");
                    return;
                };
                (
                    "database.schema_drop",
                    db_schema(None, Some(database.to_string())),
                    text_attrs(&[("object_kind", "database")]),
                )
            }
            "firestore:delete" => {
                let database = Some(text(&["--database"]).unwrap_or("(default)").to_string());
                if scanned.value_of(&["--database"]).is_some() && text(&["--database"]).is_none() {
                    unmodeled_rest(builder, model_node, "firestore database is not literal");
                    return;
                }
                if scanned.has(&["--all-collections"]) {
                    // Every collection and document in the database.
                    (
                        "database.truncate",
                        db_schema(None, database),
                        text_attrs(&[("object_kind", "database")]),
                    )
                } else {
                    let recursive = scanned.has(&["-r", "--recursive", "--shallow"]);
                    match segments {
                        Some(segments) if !segments.is_empty() => {
                            let resource = db_table(None, database, None, segments.join("/"));
                            // An odd segment count names a collection, an even
                            // one a document; a recursive delete removes every
                            // document at and under the path.
                            if recursive {
                                (
                                    "database.schema_drop",
                                    resource,
                                    text_attrs(&[("object_kind", "collection")]),
                                )
                            } else {
                                let mut attributes = text_attrs(&[("action", "delete")]);
                                if segments.len() % 2 == 0 {
                                    attributes.insert("filtered".into(), AttrValue::Bool(true));
                                }
                                ("database.write", resource, attributes)
                            }
                        }
                        Some(_) => {
                            unmodeled_rest(builder, model_node, "firestore:delete path");
                            return;
                        }
                        None if recursive => (
                            "database.schema_drop",
                            unresolved_resource("db"),
                            text_attrs(&[("object_kind", "collection")]),
                        ),
                        None => (
                            "database.write",
                            unresolved_resource("db"),
                            text_attrs(&[("action", "delete")]),
                        ),
                    }
                }
            }
            _ => {
                let instance = text(&["--instance"]).map(str::to_string);
                if scanned.value_of(&["--instance"]).is_some() && instance.is_none() {
                    unmodeled_rest(builder, model_node, "database instance is not literal");
                    return;
                }
                // database:set replaces all data at its path.
                let remove = command == "database:remove";
                match segments {
                    // The root path is the whole database.
                    Some(segments) if segments.is_empty() => {
                        if remove {
                            (
                                "database.truncate",
                                db_schema(None, instance),
                                text_attrs(&[("object_kind", "database")]),
                            )
                        } else {
                            (
                                "database.write",
                                db_schema(None, instance),
                                text_attrs(&[("action", "overwrite")]),
                            )
                        }
                    }
                    Some(segments) => (
                        "database.write",
                        db_table(None, instance, None, segments.join("/")),
                        text_attrs(&[("action", if remove { "delete" } else { "overwrite" })]),
                    ),
                    None => (
                        "database.write",
                        unresolved_resource("db"),
                        text_attrs(&[("action", if remove { "delete" } else { "overwrite" })]),
                    ),
                }
            }
        };
        cloud_database_coverage(builder, vec![model_node]);
        datastore_effect(builder, provenance, operation, resource, attributes);
        // database:set PATH FILE reads the new value from FILE.
        if command == "database:set"
            && scanned.value_of(&["-d", "--data"]).is_none()
            && let Some(&(index, file)) = scanned.operands.get(2)
        {
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            let arg = crate::models::common::fs_arg_node(builder, ctx, index, file);
            datastore_effect(
                builder,
                vec![arg, model_node],
                "filesystem.read",
                ctx.resolve_fs_word(file),
                Attrs::new(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recognized operation and the collection it names.
    type Recognized = Vec<(MongoOpKind, Option<Option<String>>)>;

    /// The operations each statement of `script` is recognized as, with
    /// None for a statement left to a boundary.
    fn recognized(script: &str) -> Vec<Option<Recognized>> {
        lex_js(script)
            .and_then(js_statements)
            .expect("script tokenizes")
            .iter()
            .map(|statement| match recognize_mongo(statement) {
                MongoStatement::Ops(ops) => {
                    Some(ops.into_iter().map(|op| (op.kind, op.collection)).collect())
                }
                MongoStatement::Use(_) | MongoStatement::ChildProcess(_) => Some(Vec::new()),
                MongoStatement::Unknown => None,
            })
            .collect()
    }

    #[test]
    fn data_store_scripts_neither_hide_nor_invent_removals() {
        let users = || Some(Some("users".to_string()));
        let drop_database = Some(vec![(MongoOpKind::DropDatabase, None)]);
        // Quotes inside a regular expression, strings, and comments do not
        // swallow the statement after them.
        assert_eq!(
            recognized("db.users.find({a: /'/}); db.dropDatabase()")[1],
            drop_database
        );
        assert_eq!(
            recognized("db.users.find({a: \"'\"})\ndb.dropDatabase() // '")[1],
            drop_database
        );
        assert!(
            recognized("print(\"db.dropDatabase()\") /* db.dropDatabase() */")[0]
                .as_ref()
                .is_some_and(Vec::is_empty)
        );
        // A call continued on the next line is one statement.
        assert_eq!(
            recognized("db.users\n  .drop()"),
            vec![Some(vec![(MongoOpKind::DropCollection, users())])]
        );
        // Only a literal empty filter selects every document.
        for (script, filtered) in [
            ("db.users.deleteMany({})", Some(false)),
            ("db.users.remove({}, {writeConcern: {w: 1}})", Some(false)),
            ("db.users.deleteMany({a: {$gt: 1}})", Some(true)),
            ("db.users.deleteMany(filter)", None),
            ("db.users.remove({}, 1)", None),
        ] {
            assert_eq!(
                recognized(script),
                vec![Some(vec![(MongoOpKind::DeleteMany { filtered }, users())])],
                "{script}"
            );
        }
        assert_eq!(
            recognized("db.users.remove({}, {justOne: true})"),
            vec![Some(vec![(MongoOpKind::DeleteOne, users())])]
        );
        // Bulk writes remove what their filters select, and only an executed
        // builder chain writes.
        for (script, filtered) in [
            (
                "db.users.bulkWrite([{deleteMany: {filter: {}}}])",
                Some(false),
            ),
            (
                "db.users.bulkWrite([{deleteMany: {filter: {a: 1}}}])",
                Some(true),
            ),
            (
                "db.users.initializeUnorderedBulkOp().find({}).remove().execute()",
                Some(false),
            ),
            (
                "db.users.initializeOrderedBulkOp().find({a: 1}).delete().execute()",
                Some(true),
            ),
        ] {
            assert_eq!(
                recognized(script),
                vec![Some(vec![(MongoOpKind::DeleteMany { filtered }, users())])],
                "{script}"
            );
        }
        // $out into its own source replaces an existing collection; $merge
        // only writes documents.
        let archive = || Some(Some("archive".to_string()));
        assert_eq!(
            recognized("db.users.aggregate([{$match: {a: 1}}, {$out: \"users\"}])"),
            vec![Some(vec![
                (MongoOpKind::Read, users()),
                (MongoOpKind::Overwrite, users()),
            ])]
        );
        assert_eq!(
            recognized("db.users.aggregate([{$merge: {into: \"archive\"}}])"),
            vec![Some(vec![
                (MongoOpKind::Read, users()),
                (MongoOpKind::Update { filtered: None }, archive()),
            ])]
        );
        // Arguments that run code, aliases, unexecuted bulk builders, and
        // $out stages whose target is not established to exist stay
        // boundaries.
        for script in [
            "db.users.deleteMany((() => { db.dropDatabase(); return {}; })())",
            "const d = db",
            "db.users.aggregate([{$out: name}])",
            "db.users.aggregate([{$out: \"archive\"}])",
            "db.users.initializeUnorderedBulkOp().find({}).remove()",
            "db.users.initializeUnorderedBulkOp().execute()",
            "db.getCollectionNames().forEach(c => db[c].drop())",
        ] {
            assert_eq!(recognized(script), vec![None], "{script}");
        }
        // A whole evaluation opening with a shell command's name is that
        // command alone, unless its first argument starts with `(`; a name
        // with other characters attached is JavaScript.
        assert_eq!(
            direct_shell_command(" use shop; db.dropDatabase();\n"),
            Some(("use", vec!["shop;", "db.dropDatabase()"]))
        );
        assert_eq!(
            direct_shell_command("use shop;"),
            Some(("use", vec!["shop"]))
        );
        for source in [
            "use (x); db.dropDatabase()",
            // JavaScript whitespace: `use("shop")` runs, then the drop.
            "use \u{feff}(\"shop\"); db.dropDatabase()",
            // A separator outside plain ASCII is left to the JavaScript reading.
            "use\u{a0}shop; db.dropDatabase()",
            "exit; db.dropDatabase()",
            "use(\"shop\"); db.dropDatabase()",
            "db.dropDatabase()",
        ] {
            assert_eq!(direct_shell_command(source), None, "{source}");
        }
        // child_process calls lower only with literal command arguments.
        let child = |script: &str| {
            let statements = lex_js(script).and_then(js_statements).unwrap();
            child_process_call(&statements[0])
        };
        assert_eq!(
            child("require('node:child_process').spawn('rm', ['-rf', '/x'])").as_deref(),
            Some("require(\"node:child_process\").spawn(\"rm\", [\"-rf\",\"/x\"]);")
        );
        for script in [
            "require('child_process').execSync(cmd)",
            "require('child_process').exec('rm -rf /x', () => {})",
            "require('child_process').execSync('rm -rf /x', {cwd: dir})",
            "require('child_process').spawn('rm', args)",
            "require(m).execSync('rm -rf /x')",
        ] {
            assert_eq!(child(script), None, "{script}");
        }
        // A template substitution leaves the script's extent unknown.
        assert!(lex_js("db.users.find(`${x}`)").is_none());
        // Every ECMAScript line terminator ends a line comment and separates
        // statements.
        for separator in ['\n', '\r', '\u{2028}', '\u{2029}'] {
            assert_eq!(
                recognized(&format!("// harmless{separator}db.dropDatabase()")),
                vec![drop_database.clone()],
                "{separator:?}"
            );
        }
        // remove's justOne: quoted keys count, the last duplicate wins, and a
        // value or key the lexer cannot read leaves the selection unknown.
        for (script, kind) in [
            (
                "db.users.remove({}, {\"justOne\": true})",
                MongoOpKind::DeleteOne,
            ),
            (
                "db.users.remove({}, {justOne: true, justOne: false})",
                MongoOpKind::DeleteMany {
                    filtered: Some(false),
                },
            ),
            (
                "db.users.remove({}, {justOne: false, 'justOne': true})",
                MongoOpKind::DeleteOne,
            ),
            (
                "db.users.remove({}, {w: 1})",
                MongoOpKind::DeleteMany {
                    filtered: Some(false),
                },
            ),
            (
                "db.users.remove({}, {justOne: 1})",
                MongoOpKind::DeleteMany { filtered: None },
            ),
            (
                "db.users.remove({}, {\"just\\u004fne\": true})",
                MongoOpKind::DeleteMany { filtered: None },
            ),
        ] {
            assert_eq!(
                recognized(script),
                vec![Some(vec![(kind, users())])],
                "{script}"
            );
        }

        // redis-cli states an exact flush target only for fully recognized
        // invocations; every other mention of a flush is a truncate on an
        // unresolved database, and nothing else invents one.
        let plan = |line: &str, stdin: Option<&str>| {
            let argv = std::iter::once("redis-cli")
                .chain(line.split(' ').filter(|word| !word.is_empty()))
                .map(Word::literal)
                .collect::<Vec<_>>();
            redis_plan(&argv, stdin.map(Some))
        };
        let exact = |plan: &RedisPlan| {
            assert!(!plan.unresolved_flush, "{plan:?}");
            let [flush] = plan.flushes.as_slice() else {
                panic!("{plan:?}");
            };
            (flush.target.server.clone(), flush.target.database.clone())
        };
        let number = |n: &str| RedisDatabase::Number(n.into());
        for (line, database) in [
            ("-4 FLUSHALL", "0"),
            ("-6 flushdb", "0"),
            ("--cursor 0 FLUSHDB", "0"),
            ("--top 10 FLUSHDB ASYNC", "0"),
            ("--show-pushes no FLUSHDB", "0"),
            ("-a -h -n 2 FLUSHDB", "2"),
        ] {
            assert_eq!(exact(&plan(line, None)), (None, number(database)), "{line}");
        }
        assert_eq!(
            exact(&plan("--cluster call cache:7000 FLUSHALL", None)),
            (Some("cache".into()), number("0"))
        );
        // Rewritten, rerouted, or mode-driven invocations: an unresolved
        // flush when a flush is mentioned anywhere, never an exact one.
        for (line, stdin) in [
            ("-X FLUSHALL FLUSHALL key", Some("GET")),
            ("-X CMD CMD", Some("FLUSHALL")),
            ("--quoted-input \"FLUSHALL\"", None),
            ("--memkeys-samples 5 FLUSHALL", None),
            ("--keystats-samples 5 FLUSHDB", None),
            ("--scan FLUSHALL", None),
            (
                "--cluster call --cluster-only-masters cache:7000 FLUSHALL",
                None,
            ),
            (
                "--cluster call cache:7000 FLUSHALL --cluster info cache:7000",
                None,
            ),
            ("--cluster-weight node=1 FLUSHALL", None),
            ("FLUSHALL now", None),
            ("", Some("FLUSH\"ALL\"")),
            ("", Some("\"FLUSH\\x41LL\"")),
        ] {
            let planned = plan(line, stdin);
            assert!(
                planned.flushes.is_empty() && planned.unresolved_flush,
                "{line} {stdin:?}: {planned:?}"
            );
        }
        let publish = plan("RPUSH queue --cluster call cache:6379 FLUSHALL", None);
        assert_eq!(publish.command, Some(1));
        assert!(publish.flushes.is_empty() && publish.unresolved_flush);
        assert!(!plan("--scan GET", None).unresolved_flush);
        // Piped lines: only plain `SELECT n` and documented flushes are
        // modeled; any other line leaves later flushes unresolved.
        let stdin_target = |script: &str| {
            let planned = plan("-h original -n 3", Some(script));
            planned
                .flushes
                .iter()
                .map(|flush| (flush.target.server.clone(), flush.target.database.clone()))
                .collect::<Vec<_>>()
        };
        // The server may reject any SELECT, so it leaves the database
        // unresolved; an unmodeled line leaves both server and database
        // unresolved, and nothing restores them.
        assert_eq!(
            stdin_target("FLUSHDB\n"),
            vec![(Some("original".into()), number("3"))]
        );
        for script in ["SELECT 5\nFLUSHDB\n", "SELECT 1000\nFLUSHDB\n"] {
            assert_eq!(
                stdin_target(script),
                vec![(Some("original".into()), RedisDatabase::Unknown)],
                "{script:?}"
            );
        }
        for script in [
            "RESET\nSELECT 5\nFLUSHDB\n",
            "CONNECT \"cache\\x\" 6379\nFLUSHDB\n",
            "SELECT 05\nFLUSHDB\n",
            "SELECT 5 junk\nFLUSHDB\n",
            "\"SELECT\" 5\nFLUSHDB\n",
            "SELECT 2147483648\nFLUSHDB\n",
        ] {
            assert_eq!(
                stdin_target(script),
                vec![(None, RedisDatabase::Unknown)],
                "{script:?}"
            );
        }
        // A script can assemble a flush from text no reading establishes,
        // so every script command or script mode is an unresolved flush.
        for script in [
            r#"return redis.call("FLU\083HALL")"#,
            r#"return redis.call("FLUSH" .. "ALL")"#,
            "return redis.call(string.char(70,76,85,83,72,65,76,76))",
            "return 1",
        ] {
            for prefix in [&[][..], &["-n", "2"][..], &["-X", "x"][..]] {
                let argv = std::iter::once("redis-cli")
                    .chain(prefix.iter().copied())
                    .chain(["EVAL", script, "0"])
                    .map(Word::literal)
                    .collect::<Vec<_>>();
                let planned = redis_plan(&argv, None);
                assert!(planned.script && planned.flushes.is_empty(), "{script}");
            }
        }
        for (line, stdin) in [
            ("fcall_ro wipe 0", None),
            ("--eval wipe.lua", None),
            ("-X x SCRIPT x", Some("LOAD")),
            ("", Some("\"evalsha\" abc 0\n")),
            ("-h original", Some("SELECT 1\nFUNCTION RESTORE x\n")),
            // A repeat count moves the command word off the first position.
            (
                "",
                Some("1 EVAL \"return redis.call(string.char(70,76,85,83,72,65,76,76))\" 0\n"),
            ),
            ("", Some("3 FCALL wipe 0\n")),
            ("3 FCALL wipe 0", None),
        ] {
            let planned = plan(line, stdin);
            assert!(
                planned.script && planned.flushes.is_empty(),
                "{line} {stdin:?}"
            );
        }
        assert!(!plan("GET key", None).script);
    }
}
