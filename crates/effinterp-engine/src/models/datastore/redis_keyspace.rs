//! Redis keyspace flushes (`FLUSHALL` and `FLUSHDB`) from the redis-cli messaging model.
//!
//! Tagged or quoted input, special modes, cluster fan-out and REPL commands
//! can rewrite or reroute a flush. Exact targets require a fully recognized
//! invocation. An uncertain flush gets an unresolved truncate and a boundary.

use effinterp_proto::{BoundaryClass, BoundaryReason, CoverageLevel, Domain, ProvenanceRef};

use super::datastore_effects::{
    datastore_connect_effect, datastore_database_resource, datastore_effect, datastore_host_port,
    datastore_text_attrs,
};
use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{Attrs, arg_node, boundary};
use crate::value::unresolved_resource;
use crate::word::Word;

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
pub(in crate::models) struct RedisCliPlan {
    pub(in crate::models) help: bool,
    flushes: Vec<RedisFlush>,
    /// Some flush may run whose target is not established.
    unresolved_flush: bool,
    /// A server-side script runs and may issue a flush.
    script: bool,
    /// The invocation is not fully modeled.
    boundary: Option<&'static str>,
    /// An ordinary non-flush command after a fully recognized prefix.
    pub(in crate::models) command: Option<usize>,
}

impl RedisCliPlan {
    /// Whether the plan's flushes are everything the invocation runs: each
    /// was recognized completely and nothing else was left unestablished.
    pub(in crate::models) fn only_exact_redis_flushes(&self) -> bool {
        !self.flushes.is_empty()
            && !self.unresolved_flush
            && !self.script
            && self.boundary.is_none()
            && self.command.is_none()
    }
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
    let host = datastore_host_port(host_port).0;
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
pub(in crate::models) fn redis_cli_plan(
    argv: &[Word],
    stdin: Option<Option<&str>>,
) -> RedisCliPlan {
    let mut plan = RedisCliPlan::default();
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
                server: Some(datastore_host_port(node).0),
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
fn redis_stdin(plan: &mut RedisCliPlan, script: &str, mut target: RedisTarget) {
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
        (true, _) => datastore_database_resource(server, None),
        (false, RedisDatabase::Number(number)) => {
            datastore_database_resource(server, Some(number.clone()))
        }
        (false, RedisDatabase::Unknown) => unresolved_resource("db"),
    };
    datastore_effect(
        builder,
        provenance,
        "database.truncate",
        resource,
        datastore_text_attrs(&[("object_kind", "keyspace")]),
    );
}

/// Emit Redis keyspace effects from the plan shared with the messaging model.
/// A server-side script or an uncertain flush emits a truncate with an unresolved target.
pub(in crate::models) fn emit_redis_keyspace_effects(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    plan: &RedisCliPlan,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_keyspace_flushes_require_established_targets() {
        // redis-cli states an exact flush target only for fully recognized
        // invocations; every other mention of a flush is a truncate on an
        // unresolved database, and nothing else invents one.
        let plan = |line: &str, stdin: Option<&str>| {
            let argv = std::iter::once("redis-cli")
                .chain(line.split(' ').filter(|word| !word.is_empty()))
                .map(Word::literal)
                .collect::<Vec<_>>();
            redis_cli_plan(&argv, stdin.map(Some))
        };
        let exact = |plan: &RedisCliPlan| {
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
                let planned = redis_cli_plan(&argv, None);
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
