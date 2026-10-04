//! Database dump and restore clients: `pg_dump`, `mysqldump` and
//! `pg_restore`.

use effinterp_proto::{
    CoverageLevel, Domain, Effect, Modality, Operation, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_with_value_indices};
use crate::models::common::{arg_node, unrecognized_arguments_boundary};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::{
    CLIENT_DOMAINS, PG_SCHEMES, client_file_operand_effect, client_host_and_port, connect_effect,
    database_effect, object_kind_attrs, parse_conn_url, parse_conninfo, unrecognized_operands,
};

pub(super) struct PgRestore;

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
            client_file_operand_effect(builder, ctx, model_node, index, archive, "filesystem.read");
        }
        let extra = operands
            .map(|(_, word)| word.as_literal().unwrap_or("?"))
            .collect::<Vec<_>>();
        unrecognized_operands(builder, model_node, &extra);
        let Some(&(database_index, database)) = scanned.values_of(&["-d", "--dbname"]).last()
        else {
            // Without a database, pg_restore writes a SQL script instead.
            if let Some(&(index, file)) = scanned.values_of(&["-f", "--file"]).last() {
                client_file_operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    file,
                    "filesystem.write",
                );
            }
            return;
        };
        let (mut server, mut server_index, port, port_index) =
            client_host_and_port(&scanned, &["-h", "--host"], &["-p", "--port"]);
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
                unresolved_resource("db"),
                object_kind_attrs("database"),
                provenance,
            );
        } else {
            database_effect(
                builder,
                "database.schema_drop",
                target,
                object_kind_attrs("database_objects"),
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

pub(super) struct PgDump;

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

pub(super) struct MysqlDump;

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
        client_file_operand_effect(
            builder,
            ctx,
            model_node,
            idx as u32,
            &word,
            "filesystem.write",
        );
    }
}
