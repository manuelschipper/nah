//! Database client models. They recover a connection scope (server/database)
//! from argv, then run the client's SQL input as a `Subject::Sql` in the
//! client's dialect, in the order the client executes it: inline SQL flags,
//! script files, stdin, and the files a script includes through client
//! commands (`\i`, `.read`, `SOURCE`, `:r`, `!source`). Input the client would
//! run but we cannot hold (an interactive session, an unreadable script, a
//! shell escape) is a boundary, never a silently empty plan.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::Scanned;
use crate::models::common::{Attrs, arg_node, boundary};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

mod bigquery;
mod db_admin;
mod db_dump_restore;
mod sql_client_commands;
mod sql_client_input;
mod sql_client_run;
mod sql_client_spec;

pub(crate) use bigquery::bq_query;
use db_admin::{Dropdb, Mysqladmin};
use db_dump_restore::{MysqlDump, PgDump, PgRestore};
use sql_client_run::sql_client;
pub(super) use sql_client_run::{SqlClientInput, document_sql};
use sql_client_spec::{
    CLICKHOUSE, COCKROACH_SQL, CQLSH, ClientSpec, DUCKDB, MYSQL, PSQL, SNOW_SQL, SNOWSQL, SQLCMD,
    SQLITE,
};

/// Every database client command model: the SQL clients, then the
/// administration, dump and restore clients.
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
            .unwrap_or(unresolved_resource("network")),
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
pub(super) fn client_file_operand_effect(
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

/// The `object_kind` attribute a `database.*` effect carries for the kind of
/// database object it names.
fn object_kind_attrs(kind: &str) -> Attrs {
    Attrs::from([("object_kind".to_string(), AttrValue::String(kind.into()))])
}

/// A gap with explicit provenance; the affected domains become partial.
fn db_gap(builder: &mut PlanBuilder, provenance: &[ProvenanceRef], domains: &[&str], detail: &str) {
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

/// An unmodeled subcommand boundary for a database client. Every client
/// domain becomes partial, because the subcommand may reach any of them.
fn db_client_unmodeled_subcommand(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    detail: &str,
) {
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

/// An unrecognized arguments boundary for operands a database client does
/// not take. No boundary when `operands` is empty.
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

/// The host and port a scanned client selects, with their argv positions.
fn client_host_and_port(
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

const PG_SCHEMES: &[&str] = &["postgres", "postgresql"];
const MYSQL_SCHEMES: &[&str] = &["mysql", "mariadb"];

/// Declare a SQL client command model: its struct, model id, command names
/// and the function that applies it to an invocation.
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
        Some(name) => db_client_unmodeled_subcommand(
            builder,
            model_node,
            &format!("subcommand {} is not modeled", name.unwrap_or("(dynamic)")),
        ),
    }
}
