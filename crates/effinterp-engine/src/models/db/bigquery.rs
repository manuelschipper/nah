//! `bq query`: BigQuery's SQL client, entered from the `bq` command model.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, ProvenanceRef, ResourceExpr, ResourceIdentity, SqlConnection,
    SqlDialect,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{Attrs, arg_node, unrecognized_arguments_boundary};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::sql_client_run::{SqlClientInput, SqlClientRun};
use super::sql_client_spec::{BASE_CLIENT_SPEC, ClientSpec};
use super::{CLIENT_DOMAINS, database_effect};

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
    ..BASE_CLIENT_SPEC
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
            None => unresolved_resource("db"),
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
    let mut run = SqlClientRun {
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
        variables: BTreeMap::new(),
        variables_unknown: false,
        conditionals: 0,
        delimiter: ";".to_string(),
        includes: Vec::new(),
        stopped: false,
    };
    match sql.as_slice() {
        [] => run.run_stdin_input(builder),
        [index] => run.run_client_input(builder, SqlClientInput::Sql(argv[*index].clone(), *index)),
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
            run.run_client_input(builder, SqlClientInput::Sql(query, indices[0]));
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
