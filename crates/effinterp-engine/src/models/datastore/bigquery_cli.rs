use effinterp_proto::{ProvenanceRef, ResourceExpr, ResourceIdentity};

use super::datastore_effects::{
    cloud_database_coverage, datastore_effect, datastore_table_resource, datastore_text_attrs,
    unmodeled_datastore_subcommand,
};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::arg_node;
use crate::models::db::bq_query;
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

/// Resolve `bq rm` dataset and table targets after global flags. The SQL model owns `bq query`.
pub(super) struct BigQuery;

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

impl CommandModel for BigQuery {
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
            unmodeled_datastore_subcommand(
                builder,
                model_node,
                "bq global flags are not recognized",
            );
            return;
        };
        match argv.get(command).and_then(Word::as_literal) {
            Some("rm") => {}
            Some("query") => return bq_query(builder, ctx, model_node),
            Some("help" | "version") => return,
            _ => {
                unmodeled_datastore_subcommand(builder, model_node, "bq subcommand");
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
            unmodeled_datastore_subcommand(builder, model_node, "bq rm operands");
            return;
        };
        let parsed = identifier.as_literal().map(parse_bq_identifier);
        let is_table = match (kind, &parsed) {
            (Some("table"), _) => true,
            (Some("dataset"), _) => false,
            (None, Some(Some(parsed))) => parsed.table.is_some(),
            (None, _) => {
                // The object kind depends on text the model cannot read.
                unmodeled_datastore_subcommand(
                    builder,
                    model_node,
                    "bq rm identifier is not literal",
                );
                return;
            }
            _ => {
                unmodeled_datastore_subcommand(builder, model_node, "bq rm of a non-data object");
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
                    datastore_table_resource(
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
            datastore_text_attrs(&[("object_kind", object_kind)]),
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
