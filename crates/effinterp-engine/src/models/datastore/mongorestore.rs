use effinterp_proto::{AttrValue, CoverageLevel, Domain, ProvenanceRef};

use super::datastore_effects::{
    datastore_connect_effect, datastore_database_resource, datastore_effect,
    datastore_table_resource, datastore_text_attrs,
};
use super::mongo_address::{mongo_host, parse_mongo_address};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{Attrs, arg_node};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

/// Model mongorestore's dump input and writes. Namespace remapping leaves the destination database unresolved.
pub(super) struct Mongorestore;

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
            (Some(database), Some(Some(collection)), true) => datastore_table_resource(
                server.clone(),
                Some(database.clone()),
                None,
                collection.clone(),
            ),
            (_, Some(None), _) | (_, _, false) => unresolved_resource("db"),
            (database, _, true) => datastore_database_resource(server.clone(), database.clone()),
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
                with_dry_run(datastore_text_attrs(&[("object_kind", "collection")])),
            );
        }
        datastore_effect(
            builder,
            provenance,
            "database.write",
            resource,
            with_dry_run(datastore_text_attrs(&[("action", "insert")])),
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
