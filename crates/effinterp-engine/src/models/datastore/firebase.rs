use effinterp_proto::{AttrValue, CoverageLevel, Domain, ProvenanceRef};

use super::datastore_effects::{
    cloud_database_coverage, datastore_database_resource, datastore_effect,
    datastore_table_resource, datastore_text_attrs, unmodeled_datastore_subcommand,
};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{Attrs, arg_node};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

/// Model Firebase deletes and overwrites. Firestore path segment parity distinguishes collections from documents.
pub(super) struct Firebase;

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
            unmodeled_datastore_subcommand(builder, model_node, "firebase without a command");
            return;
        };
        let command = command.as_literal().unwrap_or_default();
        if !matches!(
            command,
            "firestore:delete" | "firestore:databases:delete" | "database:remove" | "database:set"
        ) {
            unmodeled_datastore_subcommand(builder, model_node, "firebase command");
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
            unmodeled_datastore_subcommand(
                builder,
                model_node,
                "firebase options are not recognized",
            );
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
                    unmodeled_datastore_subcommand(
                        builder,
                        model_node,
                        "firebase database operand",
                    );
                    return;
                };
                (
                    "database.schema_drop",
                    datastore_database_resource(None, Some(database.to_string())),
                    datastore_text_attrs(&[("object_kind", "database")]),
                )
            }
            "firestore:delete" => {
                let database = Some(text(&["--database"]).unwrap_or("(default)").to_string());
                if scanned.value_of(&["--database"]).is_some() && text(&["--database"]).is_none() {
                    unmodeled_datastore_subcommand(
                        builder,
                        model_node,
                        "firestore database is not literal",
                    );
                    return;
                }
                if scanned.has(&["--all-collections"]) {
                    // Every collection and document in the database.
                    (
                        "database.truncate",
                        datastore_database_resource(None, database),
                        datastore_text_attrs(&[("object_kind", "database")]),
                    )
                } else {
                    let recursive = scanned.has(&["-r", "--recursive", "--shallow"]);
                    match segments {
                        Some(segments) if !segments.is_empty() => {
                            let resource =
                                datastore_table_resource(None, database, None, segments.join("/"));
                            // An odd segment count names a collection, an even
                            // one a document; a recursive delete removes every
                            // document at and under the path.
                            if recursive {
                                (
                                    "database.schema_drop",
                                    resource,
                                    datastore_text_attrs(&[("object_kind", "collection")]),
                                )
                            } else {
                                let mut attributes = datastore_text_attrs(&[("action", "delete")]);
                                if segments.len() % 2 == 0 {
                                    attributes.insert("filtered".into(), AttrValue::Bool(true));
                                }
                                ("database.write", resource, attributes)
                            }
                        }
                        Some(_) => {
                            unmodeled_datastore_subcommand(
                                builder,
                                model_node,
                                "firestore:delete path",
                            );
                            return;
                        }
                        None if recursive => (
                            "database.schema_drop",
                            unresolved_resource("db"),
                            datastore_text_attrs(&[("object_kind", "collection")]),
                        ),
                        None => (
                            "database.write",
                            unresolved_resource("db"),
                            datastore_text_attrs(&[("action", "delete")]),
                        ),
                    }
                }
            }
            _ => {
                let instance = text(&["--instance"]).map(str::to_string);
                if scanned.value_of(&["--instance"]).is_some() && instance.is_none() {
                    unmodeled_datastore_subcommand(
                        builder,
                        model_node,
                        "database instance is not literal",
                    );
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
                                datastore_database_resource(None, instance),
                                datastore_text_attrs(&[("object_kind", "database")]),
                            )
                        } else {
                            (
                                "database.write",
                                datastore_database_resource(None, instance),
                                datastore_text_attrs(&[("action", "overwrite")]),
                            )
                        }
                    }
                    Some(segments) => (
                        "database.write",
                        datastore_table_resource(None, instance, None, segments.join("/")),
                        datastore_text_attrs(&[(
                            "action",
                            if remove { "delete" } else { "overwrite" },
                        )]),
                    ),
                    None => (
                        "database.write",
                        unresolved_resource("db"),
                        datastore_text_attrs(&[(
                            "action",
                            if remove { "delete" } else { "overwrite" },
                        )]),
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
