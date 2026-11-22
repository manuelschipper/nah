use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use super::datastore_effects::{
    cloud_database_coverage, datastore_database_resource, datastore_effect,
    datastore_table_resource, datastore_text_attrs, unmodeled_datastore_subcommand,
};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{Attrs, arg_node};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

/// Model Bigtable `cbt` commands. Instance deletion is a cloud resource effect.
pub(super) struct Bigtable;

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

impl CommandModel for Bigtable {
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
            unmodeled_datastore_subcommand(builder, model_node, "cbt flags are not recognized");
            return;
        };
        let operand = |offset: usize| argv.get(command + offset).and_then(Word::as_literal);
        let name = operand(0).unwrap_or_default();
        let (operation, attributes, table) = match name {
            "deletetable" => (
                "database.schema_drop",
                datastore_text_attrs(&[("object_kind", "table")]),
                true,
            ),
            "deleteallrows" => ("database.truncate", Attrs::new(), true),
            "deletefamily" => {
                let mut attributes = Attrs::new();
                attributes.insert("drops_column".into(), AttrValue::Bool(true));
                ("database.schema_write", attributes, true)
            }
            "deleterow" | "deletecolumn" => {
                let mut attributes = datastore_text_attrs(&[("action", "delete")]);
                attributes.insert("filtered".into(), AttrValue::Bool(true));
                ("database.write", attributes, true)
            }
            "read" | "lookup" | "count" => ("database.read", Attrs::new(), true),
            "ls" if argv.len() == command + 1 => ("database.read", Attrs::new(), false),
            "ls" => ("database.read", Attrs::new(), true),
            "deleteinstance" => {
                let Some((id, index)) = operand(1).map(|id| (id, command + 1)) else {
                    unmodeled_datastore_subcommand(
                        builder,
                        model_node,
                        "cbt deleteinstance operand",
                    );
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
                unmodeled_datastore_subcommand(builder, model_node, "cbt subcommand");
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
                Some(table) => {
                    datastore_table_resource(None, instance.clone(), None, table.to_string())
                }
                None => unresolved_resource("db"),
            }
        } else {
            datastore_database_resource(None, instance.clone())
        };
        datastore_effect(builder, provenance, operation, resource, attributes);
    }
}
