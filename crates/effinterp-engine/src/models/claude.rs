//! Claude's explicit settings file is data loaded before the agent session.

use super::{CommandModel, InvocationCtx, common::arg_effect};
use crate::builder::PlanBuilder;
use crate::nest::SourceResolution;
use crate::word::Word;
use effinterp_proto::{AttrValue, BoundaryReason, ProvenanceRef, ResourceExpr, ResourceIdentity};

struct ClaudeSettings {
    owner: Box<dyn CommandModel>,
}

pub(super) fn with_settings(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(ClaudeSettings { owner })
}

impl CommandModel for ClaudeSettings {
    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model: ProvenanceRef) {
        let first_effect = builder.effects_len();
        self.owner.apply(builder, ctx, model);
        if ctx
            .argv
            .iter()
            .skip(1)
            .take_while(|word| word.as_literal() != Some("--"))
            .any(|word| {
                matches!(
                    word.as_literal(),
                    Some("-h" | "--help" | "-V" | "--version")
                )
            })
        {
            return;
        }
        // Only the model paths that load user configuration consume this
        // selector; scoped MCP storage edits do not. Preserve the child HOME
        // when no explicit configuration directory selects the settings.
        let reads_configuration = (first_effect..builder.effects_len()).any(|index| {
            builder.effect_operation(index) == Some("environment.read")
                && matches!(builder.effect_resource(index), Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                }) if name == "CLAUDE_CONFIG_DIR")
        });
        if reads_configuration
            && ctx.environment_value("CLAUDE_CONFIG_DIR").is_none_or(
                |value| matches!(value, ResourceExpr::Literal { value } if value.is_empty()),
            )
        {
            let mut attributes = std::collections::BTreeMap::new();
            if let Some(ResourceExpr::Literal { value }) = ctx.environment_value("HOME") {
                attributes.insert("value".into(), AttrValue::String(value));
            }
            arg_effect(
                builder,
                ctx,
                model,
                0,
                "environment.read",
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable {
                        name: "HOME".into(),
                    },
                },
                attributes,
            );
        }
        for (index, word) in ctx.argv.iter().enumerate().skip(1) {
            let value = match word.as_literal() {
                Some("--settings") => ctx.argv.get(index + 1).and_then(Word::as_literal),
                Some(word) => word.strip_prefix("--settings="),
                None => None,
            };
            let Some(path) = value.filter(|value| !value.trim_start().starts_with('{')) else {
                continue;
            };
            let mut attributes = std::collections::BTreeMap::from([(
                "configuration".into(),
                AttrValue::String("claude_settings".into()),
            )]);
            let content = crate::paths::join_source_path(ctx.runtime_cwd, path)
                .map(|(namespace, path)| {
                    if let crate::builder::WrittenSource::JsonFields(fields) = builder
                        .written_source(&path, |resource, path| {
                            ctx.nest.source_mutation_may_alias(resource, path)
                        })
                    {
                        attributes.insert("read_json_fields".into(), AttrValue::String(fields));
                    }
                    ctx.nest.resolve_data_file(builder, &path, namespace)
                })
                .unwrap_or(SourceResolution::Unavailable);
            match content {
                SourceResolution::Source { source, .. } => {
                    attributes.insert("read_content".into(), AttrValue::String(source));
                }
                unavailable => {
                    if let SourceResolution::Refused(crate::SourceRefusal::Limit { limit }) =
                        unavailable
                    {
                        builder.note_saturated(limit);
                    }
                    super::infrastructure::gap(
                        builder,
                        &[model],
                        &["filesystem"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        &format!("Claude settings file {path:?} could not be read"),
                    );
                }
            }
            arg_effect(
                builder,
                ctx,
                model,
                index as u32,
                "filesystem.read",
                ctx.resolve_fs_word(&Word::literal(path)),
                attributes,
            );
        }
    }
}
