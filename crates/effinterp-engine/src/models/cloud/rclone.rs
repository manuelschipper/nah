use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan};
use crate::models::common::{
    Attrs, environment_boundary, fs_arg_effect, program_input_attrs, program_output_attrs,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::resource_transfer::TransferBinding;
use crate::word::Word;

use super::cloud_effects::{object_store_effect, object_store_upload_effect};

/// The promoted rclone document covers `copyurl`. `copy`, `copyto`, `sync`,
/// `move`, `moveto`, `delete` and `purge`, on remote or local operands, are
/// handled here by `rclone_storage`; requests its grammar does not accept
/// continue to the wrapped model.
pub(in crate::models) fn with_rclone_storage(
    owner: Box<dyn CommandModel>,
) -> Box<dyn CommandModel> {
    Box::new(RcloneStorage { owner })
}

struct RcloneStorage {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for RcloneStorage {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if !rclone_storage(builder, ctx, model_node) {
            self.owner.apply(builder, ctx, model_node);
        }
    }
}

/// rclone options that take a separate value, so the verb after them is found.
const RCLONE_GLOBAL_FLAGS: &[&str] = &[
    "--config",
    "--transfers",
    "--checkers",
    "--bwlimit",
    "--filter",
    "--filter-from",
    "--exclude",
    "--include",
    "--log-file",
    "--log-level",
];

const RCLONE_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: RCLONE_GLOBAL_FLAGS,
    known_flags: &["--dry-run", "-n", "--interactive", "-i", "--fast-list"],
};

fn rclone_storage(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) -> bool {
    let scanned = scan(ctx.argv, &RCLONE_SPEC);
    if !scanned.unknown_flags.is_empty() {
        return false;
    }
    let Some((_, command)) = scanned.operands.first() else {
        return false;
    };
    let Some(command) = command.as_literal() else {
        return false;
    };
    let operands = &scanned.operands[1..];
    if !matches!(
        (command, operands.len()),
        ("copy" | "copyto" | "sync" | "move" | "moveto", 2) | ("delete" | "purge", 1)
    ) {
        return false;
    }

    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    let config = scanned
        .flags
        .iter()
        .rev()
        .find(|flag| flag.name == "--config");
    if let Some(config) = config {
        let config_word = config.value.as_ref().unwrap();
        let resource = ctx.resolve_fs_word(config_word);
        fs_arg_effect(
            builder,
            ctx,
            model_node,
            config.value_index.unwrap_or(config.index),
            config_word,
            "filesystem.read",
            resource.clone(),
            program_input_attrs(),
        );
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: Some(resource),
                callee: None,
                domains: vec![
                    Domain::new("filesystem"),
                    Domain::new("cloud"),
                    Domain::new("network"),
                ],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "rclone remote backend and endpoint require the named configuration file"
                        .into(),
                ),
            },
            CoverageLevel::Partial,
        );
    } else {
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("cloud"), Domain::new("network")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "rclone remote backend and endpoint require runtime configuration".into(),
                ),
            },
            CoverageLevel::Partial,
        );
    }

    let dry_run = scanned.has(&["--dry-run", "-n", "--interactive", "-i"]);
    match command {
        "copy" | "copyto" | "sync" | "move" | "moveto" => {
            let (source_index, source_word) = operands[0];
            let (destination_index, destination_word) = operands[1];
            let source = rclone_side_effect(
                builder,
                ctx,
                model_node,
                source_index,
                source_word,
                false,
                false,
                true,
                None,
            );
            if dry_run {
                if let Some(resource) = rclone_remote(destination_word) {
                    object_store_effect(
                        builder,
                        ctx,
                        model_node,
                        destination_index,
                        "cloud.object.read",
                        resource,
                        true,
                        false,
                        true,
                        Default::default(),
                    );
                }
                environment_boundary(
                    builder,
                    model_node,
                    BoundaryReason::REVIEWED_COMMAND_SURFACE,
                    BoundaryClass::Unmodeled,
                    &["filesystem", "network", "process"],
                    "rclone dry-run or interactive mode performs no unconfirmed permanent changes",
                );
                return true;
            }
            // A local source sent to a remote crosses the network: which
            // backend and endpoint the remote names lives in configuration
            // this analysis has not read, so the upload's endpoint is
            // unresolved.
            let uploads = source
                .filter(|_| rclone_remote(source_word).is_none())
                .into_iter()
                .collect::<Vec<_>>();
            let destination = rclone_side_effect(
                builder,
                ctx,
                model_node,
                destination_index,
                destination_word,
                true,
                command == "sync",
                true,
                Some(&uploads),
            );
            if let (Some(source), Some(destination)) = (source, destination) {
                builder.transfer_binding(TransferBinding::new(source, destination));
            }
            // A move deletes each source file it transferred.
            if matches!(command, "move" | "moveto") {
                if let Some(resource) = rclone_remote(source_word) {
                    object_store_effect(
                        builder,
                        ctx,
                        model_node,
                        source_index,
                        "cloud.object.delete",
                        resource,
                        true,
                        false,
                        false,
                        Default::default(),
                    );
                } else {
                    let mut attributes = Attrs::new();
                    attributes.insert("recursive".into(), AttrValue::Bool(true));
                    fs_arg_effect(
                        builder,
                        ctx,
                        model_node,
                        source_index,
                        source_word,
                        "filesystem.delete",
                        ctx.resolve_fs_word(source_word),
                        attributes,
                    );
                }
            }
            if command == "sync"
                && let Some(resource) = rclone_remote(destination_word)
            {
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    destination_index,
                    "cloud.object.delete",
                    resource,
                    true,
                    true,
                    false,
                    Default::default(),
                );
            }
        }
        "delete" | "purge" => {
            let (index, word) = operands[0];
            if dry_run {
                environment_boundary(
                    builder,
                    model_node,
                    BoundaryReason::REVIEWED_COMMAND_SURFACE,
                    BoundaryClass::Unmodeled,
                    &["filesystem", "network", "process"],
                    "rclone dry-run or interactive mode performs no unconfirmed permanent changes",
                );
            } else if let Some(resource) = rclone_remote(word) {
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "cloud.object.delete",
                    resource,
                    true,
                    false,
                    true,
                    Default::default(),
                );
            } else {
                fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    word,
                    "filesystem.delete",
                    ctx.resolve_fs_word(word),
                    Default::default(),
                );
            }
        }
        _ => unreachable!(),
    }
    true
}

/// One side of an rclone transfer. A remote destination uploads the
/// `upload` reads; a local source is read recursively, since rclone copies
/// everything under a directory.
#[allow(clippy::too_many_arguments)]
fn rclone_side_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    word: &Word,
    write: bool,
    delete: bool,
    connect: bool,
    upload: Option<&[u32]>,
) -> Option<u32> {
    if let Some(resource) = rclone_remote(word) {
        object_store_upload_effect(
            builder,
            ctx,
            model_node,
            index,
            if write {
                "cloud.object.write"
            } else {
                "cloud.object.read"
            },
            resource,
            true,
            delete,
            connect,
            Default::default(),
            upload.filter(|sources| !sources.is_empty()),
        )
    } else {
        fs_arg_effect(
            builder,
            ctx,
            model_node,
            index,
            word,
            if write {
                "filesystem.write"
            } else {
                "filesystem.read"
            },
            ctx.resolve_fs_word(word),
            if write {
                program_output_attrs()
            } else {
                let mut attributes = program_input_attrs();
                attributes.insert("recursive".into(), AttrValue::Bool(true));
                attributes
            },
        )
    }
}

/// An rclone operand naming a configured remote has the form `remote:path`,
/// and one naming a backend directly `:backend:path`; an operand without such
/// a prefix is a local path. Which endpoint either stands for lives in
/// configuration and flags this analysis has not read.
fn rclone_remote(word: &Word) -> Option<ResourceExpr> {
    let word = word.as_literal()?;
    // `:backend[,option…]:path` names a backend on the command line.
    let (remote, path) = match word.strip_prefix(':') {
        Some(rest) => {
            let (backend, path) = rest.split_once(':')?;
            (&word[..backend.len() + 1], path)
        }
        None => word.split_once(':')?,
    };
    if remote.is_empty() || remote == ":" || remote.contains('/') {
        return None;
    }
    Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::ObjectStore {
            scope: Box::new(effinterp_proto::object_scope(None)),
            provider: None,
            bucket: remote.to_string(),
            key: (!path.is_empty()).then(|| path.to_string()),
        },
    })
}
