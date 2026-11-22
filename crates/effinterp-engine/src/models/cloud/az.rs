use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, scan_literal_flags};
use crate::models::common::{
    boundary, environment_boundary, fs_arg_effect, program_input_attrs, program_output_attrs,
};
use crate::models::{CommandModel, InvocationCtx, credential};
use crate::resource_transfer::TransferBinding;
use crate::word::{Word, WordPart};

use super::cloud_args::{AZ_GLOBAL_VALUE_FLAGS, CLOUD_LITERAL_FLAGS, az_reads_argument_file};
use super::cloud_coverage::declare_cloud_common;
use super::cloud_effects::{
    cloud_effect, object_store_effect, object_store_upload_effect, symbolic_cloud,
};
use super::object_store_target::object_store_target;
use super::remote_commands::az_vm_run_command;
use super::resource_delete::{
    AZURE_DEVOPS, azure_devops_delete, cloud_resource_delete, cloud_resource_delete_effect,
    cloud_resource_delete_resolved,
};

/// Azure CLI dispatch treats argument-file input as unresolved where it can change the target.
pub(super) struct AzCommandModel;

impl CommandModel for AzCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/az@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["az"]
    }
    // `az keyvault secret show` prints the value it reads; `download`
    // writes it to its `--file`.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        let command = crate::models::scope::command_position(argv, AZ_GLOBAL_VALUE_FLAGS);
        let at = |offset: usize| argv.get(command + offset).and_then(Word::as_literal);
        if at(0) != Some("keyvault") {
            return Vec::new();
        }
        credential::read_output(
            at(2) == Some("download") && !credential::az_download_to_stdout(argv),
        )
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
        // Global arguments can precede the command group.
        let command = crate::models::scope::command_position(ctx.argv, AZ_GLOBAL_VALUE_FLAGS);
        let at = |offset: usize| ctx.argv.get(command + offset).and_then(Word::as_literal);
        if at(0) == Some("storage")
            && at(1) == Some("blob")
            && at(2) == Some("sync")
            && !ctx.argv.iter().skip(command + 3).any(|word| {
                word.as_literal()
                    .is_some_and(|word| matches!(word.split('=').next(), Some("--source" | "-s")))
            })
        {
            for domain in ["cloud", "filesystem", "network", "process"] {
                builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
            }
            environment_boundary(
                builder,
                model_node,
                BoundaryReason::REVIEWED_COMMAND_SURFACE,
                BoundaryClass::Unmodeled,
                &["cloud", "filesystem", "network", "process"],
                "az storage blob sync rejects an invocation without its required --source",
            );
            return;
        }
        // Azure's data-plane container delete has no confirmation switch;
        // unlike storage account delete, --yes/-y is an argument error.
        if at(0) == Some("storage")
            && at(1) == Some("container")
            && at(2) == Some("delete")
            && ctx.argv.iter().skip(command + 3).any(|word| {
                word.as_literal()
                    .is_some_and(|word| matches!(word.split('=').next(), Some("--yes" | "-y")))
            })
        {
            for domain in ["cloud", "network", "process"] {
                builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
            }
            return;
        }
        if at(0) == Some("keyvault") {
            let covered = credential::az_keyvault(builder, ctx, model_node);
            declare_cloud_common(builder, ctx, model_node, covered);
            return;
        }
        declare_cloud_common(
            builder,
            ctx,
            model_node,
            cloud_resource_delete_resolved(ctx.argv),
        );
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        if let Some(delete) = cloud_resource_delete(ctx.argv) {
            if delete.provider == AZURE_DEVOPS {
                azure_devops_delete(builder, ctx, model_node, &delete);
            } else {
                cloud_resource_delete_effect(builder, ctx, model_node, &delete);
            }
            return;
        }
        let argv = ctx.argv;
        let group = at(0);
        let verb = at(1);
        // The storage, disk and snapshot arms below keep such a name as
        // written; the resource it names is still the file's content.
        if az_reads_argument_file(argv)
            && matches!(
                (group, verb),
                (Some("storage"), _) | (Some("vm" | "disk" | "snapshot"), Some("delete"))
            )
        {
            boundary(
                builder,
                model_node,
                BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                BoundaryClass::Unresolved,
                &["cloud", "network"],
                "the CLI reads an argument from a file Nah does not read",
            );
        }
        match (group, verb) {
            // Deleting a container removes every blob inside it; deleting the
            // account removes the account resource and all of its containers.
            (Some("storage"), Some("container")) if at(2) == Some("delete") => {
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    command as u32 + 2,
                    "cloud.object.delete",
                    az_container_target(argv),
                    true,
                    false,
                    true,
                    Default::default(),
                );
            }
            (Some("storage"), Some("account")) if at(2) == Some("delete") => {
                let resource = scanned
                    .values_of(&["--name", "-n"])
                    .first()
                    .map(|(_, value)| *value)
                    .and_then(Word::as_literal)
                    .map_or_else(symbolic_cloud, |id| ResourceExpr::Concrete {
                        identity: ResourceIdentity::CloudResource {
                            scope: Box::new(effinterp_proto::cloud_scope(
                                Some("azure"),
                                "storage",
                                "account",
                            )),
                            provider: Some("azure".into()),
                            service: "storage".into(),
                            kind: "account".into(),
                            id: Some(id.to_string()),
                        },
                    });
                cloud_effect(
                    builder,
                    ctx,
                    model_node,
                    command as u32 + 2,
                    "cloud.resource.delete",
                    resource,
                );
            }
            (Some("storage"), Some("blob")) if at(2) == Some("delete-batch") => {
                // The batch names its container through `--source`; which blobs
                // inside it match the batch pattern is not argv evidence.
                let container = scanned
                    .values_of(&["--source", "-s"])
                    .first()
                    .map(|(_, value)| *value)
                    .map_or_else(symbolic_cloud, |source| az_object_target(&[source]));
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    command as u32 + 2,
                    "cloud.object.delete",
                    container,
                    true,
                    false,
                    true,
                    Default::default(),
                );
            }
            (Some("storage"), Some("blob")) => {
                let object = az_blob_target(argv);
                match at(2) {
                    Some("delete") => {
                        object_store_effect(
                            builder,
                            ctx,
                            model_node,
                            command as u32 + 2,
                            "cloud.object.delete",
                            object,
                            false,
                            false,
                            true,
                            Default::default(),
                        );
                    }
                    // Uploading reads the local file and writes the object.
                    Some("upload") => {
                        let source = scanned
                            .values_of(&["--file", "-f"])
                            .first()
                            .copied()
                            .and_then(|(index, file)| {
                                let slot = fs_arg_effect(
                                    builder,
                                    ctx,
                                    model_node,
                                    index,
                                    file,
                                    "filesystem.read",
                                    ctx.resolve_fs_word(file),
                                    program_input_attrs(),
                                );
                                builder.declare_coverage(
                                    Domain::new("filesystem"),
                                    CoverageLevel::Full,
                                );
                                slot
                            });
                        let destination = object_store_upload_effect(
                            builder,
                            ctx,
                            model_node,
                            command as u32 + 2,
                            "cloud.object.write",
                            object,
                            false,
                            false,
                            true,
                            Default::default(),
                            source.as_ref().map(std::slice::from_ref),
                        );
                        if let (Some(source), Some(destination)) = (source, destination) {
                            builder.transfer_binding(TransferBinding::new(source, destination));
                        }
                    }
                    // A batch upload sends every file under `--source` into
                    // the `--destination` container.
                    Some("upload-batch") => {
                        let batch = scan_literal_flags(argv, &AZ_BATCH_FLAGS);
                        let source = batch
                            .values_of(&["--source", "-s"])
                            .first()
                            .copied()
                            .and_then(|(index, directory)| {
                                let mut attributes = program_input_attrs();
                                attributes.insert("recursive".into(), AttrValue::Bool(true));
                                if let Some(included) = az_included_paths(ctx, &batch) {
                                    attributes.insert("included_paths".into(), included);
                                }
                                let slot = fs_arg_effect(
                                    builder,
                                    ctx,
                                    model_node,
                                    index,
                                    directory,
                                    "filesystem.read",
                                    ctx.resolve_fs_word(directory),
                                    attributes,
                                );
                                builder.declare_coverage(
                                    Domain::new("filesystem"),
                                    CoverageLevel::Full,
                                );
                                slot
                            });
                        let container = batch
                            .values_of(&["--destination", "-d"])
                            .first()
                            .map(|(_, value)| {
                                object_store_target(value)
                                    .unwrap_or_else(|| az_object_target(&[value]))
                            })
                            .unwrap_or_else(symbolic_cloud);
                        let destination = object_store_upload_effect(
                            builder,
                            ctx,
                            model_node,
                            command as u32 + 2,
                            "cloud.object.write",
                            container,
                            true,
                            false,
                            true,
                            Default::default(),
                            source.as_ref().map(std::slice::from_ref),
                        );
                        if let (Some(source), Some(destination)) = (source, destination) {
                            builder.transfer_binding(TransferBinding::new(source, destination));
                        }
                    }
                    // Downloading reads the object and writes the local file.
                    Some("download") => {
                        let source = object_store_effect(
                            builder,
                            ctx,
                            model_node,
                            command as u32 + 2,
                            "cloud.object.read",
                            object,
                            false,
                            false,
                            true,
                            Default::default(),
                        );
                        let destination = scanned
                            .values_of(&["--file", "-f"])
                            .first()
                            .copied()
                            .and_then(|(index, file)| {
                                let slot = fs_arg_effect(
                                    builder,
                                    ctx,
                                    model_node,
                                    index,
                                    file,
                                    "filesystem.write",
                                    ctx.resolve_fs_word(file),
                                    program_output_attrs(),
                                );
                                builder.declare_coverage(
                                    Domain::new("filesystem"),
                                    CoverageLevel::Full,
                                );
                                slot
                            });
                        if let (Some(source), Some(destination)) = (source, destination) {
                            builder.transfer_binding(TransferBinding::new(source, destination));
                        }
                    }
                    _ => boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "az storage blob verb",
                    ),
                }
            }
            (Some(service @ ("vm" | "disk" | "snapshot")), Some("delete")) => {
                let kind = if service == "vm" { "instance" } else { service };
                let name = scanned
                    .values_of(&["--ids"])
                    .first()
                    .map(|(_, value)| *value)
                    .or_else(|| {
                        scanned
                            .values_of(&["--name", "-n"])
                            .first()
                            .map(|(_, value)| *value)
                    })
                    .and_then(Word::as_literal);
                let r = match name {
                    Some(id) => ResourceExpr::Concrete {
                        identity: ResourceIdentity::CloudResource {
                            scope: Box::new(effinterp_proto::cloud_scope(
                                Some("azure"),
                                service,
                                kind,
                            )),
                            provider: Some("azure".into()),
                            service: service.into(),
                            kind: kind.into(),
                            id: Some(id.to_string()),
                        },
                    },
                    None => symbolic_cloud(),
                };
                cloud_effect(
                    builder,
                    ctx,
                    model_node,
                    command as u32 + 1,
                    "cloud.resource.delete",
                    r,
                );
            }
            (Some("vm"), Some("run-command")) if at(2) == Some("invoke") => {
                az_vm_run_command(builder, ctx, model_node)
            }
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "az command",
            ),
        }
    }
}

fn az_blob_target(argv: &[Word]) -> ResourceExpr {
    let scanned = scan_literal_flags(argv, &CLOUD_LITERAL_FLAGS);
    if let Some(url) = scanned
        .values_of(&["--blob-url"])
        .first()
        .map(|(_, value)| *value)
    {
        return object_store_target(url).unwrap_or_else(symbolic_cloud);
    }
    let Some((_, container)) = scanned
        .values_of(&["--container-name", "-c"])
        .first()
        .copied()
    else {
        return symbolic_cloud();
    };
    match scanned.values_of(&["--name", "-n"]).first().copied() {
        Some((_, name)) => az_object_target(&[container, name]),
        None => az_object_target(&[container]),
    }
}

/// `az storage container` names its container with `--name`, not `--container-name`.
/// Azure CLI's argparse also reads `--name=VALUE` and an attached `-nVALUE`.
fn az_container_target(argv: &[Word]) -> ResourceExpr {
    let attached = argv.iter().skip(1).find_map(|word| {
        let text = word.as_literal()?;
        text.strip_prefix("--name=")
            .or_else(|| text.strip_prefix("-n").filter(|value| !value.is_empty()))
            .map(Word::literal)
    });
    scan_literal_flags(argv, &CLOUD_LITERAL_FLAGS)
        .values_of(&["--name", "-n"])
        .first()
        .map(|(_, container)| (*container).clone())
        .or(attached)
        .map_or_else(symbolic_cloud, |container| az_object_target(&[&container]))
}

/// Azure container and blob names form one `az://container[/key]` object URL.
fn az_object_target(words: &[&Word]) -> ResourceExpr {
    let mut parts = vec![WordPart::Literal("az://".to_string())];
    for (position, word) in words.iter().enumerate() {
        if position > 0 {
            parts.push(WordPart::Literal("/".to_string()));
        }
        parts.extend(word.parts.clone());
    }
    object_store_target(&Word::new(parts)).unwrap_or_else(symbolic_cloud)
}

/// `az storage blob upload-batch --pattern` uploads only the files whose path,
/// joined under `--source` with the pattern's leading `/` removed, fnmatch
/// accepts, `*` crossing `/`. The `included_paths` attribute states that
/// relative glob when the command line is wholly literal. The Azure CLI accepts
/// any unique prefix of an option (`--pat`) and `--pattern=VALUE`, so every
/// option word must be one the batch scan reads.
fn az_included_paths(ctx: &InvocationCtx, batch: &Scanned) -> Option<AttrValue> {
    if !ctx.argv.iter().skip(1).all(|word| {
        word.as_literal().is_some_and(|word| {
            !word.starts_with('-') || AZ_BATCH_FLAGS.value_flags.contains(&word)
        })
    }) {
        return None;
    }
    let (_, pattern) = batch.values_of(&["--pattern"]).last().copied()?;
    let pattern = pattern.as_literal()?.trim_start_matches('/');
    (!pattern.is_empty()).then(|| {
        AttrValue::String(serde_json::to_string(&[pattern]).expect("a list of strings serializes"))
    })
}

/// `az storage blob upload-batch` names its local directory and container
/// with `--source/-s` and `--destination/-d`.
const AZ_BATCH_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--source",
        "-s",
        "--destination",
        "-d",
        "--pattern",
        "--account-name",
        "--destination-path",
    ],
    known_flags: &[],
};
