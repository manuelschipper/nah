//! Cloud CLIs: aws, gcloud/gsutil, az. Destructive object-store and cloud-
//! resource operations (s3 rm, instance terminate, db delete) are the agent-
//! guard disaster class. Effects target typed ObjectStore / CloudResource
//! identities; every cloud CLI also touches the network. Unclear or unmodeled
//! subcommands become honest boundaries, never a fabricated resource.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Field, Modality, Operation, ProvenanceRef, ResourceExpr, ResourceFamily,
    ResourceIdentity, ResourcePattern,
};

use crate::models::args::{FlagSpec, Scanned, scan, scan_literal_flags};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::attached_value;
use crate::models::common::{
    Attrs, arg_node, boundary, environment_boundary, fs_arg_effect, has_unknown,
    leading_symbolic_without, nest_remote_shell, program_input_attrs, program_output_attrs,
    symbolic_expr, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::SourceResolution;
use crate::resource_transfer::TransferBinding;
use crate::word::{Word, WordPart};

pub(super) fn cloud_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Aws),
        Box::new(Gcloud),
        Box::new(Gsutil),
        Box::new(Az),
        Box::new(Azcopy),
        Box::new(S3cmd),
    ]
}

/// The promoted rclone document covers `copyurl`. `copy`, `copyto`, `sync`,
/// `move`, `moveto`, `delete` and `purge`, on remote or local operands, are
/// handled here by `rclone_storage`; requests its grammar does not accept
/// continue to the wrapped model.
pub(super) fn with_rclone_storage(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
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
                    object_effect(
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
                    object_effect(
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
                object_effect(
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
                object_effect(
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
        object_upload_effect(
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

/// azcopy: `copy`, `sync` and `rm` over object-store URLs and local paths.
/// Its options carry their value with `=`, so a bare flag means true.
struct Azcopy;

impl CommandModel for Azcopy {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/azcopy@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["azcopy"]
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_common(builder, ctx, model_node, false);
        let argv = ctx.argv;
        match argv.get(1).and_then(Word::as_literal) {
            Some("rm" | "remove") => {
                for (i, w) in operands(argv, 2) {
                    object_effect(
                        builder,
                        ctx,
                        model_node,
                        i,
                        "cloud.object.delete",
                        object_target(w).unwrap_or_else(symbolic_cloud),
                        azcopy_flag(argv, "--recursive"),
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
            Some("cp" | "copy") => transfer_pair(
                builder,
                ctx,
                model_node,
                2,
                false,
                azcopy_flag(argv, "--recursive"),
            ),
            // azcopy sync uploads the source's top-level files even with
            // `--recursive=false`, so its read covers the whole directory.
            Some("sync") => transfer_pair(
                builder,
                ctx,
                model_node,
                2,
                azcopy_flag(argv, "--delete-destination"),
                true,
            ),
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "azcopy subcommand",
            ),
        }
    }
}

fn azcopy_flag(argv: &[Word], name: &str) -> bool {
    argv.iter().any(|word| {
        word.as_literal()
            .is_some_and(|text| match text.split_once('=') {
                Some((flag, value)) => flag == name && !matches!(value, "false" | "False"),
                None => text == name,
            })
    })
}

const S3CMD_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-c", "--config"],
    known_flags: &["-r", "--recursive", "-n", "--dry-run"],
};

struct S3cmd;

impl CommandModel for S3cmd {
    fn domains(&self) -> &'static [&'static str] {
        &["cloud", "filesystem", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "s3tools/s3cmd@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["s3cmd"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let scanned = scan(ctx.argv, &S3CMD_SPEC);
        let operands = scanned
            .operands
            .iter()
            .filter_map(|(index, word)| word.as_literal().map(|value| (*index, word, value)))
            .collect::<Vec<_>>();
        if !scanned.unknown_flags.is_empty()
            || operands.len() != 2
            || !matches!(operands[0].2, "del" | "rm")
        {
            boundary(
                builder,
                node,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &["cloud", "filesystem", "network", "process"],
                "s3cmd deletion arguments are outside the reviewed grammar",
            );
            return;
        }
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let config = scanned
            .flags
            .iter()
            .rev()
            .find(|flag| matches!(flag.name, "-c" | "--config"));
        let config_resource = config.map(|config| {
            let word = config.value.as_ref().unwrap();
            let resource = ctx.resolve_fs_word(word);
            fs_arg_effect(
                builder,
                ctx,
                node,
                config.value_index.unwrap_or(config.index),
                word,
                "filesystem.read",
                resource.clone(),
                program_input_attrs(),
            );
            resource
        });
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: config_resource,
                callee: None,
                domains: vec![
                    Domain::new("filesystem"),
                    Domain::new("cloud"),
                    Domain::new("network"),
                ],
                provenance: vec![node],
                limit: None,
                detail: Some("s3cmd endpoint and credentials require runtime configuration".into()),
            },
            CoverageLevel::Partial,
        );
        if scanned.has(&["-n", "--dry-run"]) {
            environment_boundary(
                builder,
                node,
                BoundaryReason::REVIEWED_COMMAND_SURFACE,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "s3cmd dry-run performs no permanent changes",
            );
            return;
        }
        let (index, word, _) = operands[1];
        object_effect(
            builder,
            ctx,
            node,
            index,
            "cloud.object.delete",
            object_target(word).unwrap_or_else(symbolic_cloud),
            scanned.has(&["-r", "--recursive"]),
            false,
            true,
            Default::default(),
        );
    }
}

/// Process launches are known; individual branches establish network interactions.
/// A reviewed storage or credential grammar closes cloud coverage for this invocation;
/// unrelated subcommands do not make an otherwise complete request partial.
fn declare_common(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    credential_covered: bool,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    if credential_covered || storage_command_covered(ctx) {
        builder.declare_coverage(Domain::new("cloud"), CoverageLevel::Full);
        return;
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::PARTIAL_ANALYSIS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("cloud")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("cloud model covers selected operations".to_string()),
    });
}

// Closure is limited to literal storage requests whose complete argument grammar
// and target selection the emitters below preserve. Filters, stdin lists, indirect
// IDs and unknown options still need the partial claim; scope resolution can also
// add its own boundary after this check.
fn storage_command_covered(ctx: &InvocationCtx) -> bool {
    let argv = ctx.argv;
    if argv.iter().any(|word| word.as_literal().is_none()) {
        return false;
    }
    let tool = crate::models::args::basename(argv[0].as_literal().unwrap());
    let command = match tool {
        "aws" | "gcloud" => crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS),
        "gsutil" => crate::models::scope::command_position(argv, GSUTIL_GLOBAL_FLAGS),
        "az" => crate::models::scope::command_position(argv, AZ_GLOBAL_VALUE_FLAGS),
        _ => 1,
    };
    let at = |offset| argv.get(command + offset).and_then(Word::as_literal);
    // The container emitter also reads a joined `--name=` and an attached `-n`.
    let joined_values = (tool, at(1)) == ("az", Some("container"));
    if matches!(
        (tool, at(0), at(1)),
        ("aws", Some("s3api"), Some("put-bucket-versioning"))
    ) {
        let scanned = scan(argv, &S3API_SPEC);
        return scanned.unknown_flags.is_empty()
            && scanned.operands.len() == 2
            && scanned.has(&["--bucket"])
            && !scanned.has(&["--versioning-configuration"]);
    }
    let (prefix, values, flags, target_flag, scheme, many) = match (tool, at(0), at(1), at(2)) {
        ("aws", Some("s3"), Some("rm"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url"][..],
            &["--recursive", "--quiet", "--only-show-errors"][..],
            &[][..],
            Some("s3://"),
            false,
        ),
        ("aws", Some("s3"), Some("sync"), _) => (
            2,
            &[
                "--profile",
                "--region",
                "--endpoint-url",
                "--exclude",
                "--include",
            ][..],
            &["--delete", "--quiet", "--only-show-errors", "--no-progress"][..],
            &[][..],
            Some("s3://"),
            false,
        ),
        ("aws", Some("s3api"), Some("delete-bucket"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url", "--bucket"][..],
            &[][..],
            &["--bucket"][..],
            None,
            false,
        ),
        ("aws", Some("s3api"), Some("delete-objects"), _) => (
            2,
            &[
                "--profile",
                "--region",
                "--endpoint-url",
                "--bucket",
                "--delete",
            ][..],
            &[][..],
            &["--bucket"][..],
            None,
            false,
        ),
        ("aws", Some("s3"), Some("rb"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url"][..],
            &["--force"][..],
            &[][..],
            Some("s3://"),
            false,
        ),
        ("aws", Some("ec2"), Some("delete-snapshot"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url", "--snapshot-id"][..],
            &[][..],
            &["--snapshot-id"][..],
            None,
            false,
        ),
        ("aws", Some("ec2"), Some("delete-volume"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url", "--volume-id"][..],
            &[][..],
            &["--volume-id"][..],
            None,
            false,
        ),
        ("gcloud", Some("storage"), Some("rm"), _) => (
            2,
            &["--project"][..],
            &["--recursive", "-r", "-R", "--quiet", "-q"][..],
            &[][..],
            Some("gs://"),
            true,
        ),
        ("gcloud", Some("storage"), Some("rsync"), _) => (
            2,
            &["--project"][..],
            &["--delete-unmatched-destination-objects", "--quiet", "-q"][..],
            &[][..],
            Some("gs://"),
            false,
        ),
        ("gcloud", Some("storage"), Some("buckets"), Some("delete")) => (
            3,
            &["--project"][..],
            &["--quiet", "-q"][..],
            &[][..],
            Some("gs://"),
            true,
        ),
        ("gcloud", Some("compute"), Some("snapshots" | "disks"), Some("delete")) => (
            3,
            if at(1) == Some("disks") {
                &["--project", "--zone", "--region"][..]
            } else {
                &["--project", "--region"][..]
            },
            &["--quiet", "-q"][..],
            &[][..],
            None,
            false,
        ),
        ("gsutil", Some("rm"), _, _) => (
            1,
            &[][..],
            &["-m", "-q", "-r", "-R"][..],
            &[][..],
            Some("gs://"),
            true,
        ),
        ("gsutil", Some("rsync"), _, _) => (
            1,
            &[][..],
            &["-m", "-q", "-r", "-d"][..],
            &[][..],
            Some("gs://"),
            false,
        ),
        ("gsutil", Some("rb"), _, _) => {
            (1, &[][..], &["-m", "-q"][..], &[][..], Some("gs://"), true)
        }
        ("azcopy", Some("rm" | "remove"), _, _) => (
            1,
            &[][..],
            &["--recursive"][..],
            &[][..],
            Some("https://"),
            false,
        ),
        ("azcopy", Some("sync"), _, _) => (
            1,
            &[][..],
            &["--delete-destination"][..],
            &[][..],
            Some("https://"),
            false,
        ),
        ("az", Some("storage"), Some("container" | "account"), Some("delete")) => (
            3,
            if at(1) == Some("container") {
                &[
                    "--name",
                    "-n",
                    "--account-name",
                    "--subscription",
                    "--auth-mode",
                    "--output",
                    "-o",
                    "--query",
                    "--change-reference",
                ][..]
            } else {
                &["--name", "-n", "--resource-group", "-g", "--subscription"][..]
            },
            if at(1) == Some("account") {
                &["--yes", "-y"][..]
            } else {
                // --bypass-immutability-policy deletes a container even under
                // an immutability policy; the rest are Azure CLI globals.
                &[
                    "--bypass-immutability-policy",
                    "--acquire-policy-token",
                    "--debug",
                    "--verbose",
                    "--only-show-errors",
                ][..]
            },
            &["--name", "-n"][..],
            None,
            false,
        ),
        ("az", Some("storage"), Some("blob"), Some("delete-batch")) => (
            3,
            &["--source", "--account-name", "--subscription"][..],
            &[][..],
            &["--source"][..],
            None,
            false,
        ),
        ("az", Some("snapshot" | "disk"), Some("delete"), _) => (
            2,
            &["--name", "-n", "--resource-group", "-g", "--subscription"][..],
            if at(0) == Some("disk") {
                &["--yes", "-y"][..]
            } else {
                &[][..]
            },
            &["--name", "-n"][..],
            None,
            false,
        ),
        _ => return false,
    };
    let scanned = crate::models::args::scan(
        argv,
        &FlagSpec {
            allow_abbreviation: false,
            value_flags: values,
            known_flags: flags,
        },
    );
    if scanned.dashdash.is_some() || !scanned.unknown_flags.is_empty() {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    for flag in &scanned.flags {
        let raw = argv[flag.index as usize].as_literal().unwrap();
        if !seen.insert(flag.name)
            || ((flag.index as usize) < command
                && !CLOUD_SCOPE_FLAGS.contains(&flag.name)
                && !matches!(
                    (tool, flag.name),
                    ("gsutil", "-m" | "-q")
                        | ("gcloud", "--quiet" | "-q")
                        | (
                            "az",
                            "--output"
                                | "-o"
                                | "--query"
                                | "--debug"
                                | "--verbose"
                                | "--only-show-errors"
                        )
                ))
            || (flag.name == "--delete-destination" && !raw.contains('='))
        {
            return false;
        }
        if values.contains(&flag.name) {
            // The effect emitters use detached name/ID flags. Scope flags can
            // also be assigned, but accepting them here must not widen that parser.
            if raw != flag.name && !joined_values {
                return false;
            }
            if !flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .is_some_and(|value| {
                    !value.is_empty()
                        && !value.starts_with('-')
                        && (matches!(flag.name, "--endpoint-url" | "--delete")
                            || !value.contains("://"))
                })
            {
                return false;
            }
        } else if raw.contains('=')
            && !(tool == "azcopy"
                && matches!(
                    raw.split_once('=').map(|(_, value)| value),
                    Some("true" | "false")
                ))
        {
            return false;
        }
    }
    let operands: Vec<_> = scanned
        .operands
        .iter()
        .map(|(_, word)| word.as_literal().unwrap())
        .collect();
    if operands.len() < prefix || (0..prefix).any(|offset| Some(operands[offset]) != at(offset)) {
        return false;
    }
    let targets = if target_flag.is_empty() {
        operands[prefix..].to_vec()
    } else {
        if operands.len() != prefix {
            return false;
        }
        scanned
            .flags
            .iter()
            .filter(|flag| target_flag.contains(&flag.name))
            .filter_map(|flag| flag.value.as_ref().and_then(Word::as_literal))
            .collect()
    };
    let sync = matches!(
        (tool, at(0), at(1)),
        ("gcloud", Some("storage"), Some("rsync"))
            | ("azcopy", Some("sync"), _)
            | ("aws", Some("s3"), Some("sync"))
            | ("gsutil", Some("rsync"), _)
    );
    // The source read and destination write/delete preserve this local-to-object
    // transfer. Other directions remain partial; AWS/gsutil's default symlink
    // following adds a separate filesystem boundary in transfer_pair.
    let targets = if sync {
        if targets.len() != 2
            || targets[0].is_empty()
            || targets[0].contains([':', '*', '?', '[', ']', '#'])
        {
            return false;
        }
        &targets[1..]
    } else {
        &targets[..]
    };
    !targets.is_empty()
        && (many || targets.len() == 1)
        && targets.iter().all(|target| {
            !target.is_empty()
                && !target.contains(['*', '?', '[', ']', '#'])
                && match scheme {
                    Some(scheme) => target.starts_with(scheme)
                        && matches!(object_target(&Word::literal(*target)), Some(ResourceExpr::Concrete { identity: ResourceIdentity::ObjectStore { bucket, .. } }) if !bucket.is_empty()),
                    None => !target.contains(['/', ':']),
                }
        })
}

/// One object-store interaction. The returned slot lets a transfer emitter
/// pair the endpoint it just produced.
#[allow(clippy::too_many_arguments)]
fn object_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    recursive: bool,
    delete: bool,
    connect: bool,
    attributes: std::collections::BTreeMap<String, AttrValue>,
) -> Option<u32> {
    object_upload_effect(
        builder, ctx, model_node, index, operation, resource, recursive, delete, connect,
        attributes, None,
    )
}

/// An object-store interaction that may also upload local bytes: the CLI
/// sends what the `upload` reads produced to the provider's endpoint, so the
/// write carries a `network.upload` on that endpoint, bound to each read, as
/// scp's remote destination does. An empty list still uploads (stdin).
#[allow(clippy::too_many_arguments)]
fn object_upload_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    recursive: bool,
    delete: bool,
    connect: bool,
    attributes: std::collections::BTreeMap<String, AttrValue>,
    upload: Option<&[u32]>,
) -> Option<u32> {
    cloud_request_effect(
        builder,
        ctx,
        model_node,
        index,
        operation,
        resource,
        recursive,
        delete,
        connect,
        attributes,
        upload,
        effinterp_proto::RequestAssurance::Conservative,
    )
}

/// `object_upload_effect` with the request assurance its caller established.
#[allow(clippy::too_many_arguments)]
fn cloud_request_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    recursive: bool,
    delete: bool,
    connect: bool,
    mut attributes: std::collections::BTreeMap<String, AttrValue>,
    upload: Option<&[u32]>,
    request_assurance: effinterp_proto::RequestAssurance,
) -> Option<u32> {
    let arg = arg_node(builder, ctx, index);
    let mut provenance = vec![arg, model_node];
    let mut resource = resource;
    apply_cloud_scope(builder, ctx, &mut provenance, &mut resource);
    if connect {
        cloud_network_effect(builder, ctx, &provenance, &resource, "network.connect");
    }
    if let Some(sources) = upload
        && let Some(sink) =
            cloud_network_effect(builder, ctx, &provenance, &resource, "network.upload")
    {
        for source in sources {
            builder.transfer_binding(TransferBinding::new(*source, sink));
        }
    }
    if recursive {
        attributes.insert(
            "recursive".to_string(),
            effinterp_proto::AttrValue::Bool(true),
        );
    }
    if delete {
        attributes.insert("delete".to_string(), AttrValue::Bool(true));
    }
    builder.effect(Effect {
        request_assurance,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    })
}

fn cloud_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
) {
    let arg = arg_node(builder, ctx, index);
    let mut provenance = vec![arg, model_node];
    let mut resource = resource;
    apply_cloud_scope(builder, ctx, &mut provenance, &mut resource);
    if operation.starts_with("network.") {
        cloud_network_effect(builder, ctx, &provenance, &resource, operation);
        return;
    }
    if operation.starts_with("cloud.") {
        cloud_network_effect(builder, ctx, &provenance, &resource, "network.connect");
    }
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}

/// Classify a literal or symbolic object-store URL before local path
/// resolution.
fn object_target(word: &Word) -> Option<ResourceExpr> {
    if let Some(text) = word.as_literal() {
        let (scheme, rest) = text.split_once("://")?;
        let provider = match scheme {
            "s3" => Some("aws".to_string()),
            "gs" => Some("gcp".to_string()),
            "az" => Some("azure".to_string()),
            "https" if text.contains(".blob.core.windows.net") => Some("azure".to_string()),
            _ => return None,
        };
        if scheme == "https" {
            let (host, path) = rest.split_once('/')?;
            let account = host.strip_suffix(".blob.core.windows.net")?;
            if account.is_empty() || account.contains(['.', '@', ':']) {
                return None;
            }
            let (bucket, key) = path.split_once('/').map_or((path, None), |(b, k)| {
                (b, (!k.is_empty()).then(|| k.to_string()))
            });
            if bucket.is_empty() {
                return None;
            }
            let mut scope = effinterp_proto::object_scope(Some("azure"));
            scope.identity.insert(
                effinterp_proto::ScopeDimension::StorageAccount,
                effinterp_proto::ScopeValue::value(ResourceExpr::Literal {
                    value: account.to_string(),
                }),
            );
            crate::models::scope::endpoint_evidence(
                &mut scope,
                effinterp_proto::ScopeEvidenceKind::Endpoint,
                effinterp_proto::ScopeValue::value(ResourceExpr::Literal {
                    value: text.to_string(),
                }),
            );
            return Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::ObjectStore {
                    scope: Box::new(scope),
                    provider,
                    bucket: bucket.to_string(),
                    key,
                },
            });
        }
        let (bucket, key) = match rest.split_once('/') {
            Some((b, k)) if !k.is_empty() => (b.to_string(), Some(k.to_string())),
            _ => (rest.trim_end_matches('/').to_string(), None),
        };
        if bucket.is_empty() {
            return None;
        }
        return Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore {
                scope: Box::new(effinterp_proto::object_scope(provider.as_deref())),
                provider,
                bucket,
                key,
            },
        });
    }

    let WordPart::Literal(first) = word.parts.first()? else {
        return None;
    };
    let (prefix, provider) = [("s3://", "aws"), ("gs://", "gcp"), ("az://", "azure")]
        .into_iter()
        .find(|(prefix, _)| first.starts_with(prefix))?;
    let mut url_parts = word.parts.clone();
    let WordPart::Literal(first) = &mut url_parts[0] else {
        unreachable!();
    };
    *first = first.strip_prefix(prefix).unwrap().to_string();

    let (bucket_parts, key_parts) = split_object_parts(&url_parts);
    let bucket = Word::new(nonempty_literals(bucket_parts));
    if bucket.parts.is_empty() {
        return None;
    }
    if let Some(bucket) = bucket.as_literal() {
        if bucket.is_empty() {
            return None;
        }
        let base = ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore {
                scope: Box::new(effinterp_proto::object_scope(Some(provider))),
                provider: Some(provider.to_string()),
                bucket: bucket.to_string(),
                key: None,
            },
        };
        let mut parts = vec![base.clone()];
        parts.extend(symbolic_parts(key_parts, "cloud"));
        return Some(if parts.len() == 1 {
            base
        } else {
            ResourceExpr::Join { parts }
        });
    }

    let mut parts = vec![ResourceExpr::Literal {
        value: prefix.to_string(),
    }];
    parts.extend(symbolic_parts(url_parts, "cloud"));
    Some(ResourceExpr::Join { parts })
}

fn split_object_parts(parts: &[WordPart]) -> (Vec<WordPart>, Vec<WordPart>) {
    let mut bucket = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if let WordPart::Literal(value) = part
            && let Some((before, after)) = value.split_once('/')
        {
            if !before.is_empty() {
                bucket.push(WordPart::Literal(before.to_string()));
            }
            let mut key = Vec::new();
            if !after.is_empty() {
                key.push(WordPart::Literal(after.to_string()));
            }
            key.extend_from_slice(&parts[index + 1..]);
            return (bucket, key);
        }
        bucket.push(part.clone());
    }
    (bucket, Vec::new())
}

fn nonempty_literals(parts: Vec<WordPart>) -> Vec<WordPart> {
    parts
        .into_iter()
        .filter(|part| !matches!(part, WordPart::Literal(value) if value.is_empty()))
        .collect()
}

fn symbolic_parts(parts: Vec<WordPart>, family: &str) -> Vec<ResourceExpr> {
    let word = Word::new(nonempty_literals(parts));
    if word.parts.is_empty() {
        return Vec::new();
    }
    match symbolic_expr(&word, family) {
        ResourceExpr::Join { parts } => parts,
        part => vec![part],
    }
}

/// A symbolic cloud resource of an unknown identity, for a non-literal target.
fn symbolic_cloud() -> ResourceExpr {
    ResourceExpr::Unresolved {
        family: ResourceFamily::new("cloud"),
    }
}

/// The non-flag operands after `start`, with their argv indices.
fn operands(argv: &[Word], start: usize) -> Vec<(u32, &Word)> {
    argv.iter()
        .enumerate()
        .skip(start)
        .filter(|(i, w)| {
            !w.as_literal().is_some_and(|t| t.starts_with('-'))
                && !i
                    .checked_sub(1)
                    .and_then(|p| argv[p].as_literal())
                    .is_some_and(|p| CLOUD_SCOPE_FLAGS.contains(&p))
        })
        .map(|(i, w)| (i as u32, w))
        .collect()
}

pub(crate) fn unresolved_network() -> ResourceExpr {
    ResourceExpr::Unresolved {
        family: ResourceFamily::new("network"),
    }
}

fn unrecoverable_remote_source(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    argument: ProvenanceRef,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: ["environment", "filesystem", "network", "process"]
            .into_iter()
            .map(Domain::new)
            .collect(),
        provenance: vec![model_node, argument],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

struct Aws;

impl CommandModel for Aws {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/aws@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["aws"]
    }
    // Secrets Manager and Parameter Store reads print the value they read,
    // so it can reach the next stage of a pipeline.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        match argv
            .get(crate::models::scope::command_position(
                argv,
                CLOUD_SCOPE_FLAGS,
            ))
            .and_then(Word::as_literal)
        {
            Some("secretsmanager" | "ssm") => super::credential::read_output(false),
            _ => transfer_stdin_upload(argv),
        }
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            declare_common(builder, ctx, model_node, false);
            return;
        }
        let input = aws_request_input(builder, ctx);
        let expanded;
        let ctx = match &input {
            AwsInput::Read { argv, provenance } => {
                expanded = InvocationCtx {
                    argv,
                    stdin: ctx.stdin,
                    argv_provenance: Some(provenance),
                    cwd: ctx.cwd,
                    cwd_resource: ctx.cwd_resource.clone(),
                    runtime_cwd: ctx.runtime_cwd,
                    scope: ctx.scope,
                    cwd_node: ctx.cwd_node,
                    nest: ctx.nest,
                    depth: ctx.depth,
                    model_stack: ctx.model_stack.clone(),
                };
                &expanded
            }
            AwsInput::Unreadable => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("cloud"), Domain::new("network")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "AWS CLI request input supplies parameters Nah does not read".into(),
                    ),
                });
                ctx
            }
            AwsInput::Absent => ctx,
        };
        let argv = ctx.argv;
        let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
        let service = argv.get(command).and_then(Word::as_literal);
        let credential_covered = match service {
            Some("secretsmanager") => Some(super::credential::aws_secretsmanager(
                builder, ctx, model_node,
            )),
            Some("ssm")
                if matches!(
                    argv.get(command + 1).and_then(Word::as_literal),
                    Some(
                        "get-parameter"
                            | "get-parameters"
                            | "get-parameters-by-path"
                            | "put-parameter"
                            | "delete-parameter"
                            | "delete-parameters"
                    )
                ) =>
            {
                Some(super::credential::aws_ssm_parameters(
                    builder, ctx, model_node,
                ))
            }
            _ => None,
        };
        declare_common(
            builder,
            ctx,
            model_node,
            credential_covered.unwrap_or(false),
        );
        if credential_covered.is_some() {
            return;
        }
        if let Some(delete) = resource_delete(argv) {
            resource_delete_effect(builder, ctx, model_node, &delete);
            return;
        }
        // The scope reading takes a reviewed global option's separate value
        // (`aws --output json ec2 ...`) as the service; termination is read
        // with every reviewed global option, as the other deletes are.
        if let Some(service) = aws_service_after_globals(argv)
            && argv.get(service).and_then(Word::as_literal) == Some("ec2")
            && argv.get(service + 1).and_then(Word::as_literal) == Some("terminate-instances")
        {
            ec2_lifecycle(builder, ctx, model_node, service + 1);
            return;
        }
        match service {
            Some("s3") => s3(builder, ctx, model_node),
            Some("s3api") => s3api(builder, ctx, model_node),
            Some("ec2") => ec2_lifecycle(builder, ctx, model_node, command + 1),
            Some("rds") => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws rds subcommand",
            ),
            Some("cloudformation") => {
                if argv.get(command + 1).and_then(Word::as_literal) == Some("delete-stack") {
                    delete_by_flag(
                        builder,
                        ctx,
                        model_node,
                        "aws",
                        "cloudformation",
                        "stack",
                        "--stack-name",
                    );
                } else {
                    boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "aws cloudformation subcommand",
                    );
                }
            }
            Some("ssm") => ssm(builder, ctx, model_node),
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws service",
            ),
        }
    }
}

fn ssm(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    match ctx.argv.get(2).and_then(Word::as_literal) {
        Some("start-session") => ssm_start_session(builder, ctx, model_node),
        Some("send-command") => ssm_send_command(builder, ctx, model_node),
        _ => boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws ssm subcommand",
        ),
    }
}

fn ssm_start_session(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &FLAGS);
    let Some((target_index, target)) = scanned.values_of(&["--target"]).first().copied() else {
        return;
    };
    cloud_effect(
        builder,
        ctx,
        model_node,
        target_index,
        "network.connect",
        unresolved_network(),
    );
    let Some((parameter_index, parameters)) = ssm_parameters(ctx.argv) else {
        return;
    };
    let supported_document = scanned
        .values_of(&["--document-name"])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
        .is_some_and(|document| {
            matches!(
                document,
                "AWS-StartInteractiveCommand" | "AWS-StartNonInteractiveCommand"
            )
        });
    if !supported_document {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws ssm start-session document",
        );
        return;
    }
    let argument = arg_node(builder, ctx, parameter_index);
    let Ok(commands) = parse_ssm_parameters(&parameters, "command") else {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "aws ssm command is not statically recoverable",
        );
        return;
    };
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        commands.join("\n"),
        format!("ssm:{}", target.render_raw()),
    );
}

fn ssm_send_command(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &FLAGS);
    if scanned
        .values_of(&["--document-name"])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
        != Some("AWS-RunShellScript")
    {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws ssm send-command document",
        );
        return;
    }
    let instances = scanned
        .flags
        .iter()
        .find(|flag| flag.name == "--instance-ids")
        .map(|flag| {
            ctx.argv
                .iter()
                .enumerate()
                .skip(flag.index as usize + 1)
                .take_while(|(_, word)| {
                    !word
                        .as_literal()
                        .is_some_and(|value| value.starts_with('-'))
                })
                .map(|(index, word)| (index as u32, word))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let Some((parameter_index, parameters)) = ssm_parameters(ctx.argv) else {
        return;
    };
    let argument = arg_node(builder, ctx, parameter_index);
    let Ok(commands) = parse_ssm_parameters(&parameters, "commands") else {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "aws ssm commands are not statically recoverable",
        );
        return;
    };
    for (instance_index, instance) in instances {
        cloud_effect(
            builder,
            ctx,
            model_node,
            instance_index,
            "network.connect",
            unresolved_network(),
        );
        for command in &commands {
            nest_remote_shell(
                builder,
                ctx,
                &[model_node, argument],
                command.clone(),
                format!("ssm:{}", instance.render_raw()),
            );
        }
    }
}

fn ssm_parameters(argv: &[Word]) -> Option<(u32, Word)> {
    let scanned = scan_literal_flags(argv, &FLAGS);
    if let Some((index, value)) = scanned.values_of(&["--parameters"]).first().copied() {
        return Some((index, value.clone()));
    }
    argv.iter().enumerate().find_map(|(index, word)| {
        attached_value(word, "--parameters=").map(|value| (index as u32, value))
    })
}

fn parse_ssm_parameters(word: &Word, name: &str) -> Result<Vec<String>, ()> {
    let literal = word.as_literal().ok_or(())?;
    if literal.starts_with('{') {
        let object = serde_json::from_str::<serde_json::Value>(literal).map_err(|_| ())?;
        return json_string_array(object.get(name).ok_or(())?);
    }
    let (actual_name, value) = word.split_assignment().ok_or(())?;
    if actual_name != name {
        return Err(());
    }
    let value = value.as_literal().ok_or(())?;
    if name == "command" {
        return Ok(vec![value.to_string()]);
    }
    let array = serde_json::from_str::<serde_json::Value>(value).map_err(|_| ())?;
    json_string_array(&array)
}

fn json_string_array(value: &serde_json::Value) -> Result<Vec<String>, ()> {
    value
        .as_array()
        .ok_or(())?
        .iter()
        .map(|value| value.as_str().map(str::to_string).ok_or(()))
        .collect()
}

fn s3(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &FLAGS);
    let argv = ctx.argv;
    let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
    let sub = argv.get(command + 1).and_then(Word::as_literal);
    let recursive = scanned.has(&["--recursive"]);
    // A filter decides which keys under the prefix the sweep reaches; the
    // pattern is matched against the listing, not against argv.
    let filtered = scanned
        .flags
        .iter()
        .any(|flag| matches!(flag.name, "--exclude" | "--include"));
    // `--dryrun` makes cp, mv, rm and sync print each operation they would
    // perform and perform none: nothing is uploaded, written or deleted. A
    // recursive or sync run still lists the S3 side to decide what it would
    // do. argparse never takes a `-`-prefixed word as a flag's value, so a
    // literal `--dryrun` before `--` is always the flag. An unknown word
    // could expand to `--`, so it also ends the proven option prefix.
    let dry_run = argv
        .iter()
        .skip(command + 2)
        .map_while(|word| word.as_literal().filter(|literal| *literal != "--"))
        .any(|literal| literal == "--dryrun");
    if dry_run && matches!(sub, Some("cp" | "mv" | "rm" | "sync")) {
        if recursive || sub == Some("sync") {
            for (i, w) in operands(argv, command + 2) {
                if let Some(r) = object_target(w) {
                    object_effect(
                        builder,
                        ctx,
                        model_node,
                        i,
                        "cloud.object.read",
                        r,
                        true,
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
        }
        environment_boundary(
            builder,
            model_node,
            BoundaryReason::REVIEWED_COMMAND_SURFACE,
            BoundaryClass::Unmodeled,
            &["filesystem", "network", "process"],
            "aws s3 --dryrun displays the operations without performing them",
        );
        return;
    }
    match sub {
        Some("rm") => {
            if recursive && filtered {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::PARTIAL_ANALYSIS,
                    BoundaryClass::Unresolved,
                    &["cloud"],
                    "a removal filter bounds which keys under the prefix are deleted",
                );
            }
            for (i, w) in operands(
                argv,
                crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS) + 2,
            ) {
                object_effect(
                    builder,
                    ctx,
                    model_node,
                    i,
                    "cloud.object.delete",
                    object_target(w).unwrap_or_else(symbolic_cloud),
                    recursive && !filtered,
                    false,
                    true,
                    Default::default(),
                );
            }
        }
        Some("rb") => {
            // `rb` removes the bucket and nothing else: without `--force` the
            // bucket must already be empty, so only `--force` establishes the
            // deletion of the objects under it.
            let force = scanned.has(&["--force"]);
            for (i, w) in operands(
                argv,
                crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS) + 2,
            ) {
                if let Some(r) = object_target(w) {
                    object_effect(
                        builder,
                        ctx,
                        model_node,
                        i,
                        "cloud.object.delete",
                        r,
                        force,
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
        }
        Some("cp") | Some("mv") => {
            transfer_pair(builder, ctx, model_node, command + 2, false, recursive)
        }
        // `aws s3 sync` always walks the source directory.
        Some("sync") => transfer_pair(
            builder,
            ctx,
            model_node,
            command + 2,
            scanned.has(&["--delete"]),
            true,
        ),
        _ => boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws s3 subcommand",
        ),
    }
}

const S3API_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--bucket",
        "--key",
        "--delete",
        "--versioning-configuration",
        "--profile",
        "--region",
        "--endpoint-url",
    ],
    known_flags: &["--quiet", "--only-show-errors"],
};

fn s3api(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan(ctx.argv, &S3API_SPEC);
    let command = crate::models::scope::command_position(ctx.argv, CLOUD_SCOPE_FLAGS);
    let sub = ctx.argv.get(command + 1).and_then(Word::as_literal);
    match sub {
        // `delete-bucket` removes the bucket resource alone and fails unless
        // it is already empty; neither verb deletes a tree of objects.
        Some("delete-object") | Some("delete-bucket") => {
            if let Some(bucket) = scanned
                .values_of(&["--bucket"])
                .first()
                .map(|(_, value)| *value)
                .and_then(Word::as_literal)
            {
                let key = scanned
                    .values_of(&["--key"])
                    .first()
                    .map(|(_, value)| *value)
                    .and_then(Word::as_literal)
                    .map(str::to_string);
                let r = ResourceExpr::Concrete {
                    identity: ResourceIdentity::ObjectStore {
                        scope: Box::new(effinterp_proto::object_scope(Some("aws"))),
                        provider: Some("aws".into()),
                        bucket: bucket.to_string(),
                        key,
                    },
                };
                object_effect(
                    builder,
                    ctx,
                    model_node,
                    (command + 1) as u32,
                    "cloud.object.delete",
                    r,
                    false,
                    false,
                    true,
                    Default::default(),
                );
            } else {
                object_effect(
                    builder,
                    ctx,
                    model_node,
                    (command + 1) as u32,
                    "cloud.object.delete",
                    symbolic_cloud(),
                    false,
                    false,
                    true,
                    Default::default(),
                );
            }
        }
        Some("delete-objects") => {
            let bucket = scanned.value_of(&["--bucket"]).and_then(Word::as_literal);
            let manifest = scanned.flags.iter().find(|flag| flag.name == "--delete");
            let (Some(bucket), Some(manifest)) = (bucket, manifest) else {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::MISSING_REQUIRED_ARGUMENTS,
                    BoundaryClass::Unmodeled,
                    &["cloud", "filesystem", "network"],
                    "aws s3api delete-objects requires --bucket and --delete",
                );
                return;
            };
            let manifest_word = manifest.value.as_ref().unwrap();
            let Some(path) = manifest_word
                .as_literal()
                .and_then(|value| value.strip_prefix("file://"))
            else {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNSUPPORTED_SOURCE,
                    BoundaryClass::Unsupported,
                    &["cloud", "filesystem"],
                    "aws s3api delete-objects manifest is not a file:// source",
                );
                return;
            };
            let source = Word::literal(path);
            let source_resource = ctx.resolve_fs_word(&source);
            fs_arg_effect(
                builder,
                ctx,
                model_node,
                manifest.value_index.unwrap_or(manifest.index),
                &source,
                "filesystem.read",
                source_resource.clone(),
                program_input_attrs(),
            );
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNRESOLVED_SOURCE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(source_resource),
                    callee: None,
                    domains: vec![Domain::new("filesystem"), Domain::new("cloud")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "aws s3api delete-objects manifest contents are not supplied".into(),
                    ),
                },
                CoverageLevel::Partial,
            );
            let attributes = Attrs::from([
                ("selection".into(), AttrValue::String("manifest".into())),
                ("manifest".into(), AttrValue::String(path.into())),
            ]);
            object_effect(
                builder,
                ctx,
                model_node,
                (command + 1) as u32,
                "cloud.object.delete",
                ResourceExpr::Pattern {
                    pattern: ResourcePattern::ObjectStore {
                        provider: Field::Exact {
                            value: "aws".into(),
                        },
                        bucket: bucket.into(),
                        key_prefix: None,
                    },
                },
                false,
                false,
                true,
                attributes,
            );
        }
        Some("put-bucket-versioning")
            if scanned.has(&["--bucket"]) && !scanned.has(&["--versioning-configuration"]) =>
        {
            environment_boundary(
                builder,
                model_node,
                BoundaryReason::REVIEWED_COMMAND_SURFACE,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws rejects put-bucket-versioning without --versioning-configuration",
            );
        }
        _ => boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws s3api subcommand",
        ),
    }
}

/// `cp/mv/sync SRC DEST`: each side is an object store (if a URL) or local fs.
/// An object-store transfer between two operands. A server-side copy pairs the
/// object read with the object write and never invents a client-side payload
/// upload or download. A local source is uploaded: its bytes cross the network
/// into the object, and a `recursive` transfer sends everything under it.
fn transfer_pair(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    start: usize,
    delete: bool,
    recursive: bool,
) {
    let tool = crate::models::args::basename(ctx.argv[0].as_literal().unwrap_or(""));
    let value_flags = transfer_value_flags(tool);
    let spec = FlagSpec {
        allow_abbreviation: false,
        value_flags: &value_flags,
        known_flags: FLAGS.known_flags,
    };
    let scanned = scan(ctx.argv, &spec);
    let ops = transfer_operands(&scanned, start);
    let (sources, (di, dest)) = match ops.as_slice() {
        [source, destination] => (vec![*source], *destination),
        _ => {
            boundary(
                builder,
                model_node,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &["cloud", "filesystem", "network"],
                "transfer operands are outside the reviewed grammar",
            );
            // An unlisted value flag leaves its value among the operands, so
            // only the last operand is known to be the destination.
            let Some((&destination, before)) = ops.split_last() else {
                return;
            };
            let objects = before
                .iter()
                .filter(|(_, word)| object_target(word).is_some())
                .copied()
                .collect::<Vec<_>>();
            let sources = if !objects.is_empty() {
                // An object source makes this a download or a server-side
                // copy; the other words are option values, never uploaded.
                objects
            } else if object_target(destination.1).is_some() {
                // Every literal local word before an object destination may be
                // a file the CLI uploads there.
                before
                    .iter()
                    .filter(|(_, word)| word.as_literal().is_some())
                    .copied()
                    .collect()
            } else {
                return;
            };
            (sources, destination)
        }
    };
    let mut selection = Attrs::new();
    for (index, flag) in scanned
        .flags
        .iter()
        .filter(|flag| matches!(flag.name, "--exclude" | "--include"))
        .enumerate()
    {
        selection.insert(
            format!("filter_option_{index}"),
            AttrValue::String(flag.name.into()),
        );
        if let Some(value) = flag.value.as_ref().and_then(Word::as_literal) {
            selection.insert(
                format!("filter_value_{index}"),
                AttrValue::String(value.into()),
            );
        }
    }
    if sources.iter().any(|(_, src)| {
        object_target(src).is_none()
            && src.as_literal().is_some()
            && ((tool == "aws"
                && ctx.argv.get(start - 1).and_then(Word::as_literal) == Some("sync")
                && !ctx
                    .argv
                    .iter()
                    .any(|word| word.as_literal() == Some("--no-follow-symlinks")))
                || (tool == "gsutil"
                    && ctx.argv.get(start - 1).and_then(Word::as_literal) == Some("rsync")
                    && !short_option(ctx.argv, start, &['e'])))
    }) {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unresolved,
            &["filesystem"],
            "synchronization follows local symbolic links whose targets are not observed",
        );
    }
    // A synchronization filter narrows the selected entries but does not
    // disable destination pruning. Preserve the filter beside the delete.
    let mut read_slots = Vec::new();
    let mut uploads = Vec::new();
    let mut stdin = false;
    for (si, src) in &sources {
        // `-` is stdin, which the model's causal binding carries to the upload.
        if src.as_literal() == Some("-") {
            stdin = true;
            continue;
        }
        let mut source_selection = selection.clone();
        if tool == "aws"
            && recursive
            && object_target(src).is_none()
            && let Some(excluded) = aws_excluded_paths(ctx, &scanned)
        {
            source_selection.insert("excluded_paths".into(), excluded);
        }
        let slot = side_effect(
            builder,
            ctx,
            model_node,
            *si,
            src,
            false,
            false,
            &source_selection,
            recursive,
            None,
        );
        read_slots.extend(slot);
        if object_target(src).is_none() && !leading_symbolic_without(src, &['/']) {
            uploads.extend(slot);
        }
    }
    let destination = side_effect(
        builder,
        ctx,
        model_node,
        di,
        dest,
        true,
        delete,
        &selection,
        false,
        (stdin || !uploads.is_empty()).then_some(uploads.as_slice()),
    );
    if let Some(destination) = destination {
        for source in read_slots {
            builder.transfer_binding(TransferBinding::new(source, destination));
        }
    }
}

/// The shared value flags plus each CLI's documented transfer and global
/// ones, so a flag value such as `--acl public-read` or `--ca-bundle ca.pem`
/// is never taken for a transfer operand.
fn transfer_value_flags(tool: &str) -> Vec<&'static str> {
    let routine: &[&str] = match tool {
        "aws" => &[
            "--acl",
            "--content-type",
            "--cache-control",
            "--storage-class",
            "--sse",
            "--sse-kms-key-id",
            "--metadata",
            "--metadata-directive",
            "--expected-size",
            "--grants",
            "--ca-bundle",
            "--output",
            "--query",
            "--color",
            "--cli-read-timeout",
            "--cli-connect-timeout",
            "--sse-c",
            "--sse-c-key",
            "--sse-c-copy-source",
            "--sse-c-copy-source-key",
            "--request-payer",
            "--content-encoding",
            "--content-disposition",
            "--content-language",
            "--expires",
            "--website-redirect",
            "--checksum-algorithm",
            "--checksum-mode",
            "--source-region",
            "--page-size",
            "--copy-props",
        ],
        "gsutil" => &["-a", "-h", "-z", "-j", "-L"],
        "gcloud" => &[
            "--content-type",
            "--cache-control",
            "--storage-class",
            "--billing-project",
            "--content-encoding",
            "--content-disposition",
        ],
        "azcopy" => &[
            "--overwrite",
            "--include-pattern",
            "--exclude-pattern",
            "--log-level",
            "--block-size-mb",
            "--cap-mbps",
            "--from-to",
            "--include-path",
            "--exclude-path",
        ],
        _ => &[],
    };
    FLAGS.value_flags.iter().chain(routine).copied().collect()
}

fn transfer_operands<'a>(scanned: &Scanned<'a>, start: usize) -> Vec<(u32, &'a Word)> {
    scanned
        .operands
        .iter()
        .copied()
        .filter(|(index, _)| *index as usize >= start)
        .collect()
}

/// `aws s3 cp - OBJECT`, `gsutil cp - OBJECT` and `gcloud storage cp - OBJECT`
/// upload their stdin, so it flows exactly into the transfer's upload. As in
/// `transfer_pair`, a `-` anywhere before an object destination counts, since
/// an unlisted flag's value may sit among the operands.
fn transfer_stdin_upload(argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
    let tool = crate::models::args::basename(argv[0].as_literal().unwrap_or(""));
    let at = |index: usize| argv.get(index).and_then(Word::as_literal);
    let start = match tool {
        "aws" | "gcloud" => {
            let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
            let group = if tool == "aws" { "s3" } else { "storage" };
            (at(command) == Some(group) && matches!(at(command + 1), Some("cp" | "mv")))
                .then_some(command + 2)
        }
        "gsutil" => {
            let command = crate::models::scope::command_position(argv, GSUTIL_GLOBAL_FLAGS);
            matches!(at(command), Some("cp" | "mv")).then_some(command + 1)
        }
        _ => None,
    };
    let Some(start) = start else {
        return Vec::new();
    };
    let value_flags = transfer_value_flags(tool);
    let spec = FlagSpec {
        allow_abbreviation: false,
        value_flags: &value_flags,
        known_flags: FLAGS.known_flags,
    };
    let scanned = scan(argv, &spec);
    match transfer_operands(&scanned, start).split_last() {
        Some(((_, destination), sources))
            if object_target(destination).is_some()
                && !sources
                    .iter()
                    .any(|(_, word)| object_target(word).is_some())
                && sources
                    .iter()
                    .any(|(_, word)| word.as_literal() == Some("-")) =>
        {
            vec![crate::models::ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
                to: crate::models::ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
            }]
        }
        _ => Vec::new(),
    }
}

/// One side of a cloud transfer, returning the endpoint slot the pairing
/// anchors on. `upload` holds the local source reads a destination object
/// uploads; it is present but empty when the source is stdin.
#[allow(clippy::too_many_arguments)]
fn side_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    word: &Word,
    write: bool,
    delete: bool,
    selection: &Attrs,
    recursive: bool,
    upload: Option<&[u32]>,
) -> Option<u32> {
    if let Some(r) = object_target(word) {
        let op = if write {
            "cloud.object.write"
        } else {
            "cloud.object.read"
        };
        let slot = object_upload_effect(
            builder,
            ctx,
            model_node,
            index,
            op,
            r.clone(),
            false,
            delete,
            true,
            selection.clone(),
            upload,
        );
        // A synchronizing delete removes whichever destination entries the
        // source does not have; which keys those are is not argv evidence.
        if write && delete {
            object_effect(
                builder,
                ctx,
                model_node,
                index,
                "cloud.object.delete",
                r,
                true,
                true,
                false,
                selection.clone(),
            );
        }
        slot
    } else if leading_symbolic_without(word, &['/']) {
        let op = if write {
            "cloud.object.write"
        } else {
            "cloud.object.read"
        };
        let mut attributes = selection.clone();
        if delete {
            attributes.insert("delete".into(), AttrValue::Bool(true));
        }
        let slot = crate::models::common::arg_effect(
            builder,
            ctx,
            model_node,
            index,
            op,
            symbolic_expr(word, "cloud"),
            attributes,
        );
        // A local source has no local destination: the CLI requires an
        // object on one side, so the word names the object the bytes go to.
        if let Some(sources) = upload
            && let Some(sink) = crate::models::common::arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.upload",
                unresolved_network(),
                Attrs::new(),
            )
        {
            for source in sources {
                builder.transfer_binding(TransferBinding::new(*source, sink));
            }
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_TRANSFER_TARGET,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("cloud"),
                Domain::new("filesystem"),
                Domain::new("network"),
            ],
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!(
                "transfer operand {} (arg {index}) may be a local path or an object URL",
                word.render_raw()
            )),
        });
        slot
    } else {
        // A local path side.
        let op = if write {
            "filesystem.write"
        } else {
            "filesystem.read"
        };
        let resource = ctx.resolve_fs_word(word);
        let arg = crate::models::common::fs_arg_node(builder, ctx, index, word);
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        if write && delete {
            let mut delete_attributes = selection.clone();
            delete_attributes.insert("recursive".into(), AttrValue::Bool(true));
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("filesystem.delete"),
                resource: resource.clone(),
                attributes: delete_attributes,
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![arg, model_node],
            });
        }
        let mut attributes = selection.clone();
        attributes.extend(if write {
            program_output_attrs()
        } else {
            program_input_attrs()
        });
        if recursive {
            attributes.insert("recursive".into(), AttrValue::Bool(true));
        }
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(op),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![arg, model_node],
        })
    }
}

fn ec2_lifecycle(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model: ProvenanceRef,
    verb_index: usize,
) {
    // Snapshots and volumes carry their own identifier flag instead of the
    // instance-id list the instance lifecycle verbs share.
    if let Some((kind, flag)) = match ctx.argv.get(verb_index).and_then(Word::as_literal) {
        Some("delete-snapshot") => Some(("snapshot", "--snapshot-id")),
        Some("delete-volume") => Some(("volume", "--volume-id")),
        _ => None,
    } {
        delete_by_flag(builder, ctx, model, "aws", "ec2", kind, flag);
        return;
    }
    let operation = match ctx.argv.get(verb_index).and_then(Word::as_literal) {
        Some("run-instances") => "cloud.resource.create",
        Some("describe-instances") => "cloud.resource.read",
        Some("create-tags") => "cloud.resource.update",
        Some("start-instances") => "cloud.resource.start",
        Some("stop-instances") => "cloud.resource.stop",
        Some("reboot-instances") => "cloud.resource.restart",
        Some("terminate-instances") => "cloud.resource.delete",
        _ => {
            boundary(
                builder,
                model,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws ec2 subcommand",
            );
            return;
        }
    };
    let mut ids = Vec::new();
    let mut dry_run = false;
    let mut skeleton = false;
    let mut uncertain = false;
    // An option the lifecycle verbs share but termination does not document,
    // or an unresolved word among the instance IDs, which may be an option
    // (`--instance-ids i-1 "$EXTRA"` with `EXTRA=--dry-run`).
    let mut unread = false;
    let mut i = verb_index + 1;
    while i < ctx.argv.len() {
        let word = &ctx.argv[i];
        let raw = word.render_raw();
        let (flag, assigned) = word
            .split_assignment()
            .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
        match flag {
            "--dry-run" => {
                dry_run = assigned.is_none()
                    || assigned.as_ref().and_then(Word::as_literal) == Some("true");
                if assigned
                    .as_ref()
                    .is_some_and(|v| !matches!(v.as_literal(), Some("true" | "false")))
                {
                    uncertain = true;
                }
            }
            "--no-dry-run" => dry_run = false,
            "--generate-cli-skeleton" => {
                skeleton = true;
                if assigned.is_none()
                    && ctx.argv.get(i + 1).is_some_and(|w| {
                        matches!(w.as_literal(), Some("input" | "output" | "yaml-input"))
                    })
                {
                    i += 1;
                }
            }
            "--instance-ids" | "--resources" => {
                let resources = flag == "--resources";
                unread |= resources;
                // argparse stores a list option, so a repeated one replaces
                // the earlier list rather than adding to it.
                ids.retain(|(list, _, _)| *list != resources);
                if let Some(value) = assigned {
                    unread |= value.as_literal().is_none();
                    ids.push((resources, i as u32, value));
                } else {
                    let start = i;
                    i += 1;
                    while i < ctx.argv.len() && !ctx.argv[i].render_raw().starts_with('-') {
                        unread |= ctx.argv[i].as_literal().is_none();
                        ids.push((resources, i as u32, ctx.argv[i].clone()));
                        i += 1;
                    }
                    if i == start + 1 {
                        uncertain = true;
                    }
                    continue;
                }
            }
            "--tags" => {
                unread = true;
                if assigned.is_none() {
                    let start = i;
                    i += 1;
                    while i < ctx.argv.len() && !ctx.argv[i].render_raw().starts_with('-') {
                        i += 1;
                    }
                    if i == start + 1 {
                        uncertain = true;
                    }
                    continue;
                }
            }
            "--region"
            | "--endpoint-url"
            | "--profile"
            | "--image-id"
            | "--count"
            | "--min-count"
            | "--max-count"
            | "--instance-type"
            | "--key-name"
            | "--subnet-id"
            | "--output"
            | "--query"
            | "--cli-read-timeout"
            | "--cli-connect-timeout" => {
                unread |= matches!(
                    flag,
                    "--image-id"
                        | "--count"
                        | "--min-count"
                        | "--max-count"
                        | "--instance-type"
                        | "--key-name"
                        | "--subnet-id"
                );
                if assigned.is_none() {
                    if ctx
                        .argv
                        .get(i + 1)
                        .is_some_and(|w| !w.render_raw().starts_with('-'))
                    {
                        i += 1;
                    } else {
                        uncertain = true;
                    }
                }
            }
            "--force"
            | "--no-force"
            | "--hibernate"
            | "--no-hibernate"
            | "--skip-os-shutdown"
            | "--no-skip-os-shutdown"
            | "--no-cli-pager"
            | "--no-paginate"
            | "--no-sign-request"
            | "--no-verify-ssl" => unread |= matches!(flag, "--hibernate" | "--no-hibernate"),
            _ => {
                uncertain = true;
                break;
            }
        }
        i += 1;
    }
    let mut provenance = vec![model];
    for index in 1..ctx.argv.len() {
        provenance.push(arg_node(builder, ctx, index as u32));
    }
    if uncertain {
        boundary(
            builder,
            model,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "EC2 options, input indirection or required values are unresolved",
        );
    }
    for word in ctx.argv.iter().skip(verb_index + 1) {
        match word.as_literal() {
            Some("--dry-run" | "--dry-run=true") => dry_run = true,
            Some("--no-dry-run" | "--dry-run=false") => dry_run = false,
            Some(value)
                if value == "--generate-cli-skeleton"
                    || value.starts_with("--generate-cli-skeleton=") =>
            {
                skeleton = true
            }
            _ => {}
        }
    }
    if skeleton {
        return;
    }
    cloud_network_effect(
        builder,
        ctx,
        &provenance,
        &symbolic_cloud(),
        "network.request",
    );
    if dry_run && operation != "cloud.resource.read" {
        return;
    }
    if ids.is_empty() || operation == "cloud.resource.create" {
        super::infrastructure::emit(builder, &provenance, operation, symbolic_cloud());
        if operation == "cloud.resource.create" || operation == "cloud.resource.read" {
            environment_boundary(
                builder,
                model,
                BoundaryReason::LIVE_INVENTORY,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "EC2 created identities or instance inventory are unresolved",
            );
        } else {
            boundary(
                builder,
                model,
                BoundaryReason::PARTIAL_ANALYSIS,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "EC2 created identities or instance inventory are unresolved",
            );
        }
        return;
    }
    // An ID read from a file, JSON or an empty word is input Nah does not
    // read, so no instance in that effective list is an exact target.
    let instance_id = |word: &Word| {
        word.as_literal()
            .filter(|id| {
                !id.is_empty()
                    && !id.starts_with(['[', '{'])
                    && !id.starts_with("file://")
                    && !id.starts_with("fileb://")
                    && !id.chars().any(char::is_whitespace)
            })
            .map(str::to_string)
    };
    let ids_readable = ids.iter().all(|(_, _, word)| instance_id(word).is_some());
    for (_, _, word) in ids {
        let id = instance_id(&word);
        let id = id.as_deref();
        if id.is_none() {
            boundary(
                builder,
                model,
                BoundaryReason::PARTIAL_ANALYSIS,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "EC2 resource ID input is symbolic or indirect",
            );
        }
        let mut resource = id.map_or_else(symbolic_cloud, |id| ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(effinterp_proto::cloud_scope(
                    Some("aws"),
                    "ec2",
                    if operation == "cloud.resource.update" && !id.starts_with("i-") {
                        "resource"
                    } else {
                        "instance"
                    },
                )),
                provider: Some("aws".into()),
                service: "ec2".into(),
                kind: if operation == "cloud.resource.update" && !id.starts_with("i-") {
                    "resource"
                } else {
                    "instance"
                }
                .into(),
                id: Some(id.into()),
            },
        });
        let mut provenance = provenance.clone();
        apply_cloud_scope(builder, ctx, &mut provenance, &mut resource);
        let mut attributes = std::collections::BTreeMap::new();
        if operation == "cloud.resource.update" {
            attributes.insert("tag_update".into(), AttrValue::Bool(true));
        }
        // A termination whose every word was read as an option termination
        // documents and whose effective instance list is literal is the
        // request argv states.
        let request_assurance = if operation == "cloud.resource.delete"
            && !uncertain
            && !unread
            && ids_readable
            && aws_service_after_globals(ctx.argv) == Some(verb_index - 1)
        {
            effinterp_proto::RequestAssurance::Exact
        } else {
            effinterp_proto::RequestAssurance::Conservative
        };
        builder.effect(Effect {
            request_assurance,
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
}

/// The argv index of the AWS service word when every word before it is a
/// global option the CLI documents, with its value.
fn aws_service_after_globals(argv: &[Word]) -> Option<usize> {
    let mut index = 1;
    loop {
        let word = argv.get(index)?.as_literal()?;
        if !word.starts_with('-') {
            return Some(index);
        }
        let (flag, attached) = match word.split_once('=') {
            Some((flag, _)) => (flag, true),
            None => (word, false),
        };
        if AWS_COMMON_SWITCHES.contains(&flag) && !attached {
            index += 1;
        } else if AWS_COMMON_VALUES.contains(&flag) {
            index += if attached { 1 } else { 2 };
        } else {
            return None;
        }
    }
}

fn delete_by_flag(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    provider: &str,
    service: &str,
    kind: &str,
    flag: &str,
) {
    let scanned = scan_literal_flags(ctx.argv, &FLAGS);
    let r = match scanned
        .values_of(&[flag])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
    {
        Some(id) => ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(effinterp_proto::cloud_scope(Some(provider), service, kind)),
                provider: Some(provider.into()),
                service: service.into(),
                kind: kind.into(),
                id: Some(id.to_string()),
            },
        },
        None => symbolic_cloud(),
    };
    cloud_effect(builder, ctx, model_node, 2, "cloud.resource.delete", r);
}

/// What a managed-database delete leaves of the resource's automated backups,
/// as its vendor documents it.
#[derive(Clone, Copy)]
enum AutomatedBackups {
    /// A snapshot or backup delete, which removes one recovery point, or a
    /// resource delete whose backup semantics are not claimed.
    NotApplicable,
    /// Removed with the resource and no option keeps them (DocumentDB and
    /// Neptune clusters, Redshift clusters).
    Removed,
    /// Only `--delete-automated-backups` or `--no-delete-automated-backups`
    /// establishes it. An RDS cluster's default keeps them when the account's
    /// AWS Backup policy has a point-in-time rule. An RDS instance's default
    /// removes them, but argv cannot tell a standalone instance from an Aurora
    /// cluster member, whose backups belong to the cluster.
    Explicit,
}

/// A documented fully qualified resource name, which is the whole ID.
#[derive(Clone, Copy)]
enum Qualified {
    None,
    /// gcloud's collection path, e.g. `projects/P/instances/I/databases/D`
    /// for `["projects", "instances", "databases"]`.
    Path(&'static [&'static str]),
    /// An AWS ARN `arn:PARTITION:SERVICE:REGION:ACCOUNT:RESOURCE/NAME`.
    Arn {
        service: &'static str,
        resource: &'static str,
    },
}

impl Qualified {
    fn matches(self, name: &str) -> bool {
        match self {
            Qualified::None => false,
            Qualified::Path(collections) => {
                let parts: Vec<&str> = name.split('/').collect();
                parts.len() == 2 * collections.len()
                    && parts
                        .chunks(2)
                        .zip(collections)
                        .all(|(pair, collection)| pair[0] == *collection && !pair[1].is_empty())
            }
            Qualified::Arn { service, resource } => {
                let parts: Vec<&str> = name.splitn(6, ':').collect();
                matches!(
                    parts[..],
                    ["arn", partition, arn_service, region, account, path]
                        if !partition.is_empty()
                            && arn_service == service
                            && !region.is_empty()
                            && !account.is_empty()
                            && path
                                .strip_prefix(resource)
                                .and_then(|rest| rest.strip_prefix('/'))
                                .is_some_and(|name| !name.is_empty() && !name.contains('/'))
                )
            }
        }
    }
}

/// One documented cloud resource delete verb.
struct ResourceDelete {
    provider: &'static str,
    service: &'static str,
    kind: &'static str,
    /// argv indices of the command words, from the service through the verb.
    path: Vec<usize>,
    /// Options naming the resource; empty when its operand names it.
    id_flags: &'static [&'static str],
    /// Options naming the containing resources, outermost first. The CLI may
    /// take one from its configuration or a fully qualified operand instead.
    parents: &'static [&'static [&'static str]],
    /// Whether several operands each name a resource to delete.
    many: bool,
    /// The switch requesting a final backup (Cloud SQL).
    final_backup: Option<&'static str>,
    /// A switch pair whose effective `true` keeps the resource's data, so the
    /// request deletes no live data (ElastiCache's retained primary).
    keeps_data: Option<(&'static str, &'static str)>,
    /// The vendor's fully qualified form of the name, when one is documented.
    qualified: Qualified,
    /// Whether a name is checked before it becomes an ID: a `/` must form the
    /// fully qualified operand, and a value the CLI reads from a file (AWS
    /// `file://`/`fileb://`, Azure `@file`) is input Nah does not read.
    /// DB-BAK's snapshot and backup verbs keep their literal reading.
    strict_names: bool,
    /// Whether a checked name may contain `/` anyway: CloudWatch log groups
    /// and ECR repositories nest names, and some verbs take an ARN whose
    /// resource part does.
    slash_names: bool,
    /// Other command options that take a value.
    values: &'static [&'static str],
    /// Command options without a value.
    switches: &'static [&'static str],
    /// The CLI's global options, accepted after the verb too.
    common_values: &'static [&'static str],
    common_switches: &'static [&'static str],
    /// The CLI's scope options, which take a value wherever they appear.
    scope_values: &'static [&'static str],
    /// The skip-final-snapshot switch and its negation, for resource deletes.
    skip_final: Option<(&'static str, &'static str)>,
    /// The option naming the final snapshot when one is taken.
    final_snapshot: Option<&'static str>,
    backups: AutomatedBackups,
}

const AWS_COMMON_VALUES: &[&str] = &[
    "--region",
    "--profile",
    "--endpoint-url",
    "--output",
    "--query",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--color",
    "--ca-bundle",
    "--cli-binary-format",
];
const AWS_COMMON_SWITCHES: &[&str] = &[
    "--debug",
    "--no-verify-ssl",
    "--no-paginate",
    "--no-sign-request",
    "--no-cli-pager",
    "--cli-auto-prompt",
    "--no-cli-auto-prompt",
];
const GCLOUD_COMMON_VALUES: &[&str] = &[
    "--project",
    "--account",
    "--configuration",
    "--billing-project",
    "--impersonate-service-account",
    "--format",
    "--verbosity",
    "--access-token-file",
    "--flatten",
    "--trace-token",
    "--http-timeout",
    "--authority-selector",
    "--authorization-token-file",
    "--credential-file-override",
    "--universe-domain",
];
const GCLOUD_COMMON_SWITCHES: &[&str] = &[
    "--quiet",
    "-q",
    "--log-http",
    "--no-log-http",
    "--user-output-enabled",
    "--no-user-output-enabled",
];
const AZ_COMMON_VALUES: &[&str] = &[
    "--subscription",
    "--output",
    "-o",
    "--query",
    "--change-reference",
];
const AZ_COMMON_SWITCHES: &[&str] = &[
    "--debug",
    "--verbose",
    "--only-show-errors",
    "--acquire-policy-token",
];

/// The managed-database instance, cluster, database, table, snapshot and
/// backup deletes whose options the vendors document, Cloud SQL's user and
/// certificate deletes, and the reviewed deletes of other provisioned
/// resources: compute, networking, edge, identity and account scopes. Other
/// verbs keep their existing handling.
fn resource_delete(argv: &[Word]) -> Option<ResourceDelete> {
    let tool = crate::models::args::basename(argv.first()?.as_literal()?);
    let (common_values, common_switches, scope_values) = match tool {
        "aws" => (AWS_COMMON_VALUES, AWS_COMMON_SWITCHES, CLOUD_SCOPE_FLAGS),
        "gcloud" => (
            GCLOUD_COMMON_VALUES,
            GCLOUD_COMMON_SWITCHES,
            CLOUD_SCOPE_FLAGS,
        ),
        "az" => (AZ_COMMON_VALUES, AZ_COMMON_SWITCHES, AZ_GLOBAL_VALUE_FLAGS),
        _ => return None,
    };
    // The command words are found with the same global value options the
    // request is parsed with, plus the scope options that take a value but are
    // refused there (gcloud's --flags-file), so a detached global value is
    // never read as a command word. The CLIs accept global options between
    // command words (`gcloud sql --quiet instances delete x`).
    let global_values: Vec<&str> = common_values.iter().chain(scope_values).copied().collect();
    let words: Vec<usize> = crate::models::args::scan_detached(
        argv,
        &FlagSpec {
            value_flags: &global_values,
            known_flags: &[],
            allow_abbreviation: false,
        },
        false,
    )
    .operands
    .iter()
    .filter(|(_, word)| word.as_literal() != Some("-"))
    .map(|(index, _)| *index as usize)
    .collect();
    let globals = (common_values, common_switches, scope_values);
    // A word after an option the CLI's globals do not include may be that
    // option's value (`gcloud sql --weird d instances delete x`). When the
    // words as read name no verb, the one reading that skips some of those
    // words names it, if exactly one does; the skipped words stay out of the
    // operands. Only words that can precede a verb (at most five command words
    // and three skipped values) are candidates.
    resource_delete_row(argv, tool, &words, globals).or_else(|| {
        let candidates: Vec<(usize, &str)> = (0..words.len().min(8))
            .filter_map(|position| {
                argv[words[position] - 1]
                    .as_literal()
                    .filter(|flag| {
                        flag.starts_with('-')
                            && *flag != "-"
                            && *flag != "--"
                            && !flag.contains('=')
                            && !common_switches.contains(flag)
                    })
                    .map(|flag| (position, flag))
            })
            .collect();
        let readings = (1..1usize << candidates.len()).filter_map(|mask| {
            let skipped: Vec<(usize, &str)> = (0..candidates.len())
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| candidates[bit])
                .collect();
            let reading: Vec<usize> = (0..words.len())
                .filter(|position| !skipped.iter().any(|(skip, _)| skip == position))
                .map(|position| words[position])
                .collect();
            resource_delete_row(argv, tool, &reading, globals)
                .filter(|delete| skipped.iter().all(|(_, flag)| !delete.is_switch(flag)))
        });
        // Readings that skip words after the verb name the same command.
        let mut named: Vec<ResourceDelete> = Vec::new();
        for delete in readings {
            if !named.iter().any(|other| other.path == delete.path) {
                named.push(delete);
            }
        }
        (named.len() == 1).then(|| named.remove(0))
    })
}

/// The documented verb `words`, the argv indices of the command words, name.
fn resource_delete_row(
    argv: &[Word],
    tool: &str,
    words: &[usize],
    (common_values, common_switches, scope_values): (
        &'static [&'static str],
        &'static [&'static str],
        &'static [&'static str],
    ),
) -> Option<ResourceDelete> {
    use AutomatedBackups::*;
    // gcloud's alpha and beta tracks take the GA command words after the
    // track word.
    let track = usize::from(
        tool == "gcloud"
            && matches!(
                words.first().and_then(|&index| argv[index].as_literal()),
                Some("alpha" | "beta")
            ),
    );
    let at = |offset: usize| {
        words
            .get(track + offset)
            .and_then(|&index| argv[index].as_literal())
    };
    let aws_resource = |service: &'static str,
                        kind: &'static str,
                        id_flags: &'static [&'static str],
                        skip_final: (&'static str, &'static str),
                        final_snapshot: &'static str,
                        backups: AutomatedBackups| ResourceDelete {
        provider: "aws",
        service,
        kind,
        path: words[..2].to_vec(),
        id_flags,
        parents: &[],
        many: false,
        final_backup: None,
        keeps_data: None,
        qualified: Qualified::None,
        strict_names: false,
        slash_names: false,
        values: &[],
        switches: &[],
        common_values: &[],
        common_switches: &[],
        scope_values: &[],
        skip_final: Some(skip_final),
        final_snapshot: Some(final_snapshot),
        backups,
    };
    let point = |provider: &'static str,
                 service: &'static str,
                 kind: &'static str,
                 start: usize,
                 id_flags: &'static [&'static str],
                 values: &'static [&'static str],
                 switches: &'static [&'static str]| ResourceDelete {
        provider,
        service,
        kind,
        path: words[..track + start].to_vec(),
        id_flags,
        parents: &[],
        many: false,
        final_backup: None,
        keeps_data: None,
        qualified: Qualified::None,
        strict_names: false,
        slash_names: false,
        values,
        switches,
        common_values: &[],
        common_switches: &[],
        scope_values: &[],
        skip_final: None,
        final_snapshot: None,
        backups: NotApplicable,
    };
    // A live resource delete that makes no claim about the resource's backups.
    // Its names are checked before they become an ID.
    let resource = |provider: &'static str,
                    service: &'static str,
                    kind: &'static str,
                    start: usize,
                    id_flags: &'static [&'static str],
                    parents: &'static [&'static [&'static str]],
                    values: &'static [&'static str],
                    switches: &'static [&'static str]| ResourceDelete {
        parents,
        strict_names: true,
        ..point(provider, service, kind, start, id_flags, values, switches)
    };
    const SKIP: (&str, &str) = ("--skip-final-snapshot", "--no-skip-final-snapshot");
    const RETAIN_PRIMARY: (&str, &str) =
        ("--retain-primary-cluster", "--no-retain-primary-cluster");
    let mut delete = match (tool, at(0), at(1), at(2), at(3)) {
        ("aws", Some("rds"), Some("delete-db-instance"), ..) => aws_resource(
            "rds",
            "db",
            &["--db-instance-identifier"],
            SKIP,
            "--final-db-snapshot-identifier",
            Explicit,
        ),
        ("aws", Some("rds"), Some("delete-db-cluster"), ..) => aws_resource(
            "rds",
            "cluster",
            &["--db-cluster-identifier"],
            SKIP,
            "--final-db-snapshot-identifier",
            Explicit,
        ),
        ("aws", Some("docdb" | "neptune"), Some("delete-db-cluster"), ..) => aws_resource(
            if at(0) == Some("docdb") {
                "docdb"
            } else {
                "neptune"
            },
            "cluster",
            &["--db-cluster-identifier"],
            SKIP,
            "--final-db-snapshot-identifier",
            Removed,
        ),
        ("aws", Some("redshift"), Some("delete-cluster"), ..) => ResourceDelete {
            values: &["--final-cluster-snapshot-retention-period"],
            ..aws_resource(
                "redshift",
                "cluster",
                &["--cluster-identifier"],
                (
                    "--skip-final-cluster-snapshot",
                    "--no-skip-final-cluster-snapshot",
                ),
                "--final-cluster-snapshot-identifier",
                Removed,
            )
        },
        ("aws", Some("rds"), Some("delete-db-snapshot"), ..) => point(
            "aws",
            "rds",
            "snapshot",
            2,
            &["--db-snapshot-identifier"],
            &[],
            &[],
        ),
        (
            "aws",
            Some(service @ ("rds" | "docdb" | "neptune")),
            Some("delete-db-cluster-snapshot"),
            ..,
        ) => point(
            "aws",
            match service {
                "rds" => "rds",
                "docdb" => "docdb",
                _ => "neptune",
            },
            "snapshot",
            2,
            &["--db-cluster-snapshot-identifier"],
            &[],
            &[],
        ),
        ("aws", Some("rds"), Some("delete-db-instance-automated-backup"), ..) => point(
            "aws",
            "rds",
            "backup",
            2,
            &["--dbi-resource-id", "--db-instance-automated-backups-arn"],
            &[],
            &[],
        ),
        ("aws", Some("rds"), Some("delete-db-cluster-automated-backup"), ..) => point(
            "aws",
            "rds",
            "backup",
            2,
            &["--db-cluster-resource-id"],
            &[],
            &[],
        ),
        ("aws", Some("redshift"), Some("delete-cluster-snapshot"), ..) => point(
            "aws",
            "redshift",
            "snapshot",
            2,
            &["--snapshot-identifier"],
            &["--snapshot-cluster-identifier"],
            &[],
        ),
        ("aws", Some("dynamodb"), Some("delete-backup"), ..) => {
            point("aws", "dynamodb", "backup", 2, &["--backup-arn"], &[], &[])
        }
        ("gcloud", Some("sql"), Some("backups"), Some("delete"), _) => point(
            "gcp",
            "sql",
            "backup",
            3,
            &[],
            &["--instance", "-i"],
            &["--async"],
        ),
        ("gcloud", Some("spanner"), Some("backups"), Some("delete"), _) => {
            point("gcp", "spanner", "backup", 3, &[], &["--instance"], &[])
        }
        ("gcloud", Some("alloydb"), Some("backups"), Some("delete"), _) => point(
            "gcp",
            "alloydb",
            "backup",
            3,
            &[],
            &["--region"],
            &["--async"],
        ),
        ("az", Some("sql"), Some("db"), Some("ltr-backup"), Some("delete")) => point(
            "azure",
            "sql",
            "backup",
            4,
            &["--name", "-n"],
            &["--location", "-l", "--server", "-s", "--database", "-d"],
            &["--yes", "-y"],
        ),
        ("az", Some("postgres"), Some("flexible-server"), Some("backup"), Some("delete")) => point(
            "azure",
            "postgres",
            "backup",
            4,
            &["--name", "-n"],
            &["--resource-group", "-g", "--server-name", "-s"],
            &["--yes", "-y"],
        ),
        ("az", Some("mysql"), Some("flexible-server"), Some("backup"), Some("delete")) => point(
            "azure",
            "mysql",
            "backup",
            4,
            &["--backup-name", "-b"],
            &["--resource-group", "-g", "--name", "-n"],
            &[],
        ),
        // --table-name also takes the table's ARN.
        ("aws", Some("dynamodb"), Some("delete-table"), ..) => ResourceDelete {
            qualified: Qualified::Arn {
                service: "dynamodb",
                resource: "table",
            },
            ..resource(
                "aws",
                "dynamodb",
                "table",
                2,
                &["--table-name"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("redshift-serverless"), Some("delete-namespace"), ..) => resource(
            "aws",
            "redshift-serverless",
            "namespace",
            2,
            &["--namespace-name"],
            &[],
            &["--final-snapshot-name", "--final-snapshot-retention-period"],
            &[],
        ),
        // Deleting a keyspace deletes all of its tables.
        ("aws", Some("keyspaces"), Some("delete-keyspace"), ..) => resource(
            "aws",
            "keyspaces",
            "keyspace",
            2,
            &["--keyspace-name"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("keyspaces"), Some("delete-table"), ..) => resource(
            "aws",
            "keyspaces",
            "table",
            2,
            &["--table-name"],
            &[&["--keyspace-name"]],
            &[],
            &[],
        ),
        // Timestream refuses to delete a database that still has tables.
        ("aws", Some("timestream-write"), Some("delete-database"), ..) => resource(
            "aws",
            "timestream",
            "database",
            2,
            &["--database-name"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("timestream-write"), Some("delete-table"), ..) => resource(
            "aws",
            "timestream",
            "table",
            2,
            &["--table-name"],
            &[&["--database-name"]],
            &[],
            &[],
        ),
        ("aws", Some("elasticache"), Some("delete-cache-cluster"), ..) => resource(
            "aws",
            "elasticache",
            "cache-cluster",
            2,
            &["--cache-cluster-id"],
            &[],
            &["--final-snapshot-identifier"],
            &[],
        ),
        // An effective --retain-primary-cluster deletes only the read
        // replicas and keeps the primary's data.
        ("aws", Some("elasticache"), Some("delete-replication-group"), ..) => ResourceDelete {
            keeps_data: Some(RETAIN_PRIMARY),
            ..resource(
                "aws",
                "elasticache",
                "replication-group",
                2,
                &["--replication-group-id"],
                &[],
                &["--final-snapshot-identifier"],
                &[RETAIN_PRIMARY.0, RETAIN_PRIMARY.1],
            )
        },
        ("aws", Some("elasticache"), Some("delete-serverless-cache"), ..) => resource(
            "aws",
            "elasticache",
            "serverless-cache",
            2,
            &["--serverless-cache-name"],
            &[],
            &["--final-snapshot-name"],
            &[],
        ),
        // --cluster-arn takes only the cluster's ARN.
        ("aws", Some("docdb-elastic"), Some("delete-cluster"), ..) => ResourceDelete {
            qualified: Qualified::Arn {
                service: "docdb-elastic",
                resource: "cluster",
            },
            ..resource(
                "aws",
                "docdb-elastic",
                "cluster",
                2,
                &["--cluster-arn"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("lightsail"), Some("delete-relational-database"), ..) => resource(
            "aws",
            "lightsail",
            "relational-database",
            2,
            &["--relational-database-name"],
            &[],
            &["--final-relational-database-snapshot-name"],
            &["--skip-final-snapshot", "--no-skip-final-snapshot"],
        ),
        ("aws", Some("dsql"), Some("delete-cluster"), ..) => resource(
            "aws",
            "dsql",
            "cluster",
            2,
            &["--identifier"],
            &[],
            &["--client-token"],
            &[],
        ),
        ("aws", Some("memorydb"), Some("delete-cluster"), ..) => resource(
            "aws",
            "memorydb",
            "cluster",
            2,
            &["--cluster-name"],
            &[],
            &["--final-snapshot-name", "--multi-region-cluster-name"],
            &[],
        ),
        ("gcloud", Some("sql"), Some("instances"), Some("delete"), _) => ResourceDelete {
            final_backup: Some("--enable-final-backup"),
            ..resource(
                "gcp",
                "sql",
                "instance",
                3,
                &[],
                &[],
                &[
                    "--final-backup-description",
                    "--final-backup-expiry-time",
                    "--final-backup-retention-days",
                ],
                &["--async", "--enable-final-backup"],
            )
        },
        ("gcloud", Some("sql"), Some("databases"), Some("delete"), _) => resource(
            "gcp",
            "sql",
            "database",
            3,
            &[],
            &[&["--instance", "-i"]],
            &[],
            &[],
        ),
        // An instance's users and certificates hold no data; each is named
        // inside its instance, never as the instance itself.
        ("gcloud", Some("sql"), Some("users"), Some("delete"), _) => resource(
            "gcp",
            "sql",
            "user",
            3,
            &[],
            &[&["--instance", "-i"]],
            &["--host"],
            &["--async"],
        ),
        ("gcloud", Some("sql"), Some("ssl-certs"), Some("delete"), _) => resource(
            "gcp",
            "sql",
            "ssl-cert",
            3,
            &[],
            &[&["--instance", "-i"]],
            &[],
            &["--async"],
        ),
        ("gcloud", Some("sql"), Some("ssl"), Some("client-certs"), Some("delete")) => resource(
            "gcp",
            "sql",
            "client-cert",
            4,
            &[],
            &[&["--instance", "-i"]],
            &[],
            &["--async"],
        ),
        ("gcloud", Some("spanner"), Some("instances"), Some("delete"), _) => {
            resource("gcp", "spanner", "instance", 3, &[], &[], &[], &[])
        }
        ("gcloud", Some("spanner"), Some("databases"), Some("delete"), _) => ResourceDelete {
            qualified: Qualified::Path(&["projects", "instances", "databases"]),
            ..resource(
                "gcp",
                "spanner",
                "database",
                3,
                &[],
                &[&["--instance"]],
                &[],
                &[],
            )
        },
        ("gcloud", Some("firestore"), Some("databases"), Some("delete"), _) => resource(
            "gcp",
            "firestore",
            "database",
            3,
            &["--database"],
            &[],
            &["--etag"],
            &[],
        ),
        // `cbt deleteinstance` names the same resource.
        ("gcloud", Some("bigtable"), Some("instances"), Some("delete"), _) => ResourceDelete {
            many: true,
            qualified: Qualified::Path(&["projects", "instances"]),
            ..resource("gcp", "bigtable", "instance", 3, &[], &[], &[], &[])
        },
        ("gcloud", Some("bigtable"), Some("tables"), Some("delete"), _) => ResourceDelete {
            qualified: Qualified::Path(&["projects", "instances", "tables"]),
            ..resource(
                "gcp",
                "bigtable",
                "table",
                3,
                &[],
                &[&["--instance"]],
                &[],
                &[],
            )
        },
        // --force also deletes the cluster's instances; without it the delete
        // fails while any remain.
        ("gcloud", Some("alloydb"), Some("clusters"), Some("delete"), _) => resource(
            "gcp",
            "alloydb",
            "cluster",
            3,
            &[],
            &[],
            &["--region"],
            &["--async", "--force"],
        ),
        ("gcloud", Some("redis"), Some("instances"), Some("delete"), _) => ResourceDelete {
            qualified: Qualified::Path(&["projects", "locations", "instances"]),
            ..resource(
                "gcp",
                "redis",
                "instance",
                3,
                &[],
                &[],
                &["--region"],
                &["--async"],
            )
        },
        ("gcloud", Some("redis"), Some("clusters"), Some("delete"), _) => ResourceDelete {
            qualified: Qualified::Path(&["projects", "locations", "clusters"]),
            ..resource(
                "gcp",
                "redis",
                "cluster",
                3,
                &[],
                &[],
                &["--region"],
                &["--async"],
            )
        },
        ("az", Some("sql"), Some("db"), Some("delete"), _) => resource(
            "azure",
            "sql",
            "database",
            3,
            &["--name", "-n"],
            &[&["--server", "-s"]],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("sql"), Some("mi"), Some("delete"), _) => resource(
            "azure",
            "sql",
            "managed-instance",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("sql"), Some("server"), Some("delete"), _) => resource(
            "azure",
            "sql",
            "server",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("cosmosdb"), Some("delete"), ..) => resource(
            "azure",
            "cosmosdb",
            "account",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("cosmosdb"), Some("table"), Some("delete"), _) => resource(
            "azure",
            "cosmosdb",
            "table",
            3,
            &["--name", "-n"],
            &[&["--account-name", "-a"]],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        (
            "az",
            Some("cosmosdb"),
            Some(api @ ("sql" | "mongodb" | "cassandra" | "gremlin")),
            Some(collection),
            Some("delete"),
        ) => {
            // Each API names its top-level container and the collection in it.
            const ACCOUNT: &[&[&str]] = &[&["--account-name", "-a"]];
            const DATABASE: &[&[&str]] = &[&["--account-name", "-a"], &["--database-name", "-d"]];
            const KEYSPACE: &[&[&str]] = &[&["--account-name", "-a"], &["--keyspace-name", "-k"]];
            let (kind, parents) = match (api, collection) {
                ("sql" | "mongodb" | "gremlin", "database") => ("database", ACCOUNT),
                ("cassandra", "keyspace") => ("keyspace", ACCOUNT),
                ("sql", "container") => ("container", DATABASE),
                ("mongodb", "collection") => ("collection", DATABASE),
                ("gremlin", "graph") => ("graph", DATABASE),
                ("cassandra", "table") => ("table", KEYSPACE),
                _ => return None,
            };
            resource(
                "azure",
                "cosmosdb",
                kind,
                4,
                &["--name", "-n"],
                parents,
                &["--resource-group", "-g"],
                &["--yes", "-y"],
            )
        }
        (
            "az",
            Some(service @ ("postgres" | "mysql")),
            Some("flexible-server"),
            Some("delete"),
            _,
        ) => resource(
            "azure",
            if service == "postgres" {
                "postgres"
            } else {
                "mysql"
            },
            "server",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        // MySQL names the database with --database-name, PostgreSQL with --name.
        ("az", Some("postgres"), Some("flexible-server"), Some("db"), Some("delete")) => resource(
            "azure",
            "postgres",
            "database",
            4,
            &["--name", "-n"],
            &[&["--server-name", "-s"]],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("mysql"), Some("flexible-server"), Some("db"), Some("delete")) => resource(
            "azure",
            "mysql",
            "database",
            4,
            &["--database-name", "-d"],
            &[&["--server-name", "-s"]],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("redis"), Some("delete"), ..) => resource(
            "azure",
            "redis",
            "cache",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        // Provisioned resources outside the managed databases. Each verb
        // deletes the one resource its identifier option or operand names.
        ("aws", Some("ec2"), Some(verb @ ("delete-vpc" | "delete-subnet")), ..) => resource(
            "aws",
            "ec2",
            if verb == "delete-vpc" {
                "vpc"
            } else {
                "subnet"
            },
            2,
            if verb == "delete-vpc" {
                &["--vpc-id"]
            } else {
                &["--subnet-id"]
            },
            &[],
            &[],
            &["--no-dry-run"],
        ),
        ("aws", Some("ec2"), Some("delete-security-group"), ..) => resource(
            "aws",
            "ec2",
            "security-group",
            2,
            &["--group-id", "--group-name"],
            &[],
            &[],
            &["--no-dry-run"],
        ),
        ("aws", Some("eks"), Some("delete-cluster"), ..) => {
            resource("aws", "eks", "cluster", 2, &["--name"], &[], &[], &[])
        }
        ("aws", Some("efs"), Some("delete-file-system"), ..) => resource(
            "aws",
            "efs",
            "file-system",
            2,
            &["--file-system-id"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("kinesis"), Some("delete-stream"), ..) => resource(
            "aws",
            "kinesis",
            "stream",
            2,
            &["--stream-name"],
            &[],
            &[],
            &[
                "--enforce-consumer-deletion",
                "--no-enforce-consumer-deletion",
            ],
        ),
        ("aws", Some("logs"), Some("delete-log-group"), ..) => ResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "logs",
                "log-group",
                2,
                &["--log-group-name"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("cloudtrail"), Some("delete-trail"), ..) => {
            resource("aws", "cloudtrail", "trail", 2, &["--name"], &[], &[], &[])
        }
        ("aws", Some("route53"), Some("delete-hosted-zone"), ..) => {
            resource("aws", "route53", "hosted-zone", 2, &["--id"], &[], &[], &[])
        }
        ("aws", Some("elbv2"), Some("delete-load-balancer"), ..) => ResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "elbv2",
                "load-balancer",
                2,
                &["--load-balancer-arn"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("cloudfront"), Some("delete-distribution"), ..) => resource(
            "aws",
            "cloudfront",
            "distribution",
            2,
            &["--id"],
            &[],
            &["--if-match"],
            &[],
        ),
        // A --qualifier deletes one version of the function, not the function.
        ("aws", Some("lambda"), Some("delete-function"), ..) => resource(
            "aws",
            "lambda",
            "function",
            2,
            &["--function-name"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("ecr"), Some("delete-repository"), ..) => ResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "ecr",
                "repository",
                2,
                &["--repository-name"],
                &[],
                &["--registry-id"],
                &["--force", "--no-force"],
            )
        },
        ("aws", Some("iam"), Some(verb @ ("delete-user" | "delete-role" | "delete-group")), ..) => {
            let (kind, flag): (&str, &'static [&'static str]) = match verb {
                "delete-user" => ("user", &["--user-name"]),
                "delete-role" => ("role", &["--role-name"]),
                _ => ("group", &["--group-name"]),
            };
            resource("aws", "iam", kind, 2, flag, &[], &[], &[])
        }
        // --retain-resources lists resources to keep and takes several values,
        // so it stays undocumented here.
        ("aws", Some("cloudformation"), Some("delete-stack"), ..) => ResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "cloudformation",
                "stack",
                2,
                &["--stack-name"],
                &[],
                &["--role-arn", "--client-request-token", "--deletion-mode"],
                &[],
            )
        },
        // --delete-disks and --keep-disks choose what happens to the attached
        // disks; the instances are deleted either way.
        ("gcloud", Some("compute"), Some("instances"), Some("delete"), _) => ResourceDelete {
            many: true,
            qualified: Qualified::Path(&["projects", "zones", "instances"]),
            ..resource(
                "gcp",
                "compute",
                "instance",
                3,
                &[],
                &[],
                &["--zone", "--delete-disks", "--keep-disks"],
                &[],
            )
        },
        (
            "gcloud",
            Some("compute"),
            Some(collection @ ("networks" | "firewall-rules")),
            Some("delete"),
            _,
        ) => ResourceDelete {
            many: true,
            ..resource(
                "gcp",
                "compute",
                if collection == "networks" {
                    "network"
                } else {
                    "firewall-rule"
                },
                3,
                &[],
                &[],
                &[],
                &[],
            )
        },
        ("gcloud", Some("container"), Some("clusters"), Some("delete"), _) => ResourceDelete {
            many: true,
            ..resource(
                "gcp",
                "container",
                "cluster",
                3,
                &[],
                &[],
                &["--zone", "-z", "--region", "--location"],
                &["--async"],
            )
        },
        ("gcloud", Some("dataproc"), Some("clusters"), Some("delete"), _) => resource(
            "gcp",
            "dataproc",
            "cluster",
            3,
            &[],
            &[],
            &["--region", "--graceful-decommission-timeout"],
            &["--async"],
        ),
        ("gcloud", Some("functions"), Some("delete"), ..) => resource(
            "gcp",
            "functions",
            "function",
            2,
            &[],
            &[],
            &["--region"],
            &["--gen2", "--no-gen2"],
        ),
        ("gcloud", Some("run"), Some("services"), Some("delete"), _) => resource(
            "gcp",
            "run",
            "service",
            3,
            &[],
            &[],
            &["--region"],
            &["--async"],
        ),
        ("gcloud", Some("dns"), Some("managed-zones"), Some("delete"), _) => {
            resource("gcp", "dns", "managed-zone", 3, &[], &[], &[], &[])
        }
        ("gcloud", Some("iam"), Some("service-accounts"), Some("delete"), _) => {
            resource("gcp", "iam", "service-account", 3, &[], &[], &[], &[])
        }
        ("gcloud", Some("projects"), Some("delete"), ..) => {
            resource("gcp", "projects", "project", 2, &[], &[], &[], &[])
        }
        // A resource group delete removes every resource in the group.
        ("az", Some("group"), Some("delete"), ..) => resource(
            "azure",
            "group",
            "resource-group",
            2,
            &["--name", "-n", "--resource-group", "-g"],
            &[],
            &["--force-deletion-types", "-f"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("vm"), Some("delete"), ..) => resource(
            "azure",
            "vm",
            "instance",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g", "--force-deletion"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("aks"), Some("delete"), ..) => resource(
            "azure",
            "aks",
            "cluster",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("acr"), Some("delete"), ..) => resource(
            "azure",
            "acr",
            "registry",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        // A --slot deletes one deployment slot, not the app.
        ("az", Some(service @ ("webapp" | "functionapp")), Some("delete"), ..) => resource(
            "azure",
            if service == "webapp" {
                "webapp"
            } else {
                "functionapp"
            },
            "app",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            if service == "webapp" {
                &[
                    "--keep-empty-plan",
                    "--keep-metrics",
                    "--keep-dns-registration",
                ]
            } else {
                &[]
            },
        ),
        ("az", Some("network"), Some("vnet"), Some("delete"), _) => resource(
            "azure",
            "network",
            "vnet",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--no-wait"],
        ),
        ("az", Some("network"), Some("dns"), Some("zone"), Some("delete")) => resource(
            "azure",
            "network",
            "dns-zone",
            4,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("ad"), Some(object @ ("sp" | "app")), Some("delete"), _) => resource(
            "azure",
            "ad",
            if object == "sp" {
                "service-principal"
            } else {
                "application"
            },
            3,
            &["--id"],
            &[],
            &[],
            &[],
        ),
        _ => return None,
    };
    (
        delete.common_values,
        delete.common_switches,
        delete.scope_values,
    ) = (common_values, common_switches, scope_values);
    // A command word that follows one of the verb's own value options is that
    // option's value (`aws rds --db-instance-identifier delete-db-instance`),
    // so the words do not name this verb.
    if delete.path.iter().any(|&index| {
        argv[index - 1]
            .as_literal()
            .is_some_and(|flag| delete.takes_value(flag))
    }) {
        return None;
    }
    Some(delete)
}

const AUTOMATED_BACKUP_SWITCHES: [&str; 2] = [
    "--delete-automated-backups",
    "--no-delete-automated-backups",
];

impl ResourceDelete {
    /// Every option this verb documents.
    fn options(&self) -> impl Iterator<Item = &'static str> + '_ {
        [
            self.common_values,
            self.common_switches,
            self.values,
            self.switches,
            self.id_flags,
            &AUTOMATED_BACKUP_SWITCHES,
        ]
        .into_iter()
        .chain(self.parents.iter().copied())
        .flatten()
        .copied()
        .chain(self.final_snapshot)
        .chain(
            self.skip_final
                .into_iter()
                .flat_map(|(skip, keep)| [skip, keep]),
        )
    }

    fn takes_value(&self, flag: &str) -> bool {
        [self.common_values, self.values, self.id_flags]
            .iter()
            .chain(self.parents)
            .any(|flags| flags.contains(&flag))
            || self.final_snapshot == Some(flag)
    }

    fn is_switch(&self, flag: &str) -> bool {
        self.common_switches.contains(&flag)
            || self.switches.contains(&flag)
            || self
                .skip_final
                .is_some_and(|(skip, keep)| flag == skip || flag == keep)
            || (matches!(self.backups, AutomatedBackups::Explicit)
                && AUTOMATED_BACKUP_SWITCHES.contains(&flag))
    }

    /// The command's options and operands around and between its command
    /// words, when every word is a literal this verb documents. The CLIs parse
    /// options wherever they appear, and a repeated option keeps its last
    /// value, as argparse's store actions do. An option the verb does not
    /// document may still be one the CLI accepts, so it is recorded and the
    /// words around it keep their reading; a scope option keeps its value.
    /// An expansion is read as one operand or value, [`UNSTATED`], that names
    /// a resource Nah cannot. gcloud's `--flags-file`, which supplies
    /// arguments Nah does not read, AWS's `--dry-run`, which these verbs do
    /// not support, or a value option without its value leaves the request
    /// unestablished.
    fn arguments<'a>(&self, argv: &'a [Word]) -> Option<DeleteArguments<'a>> {
        let indices: Vec<usize> = (1..argv.len())
            .filter(|index| !self.path.contains(index))
            .collect();
        let mut arguments = DeleteArguments::default();
        let mut position = 0;
        // The word after an undocumented option may be its value.
        let mut maybe_value = None;
        while let Some(&index) = indices.get(position) {
            position += 1;
            let word = argv[index].as_literal().unwrap_or(UNSTATED);
            // An expansion attached to a long option (`--name="$(…)"`) is
            // that option with a value Nah cannot read.
            let attached_expansion = argv[index]
                .as_literal()
                .is_none()
                .then(|| argv[index].literal_prefix().split_once('='))
                .flatten()
                .filter(|(flag, _)| flag.starts_with("--"))
                .map(|(flag, _)| flag);
            // argparse also reads a short value option's `-nVALUE` and
            // `-n=VALUE` as `-n VALUE`.
            let short = word.get(..2).filter(|flag| {
                !word.starts_with("--")
                    && word.len() > 2
                    && flag.starts_with('-')
                    && self.takes_value(flag)
            });
            let (flag, attached) = if let Some(flag) = attached_expansion {
                (flag, Some(UNSTATED))
            } else {
                match (short, word.split_once('=')) {
                    (Some(flag), _) => (
                        flag,
                        Some(word[2..].strip_prefix('=').unwrap_or(&word[2..])),
                    ),
                    (None, Some((flag, value))) if word.starts_with("--") => (flag, Some(value)),
                    _ => (word, None),
                }
            };
            if attached.is_none() && self.is_switch(flag) {
                arguments.switches.push(flag);
            } else if self.takes_value(flag) {
                let value = match attached {
                    Some(value) => value,
                    None => {
                        let next = *indices.get(position)?;
                        position += 1;
                        if next != index + 1 {
                            return None;
                        }
                        argv[next].as_literal().unwrap_or(UNSTATED)
                    }
                };
                if value.is_empty() || value.starts_with('-') {
                    return None;
                }
                arguments.values.push((flag, value));
            } else if flag == "--flags-file" || (self.provider == "aws" && flag == "--dry-run") {
                return None;
            } else if flag.starts_with('-') {
                arguments.unknown = true;
                if attached.is_none() && self.scope_values.contains(&flag) {
                    let next = *indices.get(position)?;
                    position += 1;
                    if next != index + 1 {
                        return None;
                    }
                } else if attached.is_none() {
                    maybe_value = Some(index + 1);
                }
            } else if maybe_value == Some(index) {
                arguments.ambiguous.push(word);
            } else {
                arguments.operands.push(word);
            }
        }
        Some(arguments)
    }
}

/// A name the invocation gives in a form Nah does not read: an expansion, or
/// a value the CLI reads from a file. No argv word is a NUL.
const UNSTATED: &str = "\0";

#[derive(Default)]
struct DeleteArguments<'a> {
    operands: Vec<&'a str>,
    values: Vec<(&'a str, &'a str)>,
    switches: Vec<&'a str>,
    /// Whether an option the verb does not document was given.
    unknown: bool,
    /// Operands that may instead be such an option's value; never a target.
    ambiguous: Vec<&'a str>,
}

impl DeleteArguments<'_> {
    /// The last value any of `flags` gave.
    fn value(&self, flags: &[&str]) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(flag, _)| flags.contains(flag))
            .map(|(_, value)| *value)
    }

    /// The boolean a switch pair sets, by its last occurrence: AWS registers
    /// `--x` and `--no-x` as store_true and store_false on one destination.
    fn switch(&self, (on, off): (&str, &str)) -> Option<bool> {
        self.switches.iter().rev().find_map(|flag| {
            (*flag == on)
                .then_some(true)
                .or((*flag == off).then_some(false))
        })
    }
}

/// How an AWS invocation's options shape its request, wherever they appear.
fn aws_request_shape(argv: &[Word]) -> Option<&'static str> {
    argv.iter()
        .skip(1)
        .filter_map(Word::as_literal)
        .find_map(
            |word| match word.split_once('=').map_or(word, |(flag, _)| flag) {
                "--generate-cli-skeleton" => Some("skeleton"),
                "--cli-input-json" | "--cli-input-yaml" => Some("input"),
                _ => None,
            },
        )
}

/// What an AWS invocation's `--cli-input-json` or `--cli-input-yaml` makes of
/// its request.
enum AwsInput {
    /// No request input, or skeleton generation, which sends no request.
    Absent,
    /// argv with the input option replaced by the options its keys stand for.
    Read {
        argv: Vec<Word>,
        provenance: Vec<Vec<ProvenanceRef>>,
    },
    /// Input Nah cannot read, or that the CLI rejects.
    Unreadable,
}

/// Reads an AWS invocation's request input and spells it as options. The CLI
/// adds each top-level key, an API parameter name, to the request unless the
/// command line already set that parameter
/// (`awscli/customizations/cliinput.py`), so each key becomes the option the
/// CLI derives from its name, spelled as the command line usually spells it,
/// and the operation models read it as they read any other option.
/// The CLI reads the input inline or from a `file://`/`fileb://` path; Nah
/// reads such a path when source observation serves it, or when it is
/// `/dev/stdin` and stdin is literal text. A bare `-` is not a path to the
/// CLI, and it rejects both options together.
fn aws_request_input(builder: &mut PlanBuilder, ctx: &InvocationCtx) -> AwsInput {
    use serde_json::Value;
    let mut options = Vec::new();
    for (index, word) in ctx.argv.iter().enumerate().skip(1) {
        let Some(text) = word.as_literal() else {
            continue;
        };
        match text
            .split_once('=')
            .map_or((text, None), |(flag, value)| (flag, Some(value)))
        {
            ("--generate-cli-skeleton", _) => return AwsInput::Absent,
            ("--cli-input-json" | "--cli-input-yaml", attached) => {
                options.push((index, attached, text.starts_with("--cli-input-yaml")));
            }
            _ => {}
        }
    }
    let (option, attached, yaml) = match options[..] {
        [] => return AwsInput::Absent,
        [option] => option,
        _ => return AwsInput::Unreadable,
    };
    let value_index = if attached.is_some() {
        option
    } else {
        option + 1
    };
    let Some(value) = attached.or_else(|| ctx.argv.get(value_index).and_then(Word::as_literal))
    else {
        return AwsInput::Unreadable;
    };
    let mut from_stdin = false;
    let text = match value
        .strip_prefix("file://")
        .or_else(|| value.strip_prefix("fileb://"))
    {
        None => value.to_string(),
        Some("/dev/stdin") => {
            from_stdin = true;
            match ctx.stdin_literal() {
                Some(text) => text.to_string(),
                None => return AwsInput::Unreadable,
            }
        }
        // The CLI expands `~` and environment variables in the path.
        Some(path) if path.is_empty() || path.contains(['~', '$']) => {
            return AwsInput::Unreadable;
        }
        Some(path) => {
            match ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput) {
                SourceResolution::Source { source, .. } => source,
                _ => return AwsInput::Unreadable,
            }
        }
    };
    let parsed = if yaml {
        match super::infrastructure::parse_data(builder, &text) {
            Ok(mut documents) if documents.len() == 1 => documents.pop(),
            _ => None,
        }
    } else {
        serde_json::from_str::<Value>(&text).ok()
    };
    let Some(Value::Object(input)) = parsed else {
        return AwsInput::Unreadable;
    };
    let explicit = |name: &str| {
        ctx.argv.iter().filter_map(Word::as_literal).any(|word| {
            word.split_once('=')
                .map_or(word, |(flag, _)| flag)
                .strip_prefix("--")
                .is_some_and(|flag| flag == name || flag.strip_prefix("no-") == Some(name))
        })
    };
    let mut argv = Vec::new();
    let mut provenance = Vec::new();
    for index in (0..ctx.argv.len()).filter(|index| *index != option && *index != value_index) {
        argv.push(ctx.argv[index].clone());
        provenance.push(ctx.argv_provenance_at(builder, index));
    }
    let mut source = ctx.argv_provenance_at(builder, value_index);
    if value_index != option {
        source.extend(ctx.argv_provenance_at(builder, option));
    }
    if from_stdin && let Some(stdin) = ctx.stdin {
        source.extend(stdin.provenance.iter().copied());
    }
    for (key, value) in &input {
        let name = aws_option_name(key);
        if explicit(&name) {
            continue;
        }
        // A list of plain values is spelled as the words after its option;
        // anything else as the JSON the CLI also accepts for a parameter.
        let list = match value {
            Value::Array(items) if !items.is_empty() => items
                .iter()
                .map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    Value::Number(number) => Some(number.to_string()),
                    _ => None,
                })
                .map(|item| item.filter(|item| !item.is_empty() && !item.starts_with('-')))
                .collect::<Option<Vec<_>>>(),
            _ => None,
        };
        let words = match (value, list) {
            (_, Some(items)) => std::iter::once(format!("--{name}")).chain(items).collect(),
            (Value::Bool(true), _) => vec![format!("--{name}")],
            (Value::Bool(false), _) => vec![format!("--no-{name}")],
            (Value::Null, _) => return AwsInput::Unreadable,
            // The option and its value are two words, as usually written;
            // the CLI needs `=` for a value that starts with `-`.
            (value, _) => {
                let text = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                if text.is_empty() || text.starts_with('-') {
                    vec![format!("--{name}={text}")]
                } else {
                    vec![format!("--{name}"), text]
                }
            }
        };
        for word in words {
            argv.push(Word::literal(word));
            provenance.push(source.clone());
        }
    }
    AwsInput::Read { argv, provenance }
}

/// The option the AWS CLI derives from an API parameter name, as botocore's
/// `xform_name(name, "-")`: `SecretId` is `secret-id`,
/// `DBInstanceIdentifier` is `db-instance-identifier` and `TargetARNs` is
/// `target-arns`.
fn aws_option_name(name: &str) -> String {
    if name.contains('-') {
        return name.to_string();
    }
    let mut chars = name.chars().collect::<Vec<_>>();
    // A trailing plural acronym is split off whole.
    if chars.last() == Some(&'s') {
        let start = chars[..chars.len() - 1]
            .iter()
            .rposition(|c| !c.is_ascii_uppercase())
            .map_or(0, |index| index + 1);
        if chars.len() - 1 - start >= 2 {
            let tail = chars.split_off(start);
            chars.push('-');
            chars.extend(tail.iter().map(char::to_ascii_lowercase));
        }
    }
    // `(.)([A-Z][a-z]+)`, then `([a-z0-9])([A-Z])`, each replaced left to
    // right with a `-` between the groups.
    let mut first = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        first.push(chars[index]);
        if chars.get(index + 1).is_some_and(char::is_ascii_uppercase)
            && chars.get(index + 2).is_some_and(char::is_ascii_lowercase)
        {
            first.push('-');
            first.push(chars[index + 1]);
            index += 2;
            while chars.get(index).is_some_and(char::is_ascii_lowercase) {
                first.push(chars[index]);
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    let mut name = String::new();
    let mut index = 0;
    while index < first.len() {
        name.push(first[index]);
        if (first[index].is_ascii_lowercase() || first[index].is_ascii_digit())
            && first.get(index + 1).is_some_and(char::is_ascii_uppercase)
        {
            name.push('-');
            name.push(first[index + 1]);
            index += 2;
        } else {
            index += 1;
        }
    }
    name.to_ascii_lowercase()
}

/// A reviewed cloud resource delete. A managed-database delete also records
/// whether a final snapshot is taken and whether automated backups outlive the resource, where
/// the options and the vendor's documentation establish them. Without an
/// established request the verb keeps its earlier handling: RDS instance
/// deletion and gcloud's SQL chain still emit their delete, the other verbs a
/// boundary. AWS skeleton generation sends no request at all.
fn resource_delete_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    delete: &ResourceDelete,
) {
    let shape = (delete.provider == "aws")
        .then(|| aws_request_shape(ctx.argv))
        .flatten();
    if shape == Some("skeleton") {
        environment_boundary(
            builder,
            model_node,
            BoundaryReason::REVIEWED_COMMAND_SURFACE,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "AWS CLI skeleton generation prints a request template and sends no request",
        );
        return;
    }
    // Readable input was expanded into options before dispatch; `Aws::apply`
    // records the boundary for input it could not read.
    let arguments = if shape == Some("input") {
        None
    } else {
        delete.arguments(ctx.argv)
    };
    let ids = arguments.as_ref().and_then(|arguments| {
        if delete.id_flags.is_empty() {
            match arguments.operands[..] {
                [id] => Some(vec![id]),
                [_, _, ..] if delete.many => Some(arguments.operands.clone()),
                _ => None,
            }
        } else if arguments.operands.is_empty() {
            arguments.value(delete.id_flags).map(|id| vec![id])
        } else {
            None
        }
    });
    let containers: Vec<Option<&str>> = arguments.as_ref().map_or_else(Vec::new, |arguments| {
        delete
            .parents
            .iter()
            .map(|flags| arguments.value(flags))
            .collect()
    });
    let qualified = |id: &str| delete.qualified.matches(id);
    // A name the CLI reads from a file is one Nah does not read. Snapshot and
    // backup verbs keep their literal reading.
    let from_file = |name: &&str| {
        (delete.strict_names || delete.skip_final.is_some())
            && match delete.provider {
                "aws" => name.starts_with("file://") || name.starts_with("fileb://"),
                "azure" => name.starts_with('@'),
                _ => false,
            }
    };
    let read_from_file = ids
        .iter()
        .flatten()
        .chain(containers.iter().flatten())
        .any(from_file);
    let ids = ids.map(|ids| {
        ids.into_iter()
            .map(|name| if from_file(&name) { UNSTATED } else { name })
            .collect::<Vec<_>>()
    });
    let containers: Vec<Option<&str>> = containers
        .into_iter()
        .map(|name| name.map(|name| if from_file(&name) { UNSTATED } else { name }))
        .collect();
    let ids = ids.filter(|ids| {
        if !delete.strict_names {
            return true;
        }
        // A `/` that does not form the vendor's fully qualified operand is not
        // a name Nah can place.
        ids.iter()
            .all(|id| !id.contains('/') || qualified(id) || delete.slash_names)
            && containers.iter().flatten().all(|name| !name.contains('/'))
    });
    let (Some(arguments), Some(ids)) = (arguments.as_ref(), ids) else {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "cloud resource delete options or identifier are unresolved",
        );
        match (delete.service, delete.kind) {
            ("rds", "db") => delete_by_flag(
                builder,
                ctx,
                model_node,
                "aws",
                "rds",
                "db",
                "--db-instance-identifier",
            ),
            ("sql", _) if delete.provider == "gcp" => cloud_effect(
                builder,
                ctx,
                model_node,
                *delete.path.last().unwrap() as u32,
                "cloud.resource.delete",
                symbolic_cloud(),
            ),
            _ => {}
        }
        return;
    };
    if arguments.unknown {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "cloud resource delete options or identifier are unresolved",
        );
    }
    if delete
        .keeps_data
        .is_some_and(|pair| arguments.switch(pair) == Some(true))
    {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "the request keeps the resource's data and deletes only its replicas",
        );
        return;
    }
    let mut attributes = std::collections::BTreeMap::new();
    if let (Some(pair), Some(final_snapshot)) = (delete.skip_final, delete.final_snapshot) {
        let skipped = arguments.switch(pair) == Some(true);
        let named = arguments.value(&[final_snapshot]).is_some();
        // Skipping while naming the final snapshot is a request error, and
        // naming neither is one for a standalone instance or cluster. An Aurora
        // cluster member takes neither, so the request says nothing about
        // backups then.
        if skipped == named {
            boundary(
                builder,
                model_node,
                BoundaryReason::PARTIAL_ANALYSIS,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "managed-database final snapshot choice is not established",
            );
        } else {
            attributes.insert("final_snapshot".to_string(), AttrValue::Bool(!skipped));
            let retained = match delete.backups {
                AutomatedBackups::Removed => Some(false),
                AutomatedBackups::Explicit => arguments
                    .switch(AUTOMATED_BACKUP_SWITCHES.into())
                    .map(|remove| !remove),
                AutomatedBackups::NotApplicable => None,
            };
            match retained {
                Some(retained) => {
                    attributes.insert(
                        "automated_backups_retained".to_string(),
                        AttrValue::Bool(retained),
                    );
                }
                None => environment_boundary(
                    builder,
                    model_node,
                    BoundaryReason::LIVE_INVENTORY,
                    BoundaryClass::Unmodeled,
                    &["cloud", "network"],
                    "automated-backup retention depends on cluster membership or account backup policy",
                ),
            }
        }
    }
    if let Some(flag) = delete.final_backup
        && arguments.switches.contains(&flag)
    {
        attributes.insert("final_backup".to_string(), AttrValue::Bool(true));
    }
    // The resource ID is its containing resources' names and its own, joined
    // by `/`. A fully qualified operand is the whole ID; the containers it
    // names replace any given separately. A container the CLI takes from its
    // configuration is left out of the ID.
    if containers.contains(&None) && !ids.iter().all(|id| qualified(id)) {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "the containing resource is not named in the arguments",
        );
    }
    let names = || ids.iter().chain(containers.iter().flatten());
    if names().any(|name| *name == UNSTATED) {
        builder.boundary(Boundary {
            reason: if read_from_file {
                BoundaryReason::INPUT_DETERMINED_ARGUMENTS
            } else {
                BoundaryReason::PARTIAL_ANALYSIS
            },
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("cloud"), Domain::new("network")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(if read_from_file {
                "the CLI reads the resource name from a file Nah does not read".into()
            } else {
                "the cloud resource name is an expansion".into()
            }),
        });
    }
    // Every word is one this verb documents and every name is literal, so the
    // request is the one argv states: help, dry runs and unread input never
    // reach here, and an undocumented option may change what it selects.
    let request_assurance = if !arguments.unknown
        && arguments.ambiguous.is_empty()
        && !names().any(|name| *name == UNSTATED)
        && (!containers.contains(&None) || ids.iter().all(|id| qualified(id)))
    {
        effinterp_proto::RequestAssurance::Exact
    } else {
        effinterp_proto::RequestAssurance::Conservative
    };
    for id in ids {
        // The request names one resource of this kind whatever its name.
        let id = if id == UNSTATED
            || !qualified(id) && containers.iter().flatten().any(|name| *name == UNSTATED)
        {
            None
        } else if qualified(id) {
            Some(id.to_string())
        } else {
            Some(
                containers
                    .iter()
                    .flatten()
                    .copied()
                    .chain([id])
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        };
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(effinterp_proto::cloud_scope(
                    Some(delete.provider),
                    delete.service,
                    delete.kind,
                )),
                provider: Some(delete.provider.into()),
                service: delete.service.into(),
                kind: delete.kind.into(),
                id,
            },
        };
        cloud_request_effect(
            builder,
            ctx,
            model_node,
            *delete.path.last().unwrap() as u32,
            "cloud.resource.delete",
            resource,
            false,
            false,
            true,
            attributes.clone(),
            None,
            request_assurance,
        );
    }
}

/// Whether the command group is `secrets`, on the GA, alpha or beta track.
/// Global flags may sit on either side of the track.
fn gcloud_secrets_group(argv: &[Word]) -> bool {
    let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
    let group = |start: usize| {
        argv.get(start..).and_then(|rest| {
            rest.get(crate::models::scope::command_position(
                rest,
                CLOUD_SCOPE_FLAGS,
            ))
            .and_then(Word::as_literal)
        })
    };
    match argv.get(command).and_then(Word::as_literal) {
        Some("secrets") => true,
        Some("alpha" | "beta") => group(command) == Some("secrets"),
        _ => false,
    }
}

/// The argv index of a Cloud SQL backup restore's verb, on any track. A
/// restore replaces the data of the existing instance it restores to, which
/// `sql backups restore` names with its required --restore-instance and
/// `sql instances restore-backup` as its operand beside the required
/// --backup-id. The db family has no Cloud SQL instance identity, so the
/// overwritten data stays unresolved.
fn gcloud_sql_restore(argv: &[Word]) -> Option<usize> {
    let global_values: Vec<&str> = GCLOUD_COMMON_VALUES
        .iter()
        .chain(CLOUD_SCOPE_FLAGS)
        .copied()
        .collect();
    let words: Vec<usize> = crate::models::args::scan_detached(
        argv,
        &FlagSpec {
            value_flags: &global_values,
            known_flags: &[],
            allow_abbreviation: false,
        },
        false,
    )
    .operands
    .iter()
    .map(|(index, _)| *index as usize)
    .collect();
    let at = |offset: usize| {
        words
            .get(offset)
            .and_then(|&index| argv[index].as_literal())
    };
    let track = usize::from(matches!(at(0), Some("alpha" | "beta")));
    let required = match (at(track), at(track + 1), at(track + 2)) {
        (Some("sql"), Some("backups"), Some("restore")) => "--restore-instance",
        (Some("sql"), Some("instances"), Some("restore-backup")) => "--backup-id",
        _ => return None,
    };
    // An attached value may be an expansion (`--restore-instance="$X"`).
    let given = |flag: &str| {
        argv.iter().any(|word| {
            word.as_literal() == Some(flag)
                || word
                    .literal_prefix()
                    .strip_prefix(flag)
                    .is_some_and(|rest| rest.starts_with('='))
        })
    };
    (given(required) && !given("--help") && !given("-h")).then(|| words[track + 2])
}

struct Gcloud;

impl CommandModel for Gcloud {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/gcloud@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["gcloud"]
    }
    // `gcloud secrets versions access` prints the value it reads.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        if gcloud_secrets_group(argv) {
            super::credential::read_output(false)
        } else {
            transfer_stdin_upload(argv)
        }
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_literal_flags(ctx.argv, &FLAGS);
        if gcloud_secrets_group(ctx.argv) {
            let covered = super::credential::gcloud_secrets(builder, ctx, model_node);
            declare_common(builder, ctx, model_node, covered);
            return;
        }
        declare_common(builder, ctx, model_node, false);
        // `--help` or `-h` anywhere before `--` prints the command's help and
        // runs nothing else.
        let help = ctx
            .argv
            .iter()
            .skip(1)
            .take_while(|word| word.as_literal() != Some("--"))
            .any(|word| matches!(word.as_literal(), Some("--help" | "-h")));
        if help || ctx.argv.get(1).and_then(Word::as_literal) == Some("--version") {
            return;
        }
        if let Some(delete) = resource_delete(ctx.argv) {
            resource_delete_effect(builder, ctx, model_node, &delete);
            return;
        }
        if let Some(verb) = gcloud_sql_restore(ctx.argv) {
            object_effect(
                builder,
                ctx,
                model_node,
                verb as u32,
                "database.write",
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new("db"),
                },
                false,
                false,
                true,
                Attrs::from([("action".into(), AttrValue::String("overwrite".into()))]),
            );
            return;
        }
        let argv = ctx.argv;
        let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
        let group = argv.get(command).and_then(Word::as_literal);
        match group {
            // `gcloud storage cp|mv` recurse with -r, -R or --recursive.
            Some("storage")
                if matches!(
                    argv.get(command + 1).and_then(Word::as_literal),
                    Some("cp" | "mv")
                ) =>
            {
                transfer_pair(
                    builder,
                    ctx,
                    model_node,
                    command + 2,
                    false,
                    scanned.has(&["--recursive"]) || short_option(argv, command + 2, &['r', 'R']),
                );
            }
            // Without -r, rsync still uploads the source's top-level files, so
            // its read covers the whole directory.
            Some("storage")
                if argv.get(command + 1).and_then(Word::as_literal) == Some("rsync") =>
            {
                transfer_pair(
                    builder,
                    ctx,
                    model_node,
                    command + 2,
                    scanned.has(&["--delete-unmatched-destination-objects"]),
                    true,
                );
            }
            Some("storage") => {
                if argv.get(command + 1).and_then(Word::as_literal) == Some("buckets")
                    && argv.get(command + 2).and_then(Word::as_literal) == Some("delete")
                {
                    for (index, target) in operands(argv, command + 3) {
                        object_effect(
                            builder,
                            ctx,
                            model_node,
                            index,
                            "cloud.object.delete",
                            object_target(target).unwrap_or_else(symbolic_cloud),
                            false,
                            false,
                            true,
                            Default::default(),
                        );
                    }
                } else if argv.get(command + 1).and_then(Word::as_literal) == Some("rm") {
                    // `gcloud storage rm` spells its recursion -r, -R or
                    // --recursive; without it a prefix keeps its objects.
                    let recursive = scanned.has(&["--recursive"])
                        || short_option(argv, command + 2, &['r', 'R']);
                    for (i, w) in operands(
                        argv,
                        crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS) + 2,
                    ) {
                        if let Some(r) = object_target(w) {
                            object_effect(
                                builder,
                                ctx,
                                model_node,
                                i,
                                "cloud.object.delete",
                                r,
                                recursive,
                                false,
                                true,
                                Default::default(),
                            );
                        } else {
                            object_effect(
                                builder,
                                ctx,
                                model_node,
                                i,
                                "cloud.object.delete",
                                symbolic_cloud(),
                                false,
                                false,
                                true,
                                Default::default(),
                            );
                        }
                    }
                } else {
                    boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "gcloud storage subcommand",
                    );
                }
            }
            Some("compute") => {
                if argv.get(command + 1).and_then(Word::as_literal) == Some("ssh") {
                    gcloud_ssh(builder, ctx, model_node, Some(3), 4, None);
                } else {
                    let collection = argv
                        .get(command + 1)
                        .and_then(Word::as_literal)
                        .unwrap_or("unknown-subtype");
                    let kind = if collection == "instances" {
                        "instance"
                    } else {
                        collection
                    };
                    resource_delete_chain(builder, ctx, model_node, "gcp", "compute", kind)
                }
            }
            Some("cloud-shell")
                if argv.get(command + 1).and_then(Word::as_literal) == Some("ssh") =>
            {
                gcloud_ssh(builder, ctx, model_node, None, 3, Some("cloud-shell"));
            }
            // Cloud SQL's documented deletes are `resource_delete`'s. Any other
            // `delete` word names no resource Nah can place, so it keeps an
            // unresolved delete.
            Some("sql") => match argv.iter().position(|w| w.as_literal() == Some("delete")) {
                Some(pos) => {
                    boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "gcloud sql delete outside its documented verbs",
                    );
                    cloud_effect(
                        builder,
                        ctx,
                        model_node,
                        pos as u32,
                        "cloud.resource.delete",
                        symbolic_cloud(),
                    );
                }
                None => boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBCOMMAND,
                    BoundaryClass::Unmodeled,
                    &["cloud", "network"],
                    "gcloud non-delete verb",
                ),
            },
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "gcloud group",
            ),
        }
    }
}

fn gcloud_ssh(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    instance_index: Option<usize>,
    options_start: usize,
    fixed_instance: Option<&str>,
) {
    let instance = match (
        fixed_instance,
        instance_index.and_then(|index| ctx.argv.get(index)),
    ) {
        (Some(instance), _) => instance.to_string(),
        (None, Some(instance)) => instance
            .render_raw()
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_string(),
        (None, None) => return,
    };
    let connect_index = instance_index.unwrap_or(2) as u32;
    cloud_effect(
        builder,
        ctx,
        model_node,
        connect_index,
        "network.connect",
        unresolved_network(),
    );

    const VALUE_FLAGS: &[&str] = &[
        "--zone",
        "--project",
        "--command",
        "--ssh-flag",
        "--ssh-key-file",
        "--strict-host-key-checking",
    ];
    const BOOLEAN_FLAGS: &[&str] = &[
        "--tunnel-through-iap",
        "--internal-ip",
        "--plain",
        "--dry-run",
    ];
    let mut command = None;
    let mut trailing = None;
    let mut unknown = Vec::new();
    let mut index = options_start;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        match word.as_literal() {
            Some("--command") => {
                if let Some(value) = ctx.argv.get(index + 1) {
                    command = Some((index + 1, vec![value.clone()]));
                    index += 2;
                } else {
                    unknown.push((index as u32, "--command".to_string()));
                    index += 1;
                }
            }
            Some("--") => {
                trailing = Some(index + 1);
                break;
            }
            Some(flag) if VALUE_FLAGS.contains(&flag) => index += 2,
            Some(flag) if BOOLEAN_FLAGS.contains(&flag) => index += 1,
            Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                if let Some(value) = attached_value(word, "--command=") {
                    command = Some((index, vec![value]));
                } else if !VALUE_FLAGS
                    .iter()
                    .any(|known| flag.starts_with(&format!("{known}=")))
                {
                    unknown.push((index as u32, flag.to_string()));
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    unrecognized_arguments_boundary(
        builder,
        model_node,
        &["cloud", "network", "process"],
        &unknown,
    );
    let (source_index, words) = if let Some(command) = command {
        command
    } else if let Some(start) = trailing {
        (start, ctx.argv[start..].to_vec())
    } else {
        return;
    };
    if words.is_empty() {
        return;
    }
    let argument = arg_node(builder, ctx, source_index as u32);
    if words.iter().any(has_unknown) {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "gcloud remote command is not statically recoverable",
        );
        return;
    }
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        words
            .iter()
            .map(Word::render_raw)
            .collect::<Vec<_>>()
            .join(" "),
        format!("gce:{instance}"),
    );
}

/// gcloud `<group> <kind...> delete NAME`: find `delete` then the name operand.
fn resource_delete_chain(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    provider: &str,
    service: &str,
    kind: &str,
) {
    let argv = ctx.argv;
    let Some(pos) = argv.iter().position(|w| w.as_literal() == Some("delete")) else {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "gcloud non-delete verb",
        );
        return;
    };
    match operands(argv, pos + 1).first() {
        Some((i, w)) if w.as_literal().is_some() => {
            let r = ResourceExpr::Concrete {
                identity: ResourceIdentity::CloudResource {
                    scope: Box::new(effinterp_proto::cloud_scope(Some(provider), service, kind)),
                    provider: Some(provider.into()),
                    service: service.into(),
                    kind: kind.into(),
                    id: Some(w.as_literal().unwrap().to_string()),
                },
            };
            cloud_effect(builder, ctx, model_node, *i, "cloud.resource.delete", r);
        }
        _ => cloud_effect(
            builder,
            ctx,
            model_node,
            pos as u32,
            "cloud.resource.delete",
            symbolic_cloud(),
        ),
    }
}

struct Gsutil;

impl CommandModel for Gsutil {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/gsutil@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["gsutil"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        transfer_stdin_upload(argv)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_common(builder, ctx, model_node, false);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        let argv = ctx.argv;
        // gsutil takes its own options before the subcommand (`gsutil -m rm`).
        let command = crate::models::scope::command_position(argv, GSUTIL_GLOBAL_FLAGS);
        let sub = argv.get(command).and_then(Word::as_literal);
        match sub {
            Some("rb") => {
                for (index, target) in operands(argv, command + 1) {
                    object_effect(
                        builder,
                        ctx,
                        model_node,
                        index,
                        "cloud.object.delete",
                        object_target(target).unwrap_or_else(symbolic_cloud),
                        false,
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
            Some("rm") => {
                for (i, w) in operands(argv, command + 1) {
                    if let Some(r) = object_target(w) {
                        object_effect(
                            builder,
                            ctx,
                            model_node,
                            i,
                            "cloud.object.delete",
                            r,
                            short_option(argv, command + 1, &['r', 'R']),
                            false,
                            true,
                            Default::default(),
                        );
                    } else {
                        object_effect(
                            builder,
                            ctx,
                            model_node,
                            i,
                            "cloud.object.delete",
                            symbolic_cloud(),
                            false,
                            false,
                            true,
                            Default::default(),
                        );
                    }
                }
            }
            Some("cp") | Some("mv") => transfer_pair(
                builder,
                ctx,
                model_node,
                command + 1,
                false,
                short_option(argv, command + 1, &['r', 'R']),
            ),
            // Without -r, rsync still uploads the source's top-level files, so
            // its read covers the whole directory.
            Some("rsync") => transfer_pair(
                builder,
                ctx,
                model_node,
                command + 1,
                short_option(argv, command + 1, &['d']),
                true,
            ),
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "gsutil subcommand",
            ),
        }
    }
}

/// gsutil options taking a separate value, so the verb after them is found.
const GSUTIL_GLOBAL_FLAGS: &[&str] = &["-h", "-o", "-u", "-i"];

/// gsutil subcommand options are clustered single-dash letters (`rsync -dr`),
/// so a letter counts as present anywhere in such a word.
fn short_option(argv: &[Word], start: usize, letters: &[char]) -> bool {
    argv.iter().skip(start).any(|word| {
        word.as_literal().is_some_and(|text| {
            text.starts_with('-')
                && !text.starts_with("--")
                && text[1..].chars().any(|letter| letters.contains(&letter))
        })
    })
}

struct Az;

impl CommandModel for Az {
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
        super::credential::read_output(
            at(2) == Some("download") && !super::credential::az_download_to_stdout(argv),
        )
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_literal_flags(ctx.argv, &FLAGS);
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
            let covered = super::credential::az_keyvault(builder, ctx, model_node);
            declare_common(builder, ctx, model_node, covered);
            return;
        }
        declare_common(builder, ctx, model_node, false);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        if let Some(delete) = resource_delete(ctx.argv) {
            resource_delete_effect(builder, ctx, model_node, &delete);
            return;
        }
        let argv = ctx.argv;
        let group = at(0);
        let verb = at(1);
        match (group, verb) {
            // Deleting a container removes every blob inside it; deleting the
            // account removes the account resource and all of its containers.
            (Some("storage"), Some("container")) if at(2) == Some("delete") => {
                object_effect(
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
                object_effect(
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
                        object_effect(
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
                        let destination = object_upload_effect(
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
                                object_target(value).unwrap_or_else(|| az_object_target(&[value]))
                            })
                            .unwrap_or_else(symbolic_cloud);
                        let destination = object_upload_effect(
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
                        let source = object_effect(
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

fn az_vm_run_command(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &FLAGS);
    if scanned
        .values_of(&["--command-id"])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
        != Some("RunShellScript")
    {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "az vm run-command command id",
        );
        return;
    }
    let Some((_, name)) = scanned.values_of(&["--name", "-n"]).first().copied() else {
        return;
    };
    let argument = arg_node(builder, ctx, 3);
    cloud_network_effect(
        builder,
        ctx,
        &[model_node, argument],
        &symbolic_cloud(),
        "network.connect",
    );
    let mut scripts = Vec::new();
    let mut index = 4;
    while index < ctx.argv.len() {
        if ctx.argv[index].as_literal() != Some("--scripts") {
            index += 1;
            continue;
        }
        index += 1;
        while index < ctx.argv.len()
            && !ctx.argv[index]
                .as_literal()
                .is_some_and(|value| value.starts_with('-'))
        {
            scripts.push((index, &ctx.argv[index]));
            index += 1;
        }
    }
    let Some((script_index, _)) = scripts.first() else {
        return;
    };
    let argument = arg_node(builder, ctx, *script_index as u32);
    if scripts.iter().any(|(_, script)| has_unknown(script)) {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "az vm run-command source is not statically recoverable",
        );
        return;
    }
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        scripts
            .iter()
            .map(|(_, script)| script.render_raw())
            .collect::<Vec<_>>()
            .join("\n"),
        format!("azure-vm:{}", name.render_raw()),
    );
}

fn az_blob_target(argv: &[Word]) -> ResourceExpr {
    let scanned = scan_literal_flags(argv, &FLAGS);
    if let Some(url) = scanned
        .values_of(&["--blob-url"])
        .first()
        .map(|(_, value)| *value)
    {
        return object_target(url).unwrap_or_else(symbolic_cloud);
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
    scan_literal_flags(argv, &FLAGS)
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
    object_target(&Word::new(parts)).unwrap_or_else(symbolic_cloud)
}

/// `az storage blob upload-batch --pattern` uploads only the files whose path,
/// joined under `--source` with the pattern's leading `/` removed, fnmatch
/// accepts, `*` crossing `/`. The `included_paths` attribute states that
/// relative glob when the command line is wholly literal and the pattern has
/// no bracket class, which the bridge does not read. The Azure CLI accepts
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
    (!pattern.is_empty() && !pattern.contains('[')).then(|| {
        AttrValue::String(serde_json::to_string(&[pattern]).expect("a list of strings serializes"))
    })
}

/// aws s3 matches each `--exclude`/`--include` pattern with fnmatch against a
/// file's path joined under the source directory, `*` crossing `/`, and the
/// last matching filter decides. Only exclusions over a wholly literal
/// command line prove a file is skipped: any include may add one back, and
/// so may an unread option, since aws accepts any unique prefix of an option
/// (`--inc`). The
/// `excluded_paths` attribute states those relative globs, less any with a
/// bracket class, which the bridge does not read; leaving one out only keeps
/// more files read.
fn aws_excluded_paths(ctx: &InvocationCtx, scanned: &Scanned) -> Option<AttrValue> {
    let filters = scanned
        .flags
        .iter()
        .filter(|flag| matches!(flag.name, "--exclude" | "--include"))
        .collect::<Vec<_>>();
    if !ctx.argv.iter().all(|word| word.as_literal().is_some())
        || !scanned.unknown_flags.is_empty()
        || filters.iter().any(|flag| flag.name == "--include")
    {
        return None;
    }
    let patterns = filters
        .iter()
        .filter_map(|flag| flag.value.as_ref()?.as_literal())
        .filter(|pattern| !pattern.is_empty() && !pattern.contains('['))
        .collect::<std::collections::BTreeSet<_>>();
    (!patterns.is_empty()).then(|| {
        AttrValue::String(serde_json::to_string(&patterns).expect("a list of strings serializes"))
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

/// Azure CLI global arguments that take a value.
const AZ_GLOBAL_VALUE_FLAGS: &[&str] = &["--subscription", "--output", "-o", "--query"];

const CLOUD_SCOPE_FLAGS: &[&str] = &[
    "--region",
    "--endpoint-url",
    "--profile",
    "--project",
    "--zone",
    "--subscription",
    "--resource-group",
    "-g",
    "--account-name",
    "--configuration",
    "--flags-file",
];

fn apply_cloud_scope(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    resource: &mut ResourceExpr,
) {
    use crate::models::scope::{access_value, endpoint_evidence, scope_boundary, scope_option};
    use effinterp_proto::{ScopeDimension as D, ScopeEvidenceKind as E, ScopeValue as V};
    if let ResourceExpr::Join { parts }
    | ResourceExpr::Union {
        alternatives: parts,
    } = resource
    {
        for part in parts {
            apply_cloud_scope(builder, ctx, provenance, part);
        }
        return;
    }
    let ResourceExpr::Concrete { identity } = resource else {
        return;
    };
    let provider = match identity {
        ResourceIdentity::ObjectStore { provider, .. }
        | ResourceIdentity::CloudResource { provider, .. } => provider.clone(),
        _ => return,
    };
    let scope = identity.scope_mut().unwrap();
    match provider.as_deref() {
        Some("aws") => {
            let region = scope_option(builder, ctx, provenance, &["--region"], true, "cloud")
                .or_else(|| cloud_environment(builder, ctx, provenance, "AWS_REGION").map(V::value))
                .or_else(|| {
                    cloud_environment(builder, ctx, provenance, "AWS_DEFAULT_REGION").map(V::value)
                });
            if let Some(region) = region {
                access_value(scope, E::RequestRegion, region.clone());
                if scope.kind == effinterp_proto::NamespaceKind::AwsRegional {
                    scope.identity.insert(D::Region, region);
                }
            }
            if let Some(profile) =
                scope_option(builder, ctx, provenance, &["--profile"], true, "cloud")
            {
                access_value(scope, E::Profile, profile);
            }
            if let Some(endpoint) =
                scope_option(builder, ctx, provenance, &["--endpoint-url"], true, "cloud")
            {
                endpoint_evidence(scope, E::Endpoint, endpoint);
            } else {
                for name in [
                    "AWS_ENDPOINT_URL",
                    "AWS_ENDPOINT_URL_S3",
                    "AWS_ENDPOINT_URL_EC2",
                    "AWS_ENDPOINT_URL_RDS",
                ] {
                    if let Some(endpoint) = cloud_environment(builder, ctx, provenance, name) {
                        endpoint_evidence(scope, E::Endpoint, V::value(endpoint));
                        scope_boundary(builder, provenance, "cloud");
                    }
                }
            }
            if let Some(config) = cloud_environment(builder, ctx, provenance, "AWS_CONFIG_FILE") {
                access_value(scope, E::ConfigurationFile, V::value(config));
                scope_boundary(builder, provenance, "cloud");
            }
        }
        Some("gcp") => {
            for (flag, dimension) in [
                ("--project", D::Project),
                ("--zone", D::Zone),
                ("--region", D::Region),
            ] {
                if let Some(value) = scope_option(builder, ctx, provenance, &[flag], true, "cloud")
                    && !matches!(scope.identity.get(&dimension), Some(V::NotApplicable))
                {
                    scope.identity.insert(dimension, value);
                }
            }
            for flag in ["--configuration", "--flags-file"] {
                if let Some(value) = scope_option(builder, ctx, provenance, &[flag], true, "cloud")
                {
                    access_value(scope, E::ConfigurationFile, value);
                    scope_boundary(builder, provenance, "cloud");
                }
            }
        }
        Some("azure") => {
            // Azure CLI reads an `@file` value from that file. The managed-
            // database deletes W1d added leave such a scope unresolved; DB-BAK's
            // verbs keep their literal reading.
            let strict_names = resource_delete(ctx.argv).is_some_and(|delete| delete.strict_names);
            for (flags, dimension) in [
                (&["--subscription"][..], D::Subscription),
                (&["--resource-group", "-g"][..], D::ResourceGroup),
                (&["--account-name"][..], D::StorageAccount),
            ] {
                if let Some(value) = scope_option(builder, ctx, provenance, flags, true, "cloud") {
                    if strict_names
                        && matches!(&value, V::Value(v) if matches!(v.as_ref(), ResourceExpr::Literal { value } if value.starts_with('@')))
                    {
                        scope.identity.insert(dimension, V::Unknown);
                        builder.boundary(Boundary {
                            reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                            class: BoundaryClass::Unresolved,
                            scope: BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("cloud")],
                            provenance: provenance.clone(),
                            limit: None,
                            detail: Some(
                                "the CLI reads the scope option's value from a file Nah does not read"
                                    .into(),
                            ),
                        });
                    } else if dimension == D::Subscription
                        && matches!(&value, V::Value(v) if matches!(v.as_ref(), ResourceExpr::Literal { value } if !subscription_uuid(value)))
                    {
                        access_value(scope, E::SubscriptionName, value);
                    } else if !matches!(scope.identity.get(&dimension), Some(V::NotApplicable)) {
                        if matches!(scope.identity.get(&dimension), Some(V::Value(previous)) if V::Value(previous.clone()) != value)
                        {
                            scope.identity.insert(dimension, V::Unknown);
                            scope_boundary(builder, provenance, "cloud");
                        } else {
                            scope.identity.insert(dimension, value);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if provider.as_deref() == Some("azure")
        && ctx.argv.iter().any(|word| {
            word.as_literal().is_some_and(|s| {
                s == "--connection-string" || s.starts_with("--connection-string=")
            })
        })
    {
        if !matches!(
            scope.identity.get(&D::StorageAccount),
            Some(V::NotApplicable)
        ) {
            scope.identity.insert(D::StorageAccount, V::Unknown);
        }
        access_value(scope, E::UnresolvedConfiguration, V::Unknown);
        scope_boundary(builder, provenance, "cloud");
    }
    let gsutil_short_options = ctx.argv[0].as_literal().map(crate::models::args::basename)
        == Some("gsutil")
        && ctx
            .argv
            .iter()
            .skip(1)
            .filter_map(Word::as_literal)
            .filter(|word| word.starts_with('-'))
            .all(|word| {
                word.strip_prefix('-').is_some_and(|letters| {
                    !letters.is_empty()
                        && letters
                            .chars()
                            .all(|letter| matches!(letter, 'm' | 'q' | 'r' | 'R' | 'd'))
                })
            });
    if !gsutil_short_options {
        // Azure CLI's argparse reads `-nVALUE` as `-n VALUE`.
        let attached_names = ctx
            .argv
            .iter()
            .skip(1)
            .filter_map(Word::as_literal)
            .filter(|word| provider.as_deref() == Some("azure") && word.len() > 2)
            .filter(|word| word.starts_with("-n") && !word.contains('='));
        let supported = [
            "--region",
            "--endpoint-url",
            "--profile",
            "--project",
            "--zone",
            "--subscription",
            "--resource-group",
            "-g",
            "--account-name",
            "--configuration",
            "--flags-file",
            "--instance-ids",
            "--db-instance-identifier",
            "--skip-final-snapshot",
            "--final-db-snapshot-identifier",
            "--delete-automated-backups",
            "--bucket",
            "--key",
            "--recursive",
            "--delete",
            "--quiet",
            "--force",
            "--dryrun",
            "--exclude",
            "--include",
            "--only-show-errors",
            "--debug",
            "--verbose",
            "--bypass-immutability-policy",
            "--acquire-policy-token",
            "--change-reference",
            "--no-progress",
            "--name",
            "-n",
            "--container-name",
            "-c",
            "--blob-url",
            "--file",
            "-f",
            "--ids",
            "--yes",
            "-y",
            "--no-wait",
            "--output",
            "-o",
            "--query",
            "--auth-mode",
            "--account-key",
            "--connection-string",
            "--sas-token",
            "--no-verify-ssl",
            "--no-sign-request",
            "--snapshot-id",
            "--volume-id",
            "--source",
            "--delete-unmatched-destination-objects",
            "--delete-destination",
            "--config",
            "--fast-list",
            "-m",
            "-r",
            "-R",
            "-q",
        ]
        .into_iter()
        .chain(attached_names)
        .chain(resource_delete(ctx.argv).map_or_else(Vec::new, |delete| delete.options().collect()))
        .collect::<Vec<_>>();
        crate::models::scope::unmodeled_scope_options(
            builder, ctx, provenance, scope, &supported, "cloud",
        );
    }
    qualify_cloud_name(identity, builder, provenance);
    if let Some(scope) = identity.scope_mut() {
        effinterp_proto::normalize_scope(scope, effinterp_proto::PathPlatform::Posix);
    }
}

fn subscription_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn qualify_cloud_name(
    identity: &mut ResourceIdentity,
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
) {
    use effinterp_proto::{ScopeDimension as D, ScopeValue as V};
    let (scope, name) = match identity {
        ResourceIdentity::ObjectStore { scope, bucket, .. } => (scope, bucket),
        ResourceIdentity::CloudResource {
            scope,
            id: Some(id),
            ..
        } => (scope, id),
        _ => return,
    };
    let text = name.clone();
    if scope.kind == effinterp_proto::NamespaceKind::S3Bucket
        && ["--x-s3", "-s3alias", "--ol-s3", "--table-s3"]
            .iter()
            .any(|suffix| text.ends_with(suffix))
    {
        scope.kind = effinterp_proto::NamespaceKind::Unsupported;
        scope.identity = effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
        crate::models::scope::scope_boundary(builder, provenance, "cloud");
    }
    let mut fields = Vec::new();
    if text.starts_with("arn:") {
        let parts: Vec<_> = text.splitn(6, ':').collect();
        if parts.len() == 6 && matches!(parts[1], "aws" | "aws-cn" | "aws-us-gov") {
            match (scope.kind, parts[2], parts[5]) {
                (effinterp_proto::NamespaceKind::S3Bucket, "s3", bucket)
                    if parts[3].is_empty()
                        && parts[4].is_empty()
                        && !bucket.contains(['/', ':'])
                        && !bucket.is_empty() =>
                {
                    fields.push((D::Partition, parts[1]));
                    *name = bucket.to_string();
                }
                (effinterp_proto::NamespaceKind::AwsRegional, "ec2", target)
                    if target.starts_with("instance/") =>
                {
                    fields.extend([
                        (D::Partition, parts[1]),
                        (D::Account, parts[4]),
                        (D::Region, parts[3]),
                    ]);
                    *name = target[9..].to_string();
                }
                (effinterp_proto::NamespaceKind::AwsRegional, "rds", target)
                    if target.starts_with("db:") =>
                {
                    fields.extend([
                        (D::Partition, parts[1]),
                        (D::Account, parts[4]),
                        (D::Region, parts[3]),
                    ]);
                    *name = target[3..].to_string();
                }
                _ => {
                    scope.kind = effinterp_proto::NamespaceKind::Unsupported;
                    scope.identity =
                        effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
                    crate::models::scope::scope_boundary(builder, provenance, "cloud");
                }
            }
        } else {
            scope.kind = effinterp_proto::NamespaceKind::Unsupported;
            scope.identity =
                effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
            crate::models::scope::scope_boundary(builder, provenance, "cloud");
        }
    } else if scope.kind == effinterp_proto::NamespaceKind::GceZonal {
        let path = text
            .strip_prefix("https://www.googleapis.com/compute/v1/")
            .unwrap_or(&text);
        let parts: Vec<_> = path.split('/').collect();
        if let [
            "projects",
            project,
            location_kind,
            location,
            "instances",
            instance,
        ] = parts.as_slice()
        {
            if *location_kind == "regions" {
                scope.kind = effinterp_proto::NamespaceKind::GceRegional;
                scope.identity =
                    effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
            }
            if matches!(*location_kind, "zones" | "regions") {
                fields.push((D::Project, *project));
                fields.push((
                    if *location_kind == "zones" {
                        D::Zone
                    } else {
                        D::Region
                    },
                    *location,
                ));
                *name = instance.to_string();
            }
        }
    } else if scope.kind == effinterp_proto::NamespaceKind::AzureVm {
        let parts: Vec<_> = text.split('/').collect();
        if let [
            "",
            "subscriptions",
            subscription,
            "resourceGroups",
            group,
            "providers",
            "Microsoft.Compute",
            "virtualMachines",
            instance,
        ] = parts.as_slice()
        {
            fields.extend([(D::Subscription, *subscription), (D::ResourceGroup, *group)]);
            *name = instance.to_string();
        }
    }
    for (dimension, value) in fields {
        if value.is_empty() {
            continue;
        }
        let value = V::value(ResourceExpr::Literal {
            value: value.to_string(),
        });
        if matches!(scope.identity.get(&dimension), Some(V::Value(previous)) if V::Value(previous.clone()) != value)
        {
            scope.identity.insert(dimension, V::Unknown);
            crate::models::scope::scope_boundary(builder, provenance, "cloud");
        } else {
            scope.identity.insert(dimension, value);
        }
    }
}

fn cloud_environment(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    name: &str,
) -> Option<ResourceExpr> {
    let value = ctx.environment_value(name)?;
    if let Some(node) = ctx.nest.current_environment_node(name) {
        provenance.push(node);
    } else if ctx.tracks_host_context_environment() {
        provenance.push(builder.node(
            effinterp_proto::ProvenanceKind::HostContext {
                name: format!("env.{name}"),
            },
            &[],
        ));
    }
    Some(value)
}

fn cloud_network_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    resource: &ResourceExpr,
    operation: &str,
) -> Option<u32> {
    let mut provenance = provenance.to_vec();
    let mut scope =
        effinterp_proto::ResourceScope::new(effinterp_proto::NamespaceKind::Unsupported);
    fn collect(scope: &mut effinterp_proto::ResourceScope, resource: &ResourceExpr) {
        match resource {
            ResourceExpr::Concrete { identity } => {
                if let Some(source) = identity.scope() {
                    scope.access.extend(source.access.clone());
                }
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                for part in parts {
                    collect(scope, part);
                }
            }
            _ => {}
        }
    }
    collect(&mut scope, resource);
    if scope.access.is_empty()
        && ctx.argv[0]
            .as_literal()
            .and_then(|command| command.rsplit('/').next())
            == Some("aws")
    {
        if let Some(endpoint) = crate::models::scope::scope_option(
            builder,
            ctx,
            &mut provenance,
            &["--endpoint-url"],
            true,
            "network",
        ) {
            crate::models::scope::endpoint_evidence(
                &mut scope,
                effinterp_proto::ScopeEvidenceKind::Endpoint,
                endpoint,
            );
        } else {
            // Preserve the same supplied endpoint evidence as the cloud resource scope.
            for name in [
                "AWS_ENDPOINT_URL",
                "AWS_ENDPOINT_URL_S3",
                "AWS_ENDPOINT_URL_EC2",
                "AWS_ENDPOINT_URL_RDS",
            ] {
                if let Some(endpoint) = cloud_environment(builder, ctx, &mut provenance, name) {
                    crate::models::scope::endpoint_evidence(
                        &mut scope,
                        effinterp_proto::ScopeEvidenceKind::Endpoint,
                        effinterp_proto::ScopeValue::value(endpoint),
                    );
                    crate::models::scope::scope_boundary(builder, &provenance, "network");
                }
            }
        }
    }
    super::infrastructure::emit(
        builder,
        &provenance,
        operation,
        crate::models::scope::network_resource(&scope),
    )
}
const FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--target",
        "--document-name",
        "--instance-ids",
        "--parameters",
        "--bucket",
        "--key",
        "--db-instance-identifier",
        "--stack-name",
        "--file",
        "-f",
        "--ids",
        "--name",
        "-n",
        "--command-id",
        "--blob-url",
        "--container-name",
        "-c",
        "--snapshot-id",
        "--volume-id",
        "--source",
        "--profile",
        "--region",
        "--endpoint-url",
        "--project",
        "--exclude",
        "--include",
    ],
    known_flags: &[
        "--recursive",
        "--delete",
        "--delete-unmatched-destination-objects",
        "--force",
        "-r",
        "-d",
    ],
};
