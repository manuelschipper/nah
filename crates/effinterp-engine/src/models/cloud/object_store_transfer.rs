use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::{FlagSpec, Scanned, scan};
use crate::models::common::{
    Attrs, boundary, environment_boundary, leading_symbolic_without, program_input_attrs,
    program_output_attrs, symbolic_expr,
};
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;
use crate::word::Word;

use super::cloud_args::{
    CLOUD_LITERAL_FLAGS, CLOUD_SCOPE_FLAGS, GSUTIL_GLOBAL_FLAGS, azcopy_flag,
    cloud_has_short_option, cloud_operands,
};
use super::cloud_effects::{object_store_effect, object_store_upload_effect};
use super::object_store_target::object_store_target;

/// `cp/mv/sync SRC DEST`: each side is an object store (if a URL) or local fs.
/// An object-store transfer between two operands. A server-side copy pairs the
/// object read with the object write and never invents a client-side payload
/// upload or download. A local source is uploaded: its bytes cross the network
/// into the object, and a `recursive` transfer sends everything under it.
pub(super) fn object_store_transfer(
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
        known_flags: CLOUD_LITERAL_FLAGS.known_flags,
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
                .filter(|(_, word)| object_store_target(word).is_some())
                .copied()
                .collect::<Vec<_>>();
            let sources = if !objects.is_empty() {
                // An object source makes this a download or a server-side
                // copy; the other words are option values, never uploaded.
                objects
            } else if object_store_target(destination.1).is_some() {
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
    // aws and gsutil copy what the links under a local source lead to:
    // aws unless the last of its link options is `--no-follow-symlinks`,
    // gsutil unless `-e` makes it skip them. azcopy follows them only with
    // `--follow-symlinks`.
    let follows_links = match tool {
        "azcopy" => Some(azcopy_flag(ctx.argv, "--follow-symlinks")),
        "aws" => Some(
            ctx.argv
                .iter()
                .rev()
                .find_map(|word| match word.as_literal() {
                    Some("--follow-symlinks") => Some(true),
                    Some("--no-follow-symlinks") => Some(false),
                    _ => None,
                })
                .unwrap_or(true),
        ),
        "gsutil" => Some(!cloud_has_short_option(ctx.argv, start, &['e'])),
        _ => None,
    };
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
        if let Some(follows) = follows_links.filter(|_| {
            object_store_target(src).is_none() && !leading_symbolic_without(src, &['/'])
        }) {
            source_selection.insert("follow_links".into(), AttrValue::Bool(follows));
        }
        if tool == "aws"
            && recursive
            && object_store_target(src).is_none()
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
        if object_store_target(src).is_none() && !leading_symbolic_without(src, &['/']) {
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

/// A transfer run with its dry-run option prints each operation it would
/// perform and performs none: nothing is uploaded, written or deleted, on
/// either side. It still lists each object-store side, from `start` on, to
/// decide what it would do.
pub(super) fn object_store_dry_run(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    start: usize,
    detail: &str,
) {
    for (index, word) in cloud_operands(ctx.argv, start) {
        if let Some(target) = object_store_target(word) {
            object_store_effect(
                builder,
                ctx,
                model_node,
                index,
                "cloud.object.read",
                target,
                true,
                false,
                true,
                Default::default(),
            );
        }
    }
    environment_boundary(
        builder,
        model_node,
        BoundaryReason::REVIEWED_COMMAND_SURFACE,
        BoundaryClass::Unmodeled,
        &["filesystem", "network", "process"],
        detail,
    );
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
    CLOUD_LITERAL_FLAGS
        .value_flags
        .iter()
        .chain(routine)
        .copied()
        .collect()
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
/// `object_store_transfer`, a `-` anywhere before an object destination counts, since
/// an unlisted flag's value may sit among the operands.
pub(super) fn object_store_stdin_upload(argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
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
        known_flags: CLOUD_LITERAL_FLAGS.known_flags,
    };
    let scanned = scan(argv, &spec);
    match transfer_operands(&scanned, start).split_last() {
        Some(((_, destination), sources))
            if object_store_target(destination).is_some()
                && !sources
                    .iter()
                    .any(|(_, word)| object_store_target(word).is_some())
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
    if let Some(r) = object_store_target(word) {
        let op = if write {
            "cloud.object.write"
        } else {
            "cloud.object.read"
        };
        let slot = object_store_upload_effect(
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
            object_store_effect(
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
                unresolved_resource("network"),
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

/// aws s3 matches each `--exclude`/`--include` pattern with fnmatch against a
/// file's path joined under the source directory, `*` crossing `/`, and the
/// last matching filter decides. Only exclusions over a wholly literal
/// command line prove a file is skipped: any include may add one back, and
/// so may an unread option, since aws accepts any unique prefix of an option
/// (`--inc`). The
/// `excluded_paths` attribute states those relative globs.
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
        .filter(|pattern| !pattern.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    (!patterns.is_empty()).then(|| {
        AttrValue::String(serde_json::to_string(&patterns).expect("a list of strings serializes"))
    })
}
