use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceRef, ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::models::common::{
    Attrs, arg_node, fs_arg_effect, program_input_attrs, program_output_attrs,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::resource_transfer::TransferBinding;
use crate::word::Word;

/// Model SFTP batch transfers from literal stdin and destination downloads
/// over the session established by the registered model.
pub(in crate::models) fn with_sftp_transfers(
    owner: Box<dyn CommandModel>,
) -> Box<dyn CommandModel> {
    Box::new(SftpTransfers { owner })
}

struct SftpTransfers {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for SftpTransfers {
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
        let start = builder.effects_len();
        self.owner.apply(builder, ctx, model_node);
        let Some(session) = (start..builder.effects_len())
            .find(|&index| builder.effect_operation(index) == Some("network.connect"))
            .and_then(|index| builder.effect_resource(index).cloned())
        else {
            return;
        };
        let destination = sftp_destination(ctx.argv);
        // An IPv6 address in brackets holds colons of its own.
        if let Some((index, path)) = destination.and_then(|(index, word)| {
            let (host, path) = word.as_literal()?.split_once(':')?;
            (!host.contains('[')).then_some((index, path))
        }) {
            let provenance = vec![arg_node(builder, ctx, index as u32), model_node];
            sftp_retrieve(builder, ctx, &provenance, &session, path, None, false);
        }
        // `-b FILE` or `-bFILE`.
        let batch_file = ctx
            .argv
            .iter()
            .enumerate()
            .skip(1)
            .find_map(
                |(index, word)| match word.as_literal()?.strip_prefix("-b")? {
                    "" => Some((index + 1, ctx.argv.get(index + 1).cloned())),
                    attached => Some((index, Some(Word::literal(attached)))),
                },
            );
        match batch_file {
            Some((_, Some(word))) if word.as_literal() == Some("-") => {}
            Some((index, word)) => {
                sftp_unobserved_batch(builder, ctx, model_node, &session, index, word.as_ref());
                return;
            }
            None => {}
        }
        let (Some(commands), Some(stdin)) = (ctx.stdin_literal(), ctx.stdin) else {
            return;
        };
        let mut provenance = vec![model_node];
        provenance.extend(stdin.provenance.iter().copied());
        let unmodeled = |builder: &mut PlanBuilder, domains: &[&str], detail: &str| {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: domains.iter().copied().map(Domain::new).collect(),
                provenance: provenance.clone(),
                limit: None,
                detail: Some(detail.into()),
            });
        };
        for line in commands.lines() {
            // A leading `-` ignores the command's failure and `@` its echo.
            let mut words = line
                .trim()
                .trim_start_matches(['-', '@'])
                .split_whitespace();
            let command = words.next();
            match command {
                Some("put" | "reput" | "get" | "reget") => {}
                // A changed local directory moves every later relative path.
                Some("lcd") => {
                    unmodeled(
                        builder,
                        &["filesystem", "network"],
                        "sftp batch lcd moves the local paths of later commands",
                    );
                    break;
                }
                Some(command) if command.starts_with('!') => {
                    unmodeled(
                        builder,
                        &["filesystem", "network", "process"],
                        "sftp batch runs a local shell command",
                    );
                    continue;
                }
                Some("lmkdir") => {
                    unmodeled(
                        builder,
                        &["filesystem"],
                        "sftp batch command writes local files",
                    );
                    continue;
                }
                _ => continue,
            }
            let mut recursive = false;
            let mut paths = Vec::new();
            for word in words {
                match word.strip_prefix('-') {
                    Some(options) if paths.is_empty() => recursive |= options.contains(['r', 'R']),
                    _ => paths.push(word),
                }
            }
            if paths
                .iter()
                .any(|path| path.contains(['*', '?', '[', '"', '\'', '\\']))
            {
                unmodeled(
                    builder,
                    &["filesystem", "network"],
                    "sftp batch transfer of a pattern or quoted path",
                );
                continue;
            }
            if matches!(command, Some("get" | "reget")) {
                if let Some(remote) = paths.first() {
                    sftp_retrieve(
                        builder,
                        ctx,
                        &provenance,
                        &session,
                        remote,
                        paths.get(1).copied(),
                        recursive,
                    );
                }
                continue;
            }
            let Some(local) = paths.first() else { continue };
            let mut attributes = program_input_attrs();
            if recursive {
                attributes.insert("recursive".into(), AttrValue::Bool(true));
            }
            let read = builder.effect(sftp_effect(
                &provenance,
                "filesystem.read",
                ctx.resolve_fs_word(&Word::literal(*local)),
                attributes,
            ));
            let upload = builder.effect(sftp_effect(
                &provenance,
                "network.upload",
                session.clone(),
                Attrs::new(),
            ));
            if let (Some(read), Some(upload)) = (read, upload) {
                builder.transfer_binding(TransferBinding::new(read, upload));
            }
        }
    }
}

fn sftp_effect(
    provenance: &[ProvenanceRef],
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) -> Effect {
    Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: provenance.to_vec(),
    }
}

/// sftp options that take the next word as their value.
const SFTP_VALUE_FLAGS: &[&str] = &[
    "-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S", "-s", "-X",
];

/// The destination operand of an sftp invocation, by argv index: the first
/// word that is neither an option nor an option's value.
fn sftp_destination(argv: &[Word]) -> Option<(usize, &Word)> {
    let mut index = 1;
    while let Some(word) = argv.get(index) {
        match word.as_literal() {
            Some(flag) if flag.len() > 1 && flag.starts_with('-') => {
                index += if SFTP_VALUE_FLAGS.contains(&flag) {
                    2
                } else {
                    1
                };
            }
            _ => return Some((index, word)),
        }
    }
    None
}

/// sftp retrieves a remote file named by `[user@]host:path`, or by a batch
/// `get REMOTE [LOCAL]`, into LOCAL or, without one, the working directory
/// under the file's own name. A path ending in `/` names a directory, which
/// the destination form opens instead of retrieving; a pattern retrieves
/// entries whose names are unknown.
fn sftp_retrieve(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    session: &ResourceExpr,
    remote: &str,
    local: Option<&str>,
    recursive: bool,
) {
    let name = remote.rsplit('/').next().unwrap_or(remote);
    if remote.contains(['*', '?', '[']) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem"), Domain::new("network")],
            provenance: provenance.to_vec(),
            limit: None,
            detail: Some("sftp retrieval of a remote pattern writes unnamed local files".into()),
        });
        return;
    }
    if matches!(name, "" | "." | ".." | "~") {
        return;
    }
    // A LOCAL that names a directory receives the file under its own name.
    // Only `.`, `..` and a trailing `/` spell one; any other LOCAL may be an
    // existing directory, so both places may be written.
    let locals = match local {
        Some(directory @ ("." | "..")) => vec![format!("{directory}/{name}")],
        Some(directory) if directory.ends_with('/') => vec![format!("{directory}{name}")],
        Some(local) => vec![local.to_string(), format!("{local}/{name}")],
        None => vec![name.to_string()],
    };
    let mut attributes = program_output_attrs();
    if recursive {
        attributes.insert("recursive".into(), AttrValue::Bool(true));
    }
    let Some(download) = builder.effect(sftp_effect(
        provenance,
        "network.download",
        session.clone(),
        Attrs::new(),
    )) else {
        return;
    };
    for local in locals {
        if let Some(write) = builder.effect(sftp_effect(
            provenance,
            "filesystem.write",
            ctx.resolve_fs_word(&Word::literal(local)),
            attributes.clone(),
        )) {
            builder.transfer_binding(TransferBinding::new(download, write));
        }
    }
}

/// `sftp -b FILE` runs the commands in FILE, whose content this analysis
/// does not see: the session may upload any local file and write any local
/// path, so it carries an upload of unknown content and a boundary.
fn sftp_unobserved_batch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    session: &ResourceExpr,
    index: usize,
    word: Option<&Word>,
) {
    if let Some(word) = word {
        fs_arg_effect(
            builder,
            ctx,
            model_node,
            index as u32,
            word,
            "filesystem.read",
            ctx.resolve_fs_word(word),
            program_input_attrs(),
        );
    }
    let provenance = [model_node];
    builder.effect(sftp_effect(
        &provenance,
        "network.upload",
        session.clone(),
        Attrs::new(),
    ));
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("filesystem"),
                Domain::new("network"),
                Domain::new("process"),
            ],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "sftp batch file commands are not observed; what they upload and write is unknown"
                    .into(),
            ),
        },
        CoverageLevel::Partial,
    );
}
