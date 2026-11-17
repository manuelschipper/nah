//! `git apply`: patch inputs, individual worktree changes, and index-only modes.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, ObservationOutcome, Operation, PathKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, arg_node, program_input_attrs};
use crate::nest::SourceResolution;
use crate::paths::{join_source_path, parent_dir, resolve_fs_path};
use crate::toolcall::patch::{
    PatchError, PatchOperation, UnifiedOperation, UnifiedPaths, parse_unified,
};

use super::SubCtx;
use super::git_options::git_options;
use super::git_repository::worktree_base;

pub(super) fn apply(builder: &mut PlanBuilder, s: &SubCtx) {
    for domain in ["filesystem", "git"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    if s.ctx.argv[..s.sub_index as usize]
        .iter()
        .filter(|word| word.as_literal() == Some("-C"))
        .count()
        > 1
    {
        unsupported(
            builder,
            s,
            "git apply chained working directories are not modeled",
        );
        return;
    }
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-p", "--directory", "--whitespace"],
            known_flags: &[
                "--stat",
                "--numstat",
                "--summary",
                "--check",
                "--apply",
                "--index",
                "--cached",
                "-N",
                "--intent-to-add",
                "-R",
                "--reverse",
                "--binary",
                "--allow-binary-replacement",
                "--unidiff-zero",
                "--unsafe-paths",
                "-z",
                "-v",
                "--verbose",
                "-q",
                "--quiet",
                "-h",
                "--help",
            ],
            allow_abbreviation: true,
        },
    );
    if parsed.has(&["-h", "--help"]) {
        return;
    }
    if !parsed.unknown_flags.is_empty()
        || parsed.flags.iter().any(|flag| {
            flag.value
                .as_ref()
                .is_some_and(|value| value.as_literal().is_none())
        })
    {
        unsupported(
            builder,
            s,
            "git apply options or patch operands are not fully known",
        );
        return;
    }
    // These settings can change the bytes Git installs. Leave those modes
    // explicit until their transformations are modeled.
    if parsed.value_of(&["--whitespace"]).is_some_and(|value| {
        !matches!(
            value.as_literal(),
            Some("nowarn" | "warn" | "error" | "error-all")
        )
    }) || s.globals.opaque_config
        || s.globals.configs.iter().any(|entry| {
            entry.key.eq_ignore_ascii_case("apply.whitespace")
                || entry.key.eq_ignore_ascii_case("apply.ignoreWhitespace")
        })
    {
        unsupported(
            builder,
            s,
            "git apply whitespace transformation is not modeled",
        );
        return;
    }
    let strip = match parsed.value_of(&["-p"]) {
        None => None,
        Some(value) => match value
            .as_literal()
            .and_then(|value| value.parse::<usize>().ok())
        {
            Some(strip) => Some(strip),
            None => {
                unsupported(builder, s, "git apply path stripping is not known");
                return;
            }
        },
    };
    let directory = parsed
        .value_of(&["--directory"])
        .and_then(|value| value.as_literal())
        .unwrap_or("");
    let reverse = parsed.has(&["-R", "--reverse"]);
    let cached = parsed.has(&["--cached"]);
    let check = parsed.has(&["--check"]);
    let writes =
        parsed.has(&["--apply"]) || !parsed.has(&["--stat", "--numstat", "--summary", "--check"]);
    let command_cwd = worktree_base(s.globals, s.ctx);
    let application = if !cached && (writes || check) {
        application_root(builder, s, &command_cwd)
    } else {
        None
    };
    let mut patch_paths = application.as_ref().map(|(_, prefix)| UnifiedPaths::Git {
        strip,
        prefix,
        directory,
    });
    let mut inputs: Vec<_> = parsed
        .operands
        .iter()
        .map(|(index, word)| (s.rest_offset - 1 + *index, Some(*word)))
        .collect();
    if inputs.is_empty() {
        inputs.push((s.sub_index, None));
    }
    let mut patches = Vec::new();
    for (index, operand) in inputs {
        let stdin = operand.is_none_or(|word| word.as_literal() == Some("-"));
        let bytes = if stdin {
            s.ctx.stdin_source(builder)
        } else {
            let Some(path) = operand.and_then(|word| word.as_literal()) else {
                unsupported(builder, s, "git apply patch operand is not known");
                return;
            };
            let resource = crate::paths::resolve_fs_path_with_cwd(path, Some(command_cwd.clone()));
            emit(
                builder,
                s,
                index,
                "filesystem.read",
                resource.clone(),
                program_input_attrs(),
            );
            match resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => {
                    match s.ctx.resolve_source_operand(
                        builder,
                        &path,
                        SourcePurpose::InvocationInput,
                    ) {
                        SourceResolution::Source { source, .. } => Some(source),
                        _ => None,
                    }
                }
                _ => None,
            }
        };
        // Statistics consume only the patch; --check also reads its preimages.
        if !writes && !check {
            continue;
        }
        if cached {
            continue;
        }
        let Some(bytes) = bytes else {
            unsupported(builder, s, "git apply patch bytes are not established");
            continue;
        };
        let Some(paths) = patch_paths.as_mut() else {
            unsupported(
                builder,
                s,
                "git apply repository root or worktree selection is not established",
            );
            continue;
        };
        let limits = s.ctx.nest.limits;
        let operations = if bytes.len() as u64 > limits.max_patch_bytes {
            Err(PatchError::Limit("max_patch_bytes"))
        } else {
            parse_unified(&bytes, limits.max_patch_files, paths)
        };
        match operations {
            Ok(operations) => patches.push((index, operations)),
            Err(error) => {
                let (reason, class, limit) = match error {
                    PatchError::Parse => (
                        BoundaryReason::PATCH_PARSE_FAILURE,
                        BoundaryClass::ParseFailure,
                        None,
                    ),
                    PatchError::Limit(limit) => (
                        BoundaryReason::LIMIT_SATURATED,
                        BoundaryClass::Limit,
                        Some(limit.into()),
                    ),
                };
                boundary(
                    builder,
                    s,
                    reason,
                    class,
                    limit,
                    "git apply patch syntax is not supported",
                );
            }
        }
    }
    if !writes && (!check || patches.is_empty()) {
        return;
    }
    if writes && (cached || parsed.has(&["--index", "-N", "--intent-to-add"])) {
        s.repo_effect(builder, "git.index_write", Attrs::new());
    }
    if cached || patches.is_empty() {
        return;
    }
    let (root, prefix) = application.expect("parsed patches have an application root");
    for (index, operations) in patches {
        for mut patch in operations {
            if reverse {
                patch.reverse();
            }
            let paths = match &patch.operation {
                PatchOperation::Add { path, .. }
                | PatchOperation::Modify { path, .. }
                | PatchOperation::Delete { path, .. } => [path.as_str(), ""],
                PatchOperation::Move { from, to, .. } => [from.as_str(), to.as_str()],
            };
            if paths.into_iter().chain([directory]).any(|path| {
                !path.is_empty()
                    && (crate::paths::is_absolute(path)
                        || path.split('/').any(|part| matches!(part, "" | "." | "..")))
            }) {
                unsupported(builder, s, "git apply nonlocal patch paths are not modeled");
                continue;
            }
            let map_path = |path: &str| {
                let path = if directory.is_empty() {
                    path.to_string()
                } else {
                    format!("{}/{path}", directory.trim_end_matches('/'))
                };
                // Traditional diffs are based at the invocation directory;
                // Git-format paths are already based at the repository root.
                let path = if patch.toplevel_relative {
                    path
                } else {
                    format!("{prefix}{path}")
                };
                if !prefix.is_empty() && !path.starts_with(&prefix) {
                    return None;
                }
                Some(resolve_fs_path(&path, Some(&root)))
            };
            if !writes {
                let source = match &patch.operation {
                    PatchOperation::Add { .. } => None,
                    PatchOperation::Modify { path, .. } | PatchOperation::Delete { path, .. } => {
                        map_path(path)
                    }
                    PatchOperation::Move { from, .. } => map_path(from),
                };
                if let Some(source) = source {
                    emit(
                        builder,
                        s,
                        index,
                        "filesystem.read",
                        source,
                        program_input_attrs(),
                    );
                }
                continue;
            }
            let (path, operation, content) = match &patch.operation {
                PatchOperation::Add {
                    path,
                    written_content,
                    ..
                } => (path, "filesystem.create", written_content),
                PatchOperation::Modify {
                    path,
                    written_content,
                    ..
                } => (path, "filesystem.write", written_content),
                PatchOperation::Delete { path, .. } => {
                    if let Some(resource) = map_path(path) {
                        emit(
                            builder,
                            s,
                            index,
                            "filesystem.delete",
                            resource,
                            Attrs::new(),
                        );
                    }
                    continue;
                }
                PatchOperation::Move {
                    from,
                    to,
                    written_content,
                    ..
                } => {
                    let (Some(source), Some(destination)) = (map_path(from), map_path(to)) else {
                        continue;
                    };
                    if is_symlink(s, &source) {
                        unsupported(
                            builder,
                            s,
                            "git apply of an existing symlink is not modeled",
                        );
                        continue;
                    }
                    let mut attributes = content_attrs(
                        builder,
                        s,
                        &patch,
                        Some(&source),
                        written_content.as_deref(),
                    );
                    attributes.insert("move_destination".into(), AttrValue::Bool(true));
                    emit(builder, s, index, "filesystem.move", source, Attrs::new());
                    emit(
                        builder,
                        s,
                        index,
                        "filesystem.write",
                        destination,
                        attributes,
                    );
                    continue;
                }
            };
            let Some(resource) = map_path(path) else {
                continue;
            };
            if is_symlink(s, &resource) {
                unsupported(
                    builder,
                    s,
                    "git apply of an existing symlink is not modeled",
                );
                continue;
            }
            let original = (operation == "filesystem.write").then_some(&resource);
            let attributes = content_attrs(builder, s, &patch, original, content.as_deref());
            emit(builder, s, index, operation, resource, attributes);
        }
    }
}

fn is_symlink(s: &SubCtx, resource: &ResourceExpr) -> bool {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = resource
    else {
        return false;
    };
    matches!(s.ctx.nest.budget.observe_path(path), ObservationOutcome::Path(fact) if fact.kind == PathKind::Symlink)
}

fn content_attrs(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    patch: &UnifiedOperation,
    original: Option<&ResourceExpr>,
    written: Option<&str>,
) -> Attrs {
    let mut attributes = Attrs::new();
    if original.is_some() {
        attributes.insert("in_place".into(), AttrValue::Bool(true));
    }
    if let Some(content) = written {
        attributes.insert("written_content".into(), AttrValue::String(content.into()));
    }
    let source = match original {
        None => Some(String::new()),
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) => {
            emit(
                builder,
                s,
                s.sub_index,
                "filesystem.read",
                original.unwrap().clone(),
                program_input_attrs(),
            );
            join_source_path(s.ctx.runtime_cwd, path).and_then(|(namespace, path)| {
                match s.ctx.nest.resolve_data_file(builder, &path, namespace) {
                    SourceResolution::Source { source, .. } => Some(source),
                    _ => None,
                }
            })
        }
        _ => None,
    };
    if let Some(result) = source.and_then(|source| patch.resulting_content(&source)) {
        if result.len() as u64 <= s.ctx.nest.limits.max_source_bytes {
            attributes.insert("resulting_content".into(), AttrValue::String(result));
        } else {
            builder.note_saturated("max_source_bytes");
        }
    }
    attributes
}

fn application_root(
    builder: &PlanBuilder,
    s: &SubCtx,
    cwd: &ResourceExpr,
) -> Option<(String, String)> {
    let globals = &s.ctx.argv[..s.sub_index as usize];
    if !builder.is_host_realm()
        || globals
            .iter()
            .any(|word| word.as_literal() == Some("--bare"))
        || s.globals.configs.iter().any(|entry| {
            entry.key.eq_ignore_ascii_case("core.worktree")
                || entry.key.eq_ignore_ascii_case("core.bare")
        })
        || s.globals.git_dir.is_some()
        || s.globals.work_tree.is_some()
        || s.ctx.environment_value("GIT_DIR").is_some()
        || s.ctx.environment_value("GIT_WORK_TREE").is_some()
        || s.ctx.environment_value("GIT_CEILING_DIRECTORIES").is_some()
    {
        return None;
    }
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: cwd },
    } = cwd
    else {
        return None;
    };
    let mut root = cwd.clone();
    loop {
        match s
            .ctx
            .nest
            .budget
            .observe_path(&format!("{}/.git", root.trim_end_matches('/')))
        {
            ObservationOutcome::Path(fact) => match fact.kind {
                PathKind::Directory | PathKind::File => {
                    let prefix = cwd.strip_prefix(&root)?.trim_matches('/');
                    return Some((
                        root.clone(),
                        if prefix.is_empty() {
                            String::new()
                        } else {
                            format!("{prefix}/")
                        },
                    ));
                }
                PathKind::Missing => {}
                _ => return None,
            },
            _ => return None,
        }
        let parent = parent_dir(&root);
        if parent == root || parent.is_empty() {
            return Some((cwd.clone(), String::new()));
        }
        root = parent;
    }
}

fn emit(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) {
    let mut provenance: Vec<ProvenanceRef> = vec![s.model_node, arg_node(builder, s.ctx, index)];
    provenance.extend(s.repo_global_nodes(builder));
    provenance.extend(s.ctx.cwd_node);
    if let Some(stdin) = s.ctx.stdin {
        provenance.extend(&stdin.provenance);
    }
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
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

fn unsupported(builder: &mut PlanBuilder, s: &SubCtx, detail: &str) {
    boundary(
        builder,
        s,
        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        BoundaryClass::Unmodeled,
        None,
        detail,
    );
}

fn boundary(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    reason: BoundaryReason,
    class: BoundaryClass,
    limit: Option<String>,
    detail: &str,
) {
    builder.boundary_with_coverage(
        Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem"), Domain::new("git")],
            provenance: vec![s.model_node],
            limit,
            detail: Some(detail.into()),
        },
        CoverageLevel::Partial,
    );
}
