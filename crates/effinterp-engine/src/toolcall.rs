use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionNodeRef, ExecutionRealm, HostContext, McpServerIdentity, Modality, Operation,
    PatchFormat, ProvenanceKind, ProvenanceRef, ResourceExpr, Subject, ToolCall,
};

use crate::builder::PlanBuilder;
use crate::limits::AnalysisLimits;
use crate::nest::Nest;
use crate::paths::{
    resolve_literal_tool_path, resolve_literal_tool_path_under_root, resolve_literal_tool_pattern,
};
use crate::value::unresolved_resource;

mod original_edit;
pub(crate) mod patch;
use patch::{PatchError, PatchOperation, UnifiedPaths, parse_apply_patch, parse_unified};

const FILESYSTEM: &str = "filesystem";
const MAX_FILE_EDIT_BATCH: usize = 64;

pub(crate) fn analyze_tool_call(
    builder: &mut PlanBuilder,
    nest: &Nest,
    subject: &Subject,
    depth: u64,
) {
    let Subject::ToolCall { call, cwd, .. } = subject else {
        return;
    };
    let limits = nest.limits;
    let cwd = cwd.as_deref();
    let context = nest.context.filter(|_| builder.is_host_realm());
    match call {
        ToolCall::FileRead(args) => {
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let mut provenance = vec![tool_argument(builder, "path")];
            let mut attributes = BTreeMap::new();
            if let Some(range) = &args.range {
                let end = range
                    .end_line
                    .map_or_else(String::new, |end| end.to_string());
                attributes.insert(
                    "range".to_string(),
                    AttrValue::String(format!("lines:{}-{end}", range.start_line)),
                );
                provenance.push(tool_argument(builder, "range"));
            }
            let path = tool_path_resource(path);
            add_effect(
                builder,
                "filesystem.read",
                path.clone(),
                attributes,
                provenance.clone(),
            );
            declare_path_coverage(builder, [(path, provenance)]);
        }
        ToolCall::FileWrite(args) => {
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let provenance = vec![
                tool_argument(builder, "path"),
                tool_argument(builder, "content"),
            ];
            let path = tool_path_resource(path);
            add_effect(
                builder,
                "filesystem.write",
                path.clone(),
                BTreeMap::from([
                    ("bytes".to_string(), byte_count(args.content.len())),
                    ("create".to_string(), AttrValue::String("may".to_string())),
                    ("truncate".to_string(), AttrValue::Bool(true)),
                    (
                        "written_content".to_string(),
                        AttrValue::String(args.content.clone()),
                    ),
                ]),
                provenance.clone(),
            );
            declare_path_coverage(builder, [(path, provenance)]);
        }
        ToolCall::FileTransfer(args) => {
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let direction = match args.direction {
                effinterp_proto::TransferDirection::Upload => {
                    ("upload", "network.upload", "filesystem.read")
                }
                effinterp_proto::TransferDirection::Download => {
                    ("download", "network.download", "filesystem.write")
                }
            };
            let local_provenance = vec![tool_argument(builder, "path")];
            let local_path = tool_path_resource(path);
            let local_slot = add_effect(
                builder,
                direction.2,
                local_path.clone(),
                BTreeMap::from([(
                    "transfer_direction".to_string(),
                    AttrValue::String(direction.0.to_string()),
                )]),
                local_provenance.clone(),
            );
            declare_path_coverage(builder, [(local_path, local_provenance)]);

            let network_provenance = vec![
                tool_argument_in_domain(builder, "path", "network"),
                tool_argument_in_domain(builder, "direction", "network"),
            ];
            let remote = unresolved_resource("net");
            let network_slot = add_network_effect(
                builder,
                direction.1,
                remote.clone(),
                BTreeMap::from([(
                    "transfer_direction".to_string(),
                    AttrValue::String(direction.0.to_string()),
                )]),
                network_provenance.clone(),
            );
            let binding = match args.direction {
                effinterp_proto::TransferDirection::Upload => (local_slot, network_slot),
                effinterp_proto::TransferDirection::Download => (network_slot, local_slot),
            };
            if let (Some(source), Some(destination)) = binding {
                builder.transfer_binding(crate::resource_transfer::TransferBinding::exact(
                    source,
                    destination,
                ));
            }
            builder.boundary_with_coverage_in_domain(
                Boundary {
                    reason: BoundaryReason::UNRESOLVED_TRANSFER_TARGET,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    domains: vec![Domain::new("network")],
                    affected_resource: Some(remote),
                    callee: None,
                    provenance: network_provenance,
                    limit: None,
                    detail: None,
                },
                CoverageLevel::Partial,
                "network",
            );
        }
        ToolCall::FileDelete(args) => {
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let provenance = vec![tool_argument(builder, "path")];
            let path = tool_path_resource(path);
            add_effect(
                builder,
                "filesystem.delete",
                path.clone(),
                BTreeMap::from([("recursive".to_string(), AttrValue::Bool(false))]),
                provenance.clone(),
            );
            declare_path_coverage(builder, [(path, provenance)]);
        }
        ToolCall::FileEdit(args) => {
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let mut provenance = vec![
                tool_argument(builder, "path"),
                tool_argument(builder, "old"),
                tool_argument(builder, "new"),
            ];
            if args.count.is_some() {
                provenance.push(tool_argument(builder, "count"));
            }
            let occurrences = args.count.map_or_else(
                || AttrValue::String("all".to_string()),
                |count| AttrValue::Int(i64::from(count)),
            );
            let mut attributes = BTreeMap::from([
                ("in_place".to_string(), AttrValue::Bool(true)),
                ("new_bytes".to_string(), byte_count(args.new.len())),
                ("occurrences".to_string(), occurrences),
                ("old_bytes".to_string(), byte_count(args.old.len())),
                (
                    "written_content".to_string(),
                    AttrValue::String(args.new.clone()),
                ),
            ]);
            let path = tool_path_resource(path);
            if !args.old.is_empty()
                && let ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } = &path
                && let crate::nest::SourceResolution::Source { source, .. } =
                    nest.resolve_data_file(builder, path, crate::SourceNamespace::Host)
                && args
                    .count
                    .is_none_or(|count| source.matches(&args.old).count() == count as usize)
            {
                let matches = source.matches(&args.old).count();
                let bytes = (source.len() - matches * args.old.len())
                    .saturating_add(matches.saturating_mul(args.new.len()));
                if bytes as u64 <= nest.limits.max_source_bytes {
                    attributes.insert(
                        "resulting_content".into(),
                        AttrValue::String(source.replace(&args.old, &args.new)),
                    );
                } else {
                    builder.note_saturated("max_source_bytes");
                }
            }
            add_effect(
                builder,
                "filesystem.read",
                path.clone(),
                attributes.clone(),
                provenance.clone(),
            );
            add_effect(
                builder,
                "filesystem.write",
                path.clone(),
                attributes,
                provenance.clone(),
            );
            declare_path_coverage(builder, [(path, provenance)]);
        }
        ToolCall::FileEditBatch(args) => {
            if args.edits.len() > MAX_FILE_EDIT_BATCH {
                let path = resolve_literal_tool_path(&args.path, cwd, context);
                let provenance = vec![tool_argument(builder, "path")];
                let attributes = BTreeMap::from([
                    ("batch".to_string(), AttrValue::Bool(true)),
                    ("in_place".to_string(), AttrValue::Bool(true)),
                    (
                        "occurrences".to_string(),
                        AttrValue::String("unknown".to_string()),
                    ),
                ]);
                let target = tool_path_resource(path);
                add_effect(
                    builder,
                    "filesystem.read",
                    target.clone(),
                    attributes.clone(),
                    provenance.clone(),
                );
                add_effect(
                    builder,
                    "filesystem.write",
                    target,
                    attributes,
                    provenance.clone(),
                );
                let path_provenance = tool_argument(builder, "path");
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::LIMIT_SATURATED,
                        class: BoundaryClass::Limit,
                        scope: BoundaryScope::Invocation,
                        domains: vec![Domain::new(FILESYSTEM)],
                        affected_resource: None,
                        callee: None,
                        provenance: vec![path_provenance],
                        limit: Some("file_edit_batch_entries".into()),
                        detail: None,
                    },
                    CoverageLevel::Partial,
                );
                let path = resolve_literal_tool_path(&args.path, cwd, context);
                declare_path_coverage(builder, [(path.resource, vec![path_provenance])]);
                return;
            }
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let mut content = if let ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } = &path.resource
                && let crate::nest::SourceResolution::Source { source, .. } =
                    nest.resolve_data_file(builder, path, crate::SourceNamespace::Host)
            {
                Some(source)
            } else {
                None
            };
            // Batch tools store the completed document once. Intermediate
            // replacements do not establish the bytes left in the file.
            let mut rejected_original = false;
            if args.match_original {
                content = content.and_then(|source| {
                    use original_edit::OriginalEditResult;
                    match original_edit::apply(&source, &args.edits, nest.limits.max_source_bytes) {
                        OriginalEditResult::Applied(content) => Some(content),
                        OriginalEditResult::Rejected => {
                            rejected_original = true;
                            None
                        }
                        OriginalEditResult::Unknown => None,
                        OriginalEditResult::TooLarge => {
                            builder.note_saturated("max_source_bytes");
                            None
                        }
                    }
                });
            } else {
                for edit in &args.edits {
                    content = content
                        .filter(|source| {
                            !edit.old.is_empty()
                                && if edit.replace_all {
                                    source.contains(&edit.old)
                                } else {
                                    source.matches(&edit.old).count() == 1
                                }
                        })
                        .and_then(|source| {
                            let matches = source.matches(&edit.old).count();
                            let bytes = (source.len() - matches * edit.old.len())
                                .saturating_add(matches.saturating_mul(edit.new.len()));
                            if bytes as u64 > nest.limits.max_source_bytes {
                                builder.note_saturated("max_source_bytes");
                                return None;
                            }
                            Some(source.replace(&edit.old, &edit.new))
                        });
                }
            }
            for (index, edit) in args.edits.iter().enumerate() {
                let path = resolve_literal_tool_path(&args.path, cwd, context);
                let provenance = vec![
                    tool_argument(builder, "path"),
                    tool_argument(builder, &format!("edits[{index}].old")),
                    tool_argument(builder, &format!("edits[{index}].new")),
                    tool_argument(builder, &format!("edits[{index}].replace_all")),
                ];
                let mut attributes = BTreeMap::from([
                    ("batch".to_string(), AttrValue::Bool(true)),
                    ("batch_index".to_string(), AttrValue::Int(index as i64)),
                    ("in_place".to_string(), AttrValue::Bool(true)),
                    ("new_bytes".to_string(), byte_count(edit.new.len())),
                    (
                        "occurrences".to_string(),
                        if edit.replace_all {
                            AttrValue::String("all".to_string())
                        } else {
                            AttrValue::Int(1)
                        },
                    ),
                    ("old_bytes".to_string(), byte_count(edit.old.len())),
                ]);
                // Pi writes no fragments only when its observed original
                // proves the batch fails. Applied or unknown batches retain
                // replacement evidence for consumers such as shell profiles.
                if !rejected_original {
                    attributes.insert(
                        "written_content".into(),
                        AttrValue::String(edit.new.clone()),
                    );
                }
                if let Some(content) = &content {
                    attributes.insert(
                        "resulting_content".into(),
                        AttrValue::String(content.clone()),
                    );
                }
                let target = tool_path_resource(path);
                add_effect(
                    builder,
                    "filesystem.read",
                    target.clone(),
                    attributes.clone(),
                    provenance.clone(),
                );
                add_effect(builder, "filesystem.write", target, attributes, provenance);
            }
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let path_provenance = tool_argument(builder, "path");
            declare_path_coverage(builder, [(path.resource, vec![path_provenance])]);
        }
        ToolCall::FilePatch(args) => {
            analyze_patch(builder, args.format, &args.text, cwd, limits, context);
        }
        ToolCall::FsGlob(args) => {
            let resource =
                resolve_literal_tool_pattern(&args.pattern, args.root.as_deref(), cwd, context);
            let mut provenance = vec![tool_argument(builder, "pattern")];
            if args.root.is_some() {
                provenance.push(tool_argument(builder, "root"));
            }
            let resource = tool_path_resource(resource);
            // A glob returns the names it matches, never their contents.
            add_effect(
                builder,
                "filesystem.read",
                resource.clone(),
                BTreeMap::from([("metadata".to_string(), AttrValue::Bool(true))]),
                provenance.clone(),
            );
            declare_path_coverage(builder, [(resource, provenance)]);
        }
        ToolCall::FsFind(args) => {
            let resource = resolve_literal_tool_path(&args.root, cwd, context);
            let mut provenance = vec![tool_argument(builder, "root")];
            let mut attributes = BTreeMap::from([("recursive".to_string(), AttrValue::Bool(true))]);
            attributes.insert(
                "filename_selector".to_string(),
                AttrValue::String(args.pattern.clone()),
            );
            provenance.push(tool_argument(builder, "pattern"));
            if let Some(limit) = args.limit {
                provenance.push(tool_argument(builder, "limit"));
                attributes.insert(
                    "selection_limit".to_string(),
                    AttrValue::Int(i64::from(limit)),
                );
            }
            let resource = tool_path_resource(resource);
            add_effect(
                builder,
                "filesystem.read",
                resource.clone(),
                attributes,
                provenance.clone(),
            );
            declare_path_coverage(builder, [(resource, provenance)]);
        }
        ToolCall::FsGrep(args) => {
            let filter_node = tool_argument(builder, "pattern");
            // The search tools are ripgrep with `--hidden`: a path is searched
            // with everything below it, hidden entries included, narrowed
            // only by the glob and type filters the call states.
            let mut attributes = BTreeMap::from([
                (
                    "content_filter".to_string(),
                    AttrValue::String(args.pattern.clone()),
                ),
                ("recursive".to_string(), AttrValue::Bool(true)),
            ]);
            for (name, values) in [("search_globs", &args.globs), ("search_types", &args.types)] {
                if !values.is_empty() {
                    attributes.insert(
                        name.to_string(),
                        AttrValue::List(values.iter().cloned().map(AttrValue::String).collect()),
                    );
                }
            }
            if args.follow_links {
                attributes.insert("follow_links".to_string(), AttrValue::Bool(true));
            }
            // Without a path the search starts at the root, or the working
            // directory: the same selection as naming that directory.
            let searched = match &args.paths {
                Some(paths) => paths
                    .iter()
                    .enumerate()
                    .map(|(index, path)| (Some(index), path.as_str()))
                    .collect(),
                None => vec![(None, ".")],
            };
            let mut targets = Vec::new();
            for (index, path) in searched {
                let resource = args.root.as_deref().map_or_else(
                    || resolve_literal_tool_path(path, cwd, context),
                    |root| resolve_literal_tool_path_under_root(path, root, cwd, context),
                );
                let mut provenance = Vec::new();
                if let Some(index) = index {
                    provenance.push(tool_argument(builder, &format!("paths[{index}]")));
                }
                provenance.push(filter_node);
                if args.root.is_some() {
                    provenance.push(tool_argument(builder, "root"));
                }
                let resource = tool_path_resource(resource);
                add_effect(
                    builder,
                    "filesystem.read",
                    resource.clone(),
                    attributes.clone(),
                    provenance.clone(),
                );
                targets.push((resource, provenance));
            }
            declare_path_coverage(builder, targets);
        }
        ToolCall::FsList(args) => {
            let path = resolve_literal_tool_path(&args.path, cwd, context);
            let provenance = vec![tool_argument(builder, "path")];
            let path = tool_path_resource(path);
            add_effect(
                builder,
                "filesystem.read",
                path.clone(),
                BTreeMap::from([("metadata".to_string(), AttrValue::Bool(true))]),
                provenance.clone(),
            );
            declare_path_coverage(builder, [(path, provenance)]);
        }
        ToolCall::McpCall(args) => {
            let model = match &args.server {
                McpServerIdentity::Known { transport } => nest
                    .catalog
                    .find_mcp_tool(transport, &args.tool)
                    .map(|model| (model, transport)),
                McpServerIdentity::Unknown => None,
            };
            match model {
                Some((model, transport)) => model.apply(builder, nest, args, transport, depth),
                None => {
                    let provenance = vec![
                        unknown_tool_argument(builder, "server"),
                        unknown_tool_argument(builder, "tool"),
                        unknown_tool_argument(builder, "arguments"),
                    ];
                    unsupported_tool(builder, provenance, format!("mcp:{}", args.tool));
                }
            }
        }
        ToolCall::Unknown(args) => {
            let provenance = vec![
                unknown_tool_argument(builder, "name"),
                unknown_tool_argument(builder, "args"),
            ];
            unsupported_tool(builder, provenance, args.name.clone());
        }
    }
}

/// A call whose semantics no model establishes may affect every domain.
fn unsupported_tool(builder: &mut PlanBuilder, provenance: Vec<ProvenanceRef>, detail: String) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::UNSUPPORTED_TOOL,
            class: BoundaryClass::Unsupported,
            scope: BoundaryScope::Invocation,
            domains: effinterp_proto::DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            affected_resource: None,
            callee: None,
            provenance,
            limit: None,
            detail: Some(detail),
        },
        CoverageLevel::None,
    );
}

fn tool_path_resource(path: crate::paths::ToolPath) -> ResourceExpr {
    path.resource
}

fn byte_count(bytes: usize) -> AttrValue {
    AttrValue::Int(i64::try_from(bytes).unwrap_or(i64::MAX))
}

fn tool_argument(builder: &mut PlanBuilder, name: &str) -> ProvenanceRef {
    tool_argument_in_domain(builder, name, FILESYSTEM)
}

fn tool_argument_in_domain(
    builder: &mut PlanBuilder,
    name: &str,
    domain: &'static str,
) -> ProvenanceRef {
    builder.node_in_domain(
        ProvenanceKind::ToolArgument {
            name: name.to_string(),
        },
        &[],
        domain,
    )
}

fn unknown_tool_argument(builder: &mut PlanBuilder, name: &str) -> ProvenanceRef {
    builder.node(
        ProvenanceKind::ToolArgument {
            name: name.to_string(),
        },
        &[],
    )
}

fn add_effect(
    builder: &mut PlanBuilder,
    operation: &str,
    resource: ResourceExpr,
    attributes: BTreeMap<String, AttrValue>,
    provenance: Vec<ProvenanceRef>,
) -> Option<u32> {
    builder.effect_in_domain(
        Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            condition: None,
            realm: ExecutionRealm::Host,
            execution: ExecutionNodeRef(0),
            provenance,
        },
        FILESYSTEM,
    )
}

fn add_network_effect(
    builder: &mut PlanBuilder,
    operation: &str,
    resource: ResourceExpr,
    attributes: BTreeMap<String, AttrValue>,
    provenance: Vec<ProvenanceRef>,
) -> Option<u32> {
    builder.effect_in_domain(
        Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            condition: None,
            realm: ExecutionRealm::Host,
            execution: ExecutionNodeRef(0),
            provenance,
        },
        "network",
    )
}

fn declare_path_coverage(
    builder: &mut PlanBuilder,
    targets: impl IntoIterator<Item = (ResourceExpr, Vec<ProvenanceRef>)>,
) {
    let mut symbolic = false;
    for (resource, provenance) in targets {
        let resource =
            effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix);
        let mut errors = Vec::new();
        effinterp_proto::validate_effect_resource(
            0,
            &Operation::new("filesystem.read"),
            &resource,
            &mut errors,
        );
        if !errors.is_empty() {
            // The effect builder already retained a typed validation boundary.
            // Do not reattach its invalid resource to a coverage boundary.
            symbolic = true;
            continue;
        }
        if !is_symbolic(&resource) {
            continue;
        }
        symbolic = true;
        builder.boundary_in_domain(
            Boundary {
                reason: BoundaryReason::UNRESOLVED_TOOL_PATH,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                domains: vec![Domain::new(FILESYSTEM)],
                affected_resource: Some(resource),
                callee: None,
                provenance,
                limit: None,
                detail: None,
            },
            FILESYSTEM,
        );
    }
    if !symbolic {
        builder.declare_coverage(Domain::new(FILESYSTEM), CoverageLevel::Full);
    }
}

fn is_symbolic(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. }
        | ResourceExpr::Unresolved { .. } => true,
        ResourceExpr::Property { base, .. } => is_symbolic(base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => parts.iter().any(is_symbolic),
        ResourceExpr::Concrete { .. }
        | ResourceExpr::Literal { .. }
        | ResourceExpr::Pattern { .. } => false,
    }
}

fn analyze_patch(
    builder: &mut PlanBuilder,
    format: PatchFormat,
    text: &str,
    cwd: Option<&str>,
    limits: &AnalysisLimits,
    context: Option<&HostContext>,
) {
    let text_node = tool_argument(builder, "text");
    let max_bytes = limits.max_patch_bytes;
    let max_files = limits.max_patch_files;
    let parsed = if text.len() as u64 > max_bytes {
        Err(PatchError::Limit("max_patch_bytes"))
    } else {
        match format {
            PatchFormat::Unified => {
                parse_unified(text, max_files, &mut UnifiedPaths::Tool).map(|operations| {
                    operations
                        .into_iter()
                        .map(|parsed| parsed.operation)
                        .collect()
                })
            }
            PatchFormat::ApplyPatch => parse_apply_patch(text, max_files),
        }
    };
    let operations = match parsed {
        Ok(operations) => operations,
        Err(PatchError::Parse) => {
            patch_boundary(
                builder,
                BoundaryReason::PATCH_PARSE_FAILURE,
                BoundaryClass::ParseFailure,
                None,
                text_node,
            );
            return;
        }
        Err(PatchError::Limit(limit)) => {
            patch_boundary(
                builder,
                BoundaryReason::LIMIT_SATURATED,
                BoundaryClass::Limit,
                Some(limit),
                text_node,
            );
            return;
        }
    };

    let mut targets = Vec::new();
    for operation in operations {
        let (path, operation, mut attributes, written_content) = match operation {
            PatchOperation::Add {
                path,
                hunks,
                written_content,
            } => (
                path,
                "filesystem.create",
                BTreeMap::from([("hunks".to_string(), byte_count(hunks))]),
                written_content,
            ),
            PatchOperation::Delete { path, hunks } => (
                path,
                "filesystem.delete",
                BTreeMap::from([("hunks".to_string(), byte_count(hunks))]),
                None,
            ),
            PatchOperation::Modify {
                path,
                hunks,
                written_content,
            } => (
                path,
                "filesystem.write",
                BTreeMap::from([
                    ("hunks".to_string(), byte_count(hunks)),
                    ("in_place".to_string(), AttrValue::Bool(true)),
                ]),
                written_content,
            ),
            PatchOperation::Move {
                from,
                to,
                hunks,
                written_content,
            } => {
                let source = resolve_literal_tool_path(&from, cwd, context);
                let destination = resolve_literal_tool_path(&to, cwd, context);
                let provenance = vec![text_node];
                let source = tool_path_resource(source);
                let destination_provenance = vec![text_node];
                let destination = tool_path_resource(destination);
                add_effect(
                    builder,
                    "filesystem.move",
                    source.clone(),
                    BTreeMap::from([("hunks".to_string(), byte_count(hunks))]),
                    provenance.clone(),
                );
                let mut attributes = BTreeMap::from([
                    ("hunks".to_string(), byte_count(hunks)),
                    ("move_destination".to_string(), AttrValue::Bool(true)),
                ]);
                if let Some(content) = written_content {
                    attributes.insert("written_content".into(), AttrValue::String(content));
                }
                add_effect(
                    builder,
                    "filesystem.write",
                    destination.clone(),
                    attributes,
                    destination_provenance.clone(),
                );
                targets.push((source, provenance));
                targets.push((destination, destination_provenance));
                continue;
            }
        };
        if let Some(content) = written_content {
            attributes.insert("written_content".into(), AttrValue::String(content));
        }
        let resource = resolve_literal_tool_path(&path, cwd, context);
        let provenance = vec![text_node];
        let resource = tool_path_resource(resource);
        add_effect(
            builder,
            operation,
            resource.clone(),
            attributes,
            provenance.clone(),
        );
        targets.push((resource, provenance));
    }
    declare_path_coverage(builder, targets);
}

fn patch_boundary(
    builder: &mut PlanBuilder,
    reason: BoundaryReason,
    class: BoundaryClass,
    limit: Option<&str>,
    provenance: ProvenanceRef,
) {
    builder.boundary_with_coverage_in_domain(
        Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new(FILESYSTEM)],
            affected_resource: None,
            callee: None,
            provenance: vec![provenance],
            limit: limit.map(str::to_string),
            detail: None,
        },
        CoverageLevel::None,
        FILESYSTEM,
    );
}
