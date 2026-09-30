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
            let remote = ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("net"),
            };
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
            let attributes = BTreeMap::from([
                ("in_place".to_string(), AttrValue::Bool(true)),
                ("new_bytes".to_string(), byte_count(args.new.len())),
                ("occurrences".to_string(), occurrences),
                ("old_bytes".to_string(), byte_count(args.old.len())),
            ]);
            let path = tool_path_resource(path);
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
            for (index, edit) in args.edits.iter().enumerate() {
                let path = resolve_literal_tool_path(&args.path, cwd, context);
                let provenance = vec![
                    tool_argument(builder, "path"),
                    tool_argument(builder, &format!("edits[{index}].old")),
                    tool_argument(builder, &format!("edits[{index}].new")),
                ];
                let attributes = BTreeMap::from([
                    ("batch".to_string(), AttrValue::Bool(true)),
                    ("batch_index".to_string(), AttrValue::Int(index as i64)),
                    ("in_place".to_string(), AttrValue::Bool(true)),
                    ("new_bytes".to_string(), byte_count(edit.new.len())),
                    (
                        "occurrences".to_string(),
                        AttrValue::String("unknown".to_string()),
                    ),
                    ("old_bytes".to_string(), byte_count(edit.old.len())),
                ]);
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
            add_effect(
                builder,
                "filesystem.read",
                resource.clone(),
                BTreeMap::new(),
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
            let filter = AttrValue::String(args.pattern.clone());
            let filter_node = tool_argument(builder, "pattern");
            let mut targets = Vec::new();
            if let Some(paths) = &args.paths {
                for (index, path) in paths.iter().enumerate() {
                    let resource = args.root.as_deref().map_or_else(
                        || resolve_literal_tool_path(path, cwd, context),
                        |root| resolve_literal_tool_path_under_root(path, root, cwd, context),
                    );
                    let mut provenance = vec![
                        tool_argument(builder, &format!("paths[{index}]")),
                        filter_node,
                    ];
                    if args.root.is_some() {
                        provenance.push(tool_argument(builder, "root"));
                    }
                    let resource = tool_path_resource(resource);
                    add_effect(
                        builder,
                        "filesystem.read",
                        resource.clone(),
                        BTreeMap::from([("content_filter".to_string(), filter.clone())]),
                        provenance.clone(),
                    );
                    targets.push((resource, provenance));
                }
            } else {
                let resource =
                    resolve_literal_tool_pattern("**", args.root.as_deref(), cwd, context);
                let mut provenance = vec![filter_node];
                if args.root.is_some() {
                    provenance.push(tool_argument(builder, "root"));
                }
                let resource = tool_path_resource(resource);
                add_effect(
                    builder,
                    "filesystem.read",
                    resource.clone(),
                    BTreeMap::from([("content_filter".to_string(), filter)]),
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatchOperation {
    Add {
        path: String,
        hunks: usize,
    },
    Delete {
        path: String,
        hunks: usize,
    },
    Modify {
        path: String,
        hunks: usize,
    },
    Move {
        from: String,
        to: String,
        hunks: usize,
    },
}

enum PatchError {
    Parse,
    Limit(&'static str),
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
            PatchFormat::Unified => parse_unified(text, max_files),
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
        let (path, operation, attributes) = match operation {
            PatchOperation::Add { path, hunks } => (
                path,
                "filesystem.create",
                BTreeMap::from([("hunks".to_string(), byte_count(hunks))]),
            ),
            PatchOperation::Delete { path, hunks } => (
                path,
                "filesystem.delete",
                BTreeMap::from([("hunks".to_string(), byte_count(hunks))]),
            ),
            PatchOperation::Modify { path, hunks } => (
                path,
                "filesystem.write",
                BTreeMap::from([
                    ("hunks".to_string(), byte_count(hunks)),
                    ("in_place".to_string(), AttrValue::Bool(true)),
                ]),
            ),
            PatchOperation::Move { from, to, hunks } => {
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
                add_effect(
                    builder,
                    "filesystem.write",
                    destination.clone(),
                    BTreeMap::from([
                        ("hunks".to_string(), byte_count(hunks)),
                        ("move_destination".to_string(), AttrValue::Bool(true)),
                    ]),
                    destination_provenance.clone(),
                );
                targets.push((source, provenance));
                targets.push((destination, destination_provenance));
                continue;
            }
        };
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

fn push_operation(
    operations: &mut Vec<PatchOperation>,
    operation: PatchOperation,
    max_files: u64,
) -> Result<(), PatchError> {
    operations.push(operation);
    if operations.len() as u64 > max_files {
        Err(PatchError::Limit("max_patch_files"))
    } else {
        Ok(())
    }
}

fn parse_unified(text: &str, max_files: u64) -> Result<Vec<PatchOperation>, PatchError> {
    let lines = text.lines().collect::<Vec<_>>();
    let mut operations = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].is_empty() {
            index += 1;
            continue;
        }
        if lines[index].starts_with("diff --git ") {
            let start = index;
            index += 1;
            while index < lines.len() && !lines[index].starts_with("diff --git ") {
                index += 1;
            }
            let operation = parse_git_section(&lines[start..index])?;
            push_operation(&mut operations, operation, max_files)?;
        } else if lines[index].starts_with("--- ") {
            let (operation, next) = parse_plain_section(&lines, index)?;
            push_operation(&mut operations, operation, max_files)?;
            index = next;
        } else {
            return Err(PatchError::Parse);
        }
    }
    if operations.is_empty() {
        Err(PatchError::Parse)
    } else {
        Ok(operations)
    }
}

fn parse_plain_section(
    lines: &[&str],
    start: usize,
) -> Result<(PatchOperation, usize), PatchError> {
    let old = header_path(lines[start], "--- ")?;
    let new = lines
        .get(start + 1)
        .ok_or(PatchError::Parse)
        .and_then(|line| header_path(line, "+++ "))?;
    let raw_old = raw_header_path(lines[start], "--- ")?;
    let raw_new = raw_header_path(lines[start + 1], "+++ ")?;
    if old != "/dev/null"
        && new != "/dev/null"
        && conventional_prefix(raw_old).is_empty() != conventional_prefix(raw_new).is_empty()
    {
        return Err(PatchError::Parse);
    }
    let mut index = start + 2;
    let mut hunks = 0;
    while index < lines.len()
        && !lines[index].starts_with("--- ")
        && !lines[index].starts_with("diff --git ")
    {
        if lines[index].is_empty() {
            index += 1;
            continue;
        }
        if !lines[index].starts_with("@@ ") {
            return Err(PatchError::Parse);
        }
        let (next, old_count, new_count) = parse_unified_hunk(lines, index)?;
        validate_unified_null_counts(&old, &new, old_count, new_count)?;
        index = next;
        hunks += 1;
    }
    if hunks == 0 {
        return Err(PatchError::Parse);
    }
    Ok((operation_from_headers(old, new, hunks)?, index))
}

fn parse_git_section(lines: &[&str]) -> Result<PatchOperation, PatchError> {
    let preamble = lines.first().ok_or(PatchError::Parse)?;
    let paths = preamble
        .strip_prefix("diff --git ")
        .ok_or(PatchError::Parse)?;
    let mut old = None;
    let mut new = None;
    let mut rename_from = None;
    let mut rename_to = None;
    let mut binary = false;
    let mut binary_payload = false;
    let mut new_file = false;
    let mut deleted_file = false;
    let mut index_metadata = false;
    let mut old_mode = false;
    let mut new_mode = false;
    let mut similarity = false;
    let mut dissimilarity = false;
    let mut hunks = 0;
    let mut index = 1;
    while index < lines.len() {
        let line = lines[index];
        if binary_payload {
            index += 1;
            continue;
        }
        if let Some(path) = line.strip_prefix("rename from ") {
            if rename_from.replace(path.to_string()).is_some() || path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
        } else if let Some(path) = line.strip_prefix("rename to ") {
            if rename_to.replace(path.to_string()).is_some() || path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
        } else if line.starts_with("--- ") {
            if old.is_some() || index + 1 >= lines.len() {
                return Err(PatchError::Parse);
            }
            old = Some(raw_header_path(line, "--- ")?.to_string());
            index += 1;
            new = Some(raw_header_path(lines[index], "+++ ")?.to_string());
            index += 1;
        } else if line.starts_with("@@ ") {
            if old.is_none() || new.is_none() {
                return Err(PatchError::Parse);
            }
            let (next, old_count, new_count) = parse_unified_hunk(lines, index)?;
            validate_unified_null_counts(
                old.as_deref().ok_or(PatchError::Parse)?,
                new.as_deref().ok_or(PatchError::Parse)?,
                old_count,
                new_count,
            )?;
            index = next;
            hunks += 1;
        } else if line.starts_with("Binary files ") && line.ends_with(" differ") {
            let marker = line
                .strip_prefix("Binary files ")
                .and_then(|line| line.strip_suffix(" differ"))
                .ok_or(PatchError::Parse)?;
            if !marker.contains(" and ") {
                return Err(PatchError::Parse);
            }
            // Filenames may contain " and ", so the preamble remains the path source.
            binary = true;
            index += 1;
        } else if line == "GIT binary patch" {
            binary = true;
            binary_payload = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            if new_file || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            new_file = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            if deleted_file || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            deleted_file = true;
            index += 1;
        } else if let Some(value) = line.strip_prefix("index ") {
            if index_metadata || !valid_git_index(value) {
                return Err(PatchError::Parse);
            }
            index_metadata = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            if old_mode || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            old_mode = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            if new_mode || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            new_mode = true;
            index += 1;
        } else if let Some(value) = line.strip_prefix("similarity index ") {
            if similarity || !valid_git_percentage(value) {
                return Err(PatchError::Parse);
            }
            similarity = true;
            index += 1;
        } else if let Some(value) = line.strip_prefix("dissimilarity index ") {
            if dissimilarity || !valid_git_percentage(value) {
                return Err(PatchError::Parse);
            }
            dissimilarity = true;
            index += 1;
        } else if line.is_empty() {
            index += 1;
        } else {
            return Err(PatchError::Parse);
        }
    }

    let candidates = paths
        .match_indices(' ')
        .filter_map(|(index, _)| {
            let (old, new) = (&paths[..index], &paths[index + 1..]);
            if old.is_empty()
                || new.is_empty()
                || !conventional_prefix(paths).is_empty() && conventional_prefix(new).is_empty()
            {
                None
            } else {
                Some((old, new))
            }
        })
        .collect::<Vec<_>>();
    let (raw_old, raw_new) = if let [(old, new)] = candidates.as_slice() {
        (old.to_string(), new.to_string())
    } else {
        // Headers or rename metadata disambiguate spaces; binary payloads cannot.
        let named_old = rename_from.as_deref().or_else(|| {
            old.as_deref()
                .filter(|path| *path != "/dev/null")
                .map(strip_conventional_prefix)
        });
        let named_new = rename_to.as_deref().or_else(|| {
            new.as_deref()
                .filter(|path| *path != "/dev/null")
                .map(strip_conventional_prefix)
        });
        let old_path = named_old.or(named_new).ok_or(PatchError::Parse)?;
        let new_path = named_new.or(named_old).ok_or(PatchError::Parse)?;
        let mut matches = Vec::new();
        for p in CONVENTIONAL_PREFIXES.into_iter().chain([""]) {
            for q in CONVENTIONAL_PREFIXES.into_iter().chain([""]) {
                let raw_old = format!("{p}{old_path}");
                let raw_new = format!("{q}{new_path}");
                if paths == format!("{raw_old} {raw_new}") {
                    matches.push((raw_old, raw_new));
                }
            }
        }
        if matches.len() != 1 {
            return Err(PatchError::Parse);
        }
        matches.pop().unwrap()
    };
    let preamble_old = strip_conventional_prefix(&raw_old).to_string();
    let preamble_new = strip_conventional_prefix(&raw_new).to_string();
    if preamble_old.is_empty() || preamble_new.is_empty() {
        return Err(PatchError::Parse);
    }

    if new_file && deleted_file
        || old_mode != new_mode
        || similarity && dissimilarity
        || (new_file || deleted_file) && (old_mode || rename_from.is_some())
        || (rename_from.is_some() || rename_to.is_some())
            && (old.as_deref() == Some("/dev/null") || new.as_deref() == Some("/dev/null"))
    {
        return Err(PatchError::Parse);
    }
    if let (Some(old), Some(new)) = (old.as_deref(), new.as_deref())
        && (old != "/dev/null" && old != raw_old
            || new != "/dev/null" && new != raw_new
            || new_file && old != "/dev/null"
            || deleted_file && new != "/dev/null")
    {
        return Err(PatchError::Parse);
    }
    if rename_from
        .as_deref()
        .is_some_and(|path| path != preamble_old)
        || rename_to
            .as_deref()
            .is_some_and(|path| path != preamble_new)
    {
        return Err(PatchError::Parse);
    }
    match (rename_from, rename_to) {
        (Some(from), Some(to)) => Ok(PatchOperation::Move { from, to, hunks }),
        (Some(_), None) | (None, Some(_)) => Err(PatchError::Parse),
        (None, None) => {
            if let (Some(old), Some(new)) = (old, new) {
                if hunks == 0 && !binary {
                    return Err(PatchError::Parse);
                }
                operation_from_headers(
                    strip_conventional_prefix(&old).to_string(),
                    strip_conventional_prefix(&new).to_string(),
                    hunks,
                )
            } else if binary && new_file {
                Ok(PatchOperation::Add {
                    path: preamble_new,
                    hunks: 0,
                })
            } else if binary && deleted_file {
                Ok(PatchOperation::Delete {
                    path: preamble_old,
                    hunks: 0,
                })
            } else if binary && preamble_old == preamble_new {
                Ok(PatchOperation::Modify {
                    path: preamble_new,
                    hunks: 0,
                })
            } else {
                Err(PatchError::Parse)
            }
        }
    }
}

fn valid_git_mode(value: &str) -> bool {
    matches!(value, "100644" | "100755" | "120000" | "160000")
}

fn valid_git_index(value: &str) -> bool {
    let mut fields = value.split_ascii_whitespace();
    let Some(objects) = fields.next() else {
        return false;
    };
    let Some((old, new)) = objects.split_once("..") else {
        return false;
    };
    if old.is_empty()
        || new.is_empty()
        || !old.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !new.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    fields.next().is_none_or(valid_git_mode) && fields.next().is_none()
}

fn valid_git_percentage(value: &str) -> bool {
    value
        .strip_suffix('%')
        .and_then(|number| number.parse::<u8>().ok())
        .is_some_and(|number| number <= 100)
}

fn raw_header_path<'a>(line: &'a str, marker: &str) -> Result<&'a str, PatchError> {
    let value = line.strip_prefix(marker).ok_or(PatchError::Parse)?;
    let path = value.split_once('\t').map_or(value, |(path, _)| path);
    if path.is_empty() {
        return Err(PatchError::Parse);
    }
    Ok(path)
}

fn header_path(line: &str, marker: &str) -> Result<String, PatchError> {
    let path = strip_conventional_prefix(raw_header_path(line, marker)?);
    if path.is_empty() {
        return Err(PatchError::Parse);
    }
    Ok(path.to_string())
}

const CONVENTIONAL_PREFIXES: [&str; 6] = ["a/", "b/", "i/", "w/", "c/", "o/"];

fn conventional_prefix(path: &str) -> &'static str {
    CONVENTIONAL_PREFIXES
        .into_iter()
        .find(|prefix| path.starts_with(prefix))
        .unwrap_or("")
}

fn strip_conventional_prefix(path: &str) -> &str {
    &path[conventional_prefix(path).len()..]
}

fn operation_from_headers(
    old: String,
    new: String,
    hunks: usize,
) -> Result<PatchOperation, PatchError> {
    match (old.as_str(), new.as_str()) {
        ("/dev/null", "/dev/null") => Err(PatchError::Parse),
        ("/dev/null", _) => Ok(PatchOperation::Add { path: new, hunks }),
        (_, "/dev/null") => Ok(PatchOperation::Delete { path: old, hunks }),
        _ if old == new => Ok(PatchOperation::Modify { path: new, hunks }),
        _ => Err(PatchError::Parse),
    }
}

fn validate_unified_null_counts(
    old: &str,
    new: &str,
    old_count: u64,
    new_count: u64,
) -> Result<(), PatchError> {
    if (old == "/dev/null" && old_count != 0) || (new == "/dev/null" && new_count != 0) {
        Err(PatchError::Parse)
    } else {
        Ok(())
    }
}

fn parse_unified_hunk(lines: &[&str], start: usize) -> Result<(usize, u64, u64), PatchError> {
    let (old_count, new_count) = unified_hunk_counts(lines[start])?;
    let mut old_seen = 0u64;
    let mut new_seen = 0u64;
    let mut changed = false;
    let mut index = start + 1;
    while old_seen < old_count
        || new_seen < new_count
        || lines.get(index) == Some(&"\\ No newline at end of file")
    {
        let line = *lines.get(index).ok_or(PatchError::Parse)?;
        if line == "\\ No newline at end of file" {
            let terminal = match lines[index - 1].as_bytes().first() {
                Some(b' ') => old_seen == old_count && new_seen == new_count,
                Some(b'+') => new_seen == new_count,
                Some(b'-') => old_seen == old_count,
                _ => false,
            };
            if !terminal {
                return Err(PatchError::Parse);
            }
            index += 1;
            continue;
        }
        match line.as_bytes().first() {
            Some(b' ') => {
                old_seen += 1;
                new_seen += 1;
            }
            Some(b'+') => {
                new_seen += 1;
                changed = true;
            }
            Some(b'-') => {
                old_seen += 1;
                changed = true;
            }
            _ => return Err(PatchError::Parse),
        }
        if old_seen > old_count || new_seen > new_count {
            return Err(PatchError::Parse);
        }
        index += 1;
    }
    if changed {
        Ok((index, old_count, new_count))
    } else {
        Err(PatchError::Parse)
    }
}

fn unified_hunk_counts(header: &str) -> Result<(u64, u64), PatchError> {
    let rest = header.strip_prefix("@@ -").ok_or(PatchError::Parse)?;
    let (old, rest) = rest.split_once(" +").ok_or(PatchError::Parse)?;
    let (new, suffix) = rest.split_once(" @@").ok_or(PatchError::Parse)?;
    if !suffix.is_empty() && !suffix.starts_with(' ') {
        return Err(PatchError::Parse);
    }
    Ok((range_count(old)?, range_count(new)?))
}

fn range_count(range: &str) -> Result<u64, PatchError> {
    let (start, count) = range.split_once(',').unwrap_or((range, "1"));
    start.parse::<u64>().map_err(|_| PatchError::Parse)?;
    count.parse::<u64>().map_err(|_| PatchError::Parse)
}

fn parse_apply_patch(text: &str, max_files: u64) -> Result<Vec<PatchOperation>, PatchError> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines.first() != Some(&"*** Begin Patch")
        || lines.last() != Some(&"*** End Patch")
        || lines
            .iter()
            .filter(|line| **line == "*** Begin Patch")
            .count()
            != 1
        || lines
            .iter()
            .filter(|line| **line == "*** End Patch")
            .count()
            != 1
    {
        return Err(PatchError::Parse);
    }
    let mut operations = Vec::new();
    let mut index = 1;
    while index + 1 < lines.len() {
        let line = lines[index];
        if let Some(path) = line.strip_prefix("*** Add File: ") {
            if path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
            while index + 1 < lines.len() && !lines[index].starts_with("*** ") {
                if !lines[index].starts_with('+') {
                    return Err(PatchError::Parse);
                }
                index += 1;
            }
            push_operation(
                &mut operations,
                PatchOperation::Add {
                    path: path.to_string(),
                    hunks: 0,
                },
                max_files,
            )?;
        } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
            if path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
            if index + 1 < lines.len() && !lines[index].starts_with("*** ") {
                return Err(PatchError::Parse);
            }
            push_operation(
                &mut operations,
                PatchOperation::Delete {
                    path: path.to_string(),
                    hunks: 0,
                },
                max_files,
            )?;
        } else if let Some(path) = line.strip_prefix("*** Update File: ") {
            if path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
            let mut move_to = None;
            if let Some(line) = lines.get(index)
                && let Some(path) = line.strip_prefix("*** Move to: ")
            {
                if path.is_empty() {
                    return Err(PatchError::Parse);
                }
                move_to = Some(path.to_string());
                index += 1;
            }
            let mut hunks = 0;
            while index + 1 < lines.len() && lines[index].starts_with("@@") {
                if lines[index] != "@@" && !lines[index].starts_with("@@ ") {
                    return Err(PatchError::Parse);
                }
                hunks += 1;
                index += 1;
                let mut body_lines = 0;
                let mut end_of_file = false;
                while index + 1 < lines.len()
                    && !lines[index].starts_with("@@")
                    && !lines[index].starts_with("*** Add File: ")
                    && !lines[index].starts_with("*** Delete File: ")
                    && !lines[index].starts_with("*** Update File: ")
                    && lines[index] != "*** End Patch"
                {
                    if lines[index] == "*** End of File" {
                        if end_of_file {
                            return Err(PatchError::Parse);
                        }
                        end_of_file = true;
                        index += 1;
                        break;
                    }
                    if !matches!(lines[index].as_bytes().first(), Some(b' ' | b'+' | b'-')) {
                        return Err(PatchError::Parse);
                    }
                    body_lines += 1;
                    index += 1;
                }
                if body_lines == 0 {
                    return Err(PatchError::Parse);
                }
                if end_of_file && index + 1 < lines.len() && !lines[index].starts_with("*** ") {
                    return Err(PatchError::Parse);
                }
            }
            if hunks == 0 {
                return Err(PatchError::Parse);
            }
            let operation = move_to.map_or_else(
                || PatchOperation::Modify {
                    path: path.to_string(),
                    hunks,
                },
                |to| PatchOperation::Move {
                    from: path.to_string(),
                    to,
                    hunks,
                },
            );
            push_operation(&mut operations, operation, max_files)?;
        } else {
            return Err(PatchError::Parse);
        }
    }
    if operations.is_empty() {
        Err(PatchError::Parse)
    } else {
        Ok(operations)
    }
}
