//! Selects network-reachable filesystem operations that need bounded descendant facts.

use std::collections::BTreeSet;

use nah_proto::action::{FilesystemOperation, NetworkDirection, SemanticCode};
use nah_proto::ctx::Platform;
use nah_proto::observation::{ObservationQuery, SymlinkTraversal};

use crate::bash_flow::add_reverse_artifact_candidates;
use crate::bash_model::{InvocationDraft, ProgramDraft, StageDraft};

pub(crate) fn add_recursive_descendant_inspections(
    stages: &mut [StageDraft],
    flows: &[(usize, usize)],
    queries: &mut Vec<ObservationQuery>,
    platform: Platform,
) {
    let mut reachability_flows = flows.to_vec();
    add_reverse_artifact_candidates(stages, &mut reachability_flows, platform);
    let mut reachable = stages
        .iter()
        .enumerate()
        .filter_map(|(index, stage)| network_sink(stage).then_some(index))
        .collect::<BTreeSet<_>>();
    let mut pending = reachable.iter().copied().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        for source in reachability_flows
            .iter()
            .filter_map(|(source, sink)| (*sink == target).then_some(*source))
        {
            if reachable.insert(source) {
                pending.push(source);
            }
        }
    }

    for stage in reachable.iter().copied() {
        let link_stage = matches!(stage_program(&stages[stage]), Some("ln" | "link"));
        let symbolic_link = link_stage && stage_is_symbolic_link(&stages[stage]);
        let linked_content = link_stage
            && stages[stage]
                .filesystems
                .iter()
                .filter(|filesystem| filesystem.operation == FilesystemOperation::Write)
                .any(|written| {
                    stages
                        .iter()
                        .enumerate()
                        .skip(stage + 1)
                        .filter(|(index, _)| reachable.contains(index))
                        .flat_map(|(_, later)| later.filesystems.iter())
                        .any(|read| {
                            read.operation == FilesystemOperation::Read
                                && read.recursive
                                && (!symbolic_link
                                    || read.symlink_traversal != SymlinkTraversal::None)
                                && paths_overlap(&written.requested, &read.requested, platform)
                        })
                });
        let moves_content = matches!(
            &stages[stage].invocation,
            InvocationDraft::Known { operation, .. } if operation == &SemanticCode::MOVE
        );
        for filesystem in &mut stages[stage].filesystems {
            if linked_content && filesystem.operation == FilesystemOperation::Read {
                filesystem.content_access = true;
                filesystem.network_bound = true;
                filesystem.unresolved_selection = symbolic_link;
                continue;
            }
            if !filesystem.content_access
                || !(filesystem.operation == FilesystemOperation::Read
                    || moves_content && filesystem.operation == FilesystemOperation::Delete)
            {
                continue;
            }
            filesystem.network_bound = true;
            if !(filesystem.recursive
                || filesystem.pattern
                || moves_content && filesystem.operation == FilesystemOperation::Delete)
            {
                continue;
            }
            let key = if let Some(key) = &filesystem.key {
                key.clone()
            } else if filesystem.pattern {
                let requested = pattern_observation_root(&filesystem.requested, platform);
                let path_count = queries
                    .iter()
                    .filter(|query| matches!(query, ObservationQuery::Path { .. }))
                    .count();
                let key = format!("path-{path_count}");
                queries.push(ObservationQuery::Path {
                    key: key.clone(),
                    requested,
                    cwd_key: "cwd".into(),
                    inspect_descendants: false,
                    symlink_traversal: SymlinkTraversal::None,
                });
                key
            } else {
                continue;
            };
            filesystem.descendant_key = Some(key.clone());
            if let Some(ObservationQuery::Path {
                inspect_descendants,
                symlink_traversal,
                ..
            }) = queries.iter_mut().find(|query| query.key() == key)
            {
                *inspect_descendants = true;
                *symlink_traversal = (*symlink_traversal).max(filesystem.symlink_traversal);
            }
        }
    }
}

fn network_sink(stage: &StageDraft) -> bool {
    stage
        .network_endpoints
        .iter()
        .any(|(direction, _)| *direction == NetworkDirection::Outbound)
        || stage.network_outbound
            && matches!(
                &stage.invocation,
                InvocationDraft::Known { operation, .. } | InvocationDraft::Native { operation, .. }
                    if operation == &SemanticCode::NETWORK_TRANSFER
                        || operation == &SemanticCode::NETWORK_LISTENER
            )
}

fn stage_program(stage: &StageDraft) -> Option<&str> {
    match &stage.invocation {
        InvocationDraft::Known { program, .. } | InvocationDraft::CodeExecution { program, .. } => {
            Some(program)
        }
        InvocationDraft::Opaque {
            program: ProgramDraft::Static(program),
            ..
        } => Some(program),
        InvocationDraft::Opaque {
            program: ProgramDraft::Env { .. } | ProgramDraft::Unresolved,
            ..
        }
        | InvocationDraft::Native { .. } => None,
    }
}

fn stage_is_symbolic_link(stage: &StageDraft) -> bool {
    if stage_program(stage) != Some("ln") {
        return false;
    }
    let argv = match &stage.invocation {
        InvocationDraft::Known { argv, .. }
        | InvocationDraft::CodeExecution { argv, .. }
        | InvocationDraft::Opaque { argv, .. } => argv.as_deref(),
        InvocationDraft::Native { .. } => None,
    };
    argv.is_some_and(|argv| {
        argv.iter()
            .skip(1)
            .take_while(|argument| *argument != "--")
            .any(|argument| {
                argument == "--symbolic"
                    || argument
                        .strip_prefix('-')
                        .is_some_and(|flags| !flags.starts_with('-') && flags.contains('s'))
            })
    })
}

fn paths_overlap(left: &str, right: &str, platform: Platform) -> bool {
    crate::paths::contains(left, right, platform) || crate::paths::contains(right, left, platform)
}

pub(crate) fn pattern_observation_root(requested: &str, platform: Platform) -> String {
    let bound = nah_proto::action::pattern_bound(requested);
    let trimmed = if platform == Platform::Windows {
        bound.trim_end_matches(['/', '\\'])
    } else {
        bound.trim_end_matches('/')
    };
    if platform == Platform::Windows
        && trimmed.len() == 2
        && trimmed.as_bytes().get(1) == Some(&b':')
        && bound.len() != trimmed.len()
    {
        return format!("{trimmed}\\");
    }
    if bound.len() != trimmed.len() && !trimmed.is_empty() {
        return trimmed.to_owned();
    }
    let index = if platform == Platform::Windows {
        trimmed.rfind(['/', '\\'])
    } else {
        trimmed.rfind('/')
    };
    match index {
        Some(0) => requested[..1].to_owned(),
        Some(index) => trimmed[..index].to_owned(),
        None => requested.to_owned(),
    }
}
