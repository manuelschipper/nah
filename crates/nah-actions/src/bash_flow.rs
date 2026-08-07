//! Connects visible Bash stage and artifact flows; it does not infer hidden execution.

use std::collections::BTreeMap;

use nah_parse::Redirect;
use nah_proto::action::{FilesystemOperation, SemanticCode};
use nah_proto::ctx::Platform;

use crate::bash_model::{FilesystemDraft, InvocationDraft, ProgramDraft, StageDraft};
use crate::paths::contains;

pub(crate) fn add_artifact_flows(
    stages: &[StageDraft],
    flows: &mut Vec<(usize, usize)>,
    platform: Platform,
) {
    for sink in 0..stages.len() {
        for read in stages[sink]
            .filesystems
            .iter()
            .filter(|effect| effect.operation == FilesystemOperation::Read)
        {
            for source in 0..sink {
                for written in stages[source].filesystems.iter().filter(|effect| {
                    effect.operation == FilesystemOperation::Write
                        && effect.content_access
                        && consumed_by(effect, read, platform)
                }) {
                    let removed =
                        stages[source + 1..sink]
                            .iter()
                            .enumerate()
                            .any(|(offset, stage)| {
                                let stage_index = source + 1 + offset;
                                (stage.conditional_depth == 0
                                    || stages[sink].execution_dominators.contains(&stage_index))
                                    && stage.filesystems.iter().any(|effect| {
                                        match effect.operation {
                                            FilesystemOperation::Delete => {
                                                removes(effect, written, platform)
                                            }
                                            FilesystemOperation::Write => {
                                                replaces(effect, written, platform)
                                            }
                                            FilesystemOperation::Read => false,
                                        }
                                    })
                            });
                    if !removed {
                        flows.push((source, sink));
                    }
                }
            }
        }
    }
    for sink in 0..stages.len() {
        if !moves_artifact(&stages[sink]) {
            continue;
        }
        for deleted in stages[sink]
            .filesystems
            .iter()
            .filter(|effect| effect.operation == FilesystemOperation::Delete)
        {
            let source = (0..sink).rev().find_map(|source| {
                stages[source]
                    .filesystems
                    .iter()
                    .rev()
                    .find(|effect| effect.requested == deleted.requested)
                    .map(|effect| (source, effect.operation))
            });
            if let Some((source, FilesystemOperation::Write)) = source {
                flows.push((source, sink));
            }
        }
    }
    add_fifo_flows(stages, flows, platform);
    flows.sort_unstable();
    flows.dedup();
}

pub(crate) fn add_reverse_artifact_candidates(
    stages: &[StageDraft],
    flows: &mut Vec<(usize, usize)>,
    platform: Platform,
) {
    for (reader, stage) in stages.iter().enumerate() {
        for read in stage
            .filesystems
            .iter()
            .filter(|effect| effect.operation == FilesystemOperation::Read)
        {
            for (writer, stage) in stages.iter().enumerate().skip(reader + 1) {
                if stage.filesystems.iter().any(|effect| {
                    effect.operation == FilesystemOperation::Write
                        && effect.content_access
                        && consumed_by(effect, read, platform)
                }) {
                    flows.push((writer, reader));
                }
            }
        }
    }
    flows.sort_unstable();
    flows.dedup();
}

fn consumed_by(written: &FilesystemDraft, read: &FilesystemDraft, platform: Platform) -> bool {
    same_path(&written.requested, &read.requested, platform)
        || read.recursive
            && (contains(&read.requested, &written.requested, platform)
                || contains(&written.requested, &read.requested, platform))
}

fn removes(deleted: &FilesystemDraft, written: &FilesystemDraft, platform: Platform) -> bool {
    same_path(&deleted.requested, &written.requested, platform)
        || deleted.recursive && contains(&deleted.requested, &written.requested, platform)
}

fn replaces(replacement: &FilesystemDraft, written: &FilesystemDraft, platform: Platform) -> bool {
    replacement.content_access && same_path(&replacement.requested, &written.requested, platform)
}

fn same_path(left: &str, right: &str, platform: Platform) -> bool {
    contains(left, right, platform) && contains(right, left, platform)
}

fn add_fifo_flows(stages: &[StageDraft], flows: &mut Vec<(usize, usize)>, platform: Platform) {
    add_fifo_flows_with_markers(stages, flows, platform, Vec::new());
}

pub(crate) fn add_fifo_flows_with_markers(
    stages: &[StageDraft],
    flows: &mut Vec<(usize, usize)>,
    platform: Platform,
    mut fifos: Vec<(String, bool)>,
) {
    for stage in stages {
        if matches!(stage_program(stage), Some("mkfifo" | "mknod")) {
            fifos.extend(
                stage
                    .filesystems
                    .iter()
                    .filter(|effect| effect.operation == FilesystemOperation::Write)
                    .map(|effect| (effect.requested.clone(), effect.pattern)),
            );
        }
        if let Some((source, target, moved)) = alias_transform(stage)
            && fifos
                .iter()
                .any(|(fifo, pattern)| fifo_marker_matches(fifo, *pattern, &source, platform))
        {
            if moved {
                fifos.retain(|(fifo, pattern)| {
                    !fifo_marker_matches(fifo, *pattern, &source, platform)
                });
            }
            fifos.push((target, false));
        }
    }
    for (reader, stage) in stages.iter().enumerate() {
        for read in stage
            .filesystems
            .iter()
            .filter(|effect| effect.operation == FilesystemOperation::Read)
        {
            if !fifos.iter().any(|(fifo, pattern)| {
                fifo_marker_matches(fifo, *pattern, &read.requested, platform)
            }) {
                continue;
            }
            for (writer, stage) in stages.iter().enumerate() {
                if writer == reader || stage_program(stage) == Some("mkfifo") {
                    continue;
                }
                if stage.filesystems.iter().any(|effect| {
                    effect.operation == FilesystemOperation::Write
                        && effect.content_access
                        && same_path(&effect.requested, &read.requested, platform)
                }) {
                    flows.push((writer, reader));
                }
            }
        }
    }
    flows.sort_unstable();
    flows.dedup();
}

fn fifo_marker_matches(marker: &str, pattern: bool, path: &str, platform: Platform) -> bool {
    if !pattern {
        return same_path(marker, path, platform);
    }
    let bound = nah_proto::action::pattern_bound(marker);
    if platform == Platform::Windows {
        path.replace('\\', "/")
            .to_ascii_lowercase()
            .starts_with(&bound.replace('\\', "/").to_ascii_lowercase())
    } else {
        path.starts_with(bound)
    }
}

pub(crate) fn add_artifact_identities(stages: &mut [StageDraft], platform: Platform) {
    let mut identities = BTreeMap::<String, (String, Vec<String>)>::new();
    for stage in stages {
        let transform = alias_transform(stage);
        for filesystem in &mut stage.filesystems {
            let replaces_alias = transform.as_ref().is_some_and(|(_, target, _)| {
                filesystem.operation == FilesystemOperation::Write
                    && filesystem.requested == *target
            });
            if !replaces_alias
                && let Some((identity, requirements)) =
                    identities.get(&identity_key(&filesystem.requested, platform))
            {
                filesystem.identity = Some(identity.clone());
                filesystem.identity_requirements = requirements.clone();
            }
        }

        let Some((source, target, moved)) = transform else {
            for filesystem in &stage.filesystems {
                if filesystem.operation == FilesystemOperation::Delete {
                    if filesystem.recursive {
                        identities.retain(|path, _| {
                            !same_path(path, &filesystem.requested, platform)
                                && !contains(&filesystem.requested, path, platform)
                        });
                    } else {
                        identities.remove(&identity_key(&filesystem.requested, platform));
                    }
                }
            }
            continue;
        };
        let (identity, mut requirements) = identities
            .get(&identity_key(&source, platform))
            .cloned()
            .unwrap_or((source.clone(), Vec::new()));
        if alias_requires_missing_target(stage) {
            let Some(requirement) = stage
                .filesystems
                .iter()
                .find(|filesystem| {
                    filesystem.operation == FilesystemOperation::Write
                        && filesystem.requested == target
                })
                .and_then(|filesystem| filesystem.key.clone())
            else {
                continue;
            };
            requirements.push(requirement);
        }
        if moved {
            identities.remove(&identity_key(&source, platform));
        }
        identities.insert(identity_key(&target, platform), (identity, requirements));
    }
}

fn alias_requires_missing_target(stage: &StageDraft) -> bool {
    if stage_program(stage) != Some("ln") {
        return true;
    }
    let argv = match &stage.invocation {
        InvocationDraft::Known { argv, .. }
        | InvocationDraft::CodeExecution { argv, .. }
        | InvocationDraft::Opaque { argv, .. } => argv.as_deref(),
        InvocationDraft::Native { .. } => None,
    };
    !argv.is_some_and(|argv| {
        argv.iter()
            .skip(1)
            .take_while(|argument| *argument != "--")
            .any(|argument| {
                argument == "--force"
                    || argument
                        .strip_prefix('-')
                        .is_some_and(|flags| !flags.starts_with('-') && flags.contains('f'))
            })
    })
}

fn identity_key(path: &str, platform: Platform) -> String {
    let path = path.trim_end_matches(['/', '\\']).replace('\\', "/");
    if platform == Platform::Windows {
        path.to_ascii_lowercase()
    } else {
        path
    }
}

fn alias_transform(stage: &StageDraft) -> Option<(String, String, bool)> {
    let program = match &stage.invocation {
        InvocationDraft::Known { program, .. } | InvocationDraft::CodeExecution { program, .. } => {
            program.as_str()
        }
        InvocationDraft::Opaque {
            program: ProgramDraft::Static(program),
            ..
        } => program.as_str(),
        InvocationDraft::Opaque {
            program: ProgramDraft::Env { .. } | ProgramDraft::Unresolved,
            ..
        }
        | InvocationDraft::Native { .. } => return None,
    };
    if target_directory_form(stage) {
        return None;
    }
    let source_operation = match program {
        "ln" | "link" => FilesystemOperation::Read,
        "mv" => FilesystemOperation::Delete,
        _ => return None,
    };
    let sources = stage
        .filesystems
        .iter()
        .filter(|filesystem| filesystem.operation == source_operation)
        .collect::<Vec<_>>();
    let targets = stage
        .filesystems
        .iter()
        .filter(|filesystem| filesystem.operation == FilesystemOperation::Write)
        .collect::<Vec<_>>();
    let ([source], [target]) = (sources.as_slice(), targets.as_slice()) else {
        return None;
    };
    (!source.pattern && !target.pattern && !target.requested.ends_with(['/', '\\'])).then(|| {
        (
            source.requested.clone(),
            target.requested.clone(),
            program == "mv",
        )
    })
}

fn target_directory_form(stage: &StageDraft) -> bool {
    let argv = match &stage.invocation {
        InvocationDraft::Known { argv, .. }
        | InvocationDraft::CodeExecution { argv, .. }
        | InvocationDraft::Opaque { argv, .. } => argv.as_deref(),
        InvocationDraft::Native { .. } => None,
    };
    argv.is_some_and(|argv| {
        argv.iter().skip(1).any(|argument| {
            matches!(argument.as_str(), "-t" | "--target-directory")
                || argument.starts_with("--target-directory=")
                || argument
                    .strip_prefix("-t")
                    .is_some_and(|value| !value.is_empty())
        })
    })
}

fn moves_artifact(stage: &StageDraft) -> bool {
    matches!(
        &stage.invocation,
        InvocationDraft::Known { program, operation, .. }
            if program == "mv" && operation == &SemanticCode::MOVE
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

pub(crate) fn redirects_stdin(redirects: &[Redirect]) -> bool {
    redirects.iter().any(|redirect| {
        matches!(redirect.fd(), None | Some("0"))
            && matches!(
                redirect.operator(),
                "<" | "<>" | "<&" | "<<" | "<<-" | "<<<"
            )
            && !matches!(
                redirect.target(),
                Some("0" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
            )
    })
}

pub(crate) fn redirects_stdout(redirects: &[Redirect]) -> bool {
    redirects.iter().any(|redirect| {
        ((matches!(redirect.fd(), None | Some("1"))
            && matches!(redirect.operator(), ">" | ">>" | ">|" | ">&"))
            || matches!(redirect.operator(), "&>" | "&>>"))
            && !matches!(
                redirect.target(),
                Some("1" | "/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1")
            )
    })
}
