//! Retains normal filesystem and structural semantics at finalization.
//! Labels describe the already resolved mutation endpoint, including symlink identity.

use Knowledge::{Known, Unknown};
use nah_proto::action::{EffectKind, InvocationEffect, SemanticCode};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::effects::*;
use nah_proto::labels::{NahProtectionTier, PathScope};

fn resource(graph: &mut EffectGraph, kind: ResourceKind) -> ResourceId {
    let id = ResourceId(graph.resources.len() as u32);
    graph.resources.push(EffectResource {
        id,
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind,
            details: Unknown,
            provider: Unknown,
            name: Unknown,
        },
        selection: Selection::Unknown,
        labels: None,
    });
    id
}

fn fact(graph: &mut EffectGraph, payload: FactPayload) {
    graph.facts.push(EffectFact {
        id: FactId(graph.facts.len() as u32),
        call: CallId(0),
        realm: Realm::Host,
        certainty: Certainty::Exact,
        modality: Modality::May,
        condition: None,
        occurrences: None,
        payload,
    });
}

/// Retains call identity and distinguishes Git selection summaries from direct access.
pub(crate) struct FilesystemEvidenceContext<'a> {
    pub call: CallId,
    pub lexical_paths: &'a [(AbsolutePath, AbsolutePath)],
    pub git_managed_indices: &'a [usize],
    pub platform: Platform,
}

fn normalized_path(path: &AbsolutePath, platform: Platform) -> AbsolutePath {
    let mut normalized =
        crate::self_protection_tiers::lexically_normalized(path.as_str(), platform);
    if platform == Platform::Windows && normalized.ends_with(':') {
        normalized.push('\\');
    }
    AbsolutePath::new(platform, normalized).expect("normalized absolute filesystem identity")
}

fn path_resource(
    graph: &mut EffectGraph,
    filesystem: &nah_proto::action::FilesystemEffect,
    context: &FilesystemEvidenceContext<'_>,
) -> ResourceId {
    let id = resource(graph, ResourceKind::HostPath);
    let target = normalized_path(&filesystem.target, context.platform);
    let lexical = context
        .lexical_paths
        .iter()
        .find(|(target, _)| target == &filesystem.target)
        .map_or(&filesystem.target, |(_, lexical)| lexical);
    let lexical = normalized_path(lexical, context.platform);
    let resource = graph.resources.last_mut().expect("inserted resource");
    resource.identity.details = Known(ResourceDetails::Path {
        lexical: Known(target.clone()),
    });
    resource.selection = if filesystem.pattern {
        Selection::Pattern {
            pattern: target.as_str().to_owned(),
            bound: Bound::Unknown,
        }
    } else {
        Selection::Exact
    };
    resource.labels = Some(ResourceLabels {
        canonical: if lexical != target {
            Known(target.clone())
        } else {
            Unknown
        },
        lexical: Known(lexical),
        scope: Known(filesystem.scope.clone()),
        sensitivity: Known(filesystem.sensitivity),
        protection: Known(filesystem.protection),
        host_integrity: Known(filesystem.host_integrity.into_iter().collect()),
        selects_project: if matches!(filesystem.scope, PathScope::Project { .. })
            && filesystem.selects_root
        {
            Reach::Yes
        } else {
            Reach::No
        },
        selects_home: if filesystem.selects_home {
            Reach::Yes
        } else {
            Reach::No
        },
        selects_root: if target.as_str() == "/" {
            Reach::Yes
        } else {
            Reach::No
        },
        is_symlink: Unknown,
        link_target: Unknown,
        descendants_complete: Unknown,
        reach: vec![],
    });
    id
}

pub(crate) fn emit_stage(
    graph: &mut EffectGraph,
    effects: &[EffectKind],
    grants: Option<&PermissionGrants>,
    moves: &[(usize, usize)],
    operand_indices: &[usize],
    context: FilesystemEvidenceContext<'_>,
) {
    use nah_proto::action::FilesystemOperation as LegacyOperation;
    let operation = effects.iter().find_map(|effect| match effect {
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { operation, .. },
        } => Some(operation),
        _ => None,
    });
    let permission_change = operation.is_some_and(SemanticCode::is_permission_change);
    let moving = operation == Some(&SemanticCode::MOVE);
    let destination = moving
        .then(|| {
            effects
                .iter()
                .enumerate()
                .find_map(|(index, effect)| match effect {
                    EffectKind::Filesystem { effect }
                        if operand_indices.contains(&index)
                            && effect.operation == LegacyOperation::Write =>
                    {
                        Some(effect)
                    }
                    _ => None,
                })
        })
        .flatten();
    let unknown_grants = PermissionGrants {
        world_write: Unknown,
        setuid: Unknown,
        setgid: Unknown,
    };
    let mut emitted_permission = false;
    for (index, effect) in effects.iter().enumerate() {
        let patch_destination = moves
            .iter()
            .find(|(source, _)| *source == index)
            .and_then(|(_, destination)| effects.get(*destination))
            .and_then(|effect| match effect {
                EffectKind::Filesystem { effect } => Some(effect),
                _ => None,
            });
        match effect {
            EffectKind::Filesystem { .. } | EffectKind::FilesystemUnresolved { .. } => {
                let (target, operation, recursive) = match effect {
                    EffectKind::Filesystem { effect } => (
                        path_resource(graph, effect, &context),
                        effect.operation,
                        effect.recursive,
                    ),
                    EffectKind::FilesystemUnresolved {
                        operation,
                        recursive,
                    } => (
                        resource(graph, ResourceKind::HostPath),
                        *operation,
                        *recursive,
                    ),
                    _ => unreachable!(),
                };
                let operation = match operation {
                    LegacyOperation::Read => FilesystemOperation::Read,
                    LegacyOperation::Write
                        if permission_change && operand_indices.contains(&index) =>
                    {
                        FilesystemOperation::PermissionChange
                    }
                    LegacyOperation::Write => FilesystemOperation::Write,
                    LegacyOperation::Delete
                        if moving && operand_indices.contains(&index)
                            || patch_destination.is_some() =>
                    {
                        FilesystemOperation::Move
                    }
                    LegacyOperation::Delete => FilesystemOperation::Delete,
                };
                let destination = if operation == FilesystemOperation::Move {
                    Some(match patch_destination.or(destination) {
                        Some(path) => path_resource(graph, path, &context),
                        None => resource(graph, ResourceKind::HostPath),
                    })
                } else {
                    None
                };
                emitted_permission |= operation == FilesystemOperation::PermissionChange;
                fact(
                    graph,
                    FactPayload::FilesystemAccess {
                        operation,
                        target,
                        destination,
                        recursive: Known(recursive),
                        truncate: Unknown,
                        permissions: if operation == FilesystemOperation::PermissionChange {
                            grants.unwrap_or(&unknown_grants).clone()
                        } else {
                            unknown_grants.clone()
                        },
                        purpose: AccessPurpose::Unknown,
                    },
                );
                let emitted = graph.facts.last_mut().expect("inserted filesystem fact");
                emitted.call = context.call;
                // Git-managed selections retain their abstract filesystem reach,
                // but do not establish a direct metadata mutation.
                if !context.git_managed_indices.contains(&index) {
                    emitted.modality = Modality::MustOnSuccess;
                }
            }
            EffectKind::SystemState { operation } if operation == &SemanticCode::FORK_BOMB => fact(
                graph,
                FactPayload::ProcessGrowth {
                    background: Unknown,
                    repetition: Unknown,
                    launch_cycle: Unknown,
                    wait: Unknown,
                    dominator: Unknown,
                    growth: Bound::Unknown,
                    abstract_unbounded_spawn: Known(true),
                },
            ),
            EffectKind::SystemState { operation }
                if operation == &SemanticCode::STARTUP_MANAGEMENT =>
            {
                let target = resource(graph, ResourceKind::HostSystem);
                fact(
                    graph,
                    FactPayload::SystemChange {
                        target,
                        operation: SystemOperation::StartupChange,
                        selection: Selection::Unknown,
                        runtime_only: Known(false),
                        persistent: Known(true),
                        active: Known(true),
                        cancel: Known(false),
                        help: Known(false),
                    },
                );
            }
            EffectKind::Invocation {
                invocation:
                    InvocationEffect::Known {
                        program,
                        operation,
                        input,
                        cwd,
                    },
            } if operation == &SemanticCode::CRITICAL_MUTATION
                || operation == &SemanticCode::PERMANENT_MUTATION =>
            {
                let target = resource(graph, ResourceKind::Process);
                if let nah_proto::action::InvocationInput::Shell {
                    argv: Some(argv), ..
                } = input
                {
                    graph
                        .resources
                        .last_mut()
                        .expect("inserted resource")
                        .identity
                        .details = Known(ResourceDetails::Process {
                        executable: Known(program.clone()),
                        argv: Known(argv.iter().skip(1).cloned().collect()),
                        cwd: cwd.clone().map_or(Unknown, Known),
                    });
                }
                fact(
                    graph,
                    FactPayload::ControlMutation {
                        target,
                        action: ControlAction::Other,
                        candidate_identity: Unknown,
                        tier: Known(if operation == &SemanticCode::PERMANENT_MUTATION {
                            NahProtectionTier::Permanent
                        } else {
                            NahProtectionTier::Critical
                        }),
                    },
                );
                if !input.complete() {
                    graph
                        .facts
                        .last_mut()
                        .expect("inserted control fact")
                        .certainty = Certainty::Conservative;
                }
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::TerminalControl { control, .. },
            } => {
                use nah_proto::action::{TerminalCarrier, TerminalOperation};
                let target = resource(graph, ResourceKind::Process);
                graph
                    .resources
                    .last_mut()
                    .expect("inserted resource")
                    .identity
                    .provider = Known(
                    match control.carrier {
                        TerminalCarrier::Herdr => "herdr",
                        TerminalCarrier::Tmux => "tmux",
                        TerminalCarrier::OpenclawProcess => "openclaw",
                    }
                    .into(),
                );
                fact(
                    graph,
                    FactPayload::ControlInput {
                        target,
                        action: ControlAction::Deliver,
                        transport: match control.operation {
                            TerminalOperation::Input => ControlTransport::Input,
                            TerminalOperation::Submit => ControlTransport::Submit,
                            TerminalOperation::InputAndSubmit => ControlTransport::InputAndSubmit,
                            TerminalOperation::PasteUnknownBuffer => {
                                ControlTransport::UnknownBufferPaste
                            }
                            TerminalOperation::AgentPrompt => ControlTransport::AgentPrompt,
                        },
                        payload_certainty: Certainty::Conservative,
                        candidate_identity: Unknown,
                        tier: control
                            .candidate
                            .map_or(Unknown, |candidate| Known(candidate.tier)),
                    },
                );
            }
            _ => {}
        }
    }
    // The mode is an interpreted permission operation even when its path is unresolved.
    if let Some(grants) = grants
        && !emitted_permission
    {
        let target = resource(graph, ResourceKind::HostPath);
        fact(
            graph,
            FactPayload::FilesystemAccess {
                operation: FilesystemOperation::PermissionChange,
                target,
                destination: None,
                recursive: Unknown,
                truncate: Unknown,
                permissions: grants.clone(),
                purpose: AccessPurpose::Explicit,
            },
        );
    }
}
