#![allow(dead_code, clippy::disallowed_types)]

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, NahProtectionTier,
    PathScope, Sensitivity,
};
use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, Ctx, ExecProtocolVersion, GuardIdentity,
    Platform, PolicyCtx, SchemaVersion, ShippedGuardState, TrustProjection,
};
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};

pub(crate) fn path(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, value).unwrap()
}

pub(crate) fn filesystem(
    operation: FilesystemOperation,
    target: &str,
    scope: PathScope,
    sensitivity: Sensitivity,
) -> EffectKind {
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target: path(target),
            scope,
            sensitivity,
            protection: None,
            host_integrity: None,
            selects_root: target == "/repo",
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    }
}

pub(crate) fn project_scope() -> PathScope {
    PathScope::Project {
        root: path("/repo"),
    }
}

pub(crate) fn protected_stream(tier: NahProtectionTier) -> ActionStream {
    ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::opaque("writer").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Write,
                    target: path("/repo/.nah/guards/demo/run"),
                    scope: project_scope(),
                    sensitivity: Sensitivity::None,
                    protection: Some(tier),
                    host_integrity: None,
                    selects_root: false,
                    selects_home: false,
                    recursive: false,
                    pattern: false,
                },
            },
        ]],
        vec![],
    )
    .unwrap()
}

fn observation(declaration: ProjectGuardDeclaration) -> Observation {
    let cwd = ObservationQuery::Cwd {
        key: "cwd".into(),
        requested: path("/repo"),
    };
    let roots = ObservationQuery::Roots {
        key: "roots".into(),
        cwd_key: "cwd".into(),
    };
    let guards = ObservationQuery::ProjectGuards {
        key: "guards".into(),
        roots_key: "roots".into(),
    };
    let root = Root::new(RootKind::Project, path("/repo"));
    Observation::new(
        SchemaVersion::V1,
        "policy-test",
        vec![
            ObservationFact::new(
                cwd,
                ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: path("/repo"),
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                roots,
                ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![root.clone()],
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                guards,
                ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(Some(root), declaration).unwrap(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

pub(crate) fn context(
    shipped: &[(&str, bool)],
    activations: Vec<ActivationProjection>,
    declaration: ProjectGuardDeclaration,
) -> (Ctx, PolicyCtx) {
    let ctx = Ctx::new(
        Platform::Linux,
        path("/home/test"),
        shipped
            .iter()
            .map(|(name, enabled)| ShippedGuardState::new(*name, *enabled).unwrap())
            .collect(),
        activations,
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap();
    let policy = nah_proto::ctx::derive_policy_ctx(&ctx, &observation(declaration))
        .unwrap()
        .policy_ctx()
        .clone();
    (ctx, policy)
}

pub(crate) fn activation(name: &str) -> ActivationProjection {
    ActivationProjection::new(
        GuardIdentity::user(name).unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec![name.to_owned()],
    )
    .unwrap()
}

pub(crate) fn read_stream(
    coverage: Coverage,
    scope: PathScope,
    sensitivity: Sensitivity,
) -> ActionStream {
    ActionStream::new(
        coverage,
        vec![vec![
            EffectKind::known("Read", "read").unwrap(),
            filesystem(FilesystemOperation::Read, "/repo/file", scope, sensitivity),
        ]],
        vec![],
    )
    .unwrap()
}

pub(crate) fn guarded_stream(effect: EffectKind) -> ActionStream {
    ActionStream::new(
        Coverage::Partial,
        vec![vec![EffectKind::opaque("bash").unwrap(), effect]],
        vec![],
    )
    .unwrap()
}

pub(crate) fn guard_policy(name: &str, enabled: bool) -> PolicyCtx {
    context(&[(name, enabled)], vec![], ProjectGuardDeclaration::Absent).1
}

/// Supplies shared facts alongside the suite's legacy fixtures for unmigrated families.
/// These are test subjects, not a runtime adapter or a policy fallback.
pub(crate) fn evidence(
    stream: &ActionStream,
    report: &nah_inline::InlineReport,
) -> nah_proto::effects::GuardEvidence {
    use Knowledge::{Known, Unknown};
    use nah_proto::action::{InvocationEffect, SemanticCode};
    use nah_proto::effects::*;
    let mut graph = EffectGraph {
        calls: vec![EffectCall {
            id: CallId(0),
            parent: None,
            kind: InvocationKind::Native,
            identity: Unknown,
            input: None,
            cwd: Unknown,
            payload_group: Unknown,
            visibility_ordinal: Unknown,
            coverage: Coverage::Full,
        }],
        resources: vec![],
        facts: vec![],
        occurrences: vec![],
        relations: vec![],
        conditions: vec![],
        coverage: vec![],
        gaps: vec![],
        causality: CausalAvailability::Unavailable,
    };
    let mut stages = std::collections::BTreeMap::new();
    for effect in stream.effects() {
        if stages.contains_key(effect.stage()) {
            continue;
        }
        let input = OccurrenceId(graph.occurrences.len() as u32);
        let output = OccurrenceId(input.0 + 1);
        for (id, port) in [
            (input, PortKind::SemanticInput),
            (output, PortKind::SemanticOutput),
        ] {
            graph.occurrences.push(EffectOccurrence {
                id,
                call: CallId(0),
                fact: None,
                resource: None,
                port,
                condition: None,
            });
        }
        stages.insert(effect.stage().clone(), (input, output));
        graph.relations.push(EffectRelation {
            from: input,
            to: output,
            kind: RelationKind::ValueDependence,
            certainty: Certainty::Exact,
            condition: None,
        });
    }
    graph.causality = CausalAvailability::Available;
    for edge in stream.flows() {
        graph.relations.push(EffectRelation {
            from: stages[edge.from_stage()].1,
            to: stages[edge.to_stage()].0,
            kind: RelationKind::ByteTransfer,
            certainty: Certainty::Exact,
            condition: None,
        });
    }
    for effect in stream.effects() {
        let (input, output) = stages[effect.stage()];
        let target = ResourceId(graph.resources.len() as u32);
        let mut resource = EffectResource {
            id: target,
            realm: Realm::Host,
            identity: ResourceIdentity {
                kind: ResourceKind::Unknown,
                details: Unknown,
                provider: Unknown,
                name: Unknown,
            },
            selection: Selection::Unknown,
            labels: None,
        };
        let unknown_grants = PermissionGrants {
            world_write: Unknown,
            setuid: Unknown,
            setgid: Unknown,
        };
        let mut payload = match effect.kind() {
            EffectKind::Invocation {
                invocation: InvocationEffect::CodeExecution { source, code, .. },
            } => FactPayload::ExecutionInput {
                resource: None,
                port: Some(input),
                source: ExecutionSource::Unknown,
                derivation: if source == &SemanticCode::ENCODED_COMMAND {
                    ExecutionDerivation::Encoded
                } else if source == &SemanticCode::DECODED_EXECUTION {
                    ExecutionDerivation::Decoded
                } else if source == &SemanticCode::SHELL_PATTERN {
                    ExecutionDerivation::PatternSelected
                } else if source == &SemanticCode::UNRESOLVED_COMMAND {
                    ExecutionDerivation::UnresolvedCommand
                } else if source == &SemanticCode::EVALUATED_SHELL {
                    ExecutionDerivation::Evaluated
                } else {
                    ExecutionDerivation::Plain
                },
                visible_payload: if code.is_some() {
                    VisiblePayload::Present
                } else {
                    VisiblePayload::Absent
                },
            },
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::DECODE => FactPayload::Transform {
                operation: TransformOperation::Decode,
                input: Some(input),
                output: Some(output),
            },
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::NETWORK_SHELL => FactPayload::ExecutionInput {
                resource: None,
                port: None,
                source: ExecutionSource::NetworkAttachment,
                derivation: ExecutionDerivation::Plain,
                visible_payload: VisiblePayload::Absent,
            },
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::NETWORK_LISTENER => {
                resource.identity.kind = ResourceKind::Endpoint;
                FactPayload::NetworkAccess {
                    operation: NetworkOperation::Listen,
                    target,
                    direction: Unknown,
                    ports: vec![output],
                    attached_execution: Unknown,
                }
            }
            EffectKind::Network { direction, .. } => {
                resource.identity.kind = ResourceKind::Endpoint;
                let transfer = stream.effects().iter().any(|candidate| candidate.stage() == effect.stage() && matches!(candidate.kind(), EffectKind::Invocation { invocation: InvocationEffect::Known { operation, .. } } if operation == &SemanticCode::NETWORK_TRANSFER));
                let direction = if transfer {
                    TransferDirection::Bidirectional
                } else if *direction == nah_proto::action::NetworkDirection::Inbound {
                    TransferDirection::Inbound
                } else {
                    TransferDirection::Outbound
                };
                FactPayload::NetworkAccess {
                    operation: NetworkOperation::Transfer,
                    target,
                    direction: Known(direction),
                    ports: if direction != TransferDirection::Outbound {
                        vec![input, output]
                    } else {
                        vec![input]
                    },
                    attached_execution: Unknown,
                }
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::ENVIRONMENT_DISCLOSURE
                || operation == &SemanticCode::CREDENTIAL_DISCLOSURE =>
            {
                FactPayload::EnvironmentAccess {
                    names: if operation == &SemanticCode::ENVIRONMENT_DISCLOSURE {
                        EnvironmentSelection::Whole
                    } else {
                        EnvironmentSelection::Names(vec!["AWS_SECRET_ACCESS_KEY".into()])
                    },
                    operation: EnvironmentOperation::Read,
                    purpose: AccessPurpose::Explicit,
                    output: Some(output),
                }
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::SECRETS_STORE_READ => {
                resource.identity.kind = ResourceKind::CredentialStore;
                FactPayload::CredentialAccess {
                    target,
                    operation: CredentialOperation::ReadValue,
                    deletion: DeletionMode::Unknown,
                    workflow: CredentialWorkflow::Ordinary,
                    purpose: AccessPurpose::Explicit,
                }
            }
            EffectKind::SystemState { operation }
                if operation == &SemanticCode::SECRETS_STORE_DELETE
                    || operation == &SemanticCode::SECRETS_STORE_DESTROY =>
            {
                resource.identity.kind = ResourceKind::CredentialStore;
                FactPayload::CredentialAccess {
                    target,
                    operation: CredentialOperation::Delete,
                    deletion: if operation == &SemanticCode::SECRETS_STORE_DELETE {
                        DeletionMode::Recoverable
                    } else {
                        DeletionMode::Permanent
                    },
                    workflow: CredentialWorkflow::Ordinary,
                    purpose: AccessPurpose::Explicit,
                }
            }

            EffectKind::Filesystem { effect: fs } => {
                resource.identity.kind = ResourceKind::HostPath;
                resource.selection = if fs.pattern {
                    Selection::Pattern {
                        pattern: fs.target.as_str().into(),
                        bound: Bound::Unknown,
                    }
                } else {
                    Selection::Exact
                };
                resource.labels = Some(ResourceLabels {
                    lexical: Known(fs.target.clone()),
                    canonical: Unknown,
                    scope: Known(fs.scope.clone()),
                    sensitivity: Known(fs.sensitivity),
                    protection: Known(fs.protection),
                    host_integrity: Known(fs.host_integrity.into_iter().collect()),
                    selects_project: if fs.selects_root {
                        Reach::Yes
                    } else {
                        Reach::No
                    },
                    selects_home: if fs.selects_home {
                        Reach::Yes
                    } else {
                        Reach::No
                    },
                    selects_root: Reach::Unknown,
                    is_symlink: Unknown,
                    link_target: Unknown,
                    descendants_complete: Unknown,
                    reach: vec![],
                });
                let permission = stream.effects().iter().any(|candidate| candidate.stage() == effect.stage() && matches!(candidate.kind(), EffectKind::Invocation { invocation: InvocationEffect::Known { operation, .. } } if operation.is_permission_change()));
                let operation = match fs.operation {
                    nah_proto::action::FilesystemOperation::Read => FilesystemOperation::Read,
                    nah_proto::action::FilesystemOperation::Write if permission => {
                        FilesystemOperation::PermissionChange
                    }
                    nah_proto::action::FilesystemOperation::Write => FilesystemOperation::Write,
                    nah_proto::action::FilesystemOperation::Delete => FilesystemOperation::Delete,
                };
                FactPayload::FilesystemAccess {
                    target,
                    destination: None,
                    operation,
                    recursive: Known(fs.recursive),
                    truncate: Unknown,
                    permissions: unknown_grants,
                    purpose: AccessPurpose::Explicit,
                }
            }
            EffectKind::FilesystemUnresolved {
                operation,
                recursive,
            } => {
                let permission = stream.effects().iter().any(|candidate| candidate.stage() == effect.stage() && matches!(candidate.kind(), EffectKind::Invocation { invocation: InvocationEffect::Known { operation, .. } } if operation.is_permission_change()));
                FactPayload::FilesystemAccess {
                    target,
                    destination: None,
                    operation: match operation {
                        nah_proto::action::FilesystemOperation::Read => FilesystemOperation::Read,
                        nah_proto::action::FilesystemOperation::Write if permission => {
                            FilesystemOperation::PermissionChange
                        }
                        nah_proto::action::FilesystemOperation::Write => FilesystemOperation::Write,
                        nah_proto::action::FilesystemOperation::Delete => {
                            FilesystemOperation::Delete
                        }
                    },
                    recursive: Known(*recursive),
                    truncate: Unknown,
                    permissions: unknown_grants,
                    purpose: AccessPurpose::Explicit,
                }
            }
            EffectKind::Invocation {
                invocation:
                    InvocationEffect::Known {
                        operation, program, ..
                    },
            } => {
                if operation == &SemanticCode::PERMISSION_WEAKEN {
                    FactPayload::FilesystemAccess {
                        target,
                        destination: None,
                        operation: FilesystemOperation::PermissionChange,
                        recursive: Known(false),
                        truncate: Unknown,
                        permissions: PermissionGrants {
                            world_write: Known(true),
                            ..unknown_grants
                        },
                        purpose: AccessPurpose::Explicit,
                    }
                } else if operation == &SemanticCode::CRITICAL_MUTATION
                    || operation == &SemanticCode::PERMANENT_MUTATION && program == "nah"
                {
                    FactPayload::ControlMutation {
                        target,
                        action: ControlAction::Other,
                        candidate_identity: Unknown,
                        tier: Known(if operation == &SemanticCode::CRITICAL_MUTATION {
                            NahProtectionTier::Critical
                        } else {
                            NahProtectionTier::Permanent
                        }),
                    }
                } else {
                    continue;
                }
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::TerminalControl { control, .. },
            } => {
                use nah_proto::action::{TerminalCarrier, TerminalOperation};
                resource.identity.provider = Known(
                    match control.carrier {
                        TerminalCarrier::Herdr => "herdr",
                        TerminalCarrier::Tmux => "tmux",
                        TerminalCarrier::OpenclawProcess => "openclaw",
                    }
                    .into(),
                );
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
                    tier: control.candidate.map_or(Unknown, |c| Known(c.tier)),
                }
            }
            EffectKind::SystemState { operation } if operation == &SemanticCode::FORK_BOMB => {
                FactPayload::ProcessGrowth {
                    background: Unknown,
                    repetition: Unknown,
                    launch_cycle: Unknown,
                    wait: Unknown,
                    dominator: Unknown,
                    growth: Bound::Unknown,
                    abstract_unbounded_spawn: Known(true),
                }
            }
            EffectKind::SystemState { operation }
                if operation == &SemanticCode::LOGICAL_STORAGE_DESTROY =>
            {
                resource.identity.kind = ResourceKind::LiveVolume;
                FactPayload::StorageChange {
                    target,
                    destination: None,
                    operation: StorageOperation::Destroy,
                    kind: StorageTarget::LiveVolume,
                    selection: Selection::Unknown,
                    recursive: Unknown,
                    destination_deletion: Unknown,
                }
            }
            EffectKind::SystemState { operation }
                if operation == &SemanticCode::STARTUP_MANAGEMENT =>
            {
                FactPayload::SystemChange {
                    target,
                    operation: SystemOperation::StartupChange,
                    selection: Selection::Unknown,
                    runtime_only: Known(false),
                    persistent: Known(true),
                    active: Known(true),
                    cancel: Known(false),
                    help: Known(false),
                }
            }
            _ => continue,
        };
        graph.resources.push(resource);
        if let FactPayload::FilesystemAccess { operation, destination, .. } = &mut payload
            && *operation == FilesystemOperation::Delete
            && stream.effects().iter().any(|candidate| candidate.stage() == effect.stage() && matches!(candidate.kind(), EffectKind::Invocation { invocation: InvocationEffect::Known { operation, .. } } if operation == &SemanticCode::MOVE))
        {
            *operation = FilesystemOperation::Move;
            let id = ResourceId(graph.resources.len() as u32);
            *destination = Some(id);
            graph.resources.push(EffectResource { id, realm: Realm::Host, identity: ResourceIdentity { kind: ResourceKind::HostPath, details: Unknown, provider: Unknown, name: Unknown }, selection: Selection::Unknown, labels: None });
        }
        let source = matches!(
            payload,
            FactPayload::FilesystemAccess {
                operation: FilesystemOperation::Read | FilesystemOperation::Move,
                ..
            } | FactPayload::CredentialAccess {
                operation: CredentialOperation::ReadValue,
                ..
            }
        );
        if source {
            let occurrence = OccurrenceId(graph.occurrences.len() as u32);
            graph.occurrences.push(EffectOccurrence {
                id: occurrence,
                call: CallId(0),
                fact: Some(FactId(graph.facts.len() as u32)),
                resource: None,
                port: PortKind::SemanticOutput,
                condition: None,
            });
            graph.relations.push(EffectRelation {
                from: occurrence,
                to: output,
                kind: RelationKind::ValueDependence,
                certainty: Certainty::Exact,
                condition: None,
            });
            if stream.effects().iter().any(|candidate| {
                candidate.stage() == effect.stage()
                    && matches!(candidate.kind(), EffectKind::Network { .. })
            }) {
                graph.relations.push(EffectRelation {
                    from: occurrence,
                    to: input,
                    kind: RelationKind::ValueDependence,
                    certainty: Certainty::Exact,
                    condition: None,
                });
            }
        }
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
        if let Some(EffectFact { payload: FactPayload::FilesystemAccess { target, recursive, .. }, .. }) = graph.facts.last().cloned()
            && stream.effects().iter().any(|candidate| candidate.stage() == effect.stage() && matches!(candidate.kind(), EffectKind::Invocation { invocation: InvocationEffect::Known { operation, .. } } if operation == &SemanticCode::CREDENTIAL_SEARCH)) {
            let id = FactId(graph.facts.len() as u32);
            graph.facts.push(EffectFact { id, call: CallId(0), realm: Realm::Host, certainty: Certainty::Exact, modality: Modality::May, condition: None, occurrences: None, payload: FactPayload::FilesystemSearch { target, recursive, selection: Selection::Unknown, query: Known("AKIA".into()), kind: SearchKind::Content, output: SearchOutput::Content } });
            let occurrence = OccurrenceId(graph.occurrences.len() as u32);
            graph.occurrences.push(EffectOccurrence { id: occurrence, call: CallId(0), fact: Some(id), resource: None, port: PortKind::SemanticOutput, condition: None });
            graph.relations.push(EffectRelation { from: occurrence, to: output, kind: RelationKind::ValueDependence, certainty: Certainty::Exact, condition: None });
        }
    }
    for finding in report.findings() {
        finding.emit_effect(&mut graph, CallId(0));
    }
    GuardEvidence::new(
        graph,
        PublicSelection {
            calls: Default::default(),
            facts: Default::default(),
            resources: Default::default(),
            occurrences: Default::default(),
            relations: Default::default(),
            complete: false,
        },
    )
    .unwrap()
}
