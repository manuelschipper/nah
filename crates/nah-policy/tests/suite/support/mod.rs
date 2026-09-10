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
    for effect in stream.effects() {
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
                    allow_remove_all: nah_proto::effects::Knowledge::Unknown,
                    all_selection_requested: nah_proto::effects::Knowledge::Unknown,
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

pub(crate) fn empty_evidence() -> nah_proto::effects::GuardEvidence {
    use nah_proto::effects::*;
    GuardEvidence::new(
        EffectGraph {
            calls: vec![],
            resources: vec![],
            facts: vec![],
            occurrences: vec![],
            relations: vec![],
            conditions: vec![],
            coverage: vec![],
            gaps: vec![],
            causality: CausalAvailability::Unavailable,
        },
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

pub(crate) fn operation_evidence(
    payload: nah_proto::effects::FactPayload,
) -> nah_proto::effects::GuardEvidence {
    use nah_proto::effects::*;
    let stream = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::LOCAL_UTILITY,
    });
    let base = evidence(&stream, &nah_inline::InlineReport::default());
    let mut graph = base.graph().clone();
    let kind = match &payload {
        FactPayload::ContainerChange {
            operation: ContainerOperation::ResetRuntime,
            ..
        } => ResourceKind::ContainerRuntime,
        FactPayload::ContainerChange { .. } => ResourceKind::ContainerVolume,
        FactPayload::InfrastructureChange { .. } => ResourceKind::ManagedInfrastructure,
        FactPayload::PackageChange { .. } => ResourceKind::Package,
        FactPayload::SystemChange { .. } => ResourceKind::HostSystem,
        FactPayload::StorageChange {
            kind: StorageTarget::LiveVolume,
            ..
        } => ResourceKind::LiveVolume,
        _ => ResourceKind::Other,
    };
    graph.resources.clear();
    graph.facts.clear();
    graph.resources.push(EffectResource {
        id: ResourceId(0),
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind,
            name: Knowledge::Unknown,
            provider: Knowledge::Unknown,
            details: Knowledge::Unknown,
        },
        selection: Selection::Unknown,
        labels: None,
    });
    graph.facts.push(EffectFact {
        id: FactId(0),
        call: CallId(0),
        realm: Realm::Host,
        certainty: Certainty::Exact,
        modality: Modality::May,
        condition: None,
        occurrences: None,
        payload,
    });
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

pub(crate) fn assert_operation_uncertainty(
    evidence: &nah_proto::effects::GuardEvidence,
    name: &str,
) {
    use nah_proto::effects::*;
    let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
    for boundary in ["absent", "conditional", "conservative"] {
        let mut graph = evidence.graph().clone();
        match boundary {
            "absent" => graph.facts.clear(),
            "conditional" => {
                graph.conditions.push(EffectCondition {
                    id: ConditionId(0),
                    complete: false,
                    expression: ConditionExpr::Literal { atom: 0 },
                    alternative_group: None,
                });
                graph.facts[0].condition = Some(ConditionUse {
                    id: ConditionId(0),
                    positive: true,
                });
            }
            _ => graph.facts[0].certainty = Certainty::Conservative,
        }
        let evidence = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
        let decision =
            nah_policy::decide(&stream, &evidence, &guard_policy(name, true), &[]).unwrap();
        assert_eq!(
            decision.verdict(),
            nah_proto::decision::Verdict::Delegate,
            "{name}: {boundary}"
        );
        assert!(decision.policy_attributions().is_empty());
    }
}
