#![allow(clippy::disallowed_types)]

use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, Ctx, ExecProtocolVersion, GuardIdentity,
    Platform, PolicyCtx, SchemaVersion, ShippedGuardState, TrustProjection,
};
use nah_proto::effects::*;
use nah_proto::labels::{NahProtectionTier, PathScope, Sensitivity};
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};

pub(crate) fn path(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, value).unwrap()
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
        ExecProtocolVersion::V2,
        vec![name.to_owned()],
    )
    .unwrap()
}

pub(crate) fn guard_policy(name: &str, enabled: bool) -> PolicyCtx {
    context(&[(name, enabled)], vec![], ProjectGuardDeclaration::Absent).1
}

/// One native call and nothing else: evidence no guard or protection matches.
pub(crate) fn quiet_evidence() -> GuardEvidence {
    GuardEvidence::new(graph(vec![], vec![]), public()).unwrap()
}

/// One exact host fact on one resource, the shape the bridge publishes.
pub(crate) fn fact_evidence(resource: EffectResource, payload: FactPayload) -> GuardEvidence {
    let fact = EffectFact {
        id: FactId(0),
        call: CallId(0),
        realm: Realm::Host,
        certainty: Certainty::Exact,
        modality: Modality::May,
        condition: None,
        occurrences: None,
        payload,
    };
    GuardEvidence::new(graph(vec![resource], vec![fact]), public()).unwrap()
}

pub(crate) fn resource(kind: ResourceKind) -> EffectResource {
    EffectResource {
        id: ResourceId(0),
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind,
            details: Knowledge::Unknown,
            provider: Knowledge::Unknown,
            name: Knowledge::Unknown,
        },
        selection: Selection::Unknown,
        labels: None,
    }
}

/// A write to a path self-protection labels with `tier`.
pub(crate) fn protected_write(tier: NahProtectionTier) -> GuardEvidence {
    let mut target = resource(ResourceKind::HostPath);
    target.selection = Selection::Exact;
    target.labels = Some(ResourceLabels {
        lexical: Knowledge::Known(path("/repo/.nah/guards/demo/run")),
        canonical: Knowledge::Unknown,
        scope: Knowledge::Known(PathScope::Project {
            root: path("/repo"),
        }),
        sensitivity: Knowledge::Known(Sensitivity::None),
        protection: Knowledge::Known(Some(tier)),
        host_integrity: Knowledge::Known(Default::default()),
        selects_project: Reach::No,
        selects_home: Reach::No,
        selects_root: Reach::Unknown,
        is_symlink: Knowledge::Unknown,
        link_target: Knowledge::Unknown,
        descendants_complete: Knowledge::Unknown,
        reach: vec![],
    });
    fact_evidence(
        target,
        FactPayload::FilesystemAccess {
            target: ResourceId(0),
            destination: None,
            operation: FilesystemOperation::Write,
            recursive: Knowledge::Known(false),
            truncate: Knowledge::Unknown,
            permissions: PermissionGrants {
                world_write: Knowledge::Unknown,
                setuid: Knowledge::Unknown,
                setgid: Knowledge::Unknown,
            },
            purpose: AccessPurpose::Explicit,
        },
    )
}

/// A process launch the bridge ties to self-protection at `tier`.
pub(crate) fn control_mutation(tier: NahProtectionTier) -> GuardEvidence {
    fact_evidence(
        resource(ResourceKind::Unknown),
        FactPayload::ControlMutation {
            target: ResourceId(0),
            action: ControlAction::Other,
            candidate_identity: Knowledge::Unknown,
            tier: Knowledge::Known(tier),
        },
    )
}

/// Terminal input through `provider` carrying a protected command at `tier`.
pub(crate) fn terminal_input(provider: &str, tier: NahProtectionTier) -> GuardEvidence {
    let mut target = resource(ResourceKind::Unknown);
    target.identity.provider = Knowledge::Known(provider.into());
    fact_evidence(
        target,
        FactPayload::ControlInput {
            target: ResourceId(0),
            action: ControlAction::Deliver,
            transport: ControlTransport::Input,
            payload_certainty: Certainty::Conservative,
            candidate_identity: Knowledge::Unknown,
            tier: Knowledge::Known(tier),
        },
    )
}

/// Shipped guard matches naming exactly `names`.
pub(crate) fn guard_matches(names: &[&'static str]) -> nah_proto::guard_host::ShippedGuardMatches {
    nah_proto::guard_host::ShippedGuardMatches {
        matched: names.to_vec(),
        gaps: vec![],
    }
}

fn graph(resources: Vec<EffectResource>, facts: Vec<EffectFact>) -> EffectGraph {
    EffectGraph {
        calls: vec![EffectCall {
            arguments: Knowledge::Unknown,
            id: CallId(0),
            parent: None,
            kind: InvocationKind::Native,
            identity: Knowledge::Unknown,
            input: None,
            hidden_characters: false,
            cwd: Knowledge::Unknown,
            payload_group: Knowledge::Unknown,
            visibility_ordinal: Knowledge::Unknown,
            coverage: nah_proto::action::Coverage::Full,
        }],
        resources,
        facts,
        occurrences: vec![],
        relations: vec![],
        conditions: vec![],
        coverage: vec![],
        gaps: vec![],
        causality: CausalAvailability::Unavailable,
    }
}

fn public() -> PublicSelection {
    PublicSelection {
        calls: Default::default(),
        facts: Default::default(),
        resources: Default::default(),
        occurrences: Default::default(),
        relations: Default::default(),
        complete: false,
    }
}

/// Puts every fact behind one complete condition atom of `kind`: the first arm
/// of a two-way construct, which for a short circuit is `a && b`'s success, or
/// with `negated` the other arm, as for `a || b`.
pub(crate) fn conditioned(
    evidence: &nah_proto::effects::GuardEvidence,
    kind: nah_proto::effinterp_proto::ConditionKind,
    negated: bool,
) -> nah_proto::effects::GuardEvidence {
    let mut graph = evidence.graph().clone();
    graph.conditions.push(EffectCondition {
        id: ConditionId(0),
        complete: true,
        expression: ConditionExpr::Literal {
            atom: 0,
            origin: Some(ConditionAtomOrigin {
                kind,
                polarity: Some(true),
            }),
        },
        alternative_group: None,
    });
    if negated {
        graph.conditions.push(EffectCondition {
            id: ConditionId(1),
            complete: true,
            expression: ConditionExpr::Not(ConditionId(0)),
            alternative_group: None,
        });
    }
    for fact in &mut graph.facts {
        fact.condition = Some(ConditionUse {
            id: ConditionId(u32::from(negated)),
            positive: true,
        });
    }
    GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap()
}
