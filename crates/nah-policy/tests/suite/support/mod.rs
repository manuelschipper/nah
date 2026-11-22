#![allow(clippy::disallowed_types)]

use nah_proto::ctx::{AbsolutePath, GuardLevel, GuardSettings, Platform, RuleOverride};
use nah_proto::effects::{
    AccessPurpose, CallId, CausalAvailability, Certainty, ConditionAtomOrigin, ConditionExpr,
    ConditionId, ConditionUse, ControlAction, ControlTransport, EffectCall, EffectCondition,
    EffectFact, EffectGraph, EffectResource, FactId, FactPayload, FilesystemOperation,
    GuardEvidence, InvocationKind, Knowledge, Modality, PermissionGrants, PublicSelection, Reach,
    Realm, ResourceId, ResourceIdentity, ResourceKind, ResourceLabels, Selection,
};
use nah_proto::labels::{NahProtectionTier, PathScope, SelfRule, Sensitivity};

pub(crate) fn path(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, value).unwrap()
}

/// Every guard off, with each listed rule overridden on or off.
pub(crate) fn only_rules(rules: &[(&str, bool)]) -> GuardSettings {
    let mut settings = GuardSettings::every_guard_at(GuardLevel::Off);
    for (rule, enabled) in rules {
        settings.set_rule(
            rule,
            Some(if *enabled {
                RuleOverride::Enabled
            } else {
                RuleOverride::Disabled
            }),
        );
    }
    settings
}

pub(crate) fn guard_policy(rule: &str, enabled: bool) -> GuardSettings {
    only_rules(&[(rule, enabled)])
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
        self_rule: Some(SelfRule::NahConfigChange),
        host_integrity: Knowledge::Known(Default::default()),
        selects_project: Reach::No,
        selects_home: Reach::No,
        selects_home_folder: Reach::No,
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

/// A process launch the bridge ties to self-protection `rule` at `tier`.
pub(crate) fn control_mutation(tier: NahProtectionTier, rule: SelfRule) -> GuardEvidence {
    control_mutations(&[(tier, rule)])
}

/// One call's process launches, each tied to self-protection `rule` at
/// `tier`, in order.
pub(crate) fn control_mutations(launches: &[(NahProtectionTier, SelfRule)]) -> GuardEvidence {
    facts_evidence(
        vec![resource(ResourceKind::Unknown)],
        launches
            .iter()
            .map(|&(tier, rule)| FactPayload::ControlMutation {
                target: ResourceId(0),
                action: ControlAction::Other,
                candidate_identity: Knowledge::Unknown,
                tier: Knowledge::Known(tier),
                rule,
            })
            .collect(),
    )
}

/// One call's facts with `payloads`, in order, over `resources`, whose ids
/// must run from 0.
pub(crate) fn facts_evidence(
    resources: Vec<EffectResource>,
    payloads: Vec<FactPayload>,
) -> GuardEvidence {
    let facts = payloads
        .into_iter()
        .enumerate()
        .map(|(index, payload)| EffectFact {
            id: FactId(index as u32),
            call: CallId(0),
            realm: Realm::Host,
            certainty: Certainty::Exact,
            modality: Modality::May,
            condition: None,
            occurrences: None,
            payload,
        })
        .collect();
    GuardEvidence::new(graph(resources, facts), public()).unwrap()
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

/// Shipped matches of exactly `parts`, each the nth part of its rule in
/// definition order.
pub(crate) fn guard_matches(
    parts: &[(&'static str, usize)],
) -> nah_proto::guard_host::ShippedGuardMatches {
    let shipped = nah_policy::ShippedGuards::new();
    nah_proto::guard_host::ShippedGuardMatches {
        matched: parts
            .iter()
            .map(|(rule, nth)| nah_proto::guard_host::MatchedPart {
                rule,
                part: shipped
                    .definitions()
                    .iter()
                    .enumerate()
                    .filter(|(_, definition)| definition.rule == *rule)
                    .nth(*nth)
                    .unwrap_or_else(|| panic!("{rule} has no part {nth}"))
                    .0,
                reason: None,
            })
            .collect(),
        ..Default::default()
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
