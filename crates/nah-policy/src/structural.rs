//! Enforces non-disableable structural protection from shared evidence.

use nah_proto::effects::{
    ConditionAtomOrigin, ConditionExpr, ConditionId, ConditionUse, ControlTransport, EffectGraph,
    FactPayload, FilesystemOperation, GuardEvidence, Knowledge, Realm, ResourceId,
};
use nah_proto::effinterp_proto::ConditionKind;
use nah_proto::labels::{NahProtectionTier, SelfRule};

/// What each `self` rule protects and how a change to it is allowed: only
/// from the operator's own terminal, since a nap the agent starts is the
/// change the rule exists to stop.
pub(crate) fn reason(
    rule: SelfRule,
    tier: NahProtectionTier,
    others_block: bool,
    mode: crate::EnforcementMode,
    rules_paused: bool,
) -> String {
    let risk = match rule {
        SelfRule::NahConfigChange if tier == NahProtectionTier::Permanent => {
            return "this would pause or forge a nah nap from the agent's side, which switches nah's protection off. A nap must be started by the operator in a separate terminal, so do not retry it another way".into();
        }
        SelfRule::NahConfigChange => {
            "this would change nah's own settings, state or program, which could switch nah off"
        }
        SelfRule::AgentConfigChange => {
            "this would change the agent's hook or permission settings, which could let it run without nah"
        }
        SelfRule::UnguardedAgentLaunch => {
            "this would start an agent without nah's hook, so nothing that agent does would be checked"
        }
    };
    // An all nap already pauses every layer a further nap could. A bare nap
    // pauses only self-protection, so it would wake a rule nap, and a rule
    // nap would wake self-protection; only a nap of everything keeps both.
    if mode == crate::EnforcementMode::AllPaused {
        return format!("{risk}. Do not retry it another way; it needs the operator");
    }
    let nap = if others_block {
        "`nah nap all` in a separate terminal first, since the other rules named here block it too"
    } else if rules_paused {
        "`nah nap all` in a separate terminal first, since a nap replaces the rules already paused"
    } else {
        "`nah nap` in a separate terminal first"
    };
    format!("{risk}. Do not retry it another way; if it is intended, the operator can run {nap}")
}

/// One `self` rule a block falls under, with the text of the first fact
/// that triggered it when that fact says more than the rule's own reason.
#[derive(Clone, Copy)]
pub(crate) struct SelfBlock {
    pub(crate) rule: SelfRule,
    pub(crate) reason: Option<&'static str>,
}

/// The `self` rules of the changes to protected state at `Permanent`.
pub(crate) fn permanent_blocks(evidence: &GuardEvidence) -> Vec<SelfBlock> {
    blocks(evidence, NahProtectionTier::Permanent)
}

/// The `self` rules of the changes to protected state at `Critical`.
pub(crate) fn critical_blocks(evidence: &GuardEvidence) -> Vec<SelfBlock> {
    blocks(evidence, NahProtectionTier::Critical)
}

/// Every distinct `self` rule a fact that changes protected state at `tier`
/// falls under, in fact order, so the first leads a block and the others are
/// named after it. A protected path names the rule its labels carry (Nah's
/// state, or the runtime's wiring); a launch, the rule its control evidence
/// carries; and input typed into another terminal is always a Nah command.
fn blocks(evidence: &GuardEvidence, tier: NahProtectionTier) -> Vec<SelfBlock> {
    let mut blocks: Vec<SelfBlock> = Vec::new();
    for block in evidence
        .graph()
        .facts
        .iter()
        .flat_map(|fact| fact_blocks(evidence, fact, tier))
    {
        if !blocks.iter().any(|seen| seen.rule == block.rule) {
            blocks.push(block);
        }
    }
    blocks
}

/// The `self` rules one fact falls under at `tier`.
fn fact_blocks(
    evidence: &GuardEvidence,
    fact: &nah_proto::effects::EffectFact,
    tier: NahProtectionTier,
) -> Vec<SelfBlock> {
    let rule = |rule| SelfBlock { rule, reason: None };
    if fact.realm != Realm::Host {
        return Vec::new();
    }
    match &fact.payload {
        FactPayload::FilesystemAccess {
            operation,
            target,
            destination,
            ..
        } if *operation != FilesystemOperation::Read => {
            if !executable_position(evidence.graph(), fact.condition.as_ref()) {
                return Vec::new();
            }
            evidence
                .graph()
                .resources
                .iter()
                .filter_map(|resource| {
                    let labels = resource.labels.as_ref()?;
                    ((resource.id == *target || Some(resource.id) == *destination)
                        && labels.protection == Knowledge::Known(Some(tier)))
                    .then(|| rule(labels.self_rule.unwrap_or(SelfRule::NahConfigChange)))
                })
                .collect()
        }
        FactPayload::ControlMutation {
            tier: candidate,
            rule: launched,
            ..
        } => (*candidate == Knowledge::Known(tier)
            && executable_position(evidence.graph(), fact.condition.as_ref()))
        .then(|| rule(*launched))
        .into_iter()
        .collect(),
        FactPayload::ControlInput {
            target,
            tier: candidate,
            transport,
            ..
        } => (*candidate == Knowledge::Known(tier)
            && *transport != ControlTransport::AgentPrompt
            && on_success_path(evidence.graph(), fact.condition.as_ref()))
        .then(|| SelfBlock {
            rule: SelfRule::NahConfigChange,
            reason: terminal_reason(evidence, *target),
        })
        .into_iter()
        .collect(),
        _ => Vec::new(),
    }
}

/// The reason for a Nah command typed into another terminal through a
/// multiplexer or OpenClaw, `target`, where it would run as if the operator
/// typed it.
fn terminal_reason(evidence: &GuardEvidence, target: ResourceId) -> Option<&'static str> {
    let resource = evidence
        .graph()
        .resources
        .iter()
        .find(|resource| resource.id == target)?;
    let Knowledge::Known(provider) = &resource.identity.provider else {
        return None;
    };
    Some(match provider.as_str() {
        "herdr" => {
            "this would type a nah command into another terminal through Herdr, where it runs as if the operator typed it. Only the operator can run it, in their own terminal"
        }
        "tmux" => {
            "this would type a nah command into another terminal through tmux, where it runs as if the operator typed it. Only the operator can run it, in their own terminal"
        }
        "openclaw" => {
            "this would send a nah command through OpenClaw, where it runs as if the operator typed it. Only the operator can run it, in their own terminal"
        }
        _ => return None,
    })
}

/// Disabling Nah, or changing its protected state, is the loss wherever the
/// invocation places it, so a control mutation or a mutation of a protected
/// path counts from every position it can execute from: the success path, a
/// loop body or a branch arm. A fallback after `||`, a negated condition,
/// dispatch and unresolved execution stay conditional.
fn executable_position(graph: &EffectGraph, condition: Option<&ConditionUse>) -> bool {
    fn holds(graph: &EffectGraph, id: ConditionId) -> bool {
        graph
            .conditions
            .iter()
            .find(|node| node.id == id)
            .is_some_and(|node| match &node.expression {
                ConditionExpr::Literal { origin, .. } => origin.is_some_and(|origin| {
                    matches!(origin.kind, ConditionKind::Loop | ConditionKind::Branch)
                        || node.complete
                            && origin.kind == ConditionKind::ShortCircuit
                            && origin.polarity == Some(true)
                }),
                ConditionExpr::All(ids) | ConditionExpr::Any(ids) => {
                    ids.iter().all(|id| holds(graph, *id))
                }
                ConditionExpr::Not(_) => false,
            })
    }
    on_success_path(graph, condition)
        || condition.is_some_and(|condition| condition.positive && holds(graph, condition.id))
}

/// Nah decides for the invocation's successful path. A condition holds there
/// when every atom it names asserts that a preceding command in the same
/// invocation succeeded, as `cat` after `ln -s a b &&` does. A fallback after
/// `||`, a branch, loop, dispatch, unresolved execution, or widened condition
/// leaves the effect conditional.
fn on_success_path(graph: &EffectGraph, condition: Option<&ConditionUse>) -> bool {
    fn holds(graph: &EffectGraph, id: ConditionId) -> bool {
        graph
            .conditions
            .iter()
            .find(|node| node.id == id)
            .is_some_and(|node| {
                node.complete
                    && match &node.expression {
                        ConditionExpr::Literal { origin, .. } => {
                            *origin
                                == Some(ConditionAtomOrigin {
                                    kind: ConditionKind::ShortCircuit,
                                    polarity: Some(true),
                                })
                        }
                        ConditionExpr::All(ids) | ConditionExpr::Any(ids) => {
                            ids.iter().all(|id| holds(graph, *id))
                        }
                        ConditionExpr::Not(_) => false,
                    }
            })
    }
    condition.is_none_or(|condition| condition.positive && holds(graph, condition.id))
}
