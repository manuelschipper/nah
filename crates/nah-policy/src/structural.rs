//! Enforces non-disableable structural protection from shared evidence.

use nah_proto::effects::*;
use nah_proto::effinterp_proto::ConditionKind;
use nah_proto::labels::NahProtectionTier;

pub(crate) const CRITICAL_REASON: &str = "nah self-protection blocked a change to nah or its runtime wiring; do not retry through another tool; if intended, ask the operator to run `nah nap` in a separate terminal";
pub(crate) const PERMANENT_REASON: &str =
    "nah nap must be started by the operator in a separate terminal";
pub(crate) fn permanent_blocks(evidence: &GuardEvidence) -> bool {
    blocks(evidence, NahProtectionTier::Permanent)
}

pub(crate) fn critical_blocks(evidence: &GuardEvidence) -> bool {
    blocks(evidence, NahProtectionTier::Critical)
}

fn blocks(evidence: &GuardEvidence, tier: NahProtectionTier) -> bool {
    evidence.graph().facts.iter().any(|fact| {
        if fact.realm != Realm::Host {
            return false;
        }
        match &fact.payload {
            FactPayload::FilesystemAccess {
                operation,
                target,
                destination,
                ..
            } if *operation != FilesystemOperation::Read => {
                executable_position(evidence.graph(), fact.condition.as_ref())
                    && evidence.graph().resources.iter().any(|resource| {
                        (resource.id == *target || Some(resource.id) == *destination)
                            && resource.labels.as_ref().is_some_and(|labels| {
                                labels.protection == Knowledge::Known(Some(tier))
                            })
                    })
            }
            FactPayload::ControlMutation {
                tier: candidate, ..
            } => {
                *candidate == Knowledge::Known(tier)
                    && executable_position(evidence.graph(), fact.condition.as_ref())
            }
            FactPayload::ControlInput {
                tier: candidate,
                transport,
                ..
            } => {
                *candidate == Knowledge::Known(tier)
                    && *transport != ControlTransport::AgentPrompt
                    && on_success_path(evidence.graph(), fact.condition.as_ref())
            }
            _ => false,
        }
    })
}

pub(crate) fn terminal_reason(
    evidence: &GuardEvidence,
    tier: NahProtectionTier,
) -> Option<&'static str> {
    evidence.graph().facts.iter().find_map(|fact| {
        if fact.realm != Realm::Host || !on_success_path(evidence.graph(), fact.condition.as_ref()) { return None; }
        let FactPayload::ControlInput { target, tier: candidate, transport, .. } = &fact.payload else { return None; };
        if *candidate != Knowledge::Known(tier) || *transport == ControlTransport::AgentPrompt { return None; }
        let resource = evidence.graph().resources.iter().find(|resource| resource.id == *target)?;
        let Knowledge::Known(provider) = &resource.identity.provider else { return None; };
        Some(match (provider.as_str(), tier) {
            ("herdr", NahProtectionTier::Permanent) => "nah self-protection restricted Permanent protected-command input through Herdr; operator action is required",
            ("tmux", NahProtectionTier::Permanent) => "nah self-protection restricted Permanent protected-command input through tmux; operator action is required",
            ("herdr", _) => "nah self-protection restricted Critical protected-command input through Herdr; operator action is required",
            ("tmux", _) => "nah self-protection restricted Critical protected-command input through tmux; operator action is required",
            ("openclaw", _) => "nah self-protection restricted protected-command input through OpenClaw; operator action is required",
            _ => return None,
        })
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
