//! Enforces non-disableable structural protection from shared evidence.

use nah_proto::effects::*;
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
        if fact.realm != Realm::Host || fact.condition.is_some() {
            return false;
        }
        match &fact.payload {
            FactPayload::FilesystemAccess {
                operation,
                target,
                destination,
                ..
            } if *operation != FilesystemOperation::Read => {
                evidence.graph().resources.iter().any(|resource| {
                    (resource.id == *target || Some(resource.id) == *destination)
                        && resource
                            .labels
                            .as_ref()
                            .is_some_and(|labels| labels.protection == Knowledge::Known(Some(tier)))
                })
            }
            FactPayload::ControlMutation {
                tier: candidate, ..
            } => *candidate == Knowledge::Known(tier),
            FactPayload::ControlInput {
                tier: candidate,
                transport,
                ..
            } => {
                *candidate == Knowledge::Known(tier) && *transport != ControlTransport::AgentPrompt
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
        if fact.realm != Realm::Host || fact.condition.is_some() { return None; }
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
