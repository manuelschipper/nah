//! Enforces non-disableable structural protection; it does not consult shipped-guard enablement.

use nah_proto::action::{
    ActionStream, EffectKind, FilesystemOperation, InvocationEffect, NahProtectionTier,
    SemanticCode,
};

pub(crate) const CRITICAL_REASON: &str = "nah self-protection blocked a change to nah or its runtime wiring; do not retry through another tool; if intended, ask the operator to run `nah nap` in a separate terminal";
pub(crate) const PERMANENT_REASON: &str =
    "nah nap must be started by the operator in a separate terminal";
pub(crate) fn permanent_blocks(action_stream: &ActionStream) -> bool {
    action_stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation != FilesystemOperation::Read
                    && effect.protection == Some(NahProtectionTier::Permanent)
        ) || terminal_candidate(effect.kind(), NahProtectionTier::Permanent)
            || matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation:
                        InvocationEffect::Known {
                            program,
                            operation,
                            ..
                        },
                } if program_name(program) == "nah"
                    && operation == &SemanticCode::PERMANENT_MUTATION
            )
    })
}

pub(crate) fn critical_blocks(action_stream: &ActionStream) -> bool {
    action_stream
        .effects()
        .iter()
        .any(|effect| match effect.kind() {
            EffectKind::Filesystem { effect } => {
                effect.operation != FilesystemOperation::Read
                    && effect.protection == Some(NahProtectionTier::Critical)
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } => operation == &SemanticCode::CRITICAL_MUTATION,
            kind => terminal_candidate(kind, NahProtectionTier::Critical),
        })
}

fn program_name(program: &str) -> &str {
    let program = program
        .rsplit(['/', '\\'])
        .next()
        .filter(|program| !program.is_empty())
        .unwrap_or(program);
    if program
        .get(program.len().saturating_sub(4)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
    {
        &program[..program.len() - 4]
    } else {
        program
    }
}

fn terminal_candidate(kind: &EffectKind, tier: NahProtectionTier) -> bool {
    matches!(kind, EffectKind::Invocation { invocation: InvocationEffect::TerminalControl { control, .. } }
        if control.candidate.is_some_and(|candidate| candidate.tier == tier))
}

pub(crate) fn terminal_reason(
    stream: &ActionStream,
    tier: NahProtectionTier,
) -> Option<&'static str> {
    stream.effects().iter().find_map(|effect| {
        if !terminal_candidate(effect.kind(), tier) { return None; }
        let EffectKind::Invocation { invocation: InvocationEffect::TerminalControl { control, .. } } = effect.kind() else { return None; };
        use nah_proto::action::TerminalCarrier;
        Some(match (control.carrier, tier) {
            (TerminalCarrier::Herdr, NahProtectionTier::Permanent) => "nah self-protection restricted Permanent protected-command input through Herdr; operator action is required",
            (TerminalCarrier::Tmux, NahProtectionTier::Permanent) => "nah self-protection restricted Permanent protected-command input through tmux; operator action is required",
            (TerminalCarrier::Herdr, _) => "nah self-protection restricted Critical protected-command input through Herdr; operator action is required",
            (TerminalCarrier::Tmux, _) => "nah self-protection restricted Critical protected-command input through tmux; operator action is required",
            (TerminalCarrier::OpenclawProcess, _) => "nah self-protection restricted protected-command input through OpenClaw; operator action is required",
        })
    })
}
