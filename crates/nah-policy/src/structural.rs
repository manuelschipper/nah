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
        ) || matches!(
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
            _ => false,
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
