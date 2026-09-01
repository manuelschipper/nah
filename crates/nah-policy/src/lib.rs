#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Pure decision reduction from ActionStream, PolicyCtx, and validated guard
//! responses into DecisionCore. Shipped guards live here as plain
//! Rust code; transport, validation, and orchestration do not.

use nah_inline::InlineReport;
use nah_proto::action::ActionStream;
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{
    DecisionCore, DecisionError, GuardAttribution, GuardContribution, Verdict,
};
use nah_proto::extension::ValidatedExtensionResponse;

mod execution_guards;
mod filesystem_guards;
mod git_guards;
mod infrastructure_guards;
mod registry_guards;
mod secret_guards;
mod storage_guards;
mod structural;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementMode {
    Normal,
    SelfProtectionPaused,
    AllPaused,
}

pub const SHIPPED_GUARDS: &[&str] = &[
    "exec-decoded",
    "exec-network-shell",
    "exec-obfuscated",
    "exec-remote",
    "fs-auth-identity",
    "fs-forkbomb",
    "fs-home",
    "fs-project-root",
    "fs-raw-device",
    "fs-shell-profile",
    "fs-startup-management",
    "fs-startup-persistence",
    "fs-storage-destroy",
    "fs-system-tree",
    "git-clean-force",
    "git-force-push",
    "git-hard-reset",
    "git-metadata",
    "git-recovery-destroy",
    "git-remote-delete",
    "git-rewrite-force",
    "git-worktree-discard",
    "infra-container-prune",
    "infra-container-reset",
    "infra-iac-destroy",
    "infra-k8s-delete",
    "registry-publish",
    "registry-unpublish",
    "secrets-env",
    "secrets-exfil",
    "secrets-keys",
    "storage-destroy",
    "storage-recursive-delete",
    "storage-snapshot-delete",
];

/// Reduces shipped policy and already-validated extension responses.
///
/// Shipped guards, self-protection, and validated extension responses meet only
/// at this reducer. Incomplete analysis is evidence, not a block: a call blocks
/// only when a guard or self-protection positively identifies it.
pub fn decide(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
) -> Result<DecisionCore, DecisionError> {
    decide_with_mode(
        action_stream,
        policy_ctx,
        responses,
        EnforcementMode::Normal,
    )
}

pub fn decide_with_mode(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    decide_with_mode_and_inline(
        action_stream,
        &InlineReport::default(),
        policy_ctx,
        responses,
        mode,
    )
}

pub fn decide_with_mode_and_inline(
    action_stream: &ActionStream,
    inline_report: &InlineReport,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    decide_with_mode_and_inline_language_safety_stream(
        action_stream,
        action_stream,
        inline_report,
        policy_ctx,
        responses,
        mode,
    )
}

pub fn decide_with_mode_and_inline_language_safety_stream(
    action_stream: &ActionStream,
    language_safety_stream: &ActionStream,
    inline_report: &InlineReport,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    if structural::permanent_blocks(language_safety_stream) {
        return DecisionCore::structural_block(action_stream, structural::PERMANENT_REASON);
    }
    if mode == EnforcementMode::AllPaused {
        return DecisionCore::new(action_stream, Verdict::Delegate, vec![]);
    }
    if mode == EnforcementMode::Normal
        && (structural::critical_blocks(language_safety_stream)
            || inline_report.contains_conservative(nah_inline::FindingKind::NahTampering))
    {
        return DecisionCore::structural_block(action_stream, structural::CRITICAL_REASON);
    }

    let mut contributions = Vec::new();
    let filesystem_block = filesystem_guards::add(
        language_safety_stream,
        inline_report,
        policy_ctx,
        &mut contributions,
    )?;
    let git_block = git_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let infrastructure_block =
        infrastructure_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let registry_block =
        registry_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let secret_block = secret_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let storage_block =
        storage_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let execution_block = execution_guards::add(
        language_safety_stream,
        inline_report,
        policy_ctx,
        &mut contributions,
    )?;
    let shipped_block = filesystem_block
        || git_block
        || infrastructure_block
        || registry_block
        || secret_block
        || storage_block
        || execution_block;
    let has_block = shipped_block || responses.iter().any(ValidatedExtensionResponse::is_block);

    add_extension_guards(responses, &mut contributions)?;

    let verdict = if has_block {
        Verdict::Block
    } else {
        Verdict::Delegate
    };

    DecisionCore::new(action_stream, verdict, contributions)
}

fn add_extension_guards(
    responses: &[ValidatedExtensionResponse],
    contributions: &mut Vec<GuardContribution>,
) -> Result<(), DecisionError> {
    for response in responses.iter().filter(|response| response.is_block()) {
        let guard = GuardAttribution::extension(response.activation().clone());
        contributions.push(GuardContribution::new(guard, response.reason())?);
    }
    Ok(())
}
