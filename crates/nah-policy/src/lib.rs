#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Pure decision reduction from shared evidence, ActionStream, PolicyCtx, and validated guard
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
mod system_guards;

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
    "fs-outside-workspace-delete",
    "fs-permission-weaken",
    "fs-project-root",
    "fs-raw-device",
    "fs-shell-profile",
    "fs-startup-management",
    "fs-startup-persistence",
    "fs-system-tree",
    "fs-volume-destroy",
    "git-clean-force",
    "git-force-push",
    "git-hard-reset",
    "git-history-rewrite",
    "git-metadata",
    "git-path-discard",
    "git-protected-push",
    "git-recovery-destroy",
    "git-ref-delete",
    "git-remote-repo-delete",
    "git-remote-resource-delete",
    "git-rewrite-force",
    "git-worktree-discard",
    "infra-container-reset",
    "infra-container-volume-delete",
    "infra-iac-destroy",
    "infra-k8s-delete",
    "registry-publish",
    "registry-unpublish",
    "secrets-credentials",
    "secrets-env",
    "secrets-exfil",
    "secrets-store-delete",
    "secrets-store-destroy",
    "secrets-store-read",
    "storage-backup-destroy",
    "storage-recursive-delete",
    "storage-snapshot-delete",
    "sys-power",
    "sys-service-stop",
];

/// Reduces shipped policy and already-validated extension responses.
///
/// Shipped guards, self-protection, and validated extension responses meet only
/// at this reducer. Incomplete analysis is evidence, not a block: a call blocks
/// only when a guard or self-protection positively identifies it.
pub fn decide(
    action_stream: &ActionStream,
    evidence: &nah_proto::effects::GuardEvidence,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
) -> Result<DecisionCore, DecisionError> {
    decide_with_mode(
        action_stream,
        evidence,
        policy_ctx,
        responses,
        EnforcementMode::Normal,
    )
}

pub fn decide_with_mode(
    action_stream: &ActionStream,
    evidence: &nah_proto::effects::GuardEvidence,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    decide_with_mode_and_inline(
        action_stream,
        evidence,
        &InlineReport::default(),
        policy_ctx,
        responses,
        mode,
    )
}

pub fn decide_with_mode_and_inline(
    action_stream: &ActionStream,
    evidence: &nah_proto::effects::GuardEvidence,
    inline_report: &InlineReport,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    decide_with_mode_and_inline_language_safety_stream(
        action_stream,
        evidence,
        action_stream,
        inline_report,
        policy_ctx,
        responses,
        mode,
    )
}

/// Reduces evidence from a public action stream and its language safety stream.
/// Git, filesystem and structural protection consume shared `evidence`. Remaining
/// shipped families inspect `language_safety_stream` and the inline report;
/// `DecisionCore` is bound to `action_stream`, which custom guards inspect.
/// Callers must supply evidence and both projections of the same tool call, with extension
/// responses validated against that public action stream.
pub fn decide_with_mode_and_inline_language_safety_stream(
    action_stream: &ActionStream,
    evidence: &nah_proto::effects::GuardEvidence,
    language_safety_stream: &ActionStream,
    inline_report: &InlineReport,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    if structural::permanent_blocks(evidence) {
        return DecisionCore::structural_block(
            action_stream,
            structural::terminal_reason(evidence, nah_proto::action::NahProtectionTier::Permanent)
                .unwrap_or(structural::PERMANENT_REASON),
        );
    }
    if mode == EnforcementMode::AllPaused {
        return DecisionCore::new(action_stream, Verdict::Delegate, vec![]);
    }
    if mode == EnforcementMode::Normal && (structural::critical_blocks(evidence)) {
        return DecisionCore::structural_block(
            action_stream,
            structural::terminal_reason(evidence, nah_proto::action::NahProtectionTier::Critical)
                .unwrap_or(structural::CRITICAL_REASON),
        );
    }

    let mut contributions = Vec::new();
    let filesystem_block = filesystem_guards::add(evidence, policy_ctx, &mut contributions)?;
    let git_block = git_guards::add(evidence, policy_ctx, &mut contributions)?;
    let infrastructure_block =
        infrastructure_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let registry_block =
        registry_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let secret_block = secret_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let storage_block =
        storage_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
    let system_block = system_guards::add(language_safety_stream, policy_ctx, &mut contributions)?;
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
        || system_block
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

/// Common predicate boundary for the staged family migration. Family owners replace
/// their existing `add` function in place; producer identity is never an argument.
pub type FamilyPredicate = fn(
    &nah_proto::effects::GuardEvidence,
    &PolicyCtx,
    &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError>;

/// Structural predicates additionally honor the reducer's enforcement mode.
pub type StructuralPredicate = fn(
    &nah_proto::effects::GuardEvidence,
    &PolicyCtx,
    &mut Vec<GuardContribution>,
    EnforcementMode,
) -> Result<bool, DecisionError>;

/// Git predicates shared by normal enforcement and non-enforcing producer checks.
pub const GIT_PREDICATE: FamilyPredicate = git_guards::add;
