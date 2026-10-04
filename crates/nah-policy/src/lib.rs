#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Pure decision reduction from typed guard evidence, the call's coverage,
//! PolicyCtx, and validated guard responses into DecisionCore. Shipped guards live here as plain
//! Rust code; transport, validation, and orchestration do not.

use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{
    DecisionCore, DecisionError, GuardAttribution, GuardContribution, Verdict,
};
use nah_proto::extension::ValidatedExtensionResponse;

mod database_guards;
mod execution_guards;
mod filesystem_guards;
mod flow_guards;
mod git_guards;
mod guard_evaluation;
mod infrastructure_guards;
mod network_guards;
mod package_registry_guards;
mod registry;
mod secret_guards;
mod shared_queries;
mod structural;
mod system_guards;

pub use effinterp_matcher::QueryLimits;
pub use guard_evaluation::ShippedGuards;
pub use registry::{GuardDefinition, GuardFamily};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementMode {
    Normal,
    SelfProtectionPaused,
    AllPaused,
}

/// Reduces shipped policy and already-validated extension responses.
///
/// Shipped guards, self-protection, and validated extension responses meet only
/// at this reducer. Incomplete analysis is evidence, not a block: a call blocks
/// only when a guard or self-protection positively identifies it. `coverage` is
/// the selected public analysis; `matches` are the shipped guard matches
/// `shipped.evaluate` found for the same evidence.
pub fn reduce_policy_decision(
    evidence: &nah_proto::effects::GuardEvidence,
    shipped: &ShippedGuards,
    matches: &nah_proto::guard_host::ShippedGuardMatches,
    coverage: nah_proto::action::Coverage,
    policy_ctx: &PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: EnforcementMode,
) -> Result<DecisionCore, DecisionError> {
    if structural::permanent_blocks(evidence) {
        return DecisionCore::structural_block_with_coverage(
            coverage,
            structural::terminal_reason(evidence, nah_proto::labels::NahProtectionTier::Permanent)
                .unwrap_or(structural::PERMANENT_REASON),
        );
    }
    if mode == EnforcementMode::AllPaused {
        return DecisionCore::new_with_coverage(coverage, Verdict::Delegate, vec![]);
    }
    if mode == EnforcementMode::Normal && (structural::critical_blocks(evidence)) {
        return DecisionCore::structural_block_with_coverage(
            coverage,
            structural::terminal_reason(evidence, nah_proto::labels::NahProtectionTier::Critical)
                .unwrap_or(structural::CRITICAL_REASON),
        );
    }

    let mut contributions = Vec::new();
    let mut shipped_block = false;
    for definition in shipped.definitions() {
        if !matches.matched(definition.id)
            || !policy_ctx
                .enabled_shipped_guards()
                .iter()
                .any(|enabled| enabled == definition.id)
        {
            continue;
        }
        let guard = GuardAttribution::shipped(definition.id)?;
        contributions.push(GuardContribution::new(guard, definition.reason)?);
        shipped_block = true;
    }
    let has_block = shipped_block || responses.iter().any(ValidatedExtensionResponse::is_block);

    add_extension_guards(responses, &mut contributions)?;

    let verdict = if has_block {
        Verdict::Block
    } else {
        Verdict::Delegate
    };

    DecisionCore::new_with_coverage(coverage, verdict, contributions)
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
