#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Pure decision reduction from typed guard evidence, the call's coverage,
//! and the decision's GuardSettings into DecisionCore. Shipped rules live here as plain Rust
//! code; orchestration does not.

use nah_proto::ctx::GuardSettings;
use nah_proto::decision::{
    DecisionCore, DecisionError, GuardAttribution, GuardContribution, Verdict,
};

mod database_guards;
mod dependency_guards;
mod execution_guards;
mod filesystem_guards;
mod flow_guards;
mod git_guards;
mod guard_evaluation;
mod infrastructure_guards;
mod legacy_guards;
mod network_guards;
mod package_registry_guards;
mod registry;
mod secret_guards;
mod shared_queries;
mod structural;
mod system_guards;

pub use effinterp_matcher::QueryLimits;
pub use guard_evaluation::ShippedGuards;
pub use legacy_guards::LEGACY_GUARDS;
pub use registry::{FETCHED_CODE_RUN, GuardDefinition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementMode {
    Normal,
    SelfProtectionPaused,
    AllPaused,
}

/// Reduces shipped policy and self-protection.
///
/// Shipped guards and self-protection meet only at this reducer. Incomplete analysis is evidence, not a block: a call blocks
/// only when a guard or self-protection positively identifies it. `coverage` is
/// the selected public analysis; `matches` are the shipped guard matches
/// `shipped.evaluate` found for the same evidence. `rules_paused` means a
/// nap of named rules is already running, so a self-protection block must
/// not suggest a bare nap, which would wake those rules.
#[allow(clippy::too_many_arguments)]
pub fn reduce_policy_decision(
    evidence: &nah_proto::effects::GuardEvidence,
    shipped: &ShippedGuards,
    matches: &nah_proto::guard_host::ShippedGuardMatches,
    coverage: nah_proto::action::Coverage,
    settings: &GuardSettings,
    mode: EnforcementMode,
    rules_paused: bool,
) -> Result<DecisionCore, DecisionError> {
    use nah_proto::labels::NahProtectionTier::{Critical, Permanent};
    // Every self rule that blocks is named; the first leads. A self rule at
    // `Critical` is named beside a `Permanent` one only while
    // self-protection runs.
    let critical = || match mode {
        EnforcementMode::Normal => structural::critical_blocks(evidence),
        _ => Vec::new(),
    };
    let ids = |blocks: &[structural::SelfBlock]| {
        blocks
            .iter()
            .map(|block| block.rule.id())
            .collect::<Vec<_>>()
    };
    let mut permanent = structural::permanent_blocks(evidence);
    if let Some(&lead) = permanent.first() {
        for block in critical() {
            if !permanent.iter().any(|seen| seen.rule == block.rule) {
                permanent.push(block);
            }
        }
        // Shipped rules that match the same call are named too, unless a
        // nap of everything paused them.
        let contributions = match mode {
            EnforcementMode::AllPaused => vec![],
            _ => shipped_contributions(shipped, matches, settings)?,
        };
        let reason = lead.reason.map_or_else(
            || {
                structural::reason(
                    lead.rule,
                    Permanent,
                    !contributions.is_empty(),
                    mode,
                    rules_paused,
                )
            },
            str::to_owned,
        );
        return DecisionCore::structural_block_keeping(
            coverage,
            &ids(&permanent),
            &reason,
            contributions,
        );
    }
    if mode == EnforcementMode::AllPaused {
        return DecisionCore::new_with_coverage(coverage, Verdict::Delegate, vec![]);
    }
    let critical = critical();
    if let Some(&lead) = critical.first() {
        // Shipped rules that match the same call keep their independent
        // protection, so they are named after the self rules.
        let contributions = shipped_contributions(shipped, matches, settings)?;
        let reason = lead.reason.map_or_else(
            || {
                structural::reason(
                    lead.rule,
                    Critical,
                    !contributions.is_empty(),
                    mode,
                    rules_paused,
                )
            },
            str::to_owned,
        );
        return DecisionCore::structural_block_keeping(
            coverage,
            &ids(&critical),
            &reason,
            contributions,
        );
    }

    let contributions = shipped_contributions(shipped, matches, settings)?;
    let verdict = if !contributions.is_empty() {
        Verdict::Block
    } else {
        Verdict::Delegate
    };

    DecisionCore::new_with_coverage(coverage, verdict, contributions)
}

/// One contribution per rule with a matched part that runs at the rule's
/// level, named by the rule ID, in the order of the rule's first such part;
/// its reason is that part's. A matched part of a rule that runs below the
/// part's level contributes nothing, and never hides a part that runs.
fn shipped_contributions(
    shipped: &ShippedGuards,
    matches: &nah_proto::guard_host::ShippedGuardMatches,
    settings: &GuardSettings,
) -> Result<Vec<GuardContribution>, DecisionError> {
    let mut contributions = Vec::new();
    let mut rules = Vec::new();
    for matched in &matches.matched {
        let definition = &shipped.definitions()[matched.part];
        if rules.contains(&matched.rule)
            || settings.rule_level(matched.rule) < definition.applies_at
        {
            continue;
        }
        rules.push(matched.rule);
        let guard = GuardAttribution::shipped(matched.rule)?;
        let reason = matched.reason.as_deref().unwrap_or(definition.reason);
        contributions.push(GuardContribution::new(guard, reason)?);
    }
    Ok(contributions)
}
