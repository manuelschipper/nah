//! Case classification.
//!
//! The corpus oracle is verdict-level (block/delegate + guard name), while
//! Effect Interpreter emits effects — so the harness cannot fully automate
//! the regression / added-precision / intentional-change triage. It
//! derives the strongest signals that are automatable:
//!
//! - `regression`: nah blocked, but our plan is silent (no effects, no
//!   boundaries) while claiming full coverage. That is exactly the "silent
//!   omission where nah had supported coverage" the parity gate forbids.
//! - `explained_partial`: our plan reports boundaries or non-full coverage.
//!   Uncertainty was reported, never silently dropped; human triage decides
//!   whether coverage should grow.
//! - `covered`: our plan reports effects with full coverage. Whether the
//!   dangerous conclusion nah keyed on is among them needs effect-level
//!   triage; the per-case report carries the normalized effects for that.
//! - `unsupported_subject`: the engine has no frontend for the subject yet
//!   (all shell cases until the shell frontend lands).
//! - `unsupported`: no protocol subject exists for the case shape at all
//!   (native runtime tool calls).
//! - `engine_error` / `baseline_defect`: our failure vs. a malformed row.

use serde::{Deserialize, Serialize};

use effinterp_proto::Plan;

use crate::nah::goldens::{Golden, GoldenOutcome};
use crate::nah::normalize::Normalized;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityClass {
    // Effect-level classes (a golden applied — high confidence).
    /// Every effect nah's block is about is present in our plan.
    EffectMatch,
    SilentSymbolicDrop,
    /// A required effect is absent under Full coverage or without any retained boundary.
    MissingEffect,
    /// Required effects exist, but their source does not reach the required
    /// sink through an explained causal path.
    MissingFlow,
    // Verdict-level classes (no golden — lower confidence, from the oracle).
    Regression,
    Covered,
    ExplainedPartial,
    UnsupportedSubject,
    Unsupported,
    EngineError,
    BaselineDefect,
}

impl ParityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ParityClass::SilentSymbolicDrop => "silent_symbolic_drop",
            ParityClass::EffectMatch => "effect_match",
            ParityClass::MissingEffect => "missing_effect",
            ParityClass::MissingFlow => "missing_flow",
            ParityClass::Regression => "regression",
            ParityClass::Covered => "covered",
            ParityClass::ExplainedPartial => "explained_partial",
            ParityClass::UnsupportedSubject => "unsupported_subject",
            ParityClass::Unsupported => "unsupported",
            ParityClass::EngineError => "engine_error",
            ParityClass::BaselineDefect => "baseline_defect",
        }
    }
}

/// Classify a case that has an effect-level golden. Returns the class and, on
/// a shortfall, the required effects that were not found.
pub fn classify_golden(plan: &Plan, golden: &Golden) -> (ParityClass, Vec<String>) {
    match golden.golden_outcome(plan) {
        GoldenOutcome::BaselineDefect { reason } => (ParityClass::BaselineDefect, vec![reason]),
        GoldenOutcome::EffectMatch => (ParityClass::EffectMatch, Vec::new()),
        GoldenOutcome::MissingEffect { missing } => (ParityClass::MissingEffect, missing),
        GoldenOutcome::MissingFlow { missing } => (ParityClass::MissingFlow, missing),
        GoldenOutcome::ExplainedPartial { missing } => (ParityClass::ExplainedPartial, missing),
    }
}

/// Classify a case without a golden from its normalized plan and nah's
/// expected verdict. Lower confidence: it can only detect a total silent
/// omission, not a missed-among-several destructive effect.
pub fn classify_plan(normalized: &Normalized, expected_verdict: Option<&str>) -> ParityClass {
    if normalized.coverage.is_empty()
        || !normalized
            .coverage
            .keys()
            .all(|domain| normalized.is_full(domain))
        || !normalized.boundaries.is_empty()
    {
        return ParityClass::ExplainedPartial;
    }
    if normalized.silent() && expected_verdict == Some("block") {
        return ParityClass::Regression;
    }
    ParityClass::Covered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn normalized(effects: &[&str], boundaries: &[&str], coverage: &[(&str, &str)]) -> Normalized {
        Normalized {
            gaps: BTreeMap::new(),
            effects: effects.iter().map(|s| s.to_string()).collect(),
            boundaries: boundaries.iter().map(|s| s.to_string()).collect(),
            coverage: coverage
                .iter()
                .map(|(d, l)| (d.to_string(), l.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn silent_full_coverage_block_is_a_regression() {
        let n = normalized(&[], &[], &[("filesystem", "full")]);
        assert_eq!(classify_plan(&n, Some("block")), ParityClass::Regression);
        assert_eq!(classify_plan(&n, Some("delegate")), ParityClass::Covered);
        assert_eq!(classify_plan(&n, None), ParityClass::Covered);
    }

    #[test]
    fn boundaries_or_partial_coverage_are_explained() {
        let with_boundary = normalized(
            &["process.exec x"],
            &["unmodeled_command [process]"],
            &[("process", "full")],
        );
        assert_eq!(
            classify_plan(&with_boundary, Some("block")),
            ParityClass::ExplainedPartial
        );
        let partial = normalized(&["process.exec x"], &[], &[("process", "partial")]);
        assert_eq!(
            classify_plan(&partial, Some("block")),
            ParityClass::ExplainedPartial
        );
    }

    #[test]
    fn effects_with_full_coverage_are_covered() {
        assert_eq!(
            classify_plan(&normalized(&[], &[], &[]), None),
            ParityClass::ExplainedPartial
        );
        let n = normalized(
            &["filesystem.delete /"],
            &[],
            &[("filesystem", "full"), ("process", "full")],
        );
        assert_eq!(classify_plan(&n, Some("block")), ParityClass::Covered);
    }
}
