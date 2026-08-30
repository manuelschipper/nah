//! Deterministic decision contracts produced by policy reduction.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::action::{ActionStream, Coverage};
use crate::ctx::ActivationProjection;
use serde::{Deserialize, Serialize};

mod output;

pub use output::{Decision, DecisionEnvelope, DecisionOutput, ExitCode};

/// nah either blocks a call or leaves the decision to the agent runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Block,
    Delegate,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GuardAttribution {
    Shipped { name: String },
    Extension { activation: ActivationProjection },
}

impl GuardAttribution {
    pub fn shipped(name: &str) -> Result<Self, DecisionError> {
        Ok(Self::Shipped { name: text(name)? })
    }

    pub fn extension(activation: ActivationProjection) -> Self {
        Self::Extension { activation }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Shipped { name, .. } => name,
            Self::Extension { activation } => activation.identity().name(),
        }
    }

    fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Shipped { name: left, .. }, Self::Shipped { name: right, .. }) => left == right,
            (Self::Extension { activation: left }, Self::Extension { activation: right }) => {
                left.identity() == right.identity()
            }
            _ => false,
        }
    }
}

impl<'de> Deserialize<'de> for GuardAttribution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
        enum Wire {
            Shipped { name: String },
            Extension { activation: ActivationProjection },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Shipped { name } => text(&name).map(|name| Self::Shipped { name }),
            Wire::Extension { activation } => Ok(Self::extension(activation)),
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardContribution {
    guard: GuardAttribution,
    reason: String,
}

impl GuardContribution {
    pub fn new(guard: GuardAttribution, reason: &str) -> Result<Self, DecisionError> {
        Ok(Self {
            guard,
            reason: text(reason)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionCore {
    verdict: Verdict,
    reason: String,
    policy_attributions: Vec<GuardAttribution>,
    coverage: Coverage,
}

impl DecisionCore {
    pub fn structural_block(
        action_stream: &ActionStream,
        reason: &str,
    ) -> Result<Self, DecisionError> {
        Ok(Self {
            verdict: Verdict::Block,
            reason: text(reason)?,
            policy_attributions: vec![],
            coverage: action_stream.coverage(),
        })
    }

    pub fn new(
        action_stream: &ActionStream,
        verdict: Verdict,
        contributions: Vec<GuardContribution>,
    ) -> Result<Self, DecisionError> {
        Self::new_with_coverage(action_stream.coverage(), verdict, contributions)
    }

    pub fn new_with_coverage(
        coverage: Coverage,
        verdict: Verdict,
        mut contributions: Vec<GuardContribution>,
    ) -> Result<Self, DecisionError> {
        contributions.sort_by(|left, right| left.guard.cmp(&right.guard));
        if contributions
            .windows(2)
            .any(|pair| pair[0].guard.same_identity(&pair[1].guard))
        {
            return Err(DecisionError::DuplicateAttribution);
        }
        if verdict == Verdict::Delegate && !contributions.is_empty() {
            return Err(DecisionError::UnexpectedAttribution);
        }

        let reason = match verdict {
            Verdict::Block => unique_reasons(
                contributions
                    .iter()
                    .map(|contribution| contribution.reason.as_str()),
            ),
            Verdict::Delegate if coverage == Coverage::Partial => "partial coverage".into(),
            Verdict::Delegate => "no guard blocked this call".into(),
        };
        if reason.is_empty() {
            return Err(DecisionError::MissingVerdictContribution);
        }

        Ok(Self {
            verdict,
            reason,
            policy_attributions: contributions
                .into_iter()
                .map(|contribution| contribution.guard)
                .collect(),
            coverage,
        })
    }

    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn policy_attributions(&self) -> &[GuardAttribution] {
        &self.policy_attributions
    }

    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }
}

impl<'de> Deserialize<'de> for DecisionCore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            verdict: Verdict,
            reason: String,
            policy_attributions: Vec<GuardAttribution>,
            coverage: Coverage,
        }
        let wire = Wire::deserialize(deserializer)?;
        let core = Self {
            verdict: wire.verdict,
            reason: wire.reason,
            policy_attributions: wire.policy_attributions,
            coverage: wire.coverage,
        };
        validate_core_wire(&core).map_err(serde::de::Error::custom)?;
        Ok(core)
    }
}

fn validate_core_wire(wire: &DecisionCore) -> Result<(), DecisionError> {
    text(wire.reason())?;
    ensure_sorted_unique(
        wire.policy_attributions(),
        DecisionError::NonCanonicalOrder,
        DecisionError::DuplicateAttribution,
    )?;
    if wire
        .policy_attributions()
        .windows(2)
        .any(|pair| pair[0].same_identity(&pair[1]))
    {
        return Err(DecisionError::DuplicateAttribution);
    }
    if wire.verdict() == Verdict::Delegate && !wire.policy_attributions().is_empty() {
        return Err(DecisionError::UnexpectedAttribution);
    }

    if wire.verdict() == Verdict::Delegate {
        let expected = if wire.coverage() == Coverage::Partial {
            "partial coverage"
        } else {
            "no guard blocked this call"
        };
        if wire.reason() != expected {
            return Err(DecisionError::InconsistentReason);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionError {
    EmptyText,
    DuplicateAttribution,
    MissingVerdictContribution,
    NonCanonicalOrder,
    InconsistentReason,
    InvalidTimestamp,
    UnexpectedAttribution,
}

impl DecisionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyText => "empty-text",
            Self::DuplicateAttribution => "duplicate-attribution",
            Self::MissingVerdictContribution => "missing-verdict-contribution",
            Self::NonCanonicalOrder => "non-canonical-order",
            Self::InconsistentReason => "inconsistent-reason",
            Self::InvalidTimestamp => "invalid-timestamp",
            Self::UnexpectedAttribution => "unexpected-attribution",
        }
    }
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for DecisionError {}

fn text(value: &str) -> Result<String, DecisionError> {
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or(DecisionError::EmptyText)
}

fn ensure_sorted_unique<T: Ord>(
    values: &[T],
    order_error: DecisionError,
    duplicate_error: DecisionError,
) -> Result<(), DecisionError> {
    for pair in values.windows(2) {
        match pair[0].cmp(&pair[1]) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(duplicate_error),
            std::cmp::Ordering::Greater => return Err(order_error),
        }
    }
    Ok(())
}

fn unique_reasons<'a>(reasons: impl Iterator<Item = &'a str>) -> String {
    let mut seen = BTreeSet::new();
    reasons
        .filter(|reason| seen.insert(*reason))
        .collect::<Vec<_>>()
        .join("\n")
}
