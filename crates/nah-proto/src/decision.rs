//! Deterministic decision contracts produced by policy reduction.

use std::error::Error;
use std::fmt;

use crate::action::Coverage;
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
}

impl GuardAttribution {
    pub fn shipped(name: &str) -> Result<Self, DecisionError> {
        Ok(Self::Shipped { name: text(name)? })
    }

    /// The name an operator types to change this guard: a shipped rule ID.
    pub fn name(&self) -> &str {
        match self {
            Self::Shipped { name } => name,
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
        }

        match Wire::deserialize(deserializer)? {
            Wire::Shipped { name } => text(&name).map(|name| Self::Shipped { name }),
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

    pub fn shipped_name(&self) -> &str {
        self.guard.name()
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
    /// A block no guard contribution decided: self-protection, a suspicion
    /// after a failed evaluation, or a fail-closed refusal. `rule` is the
    /// rule ID the block falls under, when it has one.
    pub fn structural_block_with_coverage(
        coverage: Coverage,
        rule: Option<&str>,
        reason: &str,
    ) -> Result<Self, DecisionError> {
        Ok(Self {
            verdict: Verdict::Block,
            reason: headline(rule, &text(reason)?, &[]),
            policy_attributions: Vec::new(),
            coverage,
        })
    }

    /// A self-protection block under `rules`, the first leading with
    /// `reason`, that also keeps the shipped guards in `contributions`. The
    /// other self rules and then the guards are named after the lead.
    /// Attributions are the guards, in attribution order.
    pub fn structural_block_keeping(
        coverage: Coverage,
        rules: &[&str],
        reason: &str,
        mut contributions: Vec<GuardContribution>,
    ) -> Result<Self, DecisionError> {
        contributions.sort_by(|left, right| left.guard.cmp(&right.guard));
        if contributions
            .windows(2)
            .any(|pair| pair[0].guard == pair[1].guard)
        {
            return Err(DecisionError::DuplicateAttribution);
        }
        let (lead, rules) = rules.split_first().ok_or(DecisionError::EmptyText)?;
        let others = rules
            .iter()
            .map(|rule| (*rule).to_owned())
            .chain(
                contributions
                    .iter()
                    .map(|contribution| contribution.guard.name().to_owned()),
            )
            .collect::<Vec<_>>();
        Ok(Self {
            verdict: Verdict::Block,
            reason: headline(Some(lead), &text(reason)?, &others),
            policy_attributions: contributions
                .into_iter()
                .map(|contribution| contribution.guard)
                .collect(),
            coverage,
        })
    }

    pub fn new_with_coverage(
        coverage: Coverage,
        verdict: Verdict,
        mut contributions: Vec<GuardContribution>,
    ) -> Result<Self, DecisionError> {
        contributions.sort_by(|left, right| left.guard.cmp(&right.guard));
        if contributions
            .windows(2)
            .any(|pair| pair[0].guard == pair[1].guard)
        {
            return Err(DecisionError::DuplicateAttribution);
        }
        if verdict == Verdict::Delegate && !contributions.is_empty() {
            return Err(DecisionError::UnexpectedAttribution);
        }

        let reason = match verdict {
            Verdict::Block => lead_headline(&contributions),
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
        .any(|pair| pair[0] == pair[1])
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

/// Whether a block's reason is led by a `self` rule: self-protection blocked
/// the call, and any shipped rules it names after the lead matched too.
pub fn led_by_self_rule(reason: &str) -> bool {
    reason.starts_with("self/")
}

/// The first sentences of a block message, `<rule-id>: <risk>. <recovery>.`,
/// for the rule that leads it, then every other blocking rule by name:
/// `Also blocked by A and B.` The caller adds the `nah · ` prefix and the
/// next step.
fn headline(lead: Option<&str>, reason: &str, others: &[String]) -> String {
    let mut headline = match lead {
        Some(rule) => format!("{rule}: {}", sentence(reason)),
        None => sentence(reason),
    };
    if let Some((last, rest)) = others.split_last() {
        headline.push_str(" Also blocked by ");
        if !rest.is_empty() {
            headline.push_str(&rest.join(", "));
            headline.push_str(" and ");
        }
        headline.push_str(last);
        headline.push('.');
    }
    headline
}

/// `text` closed as a sentence: a reason may already end in one.
fn sentence(text: &str) -> String {
    let text = text.trim_end();
    if text.ends_with(['.', '!', '?']) {
        text.to_owned()
    } else {
        format!("{text}.")
    }
}

/// The headline of a block decided by `contributions`, in attribution
/// order; an empty list has none.
fn lead_headline(contributions: &[GuardContribution]) -> String {
    let guards = contributions
        .iter()
        .map(|contribution| contribution.guard.clone())
        .collect::<Vec<_>>();
    let Some(lead) = lead(&guards) else {
        return String::new();
    };
    let reason = contributions
        .iter()
        .find(|contribution| contribution.guard == *lead)
        .map_or("", |contribution| contribution.reason.as_str());
    headline(Some(lead.name()), reason, &others(&guards, lead))
}

/// The guard that leads a block message: the first rule in catalog order,
/// so the broadest loss speaks first.
fn lead(guards: &[GuardAttribution]) -> Option<&GuardAttribution> {
    guards.iter().min_by_key(|guard| {
        crate::ctx::Guard::of_rule(guard.name())
            .and_then(|guard| {
                crate::ctx::Guard::ALL
                    .iter()
                    .position(|each| *each == guard)
            })
            .unwrap_or(usize::MAX)
    })
}

/// The names of `guards` other than `lead`, in attribution order.
fn others(guards: &[GuardAttribution], lead: &GuardAttribution) -> Vec<String> {
    guards
        .iter()
        .filter(|guard| !std::ptr::eq(*guard, lead))
        .map(|guard| guard.name().to_owned())
        .collect()
}
