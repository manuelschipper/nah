//! Nondeterministic decision envelopes and machine-facing output contracts.

use crate::action::Coverage;
use crate::ctx::SchemaVersion;
use serde::{Deserialize, Serialize};

use super::{DecisionCore, DecisionError, GuardAttribution, Verdict, ensure_sorted_unique, text};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionEnvelope {
    id: String,
    timestamp_rfc3339: String,
    duration_us: u64,
}

impl DecisionEnvelope {
    pub fn new(id: &str, timestamp_rfc3339: &str, duration_us: u64) -> Result<Self, DecisionError> {
        if !is_rfc3339(timestamp_rfc3339) {
            return Err(DecisionError::InvalidTimestamp);
        }
        Ok(Self {
            id: text(id)?,
            timestamp_rfc3339: timestamp_rfc3339.into(),
            duration_us,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn timestamp_rfc3339(&self) -> &str {
        &self.timestamp_rfc3339
    }

    pub const fn duration_us(&self) -> u64 {
        self.duration_us
    }
}

impl<'de> Deserialize<'de> for DecisionEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: String,
            timestamp_rfc3339: String,
            duration_us: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(&wire.id, &wire.timestamp_rfc3339, wire.duration_us)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Decision {
    v: SchemaVersion,
    core: DecisionCore,
    envelope: DecisionEnvelope,
}

impl Decision {
    pub fn new(core: DecisionCore, envelope: DecisionEnvelope) -> Self {
        Self {
            v: SchemaVersion::V1,
            core,
            envelope,
        }
    }

    pub const fn version(&self) -> SchemaVersion {
        self.v
    }

    pub fn core(&self) -> &DecisionCore {
        &self.core
    }

    pub fn envelope(&self) -> &DecisionEnvelope {
        &self.envelope
    }
}

impl<'de> Deserialize<'de> for Decision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(rename = "v")]
            _v: SchemaVersion,
            core: DecisionCore,
            envelope: DecisionEnvelope,
        }
        let wire: Wire = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self::new(wire.core, wire.envelope))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionOutput {
    schema: &'static str,
    v: SchemaVersion,
    verdict: Verdict,
    reason: String,
    policy_attributions: Vec<GuardAttribution>,
    id: String,
    coverage: Coverage,
    duration_us: u64,
}

impl DecisionOutput {
    pub const SCHEMA: &'static str = "nah/decide/v1";

    pub fn new(core: &DecisionCore, id: &str, duration_us: u64) -> Result<Self, DecisionError> {
        Ok(Self::from_validated(core, text(id)?, duration_us))
    }

    fn from_validated(core: &DecisionCore, id: String, duration_us: u64) -> Self {
        let extension_selected = core.policy_attributions.iter().any(|guard| {
            matches!(guard, GuardAttribution::Extension { .. }) && core.verdict == Verdict::Block
        });
        let reason = if extension_selected {
            "extension guard blocked the call".into()
        } else {
            core.reason.clone()
        };
        Self {
            schema: Self::SCHEMA,
            v: SchemaVersion::V1,
            verdict: core.verdict,
            reason,
            policy_attributions: core.policy_attributions.clone(),
            id,
            coverage: core.coverage,
            duration_us,
        }
    }

    pub const fn version(&self) -> SchemaVersion {
        self.v
    }

    pub const fn schema(&self) -> &'static str {
        self.schema
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

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }

    pub const fn duration_us(&self) -> u64 {
        self.duration_us
    }
}

impl<'de> Deserialize<'de> for DecisionOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema: String,
            v: SchemaVersion,
            verdict: Verdict,
            reason: String,
            policy_attributions: Vec<GuardAttribution>,
            id: String,
            coverage: Coverage,
            duration_us: u64,
        }
        let wire: Wire = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        if wire.schema != Self::SCHEMA {
            return Err(serde::de::Error::custom("unsupported-decision-schema"));
        }
        text(&wire.reason).map_err(serde::de::Error::custom)?;
        text(&wire.id).map_err(serde::de::Error::custom)?;
        ensure_sorted_unique(
            &wire.policy_attributions,
            DecisionError::NonCanonicalOrder,
            DecisionError::DuplicateAttribution,
        )
        .map_err(serde::de::Error::custom)?;
        if wire.verdict == Verdict::Delegate && !wire.policy_attributions.is_empty() {
            return Err(serde::de::Error::custom(
                DecisionError::UnexpectedAttribution,
            ));
        }
        Ok(Self {
            schema: Self::SCHEMA,
            v: wire.v,
            verdict: wire.verdict,
            reason: wire.reason,
            policy_attributions: wire.policy_attributions,
            id: wire.id,
            coverage: wire.coverage,
            duration_us: wire.duration_us,
        })
    }
}

impl From<&Decision> for DecisionOutput {
    fn from(decision: &Decision) -> Self {
        Self::from_validated(
            &decision.core,
            decision.envelope.id.clone(),
            decision.envelope.duration_us,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitCode(u8);

impl ExitCode {
    /// nah could not decide at all, so it reports no verdict and no decision
    /// body. Adapters treat this as an evaluation failure and delegate.
    pub const UNAVAILABLE: Self = Self(3);

    pub const fn value(self) -> u8 {
        self.0
    }
}

impl From<Verdict> for ExitCode {
    fn from(verdict: Verdict) -> Self {
        Self(match verdict {
            Verdict::Block => 1,
            Verdict::Delegate => 2,
        })
    }
}

fn is_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        value
            .get(range)
            .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|part| part.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if year == 0 || day == 0 || day > max_day || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let mut offset = 19;
    if bytes.get(offset) == Some(&b'.') {
        offset += 1;
        let start = offset;
        while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        if offset == start {
            return false;
        }
    }
    match bytes.get(offset..) {
        Some(b"Z") => true,
        Some(zone)
            if zone.len() == 6
                && matches!(zone[0], b'+' | b'-')
                && zone[3] == b':'
                && zone[1..3].iter().all(u8::is_ascii_digit)
                && zone[4..6].iter().all(u8::is_ascii_digit) =>
        {
            let hours = u32::from(zone[1] - b'0') * 10 + u32::from(zone[2] - b'0');
            let minutes = u32::from(zone[4] - b'0') * 10 + u32::from(zone[5] - b'0');
            hours <= 23 && minutes <= 59
        }
        _ => false,
    }
}
