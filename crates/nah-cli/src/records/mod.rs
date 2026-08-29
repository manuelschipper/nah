//! Persists redacted audit data; it does not decide policy.

use std::path::PathBuf;

mod audit;
mod redaction;

use nah_proto::ctx::{AbsolutePath, Ctx, Platform};
use nah_proto::decision::{DecisionEnvelope, Verdict};
use nah_proto::tool::ToolCallInput;

use audit::{AuditError, DecisionLog, decision_log_path};
pub(crate) use redaction::{field as detail_field, short_time, verdict_name};

use crate::pipeline::DecisionResult;
use crate::runtime::Runtime;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FailureSummary {
    pub(crate) calls: usize,
    pub(crate) latest_timestamp: String,
    pub(crate) latest_component: String,
}

impl FailureSummary {
    pub(crate) fn display(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
        self.display_at(now)
    }

    fn display_at(&self, now: Option<u64>) -> String {
        let latest = now
            .zip(timestamp_seconds(&self.latest_timestamp))
            .and_then(|(now, timestamp)| now.checked_sub(timestamp))
            .map(age)
            .unwrap_or_else(|| short_time(&self.latest_timestamp));
        let noun = if self.calls == 1 { "call" } else { "calls" };
        format!(
            "nah: evaluation failures affected {} {noun} in the retained log; latest {latest} ({}).",
            self.calls, self.latest_component
        )
    }
}

pub(crate) struct DecisionLogView {
    pub(crate) records: Vec<DecisionRecord>,
    pub(crate) blocked_records: Vec<DecisionRecord>,
    pub(crate) failures: Option<FailureSummary>,
    pub(crate) recovered_from: Option<PathBuf>,
}

pub(crate) struct DecisionLines {
    pub(crate) lines: Vec<String>,
    pub(crate) failures: Option<FailureSummary>,
    pub(crate) recovered_from: Option<PathBuf>,
}

/// Only a runtime adapter knows which agent sent a call, so decisions reaching
/// the generic `nah decide` seam are recorded without one.
fn runtime_name(runtime: Option<Runtime>) -> &'static str {
    runtime.map_or(redaction::UNKNOWN_RUNTIME, Runtime::cli_name)
}

pub(crate) fn append_decision(
    ctx: &Ctx,
    tool_call: &ToolCallInput,
    result: &DecisionResult,
    envelope: DecisionEnvelope,
    runtime: Option<Runtime>,
    include_refusals: bool,
) -> Result<(), AuditError> {
    let record = redaction::AuditRecordV1::redact(
        tool_call,
        result.action_stream(),
        result.core(),
        envelope,
        runtime_name(runtime),
        redaction::AuditDiagnostics::new(
            result.warnings(),
            result.consultations(),
            result.diagnostics(),
        )
        .with_failures(result.failures())
        .with_refusals(if include_refusals {
            result.refusals()
        } else {
            &[]
        }),
    );
    DecisionLog::new(decision_log_path(ctx.home(), ctx.platform())).append(&record)
}

pub(crate) fn append_failure(
    home: &AbsolutePath,
    platform: Platform,
    tool_call: &ToolCallInput,
    result: &DecisionResult,
    envelope: DecisionEnvelope,
    runtime: Option<Runtime>,
    include_refusals: bool,
) -> Result<(), AuditError> {
    let record = redaction::AuditRecordV1::failure(
        tool_call,
        result.core(),
        envelope,
        runtime_name(runtime),
        result.warnings(),
        result.failures(),
        if include_refusals {
            result.refusals()
        } else {
            &[]
        },
    );
    DecisionLog::new(decision_log_path(home, platform)).append(&record)
}

pub(crate) fn append_unavailable(
    home: &AbsolutePath,
    platform: Platform,
    envelope: DecisionEnvelope,
    runtime: Runtime,
    component: &str,
    code: &str,
    reason: &str,
) -> Result<(), AuditError> {
    let record = redaction::AuditRecordV1::unavailable(
        envelope,
        runtime.cli_name(),
        reason,
        component,
        code,
    );
    DecisionLog::new(decision_log_path(home, platform)).append(&record)
}

pub(crate) fn explain_decision(
    home: &AbsolutePath,
    platform: Platform,
    id: &str,
) -> Result<Option<String>, AuditError> {
    Ok(DecisionLog::new(decision_log_path(home, platform))
        .find(id)?
        .map(|record| record.explanation()))
}

/// One stored decision projected for interactive browsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecisionRecord {
    pub(crate) id: String,
    pub(crate) timestamp: String,
    pub(crate) verdict: Option<Verdict>,
    pub(crate) runtime: String,
    /// Scannable row text: the command when it survived redaction, the tool
    /// and its effects when it did not.
    pub(crate) display: String,
    pub(crate) explanation: String,
}

/// Stored size of the decision log, for cheap change detection between reads.
pub(crate) fn decision_log_size(home: &AbsolutePath, platform: Platform) -> Option<u64> {
    std::fs::metadata(decision_log_path(home, platform))
        .ok()
        .map(|metadata| metadata.len())
}

/// Returns up to `limit` decisions, newest first.
pub(crate) fn recent_decisions(
    home: &AbsolutePath,
    platform: Platform,
    limit: usize,
) -> Result<DecisionLogView, AuditError> {
    let tail = DecisionLog::new(decision_log_path(home, platform))
        .tail_views_with_summary(limit, limit)?;
    Ok(DecisionLogView {
        records: tail.records.iter().rev().map(decision_record).collect(),
        blocked_records: tail
            .blocked_records
            .iter()
            .rev()
            .map(decision_record)
            .collect(),
        failures: tail.failures,
        recovered_from: tail.recovered_from,
    })
}

pub(crate) fn list_decisions(
    home: &AbsolutePath,
    platform: Platform,
    limit: usize,
    json: bool,
    blocked: bool,
) -> Result<DecisionLines, AuditError> {
    let tail = DecisionLog::new(decision_log_path(home, platform))
        .tail_views_with_summary(usize::from(!blocked) * limit, usize::from(blocked) * limit)?;
    let records = if blocked {
        &tail.blocked_records
    } else {
        &tail.records
    };
    let lines = if json {
        records
            .iter()
            .map(|record| serde_json::to_string(record).map_err(|_| AuditError::InvalidRecord))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        records
            .iter()
            .map(redaction::AuditRecordV1::summary)
            .collect()
    };
    Ok(DecisionLines {
        lines,
        failures: tail.failures,
        recovered_from: tail.recovered_from,
    })
}

fn decision_record(record: &redaction::AuditRecordV1) -> DecisionRecord {
    DecisionRecord {
        id: record.id().to_owned(),
        timestamp: record.timestamp_rfc3339().to_owned(),
        verdict: record.verdict(),
        runtime: record.runtime().to_owned(),
        display: record.display(),
        explanation: record.explanation(),
    }
}

fn age(seconds: u64) -> String {
    if seconds < 60 {
        "<1m ago".into()
    } else if seconds < 3_600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3_600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

fn timestamp_seconds(timestamp: &str) -> Option<u64> {
    if timestamp.len() != 20
        || timestamp.as_bytes().get(4) != Some(&b'-')
        || timestamp.as_bytes().get(7) != Some(&b'-')
        || timestamp.as_bytes().get(10) != Some(&b'T')
        || timestamp.as_bytes().get(13) != Some(&b':')
        || timestamp.as_bytes().get(16) != Some(&b':')
        || timestamp.as_bytes().get(19) != Some(&b'Z')
    {
        return None;
    }
    let parse = |range: std::ops::Range<usize>| timestamp.get(range)?.parse::<i64>().ok();
    let year = parse(0..4)?;
    let month = parse(5..7)?;
    let day = parse(8..10)?;
    let hour = parse(11..13)?;
    let minute = parse(14..16)?;
    let second = parse(17..19)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    if !(1..=month_days).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days.checked_mul(86_400)? + hour * 3_600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod tests {
    use super::{FailureSummary, timestamp_seconds};

    #[test]
    fn failure_summary_uses_coarse_age_and_safe_fallbacks() {
        let summary = FailureSummary {
            calls: 1,
            latest_timestamp: "2026-07-23T12:00:00Z".into(),
            latest_component: "observation".into(),
        };
        let now = timestamp_seconds("2026-07-23T12:02:00Z");
        assert_eq!(
            summary.display_at(now),
            "nah: evaluation failures affected 1 call in the retained log; latest 2m ago (observation)."
        );

        let future = timestamp_seconds("2026-07-23T11:59:00Z");
        assert_eq!(
            summary.display_at(future),
            "nah: evaluation failures affected 1 call in the retained log; latest 07-23 12:00:00 (observation)."
        );
        assert!(timestamp_seconds("2026-02-31T12:00:00Z").is_none());
    }
}
