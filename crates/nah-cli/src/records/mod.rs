//! The decision log's entry points; it records decisions and never makes one.
//! Live dispatch (`dispatch.rs`) appends each decided call with
//! `append_decision`, or `append_failure` when that append fails or the
//! call's context could not load, and `hook_adapter.rs`
//! (`record_unavailable`) records a call no decision was produced for with
//! `append_unavailable`. The readers are `nah log` (`list_decisions`),
//! `nah why` (`explain_decision`) and the TUI's log screen and its summary
//! (`recent_decisions`, `decision_log_size`).

use std::collections::BTreeMap;
use std::path::PathBuf;

mod audit_record;
mod decision_log;

use nah_proto::ctx::{AbsolutePath, Ctx, Platform};
use nah_proto::decision::{DecisionEnvelope, Verdict};
use nah_proto::tool::ToolCallInput;

pub(crate) use audit_record::presentation::{detail_field, short_time, verdict_name};
pub(crate) use audit_record::{SavedSnapshot, saved_rules};
pub(crate) use decision_log::AuditError;
use decision_log::{DecisionLog, decision_log_path};

use crate::pipeline::DecisionResult;
use crate::runtime::Runtime;

/// The evaluation failures across the retained decision log, which `nah log`
/// and the TUI's log screen summarize in one line, and the TUI's log summary
/// counts as not fully checked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FailureSummary {
    pub(crate) calls: usize,
    /// Those calls whose record says Nah let them run, and those it says
    /// Nah blocked. A call no decision was produced for says neither: the
    /// runtime's failure setting at the time decided it, and the record
    /// does not keep that setting.
    pub(crate) let_run: usize,
    pub(crate) blocked: usize,
    pub(crate) latest_timestamp: String,
    pub(crate) latest_component: String,
}

/// What the whole retained decision log holds, tallied in the one scan that
/// also finds its failures. Every call counts once: in `ran`, `blocked` or
/// `saved` when its evaluation completed, and otherwise in the failure
/// summary, so those four add up to `calls`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct LogSummary {
    pub(crate) calls: usize,
    /// Calls let run with nothing saved first.
    pub(crate) ran: usize,
    pub(crate) blocked: usize,
    /// How many blocked calls each guard's rules decided; a call two
    /// guards blocked counts for both. A nah 1.x custom guard keeps its
    /// whole `custom/<name>`, since each is a guard of its own.
    pub(crate) blocking_guards: BTreeMap<String, usize>,
    /// Calls let run once Nah had saved what they would discard.
    pub(crate) saved: usize,
    /// The snapshots those calls saved, each with when its call was
    /// decided, oldest first.
    pub(crate) saved_snapshots: Vec<(String, String)>,
}

impl FailureSummary {
    /// The failure summary line, aged against the current time.
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
    pub(crate) summary: LogSummary,
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
    runtime.map_or(audit_record::UNKNOWN_RUNTIME, Runtime::cli_name)
}

pub(crate) fn append_decision(
    ctx: &Ctx,
    tool_call: &ToolCallInput,
    result: &DecisionResult,
    envelope: DecisionEnvelope,
    runtime: Option<Runtime>,
    include_refusals: bool,
) -> Result<(), AuditError> {
    let diagnostics = audit_record::AuditDiagnostics::new(result.warnings())
        .with_failures(result.failures())
        .with_refusals(if include_refusals {
            result.refusals()
        } else {
            &[]
        })
        .with_producer(
            result
                .evidence_provenance()
                .map(|provenance| provenance.producer.as_str()),
        );
    let diagnostics = diagnostics.with_effinterp(result.effinterp());
    let record = audit_record::AuditRecordV1::redact(
        tool_call,
        result.core(),
        envelope,
        runtime_name(runtime),
        diagnostics,
    )
    .with_saved(result.saved());
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
    let record = audit_record::AuditRecordV1::failure(
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
    )
    .with_saved(result.saved());
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
    let record = audit_record::AuditRecordV1::unavailable(
        envelope,
        runtime.cli_name(),
        reason,
        component,
        code,
    );
    DecisionLog::new(decision_log_path(home, platform)).append(&record)
}

/// Explains one stored decision without recovery writes: an invalid record
/// fails the lookup and leaves the corrupt log in place for diagnosis, unlike
/// `recent_decisions` and `list_decisions`.
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
    pub(crate) row_text: String,
    pub(crate) explanation: String,
    /// The snapshots Nah made before the call could run.
    pub(crate) saved: Vec<SavedSnapshot>,
}

/// Stored size of the decision log, for cheap change detection between reads.
pub(crate) fn decision_log_size(home: &AbsolutePath, platform: Platform) -> Option<u64> {
    std::fs::metadata(decision_log_path(home, platform))
        .ok()
        .map(|metadata| metadata.len())
}

/// Returns up to `limit` decisions, newest first.
///
/// This read can write: an invalid record makes it archive the live log and
/// rewrite it with a bounded tail of valid records. `recovered_from` names the
/// archive only when this call performed that recovery; it is `None` when the
/// log was valid or a concurrent reader already repaired it.
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
        summary: tail.summary,
        failures: tail.failures,
        recovered_from: tail.recovered_from,
    })
}

/// Returns up to `limit` stored decisions, oldest first, as JSON lines or
/// summaries, optionally only blocked decisions or effinterp gaps.
///
/// Like `recent_decisions`, this read archives and rewrites a log holding an
/// invalid record, and reports the archive in `recovered_from`.
pub(crate) fn list_decisions(
    home: &AbsolutePath,
    platform: Platform,
    limit: usize,
    json: bool,
    blocked: bool,
    effinterp_gap: bool,
) -> Result<DecisionLines, AuditError> {
    let log = DecisionLog::new(decision_log_path(home, platform));
    let tail = if effinterp_gap {
        log.tail_effinterp_gaps(limit)?
    } else {
        log.tail_views_with_summary(usize::from(!blocked) * limit, usize::from(blocked) * limit)?
    };
    let records = if blocked && !effinterp_gap {
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
            .map(audit_record::AuditRecordV1::listing)
            .collect()
    };
    Ok(DecisionLines {
        lines,
        failures: tail.failures,
        recovered_from: tail.recovered_from,
    })
}

fn decision_record(record: &audit_record::AuditRecordV1) -> DecisionRecord {
    DecisionRecord {
        id: record.id().to_owned(),
        timestamp: record.timestamp_rfc3339().to_owned(),
        verdict: record.verdict(),
        runtime: record.runtime().to_owned(),
        row_text: record.row_text(),
        explanation: record.explanation(),
        saved: record.saved().to_vec(),
    }
}

pub(crate) fn age(seconds: u64) -> String {
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

/// Seconds since the Unix epoch at `timestamp`, in every RFC 3339 form an
/// audit record accepts: fractional seconds are dropped, and an offset is
/// applied, so records written in different forms compare in time.
pub(crate) fn timestamp_seconds(timestamp: &str) -> Option<u64> {
    let bytes = timestamp.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let parse = |range: std::ops::Range<usize>| {
        timestamp
            .get(range)
            .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))?
            .parse::<i64>()
            .ok()
    };
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
    // A leap second, which RFC 3339 allows, counts as the next second.
    if !(1..=month_days).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let mut zone = 19;
    if bytes.get(zone) == Some(&b'.') {
        zone += 1;
        let digits = bytes[zone..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        zone += digits;
    }
    let offset = match timestamp.get(zone..)? {
        "Z" => 0,
        offset if offset.len() == 6 && offset.as_bytes()[3] == b':' => {
            let hours = parse(zone + 1..zone + 3).filter(|hours| *hours <= 23)?;
            let minutes = parse(zone + 4..zone + 6).filter(|minutes| *minutes <= 59)?;
            let east = hours * 3_600 + minutes * 60;
            match offset.as_bytes()[0] {
                b'+' => east,
                b'-' => -east,
                _ => return None,
            }
        }
        _ => return None,
    };
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days.checked_mul(86_400)? + hour * 3_600 + minute * 60 + second - offset).ok()
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
            ..FailureSummary::default()
        };
        let now = timestamp_seconds("2026-07-23T12:02:00Z");
        let future = timestamp_seconds("2026-07-23T11:59:00Z");
        for (time, expected) in [(now, "2m ago"), (future, "07-23 12:00:00")] {
            let output = summary.display_at(time);
            assert!(output.contains(expected), "{output}");
            assert!(output.contains(&summary.latest_component), "{output}");
            assert!(output.contains(&summary.calls.to_string()), "{output}");
        }
        assert!(timestamp_seconds("2026-02-31T12:00:00Z").is_none());
        // Every form an audit record accepts names its instant.
        for same in ["2026-07-23T12:00:00.250Z", "2026-07-23T14:00:00+02:00"] {
            assert_eq!(
                timestamp_seconds(same),
                timestamp_seconds("2026-07-23T12:00:00Z")
            );
        }
    }
}
