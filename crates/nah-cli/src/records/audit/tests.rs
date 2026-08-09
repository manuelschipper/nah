use std::fs::{File, OpenOptions};
use std::path::Path;
#[cfg(unix)]
use std::time::{Duration, Instant};

use nah_proto::action::{ActionStream, Coverage, EffectKind};
use nah_proto::ctx::{AbsolutePath, Platform, PolicyVersion, SchemaVersion};
use nah_proto::decision::{
    DecisionCore, DecisionEnvelope, GuardAttribution, GuardContribution, Verdict,
};
use nah_proto::tool::ToolCallInput;

use super::{
    AuditError, COMPACTED_AUDIT_BYTES, DecisionLog, MAX_AUDIT_BYTES, RETAINED_BLOCKS,
    decision_log_path,
};
use crate::records::redaction::{AuditDiagnostics, AuditRecordV1};

fn record(id: &str) -> AuditRecordV1 {
    record_with_warnings(id, &[])
}

fn blocked_record(id: &str) -> AuditRecordV1 {
    record_with(id, Verdict::Block, &[])
}

fn record_with_warnings(id: &str, warnings: &[String]) -> AuditRecordV1 {
    record_with(id, Verdict::Delegate, warnings)
}

fn record_with(id: &str, verdict: Verdict, warnings: &[String]) -> AuditRecordV1 {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "print").unwrap()]],
        vec![],
    )
    .unwrap();
    let contributions = if verdict == Verdict::Block {
        let guard = GuardAttribution::shipped("fs-system-tree", PolicyVersion::V1).unwrap();
        vec![GuardContribution::new(guard, "fs-system-tree blocked test operation").unwrap()]
    } else {
        vec![]
    };
    let core = DecisionCore::new(&stream, verdict, contributions).unwrap();
    let call = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command":"echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    AuditRecordV1::redact(
        &call,
        &stream,
        &core,
        DecisionEnvelope::new(id, "2026-07-23T12:00:00Z", 1).unwrap(),
        "claude",
        AuditDiagnostics::new(warnings, &[], &[]),
    )
}

fn failed_record(id: &str, timestamp: &str, component: &'static str) -> AuditRecordV1 {
    let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let call = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command":"unknown"}),
        "/repo",
        None,
    )
    .unwrap();
    let failures = [crate::pipeline::EvaluationFailure::nah(component, "failed")];
    AuditRecordV1::redact(
        &call,
        &stream,
        &core,
        DecisionEnvelope::new(id, timestamp, 1).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]).with_failures(&failures),
    )
}

fn old_unavailable_record(id: &str, timestamp: &str) -> AuditRecordV1 {
    serde_json::from_value(serde_json::json!({
        "schema":"nah/audit/v1",
        "v":1,
        "status":"unavailable",
        "reason":"legacy evaluation failure",
        "envelope":{
            "id":id,
            "timestamp_rfc3339":timestamp,
            "duration_us":1
        },
        "runtime":"claude",
        "command":"[redacted]",
        "effects":[],
        "diagnostics":[],
        "consultations":[]
    }))
    .unwrap()
}

#[test]
fn log_round_trips_and_finds_records() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let path = decision_log_path(&home, Platform::Linux);
    let log = DecisionLog::new(path.clone());
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "print").unwrap()]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let call = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command":"echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    for id in ["decision-1", "decision-2"] {
        log.append(&AuditRecordV1::redact(
            &call,
            &stream,
            &core,
            DecisionEnvelope::new(id, "2026-07-23T12:00:00Z", 1).unwrap(),
            "claude",
            AuditDiagnostics::new(&[], &[], &[]),
        ))
        .unwrap();
    }

    assert_eq!(log.tail(20).unwrap().len(), 2);
    assert_eq!(log.tail(1).unwrap()[0].id(), "decision-2");
    assert_eq!(log.tail(usize::MAX).unwrap().len(), 2);
    assert_eq!(log.find("decision-2").unwrap().unwrap().id(), "decision-2");
    assert!(log.find("missing").unwrap().is_none());
    assert!(Path::new(&path).is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn retained_failure_summary_scans_beyond_the_tail_window() {
    let temp = tempfile::tempdir().unwrap();
    let log = DecisionLog::new(temp.path().join("audit.jsonl"));
    log.append(&old_unavailable_record(
        "decision-old",
        "2026-07-23T11:59:00Z",
    ))
    .unwrap();
    log.append(&failed_record(
        "decision-1",
        "2026-07-23T12:00:00Z",
        "observation",
    ))
    .unwrap();
    log.append(&record("decision-2")).unwrap();
    log.append(&failed_record(
        "decision-3",
        "2026-07-23T12:02:00Z",
        "shipped-policy",
    ))
    .unwrap();

    let view = log.tail_with_summary(1).unwrap();
    assert_eq!(view.records.len(), 1);
    let failures = view.failures.unwrap();
    assert_eq!(failures.calls, 3);
    assert_eq!(failures.latest_timestamp, "2026-07-23T12:02:00Z");
    assert_eq!(failures.latest_component, "shipped-policy");

    let empty = log.tail_with_summary(0).unwrap();
    assert!(empty.records.is_empty());
    assert!(empty.failures.is_none());
}

#[test]
fn recent_and_blocked_tails_are_independent() {
    let temp = tempfile::tempdir().unwrap();
    let log = DecisionLog::new(temp.path().join("audit.jsonl"));
    log.append(&blocked_record("decision-block-old")).unwrap();
    for index in 0..500 {
        log.append(&record(&format!("decision-delegate-{index}")))
            .unwrap();
    }
    log.append(&blocked_record("decision-block-new")).unwrap();
    log.append(&record("decision-latest")).unwrap();

    let view = log.tail_views_with_summary(2, 2).unwrap();
    assert_eq!(
        view.records
            .iter()
            .map(AuditRecordV1::id)
            .collect::<Vec<_>>(),
        ["decision-block-new", "decision-latest"]
    );
    assert_eq!(
        view.blocked_records
            .iter()
            .map(AuditRecordV1::id)
            .collect::<Vec<_>>(),
        ["decision-block-old", "decision-block-new"]
    );
}

#[test]
fn append_compacts_to_a_low_water_mark_and_then_grows_without_recompacting() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let path = decision_log_path(&home, Platform::Linux);
    let log = DecisionLog::new(path.clone());
    let new = record("decision-new");
    let old = record("decision-old");

    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut old_line = serde_json::to_vec(&old).unwrap();
    old_line.push(b'\n');
    let initial = old_line.repeat(usize::try_from(MAX_AUDIT_BYTES).unwrap() / old_line.len());
    std::fs::write(&path, initial).unwrap();
    log.append(&new).unwrap();

    let compacted = std::fs::metadata(&path).unwrap().len();
    assert!(compacted <= COMPACTED_AUDIT_BYTES);
    assert!(compacted >= COMPACTED_AUDIT_BYTES - 2 * old_line.len() as u64);
    assert_eq!(log.tail(3).unwrap(), [old.clone(), old, new.clone()]);

    let mut new_line = serde_json::to_vec(&new).unwrap();
    new_line.push(b'\n');
    for _ in 0..32 {
        log.append(&new).unwrap();
    }
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        compacted + 32 * new_line.len() as u64
    );
}

#[test]
fn compaction_preserves_blocks_older_than_the_recent_byte_window() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    let blocked = blocked_record("decision-block-old");
    let delegated = record("decision-delegate");
    let incoming = record("decision-new");
    let mut blocked_line = serde_json::to_vec(&blocked).unwrap();
    blocked_line.push(b'\n');
    let mut delegated_line = serde_json::to_vec(&delegated).unwrap();
    delegated_line.push(b'\n');
    let mut initial = blocked_line;
    let repeats =
        (usize::try_from(MAX_AUDIT_BYTES).unwrap() - initial.len()) / delegated_line.len();
    initial.extend(delegated_line.repeat(repeats));
    std::fs::write(&path, initial).unwrap();

    log.append(&incoming).unwrap();

    assert_eq!(
        log.tail_views_with_summary(0, 1).unwrap().blocked_records,
        [blocked]
    );
    assert!(log.find("decision-new").unwrap().is_some());
    assert!(std::fs::metadata(path).unwrap().len() <= MAX_AUDIT_BYTES);
}

#[test]
fn compaction_preserves_the_latest_two_hundred_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    let blocks = (0..=RETAINED_BLOCKS)
        .map(|index| blocked_record(&format!("decision-block-{index}")))
        .collect::<Vec<_>>();
    let mut initial = Vec::new();
    for block in &blocks {
        initial.extend(serde_json::to_vec(block).unwrap());
        initial.push(b'\n');
    }
    let delegated = record("decision-delegate");
    let mut delegated_line = serde_json::to_vec(&delegated).unwrap();
    delegated_line.push(b'\n');
    let repeats =
        (usize::try_from(MAX_AUDIT_BYTES).unwrap() - initial.len()) / delegated_line.len();
    initial.extend(delegated_line.repeat(repeats));
    std::fs::write(&path, initial).unwrap();
    let warnings = vec!["x".repeat(delegated_line.len())];

    log.append(&record_with_warnings("decision-new", &warnings))
        .unwrap();

    let retained = log
        .tail_views_with_summary(0, usize::MAX)
        .unwrap()
        .blocked_records;
    for index in 1..=RETAINED_BLOCKS {
        assert!(
            retained
                .iter()
                .any(|record| record.id() == format!("decision-block-{index}"))
        );
    }
}

#[test]
fn append_repairs_an_incomplete_tail_without_losing_complete_records() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    let old = record("decision-old");
    let new = record("decision-new");
    let mut bytes = serde_json::to_vec(&old).unwrap();
    bytes.extend_from_slice(b"\n{\"partial\":\"torn\"");
    std::fs::write(&path, bytes).unwrap();

    log.append(&new).unwrap();

    assert_eq!(log.tail(10).unwrap(), [old, new]);
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.ends_with(b"\n"));
    assert!(
        !bytes
            .windows(b"\"partial\"".len())
            .any(|window| window == b"\"partial\"")
    );
}

#[test]
fn held_lock_fails_fast_for_appends_and_reads() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    let old = record("decision-old");
    log.append(&old).unwrap();
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    File::lock(&held).unwrap();

    assert_eq!(log.append(&record("decision-new")), Err(AuditError::Io));
    assert_eq!(log.tail(1), Err(AuditError::Io));
    assert_eq!(log.find("decision-old"), Err(AuditError::Io));

    File::unlock(&held).unwrap();
    assert_eq!(log.tail(1).unwrap(), [old]);
}

#[test]
fn readers_reject_an_oversized_log_before_parsing_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    std::fs::write(
        path,
        vec![b'x'; usize::try_from(MAX_AUDIT_BYTES).unwrap() + 1],
    )
    .unwrap();

    assert_eq!(log.tail(1), Err(AuditError::InvalidRecord));
    assert_eq!(log.find("decision-old"), Err(AuditError::InvalidRecord));
}

#[test]
fn an_incoming_record_over_the_low_water_mark_replaces_old_history() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    let old = record("decision-old");
    let mut old_line = serde_json::to_vec(&old).unwrap();
    old_line.push(b'\n');
    std::fs::write(
        &path,
        old_line.repeat(usize::try_from(MAX_AUDIT_BYTES).unwrap() / old_line.len()),
    )
    .unwrap();
    let warnings = vec!["x".repeat(usize::try_from(COMPACTED_AUDIT_BYTES).unwrap() + 1024)];
    let large = record_with_warnings("decision-large", &warnings);

    log.append(&large).unwrap();

    assert_eq!(log.tail(2).unwrap(), [large]);
    let size = std::fs::metadata(path).unwrap().len();
    assert!(size > COMPACTED_AUDIT_BYTES);
    assert!(size <= MAX_AUDIT_BYTES);
}

#[test]
fn oversized_append_rejection_preserves_the_existing_log() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let log = DecisionLog::new(path.clone());
    log.append(&record("decision-old")).unwrap();
    let original = std::fs::read(&path).unwrap();
    let warnings = vec!["x".repeat(usize::try_from(MAX_AUDIT_BYTES).unwrap() + 1)];
    let oversized = record_with_warnings("decision-oversized", &warnings);

    assert_eq!(log.append(&oversized), Err(AuditError::InvalidRecord));
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn non_regular_audit_path_fails_without_blocking() {
    use std::os::unix::net::UnixListener;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let _socket = UnixListener::bind(&path).unwrap();
    let log = DecisionLog::new(path);
    let started = Instant::now();

    assert_eq!(log.append(&record("decision-new")), Err(AuditError::Io));
    assert_eq!(log.tail(1), Err(AuditError::Io));
    assert_eq!(log.find("decision-new"), Err(AuditError::Io));
    assert!(started.elapsed() < Duration::from_secs(1));
}
