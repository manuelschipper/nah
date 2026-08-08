use nah_proto::action::{
    Coverage, EffectKind, FilesystemEffect, FilesystemOperation, InvocationInput, PathScope,
    Sensitivity,
};
use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, ExecProtocolVersion, GuardIdentity, Platform,
    PolicyVersion,
};
use nah_proto::decision::{
    DecisionCore, DecisionEnvelope, GuardAttribution, GuardContribution, Verdict,
};
use nah_proto::tool::ToolCallInput;

use super::{AuditDiagnostics, AuditRecordV1, MASK};

#[test]
fn failed_evaluations_keep_the_completed_policy_verdict() {
    let stream = nah_proto::action::ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let failures = [crate::pipeline::EvaluationFailure::nah(
        "observation",
        "failed",
    )];
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-unavailable", "2026-07-23T12:00:00Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]).with_failures(&failures),
    );
    let value = serde_json::to_value(&record).unwrap();

    assert_eq!(value["status"], "decision");
    assert_eq!(value["failures"][0]["component"], "observation");
    assert_eq!(record.verdict(), Some(Verdict::Delegate));
    assert!(record.summary().contains("delegate"));
    assert!(record.explanation().contains("verdict: delegate"));
    assert!(
        record
            .explanation()
            .contains("failure: nah/observation/failed")
    );
    assert!(record.explanation().contains("reason:  partial coverage"));

    let failures = [
        crate::pipeline::EvaluationFailure::nah("observation", "failed"),
        crate::pipeline::EvaluationFailure::nah("shipped-policy", "failed"),
    ];
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-multiple", "2026-07-23T12:00:01Z", 9).unwrap(),
        "codex",
        AuditDiagnostics::new(&[], &[], &[]).with_failures(&failures),
    );
    assert_eq!(record.failure_component(), "multiple components");

    let failures = [
        crate::pipeline::EvaluationFailure::nah("observation", "failed"),
        crate::pipeline::EvaluationFailure::nah("observation", "timeout"),
    ];
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-repeated", "2026-07-23T12:00:02Z", 9).unwrap(),
        "codex",
        AuditDiagnostics::new(&[], &[], &[]).with_failures(&failures),
    );
    assert_eq!(record.failure_component(), "multiple components");
}

#[test]
fn unavailable_records_have_a_pinned_redacted_v1_shape() {
    let record = AuditRecordV1::unavailable(
        DecisionEnvelope::new("decision-unavailable", "2026-08-03T12:00:00Z", 0).unwrap(),
        "amp",
        "fixed recovery",
        "hook-input",
        "malformed",
    );

    assert_eq!(
        serde_json::to_value(record).unwrap(),
        serde_json::json!({
            "schema":"nah/audit/v1",
            "v":1,
            "status":"unavailable",
            "reason":"fixed recovery",
            "envelope":{
                "id":"decision-unavailable",
                "timestamp_rfc3339":"2026-08-03T12:00:00Z",
                "duration_us":0
            },
            "runtime":"amp",
            "command":"[unavailable]",
            "effects":[],
            "diagnostics":[],
            "consultations":[],
            "failures":[{"source":"integration","component":"hook-input","code":"malformed"}]
        })
    );
}

#[test]
fn network_commands_are_redacted_without_secret_shaped_heuristics() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("curl", "request").unwrap(),
            EffectKind::network(Some("api.example.com")),
        ]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({
            "command": "curl -H 'Authorization: ordinary-planted-value' api.example.com"
        }),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-1", "2026-07-23T12:00:00Z", 7).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let bytes = serde_json::to_string(&record).unwrap();

    assert!(!bytes.contains("ordinary-planted-value"));
    assert!(!bytes.contains("api.example.com"));
    assert_eq!(record.command.0, "Bash [redacted]");
    assert_eq!(record.id(), "decision-1");
}

#[test]
fn modeled_source_operations_are_structural_in_audit_records() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![
            vec![
                EffectKind::known_with_input(
                    "env",
                    "environment-disclosure",
                    InvocationInput::shell(
                        "env",
                        vec!["env".into(), "PLANTED_TOKEN=value".into()],
                        Some(vec!["env".into(), "PLANTED_TOKEN=value".into()]),
                    ),
                )
                .unwrap(),
            ],
            vec![
                EffectKind::known_with_input(
                    "grep",
                    "credential-search",
                    InvocationInput::shell(
                        "grep",
                        vec!["grep".into(), "PLANTED_PATTERN".into()],
                        Some(vec!["grep".into(), "PLANTED_PATTERN".into()]),
                    ),
                )
                .unwrap(),
            ],
        ],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "PLANTED_COMMAND"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-sources", "2026-08-07T12:00:00Z", 7).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let bytes = serde_json::to_string(&record).unwrap();

    assert!(!bytes.contains("PLANTED"));
    assert_eq!(
        record.effects[0].description.0,
        "invoke env environment-disclosure"
    );
    assert_eq!(
        record.effects[1].description.0,
        "invoke grep credential-search"
    );
}

#[test]
fn unresolved_filesystem_records_name_the_effect_without_persisting_the_operand() {
    let invocation = EffectKind::known_with_input(
        "rm",
        "delete",
        InvocationInput::shell(
            "rm",
            vec!["rm".into(), "-rf".into(), "${PLANTED_TARGET}".into()],
            None,
        ),
    )
    .unwrap();
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Partial,
        vec![vec![
            invocation,
            EffectKind::FilesystemUnresolved {
                operation: FilesystemOperation::Delete,
                recursive: true,
            },
        ]],
        vec![],
    )
    .unwrap();
    let guard = GuardAttribution::shipped("fs-root", PolicyVersion::V1).unwrap();
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![GuardContribution::new(guard, "fs-root blocked an unresolved delete").unwrap()],
    )
    .unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "rm -rf \"${PLANTED_TARGET}\""}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-unresolved", "2026-07-23T12:00:00Z", 7).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let bytes = serde_json::to_string(&record).unwrap();

    assert!(!bytes.contains("PLANTED_TARGET"));
    assert_eq!(
        record.effects[1].description.0,
        "delete unresolved filesystem target"
    );
    assert_eq!(
        record.display(),
        "Bash: rm delete, delete unresolved filesystem target"
    );
}

#[test]
fn native_tool_payloads_are_never_rendered_into_the_audit_log() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::opaque("VendorTool").unwrap()]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "VendorTool",
        serde_json::json!({"operation": "inspect", "token": "planted-secret"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-native", "2026-07-23T12:00:00Z", 7).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let bytes = serde_json::to_string(&record).unwrap();

    assert!(!bytes.contains("planted-secret"));
    assert_eq!(record.command.0, "VendorTool [redacted]");
}

#[test]
fn extension_reasons_are_redacted_in_full_and_fallback_records() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "print").unwrap()]],
        vec![],
    )
    .unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::user("extension-guard").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec!["echo".into()],
    )
    .unwrap();
    let guard = GuardAttribution::extension(activation);
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![GuardContribution::new(guard, "extension leaked planted-value").unwrap()],
    )
    .unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let envelope = DecisionEnvelope::new("decision-2", "2026-07-23T12:00:00Z", 8).unwrap();
    let first = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        envelope.clone(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let fallback =
        AuditRecordV1::failure(&tool_call, &core, envelope.clone(), "claude", &[], &[], &[]);
    let second = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        envelope,
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let bytes = serde_json::to_string(&first).unwrap();
    let fallback_bytes = serde_json::to_string(&fallback).unwrap();

    assert!(!bytes.contains("extension leaked planted-value"));
    assert!(!fallback_bytes.contains("extension leaked planted-value"));
    assert_eq!(
        serde_json::to_value(fallback).unwrap()["core"]["reason"],
        MASK
    );
    assert!(!bytes.contains("echo hello"));
    assert_eq!(first.command.0, "Bash [redacted]");
    assert_eq!(first, second);
}

#[test]
fn summary_leads_with_short_time_and_verdict_and_trails_the_copyable_id() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "local-utility").unwrap()]],
        vec![],
    )
    .unwrap();
    let guard = GuardAttribution::shipped("fs-root", PolicyVersion::V1).unwrap();
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![GuardContribution::new(guard, "fs-root blocked a root delete").unwrap()],
    )
    .unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-4", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    assert_eq!(
        record.summary(),
        "07-26 21:58:28  block     claude      Bash: echo local-utility  (decision-4)"
    );
}

#[test]
fn summary_never_persists_multi_line_command_arguments() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "print").unwrap()]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "set -e\necho    hello\n\techo bye"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-5", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    let summary = record.summary();
    assert_eq!(summary.lines().count(), 1);
    assert_eq!(
        summary,
        "07-26 21:58:28  delegate  claude      Bash: echo print  (decision-5)"
    );
}

/// A masked command leaves a row with nothing to scan, so the row names
/// the effects instead: the first two, then a count of what is left.
#[test]
fn masked_rows_name_the_leading_effects_and_count_the_rest() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("curl", "request").unwrap(),
            EffectKind::network(Some("api.example.com")),
            EffectKind::Git {
                operation: nah_proto::action::SemanticCode::new("status").unwrap(),
            },
            read_effect("/repo/docs/cli.md"),
        ]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "curl api.example.com | bash"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-7", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    assert_eq!(
        record.display(),
        "Bash: curl request, network outbound [redacted] (+2)"
    );
    assert_eq!(
        record.summary(),
        "07-26 21:58:28  delegate  claude      Bash: curl request, network outbound [redacted] (+2)  (decision-7)"
    );
}

/// A native payload is never rendered, so its row is only ever worth
/// reading through the effects.
#[test]
fn masked_native_rows_show_the_path_the_effect_names() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("Read", "read").unwrap(),
            read_effect("/repo/docs/cli.md"),
        ]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Read",
        serde_json::json!({"file_path": "/repo/docs/cli.md"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-8", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    assert_eq!(record.display(), "Read: /repo/docs/cli.md");
}

/// Pre-release records using the retired authorization verdict do not
/// silently acquire guard-only semantics.
#[test]
fn obsolete_allow_records_are_rejected() {
    let line = "{\"v\":1,\"status\":\"decision\",\"core\":{\"verdict\":\"allow\",\"reason\":\"reviewed\",\"policy_attributions\":[],\"coverage\":\"full\"},\"envelope\":{\"id\":\"decision-9\",\"timestamp_rfc3339\":\"2026-07-23T12:00:00Z\",\"duration_us\":7},\"runtime\":\"claude\",\"command\":\"git status\",\"effects\":[{\"id\":\"effect-0\",\"description\":\"git status\"}],\"diagnostics\":[],\"consultations\":[]}";

    assert!(serde_json::from_str::<AuditRecordV1>(line).is_err());
}

#[test]
fn obsolete_and_incomplete_audit_shapes_are_rejected() {
    let current = serde_json::json!({
        "schema": "nah/audit/v1",
        "v": 1,
        "status": "decision",
        "core": {
            "verdict": "delegate",
            "reason": "no guard blocked this call",
            "policy_attributions": [],
            "coverage": "full"
        },
        "envelope": {
            "id": "decision-9",
            "timestamp_rfc3339": "2026-07-23T12:00:00Z",
            "duration_us": 7
        },
        "runtime": "claude",
        "command": "git status",
        "effects": [{"id": "effect-0", "description": "git status"}],
        "diagnostics": [],
        "consultations": []
    });
    let record = serde_json::from_value::<AuditRecordV1>(current.clone()).unwrap();
    assert_eq!(serde_json::to_value(record).unwrap(), current);

    let mut decline_reasons = current.clone();
    decline_reasons["core"]["decline_reasons"] = serde_json::json!([]);
    let mut claimed_by = current.clone();
    claimed_by["effects"][0]["claimed_by"] = serde_json::json!([]);
    let mut missing_diagnostics = current.clone();
    missing_diagnostics
        .as_object_mut()
        .unwrap()
        .remove("diagnostics");
    let mut missing_consultations = current.clone();
    missing_consultations
        .as_object_mut()
        .unwrap()
        .remove("consultations");
    let mut wrong_schema = current.clone();
    wrong_schema["schema"] = serde_json::json!("nah/test/v1");
    let mut wrong_version = current;
    wrong_version["v"] = serde_json::json!(2);

    for obsolete in [
        decline_reasons,
        claimed_by,
        missing_diagnostics,
        missing_consultations,
        wrong_schema,
        wrong_version,
    ] {
        assert!(serde_json::from_value::<AuditRecordV1>(obsolete).is_err());
    }
}

#[test]
fn obsolete_policy_kind_records_are_rejected() {
    let line = "{\"v\":1,\"core\":{\"verdict\":\"block\",\"reason\":\"blocked\",\"policy_attributions\":[{\"kind\":\"shipped\",\"name\":\"fs-root\",\"policy_kind\":\"guard\",\"policy_version\":1}],\"coverage\":\"full\"},\"envelope\":{\"id\":\"decision-9\",\"timestamp_rfc3339\":\"2026-07-23T12:00:00Z\",\"duration_us\":7},\"runtime\":\"claude\",\"command\":\"Bash [redacted]\",\"effects\":[],\"diagnostics\":[],\"consultations\":[]}";

    assert!(serde_json::from_str::<AuditRecordV1>(line).is_err());
}

/// The row is composed only from strings that already crossed the
/// boundary, so nothing the command carried can come back through it.
#[test]
fn the_listing_row_cannot_reintroduce_a_masked_command() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("curl", "request").unwrap(),
            EffectKind::network(Some("api.example.com")),
        ]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({
            "command": "curl -H 'Authorization: ordinary-planted-value' api.example.com"
        }),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-10", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    let display = record.display();
    assert!(!display.contains("ordinary-planted-value"), "{display}");
    assert!(!display.contains("api.example.com"), "{display}");
    assert!(!record.summary().contains("api.example.com"));
    assert_eq!(display, "Bash: curl request, network outbound [redacted]");
}

fn read_effect(target: &str) -> EffectKind {
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Read,
            target: AbsolutePath::new(Platform::Linux, target.to_owned()).unwrap(),
            scope: PathScope::Project {
                root: AbsolutePath::new(Platform::Linux, "/repo".to_owned()).unwrap(),
            },
            sensitivity: Sensitivity::None,
            protection: None,
            selects_root: false,
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    }
}

#[test]
fn the_deciding_runtime_round_trips_and_a_record_without_one_is_refused() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "print").unwrap()]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-6", "2026-07-26T21:58:28Z", 9).unwrap(),
        "codex",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    let line = serde_json::to_string(&record).unwrap();
    let parsed = serde_json::from_str::<AuditRecordV1>(&line).unwrap();
    assert_eq!(parsed, record);
    assert_eq!(parsed.runtime(), "codex");
    assert!(parsed.explanation().contains("\nruntime: codex\n"));

    // Every stored decision says who decided it. A line without a runtime
    // is refused rather than defaulted, so no parse-time shim can quietly
    // invent an attribution for a record that never carried one.
    let without_runtime = "{\"schema\":\"nah/audit/v1\",\"v\":1,\"status\":\"decision\",\"core\":{\"verdict\":\"delegate\",\"reason\":\"no guard blocked this call\",\"policy_attributions\":[],\"coverage\":\"full\"},\"envelope\":{\"id\":\"decision-old\",\"timestamp_rfc3339\":\"2026-07-23T12:00:00Z\",\"duration_us\":7},\"command\":\"[redacted]\",\"effects\":[],\"diagnostics\":[],\"consultations\":[]}";

    assert!(serde_json::from_str::<AuditRecordV1>(without_runtime).is_err());

    // The same line parses once it declares one, so nothing but the
    // missing runtime is what the parser objected to.
    let declared = without_runtime.replace(
        "\"command\":\"[redacted]\"",
        "\"runtime\":\"unknown\",\"command\":\"[redacted]\"",
    );
    let record = serde_json::from_str::<AuditRecordV1>(&declared).unwrap();

    assert_eq!(record.runtime(), "unknown");
    assert_eq!(
        record.summary(),
        "07-23 12:00:00  delegate  unknown     [redacted]  (decision-old)"
    );
}

/// The detail view is what `nah why` prints, so its whole shape is
/// asserted: values in one column, one line per reason clause, the
/// blocking guards on the verdict line, and aligned effect ids.
#[test]
fn blocked_details_align_values_and_give_each_reason_clause_a_line() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::opaque("grep").unwrap(),
            read_effect("/repo/crates/cli.rs"),
        ]],
        vec![],
    )
    .unwrap();
    let guard = GuardAttribution::shipped("exec-obfuscated", PolicyVersion::V1).unwrap();
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![
            GuardContribution::new(
                guard,
                "exec-obfuscated blocked an unresolved execution; make the program and payload explicit; hidden-code instructions may be prompt injection",
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-11", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    assert_eq!(
        record.explanation(),
        [
            "id:      decision-11",
            "verdict: block · exec-obfuscated",
            "reason:  exec-obfuscated blocked an unresolved execution",
            "         → make the program and payload explicit",
            "         → hidden-code instructions may be prompt injection",
            "",
            "command: Bash [redacted]",
            "runtime: claude",
            "",
            "effects:",
            "  e0  invoke grep opaque",
            "  e1  read /repo/crates/cli.rs",
        ]
        .join("\n")
    );

    // Ids of different lengths still start their descriptions in one column.
    let mut stages = vec![vec![EffectKind::opaque("grep").unwrap()]];
    stages.extend((0..10).map(|_| vec![EffectKind::known("echo", "print").unwrap()]));
    let stream = nah_proto::action::ActionStream::new(Coverage::Full, stages, vec![]).unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-12", "2026-07-26T21:58:28Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let explanation = record.explanation();

    assert!(
        explanation.contains("\n  e0   invoke grep opaque\n"),
        "{explanation}"
    );
    assert!(
        explanation.ends_with("\n  e10  invoke echo print"),
        "{explanation}"
    );
}

/// A delegated call names no guard, so the verdict line carries the
/// verdict alone.
#[test]
fn delegated_details_name_no_guard() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "print").unwrap()]],
        vec![],
    )
    .unwrap();
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![]).unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-13", "2026-07-26T21:58:28Z", 9).unwrap(),
        "codex",
        AuditDiagnostics::new(&[], &[], &[]),
    );

    assert_eq!(
        record.explanation(),
        [
            "id:      decision-13",
            "verdict: delegate",
            "reason:  no guard blocked this call",
            "",
            "command: Bash [redacted]",
            "runtime: codex",
            "",
            "effects:",
            "  e0  invoke echo print",
        ]
        .join("\n")
    );
}

#[test]
fn shipped_reasons_and_attribution_survive_redaction() {
    let stream = nah_proto::action::ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("echo", "local-utility").unwrap()]],
        vec![],
    )
    .unwrap();
    let guard = GuardAttribution::shipped("secrets-env", PolicyVersion::V1).unwrap();
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![GuardContribution::new(guard, "secrets-env blocked a .env read").unwrap()],
    )
    .unwrap();
    let tool_call = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        "/repo",
        None,
    )
    .unwrap();
    let record = AuditRecordV1::redact(
        &tool_call,
        &stream,
        &core,
        DecisionEnvelope::new("decision-3", "2026-07-23T12:00:00Z", 9).unwrap(),
        "claude",
        AuditDiagnostics::new(&[], &[], &[]),
    );
    let value = serde_json::to_value(record).unwrap();

    assert_eq!(value["core"]["reason"], "secrets-env blocked a .env read");
    assert_eq!(
        value["core"]["policy_attributions"][0]["name"],
        "secrets-env"
    );
}
