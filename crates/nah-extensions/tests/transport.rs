#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::fs;
use std::time::{Duration, Instant};

use nah_proto::extension::{ConsultationOutcome, TransportRejectionCode};

use support::{Fixture, absolute, consultation_outcomes, finish, write_manifest};

#[test]
fn shell_python_and_compiled_extensions_answer_exec_v1() {
    let shell = Fixture::shell(
        "shell",
        r#"read request
printf '%s\n' '{"block":true,"reason":"shell answered"}'"#,
    );
    let outcomes = consultation_outcomes(shell.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));

    let python = Fixture::shell(
        "python",
        r#"python3 -c 'import json,sys; json.load(sys.stdin); print(json.dumps({"block": True, "reason": "python answered"}))'"#,
    );
    let outcomes = consultation_outcomes(python.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));

    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let directory = temp.path().join(".nah/guards/compiled");
    fs::create_dir_all(&directory).unwrap();
    write_manifest(&directory, "compiled", "tool");
    let source = directory.join("fixture.rs");
    fs::write(
        &source,
        r##"fn main() { println!("{}", r#"{"block":true,"reason":"compiled answered"}"#); }"##,
    )
    .unwrap();
    let run = directory.join("run");
    let status = std::process::Command::new("rustc")
        .args([source.as_os_str(), "-o".as_ref(), run.as_os_str()])
        .status()
        .unwrap();
    assert!(status.success());
    let compiled = finish(temp, home, run, "tool");
    let outcomes = consultation_outcomes(compiled.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
}

#[test]
fn explicit_abstention_is_a_successful_response() {
    let fixture = Fixture::shell("abstain", "printf '%s\\n' '{\"abstain\":true}'");
    let output = fixture.consult();
    assert!(output.failures.is_empty());
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.responses.len(), 1);
    assert!(output.responses[0].is_abstain());
}

#[test]
fn process_precedence_is_stable() {
    let timeout = Fixture::shell("timeout", "head -c 70000 /dev/zero\nsleep 2");
    let output = timeout.consult();
    assert_eq!(output.failures.len(), 1);
    let outcomes = consultation_outcomes(output);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0], ConsultationOutcome::Timeout);

    let oversize = Fixture::shell("oversize", "head -c 70000 /dev/zero\nexit 9");
    let output = oversize.consult();
    assert_eq!(output.failures.len(), 1);
    let outcomes = consultation_outcomes(output);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0],
        ConsultationOutcome::RejectedTransport {
            code: TransportRejectionCode::Oversize
        }
    );

    let crash = Fixture::shell(
        "crash",
        "printf '%s\\n' '{\"block\":true,\"reason\":\"valid\"}'\nexit 9",
    );
    let output = crash.consult();
    assert_eq!(output.failures.len(), 1);
    let outcomes = consultation_outcomes(output);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0], ConsultationOutcome::Crash);

    let silence = Fixture::shell("silence", "exit 0");
    let output = silence.consult();
    assert_eq!(output.failures[0].code(), "silence");
    assert_eq!(
        output.consultations[0].outcome,
        ConsultationOutcome::Silence
    );
    assert!(output.responses.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.ends_with("silence"))
    );

    let spawn = Fixture::shell("spawn", "exit 0");
    fs::remove_file(&spawn.run).unwrap();
    let output = spawn.consult();
    assert_eq!(output.failures.len(), 1);
    let outcomes = consultation_outcomes(output);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0], ConsultationOutcome::SpawnFailure);
}

#[test]
fn completed_extension_cannot_leave_a_pipe_holding_descendant() {
    let fixture = Fixture::shell(
        "descendant",
        "(sleep 5) &\nprintf '%s\\n' '{\"block\":true,\"reason\":\"answered\"}'",
    );
    let started = Instant::now();
    let outcomes = consultation_outcomes(fixture.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn transport_rejections_are_classified() {
    for (name, body, code, failure_code) in [
        (
            "invalid-utf8",
            "printf '\\377'",
            TransportRejectionCode::InvalidUtf8,
            "invalid-utf8",
        ),
        (
            "invalid-json",
            "printf 'garbage\\n'",
            TransportRejectionCode::InvalidJson,
            "invalid-json",
        ),
        (
            "multiple",
            "printf '{} {}\\n'",
            TransportRejectionCode::MultipleValues,
            "multiple-values",
        ),
        (
            "framing",
            "printf ' {\"block\":true,\"reason\":\"x\"}\\n'",
            TransportRejectionCode::InvalidFraming,
            "invalid-framing",
        ),
        (
            "fields",
            "printf '{\"blok\":true,\"reason\":\"x\"}\\n'",
            TransportRejectionCode::InvalidResponseFields,
            "invalid-response-fields",
        ),
    ] {
        let fixture = Fixture::shell(name, body);
        let output = fixture.consult();
        assert_eq!(output.failures.len(), 1, "{name}");
        assert_eq!(output.failures[0].code(), failure_code, "{name}");
        let outcomes = consultation_outcomes(output);
        assert_eq!(outcomes.len(), 1, "{name}");
        assert_eq!(
            outcomes[0],
            ConsultationOutcome::RejectedTransport { code },
            "{name}"
        );
    }
}

#[test]
fn semantic_rejections_keep_stable_failure_codes() {
    for (name, response, expected) in [
        ("missing", "{}", "missing-outcome"),
        ("false-block", r#"{"block":false}"#, "block-must-be-true"),
        ("missing-reason", r#"{"block":true}"#, "missing-reason"),
        (
            "ambiguous",
            r#"{"block":true,"abstain":true,"reason":"x"}"#,
            "ambiguous-response",
        ),
        (
            "abstain-reason",
            r#"{"abstain":true,"reason":"x"}"#,
            "abstain-has-reason",
        ),
    ] {
        let fixture = Fixture::shell(name, &format!("printf '%s\\n' '{response}'"));
        let output = fixture.consult();
        assert_eq!(output.failures[0].code(), expected, "{name}");
        assert!(output.responses.is_empty(), "{name}");
    }
}

#[test]
fn terminal_sequences_are_stripped_before_semantic_validation() {
    let fixture = Fixture::shell(
        "ansi",
        "printf '%s\\n' '{\"block\":true,\"reason\":\"safe\\u001b[31m red\\u001b[0m\"}'",
    );
    let output = fixture.consult();
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.responses.len(), 1);
    assert_eq!(output.responses[0].reason(), "safe red");
}

#[test]
fn bounded_stderr_is_sanitized_and_returned_as_a_diagnostic() {
    let fixture = Fixture::shell(
        "stderr",
        "printf 'planted\\033[31m red\\033[0m' >&2\nexit 9",
    );
    let output = fixture.consult();

    assert_eq!(output.failures[0].code(), "crash");
    assert_eq!(output.consultations[0].outcome, ConsultationOutcome::Crash);
    assert!(output.responses.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.ends_with("crash"))
    );
    assert_eq!(output.diagnostics.len(), 1);
    assert_eq!(output.diagnostics[0].stderr(), "planted red");
}
