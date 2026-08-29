#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::thread;
use std::time::Duration;

use nah_proto::extension::ConsultationOutcome;

use support::{Fixture, consultation_outcomes};

#[test]
fn windows_cmd_entrypoint_launches_from_a_path_with_spaces() {
    let fixture = Fixture::batch_in_folder(
        "guard with spaces",
        "spaced",
        "set /p request=\r\necho {\"block\":true,\"reason\":\"answered\"}",
    );
    assert!(matches!(
        consultation_outcomes(fixture.consult()).as_slice(),
        [ConsultationOutcome::Response { .. }]
    ));
}

#[test]
fn windows_completed_guard_cannot_leave_a_descendant_outside_its_job() {
    let fixture = Fixture::batch(
        "descendant",
        "start \"\" /b cmd /c \"ping -n 4 127.0.0.1 >nul & echo escaped > escaped\"\r\necho {\"block\":true,\"reason\":\"answered\"}",
    );
    assert!(matches!(
        consultation_outcomes(fixture.consult()).as_slice(),
        [ConsultationOutcome::Response { .. }]
    ));
    thread::sleep(Duration::from_secs(2));
    assert!(!fixture.run.parent().unwrap().join("escaped").exists());
}

#[test]
fn windows_timeout_terminates_the_full_job_before_returning() {
    let fixture = Fixture::batch(
        "timeout",
        "start \"\" /b cmd /c \"ping -n 4 127.0.0.1 >nul & echo escaped > escaped\"\r\nping -n 10 127.0.0.1 >nul",
    );
    assert_eq!(
        consultation_outcomes(fixture.consult()),
        [ConsultationOutcome::Timeout]
    );
    thread::sleep(Duration::from_secs(2));
    assert!(!fixture.run.parent().unwrap().join("escaped").exists());
}
