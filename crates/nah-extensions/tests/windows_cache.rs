#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::fs;

use nah_proto::extension::ConsultationOutcome;

use support::{Fixture, consultation_outcomes};

#[test]
fn windows_cache_reloads_a_successful_consultation_without_relaunching_the_guard() {
    let fixture = Fixture::batch("memo", "echo {\"block\":true,\"reason\":\"memoized\"}");
    assert!(matches!(
        consultation_outcomes(fixture.consult()).as_slice(),
        [ConsultationOutcome::Response { .. }]
    ));
    fs::remove_file(&fixture.run).unwrap();
    assert!(matches!(
        consultation_outcomes(fixture.consult()).as_slice(),
        [ConsultationOutcome::Response { .. }]
    ));
}
