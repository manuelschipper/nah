#[cfg(unix)]
use crate::fulfill;
use crate::fulfill_with_git;
use nah_proto::ctx::SchemaVersion;
#[cfg(unix)]
use nah_proto::observation::ObservationFailure;
use nah_proto::observation::{
    EnvObservation, ObservationQuery, ObservationRequest, ObservationValue, Observed,
};
use std::path::Path;
use std::time::Duration;

#[test]
fn env_only_requests_skip_location_work_and_return_only_env_facts() {
    let name = format!("NAH_OBSERVE_TEST_UNSET_{}", std::process::id());
    assert!(std::env::var_os(&name).is_none(), "test name must be unset");
    let request = env_request(&name);

    let observation = fulfill_with_git(
        &request,
        Path::new("/nah-test-git-must-not-run"),
        Duration::ZERO,
    )
    .expect("env-only observation");
    observation.bind(&request).expect("exact binding");
    assert!(matches!(
        observation.facts(),
        [fact]
            if matches!(fact.query(), ObservationQuery::Env { name: actual, .. } if actual == &name)
                && matches!(
                    fact.value(),
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Unset
                        }
                    }
                )
    ));
}

#[cfg(unix)]
#[test]
fn env_only_non_unicode_value_is_reported() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::process::Command;

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .arg("tests::env::env_only_non_unicode_helper")
        .arg("--exact")
        .env("NAH_OBSERVE_NON_UNICODE_HELPER", "1")
        .env(
            "NAH_OBSERVE_NON_UNICODE_VALUE",
            OsString::from_vec(vec![0xff]),
        )
        .output()
        .expect("run helper");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn env_only_non_unicode_helper() {
    if std::env::var_os("NAH_OBSERVE_NON_UNICODE_HELPER").is_none() {
        return;
    }
    let request = env_request("NAH_OBSERVE_NON_UNICODE_VALUE");
    let observation = fulfill(&request).expect("env-only observation");
    assert!(matches!(
        observation.facts(),
        [fact]
            if matches!(fact.query(), ObservationQuery::Env { .. })
                && matches!(
                    fact.value(),
                    ObservationValue::Env {
                        observed: Observed::Error {
                            error: ObservationFailure::NonUnicode
                        }
                    }
                )
    ));
}

fn env_request(name: &str) -> ObservationRequest {
    ObservationRequest::new(
        SchemaVersion::V1,
        "env-request",
        vec![ObservationQuery::Env {
            key: "env".into(),
            name: name.into(),
        }],
    )
    .expect("env request")
}
