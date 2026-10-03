#![cfg(unix)]

use super::support::{request, value};
use crate::fulfill_observation_request;
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    ObservationQuery, ObservationRequest, ObservationValue, Observed, UserHomeObservation,
};

#[test]
fn user_home_answers_from_the_account_database() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut queries = request(temp.path(), &[]).queries().to_vec();
    for (key, name) in [("root", "root"), ("absent", "nah-no-such-user-7f3a")] {
        queries.push(ObservationQuery::UserHome {
            key: key.into(),
            name: name.into(),
        });
    }
    let observation = fulfill_observation_request(
        &ObservationRequest::new(SchemaVersion::V1, "request", queries).expect("request"),
    )
    .expect("observation");

    let ObservationValue::UserHome {
        observed: Observed::Ok {
            value: UserHomeObservation::Home { path },
        },
    } = value(&observation, "root")
    else {
        panic!("root has an account entry");
    };
    let expected = if cfg!(target_os = "macos") {
        "/var/root"
    } else {
        "/root"
    };
    assert_eq!(path.as_str(), expected);
    // An unknown account is observed absent, not reported as a failed lookup.
    assert_eq!(
        value(&observation, "absent"),
        &ObservationValue::UserHome {
            observed: Observed::Ok {
                value: UserHomeObservation::NoSuchUser,
            },
        }
    );
}
