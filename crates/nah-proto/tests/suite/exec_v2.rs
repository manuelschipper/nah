use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::exec_v2::ExecObservation;
use nah_proto::observation::{ObservationFailure, Observed, Root, RootKind};

#[test]
fn exec_excerpt_carries_observation_failures_without_ambient_fallback() {
    let excerpt = ExecObservation::new(
        Observed::Error {
            error: ObservationFailure::PermissionDenied,
        },
        Observed::Error {
            error: ObservationFailure::Timeout,
        },
    )
    .unwrap();

    assert_eq!(
        serde_json::to_value(excerpt).unwrap(),
        serde_json::json!({
            "cwd": {"status": "error", "error": "permission-denied"},
            "roots": {"status": "error", "error": "timeout"}
        })
    );

    let root = Root::new(
        RootKind::Project,
        AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
    );
    assert!(
        ExecObservation::new(
            Observed::Ok {
                value: AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
            },
            Observed::Ok {
                value: vec![root.clone(), root],
            },
        )
        .is_err()
    );
}
