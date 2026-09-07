use nah_proto::action::{ActionStream, Coverage, EffectKind};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::exec_v1::{ExecObservation, ExecV1Request};
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

    let request = ExecV1Request::new(
        action_stream(),
        Observed::Error {
            error: ObservationFailure::PermissionDenied,
        },
        Observed::Error {
            error: ObservationFailure::Timeout,
        },
    )
    .unwrap();
    assert_eq!(
        serde_json::from_value::<ExecV1Request>(serde_json::to_value(&request).unwrap()).unwrap(),
        request
    );
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({
            "v": 1,
            "action_stream": {
                "v": 1,
                "coverage": "full",
                "effects": [
                    {"id":"e0","stage":"s0","kind":{"kind":"invocation","invocation":{"kind":"known","program":"curl","operation":"request","input":{"kind":"shell","words":["curl"],"argv":["curl"]}}}},
                    {"id":"e1","stage":"s0","kind":{"kind":"network","direction":"outbound","host":"example.com"}}
                ],
                "flows": []
            },
            "observation": {
                "cwd": {"status":"error","error":"permission-denied"},
                "roots": {"status":"error","error":"timeout"}
            }
        })
    );

    let root = Root::new(
        RootKind::Project,
        AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
    );
    assert!(
        ExecV1Request::new(
            action_stream(),
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

#[test]
fn exec_decodes_version_before_its_nested_payload() {
    let exec_error = serde_json::from_value::<ExecV1Request>(serde_json::json!({
        "v": 2,
        "action_stream": {"v": 1, "effects": [{"kind": "future"}]}
    }))
    .unwrap_err();
    assert!(exec_error.to_string().contains("unsupported-version"));
}

fn action_stream() -> ActionStream {
    ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("curl", "request").unwrap(),
            EffectKind::network(Some("example.com")),
        ]],
        vec![],
    )
    .unwrap()
}
