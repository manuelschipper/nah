use nah_proto::action::{
    ActionStream, ActionStreamVersion, Coverage, EffectId, EffectKind, FilesystemEffect,
    FilesystemOperation, FlowOrdinals, InvocationInput, PathScope, Sensitivity, pattern_bound,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use proptest::prelude::*;

fn known(program: &str, operation: &str) -> EffectKind {
    EffectKind::known(program, operation).unwrap()
}

#[test]
fn pattern_bounds_include_extglob_operators() {
    assert_eq!(pattern_bound("/repo/keys/@(id_rsa)"), "/repo/keys/");
    assert_eq!(pattern_bound("/repo/keys/+(id_*)"), "/repo/keys/");
}

#[test]
fn action_stream_assigns_canonical_ordinals_and_flow_bytes() {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![
            vec![known("curl", "get"), EffectKind::network(None)],
            vec![EffectKind::code_execution(Some("bash"), "inline").unwrap()],
        ],
        vec![FlowOrdinals::new(0, 1)],
    )
    .unwrap();

    assert_eq!(stream.version(), ActionStreamVersion::V1);
    assert_eq!(stream.effects()[0].id().as_str(), "e0");
    assert_eq!(stream.effects()[0].stage().as_str(), "s0");
    assert_eq!(stream.effects()[2].id().as_str(), "e2");
    assert_eq!(stream.effects()[2].stage().as_str(), "s1");
    assert_eq!(
        stream.canonical_json().unwrap(),
        r#"{"v":1,"coverage":"full","effects":[{"id":"e0","stage":"s0","kind":{"kind":"invocation","invocation":{"kind":"known","program":"curl","operation":"get","input":{"kind":"shell","words":["curl"],"argv":["curl"]}}}},{"id":"e1","stage":"s0","kind":{"kind":"network","direction":"outbound"}},{"id":"e2","stage":"s1","kind":{"kind":"invocation","invocation":{"kind":"code-execution","program":"bash","interpreter":"bash","source":"inline","input":{"kind":"shell","words":["bash"],"argv":["bash"]}}}}],"flows":[{"from_stage":"s0","to_stage":"s1"}]}"#
    );
    assert_eq!(
        serde_json::from_str::<ActionStream>(&stream.canonical_json().unwrap()).unwrap(),
        stream
    );
}

#[test]
fn unresolved_filesystem_effect_round_trips_without_inventing_a_root() {
    let invocation = EffectKind::known_with_input(
        "rm",
        "delete",
        InvocationInput::shell(
            "rm",
            vec!["rm".into(), "-rf".into(), "${TARGET}".into()],
            None,
        ),
    )
    .unwrap();
    let stream = ActionStream::new(
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
    let value = serde_json::to_value(&stream).unwrap();

    assert_eq!(
        value["effects"][0]["kind"]["invocation"]["input"],
        serde_json::json!({
            "kind": "shell",
            "words": ["rm", "-rf", "${TARGET}"]
        })
    );
    assert_eq!(
        value["effects"][1]["kind"],
        serde_json::json!({
            "kind": "filesystem-unresolved",
            "operation": "delete",
            "recursive": true
        })
    );
    assert!(value["effects"][1]["kind"].get("target").is_none());
    assert_eq!(
        serde_json::from_value::<ActionStream>(value).unwrap(),
        stream
    );
}

#[test]
fn invocation_cwd_is_visible_and_lexically_normalized() {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![
            known("/usr/bin/aws", "read-only")
                .with_invocation_cwd(AbsolutePath::new(Platform::Linux, "/repo/subdir").unwrap()),
        ]],
        vec![],
    )
    .unwrap();
    let value = serde_json::to_value(&stream).unwrap();
    assert_eq!(
        value["effects"][0]["kind"]["invocation"]["cwd"],
        "/repo/subdir"
    );
    assert_eq!(
        serde_json::from_value::<ActionStream>(value.clone()).unwrap(),
        stream
    );

    for invalid in ["relative", "/repo/../outside", "/repo/"] {
        let mut malformed = value.clone();
        malformed["effects"][0]["kind"]["invocation"]["cwd"] = serde_json::json!(invalid);
        assert!(
            serde_json::from_value::<ActionStream>(malformed).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn malformed_stages_and_flows_are_rejected() {
    assert!(ActionStream::new(Coverage::Full, vec![vec![]], vec![]).is_err());
    assert!(
        ActionStream::new(
            Coverage::Full,
            vec![vec![known("echo", "print")]],
            vec![FlowOrdinals::new(0, 1)],
        )
        .is_err()
    );
    assert!(
        ActionStream::new(
            Coverage::Full,
            vec![vec![known("echo", "print")]],
            vec![FlowOrdinals::new(0, 0)],
        )
        .is_err()
    );
}

#[test]
fn only_partial_action_streams_may_be_empty() {
    let partial = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
    assert!(partial.effects().is_empty());
    assert!(partial.flows().is_empty());
    assert_eq!(
        partial.canonical_json().unwrap(),
        r#"{"v":1,"coverage":"partial","effects":[],"flows":[]}"#
    );
    assert_eq!(
        serde_json::from_str::<ActionStream>(&partial.canonical_json().unwrap()).unwrap(),
        partial
    );

    assert!(ActionStream::new(Coverage::Full, vec![], vec![]).is_err());
    assert!(ActionStream::new(Coverage::Partial, vec![vec![]], vec![]).is_err());
}

#[test]
fn future_action_version_dispatches_before_unknown_effect_decode() {
    let json = r#"{"v":2,"coverage":"full","effects":[{"kind":"future"}],"flows":[]}"#;
    let error = serde_json::from_str::<ActionStream>(json).unwrap_err();
    assert!(error.to_string().contains("unsupported-version"));
}

#[test]
fn network_hosts_are_normalized_or_omitted() {
    assert_eq!(
        EffectKind::network(Some("API.Example.COM.")).network_host(),
        Some("api.example.com")
    );
    assert_eq!(
        EffectKind::network(Some("192.0.2.1")).network_host(),
        Some("192.0.2.1")
    );
    assert_eq!(
        EffectKind::network(Some("[2001:0DB8:0:0:0:0:0:1]")).network_host(),
        Some("2001:db8::1")
    );
    for invalid in ["bad host", "bad..host", "-bad.example", ":::1", "999.0.0.1"] {
        assert_eq!(EffectKind::network(Some(invalid)).network_host(), None);
    }
}

#[test]
fn complete_effect_algebra_has_stable_tags_and_scope_invariants() {
    let filesystem = |target: &str, root: &str, selects_root| EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Write,
            target: AbsolutePath::new(Platform::Linux, target.to_owned()).unwrap(),
            scope: PathScope::Project {
                root: AbsolutePath::new(Platform::Linux, root.to_owned()).unwrap(),
            },
            sensitivity: Sensitivity::None,
            protection: None,
            selects_root,
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    };
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![
            known("git", "status"),
            filesystem("/repo/file", "/repo", false),
            EffectKind::Git {
                operation: nah_proto::action::SemanticCode::new("status").unwrap(),
            },
            EffectKind::network(Some("EXAMPLE.COM.")),
            EffectKind::SystemState {
                operation: nah_proto::action::SemanticCode::new("process-start").unwrap(),
            },
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(stream).unwrap()["effects"],
        serde_json::json!([
            {"id":"e0","stage":"s0","kind":{"kind":"invocation","invocation":{"kind":"known","program":"git","operation":"status","input":{"kind":"shell","words":["git"],"argv":["git"]}}}},
            {"id":"e1","stage":"s0","kind":{"kind":"filesystem","operation":"write","target":"/repo/file","scope":{"kind":"project","root":"/repo"},"sensitivity":"none","selects_root":false,"selects_home":false,"recursive":false,"pattern":false}},
            {"id":"e2","stage":"s0","kind":{"kind":"git","operation":"status"}},
            {"id":"e3","stage":"s0","kind":{"kind":"network","direction":"outbound","host":"example.com"}},
            {"id":"e4","stage":"s0","kind":{"kind":"system-state","operation":"process-start"}}
        ])
    );

    assert!(
        ActionStream::new(
            Coverage::Full,
            vec![vec![
                known("rm", "delete"),
                filesystem("/repo", "/repo", false)
            ]],
            vec![],
        )
        .is_err()
    );
    for target in ["/repo\\outside", "/repo/../etc/passwd", "/repo/."] {
        assert!(
            ActionStream::new(
                Coverage::Full,
                vec![vec![
                    known("rm", "delete"),
                    filesystem(target, "/repo", false)
                ]],
                vec![],
            )
            .is_err()
        );
    }
    assert!(
        ActionStream::new(
            Coverage::Full,
            vec![vec![
                known("cat", "read"),
                filesystem("/tmp/file", "/", false)
            ]],
            vec![],
        )
        .is_ok()
    );
    let windows_device_effect = EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Write,
            target: AbsolutePath::new(Platform::Windows, r"\\.\PhysicalDrive0").unwrap(),
            scope: PathScope::System,
            sensitivity: Sensitivity::None,
            protection: None,
            selects_root: false,
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    };
    assert!(
        ActionStream::new(
            Coverage::Full,
            vec![vec![known("format", "write"), windows_device_effect]],
            vec![],
        )
        .is_ok()
    );
    let windows_root_effect = EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Read,
            target: AbsolutePath::new(Platform::Windows, r"C:\repo\file").unwrap(),
            scope: PathScope::Project {
                root: AbsolutePath::new(Platform::Windows, "C:\\").unwrap(),
            },
            sensitivity: Sensitivity::None,
            protection: None,
            selects_root: false,
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    };
    assert!(
        ActionStream::new(
            Coverage::Full,
            vec![vec![known("type", "read"), windows_root_effect]],
            vec![],
        )
        .is_ok()
    );
    assert!(EffectKind::known("/usr/bin/curl", "get").is_ok());
    assert!(EffectKind::known("curl*", "get").is_err());
}

#[test]
fn v1_deserialization_revalidates_ids_stages_effects_and_flows() {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![known("echo", "print")], vec![known("cat", "read")]],
        vec![FlowOrdinals::new(0, 1)],
    )
    .unwrap();
    let valid = serde_json::to_value(&stream).unwrap();

    let mut bad_id = valid.clone();
    bad_id["effects"][0]["id"] = serde_json::json!("e01");
    assert!(serde_json::from_value::<ActionStream>(bad_id).is_err());

    let mut bad_stage = valid.clone();
    bad_stage["effects"][1]["stage"] = serde_json::json!("s2");
    assert!(serde_json::from_value::<ActionStream>(bad_stage).is_err());

    let mut bad_flow = valid.clone();
    bad_flow["flows"][0]["to_stage"] = serde_json::json!("s9");
    assert!(serde_json::from_value::<ActionStream>(bad_flow).is_err());

    let mut self_flow = valid.clone();
    self_flow["flows"][0]["to_stage"] = serde_json::json!("s0");
    assert!(serde_json::from_value::<ActionStream>(self_flow).is_err());

    let mut bad_argv_program = valid.clone();
    bad_argv_program["effects"][0]["kind"]["invocation"]["input"]["argv"][0] =
        serde_json::json!("other");
    assert!(serde_json::from_value::<ActionStream>(bad_argv_program).is_err());

    let mut bad_operation = valid;
    bad_operation["effects"][0]["kind"]["invocation"]["operation"] = serde_json::json!("Not-Kebab");
    assert!(serde_json::from_value::<ActionStream>(bad_operation).is_err());

    let relative_target = serde_json::json!({
        "v": 1,
        "coverage": "full",
        "effects": [
            {"id":"e0","stage":"s0","kind":{"kind":"invocation","invocation":{"kind":"known","program":"cat","operation":"read"}}},
            {"id":"e1","stage":"s0","kind":{"kind":"filesystem","operation":"read","target":"relative","scope":{"kind":"outside-project"},"sensitivity":"none","selects_root":false,"selects_home":false,"recursive":false,"pattern":false}}
        ],
        "flows": []
    });
    assert!(serde_json::from_value::<ActionStream>(relative_target).is_err());
}

#[test]
fn ordinal_order_is_numeric_for_effects_and_flows() {
    let e2: EffectId = serde_json::from_str("\"e2\"").unwrap();
    let e10: EffectId = serde_json::from_str("\"e10\"").unwrap();
    assert!(e2 < e10);

    let stages = (0..12)
        .map(|index| vec![known("echo", &format!("op-{index}"))])
        .collect();
    let stream = ActionStream::new(
        Coverage::Full,
        stages,
        vec![FlowOrdinals::new(10, 11), FlowOrdinals::new(2, 3)],
    )
    .unwrap();
    assert_eq!(stream.flows()[0].from_stage().as_str(), "s2");
    assert_eq!(stream.flows()[1].from_stage().as_str(), "s10");
}

proptest! {
    #[test]
    fn assigned_effect_ids_are_contiguous(stage_count in 1_usize..32) {
        let stages = (0..stage_count)
            .map(|_| vec![known("echo", "print")])
            .collect();
        let stream = ActionStream::new(Coverage::Full, stages, vec![]).unwrap();
        let ids = stream.effects().iter().map(|effect| effect.id().as_str()).collect::<Vec<_>>();
        let expected = (0..stage_count).map(|index| format!("e{index}")).collect::<Vec<_>>();
        prop_assert!(ids.into_iter().eq(expected.iter().map(String::as_str)));
    }
}
