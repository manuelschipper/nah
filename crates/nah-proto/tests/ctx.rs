use nah_proto::ctx::AbsolutePath;
use nah_proto::ctx::ActivationProjection;
use nah_proto::ctx::ContentHash;
use nah_proto::ctx::Ctx;
use nah_proto::ctx::ExecProtocolVersion;
use nah_proto::ctx::GuardIdentity;
use nah_proto::ctx::MAX_GUARD_NAME_BYTES;
use nah_proto::ctx::Platform;
use nah_proto::ctx::PolicyVersion;
use nah_proto::ctx::SchemaVersion;
use nah_proto::ctx::ShippedGuardState;
use nah_proto::ctx::TrustProjection;
use nah_proto::ctx::TrustedRoot;
use nah_proto::ctx::TrustedRootId;
use serde_json::json;

#[test]
fn ctx_rejects_duplicate_identity_keys_and_normalizes_sets() {
    let identity = GuardIdentity::user("corp").expect("identity");
    let activation = ActivationProjection::new(
        identity.clone(),
        ContentHash::new("a".repeat(64)).expect("hash"),
        ExecProtocolVersion::V1,
        vec!["wget".into(), "curl".into()],
    )
    .expect("activation");
    assert_eq!(activation.match_programs(), ["curl", "wget"]);
    assert!(
        ActivationProjection::new(
            GuardIdentity::user("path").unwrap(),
            ContentHash::new("b".repeat(64)).unwrap(),
            ExecProtocolVersion::V1,
            vec!["/usr/bin/curl".into()],
        )
        .is_ok()
    );
    assert!(
        ActivationProjection::new(
            GuardIdentity::user("invalid").unwrap(),
            ContentHash::new("b".repeat(64)).unwrap(),
            ExecProtocolVersion::V1,
            vec!["curl*".into()],
        )
        .is_err()
    );

    let duplicate = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        Vec::new(),
        vec![activation.clone(), activation],
        TrustProjection::new(Vec::new()).expect("trust"),
        PolicyVersion::V1,
    );
    assert!(duplicate.is_err());

    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&ctx).unwrap(),
        r#"{"v":1,"platform":"linux","home":"/home/test","shipped_units":[],"activations":[],"trust":{"trusted_roots":[]},"policy_version":1}"#
    );
    assert_eq!(
        serde_json::from_value::<Ctx>(serde_json::to_value(&ctx).unwrap()).unwrap(),
        ctx
    );
}

#[test]
fn custom_guard_identity_names_are_canonical_and_bounded() {
    assert!(GuardIdentity::user("guard-1.example").is_ok());
    assert!(GuardIdentity::user("a".repeat(MAX_GUARD_NAME_BYTES)).is_ok());
    for invalid in ["", "FS-ROOT", "-guard", "guard-", "guard name"] {
        assert!(GuardIdentity::user(invalid).is_err(), "{invalid}");
    }
    assert!(GuardIdentity::user("a".repeat(MAX_GUARD_NAME_BYTES + 1)).is_err());
    assert!(
        serde_json::from_value::<GuardIdentity>(json!({
            "scope": "user",
            "name": "FS-ROOT"
        }))
        .is_err()
    );
}

#[test]
fn nested_context_contracts_have_exact_json() {
    let trusted_root_id = TrustedRootId::new("trust-1").unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::project(trusted_root_id.clone(), "deploy").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec!["git".into(), "curl".into()],
    )
    .unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        vec![ShippedGuardState::new("secrets-env", true).unwrap()],
        vec![activation],
        TrustProjection::new(vec![TrustedRoot::new(trusted_root_id, absolute("/repo"))]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap();

    assert_eq!(
        serde_json::to_value(&ctx).unwrap(),
        json!({
            "v": 1,
            "platform": "linux",
            "home": "/home/test",
            "shipped_units": [{"name":"secrets-env","enabled":true}],
            "activations": [{
                "identity":{"scope":"project","trusted_root":"trust-1","name":"deploy"},
                "bundle_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "protocol":1,
                "match_programs":["curl","git"]
            }],
            "trust":{"trusted_roots":[{"identity":"trust-1","path":"/repo"}]},
            "policy_version":1
        })
    );
}

#[test]
fn project_activations_require_their_trusted_root_in_context() {
    let identity = TrustedRootId::new("trust-1").unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::project(identity, "deploy").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec![],
    )
    .unwrap();
    let error = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![activation],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "untrusted-activation");
}

#[test]
fn semantic_versions_reject_zero_in_direct_and_nested_json() {
    for error in [
        serde_json::from_str::<SchemaVersion>("0").expect_err("zero schema version"),
        serde_json::from_str::<PolicyVersion>("0").expect_err("zero policy version"),
        serde_json::from_str::<ExecProtocolVersion>("0").expect_err("zero exec version"),
    ] {
        assert!(error.to_string().contains("zero-version"));
    }
    assert_eq!(
        serde_json::from_str::<PolicyVersion>("2")
            .expect("future nonzero policy version remains inspectable")
            .value(),
        2
    );
    assert_eq!(
        serde_json::from_str::<ExecProtocolVersion>("2")
            .expect("future nonzero exec version remains inspectable")
            .value(),
        2
    );

    let activation_error = serde_json::from_value::<ActivationProjection>(json!({
        "identity": {"scope": "user", "name": "corp"},
        "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "protocol": 0,
        "match_programs": ["curl"]
    }))
    .expect_err("zero nested exec version");
    assert!(activation_error.to_string().contains("zero-version"));

    let ctx_error = serde_json::from_value::<Ctx>(json!({
        "v": 1,
        "platform": "linux",
        "home": "/home/test",
        "shipped_units": [],
        "activations": [],
        "trust": {"trusted_roots": []},
        "policy_version": 0
    }))
    .expect_err("zero nested policy version");
    assert!(ctx_error.to_string().contains("zero-version"));
}

#[test]
fn removed_policy_kind_fields_are_rejected() {
    let activation = json!({
        "identity": {"scope": "user", "name": "corp"},
        "kind": "guard",
        "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "protocol": 1,
        "match_programs": ["curl"]
    });
    assert!(
        serde_json::from_value::<ActivationProjection>(activation)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );

    let shipped = json!({"name":"secrets-env","kind":"guard","enabled":true});
    assert!(
        serde_json::from_value::<ShippedGuardState>(shipped)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );
}

#[test]
fn windows_unc_paths_require_server_and_share() {
    for invalid in [r"\\", r"\\server"] {
        assert!(AbsolutePath::new(Platform::Windows, invalid).is_err());
        assert!(serde_json::from_value::<AbsolutePath>(json!(invalid)).is_err());
    }
    assert!(AbsolutePath::new(Platform::Windows, r"\\server\share").is_ok());
}

#[test]
fn future_ctx_version_dispatches_before_zero_nested_policy_version() {
    let error = serde_json::from_value::<Ctx>(json!({
        "v": 2,
        "platform": "not-a-v1-platform",
        "home": false,
        "policy_version": 0
    }))
    .expect_err("v2 context is unsupported");
    assert!(error.to_string().contains("unsupported-version"));
    assert!(!error.to_string().contains("zero-version"));
}

fn absolute(path: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, path).expect("absolute path")
}
