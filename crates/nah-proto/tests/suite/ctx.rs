use nah_proto::ctx::AbsolutePath;
use nah_proto::ctx::ActivationProjection;
use nah_proto::ctx::ContentHash;
use nah_proto::ctx::Ctx;
use nah_proto::ctx::ExecProtocolVersion;
use nah_proto::ctx::GuardIdentity;
use nah_proto::ctx::MAX_GUARD_NAME_BYTES;
use nah_proto::ctx::Platform;
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
        Platform::Linux,
        absolute("/home/test"),
        Vec::new(),
        vec![activation.clone(), activation],
        TrustProjection::new(Vec::new()).expect("trust"),
    );
    assert!(duplicate.is_err());

    let ctx = Ctx::new(
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap();
    assert_eq!(ctx.platform(), Platform::Linux);
    assert_eq!(ctx.home().as_str(), "/home/test");
    assert!(ctx.shipped_guards().is_empty());
    assert!(ctx.activations().is_empty());
    assert!(ctx.trust().trusted_roots().is_empty());
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
fn ctx_retains_nested_context_state_in_memory() {
    let trusted_root_id = TrustedRootId::new("trust-1").unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::project(trusted_root_id.clone(), "deploy").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec!["git".into(), "curl".into()],
    )
    .unwrap();
    let ctx = Ctx::new(
        Platform::Linux,
        absolute("/home/test"),
        vec![ShippedGuardState::new("secrets-env", true).unwrap()],
        vec![activation],
        TrustProjection::new(vec![TrustedRoot::new(trusted_root_id, absolute("/repo"))]).unwrap(),
    )
    .unwrap();

    assert_eq!(ctx.shipped_guards()[0].name(), "secrets-env");
    assert_eq!(ctx.activations()[0].match_programs(), ["curl", "git"]);
    assert_eq!(ctx.trust().trusted_roots()[0].path().as_str(), "/repo");
}

#[test]
fn shipped_guard_state_records_only_an_explicit_global_veto() {
    let disabled =
        ShippedGuardState::with_explicit_disable("fs-auth-identity", false, true).unwrap();
    assert_eq!(
        serde_json::to_value(disabled).unwrap(),
        json!({
            "name": "fs-auth-identity",
            "enabled": false,
            "explicitly_disabled": true
        })
    );
    assert!(ShippedGuardState::with_explicit_disable("fs-auth-identity", true, true).is_err());
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
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![activation],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "untrusted-activation");
}

#[test]
fn wire_versions_reject_zero_in_direct_and_nested_json() {
    for error in [
        serde_json::from_str::<SchemaVersion>("0").expect_err("zero schema version"),
        serde_json::from_str::<ExecProtocolVersion>("0").expect_err("zero exec version"),
    ] {
        assert!(error.to_string().contains("zero-version"));
    }
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
fn windows_extended_and_device_namespaces_are_not_policy_paths() {
    for path in [
        r"\\?\C:\Users\test",
        r"\\?\UNC\server\share",
        r"\\.\PhysicalDrive0",
    ] {
        assert!(
            AbsolutePath::new(Platform::Windows, path).is_err(),
            "{path}"
        );
        assert!(
            serde_json::from_value::<AbsolutePath>(json!(path)).is_err(),
            "{path}"
        );
    }
}

fn absolute(path: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, path).expect("absolute path")
}
