use nah_proto::ctx::AbsolutePath;
use nah_proto::ctx::Ctx;
use nah_proto::ctx::Platform;
use nah_proto::ctx::SchemaVersion;
use nah_proto::ctx::{Guard, GuardLevel, GuardSettings, RuleOverride};
use serde_json::json;

#[test]
fn ctx_retains_its_context_state() {
    let ctx = Ctx::new(
        Platform::Linux,
        absolute("/home/test"),
        settings(json!({"guards": {}, "rules": {"secrets/env-files-read": "disabled"}})),
    )
    .unwrap();
    assert_eq!(ctx.platform(), Platform::Linux);
    assert_eq!(ctx.home().as_str(), "/home/test");
    assert_eq!(
        ctx.guard_settings().rule_override("secrets/env-files-read"),
        Some(RuleOverride::Disabled)
    );
}

fn settings(value: serde_json::Value) -> GuardSettings {
    serde_json::from_value(value).unwrap()
}

/// A rule runs at its guard's setting; an override replaces that, and a
/// nap pauses it whatever the override says.
#[test]
fn rule_level_joins_guard_settings_and_overrides() {
    let defaults = GuardSettings::default();
    assert_eq!(defaults.rule_level("work/stash-drop"), GuardLevel::Core);
    assert_eq!(defaults.rule_level("unknown"), GuardLevel::Off);

    let posture = settings(json!({
        "guards": {"work": "off", "machine": "strict"},
        "rules": {"work/stash-drop": "enabled", "machine/system-halt": "disabled"},
    }));
    for (rule, level) in [
        ("work/stash-drop", GuardLevel::Strict),
        ("work/branch-delete", GuardLevel::Off),
        ("machine/system-halt", GuardLevel::Off),
        ("machine/disk-overwrite", GuardLevel::Strict),
    ] {
        assert_eq!(posture.rule_level(rule), level, "{rule}");
    }
    let mut napped = posture.clone();
    napped.pause("work/stash-drop");
    assert_eq!(napped.rule_level("work/stash-drop"), GuardLevel::Off);
    assert_eq!(
        serde_json::to_value(&posture).unwrap(),
        json!({
            "guards": {"work": "off", "machine": "strict"},
            "rules": {"machine/system-halt": "disabled", "work/stash-drop": "enabled"},
        })
    );

    // Only non-defaults are stored, and `self` has no setting.
    for invalid in [
        json!({"guards": {"work": "core"}, "rules": {}}),
        json!({"guards": {"self": "off"}, "rules": {}}),
        json!({"guards": {}, "rules": {"": "enabled"}}),
    ] {
        assert!(serde_json::from_value::<GuardSettings>(invalid).is_err());
    }
    let mut canonical = GuardSettings::default();
    canonical.set_guard(Guard::Work, GuardLevel::Strict);
    canonical.set_guard(Guard::Work, GuardLevel::Core);
    canonical.set_guard(Guard::SelfProtection, GuardLevel::Off);
    assert_eq!(canonical, GuardSettings::default());
}

#[test]
fn wire_versions_reject_zero() {
    let error = serde_json::from_str::<SchemaVersion>("0").expect_err("zero schema version");
    assert!(error.to_string().contains("zero-version"));
}

#[test]
fn removed_policy_kind_fields_are_rejected() {
    let shipped = json!({"guards": {}, "rules": {}, "kind": "guard"});
    assert!(
        serde_json::from_value::<GuardSettings>(shipped)
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
