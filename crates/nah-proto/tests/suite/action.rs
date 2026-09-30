use nah_proto::action::pattern_bound;
use nah_proto::labels::HostIntegrityClass;

#[test]
fn pattern_bounds_include_extglob_operators() {
    assert_eq!(pattern_bound("/repo/keys/@(id_rsa)"), "/repo/keys/");
    assert_eq!(pattern_bound("/repo/keys/+(id_*)"), "/repo/keys/");
}

#[test]
fn host_integrity_classes_round_trip_in_strength_order() {
    let encoded = serde_json::to_value(HostIntegrityClass::ShellProfile).unwrap();
    assert_eq!(encoded, serde_json::json!("shell-profile"));
    assert_eq!(
        serde_json::from_value::<HostIntegrityClass>(encoded).unwrap(),
        HostIntegrityClass::ShellProfile
    );
    assert!(HostIntegrityClass::ShellProfile < HostIntegrityClass::StartupPersistence);
    assert!(HostIntegrityClass::StartupPersistence < HostIntegrityClass::AuthIdentity);
}
