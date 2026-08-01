use nah_proto::ctx::Platform;
use nah_proto::ctx::SchemaVersion;
use nah_proto::tool::ToolCallInput;
use serde_json::json;

#[test]
fn tool_input_has_stable_json_and_validates_authoritative_cwd() {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command": "pwd"}),
        "/repo",
        None,
    )
    .expect("valid input");
    assert_eq!(
        serde_json::to_string(&input).expect("serialize"),
        r#"{"v":1,"tool":"Bash","input":{"command":"pwd"},"cwd":"/repo"}"#
    );
    assert_eq!(
        serde_json::from_value::<ToolCallInput>(serde_json::to_value(&input).unwrap()).unwrap(),
        input
    );
    assert_eq!(
        input
            .call_site(Platform::Linux)
            .expect("absolute cwd")
            .requested_cwd()
            .as_str(),
        "/repo"
    );

    let decoded: ToolCallInput = serde_json::from_value(json!({
        "v": 1,
        "tool": "Read",
        "input": {},
        "cwd": "/repo",
        "session": null,
        "future_optional": true
    }))
    .expect("unknown fields and null optional field are accepted");
    assert_eq!(decoded.session(), None);
    assert!(decoded.call_site(Platform::Linux).is_ok());
    assert!(
        ToolCallInput::new(SchemaVersion::V1, "Read", json!({}), "relative", None)
            .expect("raw input remains representable")
            .call_site(Platform::Linux)
            .is_err()
    );

    let original = json!({"path":"file","runtime_flag":true});
    let normalized = ToolCallInput::new(
        SchemaVersion::V1,
        "Read",
        json!({"file_path":"file"}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(original.clone(), true);
    assert_eq!(normalized.invocation_input(), &original);
    assert_eq!(
        serde_json::from_value::<ToolCallInput>(serde_json::to_value(&normalized).unwrap())
            .unwrap(),
        normalized
    );

    let incomplete = ToolCallInput::new(
        SchemaVersion::V1,
        "Read",
        json!({"file_path":"file"}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(original, false);
    assert!(!incomplete.normalization_complete());
    assert_eq!(
        serde_json::to_value(&incomplete).unwrap()["normalization_complete"],
        false
    );
    assert_eq!(
        serde_json::from_value::<ToolCallInput>(serde_json::to_value(&incomplete).unwrap())
            .unwrap(),
        incomplete
    );

    let error = serde_json::from_value::<ToolCallInput>(json!({
        "v": 1,
        "tool": "Read",
        "input": {"file_path":"file"},
        "normalization_complete": false,
        "cwd": "/repo"
    }))
    .expect_err("incomplete normalization needs the runtime's original input");
    assert!(
        error
            .to_string()
            .contains("incomplete-normalization-requires-original-input")
    );
}

#[test]
fn future_tool_version_is_rejected_before_payload_decode() {
    let error = serde_json::from_value::<ToolCallInput>(json!({
        "v": 2,
        "tool": 7,
        "input": null,
        "cwd": false
    }))
    .expect_err("v2 is unsupported");
    assert!(error.to_string().contains("unsupported-version"));
}

#[test]
fn explicit_null_original_input_round_trips_as_present() {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "custom",
        serde_json::Value::Null,
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(serde_json::Value::Null, false);

    let encoded = serde_json::to_value(&input).unwrap();
    assert!(encoded.get("original_input").is_some());
    let decoded: ToolCallInput = serde_json::from_value(encoded).unwrap();

    assert_eq!(decoded.invocation_input(), &serde_json::Value::Null);
    assert!(!decoded.normalization_complete());
}
