#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;
use support::repo;

fn nah(
    home: &std::path::Path,
    cwd: &std::path::Path,
    args: &[&str],
    stdin: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn replace_path(value: &mut Value, path: &str) {
    match value {
        Value::Array(items) => {
            for item in items {
                replace_path(item, path);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                replace_path(value, path);
            }
        }
        Value::String(text) => *text = text.replace(path, "<project>").replace('\\', "/"),
        _ => {}
    }
}

fn assert_golden(value: &Value, expected: &str) {
    let rendered = serde_json::to_string_pretty(value).unwrap() + "\n";
    assert_eq!(rendered, expected);
}

#[test]
fn decide_json_has_an_exact_independent_v1_contract() {
    let home = tempfile::tempdir().unwrap();
    let project = repo(home.path());
    let payload = serde_json::json!({
        "v": 1,
        "tool": "Read",
        "input": {"file_path": "src/lib.rs"},
        "cwd": project,
    })
    .to_string();
    let output = nah(home.path(), &project, &["decide"], Some(&payload));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let mut value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value["id"] = Value::String("<decision-id>".into());
    value["duration_us"] = Value::from(0);
    // nah reports the resolved path, and macOS temp directories sit under a
    // symlinked /var, so redact the spelling it printed
    let printed = std::fs::canonicalize(&project).unwrap();
    replace_path(&mut value, printed.to_str().unwrap());
    assert_golden(&value, include_str!("golden/decide-v1.json"));
}

#[test]
fn test_json_has_an_exact_independent_v1_contract() {
    let home = tempfile::tempdir().unwrap();
    let project = repo(home.path());
    let output = nah(
        home.path(),
        &project,
        &["test", "--json", "echo hello"],
        None,
    );
    assert!(output.status.success(), "{output:?}");
    let mut value: Value = serde_json::from_slice(&output.stdout).unwrap();
    // nah reports the resolved path, and macOS temp directories sit under a
    // symlinked /var, so redact the spelling it printed
    let printed = std::fs::canonicalize(&project).unwrap();
    replace_path(&mut value, printed.to_str().unwrap());
    assert_golden(&value, include_str!("golden/test-v1.json"));
}

#[test]
fn audit_json_has_an_exact_independent_v1_contract() {
    let home = tempfile::tempdir().unwrap();
    let project = repo(home.path());
    let payload = serde_json::json!({
        "v": 1,
        "tool": "Read",
        "input": {"file_path": "src/lib.rs"},
        "cwd": project,
    })
    .to_string();
    let decided = nah(home.path(), &project, &["decide"], Some(&payload));
    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    let logged = nah(home.path(), &project, &["log", "--json", "-n", "1"], None);
    assert!(logged.status.success(), "{logged:?}");
    let mut value: Value = serde_json::from_slice(&logged.stdout).unwrap();
    value["envelope"]["id"] = Value::String("<decision-id>".into());
    value["envelope"]["timestamp_rfc3339"] = Value::String("<timestamp>".into());
    value["envelope"]["duration_us"] = Value::from(0);
    // nah reports the resolved path, and macOS temp directories sit under a
    // symlinked /var, so redact the spelling it printed
    let printed = std::fs::canonicalize(&project).unwrap();
    replace_path(&mut value, printed.to_str().unwrap());
    assert_golden(&value, include_str!("golden/audit-v1.json"));
}
