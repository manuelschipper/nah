#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

fn run_adapter(
    home: &std::path::Path,
    project: &std::path::Path,
    tool_name: &str,
    tool_input: Value,
) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "prime-agent", "run"])
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PRIME_AGENT_CODING_AGENT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({
                "tool_name":tool_name,
                "tool_input":tool_input,
                "cwd":project,
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn audit_records(home: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(home.join(".nah/audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn exact_ipython_uses_persistent_effect_analysis() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);
    let source = "import os; os.remove('/tmp/prime-agent-target')";

    assert_eq!(
        run_adapter(&home, &project, "ipython", json!({"code":source})),
        json!({"block":false,"evaluation_failed":false})
    );
    let record = audit_records(&home).pop().unwrap();
    assert_eq!(record["runtime"], "prime-agent");
    assert_eq!(record["command"], "ipython [redacted]");
    assert_eq!(record["core"]["coverage"], "full");
    assert_eq!(
        record["effects"],
        json!([
            {"id":"e0","description":"execute ipython interpreter-inline"},
            {"id":"e1","description":"invoke ipython direct-file"},
            {"id":"e2","description":"delete /tmp/prime-agent-target"},
        ])
    );
}

#[test]
fn persistent_state_and_shell_rewrites_stay_opaque() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);

    for source in [
        "open('/tmp/prior-builtin', 'w')",
        "!rm -rf /",
        "!!",
        "%%bash\nrm -rf /",
    ] {
        assert_eq!(
            run_adapter(&home, &project, "ipython", json!({"code":source})),
            json!({"block":false,"evaluation_failed":false}),
            "{source}"
        );
        let record = audit_records(&home).pop().unwrap();
        assert_eq!(record["core"]["coverage"], "partial", "{source}");
        assert_eq!(
            record["effects"],
            json!([{"id":"e0","description":"execute ipython interpreter-inline"}]),
            "{source}"
        );
    }
}

#[test]
fn destructive_and_self_protection_effects_block() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);

    let root = run_adapter(
        &home,
        &project,
        "ipython",
        json!({"code":"import shutil; shutil.rmtree('/')"}),
    );
    assert_eq!(root["block"], true);

    let extension = home.join(".prime/agent/extensions/nah/index.js");
    let source = format!("import os; os.remove({:?})", extension.to_str().unwrap());
    let protected = run_adapter(&home, &project, "ipython", json!({"code":source}));
    assert_eq!(protected["block"], true);
    assert!(
        protected["reason"]
            .as_str()
            .unwrap()
            .contains("do not retry")
    );
}

#[test]
fn invalid_code_shapes_and_other_tools_remain_opaque() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);

    for (tool, input) in [
        ("ipython", json!({"code":7})),
        (
            "ipython",
            json!({"code":"import shutil; shutil.rmtree('/')","futureBehavior":"execute"}),
        ),
        (
            "custom",
            json!({"code":"import shutil; shutil.rmtree('/')"}),
        ),
    ] {
        assert_eq!(
            run_adapter(&home, &project, tool, input),
            json!({"block":false,"evaluation_failed":false})
        );
        assert_eq!(
            audit_records(&home).pop().unwrap()["effects"],
            json!([{"id":"e0","description":format!("invoke {tool} opaque")}])
        );
    }
}
