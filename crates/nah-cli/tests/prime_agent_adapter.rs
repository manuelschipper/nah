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
    let provenance = if tool_name == "ipython" {
        Some(("builtin", "<builtin:ipython>"))
    } else {
        None
    };
    run_adapter_with_provenance(home, project, tool_name, tool_input, provenance)
}

fn run_adapter_with_provenance(
    home: &std::path::Path,
    project: &std::path::Path,
    tool_name: &str,
    tool_input: Value,
    provenance: Option<(&str, &str)>,
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
                "tool_source":provenance.map(|(source, _)| source),
                "tool_path":provenance.map(|(_, path)| path),
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn custom_ipython_override_stays_opaque_and_partial() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);
    let source = "import shutil; shutil.rmtree('/')";

    assert_eq!(
        run_adapter_with_provenance(
            &home,
            &project,
            "ipython",
            json!({"code":source}),
            Some(("local", "/repo/.prime/agent/extensions/override.ts")),
        ),
        json!({"block":false,"evaluation_failed":false})
    );
    let record = audit_records(&home).pop().unwrap();
    assert_eq!(record["core"]["coverage"], "partial");
    assert_eq!(
        record["effects"],
        json!([{"id":"e0","description":"invoke prime-agent-opaque opaque"}])
    );
}

#[test]
fn unadmitted_tools_cannot_impersonate_native_schemas() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);
    let extension = home.join(".prime/agent/extensions/nah.js");

    for (tool, input, provenance) in [
        (
            "Read",
            json!({"file_path":extension}),
            Some(("local", "/repo/.prime/agent/extensions/read.ts")),
        ),
        (
            "Write",
            json!({"file_path":extension,"content":"replacement"}),
            Some(("sdk", "<sdk:Write>")),
        ),
        (
            "Edit",
            json!({
                "file_path":extension,
                "old_string":"old",
                "new_string":"replacement"
            }),
            Some(("builtin", "<builtin:Edit>")),
        ),
        (
            "bash",
            json!({"command":"rm -rf /"}),
            Some(("builtin", "<builtin:bash>")),
        ),
    ] {
        assert_eq!(
            run_adapter_with_provenance(&home, &project, tool, input, provenance),
            json!({"block":false,"evaluation_failed":false}),
            "{tool}"
        );
        let record = audit_records(&home).pop().unwrap();
        assert_eq!(record["core"]["coverage"], "partial", "{tool}");
        assert_eq!(
            record["effects"],
            json!([{"id":"e0","description":"invoke prime-agent-opaque opaque"}]),
            "{tool}"
        );
    }
}

fn audit_records(home: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(home.join(".nah/audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn builtin_ipython_uses_current_cell_import_ownership() {
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

    let source = "open('/tmp/current-builtin', 'w')";
    assert_eq!(
        run_adapter(&home, &project, "ipython", json!({"code":source})),
        json!({"block":false,"evaluation_failed":false})
    );
    let record = audit_records(&home).pop().unwrap();
    assert_eq!(record["core"]["coverage"], "full");
    assert_eq!(
        record["effects"],
        json!([
            {"id":"e0","description":"execute ipython interpreter-inline"},
            {"id":"e1","description":"invoke ipython direct-file"},
            {"id":"e2","description":"write /tmp/current-builtin"},
        ])
    );

    for source in ["!rm -rf /", "!!", "%%bash\nrm -rf /"] {
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
fn current_cell_destructive_effects_reach_prime_guards() {
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
    assert_eq!(root["evaluation_failed"], false);
    let record = audit_records(&home).pop().unwrap();
    assert_eq!(record["core"]["coverage"], "full");
    assert_eq!(record["core"]["verdict"], "block");
    assert_eq!(
        record["effects"],
        json!([
            {"id":"e0","description":"execute ipython interpreter-inline"},
            {"id":"e1","description":"invoke ipython direct-file"},
            {"id":"e2","description":"delete /"},
        ])
    );

    let extension = home.join(".prime/agent/extensions/nah.js");
    let source = format!("import os; os.remove({:?})", extension.to_str().unwrap());
    let protected = run_adapter(&home, &project, "ipython", json!({"code":source}));
    assert_eq!(protected["block"], true);
    assert_eq!(protected["evaluation_failed"], false);
    let record = audit_records(&home).pop().unwrap();
    assert_eq!(record["core"]["verdict"], "block");
    assert!(record["effects"].as_array().unwrap().iter().any(|effect| {
        effect["description"] == format!("delete {}", extension.to_string_lossy())
    }));
}

#[test]
fn invalid_code_shapes_and_other_tools_remain_opaque() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);

    for (tool, input, effect_tool) in [
        ("ipython", json!({"code":7}), "ipython"),
        (
            "custom",
            json!({"code":"import shutil; shutil.rmtree('/')"}),
            "prime-agent-opaque",
        ),
    ] {
        assert_eq!(
            run_adapter(&home, &project, tool, input),
            json!({"block":false,"evaluation_failed":false})
        );
        assert_eq!(
            audit_records(&home).pop().unwrap()["effects"],
            json!([{"id":"e0","description":format!("invoke {effect_tool} opaque")}])
        );
    }
}

#[test]
fn additional_builtin_fields_cannot_hide_current_cell_effects() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);
    let source = "import shutil; shutil.rmtree('/')";

    let decision = run_adapter(
        &home,
        &project,
        "ipython",
        json!({"code":source,"futureBehavior":"execute"}),
    );
    assert_eq!(decision["block"], true);
    assert_eq!(decision["evaluation_failed"], false);
    let record = audit_records(&home).pop().unwrap();
    assert_eq!(record["core"]["coverage"], "partial");
    assert!(
        record["effects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|effect| effect["description"] == "delete /")
    );
}
