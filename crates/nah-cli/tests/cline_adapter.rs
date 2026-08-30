#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

fn run_hook(home: &std::path::Path, cwd: &std::path::Path, payload: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "cline", "run"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn payload(cwd: &std::path::Path, tool: &str, parameters: Value) -> Value {
    json!({
        "taskId":"task-1",
        "hookName":"PreToolUse",
        "clineVersion":"4.0.0",
        "timestamp":"1785110400000",
        "workspaceRoots":[cwd],
        "userId":"user-1",
        "model":{"provider":"test","slug":"test-model"},
        "preToolUse":{
            "toolName":tool,
            "parameters":parameters
        }
    })
}

fn cli_payload(cwd: &std::path::Path, tool: &str, parameters: Value) -> Value {
    json!({
        "taskId":"task-1",
        "hookName":"tool_call",
        "clineVersion":"3.0.48",
        "timestamp":"2026-08-01T00:00:00.000Z",
        "workspaceRoots":[cwd],
        "userId":"user-1",
        "agent_id":"agent-1",
        "parent_agent_id":null,
        "iteration":1,
        "tool_call":{"id":"call-1","name":tool,"input":parameters},
        "preToolUse":{"toolName":tool,"parameters":parameters}
    })
}

#[test]
fn adapter_blocks_definite_violations_and_preserves_cline_permissions() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    #[cfg(target_os = "linux")]
    {
        let config = home.join(".config");
        std::fs::create_dir(&config).unwrap();
        std::fs::write(
            config.join("user-dirs.dirs"),
            "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n",
        )
        .unwrap();
    }

    let allowed = run_hook(
        home,
        &project,
        payload(&project, "execute_command", json!({"command":"git status"})),
    );
    assert_eq!(allowed, json!({"cancel":false}));

    let shell_sensitive = run_hook(
        home,
        &project,
        payload(&project, "execute_command", json!({"command":"cat .env"})),
    );
    assert_eq!(shell_sensitive["cancel"], !cfg!(windows));

    let cli_allowed = run_hook(
        home,
        &project,
        cli_payload(
            &project,
            "run_commands",
            json!({"commands":"[\"git status\"]"}),
        ),
    );
    assert_eq!(cli_allowed, json!({"cancel":false}));

    let cli_sensitive = run_hook(
        home,
        &project,
        cli_payload(
            &project,
            "run_commands",
            json!({"commands":"[\"cat .env\"]"}),
        ),
    );
    assert_eq!(cli_sensitive["cancel"], !cfg!(windows));

    let delegated = run_hook(
        home,
        &project,
        payload(
            &project,
            "read_files",
            json!({"files":"[{\"path\":\"src/lib.rs\"},{\"path\":\"README.md\"}]"}),
        ),
    );
    assert_eq!(delegated, json!({"cancel":false}));

    let sensitive = run_hook(
        home,
        &project,
        payload(&project, "read_file", json!({"path":".env"})),
    );
    assert_eq!(sensitive["cancel"], true);
    assert!(
        sensitive["errorMessage"]
            .as_str()
            .unwrap()
            .starts_with("nah - ")
    );
    assert_eq!(
        sensitive["contextModification"], sensitive["errorMessage"],
        "Cline's model must receive the same block guidance as the user"
    );

    let runtime_lifecycle = run_hook(
        home,
        &project,
        payload(
            &project,
            "run_commands",
            json!({"command":"nah","args":"[\"hook\",\"cline\",\"uninstall\"]"}),
        ),
    );
    assert_eq!(runtime_lifecycle["cancel"], !cfg!(windows));
    if !cfg!(windows) {
        assert!(
            runtime_lifecycle["errorMessage"]
                .as_str()
                .unwrap()
                .contains("do not retry")
        );
    }
    assert_eq!(
        runtime_lifecycle["contextModification"],
        runtime_lifecycle["errorMessage"]
    );

    #[cfg(windows)]
    let documents = {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)",
            ])
            .env("HOME", home)
            .env("USERPROFILE", home)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let documents = std::path::PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        if documents.is_absolute() {
            documents
        } else {
            home.join("Documents")
        }
    };
    #[cfg(not(windows))]
    let documents = home.join("Documents");
    let file = if cfg!(windows) {
        "PreToolUse.ps1"
    } else {
        "PreToolUse"
    };
    let wiring = run_hook(
        home,
        &project,
        payload(
            &project,
            "write_to_file",
            json!({
                "path":documents.join("Cline/Hooks").join(file),
                "content":"disabled"
            }),
        ),
    );
    assert_eq!(wiring["cancel"], true);

    let cli_wiring = run_hook(
        home,
        &project,
        payload(
            &project,
            "write_to_file",
            json!({
                "path":home.join(".cline/hooks").join(file),
                "content":"disabled"
            }),
        ),
    );
    assert_eq!(cli_wiring["cancel"], true);
}

#[test]
fn malformed_payloads_delegate_with_native_output() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    for malformed in [
        json!({"hookName":"PreToolUse"}),
        payload(&project, "execute_command", json!({"command":7})),
        json!({
            "taskId":"task-1",
            "hookName":"PreToolUse",
            "workspaceRoots":[project],
            "preToolUse":{
                "toolName":"execute_command",
                "tool":"execute_command",
                "parameters":{"command":"pwd"}
            }
        }),
        json!({
            "taskId":"task-1",
            "hookName":"PreToolUse",
            "workspaceRoots":[project],
            "preToolUse":{
                "toolName":"execute_command",
                "parameters":{"command":"pwd"},
                "result":"not valid for PreToolUse"
            }
        }),
    ] {
        assert_eq!(run_hook(home, &project, malformed), json!({"cancel":false}));
    }
}
