#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::{Command, Stdio};

#[cfg(unix)]
use serde_json::Value;
use serde_json::json;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use support::repo;

fn nah(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[cfg(unix)]
fn hooks(home: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(home.join(".cursor/hooks.json")).unwrap()).unwrap()
}

#[cfg(unix)]
fn nah_hooks(config: &Value) -> Vec<&Value> {
    config["hooks"]["preToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hook| {
            hook["command"]
                .as_str()
                .is_some_and(|command| command.ends_with(" hook cursor run"))
        })
        .collect()
}

#[cfg(unix)]
fn run_installed_hook(
    home: &std::path::Path,
    project: &std::path::Path,
    command: &str,
    tool_name: &str,
    tool_input: Value,
) -> std::process::Output {
    run_installed_hook_input(
        home,
        command,
        json!({
            "conversation_id": "conversation-1",
            "generation_id": "generation-1",
            "hook_event_name": "preToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "call-1",
            "cwd": project,
        }),
    )
}

#[cfg(unix)]
fn run_installed_hook_input(
    home: &std::path::Path,
    command: &str,
    input: Value,
) -> std::process::Output {
    let mut child = Command::new("sh")
        .args(["-c", command])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[cfg(unix)]
#[test]
fn install_runs_cursor_hook_and_uninstall_preserves_other_hooks() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    let path = home.join(".cursor/hooks.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = json!({
        "version": 1,
        "description": "existing hooks",
        "hooks": {
            "postToolUse": [{"command":"existing-post"}],
            "preToolUse": [{"command":"existing-pre","matcher":"Shell"}]
        }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();

    let installed = nah(home, &["hook", "cursor", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let first_bytes = std::fs::read(&path).unwrap();
    let configured = hooks(home);
    assert_eq!(configured["description"], "existing hooks");
    assert_eq!(
        configured["hooks"]["postToolUse"][0]["command"],
        "existing-post"
    );
    let handlers = nah_hooks(&configured);
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["matcher"], "*");
    assert_eq!(handlers[0]["timeout"], 5);
    assert!(handlers[0].get("failClosed").is_none());

    let installed_again = nah(home, &["hook", "cursor", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&path).unwrap(), first_bytes);

    let mut duplicated = hooks(home);
    let duplicate = nah_hooks(&duplicated)[0].clone();
    duplicated["hooks"]["preToolUse"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    std::fs::write(&path, serde_json::to_vec_pretty(&duplicated).unwrap()).unwrap();
    let repaired = nah(home, &["hook", "cursor", "install"]);
    assert!(repaired.status.success(), "{repaired:?}");
    let repaired = hooks(home);
    assert_eq!(nah_hooks(&repaired).len(), 1);
    let command = nah_hooks(&repaired)[0]["command"].as_str().unwrap();

    for (tool, input) in [
        ("Read", json!({"file_path":"src/lib.rs"})),
        (
            "Write",
            json!({"file_path":"src/new.rs","content":"pub fn new() {}\n"}),
        ),
        ("Delete", json!({"file_path":"src/lib.rs"})),
        ("Grep", json!({"pattern":"demo","file_path":"src"})),
        ("List", json!({"file_path":"src"})),
        (
            "Shell",
            json!({"command":"echo ok","working_directory":project}),
        ),
        ("WebSearch", json!({"query":"example"})),
    ] {
        let output = run_installed_hook(home, &project, command, tool, input);
        assert!(output.status.success(), "{tool}: {output:?}");
        assert!(output.stdout.is_empty(), "{tool}: {output:?}");
    }

    let secret = run_installed_hook(home, &project, command, "Read", json!({"file_path":".env"}));
    assert_eq!(secret.status.code(), Some(2), "{secret:?}");
    let denied: Value = serde_json::from_slice(&secret.stdout).unwrap();
    assert_eq!(denied["permission"], "deny");
    assert!(
        denied["user_message"]
            .as_str()
            .unwrap()
            .starts_with("nah - ")
    );
    assert_eq!(denied["agent_message"], denied["user_message"]);
    let cli_secret = run_installed_hook_input(
        home,
        command,
        json!({
            "conversation_id": "conversation-2",
            "generation_id": "generation-2",
            "model": "default",
            "tool_name": "Read",
            "tool_input": {"file_path":project.join(".env")},
            "tool_use_id": "call-2",
            "session_id": "conversation-2",
            "hook_event_name": "preToolUse",
            "cursor_version": "2026.07.23-e383d2b",
            "workspace_roots": [project],
            "user_email": "user@example.com",
            "transcript_path": null
        }),
    );
    assert_eq!(cli_secret.status.code(), Some(2), "{cli_secret:?}");
    let denied: Value = serde_json::from_slice(&cli_secret.stdout).unwrap();
    assert_eq!(denied["permission"], "deny");
    let lifecycle = run_installed_hook(
        home,
        &project,
        command,
        "Shell",
        json!({"command":"nah hook cursor uninstall","cwd":project}),
    );
    assert_eq!(lifecycle.status.code(), Some(2), "{lifecycle:?}");
    let denied: Value = serde_json::from_slice(&lifecycle.stdout).unwrap();
    assert_eq!(denied["permission"], "deny");
    assert!(
        denied["agent_message"]
            .as_str()
            .unwrap()
            .contains("do not retry")
    );
    for (tool, input) in [
        (
            "Write",
            json!({
                "file_path":home.join(".cursor/hooks.json"),
                "content":"disabled"
            }),
        ),
        (
            "Delete",
            json!({"file_path":home.join(".cursor/hooks.json")}),
        ),
    ] {
        let output = run_installed_hook(home, &project, command, tool, input);
        assert_eq!(output.status.code(), Some(2), "{tool}: {output:?}");
        let denied: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(denied["permission"], "deny", "{tool}: {output:?}");
    }

    let uninstalled = nah(home, &["hook", "cursor", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert_eq!(hooks(home), original);
    let uninstalled_again = nah(home, &["hook", "cursor", "uninstall"]);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");
    assert_eq!(hooks(home), original);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn malformed_cursor_input_delegates() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    let installed = nah(home, &["hook", "cursor", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let configured = hooks(home);
    let command = nah_hooks(&configured)[0]["command"].as_str().unwrap();

    for (tool, input) in [
        ("Shell", json!({"command":7})),
        ("Read", json!({"file_path":""})),
        ("Write", json!({"file_path":"src/lib.rs"})),
        ("Delete", json!({"file_path":7})),
    ] {
        let output = run_installed_hook(home, &project, command, tool, input);
        assert!(output.status.success(), "{tool}: {output:?}");
        assert!(output.stdout.is_empty(), "{tool}: {output:?}");
        assert!(output.stderr.is_empty(), "{tool}: {output:?}");
    }
}

#[test]
fn malformed_cursor_configuration_is_not_overwritten() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = home.join(".cursor/hooks.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    for malformed in [
        json!([]),
        json!({"version":2}),
        json!({"version":1,"hooks":[]}),
        json!({"version":1,"hooks":{"preToolUse":{}}}),
        json!({"version":1,"hooks":{"preToolUse":["not-a-hook"]}}),
    ] {
        let bytes = serde_json::to_vec_pretty(&malformed).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let installed = nah(home, &["hook", "cursor", "install"]);
        assert_eq!(installed.status.code(), Some(2), "{malformed}");
        assert!(String::from_utf8_lossy(&installed.stderr).contains("invalid-cursor-hooks"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_cursor_config_and_lock() {
    use std::os::unix::fs::symlink;

    let directory_home = tempfile::tempdir().unwrap();
    let directory_target = directory_home.path().join("real-cursor");
    std::fs::create_dir(&directory_target).unwrap();
    symlink(&directory_target, directory_home.path().join(".cursor")).unwrap();
    let installed = nah(directory_home.path(), &["hook", "cursor", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&installed.stderr).contains("cursor-hooks-symlink-unsupported")
    );
    assert!(!directory_target.join("hooks.json").exists());

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = home.join(".cursor/hooks.json");
    let target = home.join("real-hooks.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&target, "{\"version\":1}\n").unwrap();
    symlink(&target, &path).unwrap();
    let installed = nah(home, &["hook", "cursor", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&installed.stderr).contains("cursor-hooks-symlink-unsupported")
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "{\"version\":1}\n"
    );

    std::fs::remove_file(&path).unwrap();
    let lock = home.join(".nah/cursor-hook.lock");
    let lock_target = home.join("lock-target");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock_target, "unchanged\n").unwrap();
    symlink(&lock_target, &lock).unwrap();
    let installed = nah(home, &["hook", "cursor", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("cursor-hook-lock-failed"));
    assert_eq!(
        std::fs::read_to_string(&lock_target).unwrap(),
        "unchanged\n"
    );
}
