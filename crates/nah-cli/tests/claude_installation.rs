#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
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

fn settings(home: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(home.join(".claude/settings.json")).unwrap()).unwrap()
}

fn is_nah_handler(handler: &Value) -> bool {
    let command = handler["command"]
        .as_str()
        .and_then(|command| std::path::Path::new(command).file_name())
        .and_then(|name| name.to_str());
    handler["type"] == "command"
        && matches!(command, Some("nah" | "nah.exe"))
        && (matches!(
            handler["args"].as_array().map(|args| args.as_slice()),
            Some([hook, claude, run])
                if hook == "hook" && claude == "claude" && run == "run"
        ) || matches!(
            handler["args"].as_array().map(|args| args.as_slice()),
            Some([hook, claude, run, strict])
                if hook == "hook"
                    && claude == "claude"
                    && run == "run"
                    && strict == "--strict"
        ))
}

fn nah_handlers(settings: &Value) -> Vec<&Value> {
    settings["hooks"]["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter(|handler| is_nah_handler(handler))
        .collect()
}

fn run_installed_hook(
    home: &std::path::Path,
    project: &std::path::Path,
    handler: &Value,
    tool: &str,
    tool_input: Value,
) -> std::process::Output {
    let mut child = Command::new(handler["command"].as_str().unwrap())
        .args(
            handler["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|arg| arg.as_str().unwrap()),
        )
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": project,
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn install_runs_the_real_hook_and_uninstall_preserves_other_settings() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let settings_path = home.join(".claude/settings.json");
    std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    let original = json!({
        "theme": "dark",
        "hooks": {
            "PostToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "existing-hook"}]
            }],
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": []
            }, {
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": "other-hook",
                    "args": ["hook", "claude", "run"]
                }]
            }]
        }
    });
    std::fs::write(
        &settings_path,
        serde_json::to_vec_pretty(&original).unwrap(),
    )
    .unwrap();

    let installed = nah(home, &["hook", "claude", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let first_bytes = std::fs::read(&settings_path).unwrap();
    let configured = settings(home);
    assert_eq!(configured["theme"], "dark");
    assert_eq!(
        configured["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "existing-hook"
    );
    let handlers = nah_handlers(&configured);
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["args"], json!(["hook", "claude", "run"]));
    assert_eq!(handlers[0]["timeout"], 5);
    assert!(std::path::Path::new(handlers[0]["command"].as_str().unwrap()).is_absolute());

    let installed_again = nah(home, &["hook", "claude", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&settings_path).unwrap(), first_bytes);
    assert_eq!(nah_handlers(&settings(home)).len(), 1);

    let mut narrowed = settings(home);
    let nah_group = narrowed["hooks"]["PreToolUse"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|group| {
            group["hooks"]
                .as_array()
                .unwrap()
                .iter()
                .any(is_nah_handler)
        })
        .unwrap();
    nah_group["matcher"] = json!("Read");
    std::fs::write(
        &settings_path,
        serde_json::to_vec_pretty(&narrowed).unwrap(),
    )
    .unwrap();
    let repaired = nah(home, &["hook", "claude", "install"]);
    assert!(repaired.status.success(), "{repaired:?}");
    let repaired_settings = settings(home);
    assert_eq!(nah_handlers(&repaired_settings).len(), 1);
    assert!(
        repaired_settings["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| {
                group["matcher"] == "*"
                    && group["hooks"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(is_nah_handler)
            })
    );

    let handler = nah_handlers(&repaired_settings)[0];
    let delegated = run_installed_hook(
        home,
        &project,
        handler,
        "Read",
        json!({"file_path":"src/lib.rs"}),
    );
    assert!(delegated.status.success(), "{delegated:?}");
    assert!(delegated.stdout.is_empty(), "{delegated:?}");
    let blocked = run_installed_hook(home, &project, handler, "Read", json!({"file_path":".env"}));
    assert!(blocked.status.success(), "{blocked:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&blocked.stdout).unwrap()["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    let lifecycle = run_installed_hook(
        home,
        &project,
        handler,
        "Bash",
        json!({"command":"nah hook claude uninstall"}),
    );
    let decision: Value = serde_json::from_slice(&lifecycle.stdout).unwrap();
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    for (tool, input) in [
        (
            "Write",
            json!({"file_path":settings_path,"content":"{\"hooks\":{}}"}),
        ),
        ("Bash", json!({"command":"claude --safe-mode"})),
    ] {
        let output = run_installed_hook(home, &project, handler, tool, input);
        assert!(output.status.success(), "{tool}: {output:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "{tool}: {output:?}"
        );
    }

    let mut legacy_settings = settings(home);
    let legacy_handler = legacy_settings["hooks"]["PreToolUse"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|group| group["hooks"].as_array_mut().into_iter().flatten())
        .find(|handler| is_nah_handler(handler))
        .unwrap();
    legacy_handler["args"] = json!(["hook", "claude", "run", "--strict"]);
    std::fs::write(
        &settings_path,
        serde_json::to_vec_pretty(&legacy_settings).unwrap(),
    )
    .unwrap();
    let migrated = nah(home, &["hook", "claude", "install"]);
    assert!(migrated.status.success(), "{migrated:?}");
    let migrated_settings = settings(home);
    let handlers = nah_handlers(&migrated_settings);
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["args"], json!(["hook", "claude", "run"]));
    let delegated = run_installed_hook(home, &project, handlers[0], "UnknownTool", json!({}));
    assert!(delegated.status.success(), "{delegated:?}");
    assert!(delegated.stdout.is_empty());

    let rejected = nah(home, &["hook", "claude", "install", "--strict"]);
    assert_eq!(rejected.status.code(), Some(4));
    assert_eq!(settings(home), migrated_settings);

    let uninstalled = nah(home, &["hook", "claude", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert_eq!(settings(home), original);
    let uninstalled_again = nah(home, &["hook", "claude", "uninstall"]);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");
    assert_eq!(settings(home), original);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&settings_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn malformed_settings_fail_without_overwriting_user_configuration() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let settings_path = home.join(".claude/settings.json");
    std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    std::fs::write(&settings_path, "not-json\n").unwrap();

    let installed = nah(home, &["hook", "claude", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("invalid-claude-settings"));
    assert_eq!(
        std::fs::read_to_string(settings_path).unwrap(),
        "not-json\n"
    );
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_claude_config_paths() {
    use std::os::unix::fs::symlink;

    let directory_home = tempfile::tempdir().unwrap();
    let directory_target = directory_home.path().join("real-claude");
    std::fs::create_dir(&directory_target).unwrap();
    symlink(&directory_target, directory_home.path().join(".claude")).unwrap();
    let installed = nah(directory_home.path(), &["hook", "claude", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&installed.stderr).contains("claude-settings-symlink-unsupported")
    );
    assert!(!directory_target.join("settings.json").exists());

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let settings_path = home.join(".claude/settings.json");
    let target = home.join("real-settings.json");
    std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    std::fs::write(&target, "{\"theme\":\"dark\"}\n").unwrap();
    symlink(&target, &settings_path).unwrap();

    let installed = nah(home, &["hook", "claude", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&installed.stderr).contains("claude-settings-symlink-unsupported")
    );
    assert!(
        std::fs::symlink_metadata(&settings_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "{\"theme\":\"dark\"}\n"
    );
}

#[cfg(unix)]
#[test]
fn install_rejects_a_symlinked_lock_file() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let lock_path = home.join(".nah/claude-hook.lock");
    let target = home.join("lock-target");
    std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    std::fs::write(&target, "unchanged\n").unwrap();
    symlink(&target, &lock_path).unwrap();

    let installed = nah(home, &["hook", "claude", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("claude-hook-lock-failed"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "unchanged\n");
}
