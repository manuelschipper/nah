#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;
use serde_json::json;
use support::repo;

fn nah(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CODEX_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn hooks(home: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(home.join(".codex/hooks.json")).unwrap()).unwrap()
}

fn nah_handlers(hooks: &Value) -> Vec<&Value> {
    hooks["hooks"]["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter(|handler| {
            handler["type"] == "command"
                && handler["command"]
                    .as_str()
                    .is_some_and(|command| command.ends_with(" hook codex run"))
        })
        .collect()
}

fn run_installed_hook(
    home: &std::path::Path,
    project: &std::path::Path,
    handler: &Value,
    tool: &str,
    tool_input: Value,
) -> std::process::Output {
    let mut command = configured_command(handler["command"].as_str().unwrap());
    let mut child = command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "session_id": "session-1",
        "turn_id": "turn-1",
        "cwd": project,
        "hook_event_name": "PreToolUse",
        "model": "gpt-test",
        "permission_mode": "default",
        "tool_name": tool,
        "tool_use_id": "call-1",
        "tool_input": tool_input,
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[cfg(unix)]
fn configured_command(command: &str) -> Command {
    let mut configured = Command::new("sh");
    configured.args(["-c", command]);
    configured
}

#[cfg(windows)]
fn configured_command(command: &str) -> Command {
    let mut configured = Command::new("cmd.exe");
    configured.args(["/d", "/c", command]);
    configured
}

#[test]
fn install_runs_the_codex_hook_and_uninstall_preserves_other_hooks() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let hooks_path = home.join(".codex/hooks.json");
    std::fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
    let original = json!({
        "description": "existing hooks",
        "hooks": {
            "PostToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "existing-hook"}]
            }],
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "other-hook"}]
            }]
        }
    });
    std::fs::write(&hooks_path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();

    let installed = nah(home, &["hook", "codex", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("run /hooks"));
    let first_bytes = std::fs::read(&hooks_path).unwrap();
    let configured = hooks(home);
    assert_eq!(configured["description"], "existing hooks");
    assert_eq!(
        configured["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "existing-hook"
    );
    let handlers = nah_handlers(&configured);
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["timeout"], 5);
    assert!(handlers[0].get("args").is_none());
    if cfg!(windows) {
        let command = handlers[0]["command"].as_str().unwrap();
        assert!(command.starts_with('"'));
        assert!(
            command
                .to_ascii_lowercase()
                .contains("nah.exe\" hook codex run")
        );
    }
    assert!(nah(home, &["hook", "codex", "status"]).status.success());

    let installed_again = nah(home, &["hook", "codex", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&hooks_path).unwrap(), first_bytes);

    let mut duplicated = hooks(home);
    let duplicate = nah_handlers(&duplicated)[0].clone();
    duplicated["hooks"]["PreToolUse"]
        .as_array_mut()
        .unwrap()
        .push(json!({"matcher": "Read", "hooks": [duplicate]}));
    std::fs::write(&hooks_path, serde_json::to_vec_pretty(&duplicated).unwrap()).unwrap();
    let repaired = nah(home, &["hook", "codex", "install"]);
    assert!(repaired.status.success(), "{repaired:?}");
    let installed_hooks = hooks(home);
    assert_eq!(nah_handlers(&installed_hooks).len(), 1);
    assert!(
        installed_hooks["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| {
                group["matcher"] == "*"
                    && group["hooks"].as_array().unwrap().iter().any(|handler| {
                        handler["command"]
                            .as_str()
                            .is_some_and(|command| command.ends_with(" hook codex run"))
                    })
            })
    );

    let handler = nah_handlers(&installed_hooks)[0];
    let allowed = run_installed_hook(
        home,
        &project,
        handler,
        "Read",
        json!({"file_path":"src/lib.rs"}),
    );
    assert!(allowed.status.success(), "{allowed:?}");
    assert!(allowed.stdout.is_empty());

    let allowed_write = run_installed_hook(
        home,
        &project,
        handler,
        "Write",
        json!({"file_path":"src/new.rs","content":"new"}),
    );
    assert!(allowed_write.status.success(), "{allowed_write:?}");
    assert!(allowed_write.stdout.is_empty());

    let blocked = run_installed_hook(home, &project, handler, "Read", json!({"file_path":".env"}));
    assert!(blocked.status.success(), "{blocked:?}");
    let blocked: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        blocked["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .starts_with("nah - ")
    );

    let allowed_bash = run_installed_hook(
        home,
        &project,
        handler,
        "Bash",
        json!({"command":"git status"}),
    );
    assert!(allowed_bash.status.success(), "{allowed_bash:?}");
    assert!(allowed_bash.stdout.is_empty());

    let blocked_bash = run_installed_hook(
        home,
        &project,
        handler,
        "Bash",
        json!({"command":"cat .env"}),
    );
    assert!(blocked_bash.status.success(), "{blocked_bash:?}");
    if cfg!(windows) {
        assert!(blocked_bash.stdout.is_empty());
    } else {
        assert_eq!(
            serde_json::from_slice::<Value>(&blocked_bash.stdout).unwrap()["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
    }

    for (tool, input) in [
        (
            "Write",
            json!({"file_path":hooks_path,"content":"{\"hooks\":{}}"}),
        ),
        (
            "Write",
            json!({"file_path":home.join(".codex/config.toml"),"content":"[features]\nhooks = false\n"}),
        ),
    ] {
        let output = run_installed_hook(home, &project, handler, tool, input);
        assert!(output.status.success(), "{tool}: {output:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "{tool}: {output:?}"
        );
    }
    let lifecycle = run_installed_hook(
        home,
        &project,
        handler,
        "Bash",
        json!({"command":"nah hook codex uninstall"}),
    );
    if cfg!(windows) {
        assert!(lifecycle.stdout.is_empty());
    } else {
        let decision: Value = serde_json::from_slice(&lifecycle.stdout).unwrap();
        assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    let allowed_patch = run_installed_hook(
        home,
        &project,
        handler,
        "apply_patch",
        json!({"command":"*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n"}),
    );
    assert!(allowed_patch.status.success(), "{allowed_patch:?}");
    assert!(allowed_patch.stdout.is_empty());

    let env_write = run_installed_hook(
        home,
        &project,
        handler,
        "apply_patch",
        json!({"command":"*** Begin Patch\n*** Add File: .env\n+SECRET=value\n*** End Patch\n"}),
    );
    assert!(env_write.status.success(), "{env_write:?}");
    assert!(env_write.stdout.is_empty());

    let delegated = run_installed_hook(home, &project, handler, "UnknownTool", json!({}));
    assert!(delegated.status.success(), "{delegated:?}");
    assert!(delegated.stdout.is_empty());

    let uninstalled = nah(home, &["hook", "codex", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert_eq!(hooks(home), original);
    let uninstalled_again = nah(home, &["hook", "codex", "uninstall"]);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");
    assert_eq!(hooks(home), original);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&hooks_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn malformed_hooks_fail_without_overwriting_codex_configuration() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let hooks_path = home.join(".codex/hooks.json");
    std::fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
    std::fs::write(&hooks_path, "not-json\n").unwrap();

    let installed = nah(home, &["hook", "codex", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("invalid-codex-hooks"));
    assert_eq!(std::fs::read_to_string(&hooks_path).unwrap(), "not-json\n");

    for malformed in [
        json!([]),
        json!({"hooks":[]}),
        json!({"hooks":{"PreToolUse":{}}}),
        json!({"hooks":{"PreToolUse":[{"hooks":{}}]}}),
    ] {
        let bytes = serde_json::to_vec_pretty(&malformed).unwrap();
        std::fs::write(&hooks_path, &bytes).unwrap();
        let installed = nah(home, &["hook", "codex", "install"]);
        assert_eq!(installed.status.code(), Some(2), "{malformed}");
        assert!(String::from_utf8_lossy(&installed.stderr).contains("invalid-codex-hooks"));
        assert_eq!(std::fs::read(&hooks_path).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_codex_config_paths() {
    use std::os::unix::fs::symlink;

    let directory_home = tempfile::tempdir().unwrap();
    let directory_target = directory_home.path().join("real-codex");
    std::fs::create_dir(&directory_target).unwrap();
    symlink(&directory_target, directory_home.path().join(".codex")).unwrap();
    let installed = nah(directory_home.path(), &["hook", "codex", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("codex-hooks-symlink-unsupported"));
    assert!(!directory_target.join("hooks.json").exists());

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let hooks_path = home.join(".codex/hooks.json");
    let target = home.join("real-hooks.json");
    std::fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
    std::fs::write(&target, "{\"hooks\":{}}\n").unwrap();
    symlink(&target, &hooks_path).unwrap();

    let installed = nah(home, &["hook", "codex", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("codex-hooks-symlink-unsupported"));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "{\"hooks\":{}}\n"
    );
}

#[cfg(unix)]
#[test]
fn install_rejects_a_symlinked_codex_lock_file() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let lock_path = home.join(".nah/codex-hook.lock");
    let target = home.join("lock-target");
    std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    std::fs::write(&target, "unchanged\n").unwrap();
    symlink(&target, &lock_path).unwrap();

    let installed = nah(home, &["hook", "codex", "install"]);
    assert_eq!(installed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&installed.stderr).contains("codex-hook-lock-failed"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "unchanged\n");
}

#[test]
fn custom_codex_home_is_rejected_until_it_can_be_self_protected() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let custom = home.join("custom-codex");
    std::fs::create_dir(&custom).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "codex", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("CODEX_HOME", &custom)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("custom-CODEX_HOME-unsupported"));
    assert!(!custom.join("hooks.json").exists());
}
