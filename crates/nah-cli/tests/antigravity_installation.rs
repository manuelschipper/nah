#![cfg(not(windows))]
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

fn hooks_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".gemini/config/hooks.json")
}

fn hooks(home: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(hooks_path(home)).unwrap()).unwrap()
}

fn installed_command(config: &Value) -> &str {
    config["nah"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
}

fn run_installed_hook(
    home: &std::path::Path,
    command: &str,
    workspaces: &[&std::path::Path],
    tool: &str,
    args: Value,
) -> std::process::Output {
    let executable = command
        .strip_suffix(" hook antigravity run")
        .unwrap()
        .trim_matches(['\'', '"']);
    let mut child = Command::new(executable)
        .args(["hook", "antigravity", "run"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "toolCall": {"name":tool,"args":args},
        "stepIdx": 1,
        "conversationId": "conversation-1",
        "workspacePaths": workspaces,
        "transcriptPath": home.join("transcript.jsonl"),
        "artifactDirectoryPath": home.join("artifacts")
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
fn install_runs_real_hook_and_uninstall_preserves_other_hooks() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    let path = hooks_path(home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = json!({
        "existing-linter": {
            "PostToolUse": [{
                "matcher": "run_command",
                "hooks": [{"type":"command","command":"existing-hook"}]
            }]
        }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();

    let installed = nah(home, &["hook", "antigravity", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("Restart Antigravity"));
    let first_bytes = std::fs::read(&path).unwrap();
    let configured = hooks(home);
    assert_eq!(configured["existing-linter"], original["existing-linter"]);
    assert_eq!(configured["nah"]["enabled"], true);
    assert_eq!(
        configured["nah"]["PreToolUse"][0]["matcher"],
        "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content|list_dir|find_by_name|grep_search"
    );
    assert_eq!(
        configured["nah"]["PreToolUse"][0]["hooks"][0]["type"],
        "command"
    );
    assert_eq!(configured["nah"]["PreToolUse"][0]["hooks"][0]["timeout"], 5);
    let command = installed_command(&configured);
    assert!(command.ends_with(" hook antigravity run"));

    let status = nah(home, &["hook", "antigravity", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "Antigravity: wiring current\nfailure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nverify: nah docs runtime-antigravity\n"
    );

    let installed_again = nah(home, &["hook", "antigravity", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&path).unwrap(), first_bytes);

    for (tool, args) in [
        (
            "run_command",
            json!({"CommandLine":"echo ok","Cwd":project}),
        ),
        (
            "view_file",
            json!({"AbsolutePath":project.join("src/lib.rs")}),
        ),
        (
            "write_to_file",
            json!({"TargetFile":project.join("src/new.rs"),"CodeContent":"new"}),
        ),
        (
            "replace_file_content",
            json!({
                "TargetFile":project.join("src/lib.rs"),
                "TargetContent":"demo",
                "ReplacementContent":"example",
                "AllowMultiple":false
            }),
        ),
        ("list_dir", json!({"DirectoryPath":project.join("src")})),
        (
            "find_by_name",
            json!({"SearchDirectory":project,"Pattern":"*.rs"}),
        ),
        (
            "grep_search",
            json!({"SearchPath":project.join("src/lib.rs"),"Query":"demo"}),
        ),
    ] {
        let output = run_installed_hook(home, command, &[&project], tool, args);
        assert!(output.status.success(), "{tool}: {output:?}");
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision, json!({"decision":"ask"}), "{tool}: {output:?}");
    }

    let delegated = run_installed_hook(
        home,
        command,
        &[&project],
        "search_web",
        json!({"query":"example"}),
    );
    assert!(delegated.status.success(), "{delegated:?}");
    let decision: Value = serde_json::from_slice(&delegated.stdout).unwrap();
    assert_eq!(decision, json!({"decision":"ask"}));

    let recursive_grep = run_installed_hook(
        home,
        command,
        &[&project],
        "grep_search",
        json!({"SearchPath":project,"Query":"demo"}),
    );
    assert!(recursive_grep.status.success(), "{recursive_grep:?}");
    let decision: Value = serde_json::from_slice(&recursive_grep.stdout).unwrap();
    assert_eq!(decision, json!({"decision":"ask"}));

    let output = run_installed_hook(
        home,
        command,
        &[&project],
        "view_file",
        json!({"AbsolutePath":project.join(".env")}),
    );
    assert!(output.status.success(), "{output:?}");
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny", "{output:?}");
    assert!(
        decision["reason"].as_str().unwrap().starts_with("nah - "),
        "{output:?}"
    );
    let unsupported_task = run_installed_hook(
        home,
        command,
        &[&project],
        "manage_task",
        json!({"Action":"send_input","TaskId":"task-1","Input":"rm -rf /"}),
    );
    assert!(unsupported_task.status.success(), "{unsupported_task:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&unsupported_task.stdout).unwrap(),
        json!({"decision":"ask"})
    );
    let runtime_lifecycle = run_installed_hook(
        home,
        command,
        &[&project],
        "run_command",
        json!({"CommandLine":"nah hook antigravity uninstall","Cwd":project}),
    );
    assert!(runtime_lifecycle.status.success(), "{runtime_lifecycle:?}");
    let runtime_lifecycle: Value = serde_json::from_slice(&runtime_lifecycle.stdout).unwrap();
    assert_eq!(runtime_lifecycle["decision"], "deny");
    assert!(
        runtime_lifecycle["reason"]
            .as_str()
            .unwrap()
            .contains("do not retry")
    );
    let shared_config = run_installed_hook(
        home,
        command,
        &[&project],
        "write_to_file",
        json!({"TargetFile":path,"CodeContent":"disabled"}),
    );
    assert!(shared_config.status.success(), "{shared_config:?}");
    let shared_config: Value = serde_json::from_slice(&shared_config.stdout).unwrap();
    assert_eq!(shared_config["decision"], "deny");

    let mut stale = hooks(home);
    stale["nah"]["enabled"] = json!(false);
    std::fs::write(&path, serde_json::to_vec_pretty(&stale).unwrap()).unwrap();
    let status = nah(home, &["hook", "antigravity", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "Antigravity: reinstall required\ndetected failure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nnext: nah hook antigravity install\ndocs: nah docs runtime-antigravity\n"
    );
    let repaired = nah(home, &["hook", "antigravity", "install"]);
    assert!(repaired.status.success(), "{repaired:?}");
    assert_eq!(hooks(home)["nah"]["enabled"], true);

    let uninstalled = nah(home, &["hook", "antigravity", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert_eq!(hooks(home), original);
    let uninstalled_again = nah(home, &["hook", "antigravity", "uninstall"]);
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

#[test]
fn installed_adapter_asks_on_malformed_input() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    let installed = nah(home, &["hook", "antigravity", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let configured = hooks(home);
    let command = installed_command(&configured);

    for (tool, args, workspaces) in [
        (
            "run_command",
            json!({"CommandLine":7,"Cwd":project}),
            vec![project.as_path()],
        ),
        (
            "view_file",
            json!({"AbsolutePath":"relative"}),
            vec![project.as_path()],
        ),
        (
            "write_to_file",
            json!({"TargetFile":project.join("x")}),
            vec![project.as_path()],
        ),
        (
            "view_file",
            json!({"AbsolutePath":project.join("src/lib.rs")}),
            vec![],
        ),
    ] {
        let output = run_installed_hook(home, command, &workspaces, tool, args);
        assert!(output.status.success(), "{tool}: {output:?}");
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision, json!({"decision":"ask"}), "{tool}: {output:?}");
    }
}

#[test]
fn malformed_configuration_is_preserved() {
    for invalid in [
        json!([]),
        json!({"nah":{"enabled":true}}),
        json!({"nah":"reserved by another hook"}),
    ] {
        let other = tempfile::tempdir().unwrap();
        let path = hooks_path(other.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = serde_json::to_vec_pretty(&invalid).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let output = nah(other.path(), &["hook", "antigravity", "install"]);
        assert_eq!(output.status.code(), Some(2), "{invalid}: {output:?}");
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_config_paths_and_lock() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = hooks_path(home);
    let target = home.join("real-hooks.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&target, "{}\n").unwrap();
    symlink(&target, &path).unwrap();
    let output = nah(home, &["hook", "antigravity", "install"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");

    let redirected = tempfile::tempdir().unwrap();
    let gemini = redirected.path().join(".gemini");
    let target_directory = redirected.path().join("redirected-config");
    std::fs::create_dir(&gemini).unwrap();
    std::fs::create_dir(&target_directory).unwrap();
    symlink(&target_directory, gemini.join("config")).unwrap();
    let output = nah(redirected.path(), &["hook", "antigravity", "install"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!target_directory.join("hooks.json").exists());

    let other = tempfile::tempdir().unwrap();
    let lock = other.path().join(".nah/antigravity-hook.lock");
    let lock_target = other.path().join("real-lock");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock_target, "unchanged").unwrap();
    symlink(&lock_target, &lock).unwrap();
    let output = nah(other.path(), &["hook", "antigravity", "install"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(std::fs::read_to_string(&lock_target).unwrap(), "unchanged");

    let redirected_lock = tempfile::tempdir().unwrap();
    let lock_directory = redirected_lock.path().join("redirected-lock");
    std::fs::create_dir(&lock_directory).unwrap();
    symlink(&lock_directory, redirected_lock.path().join(".nah")).unwrap();
    let output = nah(redirected_lock.path(), &["hook", "antigravity", "install"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!lock_directory.join("antigravity-hook.lock").exists());
}
