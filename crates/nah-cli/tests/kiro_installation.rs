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
        .env_remove("KIRO_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn hook_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".kiro/hooks/nah.json")
}

fn config(path: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[cfg(unix)]
fn run_installed_command(
    home: &std::path::Path,
    project: &std::path::Path,
    command: &str,
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
    let write = child.stdin.take().unwrap().write_all(
        json!({
            "hook_event_name":"PreToolUse",
            "cwd":project,
            "tool_name":"execute_bash",
            "tool_input":{"command":"git status"}
        })
        .to_string()
        .as_bytes(),
    );
    assert!(
        write.is_ok() || write.is_err_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
    );
    child.wait_with_output().unwrap()
}

#[test]
fn install_status_and_uninstall_own_only_nah_file() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let hooks = home.join(".kiro/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let sibling = hooks.join("audit.json");
    std::fs::write(&sibling, "{}\n").unwrap();

    let installed = nah(home, &["hook", "kiro", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let path = hook_path(home);
    let first = std::fs::read(&path).unwrap();
    let configured = config(&path);
    assert_eq!(configured["version"], "v1");
    assert_eq!(configured["hooks"][0]["name"], "nah");
    assert_eq!(configured["hooks"][0]["trigger"], "PreToolUse");
    assert_eq!(configured["hooks"][0]["timeout"], 5);
    assert_eq!(configured["hooks"][0]["enabled"], true);
    assert_eq!(configured["hooks"][0]["action"]["type"], "command");
    assert!(
        configured["hooks"][0]["action"]["command"]
            .as_str()
            .unwrap()
            .contains(" hook kiro run")
    );
    assert!(sibling.exists());

    let status = nah(home, &["hook", "kiro", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "Kiro CLI: wiring current\nfailure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nverify: nah docs runtime-kiro\n"
    );
    assert!(nah(home, &["hook", "kiro", "install"]).status.success());
    assert_eq!(std::fs::read(&path).unwrap(), first);

    let mut stale = configured;
    stale["hooks"][0]["action"]["command"] = json!(
        stale["hooks"][0]["action"]["command"]
            .as_str()
            .unwrap()
            .replace(env!("CARGO_BIN_EXE_nah"), "/stale/nah")
    );
    std::fs::write(&path, serde_json::to_vec_pretty(&stale).unwrap()).unwrap();
    let status = nah(home, &["hook", "kiro", "status"]);
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "Kiro CLI: reinstall required\ndetected failure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nnext: nah hook kiro install\ndocs: nah docs runtime-kiro\n"
    );
    assert!(nah(home, &["hook", "kiro", "install"]).status.success());

    let removed = nah(home, &["hook", "kiro", "uninstall"]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(!path.exists());
    assert!(sibling.exists());
    assert!(nah(home, &["hook", "kiro", "uninstall"]).status.success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(home.join(".nah/kiro-hook.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn installed_command_runs_the_adapter_and_delegates_without_nah() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    assert!(nah(home, &["hook", "kiro", "install"]).status.success());
    let command = config(&hook_path(home))["hooks"][0]["action"]["command"]
        .as_str()
        .unwrap()
        .to_owned();
    let healthy = run_installed_command(home, &project, &command);
    assert!(healthy.status.success(), "{healthy:?}");

    let unavailable = run_installed_command(
        home,
        &project,
        &command.replace(env!("CARGO_BIN_EXE_nah"), "/missing/nah"),
    );
    assert_eq!(unavailable.status.code(), Some(1), "{unavailable:?}");
    assert!(
        String::from_utf8_lossy(&unavailable.stderr).contains("nah - evaluation failed"),
        "{unavailable:?}"
    );
}

#[test]
fn install_rejects_conflicts_and_supports_absolute_kiro_home() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = hook_path(home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{\"version\":\"v1\",\"hooks\":[]}\n").unwrap();
    let conflict = nah(home, &["hook", "kiro", "install"]);
    assert_eq!(conflict.status.code(), Some(2), "{conflict:?}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "{\"version\":\"v1\",\"hooks\":[]}\n"
    );

    let custom_temp = tempfile::tempdir().unwrap();
    // kiro refuses a home whose canonical path differs from the one given,
    // and macOS temp directories sit under a symlinked /var
    let custom = std::fs::canonicalize(custom_temp.path()).unwrap();
    let installed = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "kiro", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("KIRO_HOME", &custom)
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");
    assert!(&custom.join("hooks/nah.json").exists());

    let relative = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "kiro", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("KIRO_HOME", "relative")
        .output()
        .unwrap();
    assert_eq!(relative.status.code(), Some(2), "{relative:?}");
}

#[test]
fn install_and_uninstall_reject_modified_nah_shaped_hooks() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = hook_path(home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let modified = json!({
        "version":"v1",
        "hooks":[{
            "name":"nah",
            "description":"user hook",
            "trigger":"SomethingElse",
            "action":{
                "type":"command",
                "command":"'/tmp/nah' hook kiro run; printf user-command"
            },
            "timeout":99,
            "enabled":false
        }]
    });
    let bytes = serde_json::to_vec_pretty(&modified).unwrap();

    for action in ["install", "uninstall"] {
        std::fs::write(&path, &bytes).unwrap();
        let output = nah(home, &["hook", "kiro", action]);
        assert_eq!(output.status.code(), Some(2), "{action}: {output:?}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{action}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("kiro-hook-file-conflict"),
            "{action}: {output:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn install_rejects_hook_and_directory_symlinks() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let target = home.join("target");
    std::fs::create_dir(&target).unwrap();
    symlink(&target, home.join(".kiro")).unwrap();
    let output = nah(home, &["hook", "kiro", "install"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!target.join("hooks/nah.json").exists());

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = hook_path(home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = home.join("target.json");
    std::fs::write(&target, "unchanged").unwrap();
    symlink(&target, &path).unwrap();
    let output = nah(home, &["hook", "kiro", "install"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let real = tempfile::tempdir().unwrap();
    let custom = home.join("custom-kiro");
    symlink(real.path(), &custom).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "kiro", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("KIRO_HOME", &custom)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!real.path().join("hooks/nah.json").exists());
}
