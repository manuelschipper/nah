#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::process::Command;

use serde_json::{Value, json};

#[cfg(unix)]
fn fake_hermes(home: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    use std::os::unix::fs::PermissionsExt;

    let bin = home.join("bin");
    let log = home.join("hermes.log");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("hermes"),
        r#"#!/bin/sh
printf '%s|%s\n' "$HERMES_HOME" "$*" >> "$HERMES_LOG"
"#,
    )
    .unwrap();
    std::fs::set_permissions(bin.join("hermes"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    (bin, log, path)
}

#[cfg(unix)]
fn run_lifecycle(
    home: &std::path::Path,
    hermes_home: &std::path::Path,
    log: &std::path::Path,
    path: &str,
    action: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "hermes", action])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("HERMES_HOME", hermes_home)
        .env("HERMES_LOG", log)
        .env("PATH", path)
        .output()
        .unwrap()
}

#[cfg(unix)]
fn yaml(path: &std::path::Path) -> serde_yaml_ng::Value {
    serde_yaml_ng::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn install_approves_only_nah_and_uninstall_preserves_other_hooks() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let hermes_home = home.join(".hermes-test");
    std::fs::create_dir_all(&hermes_home).unwrap();
    std::fs::write(
        hermes_home.join("config.yaml"),
        "model:\n  default: test\nhooks:\n  pre_tool_call:\n    - command: existing-hook\n      matcher: terminal\n",
    )
    .unwrap();
    let unrelated_approval = json!({
        "event":"pre_tool_call",
        "command":"existing-hook",
        "approved_at":"user-approved",
        "script_mtime_at_approval":null
    });
    std::fs::write(
        hermes_home.join("shell-hooks-allowlist.json"),
        json!({"approvals":[unrelated_approval.clone()]}).to_string(),
    )
    .unwrap();
    let (_, log, path) = fake_hermes(home);

    let installed = run_lifecycle(home, &hermes_home, &log, &path, "install");
    assert!(installed.status.success(), "{installed:?}");
    let config = yaml(&hermes_home.join("config.yaml"));
    let hooks = config["hooks"]["pre_tool_call"].as_sequence().unwrap();
    assert_eq!(hooks.len(), 2);
    assert_eq!(hooks[0]["command"], "existing-hook");
    assert_eq!(hooks[1]["command"], "nah hook hermes run");
    assert_eq!(hooks[1]["timeout"], 5);
    assert_eq!(hooks[1]["managed_by"], "nah");
    assert_eq!(config["model"]["default"], "test");
    let allowlist: Value = serde_json::from_str(
        &std::fs::read_to_string(hermes_home.join("shell-hooks-allowlist.json")).unwrap(),
    )
    .unwrap();
    let approvals = allowlist["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 2);
    assert_eq!(approvals[0], unrelated_approval);
    assert_eq!(approvals[1]["event"], "pre_tool_call");
    assert_eq!(approvals[1]["command"], "nah hook hermes run");
    let current = run_lifecycle(home, &hermes_home, &log, &path, "status");
    assert_eq!(
        String::from_utf8_lossy(&current.stdout),
        "Hermes: wiring current\nverify: nah docs runtime-hermes\n"
    );

    std::fs::write(
        hermes_home.join("shell-hooks-allowlist.json"),
        json!({"approvals":[unrelated_approval.clone()]}).to_string(),
    )
    .unwrap();
    let stale = run_lifecycle(home, &hermes_home, &log, &path, "status");
    assert_eq!(
        String::from_utf8_lossy(&stale.stdout),
        "Hermes: reinstall required\nnext: nah hook hermes install\ndocs: nah docs runtime-hermes\n"
    );

    let reinstalled = run_lifecycle(home, &hermes_home, &log, &path, "install");
    assert!(reinstalled.status.success(), "{reinstalled:?}");
    assert_eq!(
        yaml(&hermes_home.join("config.yaml"))["hooks"]["pre_tool_call"]
            .as_sequence()
            .unwrap()
            .len(),
        2
    );

    let uninstalled = run_lifecycle(home, &hermes_home, &log, &path, "uninstall");
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    let config = yaml(&hermes_home.join("config.yaml"));
    let hooks = config["hooks"]["pre_tool_call"].as_sequence().unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0]["command"], "existing-hook");
    assert_eq!(config["model"]["default"], "test");
    let allowlist: Value = serde_json::from_str(
        &std::fs::read_to_string(hermes_home.join("shell-hooks-allowlist.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(allowlist["approvals"], json!([unrelated_approval]));
}

#[cfg(unix)]
#[test]
fn install_rejects_unowned_or_ambiguous_native_hooks() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let (_, log, path) = fake_hermes(home);

    let unowned_home = home.join("unowned");
    std::fs::create_dir_all(&unowned_home).unwrap();
    std::fs::write(
        unowned_home.join("config.yaml"),
        "hooks:\n  pre_tool_call:\n    - command: nah hook hermes run\n      timeout: 9\n",
    )
    .unwrap();
    let unowned = run_lifecycle(home, &unowned_home, &log, &path, "install");
    assert!(!unowned.status.success());
    assert!(String::from_utf8_lossy(&unowned.stderr).contains("hermes-hook-not-owned"));

    let ambiguous_home = home.join("ambiguous");
    std::fs::create_dir_all(&ambiguous_home).unwrap();
    std::fs::write(
        ambiguous_home.join("config.yaml"),
        "hooks:\n  pre_tool_call:\n    - command: first\n      managed_by: nah\n    - command: second\n      managed_by: nah\n",
    )
    .unwrap();
    let ambiguous = run_lifecycle(home, &ambiguous_home, &log, &path, "install");
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("hermes-hook-ownership-ambiguous"));

    let symlink_home = home.join("symlink");
    std::fs::create_dir_all(&symlink_home).unwrap();
    let target = home.join("user-config.yaml");
    std::fs::write(&target, "model: user\n").unwrap();
    symlink(&target, symlink_home.join("config.yaml")).unwrap();
    let linked = run_lifecycle(home, &symlink_home, &log, &path, "install");
    assert!(!linked.status.success());
    assert!(String::from_utf8_lossy(&linked.stderr).contains("hermes-hook-symlink-unsupported"));
    assert_eq!(std::fs::read_to_string(target).unwrap(), "model: user\n");
}
