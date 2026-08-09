#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn nah(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("COPILOT_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[test]
fn install_status_and_uninstall_own_only_nah_file() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let hooks = home.join(".copilot/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let sibling = hooks.join("audit.json");
    std::fs::write(&sibling, "{}\n").unwrap();

    let installed = nah(home, &["hook", "copilot", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let path = hooks.join("nah.json");
    let first = std::fs::read(&path).unwrap();
    let config: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(config["version"], 1);
    assert_eq!(config["hooks"]["preToolUse"][0]["type"], "command");
    assert_eq!(config["hooks"]["preToolUse"][0]["timeoutSec"], 5);
    assert!(
        config["hooks"]["preToolUse"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with(" hook copilot run")
    );
    assert!(sibling.exists());

    let status = nah(home, &["hook", "copilot", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "GitHub Copilot: wiring current\nfailure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nverify: nah docs runtime-copilot\n"
    );
    let installed_again = nah(home, &["hook", "copilot", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&path).unwrap(), first);

    let mut stale = config;
    stale["hooks"]["preToolUse"][0]["timeoutSec"] = json!(9);
    std::fs::write(&path, serde_json::to_vec_pretty(&stale).unwrap()).unwrap();
    let status = nah(home, &["hook", "copilot", "status"]);
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "GitHub Copilot: reinstall required\ndetected failure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nnext: nah hook copilot install\ndocs: nah docs runtime-copilot\n"
    );
    assert!(nah(home, &["hook", "copilot", "install"]).status.success());

    let removed = nah(home, &["hook", "copilot", "uninstall"]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(!path.exists());
    assert!(sibling.exists());
    assert!(
        nah(home, &["hook", "copilot", "uninstall"])
            .status
            .success()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(home.join(".nah/copilot-hook.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn install_rejects_conflicts_custom_home_and_symlinks() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = home.join(".copilot/hooks/nah.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{\"hooks\":{\"preToolUse\":[]}}\n").unwrap();
    let conflict = nah(home, &["hook", "copilot", "install"]);
    assert_eq!(conflict.status.code(), Some(2), "{conflict:?}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "{\"hooks\":{\"preToolUse\":[]}}\n"
    );

    let custom = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "copilot", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("COPILOT_HOME", home.join("elsewhere"))
        .output()
        .unwrap();
    assert_eq!(custom.status.code(), Some(2), "{custom:?}");
    assert!(String::from_utf8_lossy(&custom.stderr).contains("custom-copilot-home"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let redirected = tempfile::tempdir().unwrap();
        let target = redirected.path().join("target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, redirected.path().join(".copilot")).unwrap();
        let output = nah(redirected.path(), &["hook", "copilot", "install"]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(!target.join("hooks/nah.json").exists());
    }
}

#[test]
fn owned_command_with_unowned_configuration_is_not_overwritten() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(nah(home, &["hook", "copilot", "install"]).status.success());
    let path = home.join(".copilot/hooks/nah.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["disableAllHooks"] = json!(true);
    let bytes = serde_json::to_vec_pretty(&config).unwrap();
    std::fs::write(&path, &bytes).unwrap();

    for action in ["status", "install", "uninstall"] {
        let output = nah(home, &["hook", "copilot", action]);
        assert_eq!(output.status.code(), Some(2), "{action}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("conflict"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
