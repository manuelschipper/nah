#![cfg(not(windows))]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::json;
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

fn run_hook(
    home: &std::path::Path,
    hook: &std::path::Path,
    cwd: &std::path::Path,
    command: &str,
) -> std::process::Output {
    let input = json!({"event":"before-bash","command":command,"cwd":cwd}).to_string();
    run_hook_input(home, hook, input.as_bytes())
}

fn run_hook_input(
    home: &std::path::Path,
    hook: &std::path::Path,
    input: &[u8],
) -> std::process::Output {
    let mut child = Command::new(hook)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn install_runs_before_bash_and_uninstall_preserves_other_hooks() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    let hooks = home.join(".xi/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let sibling = hooks.join("after-turn");
    std::fs::write(&sibling, "#!/bin/sh\nexit 0\n").unwrap();

    let installed = nah(home, &["hook", "xi", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let hook = hooks.join("before-bash");
    let first = std::fs::read(&hook).unwrap();
    assert_eq!(
        std::fs::metadata(&hook).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let status = nah(home, &["hook", "xi", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert!(nah(home, &["hook", "xi", "install"]).status.success());
    assert_eq!(std::fs::read(&hook).unwrap(), first);

    let delegated = run_hook(home, &hook, &project, "git status");
    assert!(delegated.status.success(), "{delegated:?}");
    assert!(delegated.stdout.is_empty());
    let blocked = run_hook(home, &hook, &project, "cat .env");
    assert_eq!(blocked.status.code(), Some(2), "{blocked:?}");
    assert!(!blocked.stdout.is_empty(), "{blocked:?}");
    let malformed = run_hook_input(home, &hook, br#"{"event":"before-bash"}"#);
    assert!(malformed.status.success(), "{malformed:?}");

    let strict = nah(home, &["hook", "xi", "install", "--fail-closed"]);
    assert!(strict.status.success(), "{strict:?}");
    let strict_bytes = std::fs::read(&hook).unwrap();
    let malformed = run_hook_input(home, &hook, br#"{"event":"before-bash"}"#);
    assert_eq!(malformed.status.code(), Some(2), "{malformed:?}");
    assert!(!malformed.stdout.is_empty(), "{malformed:?}");
    let preserved = nah(home, &["hook", "xi", "install"]);
    assert!(preserved.status.success(), "{preserved:?}");
    assert_eq!(std::fs::read(&hook).unwrap(), strict_bytes);

    let removed = nah(home, &["hook", "xi", "uninstall"]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(!hook.exists());
    assert!(sibling.exists());
    assert!(nah(home, &["hook", "xi", "uninstall"]).status.success());
    assert_eq!(
        std::fs::metadata(home.join(".nah/xi-hook.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn install_and_uninstall_refuse_an_existing_user_hook() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let hook = home.join(".xi/hooks/before-bash");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    let user_hook = b"#!/bin/sh\necho user hook\n";
    std::fs::write(&hook, user_hook).unwrap();

    let install = nah(home, &["hook", "xi", "install"]);
    assert_eq!(install.status.code(), Some(2), "{install:?}");
    let uninstall = nah(home, &["hook", "xi", "uninstall"]);
    assert_eq!(uninstall.status.code(), Some(2), "{uninstall:?}");
    assert_eq!(std::fs::read(&hook).unwrap(), user_hook);

    std::fs::remove_file(&hook).unwrap();
    let target = home.join("user-before-bash");
    std::fs::write(&target, user_hook).unwrap();
    symlink(&target, &hook).unwrap();
    let install = nah(home, &["hook", "xi", "install"]);
    assert_eq!(install.status.code(), Some(2), "{install:?}");
    assert_eq!(std::fs::read(&target).unwrap(), user_hook);
}
