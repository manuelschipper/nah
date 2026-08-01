#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

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

#[test]
fn install_runs_the_extension_and_uninstall_preserves_pi_settings() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    let settings_path = home.join(".pi/agent/settings.json");
    std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    std::fs::write(&settings_path, "{\"theme\":\"dark\"}\n").unwrap();

    let installed = nah(home, &["hook", "pi", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("/reload"));
    let extension_path = home.join(".pi/agent/extensions/nah/index.js");
    let first_bytes = std::fs::read(&extension_path).unwrap();
    let source = String::from_utf8(first_bytes.clone()).unwrap();
    assert!(source.starts_with("// Managed by nah."));
    assert!(source.contains(r#"["hook", "pi", "run"]"#));
    assert!(source.contains(env!("CARGO_BIN_EXE_nah")));
    assert!(!source.contains("@earendil-works"));
    assert!(!source.contains("@mariozechner"));
    assert_eq!(
        std::fs::read_to_string(&settings_path).unwrap(),
        "{\"theme\":\"dark\"}\n"
    );

    let installed_again = nah(home, &["hook", "pi", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&extension_path).unwrap(), first_bytes);

    if Command::new("node").arg("--version").output().is_ok() {
        assert_eq!(
            run_extension(
                home,
                &project,
                &extension_path,
                "read",
                json!({"path":"src/lib.rs"})
            ),
            Value::Null
        );
        let blocked = run_extension(
            home,
            &project,
            &extension_path,
            "read",
            json!({"path":".env"}),
        );
        assert_eq!(blocked["block"], true);
        assert!(blocked["reason"].as_str().unwrap().starts_with("nah - "));
    }

    let uninstalled = nah(home, &["hook", "pi", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert!(!extension_path.exists());
    assert_eq!(
        std::fs::read_to_string(&settings_path).unwrap(),
        "{\"theme\":\"dark\"}\n"
    );
    let uninstalled_again = nah(home, &["hook", "pi", "uninstall"]);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let installed = nah(home, &["hook", "pi", "install"]);
        assert!(installed.status.success(), "{installed:?}");
        assert_eq!(
            std::fs::metadata(&extension_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

fn run_extension(
    home: &std::path::Path,
    project: &std::path::Path,
    extension: &std::path::Path,
    tool_name: &str,
    tool_input: Value,
) -> Value {
    const HARNESS: &str = r#"
const factory = require(process.argv[1]);
let handler;
factory({ on(event, callback) { if (event === "tool_call") handler = callback; } });
const toolName = process.argv[3];
const input = JSON.parse(process.argv[4]);
Promise.resolve(handler(
  { toolName, input, toolCallId: "call-1" },
  { cwd: process.argv[2], signal: new AbortController().signal }
)).then((result) => process.stdout.write(JSON.stringify(result ?? null)));
"#;
    let output = Command::new("node")
        .args([
            "-e",
            HARNESS,
            extension.to_str().unwrap(),
            project.to_str().unwrap(),
            tool_name,
            &tool_input.to_string(),
        ])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(unix)]
#[test]
fn extension_delegates_when_the_adapter_is_unavailable() {
    use std::os::unix::fs::PermissionsExt;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    let installed = nah(home, &["hook", "pi", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let extension = home.join(".pi/agent/extensions/nah/index.js");
    let original = std::fs::read_to_string(&extension).unwrap();
    let original_executable = serde_json::to_string(env!("CARGO_BIN_EXE_nah")).unwrap();

    let cases = [
        ("missing", None, false),
        (
            "malformed",
            Some("#!/bin/sh\nprintf 'not-json\\n'\n"),
            false,
        ),
        ("timeout", Some("#!/bin/sh\nsleep 1\n"), true),
    ];
    for (name, program, shorten_timeout) in cases {
        let executable = home.join(format!("fake-{name}"));
        if let Some(program) = program {
            std::fs::write(&executable, program).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let replacement = serde_json::to_string(executable.to_str().unwrap()).unwrap();
        let mut source = original.replacen(
            &format!("const nahExecutable = {original_executable};"),
            &format!("const nahExecutable = {replacement};"),
            1,
        );
        if shorten_timeout {
            source = source.replacen(
                "setTimeout(() => fail(new Error(\"nah decision timed out\")), 5000)",
                "setTimeout(() => fail(new Error(\"nah decision timed out\")), 20)",
                1,
            );
        }
        std::fs::write(&extension, source).unwrap();
        assert_eq!(
            run_extension(
                home,
                &project,
                &extension,
                "read",
                json!({"path":"src/lib.rs"})
            ),
            Value::Null,
            "{name}"
        );
    }
}

#[test]
fn uninstall_refuses_to_remove_an_unowned_extension() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let extension = home.join(".pi/agent/extensions/nah/index.js");
    std::fs::create_dir_all(extension.parent().unwrap()).unwrap();
    std::fs::write(&extension, "module.exports = () => {};\n").unwrap();

    for action in ["install", "uninstall"] {
        let output = nah(home, &["hook", "pi", action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("pi-extension-not-owned"));
    }
    assert_eq!(
        std::fs::read_to_string(extension).unwrap(),
        "module.exports = () => {};\n"
    );
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_extension_paths_and_lock() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let extension_directory = home.join(".pi/agent/extensions");
    let target_directory = home.join("extensions-target");
    std::fs::create_dir_all(home.join(".pi/agent")).unwrap();
    std::fs::create_dir(&target_directory).unwrap();
    symlink(&target_directory, &extension_directory).unwrap();
    let output = nah(home, &["hook", "pi", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("pi-extension-symlink-unsupported"));
    assert!(
        std::fs::read_dir(&target_directory)
            .unwrap()
            .next()
            .is_none()
    );

    std::fs::remove_file(&extension_directory).unwrap();
    let lock = home.join(".nah/pi-hook.lock");
    let lock_target = home.join("lock-target");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock_target, "unchanged\n").unwrap();
    symlink(&lock_target, &lock).unwrap();
    let output = nah(home, &["hook", "pi", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("pi-hook-lock-failed"));
    assert_eq!(
        std::fs::read_to_string(&lock_target).unwrap(),
        "unchanged\n"
    );
}
