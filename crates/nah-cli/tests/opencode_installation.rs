#![cfg(not(windows))]
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
fn install_runs_the_plugin_and_uninstall_preserves_other_plugins() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    let nested = project.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join(".env"), "TOKEN=secret\n").unwrap();
    let plugins = home.join(".config/opencode/plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    let other = plugins.join("other.js");
    std::fs::write(&other, "export const Other = async () => ({});\n").unwrap();

    let installed = nah(home, &["hook", "opencode", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("Restart OpenCode"));
    let plugin = plugins.join("nah.js");
    let first_bytes = std::fs::read(&plugin).unwrap();
    let source = String::from_utf8(first_bytes.clone()).unwrap();
    assert!(source.starts_with("// Managed by nah."));
    assert!(source.contains(r#"["hook", "opencode", "run"]"#));
    assert!(source.contains(r#""tool.execute.before""#));
    assert!(source.contains(env!("CARGO_BIN_EXE_nah")));
    assert!(!source.contains("@opencode-ai/plugin"));

    let installed_again = nah(home, &["hook", "opencode", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), first_bytes);

    if Command::new("bun").arg("--version").output().is_ok() {
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "read",
                json!({"filePath":"src/lib.rs"})
            ),
            Value::Null
        );
        let blocked = run_plugin(home, &project, &plugin, "read", json!({"filePath":".env"}));
        assert!(blocked["error"].as_str().unwrap().starts_with("nah - "));
        let workdir = run_plugin(
            home,
            &project,
            &plugin,
            "bash",
            json!({"command":"cat .env","workdir":"nested"}),
        );
        assert!(workdir["error"].as_str().unwrap().starts_with("nah - "));
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "websearch",
                json!({"query":"example"})
            ),
            Value::Null
        );
    }

    let uninstalled = nah(home, &["hook", "opencode", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert!(!plugin.exists());
    assert_eq!(
        std::fs::read_to_string(&other).unwrap(),
        "export const Other = async () => ({});\n"
    );
    let uninstalled_again = nah(home, &["hook", "opencode", "uninstall"]);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let installed = nah(home, &["hook", "opencode", "install"]);
        assert!(installed.status.success(), "{installed:?}");
        assert_eq!(
            std::fs::metadata(&plugin).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

fn run_plugin(
    home: &std::path::Path,
    project: &std::path::Path,
    plugin: &std::path::Path,
    tool_name: &str,
    tool_input: Value,
) -> Value {
    const HARNESS: &str = r#"
import { pathToFileURL } from "node:url";
const mod = await import(pathToFileURL(process.argv[1]).href);
const hooks = await mod.NahPlugin({ directory: process.argv[2] });
try {
  await hooks["tool.execute.before"](
    { tool: process.argv[3], sessionID: "subagent-session", callID: "call-1" },
    { args: JSON.parse(process.argv[4]) },
  );
  process.stdout.write("null");
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error.message }));
}
"#;
    let output = Command::new("bun")
        .args([
            "-e",
            HARNESS,
            plugin.to_str().unwrap(),
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
fn plugin_delegates_when_the_adapter_is_unavailable() {
    use std::os::unix::fs::PermissionsExt;

    if Command::new("bun").arg("--version").output().is_err() {
        return;
    }
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    let installed = nah(home, &["hook", "opencode", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let plugin = home.join(".config/opencode/plugins/nah.js");
    let original = std::fs::read_to_string(&plugin).unwrap();
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
        std::fs::write(&plugin, source).unwrap();
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "read",
                json!({"filePath":"src/lib.rs"})
            ),
            Value::Null,
            "{name}"
        );
    }
}

#[test]
fn install_refuses_unowned_plugin_and_custom_xdg_config_home() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let plugin = home.join(".config/opencode/plugins/nah.js");
    std::fs::create_dir_all(plugin.parent().unwrap()).unwrap();
    std::fs::write(&plugin, "export const NahPlugin = async () => ({});\n").unwrap();

    for action in ["install", "uninstall"] {
        let output = nah(home, &["hook", "opencode", action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("opencode-plugin-not-owned"));
    }

    let custom = home.join("custom-config");
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "opencode", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", &custom)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("custom-XDG_CONFIG_HOME-unsupported"));
    assert!(!custom.join("opencode/plugins/nah.js").exists());
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_plugin_paths_and_lock() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let opencode = home.join(".config/opencode");
    let plugins = opencode.join("plugins");
    let target = home.join("plugins-target");
    std::fs::create_dir_all(&opencode).unwrap();
    std::fs::create_dir(&target).unwrap();
    symlink(&target, &plugins).unwrap();
    let output = nah(home, &["hook", "opencode", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("opencode-plugin-symlink-unsupported")
    );
    assert!(std::fs::read_dir(&target).unwrap().next().is_none());

    std::fs::remove_file(&plugins).unwrap();
    let lock = home.join(".nah/opencode-hook.lock");
    let lock_target = home.join("lock-target");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock_target, "unchanged\n").unwrap();
    symlink(&lock_target, &lock).unwrap();
    let output = nah(home, &["hook", "opencode", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("opencode-hook-lock-failed"));
    assert_eq!(
        std::fs::read_to_string(&lock_target).unwrap(),
        "unchanged\n"
    );
}
