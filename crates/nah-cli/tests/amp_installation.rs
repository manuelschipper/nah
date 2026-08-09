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
    let plugins = home.join(".config/amp/plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    let other = plugins.join("other.ts");
    std::fs::write(&other, "export default function () {}\n").unwrap();

    let absent = nah(home, &["hook", "amp", "status"]);
    assert!(absent.status.success(), "{absent:?}");
    assert_eq!(
        String::from_utf8_lossy(&absent.stdout),
        "Amp: not configured\nnext: nah hook amp install\ndocs: nah docs runtime-amp\n"
    );

    let installed = nah(home, &["hook", "amp", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("plugins: reload"));
    let plugin = plugins.join("nah.ts");
    let first_bytes = std::fs::read(&plugin).unwrap();
    let source = String::from_utf8(first_bytes.clone()).unwrap();
    assert!(source.starts_with("// Managed by nah."));
    assert!(source.contains(r#"["hook", "amp", "run"]"#));
    assert!(source.contains(r#"amp.on("tool.call""#));
    assert!(source.contains("shellCommandFromToolCall"));
    assert!(source.contains(env!("CARGO_BIN_EXE_nah")));
    let current = nah(home, &["hook", "amp", "status"]);
    assert!(current.status.success(), "{current:?}");
    assert_eq!(
        String::from_utf8_lossy(&current.stdout),
        "Amp: wiring current\nfailure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nverify: nah docs runtime-amp\n"
    );

    let strict = nah(home, &["hook", "amp", "install", "--fail-closed"]);
    assert!(strict.status.success(), "{strict:?}");
    let strict_bytes = std::fs::read(&plugin).unwrap();
    assert!(String::from_utf8_lossy(&strict_bytes).contains("--fail-closed"));
    let strict_status = nah(home, &["hook", "amp", "status"]);
    assert!(String::from_utf8_lossy(&strict_status.stdout).contains("failure policy: fail-closed"));
    let preserved = nah(home, &["hook", "amp", "install"]);
    assert!(preserved.status.success(), "{preserved:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), strict_bytes);
    std::fs::write(&plugin, [strict_bytes.as_slice(), b"// stale\n"].concat()).unwrap();
    let strict_stale = nah(home, &["hook", "amp", "status"]);
    assert!(
        String::from_utf8_lossy(&strict_stale.stdout)
            .contains("detected failure policy: fail-closed")
    );
    let preserved = nah(home, &["hook", "amp", "install"]);
    assert!(preserved.status.success(), "{preserved:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), strict_bytes);
    let downgraded = nah(home, &["hook", "amp", "install", "--fail-open"]);
    assert!(downgraded.status.success(), "{downgraded:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), first_bytes);

    std::fs::write(&plugin, format!("{source}\n// stale\n")).unwrap();
    let stale = nah(home, &["hook", "amp", "status"]);
    assert!(stale.status.success(), "{stale:?}");
    assert_eq!(
        String::from_utf8_lossy(&stale.stdout),
        "Amp: reinstall required\ndetected failure policy: fail-open\nguarantee: runtime approval remains authoritative when nah cannot decide\nnext: nah hook amp install\ndocs: nah docs runtime-amp\n"
    );

    let installed_again = nah(home, &["hook", "amp", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), first_bytes);

    if Command::new("bun").arg("--version").output().is_ok() {
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "create_file",
                json!({"path":project.join("src/new.rs"),"content":"new\n"})
            ),
            json!({"action":"allow"})
        );
        let blocked = run_plugin(
            home,
            &project,
            &plugin,
            "shell_command",
            json!({"command":"cat .env","workdir":"nested"}),
        );
        assert_eq!(blocked["action"], "reject-and-continue");
        assert!(blocked["message"].as_str().unwrap().starts_with("nah - "));
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "web_search",
                json!({"query":"example"})
            ),
            json!({"action":"allow"})
        );
        let default_download = run_plugin(
            home,
            &plugins,
            &plugin,
            "download_thread_file",
            json!({"thread":"T-other","path":"nah.ts","overwrite":true}),
        );
        assert_eq!(default_download["action"], "reject-and-continue");
    }

    let uninstalled = nah(home, &["hook", "amp", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert!(!plugin.exists());
    let absent = nah(home, &["hook", "amp", "status"]);
    assert!(absent.status.success(), "{absent:?}");
    assert_eq!(
        String::from_utf8_lossy(&absent.stdout),
        "Amp: not configured\nnext: nah hook amp install\ndocs: nah docs runtime-amp\n"
    );
    assert_eq!(
        std::fs::read_to_string(&other).unwrap(),
        "export default function () {}\n"
    );
    let uninstalled_again = nah(home, &["hook", "amp", "uninstall"]);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let installed = nah(home, &["hook", "amp", "install"]);
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
import { resolve } from "node:path";
const mod = await import(pathToFileURL(process.argv[1]).href);
const project = process.argv[2];
let handler;
mod.default({
  on(event, callback) { if (event === "tool.call") handler = callback; },
  system: { workspaceRoot: { project } },
  helpers: {
    filePathFromURI() { return project; },
    shellCommandFromToolCall(event) {
      if (event.tool !== "shell_command") return null;
      const workdir = event.input.workdir;
      return {
        command: event.input.command,
        dir: typeof workdir === "string" && workdir.length
          ? resolve(project, workdir)
          : project,
      };
    },
  },
});
const result = await handler({
  toolUseID: "tool-1",
  tool: process.argv[3],
  input: JSON.parse(process.argv[4]),
  thread: { id: "T-subagent" },
}, {
  $() {
    return Promise.resolve({ exitCode: 0, stdout: project + "\n", stderr: "" });
  },
});
process.stdout.write(JSON.stringify(result));
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
    let installed = nah(home, &["hook", "amp", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let plugin = home.join(".config/amp/plugins/nah.ts");
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
                "create_file",
                json!({"path":project.join("src/new.rs"),"content":"new\n"})
            ),
            json!({"action":"allow"}),
            "{name}"
        );
    }
}

#[test]
fn install_refuses_an_unowned_plugin() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let plugin = home.join(".config/amp/plugins/nah.ts");
    std::fs::create_dir_all(plugin.parent().unwrap()).unwrap();
    std::fs::write(&plugin, "export default function () {}\n").unwrap();

    for action in ["install", "uninstall"] {
        let output = nah(home, &["hook", "amp", action]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("amp-plugin-not-owned"));
    }
    assert_eq!(
        std::fs::read_to_string(plugin).unwrap(),
        "export default function () {}\n"
    );
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
    let amp = home.join(".config/amp");
    let plugins = amp.join("plugins");
    let target = home.join("plugins-target");
    std::fs::create_dir_all(&amp).unwrap();
    std::fs::create_dir(&target).unwrap();
    symlink(&target, &plugins).unwrap();
    let output = nah(home, &["hook", "amp", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("amp-plugin-symlink-unsupported"));
    assert!(std::fs::read_dir(&target).unwrap().next().is_none());

    std::fs::remove_file(&plugins).unwrap();
    let lock = home.join(".nah/amp-hook.lock");
    let lock_target = home.join("lock-target");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock_target, "unchanged\n").unwrap();
    symlink(&lock_target, &lock).unwrap();
    let output = nah(home, &["hook", "amp", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("amp-hook-lock-failed"));
    assert_eq!(std::fs::read_to_string(lock_target).unwrap(), "unchanged\n");
}
