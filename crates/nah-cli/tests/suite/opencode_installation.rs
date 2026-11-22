#![cfg(not(windows))]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

fn nah(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if args.contains(&"uninstall") || args.contains(&"--fail-open") {
        crate::support::operator_output(&mut command)
    } else {
        command.output().unwrap()
    }
}
#[test]
fn install_runs_the_plugin_and_uninstall_preserves_other_plugins() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    // The secret file the read below must not disclose.
    std::fs::write(project.join(".env"), "FAKE_KEY=not-a-real-secret\n").unwrap();
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
    assert!(source.contains(r#"ctx.tool.hook("execute.before""#));
    assert!(source.contains(env!("CARGO_BIN_EXE_nah")));
    assert!(!source.contains("@opencode-ai/plugin"));

    let installed_again = nah(home, &["hook", "opencode", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), first_bytes);
    // A plugin installed before the prefix was `nah · ` is still ours, and
    // install rewrites it.
    let stale = source.replace("nah · ", "nah - ");
    assert_ne!(stale, source);
    std::fs::write(&plugin, &stale).unwrap();
    let refreshed = nah(home, &["hook", "opencode", "install"]);
    assert!(refreshed.status.success(), "{refreshed:?}");
    assert_eq!(std::fs::read(&plugin).unwrap(), first_bytes);

    if support::interpreter_available("bun") {
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "read",
                json!({"path":"src/lib.rs"}),
                false
            ),
            Value::Null
        );
        let blocked = run_plugin(
            home,
            &project,
            &plugin,
            "read",
            json!({"path":".env"}),
            false,
        );
        assert!(blocked["error"].as_str().unwrap().starts_with("nah · "));
        let workdir = run_plugin(
            home,
            &project,
            &plugin,
            "shell",
            json!({"command":"cat .env","workdir":"nested"}),
            false,
        );
        assert!(workdir["error"].as_str().unwrap().starts_with("nah · "));
        assert_eq!(
            run_plugin(
                home,
                &project,
                &plugin,
                "websearch",
                json!({"query":"example"}),
                false
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
    reject_notice: bool,
) -> Value {
    const HARNESS: &str = r#"
import { pathToFileURL } from "node:url";
const mod = await import(pathToFileURL(process.argv[1]).href);
let hook;
const notices = [];
await mod.default.setup({
  tool: { hook: async (name, handler) => { if (name === "execute.before") hook = handler; } },
  session: {
    get: async () => ({ location: { directory: process.argv[2] } }),
    synthetic: async (notice) => {
      notices.push(notice);
      if (process.argv[5] === "true") throw new Error("notice request failed");
    },
  },
});
try {
  await hook({
    tool: process.argv[3],
    sessionID: "subagent-session",
    id: "call-1",
    input: JSON.parse(process.argv[4]),
  });
  process.stdout.write(JSON.stringify(notices.length ? { notices } : null));
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
            if reject_notice { "true" } else { "false" },
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
fn plugin_follows_the_failure_policy_when_the_adapter_is_unavailable() {
    use std::os::unix::fs::PermissionsExt;

    if !support::interpreter_available("bun") {
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
    let original_executable = serde_json::to_string(env!("CARGO_BIN_EXE_nah")).unwrap();

    let cases = [
        ("missing", None, false),
        (
            "malformed",
            Some("#!/bin/sh\nprintf 'not-json\\n'\n"),
            false,
        ),
        (
            "nonzero",
            Some(
                "#!/bin/sh\nprintf '{\"block\":true,\"evaluation_failed\":false,\"reason\":\"blocked\"}'\nexit 1\n",
            ),
            false,
        ),
        (
            "invalid-envelope",
            Some("#!/bin/sh\nprintf '{\"block\":true,\"reason\":\"blocked\"}'\n"),
            false,
        ),
        (
            "stdout-limit",
            Some(
                "#!/bin/sh\nprintf '{\"block\":true,\"evaluation_failed\":false,\"reason\":\"'\nhead -c 65537 /dev/zero | tr '\\000' x\nprintf '\"}'\n",
            ),
            false,
        ),
        (
            "stderr-limit",
            Some(
                "#!/bin/sh\nhead -c 65537 /dev/zero >&2\nprintf '{\"block\":true,\"evaluation_failed\":false,\"reason\":\"blocked\"}'\n",
            ),
            false,
        ),
        ("timeout", Some("#!/bin/sh\nsleep 1\n"), true),
        (
            "failed-delegate",
            Some(
                // It reads its input, as nah does, so the plugin's write
                // never meets a closed pipe.
                "#!/bin/sh\ncat >/dev/null\nprintf '{\"block\":false,\"evaluation_failed\":true,\"reason\":\"failure; run `nah why decision-1-2` for details\"}'\n",
            ),
            false,
        ),
    ];
    for (fail_closed, (name, program, shorten_timeout)) in [false, true]
        .into_iter()
        .flat_map(|fail_closed| cases.iter().map(move |case| (fail_closed, *case)))
    {
        // The previous case left a plugin install no longer owns.
        std::fs::remove_file(&plugin).unwrap();
        let mut install = vec!["hook", "opencode", "install"];
        if fail_closed {
            install.push("--fail-closed");
        }
        let installed = nah(home, &install);
        assert!(installed.status.success(), "{installed:?}");
        let original = std::fs::read_to_string(&plugin).unwrap();
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
        for reject_notice in [false, true] {
            let observed = run_plugin(
                home,
                &project,
                &plugin,
                "read",
                json!({"path":"src/lib.rs"}),
                reject_notice,
            );
            // Under fail-closed a hook that fails to answer blocks; under
            // fail-open it delegates, as in 1.x, and so does a failure nah
            // itself reports.
            if fail_closed && name != "failed-delegate" {
                assert_eq!(
                    observed["error"], "nah · evaluation was incomplete; this call was blocked",
                    "{name}: {observed}"
                );
                continue;
            }
            assert!(
                observed.get("error").is_none(),
                "notice failure must delegate: {fail_closed} {name}: {observed}"
            );
            let notices = observed["notices"].as_array().expect("failure notice");
            assert_eq!(notices.len(), 1, "{name}: {observed}");
            assert_eq!(notices[0]["sessionID"], "subagent-session");
            assert!(
                notices[0]["text"].as_str().unwrap().contains("nah why"),
                "{name}: {observed}"
            );
        }
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
