#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::Command;

use serde_json::Value;
use support::repo;

#[cfg(unix)]
#[test]
fn install_preserves_openclaw_config_and_unowned_files() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let state = home.join(".openclaw");
    let config = state.join("openclaw.json");
    let original_config =
        br#"{"plugins":{"allow":["provider"],"entries":{"other":{"enabled":false}}}}"#;
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(&config, original_config).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(args)
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("OPENCLAW_HOME")
            .env_remove("OPENCLAW_STATE_DIR")
            .env_remove("OPENCLAW_CONFIG_PATH")
            .env_remove("OPENCLAW_PROFILE")
            .output()
            .unwrap()
    };

    let installed = run(&["hook", "openclaw", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("Restart the OpenClaw Gateway"));
    assert_eq!(std::fs::read(&config).unwrap(), original_config);
    let plugin = home.join(".openclaw/extensions/nah");
    let module = std::fs::read_to_string(plugin.join("index.js")).unwrap();
    assert!(module.starts_with("// Managed by nah."));
    assert!(module.contains(r#"["hook", "openclaw", "run"]"#));
    assert!(module.contains(env!("CARGO_BIN_EXE_nah")));
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(plugin.join("package.json")).unwrap())
            .unwrap()["nah"]["managed"],
        true
    );
    let installed_again = run(&["hook", "openclaw", "install"]);
    assert!(installed_again.status.success(), "{installed_again:?}");

    std::fs::write(plugin.join("keep.txt"), "user").unwrap();
    let refused = run(&["hook", "openclaw", "uninstall"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("openclaw-plugin-not-owned"));
    assert!(plugin.exists());
    std::fs::remove_file(plugin.join("keep.txt")).unwrap();

    let uninstalled = run(&["hook", "openclaw", "uninstall"]);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert!(!plugin.exists());
    assert_eq!(std::fs::read(&config).unwrap(), original_config);
    assert!(run(&["hook", "openclaw", "uninstall"]).status.success());

    let outside = home.join("outside");
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, &plugin).unwrap();
    let symlinked = run(&["hook", "openclaw", "install"]);
    assert!(!symlinked.status.success());
    assert!(
        String::from_utf8_lossy(&symlinked.stderr).contains("openclaw-plugin-symlink-unsupported")
    );
    std::fs::remove_file(&plugin).unwrap();

    let custom = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "openclaw", "install"])
        .env("HOME", home)
        .env("OPENCLAW_STATE_DIR", home.join("other"))
        .output()
        .unwrap();
    assert!(!custom.status.success());
    assert!(String::from_utf8_lossy(&custom.stderr).contains("custom-openclaw-home-unsupported"));

    let legacy_home = tempfile::tempdir().unwrap();
    std::fs::create_dir(legacy_home.path().join(".clawdbot")).unwrap();
    let legacy = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "openclaw", "install"])
        .env("HOME", legacy_home.path())
        .env_remove("OPENCLAW_HOME")
        .env_remove("OPENCLAW_STATE_DIR")
        .env_remove("OPENCLAW_CONFIG_PATH")
        .env_remove("OPENCLAW_PROFILE")
        .output()
        .unwrap();
    assert!(!legacy.status.success());
    assert!(String::from_utf8_lossy(&legacy.stderr).contains("legacy-openclaw-state-unsupported"));
}

#[cfg(unix)]
#[test]
fn generated_plugin_maps_openclaw_hook_results() {
    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "openclaw", "install"])
        .env("HOME", home)
        .env_remove("OPENCLAW_HOME")
        .env_remove("OPENCLAW_STATE_DIR")
        .env_remove("OPENCLAW_CONFIG_PATH")
        .env_remove("OPENCLAW_PROFILE")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let sdk = home.join(".openclaw/node_modules/openclaw");
    std::fs::create_dir_all(&sdk).unwrap();
    std::fs::write(
        sdk.join("package.json"),
        r#"{"name":"openclaw","type":"module","exports":{"./plugin-sdk/plugin-entry":"./plugin-entry.js"}}"#,
    )
    .unwrap();
    std::fs::write(
        sdk.join("plugin-entry.js"),
        "export function definePluginEntry(entry) { return entry; }\n",
    )
    .unwrap();
    let module = home.join(".openclaw/extensions/nah/index.js");
    const HARNESS: &str = r#"
import { pathToFileURL } from "node:url";
const plugin = await import(pathToFileURL(process.argv[1]));
let handler;
const api = {
  runtime: {
    agent: { resolveAgentWorkspaceDir() { return process.argv[2]; } },
    config: { current() { return {}; } },
  },
  on(name, callback) { if (name === "before_tool_call") handler = callback; },
};
plugin.default.register(api);
const result = await handler(
  { toolName: "read", params: { path: process.argv[3] } },
  { agentId: process.argv[4] === "missing" ? undefined : "main", sessionId: "session-1" },
);
process.stdout.write(JSON.stringify(result ?? null));
"#;
    for (path, mode, expected) in [
        ("src/lib.rs", "normal", "continue"),
        (".env", "normal", "block"),
        ("src/lib.rs", "missing", "unavailable"),
    ] {
        let output = Command::new("node")
            .args([
                "--input-type=module",
                "-e",
                HARNESS,
                module.to_str().unwrap(),
                project.to_str().unwrap(),
                path,
                mode,
            ])
            .env("HOME", home)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        if expected == "block" {
            assert_eq!(result["block"], true);
            assert!(
                result["blockReason"]
                    .as_str()
                    .unwrap()
                    .starts_with("nah - ")
            );
        } else {
            assert!(result.is_null());
        }
    }
}
