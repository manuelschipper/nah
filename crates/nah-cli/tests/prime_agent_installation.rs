#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

fn nah(
    home: &std::path::Path,
    args: &[&str],
    agent_dir: Option<&std::path::Path>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PRIME_AGENT_CODING_AGENT_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(agent_dir) = agent_dir {
        command.env("PRIME_AGENT_CODING_AGENT_DIR", agent_dir);
    }
    command.output().unwrap()
}

#[test]
fn install_runs_the_extension_and_uninstall_removes_only_owned_wiring() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let project = repo(&home);

    let installed = nah(&home, &["hook", "prime-agent", "install"], None);
    assert!(installed.status.success(), "{installed:?}");
    assert!(String::from_utf8_lossy(&installed.stdout).contains("/reload"));
    let extension = home.join(".prime/agent/extensions/nah.js");
    let first_bytes = std::fs::read(&extension).unwrap();
    let source = String::from_utf8(first_bytes.clone()).unwrap();
    assert!(source.starts_with("// Managed by nah."));
    assert!(source.contains(r#"["hook", "prime-agent", "run"]"#));
    assert!(source.contains(env!("CARGO_BIN_EXE_nah")));

    let installed_again = nah(&home, &["hook", "prime-agent", "install"], None);
    assert!(installed_again.status.success(), "{installed_again:?}");
    assert_eq!(std::fs::read(&extension).unwrap(), first_bytes);

    if Command::new("node").arg("--version").output().is_ok() {
        assert_eq!(
            run_extension(
                &home,
                &project,
                &extension,
                "ipython",
                json!({"code":"print('ok')"}),
                true,
            ),
            Value::Null
        );
        let blocked = run_extension(
            &home,
            &project,
            &extension,
            "ipython",
            json!({"code":"import shutil; shutil.rmtree('/')"}),
            true,
        );
        assert_eq!(blocked["block"], true);
        assert!(blocked["reason"].as_str().unwrap().starts_with("nah - "));
        assert_eq!(
            run_extension(
                &home,
                &project,
                &extension,
                "ipython",
                json!({"code":"import shutil; shutil.rmtree('/')"}),
                false,
            ),
            Value::Null
        );
    }

    let sibling = extension.parent().unwrap().join("notes.txt");
    std::fs::write(&sibling, "operator-owned\n").unwrap();
    let uninstalled = nah(&home, &["hook", "prime-agent", "uninstall"], None);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert!(!extension.exists());
    assert_eq!(
        std::fs::read_to_string(&sibling).unwrap(),
        "operator-owned\n"
    );
    let uninstalled_again = nah(&home, &["hook", "prime-agent", "uninstall"], None);
    assert!(uninstalled_again.status.success(), "{uninstalled_again:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let installed = nah(&home, &["hook", "prime-agent", "install"], None);
        assert!(installed.status.success(), "{installed:?}");
        assert_eq!(
            std::fs::metadata(&extension).unwrap().permissions().mode() & 0o777,
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
    builtin: bool,
) -> Value {
    const HARNESS: &str = r#"
const factory = require(process.argv[1]);
let handler;
factory({
  on(event, callback) { if (event === "tool_call") handler = callback; },
  getAllTools() {
    return [{
      name: process.argv[3],
      sourceInfo: process.argv[5] === "builtin"
        ? { source: "builtin", path: "<builtin:ipython>" }
        : { source: "local", path: "/repo/.prime/agent/extensions/override.ts" },
    }];
  },
});
Promise.resolve(handler(
  { toolName: process.argv[3], input: JSON.parse(process.argv[4]), toolCallId: "call-1" },
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
            if builtin { "builtin" } else { "local" },
        ])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PRIME_AGENT_CODING_AGENT_DIR")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn custom_agent_directory_is_used_and_relative_values_are_rejected() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let agent_dir = home.join("profiles/prime");

    let installed = nah(&home, &["hook", "prime-agent", "install"], Some(&agent_dir));
    assert!(installed.status.success(), "{installed:?}");
    let extension = agent_dir.join("extensions/nah.js");
    assert!(extension.exists());
    assert!(!home.join(".prime/agent/extensions/nah.js").exists());

    let status = nah(&home, &["hook", "prime-agent", "status"], Some(&agent_dir));
    assert!(status.status.success(), "{status:?}");
    assert!(String::from_utf8_lossy(&status.stdout).contains("wiring current"));

    let invalid = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "prime-agent", "install"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env("PRIME_AGENT_CODING_AGENT_DIR", "relative/agent")
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("prime-agent-dir-not-absolute"));
}

#[test]
fn direct_extension_file_is_not_shadowed_by_a_same_named_directory() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let shadow = home.join(".prime/agent/extensions/nah/index.ts");
    std::fs::create_dir_all(shadow.parent().unwrap()).unwrap();
    std::fs::write(&shadow, "export default () => {};\n").unwrap();

    let installed = nah(&home, &["hook", "prime-agent", "install"], None);
    assert!(installed.status.success(), "{installed:?}");
    let extension = home.join(".prime/agent/extensions/nah.js");
    assert!(extension.exists());

    let status = nah(&home, &["hook", "prime-agent", "status"], None);
    assert!(status.status.success(), "{status:?}");
    assert!(String::from_utf8_lossy(&status.stdout).contains("wiring current"));

    let uninstalled = nah(&home, &["hook", "prime-agent", "uninstall"], None);
    assert!(uninstalled.status.success(), "{uninstalled:?}");
    assert!(!extension.exists());
    assert_eq!(
        std::fs::read_to_string(shadow).unwrap(),
        "export default () => {};\n"
    );
}

#[test]
fn fail_closed_wiring_blocks_adapter_unavailability_in_the_extension() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let extension = home.join(".prime/agent/extensions/nah.js");

    let installed = nah(&home, &["hook", "prime-agent", "install"], None);
    assert!(installed.status.success(), "{installed:?}");
    let delegate = std::fs::read_to_string(&extension).unwrap();
    assert!(delegate.contains("return undefined;"));
    assert!(delegate.contains("this call was delegated to the runtime"));
    assert!(!delegate.contains("required safety evaluation was unavailable"));

    let installed = nah(
        &home,
        &["hook", "prime-agent", "install", "--fail-closed"],
        None,
    );
    assert!(installed.status.success(), "{installed:?}");
    let strict = std::fs::read_to_string(&extension).unwrap();
    assert!(strict.contains(r#"["hook", "prime-agent", "run", "--fail-closed"]"#));
    assert!(strict.contains("return { block: true, reason: adapterFailureMessage };"));
    assert!(strict.contains("required safety evaluation was unavailable"));
    assert!(!strict.contains("return undefined;"));
}

#[test]
fn install_and_uninstall_refuse_an_unowned_extension() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let extension = home.join(".prime/agent/extensions/nah.js");
    std::fs::create_dir_all(extension.parent().unwrap()).unwrap();
    std::fs::write(&extension, "module.exports = () => {};\n").unwrap();

    for action in ["install", "uninstall"] {
        let output = nah(&home, &["hook", "prime-agent", action], None);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("prime-agent-extension-not-owned")
        );
    }
    assert_eq!(
        std::fs::read_to_string(extension).unwrap(),
        "module.exports = () => {};\n"
    );
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_extension_paths() {
    use std::os::unix::fs::symlink;

    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let extension_directory = home.join(".prime/agent/extensions");
    let target_directory = home.join("extensions-target");
    std::fs::create_dir_all(home.join(".prime/agent")).unwrap();
    std::fs::create_dir(&target_directory).unwrap();
    symlink(&target_directory, &extension_directory).unwrap();

    let output = nah(&home, &["hook", "prime-agent", "install"], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("prime-agent-extension-symlink-unsupported")
    );
    assert!(
        std::fs::read_dir(&target_directory)
            .unwrap()
            .next()
            .is_none()
    );
}
