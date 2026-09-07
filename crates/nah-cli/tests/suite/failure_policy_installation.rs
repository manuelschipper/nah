#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
use std::path::Path;
use std::process::Command;

fn nah(
    home: &std::path::Path,
    runtime: &str,
    action: &str,
    flag: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command.args(["hook", runtime, action]);
    if let Some(flag) = flag {
        command.arg(flag);
    }
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CODEX_HOME")
        .env_remove("COPILOT_HOME")
        .env_remove("HERMES_HOME")
        .env_remove("KIRO_HOME")
        .env_remove("OPENCLAW_HOME")
        .env_remove("OPENCLAW_STATE_DIR")
        .env_remove("OPENCLAW_CONFIG_PATH")
        .env_remove("PRIME_AGENT_CODING_AGENT_DIR")
        .output()
        .unwrap()
}

#[test]
fn every_installer_selects_preserves_and_downgrades_failure_policy() {
    for runtime in [
        "amp",
        "antigravity",
        "claude",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "devin",
        "droid",
        "hermes",
        "kiro",
        "openclaw",
        "opencode",
        "pi",
        "prime-agent",
    ]
    .into_iter()
    .filter(installation_supported_on_host)
    {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".hermes")).unwrap();

        let default = nah(temp.path(), runtime, "install", None);
        assert!(default.status.success(), "{runtime}: {default:?}");
        let status = nah(temp.path(), runtime, "status", None);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-open"),
            "{runtime}: {status:?}"
        );

        let strict = nah(temp.path(), runtime, "install", Some("--fail-closed"));
        assert!(strict.status.success(), "{runtime}: {strict:?}");
        let status = nah(temp.path(), runtime, "status", None);
        assert!(status.status.success(), "{runtime}: {status:?}");
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-closed"),
            "{runtime}: {status:?}"
        );
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("guarantee:"),
            "{runtime}: {status:?}"
        );

        let preserved = nah(temp.path(), runtime, "install", None);
        assert!(preserved.status.success(), "{runtime}: {preserved:?}");
        let status = nah(temp.path(), runtime, "status", None);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-closed"),
            "{runtime}: {status:?}"
        );

        let downgraded = nah(temp.path(), runtime, "install", Some("--fail-open"));
        assert!(downgraded.status.success(), "{runtime}: {downgraded:?}");
        let status = nah(temp.path(), runtime, "status", None);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-open"),
            "{runtime}: {status:?}"
        );

        let removed = nah(temp.path(), runtime, "uninstall", None);
        assert!(removed.status.success(), "{runtime}: {removed:?}");
    }
}

#[test]
fn stale_strict_wiring_is_preserved_for_path_based_installers() {
    for runtime in [
        "amp",
        "antigravity",
        "claude",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "devin",
        "droid",
        "kiro",
        "openclaw",
        "opencode",
        "pi",
        "prime-agent",
    ]
    .into_iter()
    .filter(installation_supported_on_host)
    {
        let temp = tempfile::tempdir().unwrap();
        let strict = nah(temp.path(), runtime, "install", Some("--fail-closed"));
        assert!(strict.status.success(), "{runtime}: {strict:?}");
        let stale_executable = if cfg!(windows) {
            r"C:\old\nah.exe"
        } else {
            "/old/nah"
        };
        assert!(
            rewrite_executable(temp.path(), env!("CARGO_BIN_EXE_nah"), stale_executable) > 0,
            "{runtime}"
        );

        let stale = nah(temp.path(), runtime, "status", None);
        let stale_stdout = String::from_utf8_lossy(&stale.stdout);
        assert!(
            stale_stdout.contains("reinstall required"),
            "{runtime}: {stale:?}"
        );
        assert!(
            stale_stdout.contains("detected failure policy: fail-closed"),
            "{runtime}: {stale:?}"
        );
        assert!(stale_stdout.contains("guarantee:"), "{runtime}: {stale:?}");

        let preserved = nah(temp.path(), runtime, "install", None);
        assert!(preserved.status.success(), "{runtime}: {preserved:?}");
        let current = nah(temp.path(), runtime, "status", None);
        assert!(
            String::from_utf8_lossy(&current.stdout).contains("failure policy: fail-closed"),
            "{runtime}: {current:?}"
        );
    }
}

fn installation_supported_on_host(runtime: &&str) -> bool {
    !cfg!(windows) || !matches!(*runtime, "amp" | "droid" | "hermes" | "opencode")
}

fn rewrite_executable(directory: &Path, from: &str, to: &str) -> usize {
    let mut changed = 0;
    for entry in fs::read_dir(directory).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            changed += rewrite_executable(&path, from, to);
        } else if let Ok(contents) = fs::read_to_string(&path)
            && contents.contains(from)
        {
            fs::write(path, contents.replace(from, to)).unwrap();
            changed += 1;
        }
    }
    changed
}
