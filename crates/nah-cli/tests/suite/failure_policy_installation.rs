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
        .env_remove("HERMES_HOME")
        .env_remove("OPENCLAW_HOME")
        .env_remove("OPENCLAW_STATE_DIR")
        .env_remove("OPENCLAW_CONFIG_PATH");
    if action == "uninstall" || flag == Some("--fail-open") {
        crate::support::operator_output(&mut command)
    } else {
        command.output().unwrap()
    }
}

#[test]
fn every_installer_selects_preserves_and_downgrades_failure_policy() {
    for runtime in [
        "antigravity",
        "claude",
        "codex",
        "cursor",
        "hermes",
        "openclaw",
        "opencode",
        "pi",
    ]
    .into_iter()
    .filter(installation_supported_on_host)
    {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".hermes")).unwrap();

        // Install states the policy it wrote and what it means for an
        // unanswered hook, including when reinstalling keeps it.
        let installed_policy = |output: &std::process::Output, policy: &str| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains(&format!("failure policy: {policy}\nguarantee: ")),
                "{runtime}: {stdout}"
            );
            assert_eq!(
                stdout.contains("a discard may run without a fresh save"),
                policy == "fail-open",
                "{runtime}: {stdout}"
            );
        };
        let default = nah(temp.path(), runtime, "install", None);
        assert!(default.status.success(), "{runtime}: {default:?}");
        installed_policy(&default, "fail-open");
        let status = nah(temp.path(), runtime, "status", None);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-open"),
            "{runtime}: {status:?}"
        );

        let strict = nah(temp.path(), runtime, "install", Some("--fail-closed"));
        assert!(strict.status.success(), "{runtime}: {strict:?}");
        installed_policy(&strict, "fail-closed");
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
        installed_policy(&preserved, "fail-closed");
        let status = nah(temp.path(), runtime, "status", None);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-closed"),
            "{runtime}: {status:?}"
        );

        for action in [vec!["install", "--fail-open"], vec!["uninstall"]] {
            let refused = Command::new(env!("CARGO_BIN_EXE_nah"))
                .args(["hook", runtime])
                .args(action)
                .env("HOME", temp.path())
                .env("USERPROFILE", temp.path())
                .env_remove("XDG_CONFIG_HOME")
                .output()
                .unwrap();
            assert_eq!(refused.status.code(), Some(4), "{runtime}: {refused:?}");
            let status = nah(temp.path(), runtime, "status", None);
            assert!(
                String::from_utf8_lossy(&status.stdout).contains("failure policy: fail-closed"),
                "{runtime}: {status:?}"
            );
        }

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
        "antigravity",
        "claude",
        "codex",
        "cursor",
        "hermes",
        "openclaw",
        "opencode",
        "pi",
    ]
    .into_iter()
    .filter(installation_supported_on_host)
    {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".hermes")).unwrap();
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
    !cfg!(windows) || !matches!(*runtime, "hermes" | "opencode")
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
