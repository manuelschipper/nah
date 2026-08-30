#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use support::{bash_path, repo};

fn nah(
    home: &std::path::Path,
    cwd: &std::path::Path,
    args: &[&str],
    stdin: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn decide(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> serde_json::Value {
    let payload = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": command},
        "cwd": cwd,
    })
    .to_string();
    let output = nah(home, cwd, &["decide"], Some(&payload));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn shipped_catalog_lists_docs_and_persists_guard_enablement() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    let guards = nah(temp.path(), &project, &["guards"], None);
    assert!(guards.status.success(), "{guards:?}");
    let guards = String::from_utf8(guards.stdout).unwrap();
    assert_eq!(guards, include_str!("golden/guards.txt"));

    let docs = nah(temp.path(), &project, &["docs", "guards"], None);
    assert!(docs.status.success(), "{docs:?}");
    let docs = String::from_utf8(docs.stdout).unwrap();
    assert!(docs.contains("# git-hard-reset\n\nStatus: enabled"));
    assert!(docs.contains("# fs-shell-profile\n\nStatus: disabled\n\nDefault: disabled"));
    assert!(docs.contains("# git-clean-force\n\nStatus: enabled"));
    assert!(docs.contains("# git-worktree-discard\n\nStatus: enabled"));
    assert!(
        docs.contains(
            "Examples nah blocks:\n\n- `git reset --hard`\n- `git reset --hard HEAD~1`\n"
        )
    );
    assert!(!docs.contains("Kind: guard"));
    assert!(docs.contains("If disabled, matching calls are no longer blocked"));
    assert!(!docs.contains("approval prompt"));

    for (guard, command) in [
        ("git-clean-force", "git clean -f"),
        ("git-remote-delete", "gh repo delete owner/project --yes"),
        ("git-worktree-discard", "git restore ."),
    ] {
        assert_eq!(decide(temp.path(), &project, command)["verdict"], "block");
        let disabled = nah(temp.path(), &project, &["guard", "disable", guard], None);
        assert!(disabled.status.success(), "{disabled:?}");
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate"
        );
        let enabled = nah(temp.path(), &project, &["guard", "enable", guard], None);
        assert!(enabled.status.success(), "{enabled:?}");
        assert_eq!(decide(temp.path(), &project, command)["verdict"], "block");
    }

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "git-hard-reset"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(disabled.stdout, b"disabled guard git-hard-reset\n");
    assert_eq!(
        decide(temp.path(), &project, "git reset --hard")["verdict"],
        "delegate"
    );
    let guards = nah(temp.path(), &project, &["guards"], None);
    assert!(
        String::from_utf8(guards.stdout)
            .unwrap()
            .contains("- [ ] git-hard-reset")
    );
    let docs = nah(temp.path(), &project, &["docs", "guards"], None);
    assert!(
        String::from_utf8(docs.stdout)
            .unwrap()
            .contains("# git-hard-reset\n\nStatus: disabled")
    );

    let removed = nah(temp.path(), &project, &["guards", "--docs"], None);
    assert_eq!(removed.status.code(), Some(4), "{removed:?}");

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "git-hard-reset"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    assert_eq!(enabled.stdout, b"enabled guard git-hard-reset\n");
    assert_eq!(
        decide(temp.path(), &project, "git reset --hard")["verdict"],
        "block"
    );

    // An ordinary command is never approved by nah, only left to the runtime.
    assert_eq!(
        decide(temp.path(), &project, "echo hello")["verdict"],
        "delegate"
    );

    let retired = nah(
        temp.path(),
        &project,
        &["guard", "disable", "project-read"],
        None,
    );
    assert_eq!(retired.status.code(), Some(2));
    let error = String::from_utf8_lossy(&retired.stderr);
    assert!(error.contains("guard `project-read` was not found"));
    assert!(error.contains("run `nah guards` to list available guards"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = temp.path().join(".nah/built-ins.json");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn explicit_global_disable_beats_a_project_enablement() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let profile = temp.path().join(".bashrc");
    let command = format!("printf x > {}", bash_path(&profile));

    assert_eq!(
        decide(temp.path(), &project, &command)["verdict"],
        "delegate"
    );
    std::fs::create_dir(project.join(".nah")).unwrap();
    std::fs::write(
        project.join(".nah/project.toml"),
        "enable-guards = [\"fs-shell-profile\"]\n",
    )
    .unwrap();
    assert_eq!(decide(temp.path(), &project, &command)["verdict"], "block");

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "fs-shell-profile"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        decide(temp.path(), &project, &command)["verdict"],
        "delegate"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".nah/built-ins.json")).unwrap(),
        "{\"v\":2,\"overrides\":{\"fs-shell-profile\":false}}\n"
    );
}

#[test]
fn disabling_startup_persistence_leaves_other_guards_enabled() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let persistence = temp.path().join(".ssh/rc");
    let command = format!("printf x > {}", bash_path(&persistence));

    assert_eq!(decide(temp.path(), &project, &command)["verdict"], "block");
    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "fs-startup-persistence"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".nah/built-ins.json")).unwrap(),
        "{\"v\":2,\"overrides\":{\"fs-startup-persistence\":false}}\n"
    );
    assert_eq!(
        decide(temp.path(), &project, &command)["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(
            temp.path(),
            &project,
            &format!(
                "printf x > {}",
                bash_path(&temp.path().join(".ssh/authorized_keys"))
            )
        )["policy_attributions"][0]["name"],
        "fs-auth-identity"
    );
    assert_eq!(
        decide(temp.path(), &project, "git reset --hard")["policy_attributions"][0]["name"],
        "git-hard-reset"
    );

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "fs-startup-persistence"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".nah/built-ins.json")).unwrap(),
        "{\"v\":2,\"overrides\":{}}\n"
    );
    assert_eq!(decide(temp.path(), &project, &command)["verdict"], "block");
}

#[cfg(not(windows))]
#[test]
fn startup_management_is_factory_off_and_independent() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let management = if cfg!(target_os = "macos") {
        "launchctl enable system/com.example.backup"
    } else {
        "systemctl enable backup.service"
    };
    let persistence = format!("printf x > {}", bash_path(&temp.path().join(".ssh/rc")));

    assert_eq!(
        decide(temp.path(), &project, management)["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, &persistence)["policy_attributions"][0]["name"],
        "fs-startup-persistence"
    );

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "fs-startup-management"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    assert_eq!(
        decide(temp.path(), &project, management)["policy_attributions"][0]["name"],
        "fs-startup-management"
    );

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "fs-startup-management"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".nah/built-ins.json")).unwrap(),
        "{\"v\":2,\"overrides\":{\"fs-startup-management\":false}}\n"
    );
    assert_eq!(
        decide(temp.path(), &project, management)["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, &persistence)["policy_attributions"][0]["name"],
        "fs-startup-persistence"
    );
}

#[test]
fn test_command_is_a_human_dry_run_and_does_not_write_an_audit_record() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "echo hello"], None);

    assert!(output.status.success(), "{output:?}");
    // macOS temp directories sit under a symlinked /var, and the decision
    // reports the resolved path, so redact the one nah printed
    let printed = std::fs::canonicalize(&project).unwrap();
    let stdout = String::from_utf8(output.stdout)
        .unwrap()
        .replace(printed.to_str().unwrap(), "<project>");
    assert_eq!(stdout, include_str!("golden/test-echo.txt"));
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}

#[test]
fn test_command_returns_success_after_a_blocked_dry_run() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "rm -rf /"], None);

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("verdict: block\n")
    );
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}
