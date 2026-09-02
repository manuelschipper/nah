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
        (
            "git-remote-repo-delete",
            "gh repo delete owner/project --yes",
        ),
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
fn remote_repository_guard_alias_preserves_saved_choices_and_commands() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    std::fs::create_dir(temp.path().join(".nah")).unwrap();
    let state_path = temp.path().join(".nah/built-ins.json");
    std::fs::write(
        &state_path,
        "{\"v\":2,\"overrides\":{\"git-remote-delete\":false}}\n",
    )
    .unwrap();
    let command = "gh repo delete owner/project --yes";

    assert_eq!(
        decide(temp.path(), &project, command)["verdict"],
        "delegate"
    );

    let reset = nah(
        temp.path(),
        &project,
        &["guard", "reset", "git-remote-delete"],
        None,
    );
    assert!(reset.status.success(), "{reset:?}");
    assert_eq!(reset.stdout, b"reset guard git-remote-repo-delete\n");
    assert_eq!(decide(temp.path(), &project, command)["verdict"], "block");

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "git-remote-delete"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(disabled.stdout, b"disabled guard git-remote-repo-delete\n");
    assert_eq!(
        decide(temp.path(), &project, command)["verdict"],
        "delegate"
    );
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        saved["overrides"],
        serde_json::json!({"git-remote-repo-delete": false})
    );

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "git-remote-delete"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    assert_eq!(enabled.stdout, b"enabled guard git-remote-repo-delete\n");
    assert_eq!(decide(temp.path(), &project, command)["verdict"], "block");
}

#[test]
fn unknown_saved_names_preserve_valid_overrides_and_leave_on_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    std::fs::create_dir(temp.path().join(".nah")).unwrap();
    std::fs::write(
        temp.path().join(".nah/built-ins.json"),
        "{\"v\":2,\"overrides\":{\"git-hard-reset\":false,\"retired-guard\":false}}\n",
    )
    .unwrap();

    let payload = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "git reset --hard"},
        "cwd": project,
    })
    .to_string();
    let decided = nah(temp.path(), &project, &["decide"], Some(&payload));
    assert!(!decided.stderr.is_empty());
    let decision: serde_json::Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(decision["verdict"], "delegate");
    let guards = nah(temp.path(), &project, &["guards"], None);
    assert!(guards.status.success(), "{guards:?}");
    assert!(!guards.stderr.is_empty());
    let guards = String::from_utf8(guards.stdout).unwrap();
    let listed_names = guards
        .lines()
        .filter_map(|line| line.split_once("] ").map(|(_, name)| name))
        .collect::<Vec<_>>();
    let expected_names = include_str!("golden/guards.txt")
        .lines()
        .filter_map(|line| line.split_once("] ").map(|(_, name)| name))
        .collect::<Vec<_>>();
    assert_eq!(listed_names, expected_names);

    let reset = nah(
        temp.path(),
        &project,
        &["guard", "reset", "git-hard-reset"],
        None,
    );
    assert!(reset.status.success(), "{reset:?}");
    assert!(!reset.stderr.is_empty());
    let saved: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(temp.path().join(".nah/built-ins.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved["overrides"], serde_json::json!({}));
    assert_eq!(
        decide(temp.path(), &project, "git reset --hard")["verdict"],
        "block"
    );
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
fn infrastructure_destroy_is_factory_off_and_independently_configurable() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for command in [
        "terraform destroy",
        "terraform destroy -auto-approve",
        "pulumi destroy --yes --skip-preview",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "infra-iac-destroy"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    for command in ["tofu apply -destroy -auto-approve", "pulumi down -yf"] {
        let decision = decide(temp.path(), &project, command);
        assert_eq!(decision["verdict"], "block", "{command}");
        assert_eq!(
            decision["policy_attributions"][0]["name"], "infra-iac-destroy",
            "{command}"
        );
    }

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "infra-iac-destroy"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        decide(temp.path(), &project, "terraform destroy")["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, "git reset --hard")["policy_attributions"][0]["name"],
        "git-hard-reset"
    );
}

#[test]
fn kubernetes_delete_guard_is_factory_off_and_independently_configurable() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for command in [
        "kubectl delete namespace production",
        "kubectl delete pv old-data",
        "kubectl delete pods --all",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "infra-k8s-delete"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    for command in [
        "kubectl delete namespace production",
        "kubectl delete nodes worker-1",
        "kubectl delete deployments -l preview=true",
    ] {
        let decision = decide(temp.path(), &project, command);
        assert_eq!(decision["verdict"], "block", "{command}");
        assert_eq!(
            decision["policy_attributions"][0]["name"], "infra-k8s-delete",
            "{command}"
        );
    }
    for command in [
        "kubectl delete pod api",
        "kubectl delete deployment/web",
        "kubectl delete namespace production --dry-run=server",
        "kubectl delete -f namespace.yaml",
        "kubectl get pods --all-namespaces",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "infra-k8s-delete"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        decide(temp.path(), &project, "kubectl delete namespace production")["verdict"],
        "delegate"
    );
}

#[test]
fn container_reset_and_prune_keep_independent_factory_postures() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for command in ["podman system reset", "podman system reset --force"] {
        let decision = decide(temp.path(), &project, command);
        assert_eq!(decision["verdict"], "block", "{command}");
        assert_eq!(
            decision["policy_attributions"][0]["name"], "infra-container-reset",
            "{command}"
        );
    }
    for command in [
        "docker volume prune --all",
        "docker system prune --volumes",
        "podman volume prune --all",
        "podman system prune --volumes",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "infra-container-prune"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    for command in [
        "docker volume prune --all --force",
        "docker system prune --volumes --force=false",
        "podman volume prune --all -f",
        "podman system prune --volumes",
    ] {
        let decision = decide(temp.path(), &project, command);
        assert_eq!(decision["verdict"], "block", "{command}");
        assert_eq!(
            decision["policy_attributions"][0]["name"], "infra-container-prune",
            "{command}"
        );
    }
    for command in [
        "docker volume prune",
        "docker system prune",
        "podman volume prune --all --dry-run",
        "podman system prune --volumes --filter label=temporary",
        "podman machine reset --force",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "infra-container-reset"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        decide(temp.path(), &project, "podman system reset")["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, "docker volume prune --all")["policy_attributions"][0]["name"],
        "infra-container-prune"
    );
}

#[test]
fn storage_guards_keep_independent_factory_and_project_postures() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    let destroy = decide(temp.path(), &project, "borg delete /srv/backups/repo");
    assert_eq!(destroy["verdict"], "block");
    assert_eq!(destroy["policy_attributions"][0]["name"], "storage-destroy");
    for command in [
        "rclone sync . remote:mirror",
        "restic forget --keep-daily 7 --prune",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "storage-recursive-delete"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    let recursive = decide(temp.path(), &project, "rclone sync . remote:mirror");
    assert_eq!(recursive["verdict"], "block");
    assert_eq!(
        recursive["policy_attributions"][0]["name"],
        "storage-recursive-delete"
    );
    assert_eq!(
        decide(
            temp.path(),
            &project,
            "restic forget --keep-daily 7 --prune"
        )["verdict"],
        "delegate"
    );

    let enabled = nah(
        temp.path(),
        &project,
        &["guard", "enable", "storage-snapshot-delete"],
        None,
    );
    assert!(enabled.status.success(), "{enabled:?}");
    let snapshot = decide(temp.path(), &project, "zfs destroy tank/data@snap");
    assert_eq!(snapshot["verdict"], "block");
    assert_eq!(
        snapshot["policy_attributions"][0]["name"],
        "storage-snapshot-delete"
    );

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "storage-destroy"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        decide(temp.path(), &project, "borg delete /srv/backups/repo")["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, "aws s3 rm s3://bucket --recursive")["policy_attributions"]
            [0]["name"],
        "storage-recursive-delete"
    );
    assert_eq!(
        decide(temp.path(), &project, "restic forget abc123")["policy_attributions"][0]["name"],
        "storage-snapshot-delete"
    );
}

#[test]
fn project_can_enable_the_factory_off_infrastructure_guard() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    std::fs::create_dir(project.join(".nah")).unwrap();
    std::fs::write(
        project.join(".nah/project.toml"),
        "enable-guards = [\"infra-iac-destroy\"]\n",
    )
    .unwrap();

    assert_eq!(
        decide(temp.path(), &project, "terraform destroy")["policy_attributions"][0]["name"],
        "infra-iac-destroy"
    );
    assert_eq!(
        decide(
            temp.path(),
            &project,
            "terraform destroy -target module.web"
        )["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, "pulumi destroy --preview-only")["verdict"],
        "delegate"
    );
}

#[test]
fn registry_guards_keep_independent_factory_and_project_postures() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for command in [
        "npm unpublish left-pad@1.3.0",
        "gem yank rack -v 3.0.0",
        "npm owner rm mallory left-pad",
    ] {
        let decision = decide(temp.path(), &project, command);
        assert_eq!(decision["verdict"], "block", "{command}");
        assert_eq!(
            decision["policy_attributions"][0]["name"], "registry-unpublish",
            "{command}"
        );
    }
    for command in [
        "npm publish",
        "cargo publish",
        "twine upload dist/*",
        "gem push pkg.gem",
    ] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    std::fs::create_dir(project.join(".nah")).unwrap();
    std::fs::write(
        project.join(".nah/project.toml"),
        "enable-guards = [\"registry-publish\"]\n",
    )
    .unwrap();
    for command in [
        "npm publish",
        "cargo publish",
        "twine upload dist/*",
        "gem push pkg.gem",
    ] {
        let decision = decide(temp.path(), &project, command);
        assert_eq!(decision["verdict"], "block", "{command}");
        assert_eq!(
            decision["policy_attributions"][0]["name"], "registry-publish",
            "{command}"
        );
    }
    for command in ["npm publish --dry-run", "npm pack", "cargo package"] {
        assert_eq!(
            decide(temp.path(), &project, command)["verdict"],
            "delegate",
            "{command}"
        );
    }

    let disabled = nah(
        temp.path(),
        &project,
        &["guard", "disable", "registry-unpublish"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        decide(temp.path(), &project, "npm unpublish left-pad")["verdict"],
        "delegate"
    );
    assert_eq!(
        decide(temp.path(), &project, "npm publish")["policy_attributions"][0]["name"],
        "registry-publish"
    );
}

#[test]
fn test_command_is_a_human_dry_run_and_does_not_write_an_audit_record() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "echo hello"], None);

    assert!(output.status.success(), "{output:?}");
    // The decision reports the host-resolved path, including macOS symlinks
    // and Windows short names, so redact either form nah may print.
    let printed = [support::test_temp_path(&project), project]
        .map(|path| serde_json::to_string(path.to_str().unwrap()).unwrap());
    let stdout = printed
        .iter()
        .fold(String::from_utf8(output.stdout).unwrap(), |stdout, path| {
            stdout.replace(path.trim_matches('"'), "<project>")
        });
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
