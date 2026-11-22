#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use support::{bash_path, nah, repo};

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

fn rules(decision: &serde_json::Value) -> Vec<&str> {
    decision["policy_attributions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|guard| guard["name"].as_str().unwrap())
        .collect()
}

fn saved(home: &std::path::Path) -> String {
    std::fs::read_to_string(home.join(".nah/built-ins.json")).unwrap()
}

#[test]
fn shipped_catalog_lists_docs_and_persists_guard_settings() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let home = support::test_temp_path(temp.path());
    let project = support::repo_with_work(&home);

    let guards = nah(&home, &project, &["guards"], None);
    assert!(guards.status.success(), "{guards:?}");
    let guards = String::from_utf8(guards.stdout).unwrap();
    assert_eq!(guards, include_str!("../golden/guards.txt"));

    let docs = nah(&home, &project, &["docs", "guards"], None);
    assert!(docs.status.success(), "{docs:?}");
    let docs = String::from_utf8(docs.stdout).unwrap();
    assert!(docs.contains("# work: core\n"));
    assert!(docs.contains("## work/changes-discard\n\nStatus: on"));
    assert!(docs.contains("## persistence/shell-profile-write\n\nStatus: off"));
    assert!(
        docs.contains(
            "Examples nah blocks:\n\n- `git reset --hard`\n- `git reset --hard HEAD~1`\n"
        )
    );
    assert!(docs.contains("If disabled, matching calls are no longer blocked"));
    assert!(!docs.contains("approval prompt"));

    // A rule override turns one rule off and back.
    for (rule, command) in [
        ("work/untracked-clean", "git clean -f"),
        (
            "infrastructure/vault-secret-delete",
            "vault kv destroy -versions=2 secret/api",
        ),
        (
            "remote-code/repo-delete",
            "gh repo delete owner/project --yes",
        ),
        ("work/changes-discard", "git restore ."),
    ] {
        assert_eq!(
            rules(&decide(&home, &project, command)),
            [rule],
            "{command}"
        );
        let disabled = nah(&home, &project, &["rule", "disable", rule], None);
        assert!(disabled.status.success(), "{disabled:?}");
        assert_eq!(disabled.stdout, format!("disabled {rule}\n").as_bytes());
        assert_eq!(
            decide(&home, &project, command)["verdict"],
            "delegate",
            "{command}"
        );
        let reset = nah(&home, &project, &["rule", "reset", rule], None);
        assert!(reset.status.success(), "{reset:?}");
        assert_eq!(
            decide(&home, &project, command)["verdict"],
            "block",
            "{command}"
        );
    }
    assert_eq!(saved(&home), "{\"v\":3,\"guards\":{},\"rules\":{}}\n");

    // A guard's setting decides which parts run; an override beats it.
    let delete = "vault kv delete secret/api";
    let destroy = "vault kv destroy -versions=2 secret/api";
    for (args, delete_blocks, destroy_blocks) in [
        (vec!["guard", "set", "infrastructure", "strict"], true, true),
        (vec!["guard", "set", "infrastructure", "off"], false, false),
        (
            vec!["rule", "enable", "infrastructure/vault-secret-delete"],
            true,
            true,
        ),
        (
            vec!["rule", "reset", "infrastructure/vault-secret-delete"],
            false,
            false,
        ),
        (vec!["guard", "reset", "infrastructure"], false, true),
    ] {
        let output = nah(&home, &project, &args, None);
        assert!(output.status.success(), "{args:?}: {output:?}");
        for (command, blocks) in [(delete, delete_blocks), (destroy, destroy_blocks)] {
            assert_eq!(
                decide(&home, &project, command)["verdict"],
                if blocks { "block" } else { "delegate" },
                "{args:?}: {command}"
            );
        }
    }
    let set = nah(&home, &project, &["guard", "set", "work", "strict"], None);
    assert_eq!(set.stdout, b"set guard work to strict\n");
    let disabled = nah(
        &home,
        &project,
        &["rule", "disable", "work/changes-discard"],
        None,
    );
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(
        saved(&home),
        "{\"v\":3,\"guards\":{\"work\":\"strict\"},\"rules\":{\"work/changes-discard\":\"disabled\"}}\n"
    );
    assert_eq!(
        decide(&home, &project, "git reset --hard")["verdict"],
        "delegate"
    );
    let guards = String::from_utf8(nah(&home, &project, &["guards"], None).stdout).unwrap();
    assert!(guards.contains("work: strict\n"), "{guards}");
    assert!(
        guards.contains("- [ ] work/changes-discard (disabled)\n"),
        "{guards}"
    );

    let removed = nah(&home, &project, &["guards", "--docs"], None);
    assert_eq!(removed.status.code(), Some(4), "{removed:?}");

    // An ordinary command is never approved by nah, only left to the runtime.
    assert_eq!(decide(&home, &project, "echo hello")["verdict"], "delegate");

    for (args, needle) in [
        (vec!["rule", "disable", "project-read"], "project-read"),
        (vec!["guard", "set", "self", "off"], "always on"),
        (vec!["guard", "set", "work", "loud"], "off, core, or strict"),
        // A 1.x name says which rule it became.
        (
            vec!["rule", "disable", "git-hard-reset"],
            "`git-hard-reset` is a nah 1.x guard; it is now `work/changes-discard`",
        ),
        (
            vec!["guard", "reset", "git-hard-reset"],
            "`git-hard-reset` is a nah 1.x guard; it is now `work/changes-discard`",
        ),
    ] {
        let refused = nah(&home, &project, &args, None);
        assert!(!refused.status.success(), "{args:?}: {refused:?}");
        let error = String::from_utf8_lossy(&refused.stderr);
        assert!(error.contains(needle), "{args:?}: {error}");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = &home.join(".nah/built-ins.json");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// The first command to load a 1.x settings file and nap converts them in
/// place, the file beside a byte-exact backup. A 1.x choice its rule cannot
/// carry keeps the rule blocking, and `nah guards` names it with the command
/// that changes it, the nap's as well as the settings'. When a command other
/// than a decision converted, the next decision records the import in the
/// audit log, once. An unknown rule in a current file is reported and
/// dropped by the next change, which keeps the valid overrides.
#[test]
fn a_1x_settings_file_converts_once_and_unknown_rules_are_reported() {
    let temp = tempfile::tempdir().unwrap();
    let project = support::repo_with_work(temp.path());
    let state = temp.path().join(".nah/built-ins.json");
    std::fs::create_dir(temp.path().join(".nah")).unwrap();
    let legacy = "{\"v\":2,\"overrides\":{\"git-hard-reset\":false}}\n";
    std::fs::write(&state, legacy).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    support::write_signed_nap(
        temp.path(),
        2,
        serde_json::json!({"guards": ["git-worktree-discard"]}),
        now,
        now + 600,
    );
    let settings_notice = "nah rule disable work/changes-discard";
    let nap_notice = "nah nap work/changes-discard";

    let listed = nah(temp.path(), &project, &["guards"], None);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains(settings_notice), "{listed:?}");
    assert!(stdout.contains(nap_notice), "{listed:?}");
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".nah/built-ins.json.1x")).unwrap(),
        legacy
    );
    assert_eq!(
        std::fs::read_to_string(&state).unwrap(),
        "{\"v\":3,\"guards\":{},\"rules\":{}}\n"
    );

    let payload = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "git reset --hard"},
        "cwd": project,
    })
    .to_string();
    let decided = nah(temp.path(), &project, &["decide"], Some(&payload));
    let stderr = String::from_utf8_lossy(&decided.stderr);
    assert!(
        stderr.contains("imported the nah 1.x configuration"),
        "{stderr}"
    );
    let decision: serde_json::Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(rules(&decision), ["work/changes-discard"]);
    let audit = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    assert!(audit.contains(settings_notice), "{audit}");
    assert!(audit.contains(nap_notice), "{audit}");
    let again = nah(temp.path(), &project, &["decide"], Some(&payload));
    assert!(
        !String::from_utf8_lossy(&again.stderr).contains("imported"),
        "{again:?}"
    );
    let audit = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    assert_eq!(audit.matches(settings_notice).count(), 1, "{audit}");
    let listed = nah(temp.path(), &project, &["guards"], None);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains(nap_notice),
        "{listed:?}"
    );

    std::fs::write(
        &state,
        "{\"v\":3,\"guards\":{},\"rules\":{\"retired/rule\":\"disabled\",\"work/changes-discard\":\"disabled\",\"work/untracked-clean\":\"disabled\"}}\n",
    )
    .unwrap();
    let decided = nah(temp.path(), &project, &["decide"], Some(&payload));
    assert!(
        String::from_utf8_lossy(&decided.stderr).contains("retired/rule"),
        "{decided:?}"
    );
    let decision: serde_json::Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(decision["verdict"], "delegate");
    let reset = nah(
        temp.path(),
        &project,
        &["rule", "reset", "work/changes-discard"],
        None,
    );
    assert!(reset.status.success(), "{reset:?}");
    assert_eq!(
        std::fs::read_to_string(&state).unwrap(),
        "{\"v\":3,\"guards\":{},\"rules\":{\"work/untracked-clean\":\"disabled\"}}\n"
    );
    assert_eq!(
        decide(temp.path(), &project, "git reset --hard")["verdict"],
        "block"
    );
}

/// A nah 1.x user's custom guards stop blocking in 2.0, so `nah guards` and
/// every hook install name them from `activations.json` alone, even when that
/// record cannot be read.
#[test]
fn custom_guards_nah_1x_ran_are_named_as_stopped() {
    let temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(temp.path());
    let project = support::repo_with_work(&home);
    std::fs::create_dir(home.join(".nah")).unwrap();
    // The shape nah 1.x writes: a project guard's `trusted_root` is `root:`
    // and the project's absolute path.
    let activation = |identity: serde_json::Value| {
        serde_json::json!({
            "projection": {
                "identity": identity,
                "bundle_hash": "a".repeat(64),
                "protocol": 2,
                "match_programs": ["deploy"]
            },
            "actor": "tester",
            "activated_unix_ms": 1
        })
    };
    let root = format!("root:{}", project.display());
    let records = serde_json::json!({"v": 1, "records": [
        activation(serde_json::json!({"scope": "user", "name": "corp"})),
        activation(serde_json::json!({"scope": "project", "trusted_root": root, "name": "deploy"})),
    ]});
    std::fs::write(home.join(".nah/activations.json"), records.to_string()).unwrap();
    let deploy = project.join(".nah").join("guards").join("deploy");

    let listed = nah(&home, &project, &["guards"], None);
    assert!(listed.status.success(), "{listed:?}");
    let listed = String::from_utf8(listed.stdout).unwrap();
    // The notice closes the catalog.
    assert!(
        listed.starts_with(include_str!("../golden/guards.txt")),
        "{listed}"
    );
    let installed = nah(&home, &project, &["hook", "claude", "install"], None);
    assert!(installed.status.success(), "{installed:?}");
    for output in [listed, String::from_utf8(installed.stderr).unwrap()] {
        assert!(output.contains("custom/corp"), "{output}");
        assert!(output.contains("custom/deploy"), "{output}");
        assert!(output.contains(&deploy.display().to_string()), "{output}");
    }

    std::fs::write(home.join(".nah/activations.json"), "not-json").unwrap();
    let listed = nah(&home, &project, &["guards"], None);
    let output = String::from_utf8(listed.stdout).unwrap();
    let activations = home.join(".nah").join("activations.json");
    assert!(
        output.contains(&activations.display().to_string()),
        "{output}"
    );

    std::fs::remove_file(&activations).unwrap();
    let listed = nah(&home, &project, &["guards"], None);
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap(),
        include_str!("../golden/guards.txt")
    );
}

/// Nah reads no project file: a `.nah/project.toml` that names a rule turns
/// nothing on. The first hook reply that shows the user a notice, or the
/// first `nah hook <runtime> status`, says once that the file is not read; a
/// dry run says nothing and claims nothing, and processes racing on the first
/// meeting tell it once between them.
#[test]
fn a_project_file_turns_nothing_on_and_is_told_once() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let command = format!("printf x > {}", bash_path(&temp.path().join(".bashrc")));
    let declare = |project: &std::path::Path| {
        std::fs::create_dir_all(project.join(".nah")).unwrap();
        std::fs::write(
            project.join(".nah/project.toml"),
            "enable-rules = [\"persistence/shell-profile-write\"]\n",
        )
        .unwrap();
    };
    let told = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stdout).contains("is not read")
            || String::from_utf8_lossy(&output.stderr).contains("is not read")
    };
    let hook = || {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/lib.rs"},
            "cwd": project,
            "session_id": "session-1",
        })
        .to_string();
        nah(
            temp.path(),
            &project,
            &["hook", "claude", "run"],
            Some(&payload),
        )
    };

    declare(&project);
    assert_eq!(
        decide(temp.path(), &project, &command)["verdict"],
        "delegate"
    );
    let dry = nah(temp.path(), &project, &["test", &command], None);
    assert!(dry.status.success(), "{dry:?}");
    assert!(!told(&dry), "{dry:?}");
    let first = hook();
    assert!(first.status.success(), "{first:?}");
    let reply: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert!(
        reply["systemMessage"]
            .as_str()
            .is_some_and(|message| message.contains("is not read")),
        "{reply}"
    );
    assert!(reply["hookSpecificOutput"]["permissionDecision"].is_null());
    let later = hook();
    assert!(later.status.success() && !told(&later), "{later:?}");
    let status = nah(temp.path(), &project, &["hook", "claude", "status"], None);
    assert!(status.status.success() && !told(&status), "{status:?}");

    let second = temp.path().join("second");
    std::fs::create_dir(&second).unwrap();
    let other = repo(&second);
    declare(&other);
    let racing = (0..8)
        .map(|_| {
            std::process::Command::new(env!("CARGO_BIN_EXE_nah"))
                .args(["hook", "claude", "status"])
                .current_dir(&other)
                .env("HOME", temp.path())
                .env("USERPROFILE", temp.path())
                .env_remove("XDG_CONFIG_HOME")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = racing
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert!(outputs.iter().all(|output| output.status.success()));
    assert_eq!(outputs.iter().filter(|output| told(output)).count(), 1);
}

/// A rule's strict part waits for strict or an `enabled` override, while its
/// core part blocks at the factory setting.
#[cfg(not(windows))]
#[test]
fn strict_parts_run_only_when_their_rule_reaches_strict() {
    let service_stop = if cfg!(target_os = "macos") {
        "launchctl stop com.example.backup"
    } else {
        "systemctl stop sshd"
    };
    for (guard, rule, strict, core) in [
        (
            "remote-code",
            "remote-code/repo-delete",
            "git push origin :old",
            "gh repo delete owner/project --yes",
        ),
        (
            "remote-code",
            "remote-code/package-unpublish",
            "cargo publish",
            "npm unpublish left-pad",
        ),
        (
            "machine",
            "machine/system-halt",
            service_stop,
            "shutdown -h now",
        ),
        (
            "infrastructure",
            "infrastructure/container-prune",
            "docker volume prune --all",
            "podman system reset",
        ),
        (
            "infrastructure",
            "infrastructure/cloud-storage-delete",
            "aws s3 rm s3://bucket --recursive",
            "borg delete /srv/backups/repo",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let project = repo(temp.path());
        assert_eq!(
            decide(temp.path(), &project, strict)["verdict"],
            "delegate",
            "{strict}"
        );
        assert_eq!(
            rules(&decide(temp.path(), &project, core)),
            [rule],
            "{core}"
        );
        for (raise, lower) in [
            (
                vec!["guard", "set", guard, "strict"],
                vec!["guard", "reset", guard],
            ),
            (vec!["rule", "enable", rule], vec!["rule", "reset", rule]),
        ] {
            assert!(nah(temp.path(), &project, &raise, None).status.success());
            assert_eq!(
                rules(&decide(temp.path(), &project, strict)),
                [rule],
                "{raise:?}: {strict}"
            );
            assert!(nah(temp.path(), &project, &lower, None).status.success());
        }
    }
}
