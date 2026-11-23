#![allow(clippy::disallowed_methods, clippy::disallowed_types)]
#![cfg(unix)]

//! Save-then-run in Claude Code: at `work` core a discard runs after a
//! snapshot the agent can undo, and what Nah cannot save blocks. Codex's
//! hook is proven in `codex_adapter`.

use crate::support::{self, git};

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// Stores the operator's `setting` in `home`: `strict` sets `work` strict,
/// `rule` enables `work/changes-discard` alone, `clean-rule`
/// `work/untracked-clean` alone, `core` restores the defaults, and `None`
/// leaves the settings as they are.
fn set_work(home: &Path, setting: Option<&str>) {
    // Nah reads only its own canonical spelling of the file.
    let settings = match setting {
        Some("strict") => r#"{"v":3,"guards":{"work":"strict"},"rules":{}}"#,
        Some("rule") => r#"{"v":3,"guards":{},"rules":{"work/changes-discard":"enabled"}}"#,
        Some("clean-rule") => r#"{"v":3,"guards":{},"rules":{"work/untracked-clean":"enabled"}}"#,
        Some(_) => {
            let _ = std::fs::remove_file(home.join(".nah/built-ins.json"));
            return;
        }
        None => return,
    };
    std::fs::create_dir_all(home.join(".nah")).unwrap();
    std::fs::write(home.join(".nah/built-ins.json"), format!("{settings}\n")).unwrap();
}

fn hook(home: &Path, setting: Option<&str>, event: Value) -> Output {
    hook_with(home, setting, &[], event)
}

/// `hook` with `env` added to the hook's environment.
fn hook_with(home: &Path, setting: Option<&str>, env: &[(&str, &OsStr)], event: Value) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(["hook", "claude", "run"])
        .envs(env.iter().copied())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_work(home, setting);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Claude Code's reply to a PreToolUse Bash call of `command` in `cwd`;
/// `Null` when the hook printed nothing.
fn bash(home: &Path, setting: Option<&str>, cwd: &Path, command: &str) -> Value {
    bash_with(home, setting, &[], cwd, command)
}

/// `bash` with `env` added to the hook's environment.
fn bash_with(
    home: &Path,
    setting: Option<&str>,
    env: &[(&str, &OsStr)],
    cwd: &Path,
    command: &str,
) -> Value {
    let output = hook_with(
        home,
        setting,
        env,
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": cwd,
            "session_id": "session-1",
        }),
    );
    assert!(output.status.success(), "{output:?}");
    if output.stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn denial(reply: &Value) -> Option<&str> {
    (reply["hookSpecificOutput"]["permissionDecision"] == "deny").then(|| {
        reply["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
    })
}

fn context(reply: &Value) -> &str {
    reply["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_else(|| panic!("no context for the agent in {reply}"))
}

/// The snapshot the latest decision in `home`'s audit log saved under
/// `rule`, or its only snapshot when `rule` is `None`, read from the
/// record's structured save rather than the note to the agent.
fn snapshot_id(home: &Path, rule: Option<&str>) -> String {
    let audit = std::fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
    let record: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    let saved = record["saved"]
        .as_array()
        .unwrap_or_else(|| panic!("no snapshot in {record}"));
    let matching = saved
        .iter()
        .filter(|saved| {
            rule.is_none_or(|rule| saved["rules"].as_array().unwrap().iter().any(|r| r == rule))
        })
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "{record}");
    matching[0]["snapshot"].as_str().unwrap().to_owned()
}

/// Asserts that `id`, the snapshot Nah named as the undo of `command` in
/// `project`, carries the naming record in its store and that `nah
/// snapshots` marks it with `command`, in its text and in `--json`.
fn assert_named_undo(home: &Path, project: &Path, id: &str, command: &str) {
    let named = std::fs::read_dir(home.join(".nah/snapshots"))
        .unwrap()
        .any(|store| {
            let snapshot = store.unwrap().path().join("snapshots").join(id);
            snapshot.join("named").exists()
        });
    assert!(named, "{id} holds no naming record");
    let listed = support::nah(home, project, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let entry = listed.as_array().unwrap().iter().find(|s| s["id"] == id);
    assert_eq!(
        entry.unwrap_or_else(|| panic!("{listed}"))["undo"]["command"],
        command,
        "{listed}"
    );
    let text = support::nah(home, project, &["snapshots"], None);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.lines()
            .any(|line| line.starts_with(id) && line.contains(command)),
        "{text}"
    );
}

/// Every file under `root` but `.git`, with its bytes.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name() == Some(".git".as_ref()) {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    files
}

#[test]
fn a_discard_runs_after_a_snapshot_the_agent_can_undo() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join(".gitignore"), "*.log\nlocal-data/\n").unwrap();
    std::fs::create_dir(repo.join("local-data")).unwrap();
    std::fs::write(repo.join("local-data/draft.txt"), "ignored draft\n").unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    std::fs::write(repo.join("src/staged.rs"), "pub fn staged() {}\n").unwrap();
    git(&repo, &["add", "src/staged.rs"]);
    std::fs::write(repo.join("notes.md"), "draft\n").unwrap();
    std::fs::write(repo.join("build.log"), "local log\n").unwrap();
    let before = tree(&repo);

    // At strict the rule blocks the reset as 1.x did, and so does the rule
    // enabled on its own; neither saves anything.
    for setting in [Some("strict"), Some("rule")] {
        let reply = bash(&home, setting, &repo, "git reset --hard");
        assert!(
            denial(&reply).unwrap().contains("work/changes-discard"),
            "{reply}"
        );
    }
    assert!(!home.join(".nah/snapshots").exists());
    // Strict also blocks a named-path discard, which 1.x shipped off.
    let reply = bash(&home, Some("strict"), &repo, "git checkout -- src/lib.rs");
    assert!(
        denial(&reply).unwrap().contains("work/changes-discard"),
        "{reply}"
    );
    // A runtime whose hook does not say where a command runs blocks at core
    // what 1.x blocked. Hermes's adapter protects its own home, so it gets one.
    std::fs::create_dir_all(home.join(".hermes")).unwrap();
    let hermes = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "hermes", "run"])
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HERMES_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(
                json!({
                    "hook_event_name": "pre_tool_call",
                    "tool_name": "terminal",
                    "tool_input": {"command": "git reset --hard"},
                    "cwd": repo,
                    "session_id": "session-1",
                })
                .to_string()
                .as_bytes(),
            )?;
            child.wait_with_output()
        })
        .unwrap();
    let reply: Value = serde_json::from_slice(&hermes.stdout).unwrap();
    assert_eq!(reply["decision"], "block", "{hermes:?}");
    assert!(
        reply["reason"]
            .as_str()
            .unwrap()
            .contains("work/changes-discard"),
        "{hermes:?}"
    );
    assert!(!home.join(".nah/snapshots").exists());

    let reply = bash(&home, Some("core"), &repo, "git reset --hard");
    assert!(denial(&reply).is_none(), "{reply}");
    assert!(reply["hookSpecificOutput"]["permissionDecision"].is_null());
    let note = context(&reply);
    assert!(note.contains("work/changes-discard"), "{note}");
    let reset = snapshot_id(&home, None);
    git(&repo, &["reset", "-q", "--hard"]);
    // The refresh after the reset leaves a newer rolling copy, which `nah
    // snapshots` lists first: only the undo Nah named is marked as one, with
    // the command it was saved before.
    let refreshed = hook(
        &home,
        Some("core"),
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git reset --hard"},
            "tool_response": {},
            "cwd": repo,
            "session_id": "session-1",
        }),
    );
    assert!(refreshed.status.success(), "{refreshed:?}");
    let listed = support::nah(&home, &repo, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_ne!(listed[0]["id"], reset, "{listed}");
    assert!(listed[0]["undo"].is_null(), "{listed}");
    let named = listed.as_array().unwrap().iter().find(|s| s["id"] == reset);
    assert_eq!(
        named.unwrap()["undo"]["command"],
        "git reset --hard",
        "{listed}"
    );
    let text = support::nah(&home, &repo, &["snapshots"], None);
    let text = String::from_utf8(text.stdout).unwrap();
    let marked = text
        .lines()
        .filter(|line| line.contains("git reset --hard"));
    assert!(
        marked.eq(text.lines().filter(|line| line.starts_with(&reset))),
        "{text}"
    );
    assert_named_undo(&home, &repo, &reset, "git reset --hard");
    // A store from before snapshots were named at their save records the
    // last undo Nah gave only as `promised`; it still lists as an undo.
    let store = std::fs::read_dir(home.join(".nah/snapshots"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(store.join("snapshots").join(&reset).join("named")).unwrap();
    let listed = support::nah(&home, &repo, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let named = listed.as_array().unwrap().iter().find(|s| s["id"] == reset);
    assert!(named.unwrap()["undo"].is_object(), "{listed}");

    // The clean deletes the ignored log and folder, which only this save
    // copies.
    let reply = bash(&home, Some("core"), &repo, "git clean -fdx");
    let note = context(&reply);
    assert!(note.contains("work/untracked-clean"), "{note}");
    let clean = snapshot_id(&home, None);
    // Saved with the ignored files only this save copies.
    assert_named_undo(&home, &repo, &clean, "git clean -fdx");
    git(&repo, &["clean", "-q", "-fdx"]);
    assert!(!repo.join("notes.md").exists());

    for id in [&clean, &reset] {
        let undone = support::nah(&home, &repo, &["undo", id], None);
        assert!(undone.status.success(), "{undone:?}");
    }
    assert_eq!(tree(&repo), before);
    // What each undo replaced was saved first, as the undo of that undo.
    let listed = support::nah(&home, &repo, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    for id in [&clean, &reset] {
        let undo = format!("nah undo {id}");
        assert!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .any(|snapshot| snapshot["undo"]["command"] == undo.as_str()),
            "{listed}"
        );
    }
    let staged = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&staged.stdout), "src/staged.rs\n");
}

/// The audit record of a saved discard holds the save as data, so neither a
/// file named like an undo command or with a newline in its name, nor a
/// project path with `;` and `(`, changes the rule, snapshot, root or undo
/// command `nah log` shows.
#[test]
fn a_saved_discard_is_recorded_with_its_snapshot_and_undo() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let project = home.join("project (demo); backup");
    std::fs::create_dir(&project).unwrap();
    let repo = support::repo(&project);
    let names = ["how to nah undo changes.md", "two\nlines.md"];
    for name in names {
        std::fs::write(repo.join(name), "first\n").unwrap();
    }
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-q",
            "-m",
            "notes",
        ],
    );
    for name in names {
        std::fs::write(repo.join(name), "edited\n").unwrap();
    }

    let reply = bash(&home, Some("core"), &repo, "git reset --hard");
    assert!(denial(&reply).is_none(), "{reply}");
    let audit = std::fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
    let record: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(record["core"]["verdict"], "delegate", "{record}");
    let saved = record["saved"].as_array().unwrap();
    assert_eq!(saved.len(), 1, "{record}");
    assert_eq!(
        saved[0]["rules"],
        json!(["work/changes-discard"]),
        "{record}"
    );
    assert_eq!(saved[0]["root"], repo.to_str().unwrap(), "{record}");
    let id = saved[0]["snapshot"].as_str().unwrap();
    let root = repo.display();
    assert!(
        context(&reply).contains(&format!("Undo with: nah undo {id} (run in {root})")),
        "{reply}"
    );

    let log = support::nah(&home, &repo, &["log", "-n", "1"], None);
    let log = String::from_utf8(log.stdout).unwrap();
    let field = |key: &str| {
        log.lines()
            .find_map(|line| line.trim_start().strip_prefix(key))
            .map(str::trim_start)
            .unwrap_or_else(|| panic!("no {key} in {log}"))
            .to_owned()
    };
    assert!(log.lines().next().unwrap().contains(" saved "), "{log}");
    assert!(field("saved:").contains("work/changes-discard"), "{log}");
    assert_eq!(field("in:"), repo.to_str().unwrap());
    assert_eq!(field("undo:"), format!("nah undo {id}"));

    // The recorded snapshot is the one that holds the discarded edit.
    git(&repo, &["reset", "-q", "--hard"]);
    let undone = support::nah(&home, &repo, &["undo", id], None);
    assert!(undone.status.success(), "{undone:?}");
    for name in names {
        assert_eq!(
            std::fs::read_to_string(repo.join(name)).unwrap(),
            "edited\n"
        );
    }
}

/// A call whose save fails in a later repository, here on its index lock,
/// blocks, and its record keeps the snapshot already saved of the earlier
/// one with the undo that restores it.
#[test]
fn a_save_that_fails_in_a_later_repository_keeps_the_earlier_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let [first, second] = ["a", "b"].map(|name| {
        let parent = home.join(name);
        std::fs::create_dir(&parent).unwrap();
        let repo = support::repo(&parent);
        std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
        repo
    });
    std::fs::write(second.join(".git/index.lock"), "").unwrap();

    let command = format!(
        "git -C '{}' reset --hard && git -C '{}' reset --hard",
        first.display(),
        second.display()
    );
    let reply = bash(&home, Some("core"), &home, &command);
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("index lock"), "{reason}");
    let audit = std::fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
    let record: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(record["core"]["verdict"], "block", "{record}");
    let saved = record["saved"].as_array().unwrap();
    assert_eq!(saved.len(), 1, "{record}");
    assert_eq!(saved[0]["root"], first.to_str().unwrap(), "{record}");
    let id = saved[0]["snapshot"].as_str().unwrap();
    let log = support::nah(&home, &home, &["log", "--blocked", "-n", "1"], None);
    let log = String::from_utf8(log.stdout).unwrap();
    assert!(
        log.lines()
            .any(|line| line.trim_start() == format!("undo:     nah undo {id}")),
        "{log}"
    );

    // The recorded snapshot holds the first repository's edit.
    git(&first, &["reset", "-q", "--hard"]);
    let undone = support::nah(&home, &first, &["undo", id], None);
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(
        std::fs::read_to_string(first.join("src/lib.rs")).unwrap(),
        "pub fn edited() {}\n"
    );
}

/// Every entry under `root` but `.git`: a file's mode and bytes, or a link's
/// target with mode 0.
fn entries(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    use std::os::unix::fs::PermissionsExt;
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if path.file_name() == Some(".git".as_ref()) {
                continue;
            } else if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                found.insert(relative, (0, target.into_os_string().into_encoded_bytes()));
            } else if metadata.is_dir() {
                pending.push(path);
            } else {
                let mode = metadata.permissions().mode() & 0o777;
                found.insert(relative, (mode, std::fs::read(&path).unwrap()));
            }
        }
    }
    found
}

/// Writes work Git cannot restore under `src`: an executable, files with
/// permissions Git does not keep, a link, an ignored log, and, in a Git
/// work tree, a changed and a staged file.
fn write_src_work(project: &Path, git_tree: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &str, mode| {
        std::fs::set_permissions(project.join(path), std::fs::Permissions::from_mode(mode)).unwrap()
    };
    std::fs::create_dir_all(project.join("src/tools")).unwrap();
    std::fs::write(project.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    mode("src/lib.rs", 0o740);
    std::fs::write(project.join("src/tools/run.sh"), "#!/bin/sh\necho run\n").unwrap();
    mode("src/tools/run.sh", 0o755);
    std::fs::write(project.join("src/tools/notes.txt"), "draft\n").unwrap();
    mode("src/tools/notes.txt", 0o655);
    std::os::unix::fs::symlink("../lib.rs", project.join("src/tools/lib-link")).unwrap();
    std::fs::write(project.join("src/debug.log"), "local log\n").unwrap();
    mode("src/debug.log", 0o640);
    if git_tree {
        std::fs::write(project.join("src/staged.rs"), "pub fn staged() {}\n").unwrap();
        git(project, &["add", "src/staged.rs"]);
    }
}

#[test]
fn a_recursive_delete_inside_the_project_runs_after_a_snapshot_undo_restores() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let commit = |message: &str| {
        git(
            &repo,
            &[
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit",
                "-qm",
                message,
            ],
        )
    };
    // Status compares only a file's size, mode and modification time here.
    git(&repo, &["config", "core.trustctime", "false"]);
    git(&repo, &["config", "core.checkStat", "minimal"]);
    let racy = repo.join("src/racy.txt");
    // Git's `--stdin-paths` would read these names as `q` and `cr/x`.
    let quoted = repo.join("\"q\"");
    let carriage = repo.join("cr/x\r");
    let then = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800);
    let write_keeping_metadata = |path: &Path, bytes: &[u8]| {
        std::fs::write(path, bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(then)
            .unwrap();
    };
    write_keeping_metadata(&racy, b"original\n");
    write_keeping_metadata(&quoted, b"original\n");
    std::fs::write(repo.join("q"), "committed\n").unwrap();
    git(&repo, &["add", "src/racy.txt", "\"q\"", "q"]);
    commit("original");
    std::fs::write(repo.join(".gitignore"), "*.log\n").unwrap();
    // A clean tracked file beside the work, which Git holds.
    std::fs::write(repo.join("src/clean.rs"), "pub fn clean() {}\n").unwrap();
    std::fs::write(repo.join("src/hidden.txt"), "committed\n").unwrap();
    std::fs::create_dir(repo.join("cr")).unwrap();
    std::fs::write(repo.join("cr/x"), "committed\n").unwrap();
    for path in [&racy, &quoted, &carriage] {
        write_keeping_metadata(path, b"committed\n");
    }
    git(&repo, &["add", "src", "cr", "\"q\""]);
    // A link Git checks out as a plain file holding its target, as it does
    // where links are off.
    git(&repo, &["config", "core.symlinks", "false"]);
    std::fs::write(repo.join("src/link"), "target").unwrap();
    let blob = Command::new("git")
        .args(["hash-object", "-w", "src/link"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let blob = String::from_utf8(blob.stdout).unwrap();
    git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{},src/link", blob.trim()),
        ],
    );
    commit("clean");
    // Edits status calls clean: ones keeping size and modification time, and
    // one to a skip-worktree entry.
    write_keeping_metadata(&racy, b"localedit\n");
    write_keeping_metadata(&carriage, b"localedit\n");
    git(
        &repo,
        &["update-index", "--skip-worktree", "src/hidden.txt"],
    );
    std::fs::write(repo.join("src/hidden.txt"), "edited\n").unwrap();
    write_src_work(&repo, true);
    let before = entries(&repo);

    // At strict the delete blocks and nothing is saved.
    let reply = bash(&home, Some("strict"), &repo, "rm -rf src");
    assert!(
        denial(&reply).unwrap().contains("work/files-delete"),
        "{reply}"
    );
    assert!(!home.join(".nah/snapshots").exists());

    let reply = bash(&home, Some("core"), &repo, "rm -rf src");
    assert!(denial(&reply).is_none(), "{reply}");
    let note = context(&reply);
    assert!(note.contains("work/files-delete"), "{note}");
    let id = snapshot_id(&home, None);
    assert_named_undo(&home, &repo, &id, "rm -rf src");
    std::fs::remove_dir_all(repo.join("src")).unwrap();
    // The undo alone brings back the clean, changed, staged, untracked and
    // ignored files, with their permissions.
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(entries(&repo), before);
    let staged = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&staged.stdout), "src/staged.rs\n");

    // A copy from another revision over the edit status calls clean saves
    // its bytes too.
    write_keeping_metadata(&racy, b"localedit\n");
    write_keeping_metadata(&quoted, b"localedit\n");
    for (path, named) in [(&racy, "src/racy.txt"), (&quoted, "\"q\"")] {
        let reply = bash(
            &home,
            Some("core"),
            &repo,
            &format!("git checkout HEAD~1 -- '{named}'"),
        );
        let id = snapshot_id(&home, None);
        assert!(context(&reply).contains(&format!("nah undo {id}")));
        git(&repo, &["checkout", "HEAD~1", "--", named]);
        let undone = support::nah(&home, &repo, &["undo", &id], None);
        assert!(undone.status.success(), "{undone:?}");
        assert_eq!(std::fs::read(path).unwrap(), b"localedit\n");
    }
    // An edit under a name with a carriage return is no clean file either,
    // so the delete saves first; undo never writes such a name back.
    let reply = bash(&home, Some("core"), &repo, "rm -rf cr");
    assert!(denial(&reply).is_none(), "{reply}");
    snapshot_id(&home, None);

    // Outside Git the folder is a project only outside temporary space, so
    // it lies under the home of the user running the tests.
    let folder = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let project = std::fs::canonicalize(folder.path()).unwrap();
    std::fs::write(project.join("README.md"), "# demo\n").unwrap();
    write_src_work(&project, false);
    let before = entries(&project);
    let reply = bash(&home, Some("core"), &project, "rm -rf src");
    let id = snapshot_id(&home, None);
    assert!(context(&reply).contains(&format!("nah undo {id}")));
    assert_named_undo(&home, &project, &id, "rm -rf src");
    std::fs::remove_dir_all(project.join("src")).unwrap();
    let undone = support::nah(&home, &project, &["undo", &id], None);
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(entries(&project), before);
}

#[test]
fn a_rewrite_no_reflog_keeps_runs_after_a_save_its_undo_brings_back() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = home.join("repo");
    std::fs::create_dir(&repo).unwrap();
    let run = |args: &[&str]| {
        let output = Command::new("git")
            .args([
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
            ])
            .args(args)
            .current_dir(&repo)
            .env("FILTER_BRANCH_SQUELCH_WARNING", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    run(&["init", "-q", "-b", "main"]);
    // No reflog records a move: whatever a rewrite leaves, gc prunes.
    run(&["config", "core.logAllRefUpdates", "false"]);
    std::fs::create_dir(repo.join("src")).unwrap();
    for (file, text) in [
        ("src/lib.rs", "one\n"),
        ("README", "two\n"),
        ("src/lib.rs", "three\n"),
    ] {
        std::fs::write(repo.join(file), text).unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-qm", text.trim()]);
    }
    run(&["checkout", "-q", "-b", "topic", "HEAD~2"]);
    std::fs::write(repo.join("src/topic.rs"), "topic\n").unwrap();
    run(&["add", "-A"]);
    run(&["commit", "-qm", "topic"]);
    // Saves `command`, runs it as `args`, prunes what nothing reaches (it
    // takes `lost`), undoes the save, and returns the snapshot's id.
    let saved_then_undone = |command: &str, args: &[&str], lost: &str| {
        let reply = bash(&home, Some("core"), &repo, command);
        let note = context(&reply);
        // A hard reset also saves the files it discards, on a line of its
        // own.
        let line = note
            .lines()
            .find(|line| line.contains("work/history-rewrite"))
            .unwrap_or_else(|| panic!("{note}"));
        let id = snapshot_id(&home, Some("work/history-rewrite"));
        assert!(line.contains(&format!("nah undo {id} ")), "{line}");
        run(args);
        run(&["reflog", "expire", "--expire=now", "--all"]);
        run(&["gc", "-q", "--prune=now"]);
        assert!(
            Command::new("git")
                .args(["cat-file", "-e", lost])
                .current_dir(&repo)
                .status()
                .is_ok_and(|status| !status.success()),
            "gc kept {lost} after `{command}`"
        );
        let undone = support::nah(&home, &repo, &["undo", &id], None);
        assert!(undone.status.success(), "{undone:?}");
        id
    };

    let topic = run(&["rev-parse", "topic"]);
    let main = run(&["rev-parse", "main"]);
    let id = saved_then_undone("git rebase main", &["rebase", "-q", "main"], &topic);
    assert_eq!(
        run(&["rev-parse", &format!("refs/nah/{id}/heads/topic")]),
        topic
    );
    // The rebased branch stays as the rebase left it.
    assert_eq!(run(&["rev-parse", "topic~1"]), main);

    let rebased = run(&["rev-parse", "topic"]);
    let id = saved_then_undone(
        "git reset --hard HEAD~1",
        &["reset", "-q", "--hard", "HEAD~1"],
        &rebased,
    );
    assert_eq!(
        run(&["rev-parse", &format!("refs/nah/{id}/heads/topic")]),
        rebased
    );
    assert_eq!(run(&["rev-parse", "topic"]), main);

    // A forced filter-branch overwrites the backup an earlier one left.
    run(&["checkout", "-q", "main"]);
    let backup = run(&["commit-tree", "HEAD^{tree}", "-m", "backup"]);
    run(&["update-ref", "refs/original/refs/heads/main", &backup]);
    let id = saved_then_undone(
        "git filter-branch --force --subdirectory-filter src",
        &["filter-branch", "--force", "--subdirectory-filter", "src"],
        &backup,
    );
    assert_eq!(
        run(&[
            "rev-parse",
            &format!("refs/nah/{id}/original/refs/heads/main")
        ]),
        backup
    );

    // A pull's fetch moves the upstream ref that alone kept the branch's
    // old base before its rebase replays the branch: the save holds that
    // base too.
    run(&["clone", "-q", "--bare", ".", "../upstream.git"]);
    run(&["remote", "add", "origin", "../upstream.git"]);
    run(&["fetch", "-q", "origin"]);
    let base = run(&["rev-parse", "main"]);
    std::fs::write(repo.join("local.rs"), "local\n").unwrap();
    run(&["add", "-A"]);
    run(&["commit", "-qm", "local"]);
    // The upstream rewrites its main in its own repository: since Git 2.56
    // a push to a URL a configured remote names also moves that remote's
    // tracking ref, which leaves the pull's fetch nothing to move.
    let upstream = "--git-dir=../upstream.git";
    let rewritten = run(&[
        upstream,
        "commit-tree",
        &format!("{base}^{{tree}}"),
        "-m",
        "rewritten",
    ]);
    run(&[upstream, "update-ref", "refs/heads/main", &rewritten]);
    let id = saved_then_undone(
        "git pull --rebase origin main",
        &["pull", "-q", "--rebase", "origin", "main"],
        &base,
    );
    assert_eq!(
        run(&["rev-parse", &format!("refs/nah/{id}/heads/main~1")]),
        base
    );
}

#[test]
fn what_nah_cannot_save_blocks_and_other_guards_still_decide() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join("notes.md"), "draft\n").unwrap();
    std::fs::write(repo.join(".env"), "TOKEN=secret\n").unwrap();

    // A delete of a folder above the one the call runs in takes more than
    // that folder's files, though all lie in one repository.
    std::fs::create_dir_all(repo.join("pkg/app")).unwrap();
    std::fs::write(repo.join("pkg/plan.md"), "draft\n").unwrap();
    let reply = bash(&home, Some("core"), &repo.join("pkg/app"), "rm -rf ..");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(
        reason.contains("work/files-delete")
            && reason.contains(&repo.join("pkg").display().to_string()),
        "{reason}"
    );
    std::fs::remove_dir_all(repo.join("pkg")).unwrap();

    // The clean would delete .env, which Nah never copies.
    let reply = bash(&home, Some("core"), &repo, "git clean -fd");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(
        reason.contains(".env") && reason.contains("13 B"),
        "{reason}"
    );

    // Ignored, .env survives a clean without -x, and the clean runs.
    std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();
    let reply = bash(&home, Some("core"), &repo, "git clean -fd");
    assert!(context(&reply).contains("work/untracked-clean"), "{reply}");
    let reply = bash(&home, Some("core"), &repo, "git clean -fdx");
    assert!(denial(&reply).unwrap().contains(".env"), "{reply}");

    // A copy of an ignored repository's files would not hold its history.
    std::fs::remove_file(repo.join(".env")).unwrap();
    std::fs::create_dir(repo.join("checkout")).unwrap();
    git(&repo.join("checkout"), &["init", "-q"]);
    std::fs::write(repo.join(".gitignore"), "checkout/\n").unwrap();
    let reply = bash(&home, Some("core"), &repo, "git clean -ffdx");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("checkout/"), "{reason}");
    std::fs::remove_dir_all(repo.join("checkout")).unwrap();
    // Inside a skip-list folder too, whose other files are not copied.
    std::fs::write(repo.join(".gitignore"), "build/\n").unwrap();
    std::fs::create_dir_all(repo.join("build/out")).unwrap();
    std::fs::write(repo.join("build/out/app"), "built\n").unwrap();
    git(&repo, &["init", "-q", "build/vendored"]);
    let reply = bash(&home, Some("core"), &repo, "git clean -fdx");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("build/vendored/"), "{reason}");
    std::fs::remove_dir_all(repo.join("build")).unwrap();

    // 1.x lets a clean of logs through as regenerable; one over the copy
    // cap still blocks.
    std::fs::write(repo.join(".gitignore"), "*.log\n").unwrap();
    std::fs::write(repo.join("important.log"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
    for command in ["git clean -fX", "git clean -fdx"] {
        let reply = bash(&home, Some("core"), &repo, command);
        let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
        assert!(reason.contains("important.log"), "{reason}");
    }

    // A submodule's own work tree is not saved: a reset that may recurse
    // into it blocks while it holds changes, and runs once it holds none.
    std::fs::remove_file(repo.join("important.log")).unwrap();
    let library = home.join("library");
    std::fs::create_dir(&library).unwrap();
    git(&library, &["init", "-q"]);
    std::fs::write(library.join("lib.txt"), "lib\n").unwrap();
    git(&library, &["add", "lib.txt"]);
    let commit = [
        "-c",
        "user.name=nah test",
        "-c",
        "user.email=nah@example.invalid",
        "commit",
        "-qm",
    ];
    git(&library, &[&commit[..], &["library"]].concat());
    git(
        &repo,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            library.to_str().unwrap(),
            "lib",
        ],
    );
    git(&repo, &[&commit[..], &["submodule"]].concat());
    std::fs::write(repo.join("lib/lib.txt"), "local edit\n").unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let reply = bash(&home, Some("core"), &repo, "git reset --hard");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("lib/"), "{reason}");
    git(&repo.join("lib"), &["checkout", "-q", "--", "lib.txt"]);
    assert!(context(&bash(&home, Some("core"), &repo, "git reset --hard")).contains("snapshot"));

    // A reset only discards tracked changes; another guard still blocks the
    // same call when it reads the secret.
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let reply = bash(&home, Some("core"), &repo, "git reset --hard && cat .env");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("secrets/env-files-read"), "{reason}");

    // A discard Nah cannot save keeps its rule's own reason, and a call
    // whose other work rule runs whole is blocked under both rules, with
    // both reasons, whichever rule runs whole.
    std::fs::write(repo.join("draft.md"), "draft\n").unwrap();
    for setting in ["rule", "clean-rule"] {
        let reply = bash(
            &home,
            Some(setting),
            &repo,
            "git checkout -- src/lib.rs && git clean -fd",
        );
        let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
        assert!(
            reason.contains("uncommitted changes to the named files")
                && reason.contains("work/untracked-clean: this would delete untracked files")
                && reason.contains("could not save it first"),
            "{setting}: {reason}"
        );
    }
    std::fs::remove_file(repo.join("draft.md")).unwrap();
    let worktree = home.join("wt");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            worktree.to_str().unwrap(),
        ],
    );
    std::fs::write(worktree.join("src/lib.rs"), "pub fn wt() {}\n").unwrap();
    let reply = bash(
        &home,
        Some("core"),
        &repo,
        &format!("git worktree remove --force {}", worktree.display()),
    );
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(
        reason.contains("force-remove a worktree") && reason.contains("could not save it first"),
        "{reason}"
    );
}

#[test]
fn a_stalled_save_blocks_by_the_hook_deadline_and_publishes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    // The save child stalls right before it would publish.
    let stalled = home.join("save-child.pid");
    let started = Instant::now();
    let reply = bash_with(
        &home,
        Some("core"),
        &[("NAH_TEST_SAVE_STALL", stalled.as_os_str())],
        &repo,
        "git reset --hard",
    );
    let elapsed = started.elapsed();
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("took longer"), "{reason}");
    // Within Claude Code's 5 s hook timeout, launching nah included.
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    let child = std::fs::read_to_string(&stalled).unwrap();
    let alive = Command::new("kill")
        .args(["-0", child.trim()])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!alive.success(), "the save child {child} outlived the hook");
    let listed = support::nah(&home, &repo, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed, json!([]));
}

// A store that stops answering once the child was let publish: neither the
// child nor the hook's own look at the store holds the answer back, and the
// snapshot that may yet appear is named.
#[test]
fn a_store_stalled_after_a_granted_publication_still_blocks_by_the_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let started = Instant::now();
    let reply = bash_with(
        &home,
        Some("core"),
        &[("NAH_TEST_STORE_STALL", "1".as_ref())],
        &repo,
        "git reset --hard",
    );
    let elapsed = started.elapsed();
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("may still appear"), "{reason}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn every_failure_around_the_save_blocks_with_its_reason() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let blocked = |home: &Path, expected: &str| {
        let reply = bash(home, None, &repo, "git reset --hard");
        let reason = denial(&reply).unwrap_or_else(|| panic!("{expected}: {reply}"));
        assert!(reason.contains(expected), "{reason}");
    };

    // Without its settings, Nah cannot save; a call that discards nothing
    // still fails open as before.
    let missing = home.join("missing");
    blocked(&missing, "could not load its settings");
    assert!(denial(&bash(&missing, Some("core"), &repo, "git status")).is_none());

    // Damaged settings are replaced with safe defaults for every other
    // guard, but may name what a save must not copy.
    let nah = home.join(".nah");
    std::fs::create_dir_all(nah.join("sessions")).unwrap();
    std::fs::write(nah.join("built-ins.json"), "{").unwrap();
    blocked(&home, "could not read all its settings");
    std::fs::remove_file(nah.join("built-ins.json")).unwrap();

    std::fs::write(nah.join("snapshots"), "").unwrap();
    blocked(&home, "snapshot store cannot be written");
    std::fs::remove_file(nah.join("snapshots")).unwrap();

    // The marker of the decision in progress, written before the save.
    std::fs::remove_dir_all(nah.join("save-then-run")).unwrap();
    std::fs::write(nah.join("save-then-run"), "").unwrap();
    blocked(&home, "could not record the save it starts");
    std::fs::remove_file(nah.join("save-then-run")).unwrap();

    // The save's refusal follows the rule's own reason, and the dry run
    // shows the block the hook gives.
    std::fs::write(repo.join(".git/index.lock"), "").unwrap();
    blocked(&home, "holds the index lock");
    blocked(&home, "this would discard");
    let tested = support::nah(
        &home,
        &repo,
        &["test", "--runtime", "claude", "--json", "git reset --hard"],
        None,
    );
    let tested: Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(tested["decision"]["verdict"], "block", "{tested}");
    assert_eq!(tested["saves"], Value::Null, "{tested}");
    std::fs::remove_file(repo.join(".git/index.lock")).unwrap();

    // No part of the rule covers `--merge`; a write beside it, which keeps
    // the save from running, still blocks it.
    let reply = bash(
        &home,
        None,
        &repo,
        "echo x > notes.txt; git reset --merge HEAD",
    );
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("could not save it first"), "{reason}");

    // With the latest snapshot current, a check may skip the walk; the
    // labels are read all the same. Without a label index, or with a damaged
    // one, Nah reads every session ledger, and one cannot be read.
    assert!(context(&bash(&home, Some("core"), &repo, "git reset --hard")).contains("snapshot"));
    let ledger = nah.join("sessions/other.jsonl");
    std::fs::write(&ledger, "").unwrap();
    std::fs::set_permissions(&ledger, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    blocked(&home, "label secret cannot be read");
    std::fs::write(nah.join("sessions/labels.json"), "{").unwrap();
    blocked(&home, "label secret cannot be read");
    std::fs::remove_file(&ledger).unwrap();
    std::fs::remove_file(nah.join("sessions/labels.json")).unwrap();

    assert!(context(&bash(&home, Some("core"), &repo, "git reset --hard")).contains("snapshot"));
}

#[test]
fn wildcard_pathspec_discards_save_what_they_reach_or_block() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join(".gitignore"), "*.log\n.env\n").unwrap();
    std::fs::write(repo.join(".env"), "TOKEN=secret\n").unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    std::fs::write(repo.join("build.log"), "ignored log\n").unwrap();
    std::fs::write(repo.join("notes.md"), "draft\n").unwrap();
    let before = tree(&repo);

    // The ignored .env is no file these reach, so none blocks on it. An
    // unquoted `*.rs` matches nothing in the folder, so the shell passes it
    // to git as it is.
    for (command, discard) in [
        ("git checkout -- '*.rs'", &["checkout", "--", "*.rs"][..]),
        ("git checkout -- *.rs", &["checkout", "--", "*.rs"][..]),
        (
            "git restore ':(glob)src/**'",
            &["restore", ":(glob)src/**"][..],
        ),
        (
            "git clean -fdx -- '*.log'",
            &["clean", "-q", "-fdx", "--", "*.log"][..],
        ),
    ] {
        let reply = bash(&home, Some("core"), &repo, command);
        let note = context(&reply);
        let id = snapshot_id(&home, None);
        assert!(note.contains(&format!("nah undo {id}")));
        git(&repo, discard);
        assert_ne!(tree(&repo), before, "{command} discarded nothing");
        let undone = support::nah(&home, &repo, &["undo", &id], None);
        assert!(undone.status.success(), "{command}: {undone:?}");
        assert_eq!(tree(&repo), before, "{command}");
    }

    // Git's pathspecs reach the secret, which Nah never copies.
    let reply = bash(&home, Some("core"), &repo, "git clean -fdx -- '*.env'");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains(".env"), "{reason}");
    // So does `:/` from a subfolder, which selects the whole tree.
    let reply = bash(
        &home,
        Some("core"),
        &repo.join("src"),
        "git clean -fdx -- :/",
    );
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains(".env"), "{reason}");
    // Git reads a name an unquoted `:` glob expands to as pathspec magic, so
    // Nah cannot tell what it reaches.
    let reply = bash(&home, Some("core"), &repo, "git checkout -- :*.rs");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains("pathspec magic"), "{reason}");
    // So does such a name in the folder that a glob of any text may expand
    // to: in `src`, `:(top)` makes git clean the whole tree.
    std::fs::write(repo.join("src/:(top)"), "").unwrap();
    let reply = bash(&home, Some("core"), &repo.join("src"), "git clean -fd -- *");
    let reason = denial(&reply).unwrap_or_else(|| panic!("{reply}"));
    assert!(reason.contains(":(top)"), "{reason}");
    std::fs::remove_file(repo.join("src/:(top)")).unwrap();

    // A checkout from another commit writes over untracked work and stages
    // its own version, which undo keeps as newer work. Nah cannot tell which
    // tree a wildcard pathspec copies from, so untracked work it reaches
    // blocks: a file it matches, or a folder matched by its own name, ignored
    // or not, which `target` replaces with a file. A named path blocks where
    // `target` tracks it.
    std::fs::remove_file(repo.join(".env")).unwrap();
    git(&repo, &["checkout", "-q", "-b", "target"]);
    std::fs::write(repo.join("x.rs"), "pub fn target() {}\n").unwrap();
    git(&repo, &["add", "x.rs"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "target",
        ],
    );
    git(&repo, &["checkout", "-q", "-"]);
    let blocked_on = |command: &str, path: &str| {
        let reply = bash(&home, Some("core"), &repo, command);
        let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
        assert!(reason.contains(path), "{command}: {reason}");
    };
    std::fs::write(repo.join("src/new.rs"), "pub fn new() {}\n").unwrap();
    blocked_on("git checkout -- '*.rs'", "src/new.rs");
    std::fs::remove_file(repo.join("src/new.rs")).unwrap();
    std::fs::create_dir(repo.join("x.rs")).unwrap();
    std::fs::write(repo.join("x.rs/notes"), "only here\n").unwrap();
    blocked_on("git checkout target -- '*.rs'", "x.rs/notes");
    blocked_on("git checkout target -- x.rs", "x.rs/notes");
    std::fs::write(repo.join(".gitignore"), "*.log\n.env\nx.rs/\n").unwrap();
    blocked_on("git checkout target -- '*.rs'", "x.rs");
    // A repository of its own there would lose its history with it.
    std::fs::remove_dir_all(repo.join("x.rs")).unwrap();
    std::fs::write(repo.join(".gitignore"), "*.log\n.env\n").unwrap();
    git(&repo, &["init", "-q", "x.rs"]);
    blocked_on("git checkout target -- '*.rs'", "x.rs/");
    // So would one in a skip-list folder, whose other files are not copied.
    std::fs::remove_dir_all(repo.join("x.rs")).unwrap();
    std::fs::write(repo.join(".gitignore"), "*.log\n.env\ntarget/\n").unwrap();
    std::fs::create_dir_all(repo.join("target/debug")).unwrap();
    std::fs::write(repo.join("target/debug/out.o"), "built\n").unwrap();
    git(&repo, &["init", "-q", "target/x.rs"]);
    blocked_on("git checkout target -- '*.rs'", "target/x.rs/");
}

#[test]
fn a_tree_that_writes_a_file_over_a_submodule_keeping_its_repository_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let commit = |repo: &Path, message: &str| {
        git(repo, &["add", "-A"]);
        git(
            repo,
            &[
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit",
                "-qm",
                message,
            ],
        );
    };
    // `other` tracks a plain file where this branch has a clean submodule
    // that keeps its repository in its own `.git` folder.
    git(&repo, &["checkout", "-q", "-b", "other"]);
    std::fs::write(repo.join("lib"), "a file\n").unwrap();
    commit(&repo, "other");
    git(&repo, &["checkout", "-q", "-"]);
    let library = home.join("library");
    std::fs::create_dir(&library).unwrap();
    git(&library, &["init", "-q"]);
    std::fs::write(library.join("lib.txt"), "lib\n").unwrap();
    commit(&library, "library");
    git(&repo, &["clone", "-q", library.to_str().unwrap(), "lib"]);
    commit(&repo, "submodule");
    assert!(repo.join("lib/.git").is_dir());
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();

    // The same tree's copy of another path leaves the submodule alone.
    let reply = bash(&home, None, &repo, "git checkout other -- src/lib.rs");
    assert!(context(&reply).contains("snapshot"), "{reply}");
    // So does one Nah cannot name the tree of: a ref another step moves,
    // HEAD's own branch too, or a pathspec copy.
    for command in [
        "git checkout -f other",
        "git checkout other -- .",
        "git branch -f moving other && git checkout -f moving",
        "git reset --soft other && git reset --hard",
        "git checkout other -- 'l*'",
    ] {
        let reply = bash(&home, None, &repo, command);
        let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
        assert!(reason.contains("lib/"), "{command}: {reason}");
    }
    // A pathspec that only excludes copies the whole tree but what it
    // excludes, even from a subfolder.
    let command = "git checkout other -- ':!nothing'";
    let reply = bash(&home, None, &repo.join("src"), command);
    let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
    assert!(reason.contains("lib/"), "{command}: {reason}");
}

#[test]
fn a_discard_onto_another_revision_saves_what_it_writes_over() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let commit = |message: &str| {
        git(&repo, &["add", "-A"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit",
                "-qm",
                message,
            ],
        );
    };
    // `other` tracks what this branch ignores.
    git(&repo, &["checkout", "-q", "-b", "other"]);
    std::fs::write(repo.join("src/lib.rs"), "pub fn other() {}\n").unwrap();
    std::fs::write(repo.join("payload"), "theirs\n").unwrap();
    std::fs::write(repo.join("notes"), "theirs\n").unwrap();
    std::fs::write(repo.join(".env"), "TOKEN=theirs\n").unwrap();
    commit("other");
    git(&repo, &["checkout", "-q", "-"]);
    std::fs::write(repo.join(".gitignore"), "payload\nnotes/\n.env\n").unwrap();
    std::fs::write(repo.join("docs"), "tracked\n").unwrap();
    commit("ignore");
    std::fs::write(repo.join("payload"), "mine\n").unwrap();
    // A folder where `other` tracks a file.
    std::fs::create_dir(repo.join("notes")).unwrap();
    std::fs::write(repo.join("notes/draft.md"), "mine\n").unwrap();
    std::fs::write(repo.join(".env"), "TOKEN=mine\n").unwrap();

    // With no tracked change, a reset onto the current commit loses nothing,
    // while a reset or forced checkout onto `other` still writes over the
    // files it tracks that are untracked here.
    assert_eq!(
        bash(&home, Some("core"), &repo, "git reset --hard"),
        Value::Null
    );
    for command in ["git reset --hard other", "git checkout -f other"] {
        let reply = bash(&home, Some("core"), &repo, command);
        let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
        assert!(reason.contains(".env"), "{reason}");
    }

    // A reset onto the current commit leaves ignored files alone; onto
    // `other`, or onto a ref a fetch may move first, it writes over .env.
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    assert!(context(&bash(&home, Some("core"), &repo, "git reset --hard")).contains("snapshot"));
    for command in [
        "git reset --hard other",
        "git fetch -q . other:refs/remotes/origin/other && git reset --hard origin/other",
    ] {
        let reply = bash(&home, Some("core"), &repo, command);
        let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
        assert!(reason.contains(".env"), "{reason}");
    }

    // Without the secret, the ignored payload and folder are copied, and
    // undo brings back them and the staged and unstaged edit over `other`'s
    // committed versions.
    std::fs::remove_file(repo.join(".env")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn staged() {}\n").unwrap();
    git(&repo, &["add", "src/lib.rs"]);
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let index = |repo: &Path| {
        let listed = Command::new("git")
            .args(["ls-files", "-s", "src/lib.rs"])
            .current_dir(repo)
            .output()
            .unwrap();
        String::from_utf8(listed.stdout).unwrap()
    };
    let staged = index(&repo);
    let before = tree(&repo);
    let reply = bash(&home, Some("core"), &repo, "git checkout -f other");
    let id = snapshot_id(&home, None);
    assert!(context(&reply).contains(&format!("nah undo {id}")));
    git(&repo, &["checkout", "-q", "-f", "other"]);
    std::fs::remove_file(repo.join(".env")).unwrap();
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(undone.status.success(), "{undone:?}");
    let mut after = tree(&repo);
    let mut expected = before;
    for gone in [".gitignore", "docs"] {
        after.remove(Path::new(gone));
        expected.remove(Path::new(gone));
    }
    assert_eq!(after, expected);
    assert_eq!(index(&repo), staged);

    // `--merge` drops a newly staged file, and the snapshot keeps it.
    git(&repo, &["checkout", "-q", "-f", "-"]);
    std::fs::write(repo.join("src/new.rs"), "pub fn new() {}\n").unwrap();
    git(&repo, &["add", "src/new.rs"]);
    let reply = bash(&home, Some("core"), &repo, "git reset --merge HEAD");
    let id = snapshot_id(&home, None);
    assert!(context(&reply).contains(&format!("nah undo {id}")));
    git(&repo, &["reset", "-q", "--merge", "HEAD"]);
    assert!(!repo.join("src/new.rs").exists());
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(undone.status.success(), "{undone:?}");
    let staged = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&staged.stdout), "src/new.rs\n");

    // A tracked file replaced by a folder: git status shows nothing under
    // it, and a reset writes the file back over the folder.
    std::fs::remove_file(repo.join("docs")).unwrap();
    std::fs::create_dir(repo.join("docs")).unwrap();
    std::fs::write(repo.join("docs/draft.md"), "only here\n").unwrap();
    let reply = bash(&home, Some("core"), &repo, "git reset --hard");
    let id = snapshot_id(&home, None);
    assert!(context(&reply).contains(&format!("nah undo {id}")));
    git(&repo, &["reset", "-q", "--hard"]);
    assert!(repo.join("docs").is_file());
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(
        std::fs::read_to_string(repo.join("docs/draft.md")).unwrap(),
        "only here\n"
    );
}

// A discard loses nothing only when every tracked file it reaches already
// holds what it writes. Anything else is saved first: a file the target
// adds beside an untracked sibling, an edit outside the folder a
// `diff.relative` diff would show, an index change a worktree copy keeps.
// What the save cannot hold, such as a repository in a folder that differs
// only by case from a file the target tracks, blocks; a file that differs
// only by Unicode normalization is saved.
#[test]
fn a_discard_from_another_revision_is_judged_by_that_revision() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let commit = |message: &str| {
        git(&repo, &["add", "-A"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit",
                "-qm",
                message,
            ],
        );
    };
    let saved = |command: &str| {
        let reply = bash(&home, Some("core"), &repo, command);
        assert!(context(&reply).contains("snapshot"), "{command}: {reply}");
        context(&reply).to_owned()
    };
    git(&repo, &["checkout", "-q", "-b", "other"]);
    std::fs::write(repo.join("src/lib.rs"), "pub fn other() {}\n").unwrap();
    commit("other");
    git(&repo, &["checkout", "-q", "-"]);

    // The index and working copy already hold `other`'s tree.
    git(&repo, &["checkout", "-q", "other", "--", "src/lib.rs"]);
    std::fs::write(repo.join("draft.md"), "draft\n").unwrap();
    for command in ["git reset --hard other", "git checkout -f other"] {
        assert_eq!(
            bash(&home, Some("core"), &repo, command),
            Value::Null,
            "{command}"
        );
    }
    // An edit at the top level is reached from a subfolder, whatever the
    // repository's `diff.relative`.
    git(&repo, &["config", "diff.relative", "true"]);
    std::fs::write(repo.join("package.json"), "{}\n").unwrap();
    assert!(saved("git -C src reset --hard other").contains("package.json"));
    git(&repo, &["config", "--unset", "diff.relative"]);
    git(&repo, &["reset", "-q", "--hard"]);

    // A copy into the working tree over a staged change is saved, even
    // where the working copy equals the source.
    let restore = "git restore --source=HEAD --worktree src/lib.rs";
    assert_eq!(bash(&home, Some("core"), &repo, restore), Value::Null);
    std::fs::write(repo.join("src/lib.rs"), "pub fn staged() {}\n").unwrap();
    git(&repo, &["add", "src/lib.rs"]);
    std::fs::write(repo.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    saved(restore);
    git(&repo, &["reset", "-q", "--hard"]);

    // A target adding a file beside an untracked one is saved.
    git(&repo, &["checkout", "-q", "-b", "notes"]);
    std::fs::create_dir(repo.join("notes")).unwrap();
    std::fs::write(repo.join("notes/template.md"), "template\n").unwrap();
    std::fs::write(repo.join("build"), "a file here\n").unwrap();
    commit("notes");
    git(&repo, &["checkout", "-q", "-"]);
    std::fs::create_dir(repo.join("notes")).unwrap();
    std::fs::write(repo.join("notes/keep.md"), "mine\n").unwrap();
    saved("git reset --hard notes");
    std::fs::remove_dir_all(repo.join("notes")).unwrap();

    // A repository of its own where the target writes a file blocks,
    // spelled in any case.
    std::fs::write(repo.join(".gitignore"), "build/\nBuild/\n").unwrap();
    commit("ignore");
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    for folder in ["build", "Build"] {
        std::fs::create_dir_all(repo.join(folder).join("nested")).unwrap();
        git(&repo.join(folder).join("nested"), &["init", "-q"]);
        for command in ["git reset --hard notes", "git checkout -f notes"] {
            let reply = bash(&home, Some("core"), &repo, command);
            let reason = denial(&reply).unwrap_or_else(|| panic!("{command}: {reply}"));
            assert!(reason.contains(&format!("{folder}/nested")), "{reason}");
        }
        std::fs::remove_dir_all(repo.join(folder)).unwrap();
    }

    // So is a file whose name differs from one the target tracks only by
    // Unicode normalization, which macOS takes for the same file: the
    // snapshot holds it, and undo brings its bytes back.
    let (composed, decomposed) = ("caf\u{e9}.txt", "cafe\u{301}.txt");
    git(&repo, &["config", "core.precomposeunicode", "false"]);
    git(&repo, &["checkout", "-q", "-b", "accent"]);
    std::fs::write(repo.join(composed), "theirs\n").unwrap();
    commit("accent");
    git(&repo, &["checkout", "-q", "-"]);
    std::fs::write(repo.join(".gitignore"), "*.txt\n").unwrap();
    commit("ignore text");
    std::fs::write(repo.join(decomposed), "mine\n").unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let note = saved("git reset --hard accent");
    assert!(note.contains(decomposed), "{note}");
    let id = snapshot_id(&home, None);
    git(&repo, &["reset", "-q", "--hard", "accent"]);
    let restored = home.join("accent-restored");
    let undone = support::nah(
        &home,
        &repo,
        &["undo", &id, "--into", restored.to_str().unwrap()],
        None,
    );
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(
        std::fs::read_to_string(restored.join(decomposed)).unwrap(),
        "mine\n"
    );
}

#[test]
fn undo_of_a_revision_copy_restores_bytes_and_keeps_newer_work() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let path = repo.join("src/lib.rs");
    let source = std::fs::read(&path).unwrap();
    let head = b"HEAD version\n";
    std::fs::write(&path, head).unwrap();
    git(&repo, &["add", "src/lib.rs"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "second revision",
        ],
    );
    let staged = b"staged\0\xff\r\n";
    let worktree = b"unstaged\0\xfe";
    let index = || {
        let shown = Command::new("git")
            .args(["show", ":src/lib.rs"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(shown.status.success(), "{shown:?}");
        shown.stdout
    };
    for (args, before_index, after_index, newer_worktree, newer_index) in [
        (
            &["checkout", "HEAD~1", "--", "src/lib.rs"][..],
            &staged[..],
            source.as_slice(),
            None,
            false,
        ),
        (
            &["checkout", "HEAD~1", "--", "src/lib.rs"],
            &head[..],
            source.as_slice(),
            None,
            false,
        ),
        (
            &["restore", "--source", "HEAD~1", "--", "src/lib.rs"],
            &staged[..],
            &staged[..],
            None,
            false,
        ),
        (
            &["restore", "--source=HEAD~1", "-SW", "--", "src/lib.rs"],
            &staged[..],
            source.as_slice(),
            None,
            false,
        ),
        (
            &["checkout", "HEAD~1", "--", "src/lib.rs"],
            &staged[..],
            source.as_slice(),
            Some(&head[..]),
            false,
        ),
        (
            &["restore", "--source=HEAD~1", "--", "src/lib.rs"],
            &staged[..],
            &staged[..],
            None,
            true,
        ),
    ] {
        std::fs::write(&path, before_index).unwrap();
        git(&repo, &["add", "src/lib.rs"]);
        std::fs::write(&path, worktree).unwrap();
        let command = format!("git {}", args.join(" "));
        let reply = bash(&home, Some("core"), &repo, &command);
        assert!(denial(&reply).is_none(), "{reply}");
        let id = snapshot_id(&home, None);
        assert!(context(&reply).contains(&format!("nah undo {id} (")));
        git(&repo, args);
        assert_eq!(std::fs::read(&path).unwrap(), source, "{command}");
        assert_eq!(index(), after_index, "{command}");
        let refreshed = hook(
            &home,
            Some("core"),
            json!({
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_response": {},
                "cwd": repo,
                "session_id": "session-1",
            }),
        );
        assert!(refreshed.status.success(), "{refreshed:?}");
        if let Some(newer) = newer_worktree {
            std::fs::write(&path, newer).unwrap();
        }
        if newer_index {
            git(&repo, &["add", "src/lib.rs"]);
        }
        let undone = support::nah(&home, &repo, &["undo", &id], None);
        let left_paths = newer_worktree.is_some() || newer_index;
        assert_eq!(undone.status.success(), !left_paths, "{undone:?}");
        if left_paths {
            let note = String::from_utf8(undone.stdout).unwrap();
            assert!(note.contains("left src/lib.rs"), "{note}");
            assert!(note.contains(&format!("nah undo {id} --into")), "{note}");
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            newer_worktree.unwrap_or(worktree)
        );
        let expected_index = if newer_index {
            source.as_slice()
        } else {
            before_index
        };
        assert_eq!(index(), expected_index, "{command}");
    }
}

#[test]
fn undo_of_a_directory_revision_copy_restores_all_changed_paths() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let commit = |message: &str| {
        git(&repo, &["add", "-A"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit",
                "-qm",
                message,
            ],
        );
    };
    std::fs::write(repo.join("src/clean"), b"old\0\xfc").unwrap();
    std::fs::write(repo.join("src/from-source"), b"old only\0\xfd").unwrap();
    commit("source");
    std::fs::write(repo.join("src/clean"), b"clean at HEAD\0\xfe").unwrap();
    std::fs::write(repo.join("src/head-only"), b"HEAD only\0\xff").unwrap();
    std::fs::remove_file(repo.join("src/from-source")).unwrap();
    commit("HEAD");
    std::fs::write(repo.join("src/lib.rs"), b"staged\0\xff\r\n").unwrap();
    git(&repo, &["add", "src/lib.rs"]);
    std::fs::write(repo.join("src/lib.rs"), b"unstaged\0\xfe").unwrap();

    let index = || {
        let listed = Command::new("git")
            .args(["ls-files", "-s", "-z"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(listed.status.success(), "{listed:?}");
        listed.stdout
    };
    let before_tree = tree(&repo);
    let before_index = index();
    for (copy, checkout_index, newer) in [
        (&["checkout", "HEAD~1", "--", "src"][..], false, false),
        (
            &["restore", "--source=HEAD~1", "-SW", "--", "src"],
            false,
            false,
        ),
        (&["checkout", "HEAD~1", "--", "src"], true, false),
        (&["restore", "--source=HEAD~1", "--", "src"], true, false),
        (&["checkout", "HEAD~1", "--", "src"], false, true),
    ] {
        let checkout = ["checkout", "--", "src/lib.rs"];
        let mut command = format!("git {}", copy.join(" "));
        if checkout_index {
            command.push_str(&format!(" && git {}", checkout.join(" ")));
        }
        let reply = bash(&home, Some("core"), &repo, &command);
        assert!(denial(&reply).is_none(), "{reply}");
        let id = snapshot_id(&home, None);
        git(&repo, copy);
        if checkout_index {
            git(&repo, &checkout);
        }
        assert_eq!(std::fs::read(repo.join("src/clean")).unwrap(), b"old\0\xfc");
        assert!(repo.join("src/from-source").is_file());
        assert_eq!(repo.join("src/head-only").is_file(), copy[0] == "checkout");
        if copy[0] == "restore" && checkout_index {
            assert_eq!(
                std::fs::read(repo.join("src/lib.rs")).unwrap(),
                b"staged\0\xff\r\n"
            );
        }
        let refreshed = hook(
            &home,
            Some("core"),
            json!({
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_response": {},
                "cwd": repo,
                "session_id": "session-1",
            }),
        );
        assert!(refreshed.status.success(), "{refreshed:?}");
        let mut expected = before_tree.clone();
        if newer {
            for path in ["src/clean", "src/from-source"] {
                let bytes = b"edited after checkout\0";
                std::fs::write(repo.join(path), bytes).unwrap();
                expected.insert(PathBuf::from(path), bytes.to_vec());
            }
        }
        let undo = support::nah(&home, &repo, &["undo", &id], None);
        assert_eq!(undo.status.success(), !newer, "{command}: {undo:?}");
        if newer {
            let note = String::from_utf8(undo.stdout).unwrap();
            assert!(note.contains("left src/clean"), "{note}");
            assert!(note.contains("left src/from-source"), "{note}");
            assert!(note.contains(&format!("nah undo {id} --into")), "{note}");
        }
        assert_eq!(tree(&repo), expected, "{command}");
        assert_eq!(index(), before_index, "{command}");
    }
}

#[test]
fn clean_revision_copies_use_no_snapshot_byte_budget_and_summarize_undo() {
    for (count, bytes_per_file) in [(3000u32, 32), (1, 64 * 1024 * 1024)] {
        let temp = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(temp.path()).unwrap();
        let repo = support::repo(&home);
        let commit = |message: &str| {
            git(&repo, &["add", "bulk"]);
            git(
                &repo,
                &[
                    "-c",
                    "user.name=nah test",
                    "-c",
                    "user.email=nah@example.invalid",
                    "commit",
                    "-qm",
                    message,
                ],
            );
        };
        let index = || {
            let listed = Command::new("git")
                .args(["ls-files", "-s", "-z"])
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(listed.status.success(), "{listed:?}");
            listed.stdout
        };
        std::fs::create_dir(repo.join("bulk")).unwrap();
        for number in 0..count {
            std::fs::write(repo.join(format!("bulk/{number:04}.bin")), b"older\0").unwrap();
        }
        commit("older files");
        let mut bytes = vec![0xf9; bytes_per_file];
        for number in 0..count {
            bytes[..4].copy_from_slice(&number.to_le_bytes());
            std::fs::write(repo.join(format!("bulk/{number:04}.bin")), &bytes).unwrap();
        }
        let first = repo.join("bulk/0000.bin");
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o755)).unwrap();
        commit("clean files at HEAD");
        let before_index = index();
        // So the copy also reaches one changed file, which the rolling copy
        // already holds.
        let edited = b"{\"scripts\":{}}";
        std::fs::write(repo.join("package.json"), edited).unwrap();

        let reply = bash(
            &home,
            Some("core"),
            &repo,
            "git checkout HEAD~1 -- bulk package.json",
        );
        assert!(denial(&reply).is_none(), "{reply}");
        let id = snapshot_id(&home, None);
        let snapshots = support::nah(&home, &repo, &["snapshots", "--json"], None);
        assert!(snapshots.status.success(), "{snapshots:?}");
        let listed: Value = serde_json::from_slice(&snapshots.stdout).unwrap();
        let saved = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap();
        assert_eq!(saved["summary"]["new_bytes"], 0);

        git(&repo, &["checkout", "HEAD~1", "--", "bulk", "package.json"]);
        assert_eq!(std::fs::read(&first).unwrap(), b"older\0");
        let undo = support::nah(&home, &repo, &["undo", &id], None);
        assert!(undo.status.success(), "{undo:?}");
        let note = String::from_utf8(undo.stdout).unwrap();
        let clean = note
            .lines()
            .find(|line| line.contains(&format!("restored {count} clean")))
            .unwrap();
        assert!(clean.contains("bulk/0000.bin"), "{clean}");
        // One more line for the changed file.
        assert!(
            note.lines().count() <= 4,
            "undo printed {} lines for {count} clean files",
            note.lines().count()
        );
        if count > 5 {
            assert!(
                clean.contains("bulk/0004.bin") && !clean.contains("bulk/0005.bin"),
                "{clean}"
            );
        }
        assert_eq!(index(), before_index);
        assert_ne!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o100,
            0
        );
        for number in 0..count {
            bytes[..4].copy_from_slice(&number.to_le_bytes());
            assert!(
                std::fs::read(repo.join(format!("bulk/{number:04}.bin"))).unwrap() == bytes,
                "file {number} differs after undo"
            );
        }
        if count == 1 {
            let copied = support::nah(&home, &repo, &["undo", &id, "--into", "recovered"], None);
            assert!(copied.status.success(), "{copied:?}");
            assert!(std::fs::read(repo.join("recovered/bulk/0000.bin")).unwrap() == bytes);
        }
    }
}

#[test]
fn undo_across_a_file_and_folder_swap_keeps_only_newer_work() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    let commit = |message: &str| {
        git(&repo, &["add", "-A"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit",
                "-qm",
                message,
            ],
        );
    };
    std::fs::write(repo.join("box"), "base\n").unwrap();
    commit("box is a file");
    git(&repo, &["checkout", "-q", "-b", "folder"]);
    std::fs::remove_file(repo.join("box")).unwrap();
    std::fs::create_dir(repo.join("box")).unwrap();
    std::fs::write(repo.join("box/child"), "theirs\n").unwrap();
    commit("box is a folder");
    git(&repo, &["checkout", "-q", "-b", "folder-env"]);
    std::fs::write(repo.join("box/.env"), "TOKEN=committed\n").unwrap();
    commit("box holds a secret");
    git(&repo, &["checkout", "-q", "-f", "@{-2}"]);
    let saved = |command: &str| {
        context(&bash(&home, Some("core"), &repo, command));
        snapshot_id(&home, None)
    };
    let index = || {
        let listed = Command::new("git")
            .args(["ls-files", "-s"])
            .current_dir(&repo)
            .output()
            .unwrap();
        String::from_utf8(listed.stdout).unwrap()
    };

    let start = {
        let named = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(&repo)
            .output()
            .unwrap();
        String::from_utf8(named.stdout).unwrap().trim().to_owned()
    };

    // The edited file comes back over the folder the reset checked out,
    // and undoing that undo puts the folder and its index entry back.
    std::fs::write(repo.join("box"), "edited\n").unwrap();
    let id = saved("git reset --hard folder");
    git(&repo, &["reset", "-q", "--hard", "folder"]);
    let landed = (tree(&repo), index());
    let undone = support::nah(&home, &repo, &["undo", &id, "--json"], None);
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(
        std::fs::read_to_string(repo.join("box")).unwrap(),
        "edited\n"
    );
    let undone: Value = serde_json::from_slice(&undone.stdout).unwrap();
    let before_undo = undone["before_undo"].as_str().unwrap();
    let redone = support::nah(&home, &repo, &["undo", before_undo], None);
    assert!(redone.status.success(), "{redone:?}");
    assert_eq!((tree(&repo), index()), landed);

    // What git status does not show there, and cannot write back, stays: a
    // repository of its own, or a file git was told to leave alone.
    git(&repo, &["reset", "-q", "--hard", "folder~1"]);
    std::fs::write(repo.join("box"), "edited\n").unwrap();
    let id = saved("git checkout -f folder");
    git(&repo, &["checkout", "-q", "-f", "folder"]);
    git(&repo, &["update-index", "--skip-worktree", "box/child"]);
    std::fs::write(repo.join("box/child"), "hidden\n").unwrap();
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(!undone.status.success(), "{undone:?}");
    assert_eq!(
        std::fs::read_to_string(repo.join("box/child")).unwrap(),
        "hidden\n"
    );
    git(&repo, &["update-index", "--no-skip-worktree", "box/child"]);
    git(&repo, &["checkout", "-q", "--", "box/child"]);
    git(&repo.join("box"), &["init", "-q", "inner"]);
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(!undone.status.success(), "{undone:?}");
    assert!(repo.join("box/inner/.git").is_dir());
    std::fs::remove_dir_all(repo.join("box/inner")).unwrap();
    git(&repo, &["checkout", "-q", "-f", &start]);

    // Nor does undo clear a secret, which the save before it never copies.
    std::fs::write(repo.join("box"), "edited\n").unwrap();
    let id = saved("git checkout -f folder-env");
    git(&repo, &["checkout", "-q", "-f", "folder-env"]);
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(!undone.status.success(), "{undone:?}");
    assert!(repo.join("box/.env").is_file());
    let listed = support::nah(&home, &repo, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    for snapshot in listed.as_array().unwrap() {
        for entry in snapshot["entries"].as_array().into_iter().flatten() {
            assert_ne!(entry["path"], "box/.env", "{snapshot}");
        }
    }
    git(&repo, &["checkout", "-q", "-f", &start]);

    // A file added to that folder since is newer work, and stays.
    git(&repo, &["reset", "-q", "--hard", "folder~1"]);
    std::fs::write(repo.join("box"), "edited\n").unwrap();
    let id = saved("git checkout -f folder");
    git(&repo, &["checkout", "-q", "-f", "folder"]);
    std::fs::write(repo.join("box/newer"), "newer\n").unwrap();
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(!undone.status.success(), "{undone:?}");
    assert_eq!(
        std::fs::read_to_string(repo.join("box/newer")).unwrap(),
        "newer\n"
    );

    // Staged and unstaged files under the folder come back over the file a
    // forced checkout staged.
    std::fs::remove_file(repo.join("box/newer")).unwrap();
    git(&repo, &["checkout", "-q", "-f", "folder"]);
    std::fs::write(repo.join("box/child"), "staged\n").unwrap();
    git(&repo, &["add", "box/child"]);
    std::fs::write(repo.join("box/child"), "unstaged\n").unwrap();
    let staged = index();
    let id = saved(&format!("git checkout -f {start}"));
    git(&repo, &["checkout", "-q", "-f", &start]);
    let undone = support::nah(&home, &repo, &["undo", &id], None);
    assert!(undone.status.success(), "{undone:?}");
    assert_eq!(index(), staged);
    assert_eq!(
        std::fs::read_to_string(repo.join("box/child")).unwrap(),
        "unstaged\n"
    );
}

#[test]
fn the_rolling_copy_refreshes_after_calls_and_an_unfinished_decision_is_reported() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    std::fs::write(repo.join("src/lib.rs"), "pub fn written() {}\n").unwrap();
    let refreshed = hook(
        &home,
        Some("core"),
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": repo.join("src/lib.rs"), "content": "pub fn written() {}\n"},
            "tool_response": {},
            "cwd": repo,
            "session_id": "session-1",
        }),
    );
    assert!(refreshed.status.success() && refreshed.stdout.is_empty());
    let listed = support::nah(&home, &repo, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let latest = listed[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(listed[0]["summary"]["files"], 1);

    // As a hook killed while saving leaves it: its process is gone.
    let markers = home.join(".nah/save-then-run/unfinished");
    std::fs::create_dir_all(&markers).unwrap();
    std::fs::write(
        markers.join("killed.json"),
        json!({"pid": 999_999, "started_ms": 0, "command": "git reset --hard", "directory": repo})
            .to_string(),
    )
    .unwrap();
    let reply = bash(&home, Some("core"), &repo, "git status");
    let report = context(&reply);
    assert!(report.contains("`git reset --hard`"), "{report}");
    assert!(report.contains(&format!("nah undo {latest}")), "{report}");
    assert!(reply["systemMessage"].as_str().is_some(), "{reply}");
    // Reported once.
    assert!(bash(&home, Some("core"), &repo, "git status").is_null());

    // A refresh that saves also drops what retention no longer keeps: here
    // the earlier copy, as if saved and reported weeks ago. The report named
    // it, so retention would otherwise keep it 14 days from then.
    let store = std::fs::read_dir(home.join(".nah/snapshots"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let snapshot = store.join("snapshots").join(&latest);
    let manifest = snapshot.join("manifest.json");
    let mut aged: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    aged["created_ms"] = json!(0);
    std::fs::write(&manifest, aged.to_string()).unwrap();
    let named = snapshot.join("named");
    assert!(named.exists());
    std::fs::write(&named, "0").unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn rewritten() {}\n").unwrap();
    let refreshed = hook(
        &home,
        Some("core"),
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": repo.join("src/lib.rs"), "content": "pub fn rewritten() {}\n"},
            "tool_response": {},
            "cwd": repo,
            "session_id": "session-1",
        }),
    );
    assert!(refreshed.status.success() && refreshed.stdout.is_empty());
    let listed = listed_once_gone(&home, &repo, &latest);
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert!(!listed.contains(&latest), "{listed:?}");
}

/// The ids `nah snapshots` lists in `repo` once `gone` is no longer among
/// them, or after 30 seconds: retention runs in a process of its own.
fn listed_once_gone(home: &Path, repo: &Path, gone: &str) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let listed = support::nah(home, repo, &["snapshots", "--json"], None);
        let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
        let ids = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|snapshot| snapshot["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        if !ids.iter().any(|id| id == gone) || Instant::now() >= deadline {
            return ids;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_save_before_a_call_applies_retention_in_the_background() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let repo = support::repo(&home);
    // Branches whose commits nothing else reaches, made without moving HEAD.
    for branch in ["first", "second"] {
        let made = Command::new("git")
            .args([
                "-c",
                "user.name=nah test",
                "-c",
                "user.email=nah@example.invalid",
                "commit-tree",
                "HEAD^{tree}",
                "-p",
                "HEAD",
                "-m",
                branch,
            ])
            .current_dir(&repo)
            .output()
            .unwrap();
        let commit = String::from_utf8(made.stdout).unwrap();
        git(
            &repo,
            &["update-ref", &format!("refs/heads/{branch}"), commit.trim()],
        );
    }
    let save = |branch: &str| {
        let reply = bash(
            &home,
            Some("core"),
            &repo,
            &format!("git branch -D {branch}"),
        );
        assert!(denial(&reply).is_none(), "{reply}");
        git(&repo, &["branch", "-q", "-D", branch]);
        let id = snapshot_id(&home, Some("work/branch-delete"));
        assert_named_undo(&home, &repo, &id, &format!("git branch -D {branch}"));
        id
    };
    let first = save("first");
    let store = std::fs::read_dir(home.join(".nah/snapshots"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let manifest = store.join("snapshots").join(&first).join("manifest.json");
    let mut aged: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    aged["created_ms"] = json!(0);
    std::fs::write(&manifest, aged.to_string()).unwrap();
    // It was given as the branch delete's undo when saved, weeks ago too.
    std::fs::write(store.join("snapshots").join(&first).join("named"), "0").unwrap();

    // Saving only commits leaves no work-tree change for a refresh to save,
    // yet the save itself has retention run, in a process of its own.
    let second = save("second");
    let ids = listed_once_gone(&home, &repo, &first);
    assert_eq!(ids, [second]);
}

#[test]
fn undo_leaves_out_what_a_direct_write_would_be_blocked_on() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    // A home folder kept in git, as a dotfiles repository is.
    git(&home, &["init", "-q"]);
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude/settings.json"), "{}\n").unwrap();
    std::fs::write(home.join("notes.md"), "base\n").unwrap();
    // Nah's own state, the snapshot store included, lives in this home.
    std::fs::write(home.join(".gitignore"), ".nah/\n").unwrap();
    git(&home, &["add", "."]);
    git(
        &home,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "dotfiles",
        ],
    );
    std::fs::write(home.join(".claude/settings.json"), "{\"hooks\":{}}\n").unwrap();
    std::fs::write(home.join("notes.md"), "edited\n").unwrap();
    // Only the operator saves one directly.
    let refused = support::nah(&home, &home, &["snapshot", "save", "--json"], None);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!home.join(".nah/snapshots").exists());
    let saved = support::operator_output(
        Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(["snapshot", "save", "--json"])
            .current_dir(&home)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME"),
    );
    let saved: Value = serde_json::from_slice(&saved.stdout).unwrap();
    let id = saved["snapshot"]["id"].as_str().unwrap();
    git(&home, &["checkout", "-q", "--", "."]);

    let undone = support::nah(&home, &home, &["undo", id], None);
    let report = String::from_utf8_lossy(&undone.stdout);
    assert!(report.contains("left .claude/settings.json"), "{report}");
    assert_eq!(
        std::fs::read_to_string(home.join(".claude/settings.json")).unwrap(),
        "{}\n"
    );
    assert_eq!(
        std::fs::read_to_string(home.join("notes.md")).unwrap(),
        "edited\n"
    );

    // The agent may list and undo, but only the operator prunes.
    let refused = support::nah(&home, &home, &["snapshots", "prune", "--all"], None);
    assert!(!refused.status.success(), "{refused:?}");
    let listed = support::nah(&home, &home, &["snapshots", "--json"], None);
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(!listed.as_array().unwrap().is_empty());
    let pruned = support::operator_output(
        Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(["snapshots", "prune", "--all", "--json"])
            .current_dir(&home)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME"),
    );
    let pruned: Value = serde_json::from_slice(&pruned.stdout).unwrap();
    assert_eq!(pruned["kept"], 0, "{pruned}");
    let listed = support::nah(&home, &home, &["snapshots", "--json"], None);
    assert_eq!(
        serde_json::from_slice::<Value>(&listed.stdout).unwrap(),
        json!([])
    );
}

#[test]
fn the_installer_wires_the_refresh_and_a_dead_hook_follows_the_failure_policy() {
    let temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let hook_command = |args: &[&str]| -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
        command
            .args(["hook", "claude"])
            .args(args)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = if args == ["uninstall"] || args.contains(&"--fail-open") {
            support::operator_output(&mut command)
        } else {
            command.output().unwrap()
        };
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let settings_path = home.join(".claude/settings.json");
    let settings =
        || -> Value { serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap() };

    // Fail-open lets a call the hook never answers run, as in 1.x.
    hook_command(&["install"]);
    let installed = settings();
    let pre = &installed["hooks"]["PreToolUse"][0]["hooks"][0];
    assert!(pre.get("onFailure").is_none(), "{pre}");
    let post = &installed["hooks"]["PostToolUse"][0];
    assert_eq!(post["hooks"][0]["async"], true);
    assert_eq!(post["hooks"][0]["args"], json!(["hook", "claude", "run"]));
    assert!(post["matcher"].as_str().unwrap().contains("Write"));

    // A fail-open install that blocks a dead hook, as 2.0-dev wrote it, needs
    // reinstalling, and reinstalling keeps fail-open and drops the block.
    let mut dev_install = installed.clone();
    dev_install["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"] = json!("block");
    std::fs::write(&settings_path, serde_json::to_vec(&dev_install).unwrap()).unwrap();
    let status = hook_command(&["status"]);
    assert!(status.contains("reinstall required"), "{status}");
    assert!(
        status.contains("detected failure policy: fail-open"),
        "{status}"
    );
    hook_command(&["install"]);
    assert_eq!(settings(), installed);

    // Fail-closed has Claude Code block it.
    hook_command(&["install", "--fail-closed"]);
    let pre = settings()["hooks"]["PreToolUse"][0]["hooks"][0].clone();
    assert_eq!(pre["onFailure"], "block");
    assert!(hook_command(&["status"]).contains("failure policy: fail-closed"));
    // And one without the block needs reinstalling.
    let mut unblocked = settings();
    unblocked["hooks"]["PreToolUse"][0]["hooks"][0]
        .as_object_mut()
        .unwrap()
        .remove("onFailure");
    std::fs::write(&settings_path, serde_json::to_vec(&unblocked).unwrap()).unwrap();
    let status = hook_command(&["status"]);
    assert!(status.contains("reinstall required"), "{status}");
    assert!(
        status.contains("detected failure policy: fail-closed"),
        "{status}"
    );

    hook_command(&["uninstall"]);
    assert!(settings().get("hooks").is_none(), "{}", settings());
}
