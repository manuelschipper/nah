#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};

use nah_proto::decision::{DecisionOutput, Verdict};
use serde_json::json;

use support::repo;

const LEGACY_SETTINGS: &str = "{\"v\":2,\"overrides\":{\"git-hard-reset\":false}}\n";

fn nah(home: &std::path::Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    run_nah(home, command.args(args), stdin)
}

fn run_nah(
    home: &std::path::Path,
    command: &mut Command,
    stdin: Option<&str>,
) -> std::process::Output {
    command
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

#[test]
fn decide_writes_a_redacted_log_which_drives_why_and_log() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {
            "command": "curl -H 'Authorization: ordinary-planted-value' api.example.com"
        },
        "cwd": project,
    })
    .to_string();

    let decided = nah(&root, &["decide"], Some(&payload));
    assert!(decided.status.code().is_some(), "{decided:?}");
    let output: DecisionOutput = serde_json::from_slice(&decided.stdout).unwrap();
    let log_path = &root.join(".nah/audit.jsonl");
    let bytes = std::fs::read_to_string(log_path).unwrap();
    assert!(!bytes.contains("ordinary-planted-value"));
    assert!(!bytes.contains("api.example.com"));
    assert!(bytes.contains("[redacted]"));

    let why = nah(&root, &["why", output.id()], None);
    assert!(why.status.success(), "{why:?}");
    let why = String::from_utf8(why.stdout).unwrap();
    assert!(why.contains(&format!("id:       {}", output.id())));
    assert!(!why.contains("decision decision-"));
    assert!(why.contains("command:  Bash [redacted]"));
    assert!(!why.contains("ordinary-planted-value"));
    assert!(!why.contains("api.example.com"));

    let listed = nah(&root, &["log", "-n", "1"], None);
    assert!(listed.status.success(), "{listed:?}");
    let listed = String::from_utf8(listed.stdout).unwrap();
    assert!(listed.contains(output.id()));
    assert!(listed.contains("[redacted]"));
    // The masked command leaves the row nothing to scan, so it reads the
    // effects, which crossed the same boundary.
    assert!(listed.contains("Bash: process.exec curl"), "{listed}");
    assert!(!listed.contains("ordinary-planted-value"), "{listed}");
    assert!(!listed.contains("api.example.com"), "{listed}");

    let json_log = nah(&root, &["log", "--json", "-n", "1"], None);
    assert!(json_log.status.success(), "{json_log:?}");
    let json: serde_json::Value = serde_json::from_slice(&json_log.stdout).unwrap();
    assert_eq!(json["schema"], "nah/audit/v1");
    assert_eq!(json["envelope"]["id"], output.id());
    assert_eq!(json["command"], "Bash [redacted]");
    assert!(!String::from_utf8_lossy(&json_log.stdout).contains("ordinary-planted-value"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(log_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn blocked_inline_source_never_reaches_the_audit_log() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {
            "command": "python3 -c \"import shutil; marker='inline-planted-secret'; shutil.rmtree('/')\""
        },
        "cwd": project,
    })
    .to_string();

    let decided = nah(&root, &["decide"], Some(&payload));
    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    let bytes = std::fs::read_to_string(root.join(".nah/audit.jsonl")).unwrap();
    assert!(!bytes.contains("inline-planted-secret"));
    assert!(!bytes.contains("shutil.rmtree"));
    assert!(bytes.contains("Bash [redacted]"));
}

#[test]
fn blocked_log_lists_the_last_blocks_independently() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = support::repo_with_work(&root);
    let decide = |command: &str| {
        let payload = json!({
            "v": 1,
            "tool": "Bash",
            "input": {"command": command},
            "cwd": project,
        })
        .to_string();
        let output = nah(&root, &["decide"], Some(&payload));
        serde_json::from_slice::<DecisionOutput>(&output.stdout).unwrap()
    };

    let old_block = decide("rm -rf /");
    for index in 0..25 {
        decide(&format!("echo {index}"));
    }
    let new_block = decide("git reset --hard");
    decide("echo latest");

    let latest = nah(&root, &["log", "--blocked", "-n", "1"], None);
    assert!(latest.status.success(), "{latest:?}");
    let latest = String::from_utf8(latest.stdout).unwrap();
    assert!(latest.contains(new_block.id()), "{latest}");
    assert!(!latest.contains(old_block.id()), "{latest}");

    let json_log = nah(&root, &["log", "--blocked", "--json", "-n", "2"], None);
    assert!(json_log.status.success(), "{json_log:?}");
    let records = String::from_utf8(json_log.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["core"]["verdict"], "block");
    assert_eq!(records[1]["core"]["verdict"], "block");
    assert_eq!(records[0]["envelope"]["id"], old_block.id());
    assert_eq!(records[1]["envelope"]["id"], new_block.id());
}

#[test]
fn adapters_record_the_runtime_that_decided_and_decide_records_none() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let hook_payload = |command: &str| {
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": project,
            "session_id": "session-1",
        })
        .to_string()
    };

    let claude = nah(
        &root,
        &["hook", "claude", "run"],
        Some(&hook_payload("echo one")),
    );
    assert!(claude.status.success(), "{claude:?}");
    let codex = nah(
        &root,
        &["hook", "codex", "run"],
        Some(&hook_payload("echo two")),
    );
    assert!(codex.status.success(), "{codex:?}");
    // Generic `nah decide` cannot know which runtime sent the call, and the
    // runtime is not a wire field a caller can name for itself.
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "echo three"},
        "cwd": project,
        "runtime": "planted-runtime",
    })
    .to_string();
    let decided = nah(&root, &["decide"], Some(&payload));
    assert!(decided.status.code().is_some(), "{decided:?}");

    let recorded = std::fs::read_to_string(root.join(".nah/audit.jsonl")).unwrap();
    let runtimes = recorded
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["runtime"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(runtimes, ["claude", "codex", "unknown"]);
    assert!(!recorded.contains("planted-runtime"), "{recorded}");

    // Both human views carry it: a column in the listing, a line in the detail.
    let listed = nah(&root, &["log", "-n", "3"], None);
    assert!(listed.status.success(), "{listed:?}");
    let listed = String::from_utf8(listed.stdout).unwrap();
    // An inert echo states no effect, so the masked command is all the row has.
    assert!(listed.contains("claude      Bash [redacted]"), "{listed}");
    let codex_tool = if cfg!(windows) {
        "CodexWindowsShell"
    } else {
        "Bash [redacted]"
    };
    assert!(
        listed.contains(&format!("codex       {codex_tool}")),
        "{listed}"
    );
    assert!(listed.contains("unknown     Bash [redacted]"), "{listed}");

    let id = serde_json::from_str::<serde_json::Value>(recorded.lines().next().unwrap()).unwrap()
        ["envelope"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let why = nah(&root, &["why", &id], None);
    assert!(why.status.success(), "{why:?}");
    assert!(
        String::from_utf8(why.stdout)
            .unwrap()
            .contains("\nruntime:  claude\n"),
        "{id}"
    );
}

#[test]
fn why_fails_loudly_for_missing_or_corrupt_records() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let missing = nah(&root, &["why", "missing"], None);
    assert_eq!(missing.status.code(), Some(2));
    let error = String::from_utf8_lossy(&missing.stderr);
    assert!(error.contains("was not found"));
    assert!(error.contains("run `nah log` to list recent decision IDs"));

    let directory = &root.join(".nah");
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("audit.jsonl"), "not-json\n").unwrap();
    let corrupt = nah(&root, &["why", "missing"], None);
    assert_eq!(corrupt.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&corrupt.stderr).contains("invalid-audit-record"));
}

#[test]
fn log_archives_unreadable_input_and_lists_the_readable_records() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "echo hello"},
        "cwd": project,
    })
    .to_string();
    let first: DecisionOutput =
        serde_json::from_slice(&nah(&root, &["decide"], Some(&payload)).stdout).unwrap();
    let audit = root.join(".nah/audit.jsonl");
    OpenOptions::new()
        .append(true)
        .open(&audit)
        .unwrap()
        .write_all(b"not-json\n")
        .unwrap();
    let latest: DecisionOutput =
        serde_json::from_slice(&nah(&root, &["decide"], Some(&payload)).stdout).unwrap();
    let original = std::fs::read(&audit).unwrap();

    let listed = nah(&root, &["log", "--json", "-n", "10"], None);
    assert!(listed.status.success(), "{listed:?}");
    let ids = String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["envelope"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, [first.id(), latest.id()]);
    assert!(!listed.stderr.is_empty());

    let backups = std::fs::read_dir(root.join(".nah/old_logs"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read(backups[0].path()).unwrap(), original);
    assert!(
        std::fs::read_to_string(audit)
            .unwrap()
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );
}

#[test]
fn an_empty_human_log_explains_itself_while_json_stays_empty() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());

    let human = nah(&root, &["log"], None);
    assert!(human.status.success(), "{human:?}");
    assert_eq!(human.stdout, b"No decisions recorded.\n");

    let json = nah(&root, &["log", "--json"], None);
    assert!(json.status.success(), "{json:?}");
    assert!(json.stdout.is_empty());

    let blocked = nah(&root, &["log", "--blocked"], None);
    assert!(blocked.status.success(), "{blocked:?}");
    assert_eq!(blocked.stdout, b"No blocked decisions recorded.\n");
}

#[test]
fn opaque_native_payloads_are_redacted_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let payload = json!({
        "v": 1,
        "tool": "VendorTool",
        "input": {"operation": "inspect", "token": "planted-secret"},
        "cwd": project,
    })
    .to_string();

    let decided = nah(&root, &["decide"], Some(&payload));
    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    let bytes = std::fs::read_to_string(root.join(".nah/audit.jsonl")).unwrap();
    assert!(!bytes.contains("planted-secret"));
    assert!(bytes.contains("VendorTool [redacted]"));
}

#[test]
fn damaged_state_is_logged_without_exposing_the_command() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let config = &root.join(".nah");
    std::fs::create_dir_all(config).unwrap();
    std::fs::write(config.join("built-ins.json"), "not-json").unwrap();
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "echo planted-secret"},
        "cwd": project,
    })
    .to_string();

    let decided = nah(&root, &["decide"], Some(&payload));
    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    let bytes = std::fs::read_to_string(config.join("audit.jsonl")).unwrap();
    assert!(!bytes.contains("planted-secret"));
    let audit: serde_json::Value = serde_json::from_str(bytes.trim()).unwrap();
    let id = audit["envelope"]["id"].as_str().unwrap();
    assert_eq!(audit["status"], "decision");
    assert_eq!(audit["core"]["verdict"], "delegate");
    assert_eq!(audit["command"], "Bash [redacted]");
    assert_eq!(audit["failures"][0]["source"], "nah");
    assert_eq!(audit["failures"][0]["component"], "built-ins.json");
    assert_eq!(audit["failures"][0]["code"], "invalid-shipped-state");
    let diagnostic = audit["diagnostics"][0].as_str().unwrap();
    assert!(diagnostic.contains("~/.nah/built-ins.json"), "{diagnostic}");
    assert!(diagnostic.contains("invalid-shipped-state"), "{diagnostic}");

    let why = nah(&root, &["why", id], None);
    assert!(why.status.success(), "{why:?}");
    let why = String::from_utf8(why.stdout).unwrap();
    assert!(
        why.contains("nah/built-ins.json/invalid-shipped-state"),
        "{why}"
    );
    assert!(why.contains("~/.nah/built-ins.json"), "{why}");
    assert!(!why.contains("planted-secret"));
}

#[test]
fn audit_failure_never_changes_the_policy_verdict() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let config = root.join(".nah");
    let audit = config.join("audit.jsonl");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::write(config.join("built-ins.json"), LEGACY_SETTINGS).unwrap();
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "rm -rf /"},
        "cwd": project,
    })
    .to_string();

    let decided = nah(&root, &["decide"], Some(&payload));
    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    let output: DecisionOutput = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(output.verdict(), Verdict::Block);
    let stderr = String::from_utf8(decided.stderr).unwrap();
    assert!(stderr.contains("audit failed: audit-io-failed"));
    assert!(stderr.contains("audit fallback failed: audit-io-failed"));
    assert!(config.join("1x-import-pending.txt").is_file());

    std::fs::rename(&audit, config.join("blocked-audit-path")).unwrap();
    let retried = nah(&root, &["decide"], Some(&payload));
    assert_eq!(retried.status.code(), Some(1), "{retried:?}");
    assert!(!config.join("1x-import-pending.txt").exists());
    let row = std::fs::read_to_string(audit).unwrap();
    assert_eq!(row.matches("imported the nah 1.x configuration").count(), 1);
}

#[cfg(unix)]
#[test]
fn an_audit_fallback_that_records_the_import_does_not_requeue_it() {
    let temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(temp.path());
    let project = repo(&home);
    let config = home.join(".nah");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(config.join("built-ins.json"), LEGACY_SETTINGS).unwrap();
    let imported = nah(&home, &["guards"], None);
    assert!(imported.status.success(), "{imported:?}");

    // The runtime only plans these mkdirs. Their effects make the primary
    // row larger than the child's file size limit, while the fallback fits.
    let command = (0..80)
        .map(|index| format!("mkdir dir-{index}"))
        .collect::<Vec<_>>()
        .join(" && ");
    let mut payload =
        json!({"v": 1, "tool": "Bash", "input": {"command": command}, "cwd": project});
    let mut limited = Command::new("bash");
    limited.args([
        "-c",
        r#"ulimit -f 4 && trap '' XFSZ && exec "$@""#,
        "audit-test",
        env!("CARGO_BIN_EXE_nah"),
        "decide",
    ]);
    let first = run_nah(&home, &mut limited, Some(&payload.to_string()));
    assert_eq!(first.status.code(), Some(2), "{first:?}");
    let warnings = String::from_utf8(first.stderr).unwrap();
    assert!(
        warnings.contains("audit failed: audit-io-failed"),
        "{warnings}"
    );
    assert!(!warnings.contains("audit fallback failed"), "{warnings}");

    payload["input"]["command"] = json!("echo done");
    let next = nah(&home, &["decide"], Some(&payload.to_string()));
    assert_eq!(next.status.code(), Some(2), "{next:?}");
    assert!(!config.join("1x-import-pending.txt").exists());
    let audit = std::fs::read_to_string(config.join("audit.jsonl")).unwrap();
    let mut rows = audit.lines();
    let fallback = rows.next().unwrap();
    assert!(
        fallback.contains("audit failed: audit-io-failed"),
        "{fallback}"
    );
    assert!(
        fallback.contains("imported the nah 1.x configuration"),
        "{fallback}"
    );
    assert!(
        !rows
            .next()
            .unwrap()
            .contains("imported the nah 1.x configuration")
    );
    assert!(rows.next().is_none());
}

/// A stopped Nah process, such as one in a suspended terminal, can hold the
/// settings lock indefinitely. The hook waits for it only briefly, then
/// answers without failing the call, so even a fail-closed hook lets a
/// harmless call through, while the settings as they stand keep blocking
/// what they block: a 1.x file read as its import would write it, or the
/// current settings beside a 1.x nap. The import runs on a later call once
/// the lock is free.
#[test]
fn a_held_settings_lock_never_stalls_the_hook() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Each deletes container volumes, which the shipped defaults let through:
    // 1.x's `infra-container-volume-delete` shipped off, and `infrastructure`
    // at strict blocks the same delete.
    for (case, settings) in [
        (
            "legacy-settings",
            "{\"v\":2,\"overrides\":{\"infra-container-volume-delete\":true}}\n",
        ),
        (
            "legacy-nap",
            "{\"v\":3,\"guards\":{\"infrastructure\":\"strict\"},\"rules\":{}}\n",
        ),
    ] {
        let home = root.join(case);
        let config = home.join(".nah");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("built-ins.json"), settings).unwrap();
        if case == "legacy-nap" {
            support::write_signed_nap(&home, 2, json!("self-protection"), now, now + 600);
        }
        let imported = || match case {
            "legacy-settings" => config.join("built-ins.json.1x").is_file(),
            _ => std::fs::read_to_string(config.join("nap.json"))
                .unwrap()
                .contains("\"v\":3"),
        };
        let held = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(config.join("built-ins.lock"))
            .unwrap();
        File::lock(&held).unwrap();
        for (command, verdict) in [
            ("echo held", "delegate"),
            ("docker compose down -v", "block"),
        ] {
            let record = fail_closed_hook_record(&home, &project, command);
            assert_eq!(record["core"]["verdict"], verdict, "{case}: {record}");
            assert!(record.get("failures").is_none(), "{case}: {record}");
            assert!(
                record["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|diagnostic| diagnostic.as_str().unwrap().contains("on a later call")),
                "{case}: {record}"
            );
        }
        assert!(!imported(), "{case}");

        File::unlock(&held).unwrap();
        let record = fail_closed_hook_record(&home, &project, "docker compose down -v");
        assert_eq!(record["core"]["verdict"], "block", "{case}: {record}");
        assert!(imported(), "{case}");
        if case == "legacy-settings" {
            assert!(
                record
                    .to_string()
                    .contains("imported the nah 1.x configuration"),
                "{record}"
            );
        }
    }
}

/// Runs Claude Code's fail-closed hook on `command` and returns the audit
/// record it wrote. A hook that waited for a held lock would never answer;
/// the ceiling only keeps such a failure from hanging the suite.
fn fail_closed_hook_record(
    home: &std::path::Path,
    project: &std::path::Path,
    command: &str,
) -> serde_json::Value {
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": project,
        "session_id": "session-1"
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "claude", "run", "--fail-closed"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let ceiling = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > ceiling {
            child.kill().unwrap();
            panic!("the hook waited on a held lock");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let audit = std::fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
    serde_json::from_str(audit.lines().last().unwrap()).unwrap()
}

#[test]
fn concurrent_first_decisions_each_write_a_normal_audit_row() {
    use std::sync::Barrier;

    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let payload =
        json!({"v": 1, "tool": "Bash", "input": {"command": "echo audit"}, "cwd": project})
            .to_string();
    for trial in 0..12 {
        let home = root.join(format!("home-{trial}"));
        std::fs::create_dir(&home).unwrap();
        let legacy = trial % 2 == 1;
        if legacy {
            std::fs::create_dir(home.join(".nah")).unwrap();
            std::fs::write(home.join(".nah/built-ins.json"), LEGACY_SETTINGS).unwrap();
        }
        let start = Barrier::new(3);
        let mut ids = std::thread::scope(|scope| {
            let workers = (0..3)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        nah(&home, &["decide"], Some(&payload))
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| {
                    let output = worker.join().unwrap();
                    assert_eq!(output.status.code(), Some(2), "{output:?}");
                    assert!(
                        !String::from_utf8_lossy(&output.stderr).contains("audit failed"),
                        "{output:?}"
                    );
                    let decision: DecisionOutput = serde_json::from_slice(&output.stdout).unwrap();
                    decision.id().to_owned()
                })
                .collect::<Vec<_>>()
        });
        ids.sort_unstable();
        let audit = std::fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
        let rows = audit
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let mut logged = rows
            .iter()
            .map(|row| row["envelope"]["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        logged.sort_unstable();
        assert_eq!(logged, ids);
        assert_eq!(
            audit.matches("imported the nah 1.x configuration").count(),
            usize::from(legacy)
        );
        assert!(!home.join(".nah/1x-import-pending.txt").exists());
    }
}

#[test]
fn audit_lock_contention_never_stalls_a_decision() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let directory = &root.join(".nah");
    std::fs::create_dir_all(directory).unwrap();
    let held = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("audit.jsonl"))
        .unwrap();
    File::lock(&held).unwrap();
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "rm -rf /"},
        "cwd": project,
    })
    .to_string();

    // The lock stays held until nah returns, so a blocking acquisition would
    // never return; the failure code below proves the bounded wait gave up,
    // without a fallback append to the same held log.
    let decided = nah(&root, &["decide"], Some(&payload));

    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    let output: DecisionOutput = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(output.verdict(), Verdict::Block);
    let stderr = String::from_utf8(decided.stderr).unwrap();
    assert!(stderr.contains("audit failed: audit-lock-contended"));
    assert!(!stderr.contains("audit fallback failed"));
    File::unlock(&held).unwrap();
}

#[cfg(unix)]
#[test]
fn audit_symlinks_never_modify_their_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for parent_symlink in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        // macOS temp directories sit under a symlinked /var, and nah resolves
        // paths before matching them
        let root = support::test_temp_path(temp.path());
        let project = repo(&root);
        let victim_directory = &root.join("victim");
        std::fs::create_dir_all(victim_directory).unwrap();
        let victim = victim_directory.join("audit.jsonl");
        let original = b"victim bytes\n";
        std::fs::write(&victim, original).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();

        if parent_symlink {
            symlink(victim_directory, root.join(".nah")).unwrap();
        } else {
            let directory = &root.join(".nah");
            std::fs::create_dir_all(directory).unwrap();
            symlink(&victim, directory.join("audit.jsonl")).unwrap();
        }
        let payload = json!({
            "v": 1,
            "tool": "Bash",
            "input": {"command": "rm -rf /"},
            "cwd": project,
        })
        .to_string();

        let decided = nah(&root, &["decide"], Some(&payload));

        assert_eq!(decided.status.code(), Some(1), "{decided:?}");
        assert_eq!(std::fs::read(&victim).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}

#[cfg(any(unix, windows))]
#[test]
fn audit_hard_link_never_modifies_its_target() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let project = repo(&root);
    let directory = &root.join(".nah");
    std::fs::create_dir_all(directory).unwrap();
    let victim = &root.join("victim");
    let original = b"victim bytes\n";
    std::fs::write(victim, original).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(victim, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    std::fs::hard_link(victim, directory.join("audit.jsonl")).unwrap();
    let payload = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "rm -rf /"},
        "cwd": project,
    })
    .to_string();

    let decided = nah(&root, &["decide"], Some(&payload));

    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    assert_eq!(std::fs::read(victim).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
