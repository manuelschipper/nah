// UNDOCUMENTED-EFFINTERP: coverage for the hidden `nah daemon` snapshot publisher.
#![cfg(feature = "effinterp")]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

// UNDOCUMENTED-EFFINTERP: shared CLI fixture construction for daemon integration tests.
mod support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use support::repo;

// UNDOCUMENTED-EFFINTERP: the fixture's shell script entrypoint, mutated to force a rebuild.
const CLEAN_SCRIPT: &str = r#"{"scripts":{"clean":"rm -rf dist","build":"tsc -p ."}}"#;
// UNDOCUMENTED-EFFINTERP: a background daemon's first publication bounds every wait in this file.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

// UNDOCUMENTED-EFFINTERP: run the feature-enabled binary against one isolated home.
fn nah(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap()
}

// UNDOCUMENTED-EFFINTERP: give each daemon test an independent trust and storage directory.
fn temp_home(temp: &Path) -> PathBuf {
    let home = temp.join("home");
    std::fs::create_dir_all(&home).unwrap();
    home
}

// UNDOCUMENTED-EFFINTERP: authorize one fixture through the same CLI boundary as users.
fn trust(home: &Path, root: &Path) {
    let output = nah(home, &["trust", root.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
}

// UNDOCUMENTED-EFFINTERP: revoke one fixture through the live trust database boundary.
fn untrust(home: &Path, root: &Path) {
    let output = nah(home, &["untrust", root.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
}

// UNDOCUMENTED-EFFINTERP: load and validate the snapshot visible to a later consultation.
fn published(home: &Path, root: &Path) -> nah_effinterp::PublishedSnapshotVerification {
    nah_effinterp::verify_published_snapshot(home, root)
        .expect("a published snapshot loads")
        .expect("the daemon published a snapshot")
}

/// Starts a foreground daemon and waits until its first publication is visible.
/// Readiness is read from the daemon's own `status.json`: opening the storage from a
/// second process runs recovery, which would race the publication this wait is waiting
/// for.
// UNDOCUMENTED-EFFINTERP: start the foreground daemon and wait for its initial publication.
fn spawn_daemon(home: &Path, root: &Path, poll_seconds: u64) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["daemon", "run", "--poll", &poll_seconds.to_string()])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    if wait_for_snapshot_status(home, root) {
        return child;
    }
    child.kill().unwrap();
    child.wait().unwrap();
    panic!("the background daemon never published a snapshot");
}

// UNDOCUMENTED-EFFINTERP: bound asynchronous publication waits with daemon-owned status.
fn wait_for_snapshot_status(home: &Path, root: &Path) -> bool {
    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if root_status(home, root)
            .map(|status| !status["snapshot_id"].is_null())
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// UNDOCUMENTED-EFFINTERP: a published snapshot must load and still describe the tree exactly.
#[test]
fn daemon_run_once_publishes_a_snapshot_matching_the_working_tree() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);

    let output = nah(&home, &["daemon", "run", "--once"]);
    assert!(output.status.success(), "{output:?}");

    let snapshot = published(&home, &root);
    assert_eq!(snapshot.generation, 1);
    assert!(snapshot.matches_working_tree);
}

// UNDOCUMENTED-EFFINTERP: a source change must reach a new publication, not a stale reuse.
#[test]
fn daemon_run_once_publishes_a_new_generation_after_a_source_change() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);

    assert!(nah(&home, &["daemon", "run", "--once"]).status.success());
    let first = published(&home, &root);

    std::fs::write(root.join("package.json"), CLEAN_SCRIPT).unwrap();
    assert!(nah(&home, &["daemon", "run", "--once"]).status.success());
    let second = published(&home, &root);

    assert!(second.generation > first.generation);
    assert_ne!(second.snapshot_id, first.snapshot_id);
    assert!(second.matches_working_tree);
}

// UNDOCUMENTED-EFFINTERP: the advisory lock is the only admission control for a second daemon.
#[test]
fn daemon_run_refuses_a_second_concurrent_daemon() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);

    let mut daemon = spawn_daemon(&home, &root, 3_600);
    let refused = nah(&home, &["daemon", "run", "--once"]);
    assert_eq!(nah(&home, &["daemon", "stop"]).status.code(), Some(0));
    daemon.wait().unwrap();

    assert_eq!(refused.status.code(), Some(2));
}

// UNDOCUMENTED-EFFINTERP: stop is the only supported shutdown, and says when nothing runs.
#[test]
fn daemon_stop_reports_whether_a_daemon_was_running() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);

    assert_eq!(nah(&home, &["daemon", "stop"]).status.code(), Some(1));

    let mut daemon = spawn_daemon(&home, &root, 3_600);
    assert_eq!(nah(&home, &["daemon", "stop"]).status.code(), Some(0));
    assert!(daemon.wait().unwrap().success());

    assert_eq!(nah(&home, &["daemon", "stop"]).status.code(), Some(1));
}

// UNDOCUMENTED-EFFINTERP: status answers without a daemon and carries the build's measured cost.
#[test]
fn daemon_status_reports_each_trusted_root_with_its_snapshot_and_build_cost() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);
    assert!(nah(&home, &["daemon", "run", "--once"]).status.success());
    let snapshot = published(&home, &root);

    let output = nah(&home, &["daemon", "status"]);
    assert!(output.status.success(), "{output:?}");
    let listing = String::from_utf8(output.stdout).unwrap();
    let line = listing
        .lines()
        .find(|line| line.contains(root.to_str().unwrap()))
        .expect("status lists the trusted root");

    assert!(line.contains(&format!("snapshot={}", snapshot.snapshot_id)));
    let peak = field(line, "peak_rss=");
    let duration = field(line, "duration=");
    assert!(peak.ends_with("KiB") && peak != "-", "{line}");
    assert!(duration.ends_with("ms") && duration != "-", "{line}");
}

// UNDOCUMENTED-EFFINTERP: status must not run storage recovery beside a live publisher.
#[test]
fn daemon_status_does_not_touch_snapshot_storage() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);
    assert!(nah(&home, &["daemon", "run", "--once"]).status.success());

    let staging = root_daemon_directory(&home, &root)
        .unwrap()
        .join("storage/staging/status-sentinel");
    std::fs::write(&staging, b"incomplete publication").unwrap();

    assert!(nah(&home, &["daemon", "status"]).status.success());
    assert!(staging.is_file());
}

// UNDOCUMENTED-EFFINTERP: one unusable root must never cost the other trusted roots a snapshot.
#[test]
fn daemon_isolates_a_deleted_trusted_root_from_a_valid_one() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    let deleted = temp.path().join("deleted");
    std::fs::create_dir_all(&deleted).unwrap();
    trust(&home, &root);
    trust(&home, &deleted);
    std::fs::remove_dir(&deleted).unwrap();

    let output = nah(&home, &["daemon", "run", "--once"]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains(deleted.to_str().unwrap())
    );
    assert!(published(&home, &root).matches_working_tree);
}

// UNDOCUMENTED-EFFINTERP: one unreadable crawl fails without suppressing a sibling publish.
#[cfg(unix)]
#[test]
fn daemon_isolates_an_unreadable_trusted_root_from_a_valid_one() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let valid = repo(temp.path());
    let unreadable_parent = temp.path().join("unreadable-parent");
    std::fs::create_dir(&unreadable_parent).unwrap();
    let unreadable = repo(&unreadable_parent);
    trust(&home, &valid);
    trust(&home, &unreadable);

    let original_permissions = std::fs::metadata(&unreadable).unwrap().permissions();
    let mut unreadable_permissions = original_permissions.clone();
    unreadable_permissions.set_mode(0o000);
    std::fs::set_permissions(&unreadable, unreadable_permissions).unwrap();
    let output = nah(&home, &["daemon", "run", "--once"]);
    std::fs::set_permissions(&unreadable, original_permissions).unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(last_error(&home, &unreadable).is_some());
    assert!(published(&home, &valid).matches_working_tree);
    assert!(
        nah_effinterp::verify_published_snapshot(&home, &unreadable)
            .unwrap()
            .is_none()
    );
}

// UNDOCUMENTED-EFFINTERP: each poll must drop revoked roots and initialize newly trusted roots.
#[test]
fn daemon_reloads_trusted_roots_before_each_poll() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let revoked = repo(temp.path());
    let added_parent = temp.path().join("added-parent");
    std::fs::create_dir(&added_parent).unwrap();
    let added = repo(&added_parent);
    trust(&home, &revoked);

    let mut daemon = spawn_daemon(&home, &revoked, 1);
    let before = root_status(&home, &revoked).unwrap();
    untrust(&home, &revoked);
    std::fs::write(revoked.join("package.json"), CLEAN_SCRIPT).unwrap();
    trust(&home, &added);
    if !wait_for_snapshot_status(&home, &added) {
        let _ = nah(&home, &["daemon", "stop"]);
        let _ = daemon.wait();
        panic!("the daemon never published the newly trusted root");
    }
    std::thread::sleep(Duration::from_millis(1_200));
    assert_eq!(nah(&home, &["daemon", "stop"]).status.code(), Some(0));
    assert!(daemon.wait().unwrap().success());

    let after = root_status(&home, &revoked).unwrap();
    assert_eq!(after["snapshot_id"], before["snapshot_id"]);
    assert_eq!(after["generation"], before["generation"]);
    assert!(published(&home, &added).matches_working_tree);
}

// UNDOCUMENTED-EFFINTERP: running the daemon is opt-in and does nothing before `nah trust`.
#[test]
fn daemon_run_without_trusted_roots_exits_zero_with_a_note() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());

    let output = nah(&home, &["daemon", "run", "--once"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(!output.stderr.is_empty());
    assert!(output.stdout.is_empty());
}

// UNDOCUMENTED-EFFINTERP: a build killed by its address-space ceiling is a recoverable per-path error.
#[test]
fn daemon_build_failure_under_a_memory_cap_is_recorded_per_root() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let first = repo(temp.path());
    let second = temp.path().join("second");
    std::fs::create_dir_all(second.join("src")).unwrap();
    std::fs::write(second.join("package.json"), CLEAN_SCRIPT).unwrap();
    trust(&home, &first);
    trust(&home, &second);

    // 64 MiB is below the address space any build needs, so both roots fail; the
    // run still exits 0 and each root keeps its own error.
    let capped = nah(&home, &["daemon", "run", "--once", "--max-memory", "64"]);
    assert_eq!(capped.status.code(), Some(0), "{capped:?}");
    for root in [&first, &second] {
        assert!(last_error(&home, root).is_some());
        assert!(
            nah_effinterp::verify_published_snapshot(&home, root)
                .unwrap()
                .is_none()
        );
    }

    // Removing the cap clears both errors, proving the failures were not durable state.
    assert!(nah(&home, &["daemon", "run", "--once"]).status.success());
    for root in [&first, &second] {
        assert_eq!(last_error(&home, root), None);
        assert!(published(&home, root).matches_working_tree);
    }
}

// UNDOCUMENTED-EFFINTERP: the parent must never hold a built index; only the child pays for one.
#[cfg(target_os = "linux")]
#[test]
fn daemon_parent_stays_below_the_build_child_peak() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp_home(temp.path());
    let root = repo(temp.path());
    trust(&home, &root);

    let mut daemon = spawn_daemon(&home, &root, 3_600);
    let parent_peak_kib = peak_rss_kib(daemon.id());
    assert_eq!(nah(&home, &["daemon", "stop"]).status.code(), Some(0));
    daemon.wait().unwrap();

    let child_peak_kib = root_status(&home, &root)
        .and_then(|status| status["build_peak_rss_kib"].as_u64())
        .expect("the daemon measured its build child");
    assert!(
        parent_peak_kib < child_peak_kib,
        "parent peak {parent_peak_kib} KiB is not below child peak {child_peak_kib} KiB"
    );
}

// UNDOCUMENTED-EFFINTERP: the kernel's high-water mark is the only live parent RSS measurement.
#[cfg(target_os = "linux")]
fn peak_rss_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .expect("VmHWM is reported for a live process")
}

// UNDOCUMENTED-EFFINTERP: select one named field from the human status line.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key))
        .unwrap_or_else(|| panic!("{key} missing from {line}"))
}

// UNDOCUMENTED-EFFINTERP: expose one root's persisted error without opening storage.
fn last_error(home: &Path, root: &Path) -> Option<String> {
    let status = root_status(home, root)?;
    status
        .get("last_error")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

// UNDOCUMENTED-EFFINTERP: read one root's persisted status without invoking recovery.
fn root_status(home: &Path, root: &Path) -> Option<serde_json::Value> {
    let directory = root_daemon_directory(home, root)?;
    let status = std::fs::read_to_string(directory.join("status.json")).ok()?;
    serde_json::from_str(&status).ok()
}

// UNDOCUMENTED-EFFINTERP: locate a root's daemon namespace through its persisted config.
fn root_daemon_directory(home: &Path, root: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(root).ok()?;
    for entry in std::fs::read_dir(home.join(".nah/effinterp"))
        .ok()?
        .flatten()
    {
        let configured = entry.path().join("daemon.json");
        let Ok(text) = std::fs::read_to_string(&configured) else {
            continue;
        };
        let config: serde_json::Value = serde_json::from_str(&text).ok()?;
        let configured_root = config["repositories"][0]["root"].as_str()?;
        if Path::new(configured_root) != canonical {
            continue;
        }
        return Some(entry.path());
    }
    None
}
