// UNDOCUMENTED-EFFINTERP: trusted-root snapshot publication for the hidden daemon CLI.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use effinterp_daemon::{Daemon, RepositoryIdentity};
use effinterp_proto::AnalysisStatus;
use effinterp_repo::{
    CrawlLimits, SkipCategory, UpdateOutcome, apply_changes, build_index, reconcile_working_tree,
    validate_working_tree,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// UNDOCUMENTED-EFFINTERP: the hidden CLI defaults stay available to unit tests and callers.
const DEFAULT_POLL_SECONDS: u64 = 30;
// UNDOCUMENTED-EFFINTERP: builds default to a two-GiB address-space ceiling.
const DEFAULT_MAX_MEMORY_MIB: u64 = 2_048;
// UNDOCUMENTED-EFFINTERP: daemon crawls are intentionally smaller than effectinterp's default.
const DEFAULT_MAX_FILES: u64 = 5_000;
// UNDOCUMENTED-EFFINTERP: stop waits only for the current atomic publication step.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
// UNDOCUMENTED-EFFINTERP: the hidden daemon depends on Unix process and lock primitives.
const UNIX_ONLY_ERROR: &str = "nah daemon: unavailable on non-Unix platforms";
// UNDOCUMENTED-EFFINTERP: signal handlers only request shutdown at the next safe boundary.
static TERMINATE: AtomicBool = AtomicBool::new(false);

// UNDOCUMENTED-EFFINTERP: resource and polling limits for one foreground daemon run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonRunOptions {
    pub once: bool,
    pub poll_seconds: u64,
    pub max_memory_mib: u64,
    pub max_files: u64,
}

// UNDOCUMENTED-EFFINTERP: keep flag defaults in the daemon owner rather than the CLI wiring.
impl Default for DaemonRunOptions {
    fn default() -> Self {
        Self {
            once: false,
            poll_seconds: DEFAULT_POLL_SECONDS,
            max_memory_mib: DEFAULT_MAX_MEMORY_MIB,
            max_files: DEFAULT_MAX_FILES,
        }
    }
}

// UNDOCUMENTED-EFFINTERP: effectinterp-daemon's strict on-disk configuration envelope.
#[derive(Serialize)]
struct StoredDaemonConfig<'a> {
    schema: &'static str,
    storage_root: &'static str,
    repositories: [StoredRepositoryConfig<'a>; 1],
}

// UNDOCUMENTED-EFFINTERP: one trusted root occupies one independent storage namespace.
#[derive(Serialize)]
struct StoredRepositoryConfig<'a> {
    repository_id: &'a str,
    worktree_id: &'static str,
    root: &'a Path,
    limits: CrawlLimits,
}

// UNDOCUMENTED-EFFINTERP: durable per-root health and publication metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DaemonRootStatus {
    snapshot_id: Option<String>,
    generation: Option<u64>,
    publication_id: Option<String>,
    last_poll_unix: Option<u64>,
    last_publish_unix: Option<u64>,
    last_error: Option<String>,
    build_peak_rss_kib: Option<u64>,
    build_duration_ms: Option<u64>,
}

// UNDOCUMENTED-EFFINTERP: the build child reads back the root and limits nah itself wrote.
#[derive(Deserialize)]
struct StoredBuildTarget {
    repositories: Vec<StoredBuildRepository>,
}

// UNDOCUMENTED-EFFINTERP: only the crawl inputs the child needs to rebuild a candidate.
#[derive(Deserialize)]
struct StoredBuildRepository {
    repository_id: String,
    worktree_id: String,
    root: PathBuf,
    limits: CrawlLimits,
}

// UNDOCUMENTED-EFFINTERP: prepared state keeps errors isolated to their trusted root.
struct DaemonRoot {
    id: String,
    root: PathBuf,
    config_path: PathBuf,
    status_path: PathBuf,
    limits: CrawlLimits,
    ready: bool,
    status: DaemonRootStatus,
}

// UNDOCUMENTED-EFFINTERP: measured child completion without retaining an index in the parent.
struct BuildCompletion {
    status: ExitStatus,
    stderr: String,
    peak_rss_kib: Option<u64>,
    duration_ms: u64,
}

// UNDOCUMENTED-EFFINTERP: run the foreground publisher for every currently trusted root.
pub fn run_daemon(options: DaemonRunOptions, stderr: &mut dyn Write) -> u8 {
    if !cfg!(unix) {
        let _ = writeln!(stderr, "{UNIX_ONLY_ERROR}");
        return 2;
    }
    if options.max_memory_mib == 0 || options.max_files == 0 {
        let _ = writeln!(stderr, "nah daemon: limits must be greater than zero");
        return 2;
    }
    let home = match home_directory() {
        Ok(home) => home,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: {error}");
            return 2;
        }
    };
    let _lock = match acquire_daemon_lock(&home) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            let _ = writeln!(stderr, "nah daemon: already running");
            return 2;
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: {error}");
            return 2;
        }
    };
    let trusted_roots = match load_trusted_roots(&home) {
        Ok(roots) => roots,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: {error}");
            return 2;
        }
    };
    if trusted_roots.is_empty() {
        let _ = writeln!(stderr, "nah daemon: no trusted roots; nothing to index");
        return 0;
    }

    TERMINATE.store(false, Ordering::SeqCst);
    install_termination_handlers();
    let mut roots = prepare_roots(&home, trusted_roots, options.max_files, stderr);
    for root in &mut roots {
        if TERMINATE.load(Ordering::SeqCst) {
            break;
        }
        if root.ready {
            publish_with_child(&home, root, options, stderr);
        }
        let _ = save_root_status(root);
    }
    if TERMINATE.load(Ordering::SeqCst) {
        return 0;
    }
    if options.once {
        reload_and_poll_roots(&home, &mut roots, options, stderr);
        return 0;
    }

    while !TERMINATE.load(Ordering::SeqCst) {
        sleep_until_poll(options.poll_seconds);
        if TERMINATE.load(Ordering::SeqCst) {
            break;
        }
        reload_and_poll_roots(&home, &mut roots, options, stderr);
    }
    0
}

// UNDOCUMENTED-EFFINTERP: print persisted status without opening snapshot storage.
pub fn daemon_status(stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if !cfg!(unix) {
        let _ = writeln!(stderr, "{UNIX_ONLY_ERROR}");
        return 2;
    }
    let home = match home_directory() {
        Ok(home) => home,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: {error}");
            return 2;
        }
    };
    let roots = match load_trusted_roots(&home) {
        Ok(roots) => roots,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: {error}");
            return 2;
        }
    };
    let now = unix_seconds();
    for stored_root in roots {
        let canonical = std::fs::canonicalize(&stored_root).unwrap_or(stored_root.clone());
        let id = path_id(&canonical);
        let base = daemon_root_directory(&home, &id);
        let status = load_root_status(&base.join("status.json"));
        let age = status
            .last_poll_unix
            .map(|poll| format!("{}s", now.saturating_sub(poll)))
            .unwrap_or_else(|| "-".to_owned());
        let snapshot = status.snapshot_id.as_deref().unwrap_or("-");
        let generation = status
            .generation
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_owned());
        let peak = status
            .build_peak_rss_kib
            .map(|value| format!("{value}KiB"))
            .unwrap_or_else(|| "-".to_owned());
        let duration = status
            .build_duration_ms
            .map(|value| format!("{value}ms"))
            .unwrap_or_else(|| "-".to_owned());
        let error = status.last_error.as_deref().unwrap_or("-");
        let _ = writeln!(
            stdout,
            "{id} {} snapshot={snapshot} generation={generation} age={age} peak_rss={peak} duration={duration} error={error}",
            stored_root.display()
        );
    }
    0
}

// UNDOCUMENTED-EFFINTERP: request graceful shutdown and wait for the advisory lock to release.
pub fn stop_daemon(stderr: &mut dyn Write) -> u8 {
    if !cfg!(unix) {
        let _ = writeln!(stderr, "{UNIX_ONLY_ERROR}");
        return 2;
    }
    let home = match home_directory() {
        Ok(home) => home,
        Err(_) => return 1,
    };
    let lock_path = daemon_directory(&home).join("daemon.lock");
    let probe = match OpenOptions::new().read(true).write(true).open(&lock_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return 1,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: cannot open daemon lock: {error}");
            return 2;
        }
    };
    if probe.try_lock().is_ok() {
        let _ = probe.unlock();
        return 1;
    }
    let pid = match std::fs::read_to_string(&lock_path)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
    {
        Some(pid) => pid,
        None => {
            let _ = writeln!(stderr, "nah daemon: invalid daemon lock pid");
            return 2;
        }
    };
    if let Err(error) = terminate_process(pid) {
        let _ = writeln!(stderr, "nah daemon: {error}");
        return 2;
    }

    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let Ok(file) = OpenOptions::new().read(true).write(true).open(&lock_path) else {
            return 0;
        };
        if file.try_lock().is_ok() {
            let _ = file.unlock();
            return 0;
        }
    }
    let _ = writeln!(stderr, "nah daemon: timed out waiting for shutdown");
    2
}

// UNDOCUMENTED-EFFINTERP: child-only bounded build and atomic publication entry point.
pub fn build_daemon_snapshot(id: &str, max_memory_mib: u64, stderr: &mut dyn Write) -> u8 {
    if !cfg!(unix) {
        let _ = writeln!(stderr, "{UNIX_ONLY_ERROR}");
        return 2;
    }
    if let Err(error) = apply_build_resource_limits(max_memory_mib) {
        let _ = writeln!(stderr, "nah daemon build: {error}");
        return 2;
    }
    let home = match home_directory() {
        Ok(home) => home,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon build: {error}");
            return 2;
        }
    };
    let config_path = daemon_root_directory(&home, id).join("daemon.json");
    let (root, limits) = match read_build_target(&config_path, id) {
        Ok(target) => target,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon build: {error}");
            return 2;
        }
    };
    let candidate = build_index(&root, limits);
    if let Some(skip) = candidate
        .skipped
        .iter()
        .find(|skip| skip.path == ".effinterp-root" && skip.category == SkipCategory::Failure)
    {
        let _ = writeln!(stderr, "nah daemon build: {}", skip.reason);
        return 2;
    }
    let identity = repository_identity(id);
    match Daemon::open(&config_path)
        .and_then(|daemon| daemon.publish_candidate(&identity, &candidate))
    {
        Ok(_) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon build: {error}");
            2
        }
    }
}

// UNDOCUMENTED-EFFINTERP: recover the crawl root and limits nah wrote for this repository id.
fn read_build_target(config_path: &Path, id: &str) -> Result<(PathBuf, CrawlLimits), String> {
    let text = std::fs::read_to_string(config_path).map_err(|error| error.to_string())?;
    let stored: StoredBuildTarget =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;
    stored
        .repositories
        .into_iter()
        .find(|repository| repository.repository_id == id && repository.worktree_id == "tree")
        .map(|repository| (repository.root, repository.limits))
        .ok_or_else(|| format!("daemon config has no repository {id}"))
}

// UNDOCUMENTED-EFFINTERP: what a consumer learns by loading the snapshot published for a root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedSnapshotVerification {
    pub snapshot_id: String,
    pub generation: u64,
    pub matches_working_tree: bool,
}

/// Loads the snapshot the daemon currently publishes for `root` under `home` and
/// validates it against that working tree. `matches_working_tree` is true only when
/// the loaded index still claims an exact match for the files on disk; `None` means
/// no snapshot has been published for the root yet.
// UNDOCUMENTED-EFFINTERP: the loader-side half of publication, off the decision path.
pub fn verify_published_snapshot(
    home: &Path,
    root: &Path,
) -> Result<Option<PublishedSnapshotVerification>, String> {
    let canonical = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let id = path_id(&canonical);
    let config_path = daemon_root_directory(home, &id).join("daemon.json");
    let identity = repository_identity(&id);
    let daemon = Daemon::open(&config_path).map_err(|error| error.to_string())?;
    let Some(current) = daemon
        .current(&identity)
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let index = daemon
        .load_current(&identity)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "published manifest has no loadable index".to_owned())?;
    let validation = validate_working_tree(&index, &canonical);
    Ok(Some(PublishedSnapshotVerification {
        snapshot_id: current.snapshot_id,
        generation: current.generation,
        matches_working_tree: validation.status == AnalysisStatus::Complete,
    }))
}

// UNDOCUMENTED-EFFINTERP: prepare strict daemon configurations without aborting sibling roots.
fn prepare_roots(
    home: &Path,
    trusted_roots: Vec<PathBuf>,
    max_files: u64,
    stderr: &mut dyn Write,
) -> Vec<DaemonRoot> {
    trusted_roots
        .into_iter()
        .map(|stored_root| {
            let (root, canonical_error) = match std::fs::canonicalize(&stored_root) {
                Ok(root) => (root, None),
                Err(error) => (stored_root, Some(error)),
            };
            let id = path_id(&root);
            let base = daemon_root_directory(home, &id);
            let config_path = base.join("daemon.json");
            let status_path = base.join("status.json");
            let limits = CrawlLimits {
                max_files,
                ..CrawlLimits::default()
            };
            let mut daemon_root = DaemonRoot {
                id,
                root,
                config_path,
                status_path: status_path.clone(),
                limits,
                ready: false,
                status: load_root_status(&status_path),
            };
            let prepared = canonical_error
                .map(|error| Err(format!("cannot canonicalize trusted root: {error}")))
                .unwrap_or(Ok(()))
                .and_then(|()| write_daemon_config(&daemon_root))
                .and_then(|_| {
                    Daemon::open(&daemon_root.config_path)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                });
            match prepared {
                Ok(()) => daemon_root.ready = true,
                Err(error) => {
                    daemon_root.status.last_error = Some(error.clone());
                    let _ = writeln!(
                        stderr,
                        "nah daemon: {} {}: {error}",
                        daemon_root.id,
                        daemon_root.root.display()
                    );
                }
            }
            daemon_root
        })
        .collect()
}

// UNDOCUMENTED-EFFINTERP: refresh authorization before every poll and initialize new roots.
fn reload_and_poll_roots(
    home: &Path,
    roots: &mut Vec<DaemonRoot>,
    options: DaemonRunOptions,
    stderr: &mut dyn Write,
) {
    let trusted_roots = match load_trusted_roots(home) {
        Ok(roots) => roots,
        Err(error) => {
            let _ = writeln!(stderr, "nah daemon: cannot reload trusted roots: {error}");
            return;
        }
    };
    let mut previous = std::mem::take(roots);
    let mut refreshed = Vec::with_capacity(trusted_roots.len());
    for stored_root in trusted_roots {
        if TERMINATE.load(Ordering::SeqCst) {
            break;
        }
        let canonical = std::fs::canonicalize(&stored_root).unwrap_or_else(|_| stored_root.clone());
        let id = path_id(&canonical);
        if let Some(position) = previous.iter().position(|root| root.id == id && root.ready) {
            refreshed.push(previous.remove(position));
            continue;
        }
        previous.retain(|root| root.id != id);
        let mut root = prepare_roots(home, vec![stored_root], options.max_files, stderr)
            .pop()
            .expect("one trusted root produces one daemon root");
        if root.ready {
            publish_with_child(home, &mut root, options, stderr);
            let _ = save_root_status(&root);
        }
        refreshed.push(root);
    }
    *roots = refreshed;
    poll_roots(home, roots, options, stderr);
}

// UNDOCUMENTED-EFFINTERP: reconcile every published index once per configured poll.
fn poll_roots(
    home: &Path,
    roots: &mut [DaemonRoot],
    options: DaemonRunOptions,
    stderr: &mut dyn Write,
) {
    for root in roots {
        if TERMINATE.load(Ordering::SeqCst) {
            break;
        }
        root.status.last_poll_unix = Some(unix_seconds());
        if root.ready {
            poll_root(home, root, options, stderr);
        }
        if let Err(error) = save_root_status(root) {
            let _ = writeln!(stderr, "nah daemon: {}: {error}", root.id);
        }
    }
}

// UNDOCUMENTED-EFFINTERP: a loaded read-only index turns any detected change into a child rebuild.
fn poll_root(
    home: &Path,
    root: &mut DaemonRoot,
    options: DaemonRunOptions,
    stderr: &mut dyn Write,
) {
    let daemon = match Daemon::open(&root.config_path) {
        Ok(daemon) => daemon,
        Err(error) => {
            record_root_error(root, error.to_string(), stderr);
            return;
        }
    };
    let identity = repository_identity(&root.id);
    let Some(mut index) = (match daemon.load_current(&identity) {
        Ok(index) => index,
        Err(error) => {
            record_root_error(root, error.to_string(), stderr);
            return;
        }
    }) else {
        return;
    };
    let reconciliation = reconcile_working_tree(&index, &root.root);
    if reconciliation.changes.is_empty() {
        if let Ok(Some(current)) = daemon.current(&identity) {
            set_current(&mut root.status, &current);
        }
        return;
    }
    let update = apply_changes(
        &mut index,
        &root.root,
        &root.limits,
        &reconciliation.changes,
    );
    match update.outcome {
        UpdateOutcome::Published => match daemon.publish_candidate(&identity, &index) {
            Ok(current) => {
                set_current(&mut root.status, &current);
                root.status.last_publish_unix = Some(unix_seconds());
                root.status.last_error = None;
                let _ = writeln!(
                    stderr,
                    "nah daemon: published {} {}",
                    root.id, current.snapshot_id
                );
            }
            Err(error) => record_root_error(root, error.to_string(), stderr),
        },
        UpdateOutcome::Failed { .. } => {
            drop(index);
            drop(daemon);
            publish_with_child(home, root, options, stderr);
        }
        UpdateOutcome::Unchanged => {}
    }
}

// UNDOCUMENTED-EFFINTERP: spawn exactly one memory-capped build at a time.
fn publish_with_child(
    home: &Path,
    root: &mut DaemonRoot,
    options: DaemonRunOptions,
    stderr: &mut dyn Write,
) {
    let completion = match spawn_build_child(home, &root.id, options) {
        Ok(completion) => completion,
        Err(error) => {
            record_root_error(root, error, stderr);
            return;
        }
    };
    root.status.build_peak_rss_kib = completion.peak_rss_kib;
    root.status.build_duration_ms = Some(completion.duration_ms);
    if !completion.status.success() {
        let detail = completion.stderr.trim();
        let status = completion
            .status
            .code()
            .map(|code| format!("exit {code}"))
            .unwrap_or_else(|| "terminated by signal".to_owned());
        let error = if detail.is_empty() {
            format!("build failed: {status}")
        } else {
            format!("build failed: {status}: {detail}")
        };
        record_root_error(root, error, stderr);
        return;
    }
    match Daemon::open(&root.config_path)
        .and_then(|daemon| daemon.current(&repository_identity(&root.id)))
    {
        Ok(Some(current)) => {
            set_current(&mut root.status, &current);
            root.status.last_publish_unix = Some(unix_seconds());
            root.status.last_error = None;
            let _ = writeln!(
                stderr,
                "nah daemon: published {} {}",
                root.id, current.snapshot_id
            );
        }
        Ok(None) => record_root_error(
            root,
            "build completed without publishing a snapshot".to_owned(),
            stderr,
        ),
        Err(error) => record_root_error(root, error.to_string(), stderr),
    }
}

// UNDOCUMENTED-EFFINTERP: invoke the current nah binary as the isolated build worker.
fn spawn_build_child(
    home: &Path,
    id: &str,
    options: DaemonRunOptions,
) -> Result<BuildCompletion, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = Command::new(executable);
    command
        .args([
            "daemon",
            "build",
            id,
            "--max-memory",
            &options.max_memory_mib.to_string(),
        ])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    let child = command.spawn().map_err(|error| error.to_string())?;
    wait_for_build(child)
}

// UNDOCUMENTED-EFFINTERP: wait4 supplies the child's peak resident set even after a limit kill.
#[cfg(unix)]
fn wait_for_build(mut child: Child) -> Result<BuildCompletion, String> {
    use std::io::Read as _;
    use std::os::unix::process::ExitStatusExt;

    let started = Instant::now();
    let mut raw_status = 0;
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let mut termination_sent = false;
    loop {
        // SAFETY: wait4 receives this live child's pid and valid writable result pointers.
        let waited = unsafe {
            libc::wait4(
                child.id() as libc::pid_t,
                &mut raw_status,
                libc::WNOHANG,
                usage.as_mut_ptr(),
            )
        };
        if waited > 0 {
            break;
        }
        if waited == 0 {
            if TERMINATE.load(Ordering::SeqCst) && !termination_sent {
                terminate_process_group(child.id())?;
                termination_sent = true;
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.to_string());
        }
    }
    // SAFETY: wait4 initialized rusage after returning the requested child pid.
    let usage = unsafe { usage.assume_init() };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let raw_peak = usage.ru_maxrss.max(0) as u64;
    #[cfg(target_os = "macos")]
    let peak_rss_kib = raw_peak / 1_024;
    #[cfg(not(target_os = "macos"))]
    let peak_rss_kib = raw_peak;
    Ok(BuildCompletion {
        status: ExitStatus::from_raw(raw_status),
        stderr,
        peak_rss_kib: Some(peak_rss_kib),
        duration_ms: duration_millis(started.elapsed()),
    })
}

// UNDOCUMENTED-EFFINTERP: keep the compile-only backend behind the Unix-only entry point.
#[cfg(not(unix))]
fn wait_for_build(child: Child) -> Result<BuildCompletion, String> {
    let started = Instant::now();
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    Ok(BuildCompletion {
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        peak_rss_kib: None,
        duration_ms: duration_millis(started.elapsed()),
    })
}

// UNDOCUMENTED-EFFINTERP: enforce the build child's address-space ceiling and low priority.
#[cfg(unix)]
fn apply_build_resource_limits(max_memory_mib: u64) -> Result<(), String> {
    let bytes = max_memory_mib
        .checked_mul(1_024 * 1_024)
        .ok_or_else(|| "max-memory is too large".to_owned())?;
    let limit = libc::rlimit {
        rlim_cur: bytes as libc::rlim_t,
        rlim_max: bytes as libc::rlim_t,
    };
    // SAFETY: setrlimit receives a valid immutable rlimit for this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } != 0 {
        return Err(format!(
            "cannot set address-space limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: nice adjusts only this process and failure is non-fatal isolation metadata.
    let _ = unsafe { libc::nice(10) };
    #[cfg(target_os = "linux")]
    {
        const IOPRIO_WHO_PROCESS: libc::c_int = 1;
        const IOPRIO_CLASS_IDLE: libc::c_int = 3 << 13;
        // SAFETY: ioprio_set targets the current process and uses constant kernel values.
        let _ = unsafe {
            libc::syscall(
                libc::SYS_ioprio_set,
                IOPRIO_WHO_PROCESS,
                0,
                IOPRIO_CLASS_IDLE,
            )
        };
    }
    Ok(())
}

// UNDOCUMENTED-EFFINTERP: the Unix-only entry point never permits an uncapped build.
#[cfg(not(unix))]
fn apply_build_resource_limits(_max_memory_mib: u64) -> Result<(), String> {
    Err("address-space limits are unavailable on this platform".to_owned())
}

// UNDOCUMENTED-EFFINTERP: load the exact canonical roots persisted by nah trust.
fn load_trusted_roots(home: &Path) -> Result<Vec<PathBuf>, String> {
    let platform = host_platform();
    let absolute_home = AbsolutePath::new(
        platform,
        home.to_str()
            .ok_or_else(|| "home path is not UTF-8".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    let database = nah_extensions::TrustDatabase::load(
        &nah_extensions::trust_database_path(&absolute_home, platform),
        platform,
    )
    .map_err(|error| error.to_string())?;
    let projection = database.projection().map_err(|error| error.to_string())?;
    Ok(projection
        .trusted_roots()
        .iter()
        .map(|root| PathBuf::from(root.path().as_str()))
        .collect())
}

// UNDOCUMENTED-EFFINTERP: derive the current user's home without introducing daemon config.
fn home_directory() -> Result<PathBuf, String> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{variable} is not set"))?;
    if !home.is_absolute() {
        return Err(format!("{variable} is not an absolute path"));
    }
    Ok(home)
}

// UNDOCUMENTED-EFFINTERP: match nah's host path validation platform.
const fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

// UNDOCUMENTED-EFFINTERP: hash the canonical root into a bounded filesystem identity.
fn path_id(root: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(root.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut id = String::with_capacity(16);
    for byte in &digest[..8] {
        write!(&mut id, "{byte:02x}").expect("writing to a string succeeds");
    }
    id
}

// UNDOCUMENTED-EFFINTERP: the shared daemon directory is protected by nah's .nah tier.
fn daemon_directory(home: &Path) -> PathBuf {
    home.join(".nah/effinterp")
}

// UNDOCUMENTED-EFFINTERP: each repository id owns one config, status, and storage tree.
fn daemon_root_directory(home: &Path, id: &str) -> PathBuf {
    daemon_directory(home).join(id)
}

// UNDOCUMENTED-EFFINTERP: effectinterp uses one fixed worktree identity per canonical root.
fn repository_identity(id: &str) -> RepositoryIdentity {
    RepositoryIdentity {
        repository_id: id.to_owned(),
        worktree_id: "tree".to_owned(),
    }
}

// UNDOCUMENTED-EFFINTERP: write one strict relative-storage config atomically.
fn write_daemon_config(root: &DaemonRoot) -> Result<(), String> {
    let config = StoredDaemonConfig {
        schema: effinterp_daemon::CONFIG_SCHEMA,
        storage_root: "storage",
        repositories: [StoredRepositoryConfig {
            repository_id: &root.id,
            worktree_id: "tree",
            root: &root.root,
            limits: root.limits,
        }],
    };
    atomic_json(&root.config_path, &config)
}

// UNDOCUMENTED-EFFINTERP: status writes use the same durable rename boundary as configs.
fn save_root_status(root: &DaemonRoot) -> Result<(), String> {
    atomic_json(&root.status_path, &root.status)
}

// UNDOCUMENTED-EFFINTERP: absent or corrupt status never prevents independent snapshot recovery.
fn load_root_status(path: &Path) -> DaemonRootStatus {
    File::open(path)
        .ok()
        .and_then(|file| serde_json::from_reader(file).ok())
        .unwrap_or_default()
}

// UNDOCUMENTED-EFFINTERP: atomic JSON replacement prevents partial state after interruption.
fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "state path has no parent".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut temporary, value).map_err(|error| error.to_string())?;
    temporary
        .write_all(b"\n")
        .map_err(|error| error.to_string())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    temporary.persist(path).map_err(|error| error.to_string())?;
    sync_directory(parent)
}

// UNDOCUMENTED-EFFINTERP: persist the renamed directory entry on Unix hosts.
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

// UNDOCUMENTED-EFFINTERP: Windows rename durability is supplied by the file flush.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

// UNDOCUMENTED-EFFINTERP: acquire a private advisory lock and record its live owner pid.
fn acquire_daemon_lock(home: &Path) -> Result<Option<File>, String> {
    let directory = daemon_directory(home);
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let path = directory.join("daemon.lock");
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    if file.try_lock().is_err() {
        return Ok(None);
    }
    file.set_len(0).map_err(|error| error.to_string())?;
    writeln!(file, "{}", std::process::id()).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(Some(file))
}

// UNDOCUMENTED-EFFINTERP: update the status record from effectinterp's validated manifest.
fn set_current(status: &mut DaemonRootStatus, current: &effinterp_daemon::PublishedSnapshot) {
    status.snapshot_id = Some(current.snapshot_id.clone());
    status.generation = Some(current.generation);
    status.publication_id = Some(current.publication_id.clone());
}

// UNDOCUMENTED-EFFINTERP: keep errors scoped and observable without aborting sibling roots.
fn record_root_error(root: &mut DaemonRoot, error: String, stderr: &mut dyn Write) {
    root.status.last_error = Some(error.clone());
    let _ = writeln!(
        stderr,
        "nah daemon: {} {}: {error}",
        root.id,
        root.root.display()
    );
}

// UNDOCUMENTED-EFFINTERP: cap duration fields without panicking after extreme uptime.
fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

// UNDOCUMENTED-EFFINTERP: wall-clock seconds make status portable across daemon processes.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// UNDOCUMENTED-EFFINTERP: short sleeps let SIGTERM stop an idle foreground daemon promptly.
fn sleep_until_poll(seconds: u64) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline && !TERMINATE.load(Ordering::SeqCst) {
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        );
    }
}

// UNDOCUMENTED-EFFINTERP: async-signal-safe handler only flips one atomic flag.
#[cfg(unix)]
extern "C" fn termination_signal(_signal: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
}

// UNDOCUMENTED-EFFINTERP: install graceful foreground shutdown for SIGTERM and Ctrl-C.
#[cfg(unix)]
fn install_termination_handlers() {
    // SAFETY: the handler has C ABI and performs only an atomic store.
    unsafe {
        libc::signal(libc::SIGTERM, termination_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, termination_signal as libc::sighandler_t);
    }
}

// UNDOCUMENTED-EFFINTERP: the Unix-only entry point never installs handlers on other hosts.
#[cfg(not(unix))]
fn install_termination_handlers() {}

// UNDOCUMENTED-EFFINTERP: send SIGTERM to the pid proven live by the held lock.
#[cfg(unix)]
fn terminate_process(pid: u32) -> Result<(), String> {
    // SAFETY: kill receives a parsed positive pid and a standard termination signal.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot signal daemon: {}",
            std::io::Error::last_os_error()
        ))
    }
}

// UNDOCUMENTED-EFFINTERP: stop the isolated build and any subprocesses it started.
#[cfg(unix)]
fn terminate_process_group(pid: u32) -> Result<(), String> {
    // SAFETY: the build child is its process-group leader, so a negative pid targets that group.
    if unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(format!("cannot signal daemon build: {error}"))
    }
}

// UNDOCUMENTED-EFFINTERP: Windows shutdown support is outside the hidden Unix daemon seam.
#[cfg(not(unix))]
fn terminate_process(_pid: u32) -> Result<(), String> {
    Err("daemon stop is unavailable on this platform".to_owned())
}

// UNDOCUMENTED-EFFINTERP: focused contracts for daemon identity, limits, and failure isolation.
#[cfg(test)]
mod tests {
    use super::*;

    // UNDOCUMENTED-EFFINTERP: defaults are part of the hidden resource contract.
    #[test]
    fn daemon_flag_defaults_are_bounded() {
        assert_eq!(
            DaemonRunOptions::default(),
            DaemonRunOptions {
                once: false,
                poll_seconds: 30,
                max_memory_mib: 2_048,
                max_files: 5_000,
            }
        );
    }

    // UNDOCUMENTED-EFFINTERP: canonical roots hash identically across trailing slash spelling.
    #[test]
    fn path_id_is_stable_across_trailing_slashes() {
        let temp = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(temp.path()).unwrap();
        let with_slash = PathBuf::from(format!("{}/", canonical.display()));
        assert_eq!(
            path_id(&std::fs::canonicalize(canonical).unwrap()),
            path_id(&std::fs::canonicalize(with_slash).unwrap())
        );
    }

    // UNDOCUMENTED-EFFINTERP: a deleted trusted root records an error without rejecting siblings.
    #[test]
    fn deleted_trusted_root_is_isolated_during_preparation() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let valid = temp.path().join("valid");
        let deleted = temp.path().join("deleted");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&valid).unwrap();
        std::fs::create_dir_all(&deleted).unwrap();
        let platform = host_platform();
        let absolute_home = AbsolutePath::new(platform, home.to_str().unwrap()).unwrap();
        let trust_path = nah_extensions::trust_database_path(&absolute_home, platform);
        for root in [&valid, &deleted] {
            let canonical = std::fs::canonicalize(root).unwrap();
            let absolute = AbsolutePath::new(platform, canonical.to_str().unwrap()).unwrap();
            nah_extensions::record_trusted_root(&trust_path, platform, absolute).unwrap();
        }
        std::fs::remove_dir(&deleted).unwrap();

        let roots = load_trusted_roots(&home).unwrap();
        let mut stderr = Vec::new();
        let prepared = prepare_roots(&home, roots, 5_000, &mut stderr);
        assert_eq!(prepared.len(), 2);
        assert!(prepared.iter().any(|root| root.ready));
        assert!(
            prepared
                .iter()
                .any(|root| !root.ready && root.status.last_error.is_some())
        );
    }
}
