#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use nah_cli::DecisionResult;
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::effects::{
    EffectCall, EffectFact, EffectResource, FactPayload, FilesystemOperation, Knowledge,
};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationQuery, ObservationRequest,
    ObservationValue, Observed,
};
use nah_proto::tool::ToolCallInput;

/// Gives an operator command terminal stdin and stdout while preserving its
/// output for assertions. Machine-facing calls keep using pipes.
pub(crate) fn operator_output(command: &mut Command) -> std::process::Output {
    use std::io::Read;

    let (mut master, slave) = operator_terminal();
    command
        .stdin(slave.try_clone().unwrap())
        .stdout(slave)
        .stderr(Stdio::piped());
    let child = command.spawn().unwrap();
    // Release the slave handles retained by Command so the master reaches EOF.
    command.stdin(Stdio::null()).stdout(Stdio::null());
    let mut stdout = Vec::new();
    match master.read_to_end(&mut stdout) {
        Ok(_) => {}
        // Linux signals the last slave closing with EIO.
        Err(error) if cfg!(unix) && error.raw_os_error() == Some(5) => {}
        Err(error) => panic!("read operator terminal: {error}"),
    }
    let mut output = child.wait_with_output().unwrap();
    output.stdout = stdout;
    output
}

#[cfg(unix)]
pub(crate) fn operator_terminal() -> (std::fs::File, std::fs::File) {
    use std::os::unix::ffi::OsStrExt;

    let master = rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR).unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::ffi::OsStr::from_bytes(name.to_bytes()))
        .unwrap();
    let mut termios = rustix::termios::tcgetattr(&slave).unwrap();
    termios.make_raw();
    rustix::termios::tcsetattr(&slave, rustix::termios::OptionalActions::Now, &termios).unwrap();
    (master.into(), slave)
}

#[cfg(windows)]
pub(crate) fn operator_terminal() -> (std::fs::File, std::fs::File) {
    use std::io::IsTerminal;
    use std::os::windows::io::FromRawHandle;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::CreateNamedPipeW;

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    // Rust recognizes MSYS-style named pipes as terminal handles on Windows.
    let name = format!(
        r"\\.\pipe\msys-nah-{}-pty{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    // SAFETY: the name is NUL-terminated and the security attributes are absent.
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            0,
            1,
            65536,
            65536,
            0,
            std::ptr::null(),
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    // SAFETY: CreateNamedPipeW returned an owned handle, transferred once.
    let master = unsafe { std::fs::File::from_raw_handle(handle) };
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name)
        .unwrap();
    assert!(slave.is_terminal());
    (master, slave)
}

/// Resolves temp paths without exposing Windows device-namespace paths.
pub(crate) fn test_temp_path(path: &Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let path = std::fs::canonicalize(path).unwrap();
        std::path::PathBuf::from(nah_observe::normalize_windows_observed_path(
            path.to_str().unwrap(),
        ))
    }
    #[cfg(not(windows))]
    {
        std::fs::canonicalize(path).unwrap()
    }
}

pub(crate) fn absolute(path: &Path) -> AbsolutePath {
    let path = path.to_str().unwrap();
    #[cfg(windows)]
    let path = nah_observe::normalize_windows_observed_path(path);
    AbsolutePath::new(host_platform(), path).unwrap()
}

pub(crate) const fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

pub(crate) fn bash_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\\', "/"))
}

pub(crate) fn ctx(home: &Path) -> Ctx {
    Ctx::new(
        host_platform(),
        absolute(home),
        nah_cli::all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap()
}

pub(crate) fn factory_ctx(home: &Path) -> Ctx {
    Ctx::new(
        host_platform(),
        absolute(home),
        nah_cli::shipped_guard_states(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap()
}

pub(crate) fn call(tool: &str, input: serde_json::Value, cwd: &Path) -> ToolCallInput {
    ToolCallInput::new(SchemaVersion::V1, tool, input, cwd.to_str().unwrap(), None).unwrap()
}

pub(crate) fn git(directory: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?}");
}

pub(crate) fn repo(temp: &Path) -> std::path::PathBuf {
    let repo = temp.join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    std::fs::create_dir(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"scripts":{"clean":"rm -rf dist"}}"#,
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    repo
}

/// A repository like [`repo`] that holds what a Git discard destroys: an
/// uncommitted edit to a tracked file, an untracked file and a stash entry.
/// Nah delegates a discard in a repository it observes to hold none of these.
pub(crate) fn repo_with_work(temp: &Path) -> std::path::PathBuf {
    let repo = repo(temp);
    std::fs::write(repo.join("src/lib.rs"), "pub fn stashed() {}\n").unwrap();
    git(
        &repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "stash",
            "-q",
        ],
    );
    std::fs::write(repo.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    std::fs::write(repo.join("notes.md"), "draft\n").unwrap();
    repo
}

/// Runs the built `nah` binary in `cwd` with `home` as its only user home,
/// optionally feeding `stdin`.
pub(crate) fn nah(
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
    if matches!(args, ["guard", "disable" | "reset", ..]) && !args.contains(&"--help") {
        return operator_output(&mut command);
    }
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

/// Every filesystem access the engine's evidence states, with the fact and the
/// resource it targets. Empty when the decision carries no evidence.
pub(crate) fn filesystem_accesses(
    result: &DecisionResult,
) -> Vec<(FilesystemOperation, &EffectResource, &EffectFact)> {
    let Some(Ok(evidence)) = result.guard_evidence() else {
        return Vec::new();
    };
    let graph = evidence.graph();
    graph
        .facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            FactPayload::FilesystemAccess {
                operation, target, ..
            } => graph
                .resources
                .iter()
                .find(|resource| resource.id == *target)
                .map(|resource| (*operation, resource, fact)),
            _ => None,
        })
        .collect()
}

/// The path a filesystem resource names, when the producer knows it.
pub(crate) fn resource_path(resource: &EffectResource) -> Option<&str> {
    match &resource.identity.name {
        Knowledge::Known(name) => Some(name.as_str()),
        Knowledge::Unknown => None,
    }
}

pub(crate) fn has_filesystem_access(
    result: &DecisionResult,
    operation: FilesystemOperation,
    path: &str,
) -> bool {
    filesystem_accesses(result)
        .iter()
        .any(|(actual, resource, _)| *actual == operation && resource_path(resource) == Some(path))
}

/// The invocations the engine's evidence names, in graph order.
pub(crate) fn calls(result: &DecisionResult) -> &[EffectCall] {
    match result.guard_evidence() {
        Some(Ok(evidence)) => &evidence.graph().calls,
        _ => &[],
    }
}

/// The facts the evidence states, for assertion messages.
pub(crate) fn facts(result: &DecisionResult) -> &[EffectFact] {
    match result.guard_evidence() {
        Some(Ok(evidence)) => &evidence.graph().facts,
        _ => &[],
    }
}

/// Whether `interpreter` can run a generated JavaScript plugin here. A
/// developer machine without it skips the plugin's behavior checks. CI sets
/// `CI`, and there a missing interpreter fails the test, so the plugin never
/// ships unexercised behind a passing run. Only the plugin tests that run on
/// Unix-like hosts call it.
#[cfg(not(windows))]
pub(crate) fn interpreter_available(interpreter: &str) -> bool {
    let available = Command::new(interpreter).arg("--version").output().is_ok();
    assert!(
        available || std::env::var_os("CI").is_none(),
        "{interpreter} is not installed, and CI must run the plugin tests that need it"
    );
    available
}

/// A PATH a test owns: an empty `decoy` directory a test may fill with
/// another `nah`, then a stand-in `nah` at the home's standard install
/// location, then stand-ins for the `launchers` its commands run through.
/// Launchers are not source a search could read, so their basename models
/// describe them.
pub fn search_path(home: &Path, launchers: &[&str]) -> String {
    let installed = home.join(".local/bin");
    let tools = home.join("tools");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    let stubs = std::iter::once((installed.join("nah"), &b"#!/bin/sh\n"[..])).chain(
        launchers
            .iter()
            .map(|name| (tools.join(name), &b"\x7fELF\xff"[..])),
    );
    for (path, bytes) in stubs {
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    [home.join("decoy"), installed, tools]
        .iter()
        .map(|directory| directory.to_str().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join(":")
}

/// Fulfils an observation in process with the test git timeout, so git under
/// parallel test load does not turn root facts unavailable.
pub fn fulfill_observation(request: &ObservationRequest) -> Result<Observation, String> {
    nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
        .map_err(|error| error.to_string())
}

/// Answers the PATH lookup with `path`: a bare command's PATH search then
/// selects executables the test owns, not whatever this process inherited.
pub fn observe_with_path(path: &str, request: &ObservationRequest) -> Result<Observation, String> {
    let observation = fulfill_observation(request)?;
    let facts = observation
        .facts()
        .iter()
        .map(|fact| {
            let value = match fact.query() {
                ObservationQuery::Env { name, .. } if name == "PATH" => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Value {
                            text: path.to_owned(),
                        },
                    },
                },
                _ => fact.value().clone(),
            };
            ObservationFact::new(fact.query().clone(), value).unwrap()
        })
        .collect();
    Ok(Observation::new(request.version(), request.request_id(), facts).unwrap())
}

/// Answers the engine's home lookup with the context home: production builds
/// the context from the home the engine observes, while this process keeps the
/// developer's HOME and each test owns a temporary home.
pub fn observe_with_home(home: &Path, request: &ObservationRequest) -> Result<Observation, String> {
    let observation = fulfill_observation(request)?;
    let facts = observation
        .facts()
        .iter()
        .map(|fact| {
            let value = match fact.query() {
                ObservationQuery::Env { name, .. } if name == "HOME" || name == "USERPROFILE" => {
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Value {
                                text: home.to_str().unwrap().to_owned(),
                            },
                        },
                    }
                }
                _ => fact.value().clone(),
            };
            ObservationFact::new(fact.query().clone(), value).unwrap()
        })
        .collect();
    Ok(Observation::new(request.version(), request.request_id(), facts).unwrap())
}
