#![allow(dead_code, clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::Path;
use std::process::Command;

use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::tool::ToolCallInput;

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
