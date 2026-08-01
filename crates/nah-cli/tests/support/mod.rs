#![allow(dead_code, clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::Path;
use std::process::Command;

use nah_cli::POLICY_VERSION;
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::tool::ToolCallInput;

pub(crate) fn absolute(path: &Path) -> AbsolutePath {
    AbsolutePath::new(host_platform(), path.to_str().unwrap()).unwrap()
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
        SchemaVersion::V1,
        host_platform(),
        absolute(home),
        nah_cli::all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
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
