use crate::io_paths::host_platform;
use nah_proto::ctx::{AbsolutePath, SchemaVersion};
use nah_proto::observation::{
    Observation, ObservationQuery, ObservationRequest, ObservationValue, SymlinkTraversal,
};
use std::fs;
use std::path::Path;
use std::process::Command;

pub(super) fn absolute(path: &Path) -> AbsolutePath {
    AbsolutePath::new(host_platform(), path.to_string_lossy()).expect("absolute test path")
}

pub(super) fn request(cwd: &Path, paths: &[(&str, &str)]) -> ObservationRequest {
    let mut queries = vec![
        ObservationQuery::Cwd {
            key: "cwd".into(),
            requested: absolute(cwd),
        },
        ObservationQuery::Roots {
            key: "roots".into(),
            cwd_key: "cwd".into(),
        },
        ObservationQuery::ProjectGuards {
            key: "guards".into(),
            roots_key: "roots".into(),
        },
    ];
    queries.extend(paths.iter().map(|(key, requested)| ObservationQuery::Path {
        key: (*key).into(),
        requested: (*requested).into(),
        cwd_key: "cwd".into(),
        inspect_descendants: false,
        symlink_traversal: SymlinkTraversal::None,
    }));
    ObservationRequest::new(SchemaVersion::V1, "request", queries).expect("request")
}

pub(super) fn init_repo(path: &Path) {
    fs::create_dir_all(path).expect("repo directory");
    run(Command::new("git").args(["init", "-q"]).current_dir(path));
    fs::write(path.join("tracked"), "one\n").expect("tracked file");
    run(Command::new("git")
        .args(["add", "tracked"])
        .current_dir(path));
    run(Command::new("git")
        .args([
            "-c",
            "user.name=Nah Test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "initial",
        ])
        .current_dir(path));
}

pub(super) fn run(command: &mut Command) {
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(super) fn value<'a>(observation: &'a Observation, key: &str) -> &'a ObservationValue {
    observation
        .facts()
        .iter()
        .find(|fact| fact.query().key() == key)
        .expect("fact")
        .value()
}
