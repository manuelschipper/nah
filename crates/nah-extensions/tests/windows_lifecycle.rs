#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::Command;

use nah_extensions::{create_project_guard, create_user_guard};
use nah_proto::ctx::Platform;

use support::{absolute, finish_windows};

#[test]
fn generated_windows_template_activates_and_answers() {
    let launcher = Command::new("py")
        .args(["-3", "-S", "-c", "import json"])
        .status()
        .unwrap();
    assert!(launcher.success());

    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let directory = create_user_guard(&home, Platform::Windows, "example").unwrap();
    assert!(directory.join("run.cmd").is_file());
    assert!(directory.join("run.py").is_file());
    let manifest = std::fs::read_to_string(directory.join("policy.toml")).unwrap();
    assert!(manifest.contains("data = [\"run.py\"]"));

    let fixture = finish_windows(temp, home, directory.join("run.cmd"), "example");
    let output = fixture.consult();
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.responses.len(), 1);
    assert!(output.responses[0].is_abstain());
}

#[test]
fn project_template_uses_the_windows_wrapper() {
    let temp = tempfile::tempdir().unwrap();
    let root = absolute(temp.path());
    let directory = create_project_guard(&root, Platform::Windows, "example").unwrap();
    let wrapper = std::fs::read_to_string(directory.join("run.cmd")).unwrap();
    assert!(wrapper.contains("py -3"));
    assert!(wrapper.contains("%~dp0run.py"));
}
