#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::process::Command;

#[test]
fn tui_requires_an_interactive_terminal() {
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("tui")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "nah: `nah tui` requires an interactive terminal.\n"
    );
}
