#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

#[test]
fn tui_requires_an_interactive_terminal() {
    let temp = tempfile::tempdir().unwrap();
    let output = support::nah(temp.path(), temp.path(), &["tui"], None);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "nah: `nah tui` requires an interactive terminal.\n"
    );
}
