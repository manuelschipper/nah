//! Runtime-CLI recognition of launches that bypass hook wiring, over literal
//! argv. Plugin and Nah state mutations are the engine models' stated control
//! changes, which the corpus exercises end to end.

use nah_effinterp::runtime_cli;
use nah_proto::ctx::{AbsolutePath, Platform};

fn argv(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn runtime_launch_bypasses_are_recognized() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (program, arguments, expected) in [
        ("claude", &["--safe-mode"][..], "claude"),
        ("claude", &["--bare"][..], "claude"),
        (
            "claude",
            &["--settings", r#"{"disableAllHooks": true}"#][..],
            "claude",
        ),
        (
            "claude",
            &[r#"--settings={"\u0064isableAllHooks":1}"#][..],
            "claude",
        ),
        ("cline", &["--config", "/tmp/other"][..], "cline"),
        ("codex", &["--disable", "hooks"][..], "codex"),
        ("codex", &["--disable=codex_hooks"][..], "codex"),
        ("codex", &["-c", "features.hooks=false"][..], "codex"),
        ("codex", &["-cfeatures.codex_hooks=0"][..], "codex"),
        (
            "codex",
            &["exec", "--config=features.\"hooks\"=false"][..],
            "codex",
        ),
        ("codex", &["-c", "features={ hooks = false }"][..], "codex"),
        (
            "codex",
            &["-c", r#"features={"\u0068ooks"=false}"#][..],
            "codex",
        ),
        (
            "codex",
            &["-p", "work", "-c", "profiles.work={features={hooks=false}}"][..],
            "codex",
        ),
        ("claude", &["--setting-sources", "project"][..], "claude"),
        (
            "claude",
            &[
                "--append-system-prompt",
                "--",
                "--settings",
                r#"{"disableAllHooks":true}"#,
            ][..],
            "claude",
        ),
        ("claude", &["--setting-sources=project,local"][..], "claude"),
        ("devin", &["--config", "/tmp/unsafe.json"][..], "devin"),
        ("droid", &["--settings=/tmp/unsafe.json"][..], "droid"),
        ("hermes", &["--safe-mode"][..], "hermes"),
        ("openclaw", &["--profile", "other"][..], "openclaw"),
        ("openclaw", &["--dev"][..], "openclaw"),
        ("pi", &["--no-extensions"][..], "pi"),
    ] {
        assert_eq!(
            runtime_cli::recognize_runtime_cli(
                program,
                &argv(arguments),
                false,
                &home,
                Platform::Linux
            ),
            Some(expected),
            "{program} {arguments:?}"
        );
    }
    for (program, arguments) in [
        ("cline", &["--config", ""][..]),
        ("cline", &["--config="][..]),
        ("cline", &["--config", "/home/test/.cline"][..]),
        ("devin", &["--config", ""][..]),
        (
            "devin",
            &["--config", "/home/test/.config/devin/config.json"][..],
        ),
        ("droid", &["--settings", ""][..]),
        (
            "droid",
            &["--settings", "/home/test/.factory/settings.json"][..],
        ),
        ("openclaw", &["--profile", "default"][..]),
        ("claude", &["--settings", r#"{"model": "opus"}"#][..]),
        ("claude", &["--settings", "./disableAllHooks.json"][..]),
        ("codex", &["-c", "features.hooks=true"][..]),
        ("codex", &["-c", "features.unified_exec=false"][..]),
        ("codex", &["--enable", "hooks"][..]),
        ("claude", &["--setting-sources", "user,project"][..]),
        (
            "droid",
            &["exec", "--skip-permissions-unsafe", "echo ok"][..],
        ),
        ("cargo", &["uninstall", "nah-cli"][..]),
    ] {
        assert_eq!(
            runtime_cli::recognize_runtime_cli(
                program,
                &argv(arguments),
                false,
                &home,
                Platform::Linux
            ),
            None,
            "{program} {arguments:?}"
        );
    }
}

#[test]
fn help_and_version_argv_never_recognize_a_runtime_launch() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (program, arguments) in [
        ("claude", &["--safe-mode", "--help"][..]),
        ("hermes", &["--safe-mode", "--version"][..]),
    ] {
        assert_eq!(
            runtime_cli::recognize_runtime_cli(
                program,
                &argv(arguments),
                false,
                &home,
                Platform::Linux
            ),
            None,
            "{program} {arguments:?}"
        );
    }
}

/// The engine states a runtime home selector unresolved after a shell
/// builtin it does not model exactly; a selector Nah checks that the engine
/// does not list would read as the default home there instead.
#[test]
fn engine_lists_every_runtime_home_selector() {
    use std::cell::RefCell;
    let read = RefCell::new(Vec::new());
    for program in [
        "amp", "claude", "cline", "codex", "copilot", "hermes", "kiro-cli", "openclaw", "opencode",
        "pi",
    ] {
        nah_proto::runtime_protection::environment_operation(
            program,
            |name| {
                read.borrow_mut().push(name.to_owned());
                nah_proto::effects::Knowledge::Known(None)
            },
            |_| None,
            "/home/test",
            None,
            &[],
            Platform::Linux,
        );
    }
    for name in read.into_inner() {
        assert!(
            effinterp_engine::RUNTIME_HOME_SELECTORS.contains(&name.as_str()),
            "{name}"
        );
    }
}
