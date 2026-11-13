#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! `nah test`: a human-readable dry run that reports the decision, always exits
//! successfully, and never appends an audit record.

use crate::support;

use support::{nah, repo};

#[test]
fn test_command_is_a_human_dry_run_and_does_not_write_an_audit_record() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "echo hello"], None);

    assert!(output.status.success(), "{output:?}");
    // The decision reports the host-resolved path, including macOS symlinks
    // and Windows short names, so redact either form nah may print.
    let printed = [support::test_temp_path(&project), project]
        .map(|path| serde_json::to_string(path.to_str().unwrap()).unwrap());
    let stdout = printed
        .iter()
        .fold(String::from_utf8(output.stdout).unwrap(), |stdout, path| {
            stdout.replace(path.trim_matches('"'), "<project>")
        })
        // The producer identity is derived from the engine's sources, which
        // move with every engine change.
        .lines()
        .map(|line| {
            if line.starts_with("producer: effinterp/blake3:") {
                "producer: effinterp/blake3:<identity>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .map(|line| line + "\n")
        .collect::<String>();
    assert_eq!(stdout, include_str!("../golden/test-echo.txt"));
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}

#[test]
fn test_command_returns_success_after_a_blocked_dry_run() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "rm -rf /"], None);

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("verdict: block\n")
    );
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}

#[test]
fn recursive_grep_exempts_only_observed_non_matching_environment_files() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let credential = "TOKEN=private-fixture-value\nMixedCase=value\n";
    std::fs::write(project.join(".env"), credential).unwrap();
    for (name, value) in [("GREP_OPTIONS", "-v"), ("POSIXLY_CORRECT", "")] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(["test", "grep -r TODO ."])
            .current_dir(&project)
            .env("HOME", temp.path())
            .env("USERPROFILE", temp.path())
            .env(name, value)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with("verdict: block\n")
        );
    }
    let output = nah(
        temp.path(),
        &project,
        &["test", "--json", "grep -r TODO ."],
        None,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("private-fixture-value")
    );
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("private-fixture-value")
    );
    let check = |command: &str, verdict: &str| {
        let output = nah(temp.path(), &project, &["test", command], None);
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.starts_with(&format!("verdict: {verdict}\n")),
            "{command}: {stdout}"
        );
        assert!(!stdout.contains("private-fixture-value"));
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains("private-fixture-value")
        );
    };
    for command in [
        "grep -r TODO .",
        "grep -R TODO .",
        "grep -rn TODO .",
        "grep -ri todo .",
        "grep -rF 'not.a[regex]' .",
        "grep -rE TODO .",
        "grep -r -e TODO -e FIXME .",
        "grep -r -e TODO . src",
        "grep -r $'TODO\\nFIXME' .",
    ] {
        check(command, "delegate");
    }
    #[cfg(unix)]
    for command in ["grep -rn TODO . 2>/dev/null", "grep -rn TODO . >/dev/null"] {
        check(command, "delegate");
    }
    for command in [
        "grep -r = .",
        "grep -ri mixedcase .",
        "grep -r -e TODO -e TOKEN .",
        "grep -r -e TODO -e 'T.*' .",
        "grep -r 'T.*' .",
        "grep -r '' .",
        "grep -rv TODO .",
        "grep -r -A 1 TODO .",
        "grep -r -B1 TODO .",
        "grep -rC1 TODO .",
        "grep -r --context=1 TODO .",
        "grep -r --context 1 TODO .",
        "grep -r --context TODO .",
        "grep --context -r TOKEN .",
        "grep --context --context -r TOKEN .",
        "grep -r --inv TODO .",
        "grep -r --line-buffered TODO .",
        "grep -r --line-buffered TOKEN .",
        "grep -r --group-separator SEP TOKEN .",
        "grep -r --group-separator SEP TOKEN",
        "grep -r --group-separator SEP TOKEN .env",
        "grep -r --group-separator TOKEN .env",
        "grep -r --line-buffered TOKEN",
        "grep -r --line-buffered TOKEN .env",
        "grep -rnTOKEN .",
        "grep -rA1 TOKEN .",
        "grep -rneTOKEN .",
        "grep -rnfpatterns .",
        "grep -rz TODO .",
        "grep -rq TODO .",
        "grep -rl TODO .",
        "grep -r -f patterns .",
        "grep TODO .env",
        "grep -r TODO .env",
        "printf 'TOKEN=TODO' > .env; grep -r TODO .",
        "printf 'TOKEN=TODO' > .env; grep -r TODO . 2>/dev/null",
        "grep -r TODO . > .env.new",
        "grep -r TOKEN . 2>/dev/null",
        "grep -r TODO .; cat .env",
        "GREP_OPTIONS=-v grep -r TODO .",
        "env GREP_OPTIONS=-v grep -r TODO .",
        "export GREP_OPTIONS=-v; grep -r TODO .",
        "POSIXLY_CORRECT=1 grep -r 'T.*' . -F",
    ] {
        check(command, "block");
    }
    std::fs::create_dir(project.join("nested")).unwrap();
    std::fs::write(project.join("nested/.env.local"), "OTHER=TODO\n").unwrap();
    check("grep -r TODO .", "block");
    check("grep -r TODO --exclude=.env.local .", "delegate");
    std::fs::write(project.join("nested/.env.local"), "OTHER=value\n").unwrap();
    check("grep -r TODO .", "delegate");
    std::fs::write(project.join(".env"), vec![b'x'; 65537]).unwrap();
    check("grep -r TODO .", "block");
    std::fs::write(project.join(".env"), b"TOKEN=value\0\n").unwrap();
    check("grep -r TODO .", "block");
    std::fs::write(project.join(".env"), "TOKEN=\u{212a}\n").unwrap();
    check("grep -ri k .", "block");
    check("grep -rF TODO .", "delegate");
    std::fs::write(project.join(".env"), credential).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        std::fs::set_permissions(project.join(".env"), std::fs::Permissions::from_mode(0o0))
            .unwrap();
        if std::fs::read(project.join(".env")).is_err() {
            check("grep -r TODO .", "block");
        }
        std::fs::set_permissions(project.join(".env"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        symlink(".env", project.join("public")).unwrap();
        check("grep -R TODO .", "delegate");
        check("grep -R TOKEN .", "block");
        symlink("missing", project.join(".env.missing")).unwrap();
        check("grep -R TODO .", "block");
    }
    std::fs::create_dir(project.join(".boto")).unwrap();
    std::fs::write(project.join(".boto/config"), "TOKEN=TODO\n").unwrap();
    check("grep -r TODO .boto", "block");
}

#[test]
fn native_search_ignore_exemptions_require_runtime_evidence_and_no_ripgrep_config() {
    let temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(temp.path());
    let project = repo(&home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    std::fs::write(project.join(".gitignore"), ".env\n").unwrap();
    let config = home.join("ripgrep.conf");
    std::fs::write(&config, "--no-ignore\n").unwrap();

    for (runtime, tool, input) in [
        (
            "antigravity",
            "grep_search",
            serde_json::json!({"SearchPath":project,"Query":"TODO"}),
        ),
        (
            "droid",
            "Grep",
            serde_json::json!({"path":project,"pattern":"TODO"}),
        ),
        (
            "copilot",
            "grep",
            serde_json::json!({"path":project,"pattern":"TODO"}),
        ),
        (
            "openclaw",
            "grep",
            serde_json::json!({"path":project,"pattern":"TODO"}),
        ),
        (
            "hermes",
            "search_files",
            serde_json::json!({"path":project,"pattern":"TODO","target":"content"}),
        ),
        (
            "cline",
            "search_files",
            serde_json::json!({"path":project,"regex":"TODO"}),
        ),
        (
            "cline",
            "search_codebase",
            serde_json::json!({"queries":["TODO"]}),
        ),
        (
            "claude",
            "Grep",
            serde_json::json!({"path":project,"pattern":"TODO"}),
        ),
    ] {
        for configured in [false, true] {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_nah"));
            command
                .args([
                    "test",
                    "--json",
                    "--runtime",
                    runtime,
                    "--tool",
                    tool,
                    "--args-json",
                    &input.to_string(),
                ])
                .current_dir(&project)
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("RIPGREP_CONFIG_PATH");
            if configured {
                command.env("RIPGREP_CONFIG_PATH", &config);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{output:?}");
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let blocked = configured || runtime != "claude";
            assert_eq!(
                value["decision"]["verdict"],
                if blocked { "block" } else { "delegate" },
                "{runtime} {tool}, configured={configured}: {value}"
            );
            assert_eq!(
                value["decision"]["policy_attributions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|guard| guard["name"] == "secrets-env"),
                blocked,
                "{runtime} {tool}, configured={configured}: {value}"
            );
        }
    }
}
