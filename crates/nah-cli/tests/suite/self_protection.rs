#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::path::Path;

use nah_cli::decide_with;
#[cfg(unix)]
use nah_proto::decision::DecisionOutput;
use nah_proto::decision::{DecisionCore, Verdict};
#[cfg(unix)]
use nah_proto::effects::FactPayload;
use serde_json::json;
#[cfg(unix)]
use support::bash_path;
use support::{call, ctx, repo};

fn decide(home: &Path, repo: &Path, tool: &str, input: serde_json::Value) -> DecisionCore {
    let disabled = support::settings_ctx(
        home,
        nah_proto::ctx::GuardSettings::every_guard_at(nah_proto::ctx::GuardLevel::Off),
    );
    let search_path = search_path(home);
    nah_cli::decide_with(&call(tool, input, repo), &disabled, |request| {
        support::observe_with_path(&search_path, request)
    })
    .core()
    .clone()
}

/// The PATH a bare `nah` is searched on, with the launchers this suite wraps
/// it in.
fn search_path(home: &Path) -> String {
    support::search_path(home, &["bash", "doas", "env", "git", "nice", "nohup", "sh"])
}

#[test]
fn self_protection_owns_nah_authority_and_runtime_lifecycle_commands() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let critical_path = home.join(".nah/trust.json");
    std::fs::create_dir_all(critical_path.parent().unwrap()).unwrap();
    std::fs::write(&critical_path, "{}").unwrap();

    let critical_writes = [home.join(".nah/trust.json")];
    for path in critical_writes {
        let decision = decide(
            home,
            &repo,
            "Write",
            json!({"file_path":path, "content":"replace"}),
        );
        assert_eq!(decision.verdict(), Verdict::Block, "{path:?}");
        assert!(decision.reason().contains("nah nap"));
        assert!(decision.policy_attributions().is_empty());
    }

    for command in [
        "nah tui",
        "nah snapshot save --budget-bytes 9999999999",
        "nah snapshot fresh",
        "nah snapshots prune",
        "nah snapshots --json prune --all",
        "nah rule disable machine/system-files-modify",
        "nah rule reset machine/system-files-modify",
        "git -c 'alias.off=!nah rule disable machine/system-files-modify' off",
        "nah guard set machine off",
        "nah guard reset machine",
        "cargo uninstall nah",
        "cargo uninstall nah-cli",
        "nah hook claude install",
        "nah hook codex install",
        "nah hook hermes install",
        "nah hook claude uninstall",
        "nah hook antigravity uninstall",
        "nah hook cline uninstall",
        "nah hook codex uninstall",
        "nah hook copilot uninstall",
        "nah hook cursor uninstall",
        "nah hook devin uninstall",
        "nah hook droid uninstall",
        "nah hook hermes uninstall",
        "nah hook kiro uninstall",
        "nah hook openclaw uninstall",
        "nah hook pi uninstall",
        "nah hook opencode uninstall",
        "nah hook amp uninstall",
        "agy plugin disable nah",
        "droid plugin uninstall nah",
        "hermes hooks revoke 'nah hook hermes run'",
        "hermes hooks rm 'nah hook hermes run'",
        "copilot plugin remove nah",
        "openclaw plugins disable nah",
        "openclaw config set plugins.enabled false",
        "amp plugins remove nah.ts --target system",
        "claude --safe-mode",
        "claude --bare",
        "codex --disable hooks",
        "CODEX_HOME=/tmp/other codex",
        "hermes --safe-mode",
        "hermes --ignore-user-config",
        "HERMES_HOME=/tmp/other hermes",
        "hermes config set hooks.pre_tool_call.0.command true",
        "hermes config unset hooks.pre_tool_call.0",
        "openclaw --profile other",
        "openclaw --dev",
        "OPENCLAW_STATE_DIR=/tmp/other openclaw",
        "XDG_CONFIG_HOME=/tmp/other opencode",
        "pi --no-extensions",
        "PI_CODING_AGENT_DIR=/tmp/other pi",
    ] {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_eq!(decision.verdict(), Verdict::Block, "{command}");
        assert!(decision.reason().contains("nah nap"), "{command}");
    }

    for command in [
        "agy plugin install /tmp/example",
        "droid plugin install example",
        "copilot plugin install ./example",
        "openclaw plugins install ./example",
        "amp plugins add @owner/example",
        "hermes plugins disable nah",
        "hermes hooks revoke 'xnah hook hermes runx'",
        "claude --dangerously-skip-permissions",
        "codex --yolo",
        "copilot --allow-all",
        "droid --skip-permissions-unsafe",
        "hermes /yolo",
        "cline --config --help",
        "cline --hooks-dir /tmp/additional",
        "claude --safe-mode --help",
        // The agent's own recovery from a save-then-run discard.
        "nah undo 0123456789abcdef",
        "nah snapshots",
    ] {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_ne!(decision.verdict(), Verdict::Block, "{command}");
    }

    for path in [
        home.join(".codex/hooks.json"),
        home.join(".cursor/hooks.json"),
        home.join(".gemini/config/hooks.json"),
        home.join(".factory/settings.json"),
        home.join(".hermes/config.yaml"),
        home.join(".kiro/hooks/nah.json"),
        home.join(".openclaw/openclaw.json"),
        home.join(".pi/agent/settings.json"),
        home.join(".copilot/hooks/nah.json"),
        home.join("Documents/Cline/Hooks/PreToolUse"),
        home.join(".openclaw/extensions/nah/index.js"),
        home.join(".pi/agent/extensions/nah/index.js"),
        home.join(".config/opencode/plugins/nah.js"),
        home.join(".config/amp/plugins/nah.ts"),
        repo.join(".github/hooks/nah.json"),
        repo.join(".cline/plugins/example.js"),
        repo.join(".opencode/plugins/example.js"),
        repo.join(".amp/plugins/example.ts"),
    ] {
        let decision = decide(
            home,
            &repo,
            "Write",
            json!({"file_path":path, "content":"replace"}),
        );
        assert_ne!(decision.verdict(), Verdict::Block, "{path:?}");
    }
}

#[test]
fn nap_state_is_permanent() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);

    for input in [
        call("Bash", json!({"command":"nah nap"}), &repo),
        call(
            "Write",
            json!({"file_path":home.join(".nah/nap.json"), "content":"{}"}),
            &repo,
        ),
        call(
            "Write",
            json!({"file_path":home.join(".nah/nap.key"), "content":"forged"}),
            &repo,
        ),
    ] {
        let result = decide_with(&input, &ctx(home), |request| {
            support::observe_with_path(&search_path(home), request)
        });
        assert_eq!(result.core().verdict(), Verdict::Block);
        assert!(
            result
                .core()
                .reason()
                .contains("must be started by the operator"),
            "{}",
            result.core().reason()
        );
    }
}

#[test]
fn native_tool_payload_cannot_forge_the_internal_critical_operation() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let decision = decide(
        home,
        &repo,
        "custom_tool",
        json!({"program":"nah","operation":"critical-mutation"}),
    );
    assert_eq!(decision.verdict(), Verdict::Delegate);
}

#[cfg(unix)]
#[test]
fn shell_state_indirection_cannot_hide_nah_authority_mutations() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let critical = bash_path(&home.join(".nah/config"));
    let commands = [
        format!("set -- {critical}; printf x > \"$1\""),
        format!("bash -c 'printf x > \"$1\"' shell {critical}"),
        format!("bash -c 'printf x > \"$0\"' {critical}"),
        r#"env 'BASH_FUNC_f%%=() { nah nap; }' bash -c f"#.to_owned(),
        r#"env -S "bash -c 'nah nap'""#.to_owned(),
        // Padding before the deletion cannot push it past an analysis bound.
        format!(
            "{}rm -rf {}",
            "echo y && ".repeat(5000),
            bash_path(&home.join(".nah"))
        ),
    ];
    for command in commands {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_eq!(decision.verdict(), Verdict::Block, "{command}");
    }

    for command in ["set -- safe; shift 2; printf x > \"$1\"", "env printf safe"] {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_ne!(decision.verdict(), Verdict::Block, "{command}");
    }
}

/// A bare `nah`, however it is launched, is identified by its PATH search:
/// it blocks because every earlier candidate is observed absent and the one
/// selected is the installed binary, so a decoy `nah` earlier on PATH is what
/// runs instead, and the call no longer controls nah.
#[cfg(unix)]
#[test]
fn bare_nah_is_identified_by_the_executable_its_path_search_selects() {
    use std::os::unix::fs::PermissionsExt;

    let home_temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let commands = [
        "nah rule disable work/files-delete".to_owned(),
        "exec nah rule disable work/files-delete".to_owned(),
        "nice nah rule disable work/files-delete".to_owned(),
        "nohup nah rule disable work/files-delete".to_owned(),
        "doas nah rule disable work/files-delete".to_owned(),
        "env nah rule disable work/files-delete".to_owned(),
        "(nah rule disable work/files-delete)".to_owned(),
        "if true; then nah rule disable work/files-delete; fi".to_owned(),
        "git -c 'alias.t=!nah rule disable work/files-delete' t".to_owned(),
        "CMD=nah; \"$CMD\" rule disable work/files-delete".to_owned(),
        "bash -c 'nah rule disable work/files-delete'".to_owned(),
        "printf 'nah rule disable work/files-delete' | bash".to_owned(),
        "nah nap".to_owned(),
    ];
    for command in &commands {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_eq!(decision.verdict(), Verdict::Block, "{command}");
        assert!(decision.reason().contains("nah nap"), "{command}");
    }

    let decoy = home.join("decoy/nah");
    std::fs::create_dir_all(decoy.parent().unwrap()).unwrap();
    std::fs::write(&decoy, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
    for command in &commands {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        // doas searches its own safe path, not the caller's, so the decoy
        // there proves nothing and the uncertified nah still blocks.
        if command.starts_with("doas ") {
            assert_eq!(decision.verdict(), Verdict::Block, "{command}");
        } else {
            assert_ne!(decision.verdict(), Verdict::Block, "{command}");
        }
    }
}

/// An installed nah beside project executables, aliases and copies of it.
#[cfg(unix)]
fn alias_fixture(home: &Path, repo: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let installed = home.join(".local/bin/nah");
    std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
    std::fs::write(&installed, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(repo.join("ordinary"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        repo.join("ordinary"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::copy(repo.join("ordinary"), repo.join("existing")).unwrap();
    std::fs::create_dir(repo.join("directory")).unwrap();
    symlink(repo, home.join("repo-link")).unwrap();
    symlink(&installed, repo.join("linked")).unwrap();
    symlink(&installed, repo.join("nah")).unwrap();
    std::fs::copy(&installed, repo.join("copied")).unwrap();
    installed
}

#[cfg(unix)]
#[test]
fn direct_and_same_call_nah_executable_aliases_remain_self_protected() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let installed = alias_fixture(home, &repo);
    let state = home.join(".nah/trust.json");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    std::fs::write(&state, "{}").unwrap();
    let hard_link = format!(
        "python3 -c 'import os; os.link(\"{}\", \"/tmp/trust-alias\")'",
        state.display()
    );

    let result = decide_with(
        &call(
            "Bash",
            json!({"command":format!("{} nap", bash_path(&installed))}),
            &repo,
        ),
        &ctx(home),
        support::fulfill_observation,
    );
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(result.core().reason().contains("nah nap"));

    // A link this call creates, or one the host already had, resolves to the
    // installed binary whatever the name it is run under. A `nah` this call
    // rewrote has no identity and keeps its spelling's tier for now. Moving
    // the binary blocks as a mutation of it, and a hard link to protected
    // state blocks as a new name through which that state can be written.
    for (command, reason) in [
        (hard_link.clone(), "nah nap"),
        (format!("test -e x && {hard_link}"), "nah nap"),
        (
            "./nah rule disable work/files-delete".to_owned(),
            "self/nah-config-change: ",
        ),
        (
            "./linked rule disable work/files-delete".to_owned(),
            "self/nah-config-change: ",
        ),
        (
            "ln -s nah relative && ./relative rule disable work/files-delete".to_owned(),
            "self/nah-config-change: ",
        ),
        (
            "mkdir tools; cp ordinary tools/nah; ./tools/nah rule disable work/files-delete"
                .to_owned(),
            "self/nah-config-change: ",
        ),
        (
            format!(
                "ln -s {} alias && ./alias rule disable work/files-delete",
                bash_path(&installed)
            ),
            "self/nah-config-change: ",
        ),
        (
            format!(
                "ln -f {} existing && ./existing rule disable work/files-delete",
                bash_path(&installed)
            ),
            "self/nah-config-change: ",
        ),
        (
            format!(
                "ln {} existing; ./existing rule disable work/files-delete",
                bash_path(&installed)
            ),
            "self/nah-config-change: ",
        ),
        (
            format!("ln -s {} alias && ./alias nap", bash_path(&installed)),
            "must be started by the operator",
        ),
        (
            format!(
                "mv {} alias && ./alias rule disable work/files-delete",
                bash_path(&installed)
            ),
            "nah nap",
        ),
        (
            format!(
                "mv {} existing && ./existing rule disable work/files-delete",
                bash_path(&installed)
            ),
            "nah nap",
        ),
        // The same file copied and launched through a directory link.
        (
            format!(
                "cp {} {link}/first && cp {link}/first {link}/second && ./second rule disable work/files-delete",
                bash_path(&installed),
                link = bash_path(&home.join("repo-link")),
            ),
            "self/nah-config-change: ",
        ),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &ctx(home),
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(result.core().reason().contains(reason), "{command}");
    }

    // Replaced before it runs, the pre-existing `./nah` names the ordinary
    // program: the call blocks for replacing the link, not as a nah command.
    let replaced = decide_with(
        &call(
            "Bash",
            json!({"command":"ln -sf ordinary nah; ./nah rule disable work/files-delete".to_owned()}),
            &repo,
        ),
        &ctx(home),
        support::fulfill_observation,
    );
    assert!(
        !support::facts(&replaced)
            .iter()
            .any(|fact| matches!(fact.payload, FactPayload::ControlMutation { .. })),
        "{:?}",
        support::facts(&replaced)
    );

    for command in [
        format!("test -e x || {hard_link}"),
        format!("cp {} /tmp/copy", bash_path(&state)),
        format!("ln -s {} /tmp/alias", bash_path(&state)),
        format!(
            "python3 -c 'import shutil; shutil.copy(\"{}\", \"/tmp/copy\")'",
            state.display()
        ),
        "/tmp/nah rule disable work/files-delete".to_owned(),
        format!(
            "ln -s {} alias && ./alias docs extending",
            bash_path(&installed)
        ),
        format!(
            "ln -s {} alias; rm alias; ./alias rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "ln -s {} alias; ln -sf ordinary alias; ./alias rule disable work/files-delete",
            bash_path(&installed)
        ),
        "./copied rule disable work/files-delete".to_owned(),
        "./ordinary rule disable work/files-delete".to_owned(),
        "./linked docs extending".to_owned(),
        format!(
            "cp {} alias; printf x > alias; ./alias rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp {} alias; rm alias; ./alias rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp {} alias; cp ordinary alias; ./alias rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp -n {} existing; ./existing rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp -u {} existing; ./existing rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp {} absent/alias; ./absent/alias rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp {} directory; ./directory rule disable work/files-delete",
            bash_path(&installed)
        ),
        format!(
            "cp {} -t directory; ./directory rule disable work/files-delete",
            bash_path(&installed)
        ),
        "ln -s missing dangling; ./dangling rule disable work/files-delete".to_owned(),
        "ln -s ordinary ordinary-link; ./ordinary-link rule disable work/files-delete".to_owned(),
    ] {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_ne!(decision.verdict(), Verdict::Block, "{command}");
    }
}

/// The deciding executable is nah wherever it is installed: this test binary
/// sits outside every standard install location.
#[cfg(unix)]
#[test]
fn the_deciding_executable_is_nah_at_any_install_path() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let home_temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let executable = Path::new(env!("CARGO_BIN_EXE_nah"));
    std::os::unix::fs::symlink(executable, repo.join("tool")).unwrap();
    for command in [
        format!("{} rule disable work/files-delete", bash_path(executable)),
        "./tool rule disable work/files-delete".to_owned(),
    ] {
        let mut child = Command::new(executable)
            .arg("decide")
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                json!({"v":1,"tool":"Bash","input":{"command":command},"cwd":repo})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let decision: DecisionOutput = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{command}");
    }
}

#[cfg(unix)]
#[test]
fn shell_hard_link_to_protected_state_is_self_protected() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let state = home.join(".nah/trust.json");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    std::fs::write(&state, "{}").unwrap();

    let command = format!("ln {} /tmp/alias", bash_path(&state));
    let decision = decide(home, &repo, "Bash", json!({"command":command}));
    assert_eq!(decision.verdict(), Verdict::Block, "{command}");
}
