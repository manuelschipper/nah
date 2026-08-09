#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::path::Path;

use nah_cli::{POLICY_VERSION, decide_with};
use nah_proto::ctx::{Ctx, SchemaVersion, ShippedGuardState, TrustProjection};
use nah_proto::decision::{DecisionCore, Verdict};
use serde_json::json;
use support::{absolute, bash_path, call, ctx, host_platform, repo};

fn decide(home: &Path, repo: &Path, tool: &str, input: serde_json::Value) -> DecisionCore {
    let disabled = Ctx::new(
        SchemaVersion::V1,
        host_platform(),
        absolute(home),
        nah_cli::shipped_guard_states()
            .into_iter()
            .map(|state| ShippedGuardState::new(state.name(), false).unwrap())
            .collect(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap();
    nah_cli::decide_with(&call(tool, input, repo), &disabled, |request| {
        nah_observe::fulfill(request).map_err(|error| error.to_string())
    })
    .core()
    .clone()
}

#[test]
fn self_protection_owns_nah_authority_and_runtime_lifecycle_commands() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
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
        "nah trust .",
        "nah untrust .",
        "nah guard disable fs-system-tree",
        "git -c 'alias.off=!nah guard disable fs-system-tree' off",
        "nah guard disable fs-system-tree",
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
        "PLUGINS=off amp",
        "OPENCODE_PURE=1 opencode",
        "KIRO_HOME=/tmp/other kiro-cli --v3",
        "claude --safe-mode",
        "claude --bare",
        "cline --config /tmp/without-nah",
        "CLINE_DIR=/tmp/without-nah cline",
        "codex --disable hooks",
        "CODEX_HOME=/tmp/other codex",
        "COPILOT_HOME=/tmp/other copilot",
        "devin --config /tmp/other.json",
        "droid --settings /tmp/without-nah.json",
        "hermes --safe-mode",
        "hermes --ignore-user-config",
        "HERMES_HOME=/tmp/other hermes",
        "hermes config set hooks.pre_tool_call.0.command true",
        "hermes config unset hooks.pre_tool_call.0",
        "openclaw --profile other",
        "openclaw --dev",
        "OPENCLAW_STATE_DIR=/tmp/other openclaw",
        "opencode --pure",
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
        "opencode --pure --version",
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
fn nap_state_is_permanent_and_project_policy_remains_a_proposal() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
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
            nah_observe::fulfill(request).map_err(|error| error.to_string())
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

    let proposal = decide_with(
        &call(
            "Write",
            json!({"file_path":repo.join(".nah/guards/demo/run"), "content":"proposal"}),
            &repo,
        ),
        &ctx(home),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(proposal.core().verdict(), Verdict::Delegate);
}

#[test]
fn native_tool_payload_cannot_forge_the_internal_critical_operation() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
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

#[test]
fn shell_state_indirection_cannot_hide_nah_authority_mutations() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let repo = repo(home);
    let critical = bash_path(&home.join(".nah/config"));
    let commands = [
        format!("set -- {critical}; printf x > \"$1\""),
        format!("bash -c 'printf x > \"$1\"' shell {critical}"),
        format!("bash -c 'printf x > \"$0\"' {critical}"),
        format!(
            "printf 'printf x > \"$1\"' > startup; BASH_ENV=\"$PWD/startup\" bash script {critical}"
        ),
        r#"env 'BASH_FUNC_f%%=() { nah nap; }' bash -c f"#.to_owned(),
        r#"env -S "bash -c 'nah nap'""#.to_owned(),
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

#[cfg(unix)]
#[test]
fn direct_project_interpreter_cannot_hide_descriptor_self_protection() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let repo = repo(home);
    std::fs::create_dir_all(repo.join("bin")).unwrap();
    std::fs::write(repo.join("bin/python"), "#!/usr/bin/env python3\n").unwrap();
    let protected = bash_path(&home.join(".local/bin/nah"));
    let command =
        format!(r#"exec 3<<<'import os; os.chmod("{protected}", 0)'; ./bin/python /dev/fd/3"#);

    let decision = decide(home, &repo, "Bash", json!({"command":command}));
    assert_eq!(decision.verdict(), Verdict::Block);
}

#[cfg(unix)]
#[test]
fn direct_and_same_call_nah_executable_aliases_remain_self_protected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let repo = repo(home);
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
    symlink(&installed, repo.join("linked")).unwrap();
    symlink(&installed, repo.join("nah")).unwrap();
    std::fs::copy(&installed, repo.join("copied")).unwrap();

    for command in [
        format!("./linked trust {}", bash_path(&repo)),
        format!("{} nap", bash_path(&installed)),
        format!(
            "cp {} alias && ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "ln -s {} alias && ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "ln -s nah relative && ./relative trust {}",
            bash_path(&repo)
        ),
        format!(
            "cp {} first && ln -s first second && ./second trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "link {} alias && ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "mv {} alias && ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp {} existing && ./existing trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp -i {} existing; ./existing trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "mv {} existing && ./existing trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "ln -f {} existing && ./existing trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "ln {} existing; ./existing trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &ctx(home),
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(
            result.core().verdict(),
            Verdict::Block,
            "{command}: {:?}",
            result.action_stream().effects()
        );
        assert!(result.core().reason().contains("nah nap"), "{command}");
    }

    for command in [
        format!("./copied trust {}", bash_path(&repo)),
        format!("./ordinary trust {}", bash_path(&repo)),
        "./linked docs extending".to_owned(),
        format!(
            "cp {} alias; printf x > alias; ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp {} alias; rm alias; ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp {} alias; cp ordinary alias; ./alias trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp -n {} existing; ./existing trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp {} directory; ./directory trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "cp {} -t directory; ./directory trust {}",
            bash_path(&installed),
            bash_path(&repo)
        ),
        format!(
            "ln -s missing dangling; ./dangling trust {}",
            bash_path(&repo)
        ),
        format!(
            "ln -s ordinary ordinary-link; ./ordinary-link trust {}",
            bash_path(&repo)
        ),
    ] {
        let decision = decide(home, &repo, "Bash", json!({"command":command}));
        assert_ne!(decision.verdict(), Verdict::Block, "{command}");
    }
}
