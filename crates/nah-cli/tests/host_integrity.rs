#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use nah_cli::decide_with;
#[cfg(unix)]
use nah_proto::action::EffectKind;
use nah_proto::decision::Verdict;
use serde_json::json;
use support::{bash_path, call, ctx, factory_ctx, repo};

fn decide(
    command: &str,
    cwd: &std::path::Path,
    context: &nah_proto::ctx::Ctx,
) -> nah_cli::DecisionResult {
    decide_with(
        &call("Bash", json!({"command":command}), cwd),
        context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    )
}

#[test]
fn factory_posture_delegates_shell_profiles_and_blocks_persistence_and_auth_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = factory_ctx(&root);
    let profile = root.join(".bashrc");
    let persistence = root.join(".ssh/rc");
    let auth = root.join(".ssh/authorized_keys");

    for command in [
        format!("printf '%s\\n' alias >> {}", bash_path(&profile)),
        format!("rm {}", bash_path(&profile)),
    ] {
        assert_eq!(
            decide(&command, &repo, &context).core().verdict(),
            Verdict::Delegate,
            "{command}"
        );
    }

    let persistence_result = decide(
        &format!("printf '%s\\n' hook >> {}", bash_path(&persistence)),
        &repo,
        &context,
    );
    assert_eq!(persistence_result.core().verdict(), Verdict::Block);
    assert_eq!(
        persistence_result.core().policy_attributions()[0].name(),
        "fs-startup-persistence"
    );

    let auth_result = decide(
        &format!("printf '%s\\n' key >> {}", bash_path(&auth)),
        &repo,
        &context,
    );
    assert_eq!(auth_result.core().verdict(), Verdict::Block);
    assert_eq!(
        auth_result.core().policy_attributions()[0].name(),
        "fs-auth-identity"
    );
    assert!(auth_result.core().reason().contains("nah tui"));
}

#[test]
fn enabling_shell_profiles_blocks_each_visible_mutation_producer() {
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let profile = root.join(".zshrc");

    let bash = decide(
        &format!("printf '%s\\n' alias >> {}", bash_path(&profile)),
        &repo,
        &context,
    );
    assert_eq!(bash.core().verdict(), Verdict::Block);
    assert!(
        bash.core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-shell-profile")
    );

    let native = decide_with(
        &call(
            "Write",
            json!({"file_path":profile,"content":"alias ll='ls -la'\n"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(native.core().verdict(), Verdict::Block);
    assert!(
        native
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-shell-profile")
    );

    let patch = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Add File: ../.bashrc\n+alias ll='ls -la'\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(patch.core().verdict(), Verdict::Block);
    assert!(
        patch
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-shell-profile")
    );

    let source = format!(
        "from pathlib import Path; Path({}).write_text(\"alias ll=ls\")",
        serde_json::to_string(profile.to_str().unwrap()).unwrap()
    );
    let visible_python = decide(&format!("python3 -c '{source}'"), &repo, &context);
    assert_eq!(visible_python.core().verdict(), Verdict::Block);
    assert!(
        visible_python
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-shell-profile")
    );
}

#[cfg(unix)]
#[test]
fn reviewed_destructive_utilities_name_only_real_auth_targets() {
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = factory_ctx(&root);

    for command in [
        "truncate -s 0 /etc/passwd",
        "truncate --size=0 /etc/passwd",
        "shred -u -z /etc/passwd",
        "shred --remove=wipe /etc/passwd",
    ] {
        let result = decide(command, &repo, &context);
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|guard| guard.name() == "fs-auth-identity"),
            "{command}: {:?}",
            result.core().policy_attributions()
        );
        assert!(
            result
                .action_stream()
                .effects()
                .iter()
                .filter_map(|effect| match effect.kind() {
                    EffectKind::Filesystem { effect } => Some(effect),
                    _ => None,
                })
                .all(|effect| !effect.target.as_str().ends_with("/0")),
            "{command}"
        );
    }
}

#[test]
fn ordinary_reads_dotfiles_and_unlisted_system_writes_still_delegate() {
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    for command in [
        format!("cat {}", bash_path(&root.join(".bashrc"))),
        format!("printf x > {}", bash_path(&root.join(".vimrc"))),
        "printf x > /etc/hosts".into(),
        "printf x > /tmp/ordinary".into(),
    ] {
        assert_eq!(
            decide(&command, &repo, &context).core().verdict(),
            Verdict::Delegate,
            "{command}"
        );
    }
}

#[cfg(unix)]
#[test]
fn requested_shell_profile_identity_survives_a_symlinked_target() {
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let target = repo.join("zshrc");
    std::fs::write(&target, "# aliases\n").unwrap();
    let startup = root.join(".zshrc");
    std::os::unix::fs::symlink(&target, &startup).unwrap();

    let result = decide_with(
        &call(
            "Write",
            json!({"file_path":startup,"content":"alias ll='ls -la'\n"}),
            &repo,
        ),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(
        result
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-shell-profile")
    );
}
