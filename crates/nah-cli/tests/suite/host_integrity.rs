#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use nah_cli::decide_with;
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
        support::fulfill_observation,
    )
}

#[test]
fn factory_posture_delegates_shell_profiles_and_blocks_persistence_and_auth_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
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
        "persistence/startup-item-add"
    );

    let auth_result = decide(
        &format!("printf '%s\\n' key >> {}", bash_path(&auth)),
        &repo,
        &context,
    );
    assert_eq!(auth_result.core().verdict(), Verdict::Block);
    assert_eq!(
        auth_result.core().policy_attributions()[0].name(),
        "persistence/auth-files-modify"
    );
}

#[test]
fn enabling_shell_profiles_blocks_each_visible_mutation_producer() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
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
            .any(|guard| guard.name() == "persistence/shell-profile-write")
    );

    let native = decide_with(
        &call(
            "Write",
            json!({"file_path":profile,"content":"alias ll='ls -la'\n"}),
            &repo,
        ),
        &context,
        support::fulfill_observation,
    );
    assert_eq!(native.core().verdict(), Verdict::Block);
    assert!(
        native
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "persistence/shell-profile-write")
    );

    let patch = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Add File: ../.bashrc\n+alias ll='ls -la'\n*** End Patch"}),
            &repo,
        ),
        &context,
        support::fulfill_observation,
    );
    assert_eq!(patch.core().verdict(), Verdict::Block);
    assert!(
        patch
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "persistence/shell-profile-write")
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
            .any(|guard| guard.name() == "persistence/shell-profile-write")
    );
}

#[cfg(unix)]
#[test]
fn reviewed_destructive_utilities_name_only_real_auth_targets() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
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
                .any(|guard| guard.name() == "persistence/auth-files-modify"),
            "{command}: {:?}",
            result.core().policy_attributions()
        );
        assert!(
            support::filesystem_accesses(&result)
                .iter()
                .all(|(_, resource, _)| !support::resource_path(resource)
                    .is_some_and(|path| path.ends_with("/0"))),
            "{command}: {:?}",
            support::facts(&result)
        );
    }
}

#[test]
fn ordinary_reads_dotfiles_and_unlisted_system_writes_still_delegate() {
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
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
    let root = support::test_temp_path(temp.path());
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
        support::fulfill_observation,
    );
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(
        result
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "persistence/shell-profile-write")
    );

    // The code a shell append writes is judged as startup code when the
    // command opens the profile by its startup name, though the engine names
    // the write by the ordinary file the link reaches; and when a project
    // link reaches a profile after enough writes that the engine's own path
    // lookups ran out.
    std::fs::write(repo.join(".env"), "TOKEN=x\n").unwrap();
    let profile = root.join(".bashrc");
    std::fs::write(&profile, "").unwrap();
    let linked = repo.join("rc");
    std::os::unix::fs::symlink(&profile, &linked).unwrap();
    let generated = (0..70)
        .map(|index| format!(": > generated-{index}"))
        .collect::<Vec<_>>()
        .join("; ");
    let reads_env = format!("echo \"cat {}\" >>", bash_path(&repo.join(".env")));
    for command in [
        format!("{reads_env} {}", bash_path(&startup)),
        format!("{generated}; {reads_env} {}", bash_path(&linked)),
    ] {
        let result = decide(&command, &repo, &factory_ctx(&root));
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|guard| guard.name() == "secrets/env-files-read"),
            "{command}"
        );
    }

    // Past the write-target lookups' own limit, where the last write lands
    // is not established, so the call is blocked whatever that write carries.
    let exhausted = (0..250)
        .map(|index| format!(": > generated-{index}"))
        .collect::<Vec<_>>()
        .join("; ");
    let command = format!("{exhausted}; echo alias >> {}", bash_path(&linked));
    let result = decide(&command, &repo, &factory_ctx(&root));
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(
        result
            .refusals()
            .iter()
            .any(|refusal| refusal.code() == "startup-target-observation-limit")
    );
}
