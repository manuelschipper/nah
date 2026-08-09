#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::cell::Cell;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use nah_cli::decide_with;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, PathScope};
use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::{DecisionOutput, Verdict};
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use support::{bash_path, call, ctx, git, repo};

#[test]
fn live_native_tools_delegate_project_effects_and_block_environment_secrets() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);

    for (tool, input) in [
        ("Read", json!({"file_path":"src/lib.rs"})),
        ("Write", json!({"file_path":"new.txt", "content":"new"})),
        (
            "Edit",
            json!({"file_path":"src/lib.rs", "old_string":"demo", "new_string":"next"}),
        ),
        ("Glob", json!({"pattern":"lib.rs", "path":"src"})),
        ("Grep", json!({"pattern":"demo", "path":"src/lib.rs"})),
    ] {
        let result = decide_with(&call(tool, input, &repo), &context, |request| {
            nah_observe::fulfill(request).map_err(|error| error.to_string())
        });
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{tool}");
        assert_eq!(result.core().coverage(), Coverage::Full);
    }

    let sensitive = decide_with(
        &call("Read", json!({"file_path":".env"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(sensitive.core().verdict(), Verdict::Block);

    let git_metadata = decide_with(
        &call(
            "Write",
            json!({"file_path":".git/config", "content":"[core]\n"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(git_metadata.core().verdict(), Verdict::Delegate);
    assert_eq!(git_metadata.core().coverage(), Coverage::Full);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let outside = &root.join("outside");
        std::fs::create_dir(outside).unwrap();
        symlink(outside.join("new-file"), repo.join("dangling-link")).unwrap();
        symlink(outside.join("missing-dir"), repo.join("dangling-parent")).unwrap();
        let escaped_write = decide_with(
            &call(
                "Write",
                json!({"file_path":"dangling-link", "content":"new"}),
                &repo,
            ),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(escaped_write.core().verdict(), Verdict::Delegate);

        let escaped_child_write = decide_with(
            &call(
                "Write",
                json!({"file_path":"dangling-parent/file", "content":"new"}),
                &repo,
            ),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(escaped_child_write.core().verdict(), Verdict::Delegate);

        std::fs::write(outside.join("secret.txt"), "outside\n").unwrap();
        std::fs::create_dir(repo.join("escape")).unwrap();
        std::fs::write(repo.join("escape/secret.txt"), "inside\n").unwrap();
        symlink(outside, repo.join("escape\\")).unwrap();
        let escaped_glob = decide_with(
            &call(
                "Glob",
                json!({"pattern":"secret.txt", "path":"escape\\"}),
                &repo,
            ),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(escaped_glob.core().verdict(), Verdict::Delegate);
        assert_eq!(escaped_glob.core().coverage(), Coverage::Full);
    }

    {
        let key_dir = &root.join(".ssh");
        std::fs::create_dir(key_dir).unwrap();
        let key = key_dir.join("id_ed25519");
        std::fs::write(&key, "private\n").unwrap();
        std::fs::hard_link(&key, repo.join("innocent.txt")).unwrap();
        for (tool, input) in [
            ("Read", json!({"file_path":"innocent.txt"})),
            (
                "Write",
                json!({"file_path":"innocent.txt", "content":"changed"}),
            ),
        ] {
            let aliased = decide_with(&call(tool, input, &repo), &context, |request| {
                nah_observe::fulfill(request).map_err(|error| error.to_string())
            });
            assert_eq!(aliased.core().verdict(), Verdict::Delegate, "{tool}");
            assert_eq!(aliased.core().coverage(), Coverage::Partial, "{tool}");
        }
    }

    for input in [
        json!({"pattern":"../outside/*", "path":"."}),
        json!({"pattern":".e??", "path":"."}),
    ] {
        let glob = decide_with(&call("Glob", input, &repo), &context, |request| {
            nah_observe::fulfill(request).map_err(|error| error.to_string())
        });
        assert_eq!(glob.core().verdict(), Verdict::Delegate);
        assert_eq!(glob.core().coverage(), Coverage::Partial);
    }
    let recursive_grep = decide_with(
        &call("Grep", json!({"pattern":"password", "path":"src"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(recursive_grep.core().verdict(), Verdict::Delegate);
    assert_eq!(recursive_grep.core().coverage(), Coverage::Partial);
}

#[test]
fn live_bash_analysis_keeps_exact_quoted_here_document_code() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let command = format!(
        "python <<'PY'\nimport os\nos.remove({:?})\nPY",
        &root.join(".nah/trust.json").to_str().unwrap()
    );
    let result = decide_with(
        &call("Bash", json!({"command": command}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Block);
}

#[cfg(unix)]
#[test]
fn path_identity_distinguishes_entries_from_targets_and_retains_lexical_danger() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let outside = &root.join("outside");
    std::fs::create_dir(outside).unwrap();
    std::fs::write(outside.join("file"), "outside\n").unwrap();

    symlink("/", repo.join("root-link")).unwrap();
    let delete_project_link = decide_with(
        &call("Bash", json!({"command":"rm -rf root-link"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(delete_project_link.core().verdict(), Verdict::Delegate);

    let delete_through_final_link = decide_with(
        &call("Bash", json!({"command":"rm -rf root-link/."}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(delete_through_final_link.core().verdict(), Verdict::Block);

    symlink(&root, repo.join("home-link")).unwrap();
    let move_project_link = decide_with(
        &call("Bash", json!({"command":"mv home-link moved-link"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(move_project_link.core().verdict(), Verdict::Delegate);

    symlink(repo.join("src/lib.rs"), root.join("outside-link")).unwrap();
    let delete_outside_link = decide_with(
        &call(
            "Bash",
            json!({"command":format!("rm -f {}", bash_path(&root.join("outside-link")))}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(delete_outside_link.core().verdict(), Verdict::Delegate);

    symlink(outside, repo.join("escape")).unwrap();
    let delete_through_parent_link = decide_with(
        &call("Bash", json!({"command":"rm -f escape/file"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(
        delete_through_parent_link.core().verdict(),
        Verdict::Delegate
    );

    std::fs::write(repo.join(".env"), "TOKEN=secret\n").unwrap();
    std::fs::hard_link(repo.join(".env"), repo.join("env-alias")).unwrap();
    let environment = decide_with(
        &call("Read", json!({"file_path":".env"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(environment.core().verdict(), Verdict::Block);
    assert_eq!(environment.core().coverage(), Coverage::Partial);

    std::fs::create_dir(root.join(".ssh")).unwrap();
    std::fs::write(root.join(".ssh/id_rsa"), "private\n").unwrap();
    std::fs::hard_link(root.join(".ssh/id_rsa"), root.join("key-alias")).unwrap();
    let credential = decide_with(
        &call(
            "Bash",
            json!({"command":format!("cat {}", bash_path(&root.join(".ssh/id_rsa")))}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(credential.core().verdict(), Verdict::Block);
    assert_eq!(credential.core().coverage(), Coverage::Partial);

    std::fs::create_dir(root.join(".codex")).unwrap();
    std::fs::write(root.join(".codex/hooks.json"), "{}\n").unwrap();
    std::fs::hard_link(root.join(".codex/hooks.json"), root.join("hooks-alias")).unwrap();
    let shared_runtime_config = decide_with(
        &call(
            "Write",
            json!({"file_path":&root.join(".codex/hooks.json"), "content":"{}"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(shared_runtime_config.core().verdict(), Verdict::Delegate);
    assert_eq!(shared_runtime_config.core().coverage(), Coverage::Partial);
}

#[cfg(unix)]
#[test]
fn symlink_following_project_searches_delegate() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);

    for command in ["rg TODO src", "grep -r TODO src"] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }
    for command in [
        "rg --follow TODO src",
        "rg -L TODO src",
        "grep -R TODO src",
        "grep --dereference-recursive TODO src",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Partial, "{command}");
    }
}

#[test]
fn codex_apply_patch_uses_the_same_project_and_sensitive_path_policy() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);

    let safe = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-pub fn demo() {}\n+pub fn next() {}\n*** Add File: generated.txt\n+generated\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(safe.core().verdict(), Verdict::Delegate);
    assert_eq!(safe.core().coverage(), Coverage::Full);

    let moved = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Update File: src/lib.rs\n*** Move to: src/moved.rs\n@@\n-pub fn demo() {}\n+pub fn moved() {}\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(moved.core().verdict(), Verdict::Delegate);
    assert_eq!(moved.core().coverage(), Coverage::Full);
    assert_eq!(
        moved
            .action_stream()
            .effects()
            .iter()
            .filter_map(|effect| match effect.kind() {
                EffectKind::Filesystem { effect } => Some((
                    effect.operation,
                    std::path::Path::new(effect.target.as_str())
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [
            (FilesystemOperation::Delete, "lib.rs".into()),
            (FilesystemOperation::Write, "moved.rs".into()),
        ]
    );

    let env_write = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Add File: .env\n+secret\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(env_write.core().verdict(), Verdict::Delegate);
    assert_eq!(env_write.core().coverage(), Coverage::Full);

    let sensitive_delete = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Delete File: .env\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(sensitive_delete.core().verdict(), Verdict::Delegate);
    assert_eq!(sensitive_delete.core().coverage(), Coverage::Full);

    let outside = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Add File: ../outside.txt\n+outside\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(outside.core().verdict(), Verdict::Delegate);
    assert_eq!(outside.core().coverage(), Coverage::Full);

    let mixed = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Add File: safe.txt\n+safe\n*** Add File: ../outside.txt\n+outside\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(mixed.core().verdict(), Verdict::Delegate);
    assert_eq!(mixed.core().coverage(), Coverage::Full);

    let header_content = decide_with(
        &call(
            "apply_patch",
            json!({"command":"*** Begin Patch\n*** Add File: safe.txt\n+*** Add File: .env\n*** End Patch"}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(header_content.core().verdict(), Verdict::Delegate);
    assert_eq!(header_content.core().coverage(), Coverage::Full);

    for command in [
        "*** Begin Patch\n*** Frobnicate File: src/lib.rs\n*** End Patch",
        "*** Begin Patch\n*** Environment ID: remote\n*** Add File: src/remote.rs\n+remote\n*** End Patch",
    ] {
        let unsupported = decide_with(
            &call("apply_patch", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(unsupported.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(
            unsupported.core().coverage(),
            Coverage::Partial,
            "{command}"
        );
    }
}

#[test]
fn git_environment_and_config_cannot_expand_project_roots() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let outside = &root.join("outside");
    std::fs::create_dir(outside).unwrap();
    git(outside, &["init", "-q"]);
    std::fs::write(outside.join("secret.txt"), "outside\n").unwrap();

    let payload = json!({
        "v": 1,
        "tool": "Read",
        "input": {"file_path": outside.join("secret.txt")},
        "cwd": repo,
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("decide")
        .env("HOME", &root)
        .env("GIT_COMMON_DIR", outside.join(".git"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let decision: DecisionOutput = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision.verdict(), Verdict::Delegate);

    git(
        &repo,
        &["config", "core.worktree", outside.to_str().unwrap()],
    );
    let configured = decide_with(
        &call(
            "Read",
            json!({"file_path":outside.join("secret.txt")}),
            &repo,
        ),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(configured.core().verdict(), Verdict::Delegate);
}

#[test]
fn linked_worktree_includes_the_main_checkout_boundary() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let worktree = &root.join("worktree");
    git(
        &repo,
        &["worktree", "add", "-q", worktree.to_str().unwrap(), "HEAD"],
    );
    let result = decide_with(
        &call(
            "Read",
            json!({"file_path":repo.join("src/lib.rs").to_str().unwrap()}),
            worktree,
        ),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Delegate);

    let delete_main = decide_with(
        &call(
            "Bash",
            json!({"command":format!("rm -rf {}", bash_path(&repo))}),
            worktree,
        ),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(delete_main.core().verdict(), Verdict::Delegate);
    // The main checkout is inside the worktree's project boundary, and the
    // delete selects that boundary's root.
    assert!(
        delete_main
            .action_stream()
            .effects()
            .iter()
            .any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.selects_root
                        && matches!(&effect.scope, PathScope::Project { root } if root.as_str() == repo.to_str().unwrap())
            )),
        "{:?}",
        delete_main.action_stream().effects()
    );
}

#[test]
fn malformed_cwd_delegates_without_observing() {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Read",
        json!({"file_path":"file"}),
        "relative",
        None,
    )
    .unwrap();
    let called = Cell::new(false);
    let home = if cfg!(windows) {
        Path::new(r"C:\Users\test")
    } else {
        Path::new("/home/test")
    };
    let result = decide_with(&input, &ctx(home), |_| {
        called.set(true);
        unreachable!()
    });
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert!(!called.get());
}

#[test]
fn project_guard_diagnostics_never_weaken_policy() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    std::fs::create_dir(repo.join(".nah")).unwrap();
    std::fs::write(
        repo.join(".nah/project.toml"),
        "enable-guards = [\"fs-system-tree\", \"typo-guard\"]\n",
    )
    .unwrap();
    let result = decide_with(
        &call("Read", json!({"file_path":"src/lib.rs"}), &repo),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.warnings(), ["unknown project guard `typo-guard`"]);

    // A declared guard nah does know still fires from a project declaration.
    let guarded = decide_with(
        &call("Bash", json!({"command":"rm -rf /"}), &repo),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(guarded.core().verdict(), Verdict::Block);

    std::fs::write(repo.join(".nah/project.toml"), "not toml = [\n").unwrap();
    let malformed = decide_with(
        &call("Read", json!({"file_path":"src/lib.rs"}), &repo),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(malformed.core().verdict(), Verdict::Delegate);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        std::fs::remove_file(repo.join(".nah/project.toml")).unwrap();
        symlink(repo.join("missing-guards"), repo.join(".nah/project.toml")).unwrap();
        let linked = decide_with(
            &call("Read", json!({"file_path":"src/lib.rs"}), &repo),
            &ctx(&root),
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(linked.core().verdict(), Verdict::Delegate);
    }
}
