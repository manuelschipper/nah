#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Coverage is the visible product of lowering: a fully covered call is one
//! nah understood end to end. Every call still delegates unless a guard fires.

mod support;

use nah_cli::decide_with;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use serde_json::json;
use support::{bash_path, call, ctx, repo};

#[test]
fn core_decision_bytes_are_stable_for_delegate_and_block() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    let delegated = decide_with(
        &call("Bash", json!({"command":"echo hello"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(
        serde_json::to_string(delegated.core()).unwrap(),
        r#"{"verdict":"delegate","reason":"no guard blocked this call","policy_attributions":[],"coverage":"full"}"#
    );

    let blocked = decide_with(
        &call("Bash", json!({"command":"/bin/rm -rf /"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(
        serde_json::to_string(blocked.core()).unwrap(),
        r#"{"verdict":"block","reason":"fs-auth-identity blocked a change to host authentication, identity, or privilege policy; do not retry through another tool; if this host administration is intended, ask the operator to open `nah tui` in a separate terminal and disable `fs-auth-identity`, then re-enable it after the change\nfs-home blocked a destructive operation on the home root; name the exact files; ask the operator to perform any home-wide change\nfs-system-tree blocked a destructive operation on the filesystem root or a system tree; narrow the target to the intended project path; ask the operator to perform any system-wide change","policy_attributions":[{"kind":"shipped","name":"fs-auth-identity"},{"kind":"shipped","name":"fs-home"},{"kind":"shipped","name":"fs-system-tree"}],"coverage":"full"}"#
    );
}

#[test]
fn exact_language_child_cwd_and_portable_sh_reach_root_guards() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    for command in [
        r#"python3 -c "import os; os.system('rm -rf /')""#,
        r#"python3 -c "import subprocess; subprocess.run(['rm','-rf','.'],cwd='/',timeout=30,check=True,text=True,encoding='utf-8',stdin=None,stdout=None,stderr=None)""#,
        r#"node -e "process.chdir('/'); require('child_process').spawnSync('rm',['-rf','.'])""#,
        r#"deno eval --ext=js "new Deno.Command('rm',{args:['-rf','.'],cwd:'/'}).spawn()""#,
        r#"bun -e "Bun.spawnSync(['rm','-rf','.'],{cwd:'/'})""#,
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|guard| guard.name() == "fs-system-tree"),
            "{command}"
        );
    }

    for unsupported in [
        r#"python3 -c "import os; os.system('set -o pipefail; rm -rf /')""#,
        r#"node -e "require('child_process').execSync('[[ -e / ]] && rm -rf /')""#,
        r#"python3 -c "import os; os.system(\"builtin eval 'rm -rf /'\")""#,
        r#"python3 -c 'import os; os.system("printf -v TOOL %s rm; \"$TOOL\" -rf /")'"#,
        r#"python3 -c 'import os; os.system("TOOL=rm; \"${TOOL[0]}\" -rf /")'"#,
        r#"python3 -c 'import os; os.system("cd /; rm -rf ~+")'"#,
        r#"python3 -c 'import os; os.system("TOOL=$(</tmp/tool); \"$TOOL\" -rf /")'"#,
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":unsupported}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{unsupported}");
        assert_eq!(result.core().coverage(), Coverage::Partial, "{unsupported}");
    }
}

#[test]
fn arbitrary_program_paths_are_not_recognized_as_their_bare_name() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    for command in [
        "./nah guards",
        "/tmp/nah log",
        "./git status",
        "/tmp/git log",
        "./cat README.md",
        "/tmp/echo hi",
        "./rm -rf /",
        "/tmp/chmod --recursive 000 /",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Partial, "{command}");
    }

    let guarded = decide_with(
        &call("Bash", json!({"command":"/bin/rm -rf /"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(guarded.core().verdict(), Verdict::Block);
    assert!(
        guarded
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-system-tree")
    );
}

#[test]
fn read_only_nah_commands_are_fully_lowered() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    for command in [
        "nah --help",
        "nah help",
        "nah help guards",
        "nah docs security",
        "nah docs guards",
        "nah log --json -n 10",
        "nah why decision-id",
        "nah hook amp status",
        "nah trust . --help",
        "nah hook codex install --help",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }
}

#[test]
fn local_utility_lowering_is_flag_sensitive_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    for command in [
        "echo hello",
        "date",
        "echo hello | cat",
        "true && echo hello",
        "(echo hello && date)",
        "cat src/lib.rs",
        "sort -o sorted.txt",
        "cat --help .env",
        "tee --help .env",
        "sort --help -o .env",
        "date --help --file .env",
        "date -s tomorrow",
        "echo \"$TOKEN\"",
        "echo \"$TOKEN\" > generated.txt",
        "echo \"$TOKEN\" > leak.txt && git add leak.txt && git commit -m update",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    for command in [
        "sort --definitely-unknown",
        "date --definitely-unknown",
        "echo $(date)",
        "cat <(echo hello)",
        "tee >(cat -n)",
        "echo /etc/*",
        "tail -f src/lib.rs",
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
fn local_utilities_compose_with_chained_project_reads() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    let result = decide_with(
        &call("Bash", json!({"command":"cd ./src && cat lib.rs"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.core().coverage(), Coverage::Full);

    for command in ["cd - && cat src/lib.rs", "cd \"$TARGET\" && cat src/lib.rs"] {
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
fn bash_project_filesystem_effects_are_lowered_compositionally() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    for command in [
        "cat src/lib.rs",
        "echo hello > generated.txt",
        "cp src/lib.rs copied.rs",
        "mv src/lib.rs moved.rs",
        "mkdir -p generated",
        "touch generated.txt",
        "rm -f src/lib.rs",
        "rm -rf .",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    for command in [
        format!(
            "cp {} copied.rs",
            bash_path(&temp.path().join("outside/input"))
        ),
        format!(
            "mv src/lib.rs {}",
            bash_path(&temp.path().join("outside/output"))
        ),
        format!("rm -f {}", bash_path(&temp.path().join("outside/output"))),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":&command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    for command in [
        "cp --definitely-unknown src/lib.rs copied.rs",
        "cp src/lib.rs \"$OUT\"",
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
