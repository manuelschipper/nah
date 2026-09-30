#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Coverage records how much of a call nah understood: a fully covered call
//! is one nah understood end to end. Every call still delegates unless a guard fires.

use crate::support;

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
        support::fulfill_observation,
    );
    assert_eq!(
        serde_json::to_string(delegated.core()).unwrap(),
        r#"{"verdict":"delegate","reason":"no guard blocked this call","policy_attributions":[],"coverage":"full"}"#
    );

    let blocked = decide_with(
        &call("Bash", json!({"command":"/bin/rm -rf /"}), &repo),
        &context,
        support::fulfill_observation,
    );
    assert_eq!(
        serde_json::to_string(blocked.core()).unwrap(),
        r#"{"verdict":"block","reason":"fs-auth-identity blocked modification or deletion affecting host authentication, identity, or privilege-policy files; this includes recursive deletion of their parent directories; do not retry through another tool; ask the operator to perform any intended change\nfs-home blocked a destructive operation on the home root; name the exact files; ask the operator to perform any home-wide change\nfs-outside-workspace-delete blocked recursive deletion outside the active project; narrow the target to the project or a reviewed temporary root; ask the operator to perform any broader cleanup\nfs-system-tree blocked a destructive operation on the filesystem root or a system tree; narrow the target to the intended project path; ask the operator to perform any system-wide change","policy_attributions":[{"kind":"shipped","name":"fs-auth-identity"},{"kind":"shipped","name":"fs-home"},{"kind":"shipped","name":"fs-outside-workspace-delete"},{"kind":"shipped","name":"fs-system-tree"}],"coverage":"full"}"#
    );
}

#[test]
fn exact_language_child_cwd_and_portable_sh_reach_root_guards() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    // The engine interprets the inline language body and lowers the child
    // shell it launches; a proven root deletion blocks on fs-system-tree.
    // Python's environment configuration stays an open environmental
    // boundary, so its coverage is partial.
    for (command, coverage) in [
        (
            r#"python3 -c "import os; os.system('rm -rf /')""#,
            Coverage::Partial,
        ),
        (
            r#"python3 -c "import subprocess; subprocess.run(['rm','-rf','.'],cwd='/',timeout=30,check=True,text=True,encoding='utf-8',stdin=None,stdout=None,stderr=None)""#,
            Coverage::Partial,
        ),
        (
            r#"python3 -c "import os; os.system('set -o pipefail; rm -rf /')""#,
            Coverage::Partial,
        ),
        (
            r#"node -e "require('child_process').execSync('[[ -e / ]] && rm -rf /')""#,
            Coverage::Full,
        ),
        (
            r#"python3 -c 'import os; os.system("printf -v TOOL %s rm; \"$TOOL\" -rf /")'"#,
            Coverage::Partial,
        ),
        (
            r#"python3 -c "import os; os.system(\"builtin eval 'rm -rf /'\")""#,
            Coverage::Partial,
        ),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
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
        r#"python3 -c 'import os; os.system("TOOL=rm; \"${TOOL[0]}\" -rf /")'"#,
        r#"python3 -c 'import os; os.system("cd /; rm -rf ~+")'"#,
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":unsupported}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{unsupported}");
        assert_eq!(result.core().coverage(), Coverage::Partial, "{unsupported}");
    }

    // A command name read from a file at run time conceals the program, the
    // same exec-obfuscated block Nah gives it outside the interpreter.
    let concealed = r#"python3 -c 'import os; os.system("TOOL=$(</tmp/tool); \"$TOOL\" -rf /")'"#;
    let result = decide_with(
        &call("Bash", json!({"command":concealed}), &repo),
        &context,
        support::fulfill_observation,
    );
    assert_eq!(result.core().verdict(), Verdict::Block, "{concealed}");
    assert!(
        result
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "exec-obfuscated"),
        "{concealed}"
    );
}

#[test]
fn arbitrary_program_paths_are_not_recognized_as_their_bare_name() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    // An arbitrary path is never lowered to its bare name, so no guard fires.
    // Coverage is full when the program leaves no modeled effect, and partial
    // where the bare name (nah, echo) is itself partially modeled or where a
    // filesystem model is not trusted to describe the program it runs.
    for (command, coverage) in [
        ("./nah guards", Coverage::Partial),
        ("/tmp/nah log", Coverage::Partial),
        ("./git status", Coverage::Full),
        ("/tmp/git log", Coverage::Full),
        ("./cat README.md", Coverage::Partial),
        ("/tmp/echo hi", Coverage::Partial),
        ("./rm -rf /", Coverage::Partial),
        ("/tmp/chmod --recursive 000 /", Coverage::Partial),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
    }

    let guarded = decide_with(
        &call("Bash", json!({"command":"/bin/rm -rf /"}), &repo),
        &context,
        support::fulfill_observation,
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

    // Read-only nah commands delegate. The engine models most fully; the
    // model-backed log/docs readers it does not recognize in full stay partial
    // without changing the verdict.
    for (command, coverage) in [
        ("nah --help", Coverage::Full),
        ("nah help", Coverage::Full),
        ("nah help guards", Coverage::Full),
        ("nah docs security", Coverage::Full),
        ("nah docs guards", Coverage::Partial),
        ("nah log --json -n 10", Coverage::Partial),
        ("nah why decision-id", Coverage::Full),
        ("nah hook amp status", Coverage::Full),
        ("nah trust . --help", Coverage::Full),
        ("nah hook codex install --help", Coverage::Full),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
    }
}

#[test]
fn local_utility_coverage_is_flag_sensitive_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());

    // These utilities delegate. Unrecognized arguments and the staged git
    // commit stay partial; a concrete write does not need disclosure semantics
    // to preserve global filesystem coverage.
    for (command, coverage) in [
        ("echo hello", Coverage::Full),
        ("date", Coverage::Full),
        ("echo hello | cat", Coverage::Full),
        ("true && echo hello", Coverage::Full),
        ("(echo hello && date)", Coverage::Full),
        ("cat src/lib.rs", Coverage::Full),
        ("sort -o sorted.txt", Coverage::Full),
        ("cat --help .env", Coverage::Partial),
        ("tee --help .env", Coverage::Partial),
        ("sort --help -o .env", Coverage::Full),
        ("date --help --file .env", Coverage::Full),
        ("date -s tomorrow", Coverage::Full),
        ("echo \"$TOKEN\"", Coverage::Full),
        ("echo \"$TOKEN\" > generated.txt", Coverage::Full),
        (
            "echo \"$TOKEN\" > leak.txt && git add leak.txt && git commit -m update",
            Coverage::Partial,
        ),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
    }

    // An unrecognized flag or an unresolved process-substitution operand
    // stays partial; a fully modeled command substitution or glob delegates
    // with full coverage.
    for (command, coverage) in [
        ("sort --definitely-unknown", Coverage::Partial),
        ("date --definitely-unknown", Coverage::Partial),
        ("echo $(date)", Coverage::Full),
        ("cat <(echo hello)", Coverage::Partial),
        ("tee >(cat -n)", Coverage::Partial),
        ("echo /etc/*", Coverage::Full),
        ("tail -f src/lib.rs", Coverage::Full),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
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
        support::fulfill_observation,
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.core().coverage(), Coverage::Full);

    // A `cd -` to an unobserved previous directory leaves the read target
    // partial; a `cd "$TARGET"` to an unknown directory is modeled fully as a
    // project read because the trailing path stays inside the project.
    for (command, coverage) in [
        ("cd - && cat src/lib.rs", Coverage::Partial),
        ("cd \"$TARGET\" && cat src/lib.rs", Coverage::Full),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
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
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    let delete_root = decide_with(
        &call("Bash", json!({"command":"rm -rf ."}), &repo),
        &context,
        support::fulfill_observation,
    );
    assert_eq!(delete_root.core().verdict(), Verdict::Block);
    assert_eq!(delete_root.core().coverage(), Coverage::Full);
    assert!(
        delete_root
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-project-root")
    );

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
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    // An unrecognized flag keeps the copy partial; an unknown destination is
    // modeled fully because the source read is proven and the write lands
    // wherever the operand resolves.
    for (command, coverage) in [
        (
            "cp --definitely-unknown src/lib.rs copied.rs",
            Coverage::Partial,
        ),
        ("cp src/lib.rs \"$OUT\"", Coverage::Full),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
    }
}

/// Cheap padding before a danger must not push it past an analysis bound.
/// Each top-level segment gets its own step and byte allowance, so neither
/// thousands of `echo` operands nor one expensive interpreter prefix can
/// starve the deletion that follows. The largest padding is the most the
/// bridge admits: tool input stops at 1 MiB. Those allowances stay within a
/// fixed total, so costly segments after the danger cannot run the analysis
/// long enough to lose it either.
#[test]
fn padding_around_a_danger_cannot_push_it_past_a_bound() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    let context = ctx(temp.path());
    let parens = 20_000;
    let deep = format!("{}1{}", "(".repeat(parens), ")".repeat(parens));
    let mut shapes = [40, 5_000, (1024 * 1024 - 200) / "echo y && ".len()]
        .map(|count| ("echo y && ".repeat(count), String::new()))
        .to_vec();
    shapes.push((format!("perl -e 'my $x={deep};'; "), String::new()));
    shapes.push((format!("Rscript -e 'x <- {deep}'; "), String::new()));
    shapes.push((
        format!("f() {{ perl -e 'my $x={deep};'; }}; "),
        format!("; {}", "f; ".repeat(1_000)),
    ));
    shapes.push((
        format!("x=\"{}\"; ", "a ".repeat(5_000)),
        format!("; {}", ": $x; ".repeat(16_000)),
    ));

    for (before, after) in shapes {
        for (target, verdict) in [("~", Verdict::Block), ("build", Verdict::Delegate)] {
            let command = format!("{before}rm -rf {target}{after}");
            let result = decide_with(
                &call("Bash", json!({ "command": command }), &repo),
                &context,
                support::fulfill_observation,
            );
            let shape = format!(
                "{}… ({} bytes) rm -rf {target} ({} bytes)",
                &before[..12],
                before.len(),
                after.len()
            );
            assert_eq!(result.core().verdict(), verdict, "{shape}");
            assert!(result.refusals().is_empty(), "{shape}");
        }
    }
}
