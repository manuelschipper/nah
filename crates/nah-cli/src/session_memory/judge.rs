//! Judges written content as if it were run: the interpreter its shebang or
//! file name selects runs it right after the write, and the live guards
//! decide that one shell call. The write and the run share the call, so the
//! engine serves the run the written bytes rather than the file on disk.

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde_json::json;

use super::Host;
use super::base_name;
use super::ledger::ContentVerdict;
use crate::commands::quote_posix_shell_word;

/// The synthesized call stays under the bridge's 1 MiB tool-input cap, past
/// which nothing is analyzed.
const MAX_JUDGED_BYTES: usize = 900 * 1024;
/// A Makefile's targets beyond this many are not judged.
const MAX_MAKE_TARGETS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Interpreter {
    Shell,
    Python,
    Node,
    Make,
    Npm,
}

pub(crate) struct Judgment {
    pub(crate) judged: Judged,
    pub(crate) verdict: ContentVerdict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Judged {
    /// The content blocks when run.
    Flagged,
    Clean,
    /// No interpreter is selected by its name, shebang or the launch waiting
    /// for it, or it is too large.
    Unjudged,
}

/// The interpreter a shebang names, else the one a file name implies. A
/// shebang naming any other program selects none.
pub(crate) fn interpreter_for(path: &str, content: &str) -> Option<Interpreter> {
    if let Some(line) = content
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("#!"))
    {
        let mut words = line.split_whitespace();
        let mut program = base_name(words.next()?);
        if program == "env" {
            program = base_name(words.find(|word| !word.starts_with('-') && !word.contains('='))?);
        }
        return match program {
            "sh" | "bash" | "zsh" | "dash" | "ksh" => Some(Interpreter::Shell),
            "node" | "nodejs" => Some(Interpreter::Node),
            program if program.starts_with("python") => Some(Interpreter::Python),
            _ => None,
        };
    }
    let name = base_name(path);
    match name {
        "Makefile" | "makefile" | "GNUmakefile" => return Some(Interpreter::Make),
        "package.json" => return Some(Interpreter::Npm),
        ".bashrc" | ".bash_profile" | ".bash_login" | ".profile" | ".zshrc" | ".zshenv"
        | ".zprofile" | ".zlogin" => return Some(Interpreter::Shell),
        _ => {}
    }
    match name.rsplit_once('.')?.1 {
        "sh" | "bash" | "zsh" | "ksh" => Some(Interpreter::Shell),
        "py" => Some(Interpreter::Python),
        "js" | "mjs" | "cjs" => Some(Interpreter::Node),
        "mk" => Some(Interpreter::Make),
        _ => None,
    }
}

/// Judges `content` written to `path`. `launcher` names the program a
/// pending launch or a shell profile will run the file with, which selects
/// the interpreter over the file's own name and shebang: `sh future.py`
/// runs shell.
pub(crate) fn judge_written_content(
    path: &str,
    content: &str,
    launcher: Option<&str>,
    cwd: &str,
    host: &Host<'_>,
) -> Judgment {
    let interpreter = launcher
        .and_then(by_launcher)
        .or_else(|| interpreter_for(path, content));
    let unjudged = Judgment {
        judged: Judged::Unjudged,
        verdict: ContentVerdict::default(),
    };
    let Some(selected) = interpreter else {
        return unjudged;
    };
    if content.len() > MAX_JUDGED_BYTES {
        return unjudged;
    }
    let quoted = quote_posix_shell_word(path);
    let parent = path
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or(cwd);
    let (runs, run_cwd) = match selected {
        Interpreter::Shell => (vec![format!("sh {quoted}")], cwd),
        Interpreter::Python => (vec![format!("python3 {quoted}")], cwd),
        Interpreter::Node => (vec![format!("node {quoted}")], cwd),
        Interpreter::Make => {
            let targets = make_targets(content);
            let runs = if targets.is_empty() {
                vec![format!("make -f {quoted}")]
            } else {
                targets
                    .iter()
                    .map(|target| format!("make -f {quoted} {}", quote_posix_shell_word(target)))
                    .collect()
            };
            (runs, parent)
        }
        Interpreter::Npm => {
            let Ok(manifest) = serde_json::from_str::<serde_json::Value>(content) else {
                return unjudged;
            };
            let runs: Vec<_> = manifest
                .get("scripts")
                .and_then(serde_json::Value::as_object)
                .map(|scripts| {
                    scripts
                        .keys()
                        .map(|name| format!("npm run {}", quote_posix_shell_word(name)))
                        .collect()
                })
                .unwrap_or_default();
            if runs.is_empty() {
                return Judgment {
                    judged: Judged::Clean,
                    verdict: ContentVerdict::default(),
                };
            }
            (runs, parent)
        }
    };
    // A delimiter derived from the content's digest cannot end the body early.
    let delimiter = format!(
        "NAH_JUDGED_{}",
        &nah_proto::effinterp_proto::content_digest(content.as_bytes())[7..23]
    );
    let newline = if content.ends_with('\n') || content.is_empty() {
        ""
    } else {
        "\n"
    };
    let write = format!("cat > {quoted} <<'{delimiter}'\n{content}{newline}{delimiter}\n");
    // The write puts the content in command text, which guards on command
    // text (hidden characters) read but a run of the file does not, so what
    // the write alone blocks on is not the content's verdict.
    let mut write_guards = None;
    let mut run_guards = |run: &str| {
        let guards = shell_call_blocking_guards(&format!("{write}{run}"), run_cwd, host)?;
        if guards.is_empty() {
            return Some(guards);
        }
        if write_guards.is_none() {
            write_guards = Some(shell_call_blocking_guards(&write, run_cwd, host)?);
        }
        let alone = write_guards.as_ref()?;
        Some(
            guards
                .into_iter()
                .filter(|guard| !alone.contains(guard))
                .collect::<Vec<_>>(),
        )
    };
    let Some(guards) = run_guards(&runs.join("\n")) else {
        return unjudged;
    };
    let mut verdict = ContentVerdict {
        guards,
        entries: Vec::new(),
    };
    // A Makefile or manifest flagged as a whole is judged again one target
    // or script at a time: a run selects some of them, and only those
    // decide (`make test` does not run `wipe`).
    if !verdict.guards.is_empty() && matches!(selected, Interpreter::Make | Interpreter::Npm) {
        for (name, run) in entry_names(selected, content).into_iter().zip(&runs) {
            let Some(guards) = run_guards(run) else {
                return unjudged;
            };
            verdict.entries.push((name, guards));
        }
    }
    Judgment {
        judged: if verdict.guards.is_empty() {
            Judged::Clean
        } else {
            Judged::Flagged
        },
        verdict,
    }
}

/// The interpreter a launching program implies for a file it runs.
fn by_launcher(launcher: &str) -> Option<Interpreter> {
    match base_name(launcher) {
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "source" | "." => Some(Interpreter::Shell),
        "node" | "nodejs" => Some(Interpreter::Node),
        program if program.starts_with("python") => Some(Interpreter::Python),
        _ => None,
    }
}

/// The names of the runs `judge_written_content` builds for a Makefile or manifest, in the
/// same order.
fn entry_names(selected: Interpreter, content: &str) -> Vec<String> {
    match selected {
        Interpreter::Make => make_targets(content),
        Interpreter::Npm => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|manifest| {
                manifest
                    .get("scripts")
                    .and_then(serde_json::Value::as_object)
                    .map(|scripts| scripts.keys().cloned().collect())
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The guards that block one shell call, empty when it delegates, or `None`
/// when the call cannot be built.
fn shell_call_blocking_guards(command: &str, cwd: &str, host: &Host<'_>) -> Option<Vec<String>> {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({ "command": command }),
        cwd,
        None,
    )
    .ok()?;
    let result = (host.decide_shell)(&input);
    if result.core().verdict() != Verdict::Block {
        return Some(Vec::new());
    }
    Some(super::blocking_guards(result.core()))
}

/// The explicit targets of a Makefile's rules, skipping special targets,
/// pattern rules and variable assignments.
fn make_targets(content: &str) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.starts_with(['\t', '#', ' ']) {
            continue;
        }
        let Some((head, rest)) = line.split_once(':') else {
            continue;
        };
        if rest.starts_with('=') || head.contains(['=', '$', '%', '?', '+']) {
            continue;
        }
        for target in head.split_whitespace() {
            if !target.starts_with('.') && !targets.iter().any(|known| known == target) {
                targets.push(target.to_owned());
            }
        }
    }
    // make runs `.DEFAULT_GOAL` when no target is named, else the first
    // target; one Nah cannot read leaves no target to judge alone, so the
    // whole file decides.
    let goal = content.lines().rev().find_map(|line| {
        let rest = line.strip_prefix(".DEFAULT_GOAL")?.trim_start();
        let value = ["::=", ":=", "?=", "="]
            .iter()
            .find_map(|operator| rest.strip_prefix(operator))?;
        Some(value.trim())
    });
    match goal {
        Some(goal) if goal.is_empty() || goal.contains(['$', ' ', '\t']) => return Vec::new(),
        Some(goal) => {
            targets.retain(|target| target != goal);
            targets.insert(0, goal.to_owned());
        }
        None => {}
    }
    targets.truncate(MAX_MAKE_TARGETS);
    targets
}

#[cfg(test)]
mod tests {
    use super::{Interpreter, interpreter_for, make_targets};

    #[test]
    fn shebang_wins_over_the_file_name_and_names_only_known_interpreters() {
        assert_eq!(
            interpreter_for("/p/tool", "#!/usr/bin/env -S python3 -u\n"),
            Some(Interpreter::Python)
        );
        assert_eq!(
            interpreter_for("/p/x.py", "#!/bin/bash\n"),
            Some(Interpreter::Shell)
        );
        assert_eq!(interpreter_for("/p/x.sh", "#!/usr/bin/ruby\n"), None);
        assert_eq!(
            interpreter_for("/p/Makefile", "all:\n"),
            Some(Interpreter::Make)
        );
        assert_eq!(interpreter_for("/p/README.md", "# x\n"), None);
    }

    #[test]
    fn make_targets_skip_special_pattern_and_assignment_lines() {
        let content =
            ".PHONY: test\nCC := cc\nX ?= y\n%.o: %.c\n\tcc $<\ntest build: deps\n\tmake\n";
        assert_eq!(make_targets(content), ["test", "build"]);
        // The default goal is what `make` alone runs, so it comes first.
        let content = "test:\n\techo ok\nwipe:\n\trm -rf ~\n.DEFAULT_GOAL := wipe\n";
        assert_eq!(make_targets(content), ["wipe", "test"]);
        assert!(make_targets(".DEFAULT_GOAL = $(GOAL)\ntest:\n").is_empty());
    }
}
