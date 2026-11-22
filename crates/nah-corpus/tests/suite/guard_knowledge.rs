//! Every example in the built-in rule knowledge records
//! (`crates/nah-cli/guards/<guard>/<rule>.toml`) names a delivered corpus row
//! that shows what the record claims, so the TUI, `nah docs guards`, and the guard
//! reference cannot drift from the decisions Nah makes.

use std::collections::BTreeMap;

use nah_cli::{PassCause, guard_knowledge};
use nah_corpus::{
    corpus_dir, decide_case_in_shell, expected_fail_ids, load_cases, load_fixtures,
    reconcile_triage_ledger, row_matches,
};
use nah_corpus_schema::{Expectation, ExpectedVerdict};
use nah_proto::ctx::GuardLevel;
use nah_proto::decision::Verdict;

/// A block example's row expects a block naming the rule. A pass example's
/// row expects a delegate under a context that runs the rule. An
/// `unresolved` pass must also report partial coverage; an `out-of-scope` pass
/// may too, because partial coverage also records gaps unrelated to the
/// guard, such as an unmodeled read-only subcommand. No example may be an
/// expected failure.
///
/// Each example also holds the level the reference shows it at: replayed
/// with every rule enabled, a `strict` block matches only the rule's strict
/// parts and any other block matches a core part (a rule with only strict
/// parts marks none); a `strict-only` pass matches only strict parts, and any
/// other pass matches no part of the rule at all.
#[test]
fn guard_knowledge_examples_match_their_corpus_rows() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("load corpus");
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let ledger = std::fs::read_to_string(dir.join("TRIAGE.md")).expect("triage ledger");
    let (expected_fail, _) = expected_fail_ids(&ledger);
    let by_id = cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();

    let mut errors = Vec::new();
    let mut passes = Vec::new();
    let mut replayed = BTreeMap::new();
    for guard in guard_knowledge() {
        let name = guard.name;
        let rows = guard
            .blocks
            .iter()
            .map(|block| (block.row.as_str(), None))
            .chain(
                guard
                    .passes
                    .iter()
                    .map(|pass| (pass.row.as_str(), Some(pass.cause))),
            );
        for (row, cause) in rows {
            let Some(case) = by_id.get(row) else {
                errors.push(format!("{name}: `{row}` is not a corpus row"));
                continue;
            };
            if expected_fail.contains(row) {
                errors.push(format!("{name}: `{row}` is an expected failure"));
            }
            let Expectation::Decision {
                verdict,
                guard: expected_guard,
                guards,
                ..
            } = &case.expected
            else {
                errors.push(format!("{name}: `{row}` expects no decision"));
                continue;
            };
            match (cause, verdict) {
                (None, ExpectedVerdict::Block) => {
                    if expected_guard.as_deref() != Some(name)
                        && !guards.iter().flatten().any(|guard| guard == name)
                    {
                        errors.push(format!("{name}: block `{row}` expects another rule"));
                    }
                }
                (Some(cause), ExpectedVerdict::Delegate) => {
                    let enabled = fixtures
                        .ctx_fixture(&case.ctx_fixture)
                        .expect("known context fixture")
                        .enabled_rules()
                        .expect("context fixture");
                    if !enabled.contains(name) {
                        errors.push(format!("{name}: pass `{row}` runs with the rule off"));
                    }
                    passes.push((row, name, cause));
                    replayed.insert(row, (*case).clone());
                }
                (None, _) => errors.push(format!("{name}: block `{row}` expects a delegate")),
                (Some(_), _) => errors.push(format!("{name}: pass `{row}` expects a block")),
            }
        }
    }

    let replayed = replayed.into_values().collect::<Vec<_>>();
    let shipped = nah_policy::ShippedGuards::new();
    let examples = guard_knowledge()
        .iter()
        .flat_map(|guard| guard.blocks.iter().map(|block| block.row.as_str()))
        .filter_map(|row| by_id.get(row).map(|case| (*case).clone()))
        .chain(replayed.iter().cloned())
        .collect::<Vec<_>>();
    let (matches, replay_errors) = row_matches(&examples, &fixtures);
    errors.extend(replay_errors);
    let levels = matches
        .iter()
        .map(|row| (row.id.as_str(), &row.parts))
        .collect::<BTreeMap<_, _>>();
    // The levels of `rule`'s parts that `row` matched, or `None` when the row
    // failed to replay (already an error).
    let matched = |row: &str, rule: &str| {
        levels.get(row).map(|parts| {
            parts
                .iter()
                .map(|index| &shipped.definitions()[*index])
                .filter(|part| part.rule == rule)
                .map(|part| part.applies_at)
                .collect::<Vec<_>>()
        })
    };
    for guard in guard_knowledge() {
        let name = guard.name;
        let has_core = shipped
            .parts(name)
            .any(|part| part.applies_at == GuardLevel::Core);
        for block in &guard.blocks {
            let Some(levels) = matched(&block.row, name) else {
                continue;
            };
            let core = levels.contains(&GuardLevel::Core);
            if block.strict && !has_core {
                errors.push(format!(
                    "{name}: block `{}` is marked strict in a rule with only strict parts",
                    block.row
                ));
            } else if has_core && block.strict == core {
                errors.push(format!(
                    "{name}: block `{}` {}",
                    block.row,
                    if core {
                        "matches a core part; drop `strict`"
                    } else {
                        "matches only strict parts; mark it `strict = true`"
                    }
                ));
            }
        }
        for pass in &guard.passes {
            let Some(levels) = matched(&pass.row, name) else {
                continue;
            };
            let holds = match pass.cause {
                PassCause::StrictOnly => !levels.is_empty() && !levels.contains(&GuardLevel::Core),
                PassCause::OutOfScope | PassCause::Unresolved => levels.is_empty(),
            };
            if !holds {
                errors.push(format!(
                    "{name}: pass `{}` ({:?}) matches the rule's parts at {levels:?}",
                    pass.row, pass.cause
                ));
            }
        }
    }

    let result = reconcile_triage_ledger(&replayed, &fixtures, "");
    errors.extend(result.unexpected_failures);
    for (row, name, cause) in passes {
        if cause == PassCause::Unresolved && !result.partial_coverage.contains(row) {
            errors.push(format!(
                "{name}: unresolved pass `{row}` reports full coverage"
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// A reverse shell or a script run from a `/dev/tcp` socket blocks in every
/// runtime, whether or not Nah can name the shell its hook runs a command in:
/// one it cannot name may be bash, which opens the socket. Each blocked
/// example of the two rules is replayed in each runtime's shell.
#[test]
fn socket_shell_examples_block_in_every_runtime() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("load corpus");
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let shipped = nah_policy::ShippedGuards::new();
    let mut errors = Vec::new();
    for guard in guard_knowledge().iter().filter(|guard| {
        [
            "untrusted-code/reverse-shell-open",
            "untrusted-code/remote-script-run",
        ]
        .contains(&guard.name)
    }) {
        for block in &guard.blocks {
            let case = cases
                .iter()
                .find(|case| case.id == block.row)
                .expect("an example names a corpus row");
            for (runtime, shell) in nah_cli::hook_runtime_shells() {
                match decide_case_in_shell(case, &fixtures, shell) {
                    Ok(result)
                        if result.core().verdict() == Verdict::Block
                            && result
                                .matched_parts()
                                .iter()
                                .any(|part| shipped.definitions()[*part].rule == guard.name) => {}
                    Ok(result) => errors.push(format!(
                        "{}: `{}` in {runtime} ({shell:?}): {:?}",
                        guard.name,
                        block.row,
                        result.core().verdict()
                    )),
                    Err(error) => errors.push(format!("{runtime}: {error}")),
                }
            }
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Blocking examples a form still keeps from blocking, by the start of the
/// forms each fails in (``under `sudo`` covers every sudo spelling), with
/// why. These are gaps, not forms that ask for something else; an entry
/// that blocks in every form it names must leave the list.
const FORM_GAPS: [(&str, &[&str], &str); 12] = [
    (
        "secrets-env.credential-expansion",
        &[
            "under `sudo",
            "under `doas`",
            "under `env`",
            "under `nice`",
            "under `nohup`",
        ],
        "a launched `echo` is a program with no model; only the shell builtin discloses the variable",
    ),
    (
        "secrets-env.git-observed-add-all",
        &["under `sudo", "after `"],
        STAGING_AFTER_BOUNDARY,
    ),
    (
        "secrets-env.git-commit-all-tracked-env",
        &["under `sudo", "after `"],
        STAGING_AFTER_BOUNDARY,
    ),
    (
        "secrets-credentials.git-add-all-private-key",
        &["under `sudo", "after `"],
        STAGING_AFTER_BOUNDARY,
    ),
    (
        "git-metadata.find-files-chmod-000-blocks",
        UNLISTED_WRITES,
        LISTING_AFTER_UNLISTED_WRITES,
    ),
    (
        "fs-shell-profile.find-home-top-level-files",
        UNLISTED_WRITES,
        LISTING_AFTER_UNLISTED_WRITES,
    ),
    (
        "fs-shell-profile.macos-pwsh-force-move-lands-zshrc",
        UNLISTED_WRITES,
        LISTING_AFTER_UNLISTED_WRITES,
    ),
    (
        "fs-startup-persistence.macos-pwsh-include-lands-launchagent",
        UNLISTED_WRITES,
        LISTING_AFTER_UNLISTED_WRITES,
    ),
    (
        "fs-home.macos-mv-desktop-away",
        UNLISTED_WRITES,
        "a step whose writes Nah cannot list may have removed or replaced the folder, so what the move takes is not observed",
    ),
    (
        "git-force-push.delete-custom-default",
        &["after `sudo apt-get"],
        "apt-get's package scripts may rewrite the repository, so the remote's default branch is not observed",
    ),
    (
        "fs-startup-persistence.profile-shell-echo-append",
        &["after `"],
        "still blocks, as untrusted-code/remote-script-run only: on a host whose PATH is observed the appended line no longer fires the startup rule",
    ),
    (
        "exec.exfil-credential-search-mail",
        &["after `brew install"],
        "the fixture cannot answer an observation the install asks for, so the corpus harness fails the evaluation",
    ),
];

/// The earlier steps whose writes Nah cannot list.
const UNLISTED_WRITES: &[&str] = &[
    "after `sudo apt-get",
    "after `sudo frobnicate",
    "after `eval",
    "after `brew install",
];

const STAGING_AFTER_BOUNDARY: &str = "a boundary that may come before the staging read, sudo's own target selection or an earlier step's, leaves the staged files unlabelled";

const LISTING_AFTER_UNLISTED_WRITES: &str = "a step whose writes Nah cannot list may have changed what the listing selects, so the selection is not observed";

/// What a rule's blocking example asks for, it asks for under a transparent
/// wrapper too, and after an earlier step Nah cannot follow, and whether the
/// host has the program it names changes neither. Each example that is one
/// command, or a pipeline whose last command the wrapper can take, is
/// replayed with each wrapper in front of that command; every example is
/// replayed after each earlier step: an install, a privileged program with
/// no model, `sudo true`, a version manager's init. Each replay runs under
/// the example's own fixture and under two hosts that observe PATH: one
/// where every program it names is installed, one where only the wrappers
/// are. None asks for something else in these forms; `FORM_GAPS` lists the
/// ones Nah does not yet judge alike.
#[test]
fn every_blocking_example_blocks_wrapped_and_after_earlier_steps() {
    use nah_corpus::FixtureRegistry;
    use nah_corpus_schema::{CaseInput, CorpusCase};
    use serde_json::{Value, json};

    const WRAPPERS: [&str; 12] = [
        "sudo",
        "sudo -n",
        "sudo -E",
        "sudo -u root",
        "sudo --",
        "doas",
        "env",
        "nice",
        "nohup",
        "time",
        "command",
        "exec",
    ];
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("load corpus");
    let by_id = cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut registry: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("FIXTURES.json")).expect("fixture registry"),
    )
    .expect("fixture registry JSON");
    let program = |path: &str, present: bool| {
        if present {
            json!({"requested": path, "resolved": path, "realpath": path,
                   "exists": true, "kind": "file", "executable": true})
        } else {
            json!({"requested": path, "resolved": path, "exists": false, "kind": "missing"})
        }
    };
    let mut wrapped = Vec::new();
    for guard in guard_knowledge() {
        for block in &guard.blocks {
            let case = by_id[block.row.as_str()];
            let CaseInput::Command(command) = &case.input else {
                continue;
            };
            let mut forms = Vec::new();
            let single = last_command(command);
            if let Some((before, last)) = single {
                let head = last.split_whitespace().next().unwrap_or_default();
                if !head.contains('=') && !WRAPPERS.iter().any(|wrapper| wrapper.starts_with(head))
                {
                    forms.extend(WRAPPERS.iter().map(|wrapper| {
                        (
                            format!("under `{wrapper}`"),
                            format!("{before}{wrapper} {last}"),
                        )
                    }));
                }
            }
            // The program the example starts first, as an earlier step installs it.
            let installed = command
                .split_whitespace()
                .find(|word| !word.contains('='))
                .filter(|word| {
                    word.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
                })
                .unwrap_or("wget");
            // An install runs first on success only where `&&` takes the
            // whole example; before a list it ends with `;`, which leaves the
            // list's own conditions as they are.
            let then = if single.is_some() { "&&" } else { ";" };
            for step in [
                "sudo apt-get update;".to_owned(),
                "sudo frobnicate --setup;".to_owned(),
                "sudo true;".to_owned(),
                "eval \"$(pyenv init -)\";".to_owned(),
                format!("brew install {installed} {then}"),
                format!("sudo apt-get install -y {installed} {then}"),
            ] {
                forms.push((format!("after `{step}`"), format!("{step} {command}")));
            }
            let base = registry["observation_fixtures"][&case.observation_fixture].clone();
            if base["platform"] == "windows" {
                continue;
            }
            // Every word that could name a program the call starts.
            let names = command
                .split(|c: char| !(c.is_ascii_alphanumeric() || "._+-".contains(c)))
                .filter(|word| !word.is_empty() && !word.starts_with('-'))
                .chain(["sh", "bash", "true", "apt-get", "brew", "pyenv"])
                .collect::<std::collections::BTreeSet<_>>();
            for (host, installed) in [
                ("own", None),
                ("installed", Some(true)),
                ("absent", Some(false)),
            ] {
                let fixture = match installed {
                    None => case.observation_fixture.clone(),
                    Some(installed) => {
                        let name = format!("{}+{host}", block.row);
                        let mut variant = base.clone();
                        variant["env"]["PATH"] = json!("/usr/bin");
                        // Listed first, so they answer before the fixture's own entries.
                        let paths = variant["paths"].as_array_mut().expect("fixture paths");
                        let programs = ["sudo", "doas", "env", "nice", "nohup"]
                            .into_iter()
                            .map(|wrapper| program(&format!("/usr/bin/{wrapper}"), true))
                            .chain(
                                names
                                    .iter()
                                    .map(|name| program(&format!("/usr/bin/{name}"), installed)),
                            )
                            .collect::<Vec<_>>();
                        paths.splice(0..0, programs);
                        registry["observation_fixtures"][&name] = variant;
                        name
                    }
                };
                for (form, text) in &forms {
                    wrapped.push(CorpusCase {
                        id: format!("{} {form} ({host} host)", block.row),
                        input: CaseInput::Command(text.clone()),
                        ctx_fixture: case.ctx_fixture.clone(),
                        observation_fixture: fixture.clone(),
                        expected: Expectation::Decision {
                            verdict: ExpectedVerdict::Block,
                            guard: Some(guard.name.to_owned()),
                            coverage: None,
                            guards: None,
                            refusal: None,
                        },
                    });
                }
            }
        }
    }
    let fixtures: FixtureRegistry = serde_json::from_value(registry).expect("variant fixtures");
    let result = reconcile_triage_ledger(&wrapped, &fixtures, "");
    let gap = |failure: &str| {
        let (row, form) = failure.split_once(' ')?;
        FORM_GAPS.iter().position(|(gap_row, forms, _)| {
            *gap_row == row && forms.iter().any(|start| form.starts_with(start))
        })
    };
    let mut errors = Vec::new();
    let mut seen = vec![false; FORM_GAPS.len()];
    for failure in result
        .unexpected_failures
        .iter()
        .chain(&result.analysis_limits)
    {
        match gap(failure) {
            Some(index) => seen[index] = true,
            None => errors.push(failure.clone()),
        }
    }
    for ((row, _, _), seen) in FORM_GAPS.iter().zip(seen) {
        if !seen {
            errors.push(format!(
                "`{row}` blocks in every form; drop it from FORM_GAPS"
            ));
        }
    }
    assert!(
        errors.is_empty(),
        "{} of {} example forms:\n{}",
        errors.len(),
        wrapped.len(),
        errors.join("\n")
    );
}

/// `command` split before its last command, when it is one command or a
/// pipeline of them: the text up to and including the last `| `, and that
/// command. A list, redirection, subshell or substitution has no one command
/// a wrapper takes in its place.
fn last_command(command: &str) -> Option<(&str, &str)> {
    let (mut single, mut double) = (false, false);
    let mut last = 0;
    let bytes = command.as_bytes();
    for (index, c) in command.char_indices() {
        match c {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '`' | '\n' => return None,
            '$' if !single && bytes.get(index + 1) == Some(&b'(') => return None,
            _ if single || double => {}
            ';' | '&' | '<' | '>' | '(' | ')' | '{' | '}' => return None,
            '|' if bytes.get(index + 1) == Some(&b'|') || index > 0 && bytes[index - 1] == b'|' => {
                return None;
            }
            '|' => last = index + 1,
            _ => {}
        }
    }
    let (before, rest) = command.split_at(last);
    let trimmed = rest.trim_start();
    Some((
        &command[..before.len() + rest.len() - trimmed.len()],
        trimmed.trim_end(),
    ))
}
