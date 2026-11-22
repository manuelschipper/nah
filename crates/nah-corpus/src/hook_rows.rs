//! Runs `corpus/hook/` rows: each builds its repository in a fresh folder,
//! sends its command to the runtime's real hook, a `nah` process under a
//! scratch HOME, and holds the reply to the row's expectation. A process of
//! its own is what the hook needs: its save runs in a child that re-executes
//! the hook's own executable, and HOME, the environment the hook observes and
//! its deadline belong to the process.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use nah_corpus_schema::{
    FixtureFile, HookCase, HookExpectation, HookRuntime, RepositoryFixture, WorkSetting,
    read_hook_rows,
};
use serde_json::{Value, json};

/// Decodes every hook row of the corpus in `dir`; any malformed row,
/// duplicate id or rule that is not shipped fails the load with every error.
pub fn load_hook_cases(dir: &Path) -> Result<Vec<HookCase>, Vec<String>> {
    let rows = read_hook_rows(dir).map_err(|error| {
        vec![format!(
            "cannot read hook rows in {}: {error}",
            dir.display()
        )]
    })?;
    let shipped = nah_policy::ShippedGuards::new();
    // `self` is structural, so its rules are no shipped guard's.
    let self_rules = {
        use nah_proto::labels::SelfRule;
        [
            SelfRule::NahConfigChange,
            SelfRule::AgentConfigChange,
            SelfRule::UnguardedAgentLaunch,
        ]
        .map(SelfRule::id)
    };
    let mut ids = BTreeSet::new();
    let mut cases = Vec::new();
    let mut errors = Vec::new();
    for row in rows {
        let location = format!("{}:{}", row.file.display(), row.line);
        match row.case {
            Ok(case)
                if rule(&case.expected).is_some_and(|rule| {
                    !shipped.rule_ids().contains(&rule) && !self_rules.contains(&rule)
                }) =>
            {
                errors.push(format!("{location}: expectation must name a shipped rule"));
            }
            Ok(case) if ids.insert(case.id.clone()) => cases.push(case),
            Ok(case) => errors.push(format!("{location}: duplicate case id `{}`", case.id)),
            Err(error) => errors.push(format!("{location}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(cases)
    } else {
        Err(errors)
    }
}

fn rule(expected: &HookExpectation) -> Option<&str> {
    match expected {
        HookExpectation::Saved { rule } | HookExpectation::Block { rule, .. } => Some(rule),
        HookExpectation::Delegate => None,
    }
}

/// Runs `case` through `nah`, an executable that is Nah's CLI.
pub fn run_hook_case(case: &HookCase, nah: &Path) -> Result<(), String> {
    // A folder no Git repository holds is a project only outside temporary
    // space, where a delete is taken for scratch work, so such a row's
    // folder lies under the home folder of the user running the corpus.
    let temp = match std::env::var_os("HOME") {
        Some(home) if case.repository.folder => tempfile::tempdir_in(home),
        _ => tempfile::tempdir(),
    }
    .map_err(|error| format!("no scratch folder: {error}"))?;
    let root = std::fs::canonicalize(temp.path()).map_err(|error| error.to_string())?;
    let home = root.join("home");
    let repo = root.join("repo");
    std::fs::create_dir_all(home.join(".nah")).map_err(|error| error.to_string())?;
    // Hermes's adapter protects its own home, so an evaluation without one
    // fails; give it the standard one.
    if case.runtime == HookRuntime::Hermes {
        std::fs::create_dir_all(home.join(".hermes")).map_err(|error| error.to_string())?;
    }
    build_repository(&repo, &home, &case.repository)?;
    if case.work == WorkSetting::Strict {
        std::fs::write(
            home.join(".nah/built-ins.json"),
            "{\"v\":3,\"guards\":{\"work\":\"strict\"},\"rules\":{}}\n",
        )
        .map_err(|error| error.to_string())?;
    }
    // Hermes names its event `pre_tool_call` and its shell tool `terminal`.
    let (event, shell) = match case.runtime {
        HookRuntime::Hermes => ("pre_tool_call", "terminal"),
        HookRuntime::Claude | HookRuntime::Codex => ("PreToolUse", "Bash"),
    };
    let event = json!({
        "hook_event_name": event,
        "tool_name": shell,
        "tool_input": {"command": case.command},
        "cwd": repo,
        "session_id": "corpus",
    });
    // Another save holds the store's lock while the hook runs: a listing
    // makes the store, the one folder under `snapshots`.
    let _store_lock = match case.repository.store_lock {
        false => None,
        true => {
            let mut listing = isolated(nah, &home);
            listing.args(["snapshots", "--json"]).current_dir(&repo);
            answer(listing, "")?;
            let store = std::fs::read_dir(home.join(".nah/snapshots"))
                .and_then(|mut stores| stores.next().transpose())
                .map_err(|error| error.to_string())?
                .ok_or("the listing made no snapshot store")?;
            let lock = std::fs::File::options()
                .write(true)
                .open(store.path().join("lock"))
                .map_err(|error| error.to_string())?;
            lock.lock().map_err(|error| error.to_string())?;
            Some(lock)
        }
    };
    // The hook runs in the scratch folder, where a relative path in `env`
    // lands.
    let mut hook = isolated(nah, &home);
    hook.args(["hook", case.runtime.as_str(), "run"])
        .envs(&case.env)
        .current_dir(&root);
    // Hermes blocks with `{"decision":"block","reason":...}`; the others
    // answer in Claude Code's `PreToolUse` reply.
    let reply = answer(hook, &event.to_string())?;
    let hermes_denial = match case.runtime {
        HookRuntime::Hermes => (reply["decision"] == "block")
            .then(|| reply["reason"].as_str().unwrap_or("").to_owned()),
        HookRuntime::Claude | HookRuntime::Codex => None,
    };
    let decision = &reply["hookSpecificOutput"];
    let denial = hermes_denial.as_deref().or_else(|| {
        (decision["permissionDecision"] == "deny")
            .then(|| decision["permissionDecisionReason"].as_str().unwrap_or(""))
    });
    match &case.expected {
        HookExpectation::Saved { rule } => {
            if let Some(reason) = denial {
                return Err(format!(
                    "expected a save under {rule}, got a block: {reason}"
                ));
            }
            let note = decision["additionalContext"]
                .as_str()
                .ok_or_else(|| format!("expected a save under {rule}, got {reply}"))?;
            // The decision's audit record names the snapshot as data; the
            // note to the agent is checked against it.
            let mut log = isolated(nah, &home);
            log.args(["log", "--json", "-n", "1"]).current_dir(&repo);
            let record = answer(log, "")?;
            let id = record["saved"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|saved| {
                    saved["rules"]
                        .as_array()
                        .is_some_and(|rules| rules.iter().any(|named| named == rule.as_str()))
                })
                .and_then(|saved| saved["snapshot"].as_str())
                .ok_or_else(|| format!("no snapshot under {rule} in the audit record {record}"))?;
            if !note.contains(rule.as_str()) || !note.contains(&format!("nah undo {id}")) {
                return Err(format!(
                    "expected the note to name {rule} and undo snapshot {id}: {note}"
                ));
            }
            let mut listing = isolated(nah, &home);
            listing.args(["snapshots", "--json"]).current_dir(&repo);
            let listed = answer(listing, "")?;
            if !listed
                .as_array()
                .is_some_and(|snapshots| snapshots.iter().any(|snapshot| snapshot["id"] == id))
            {
                return Err(format!("snapshot {id} is not in the store: {listed}"));
            }
        }
        HookExpectation::Delegate => {
            if let Some(reason) = denial {
                return Err(format!("expected a delegate, got a block: {reason}"));
            }
            // A hook that could not evaluate the call also lets it go on, with
            // nothing in its reply to tell it apart (Hermes answers `{}`), so
            // the decision log must hold an evaluated decision.
            let mut log = isolated(nah, &home);
            log.args(["log", "--json", "-n", "1"]).current_dir(&repo);
            let record = answer(log, "")?;
            if record["status"] != "decision"
                || record["failures"]
                    .as_array()
                    .is_some_and(|failures| !failures.is_empty())
            {
                return Err(format!("expected an evaluated delegate, got {record}"));
            }
            let mut listing = isolated(nah, &home);
            listing.args(["snapshots", "--json"]).current_dir(&repo);
            let listed = answer(listing, "")?;
            if listed
                .as_array()
                .is_none_or(|snapshots| !snapshots.is_empty())
            {
                return Err(format!("expected no save, got snapshots {listed}"));
            }
        }
        HookExpectation::Block { rule, reason } => {
            let Some(denied) = denial else {
                return Err(format!("expected a block under {rule}, got {reply}"));
            };
            if !denied.contains(rule.as_str()) || !denied.contains(reason.as_str()) {
                return Err(format!(
                    "expected a block under {rule} saying `{reason}`, got: {denied}"
                ));
            }
        }
    }
    Ok(())
}

/// `program` run with `home` as HOME, bash as the shell Claude Code's hook
/// reads its commands in (a row's `env` may name another), and none of git's
/// or Nah's own variables from the environment the corpus runs in.
pub(crate) fn isolated(program: &Path, home: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("SHELL", "/bin/bash")
        .env_remove("CLAUDE_CODE_SHELL")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HERMES_HOME");
    for (name, _) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("GIT_") || name.starts_with("NAH_"))
            && name != "GIT_CONFIG_NOSYSTEM"
        {
            command.env_remove(name);
        }
    }
    command
}

/// What `command` printed on `input`, read as JSON; `Null` for nothing.
fn answer(command: Command, input: &str) -> Result<Value, String> {
    let output = output_of(command, input)?;
    if !output.status.success() {
        return Err(format!("the command failed: {output:?}"));
    }
    if output.stdout.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("the command printed no JSON ({error}): {output:?}"))
}

/// How `command` ended on `input`.
pub(crate) fn output_of(mut command: Command, input: &str) -> Result<std::process::Output, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start {command:?}: {error}"))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .map_err(|error| error.to_string())?;
    child.wait_with_output().map_err(|error| error.to_string())
}

pub(crate) fn build_repository(
    repo: &Path,
    home: &Path,
    fixture: &RepositoryFixture,
) -> Result<(), String> {
    let git = |directory: &Path, args: &[&str]| {
        let output = isolated(Path::new("git"), home)
            .arg("-C")
            .arg(directory)
            .args([
                "-c",
                "user.name=nah corpus",
                "-c",
                "user.email=nah@example.invalid",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .output()
            .map_err(|error| format!("cannot run git: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("git {args:?} failed: {output:?}"))
        }
    };
    let write = |path: &str, file: &FixtureFile| {
        let path = repo.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let bytes = match file {
            FixtureFile::Text(text) => text.as_bytes().to_vec(),
            FixtureFile::Filler(filler) if filler.noise => {
                let mut state = 0x9e37_79b9_7f4a_7c15_u64;
                (0..filler.bytes)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect()
            }
            FixtureFile::Filler(filler) => vec![b'x'; filler.bytes as usize],
        };
        std::fs::write(&path, bytes).map_err(|error| format!("{}: {error}", path.display()))
    };
    let commit = |files: &BTreeMap<String, FixtureFile>| {
        for (path, file) in files {
            write(path, file)?;
        }
        git(repo, &["add", "-A"])?;
        git(repo, &["commit", "-q", "--allow-empty", "-m", "fixture"])
    };
    std::fs::create_dir_all(repo).map_err(|error| error.to_string())?;
    if !fixture.folder {
        git(repo, &["init", "-q"])?;
        for (name, value) in &fixture.config {
            git(repo, &["config", name, value])?;
        }
        commit(&fixture.committed)?;
        for files in &fixture.commits {
            commit(files)?;
        }
        for entry in &fixture.stash {
            for (path, file) in &entry.files {
                write(path, file)?;
            }
            git(repo, &["stash", "push", "-q", "-u", "-m", &entry.message])?;
        }
        for branch in &fixture.branches {
            git(
                repo,
                &[
                    "branch",
                    &branch.name,
                    branch.at.as_deref().unwrap_or("HEAD"),
                ],
            )?;
            if !branch.commits.is_empty() {
                git(repo, &["checkout", "-q", &branch.name])?;
                for files in &branch.commits {
                    commit(files)?;
                }
                git(repo, &["checkout", "-q", "main"])?;
            }
        }
        for made in &fixture.refs {
            git(
                repo,
                &[
                    "checkout",
                    "-q",
                    "--detach",
                    made.at.as_deref().unwrap_or("HEAD"),
                ],
            )?;
            for files in &made.commits {
                commit(files)?;
            }
            match (&made.message, made.name.strip_prefix("refs/tags/")) {
                (Some(message), Some(tag)) => git(repo, &["tag", "-a", "-m", message, tag])?,
                (Some(_), None) => return Err(format!("{} is no tag to annotate", made.name)),
                (None, _) => git(repo, &["update-ref", &made.name, "HEAD"])?,
            }
            git(repo, &["checkout", "-q", "main"])?;
        }
    }
    for (path, file) in &fixture.worktree {
        write(path, file)?;
    }
    // Hook rows run on Unix hosts only.
    for (path, target) in &fixture.links {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, repo.join(path))
            .map_err(|error| format!("{path}: {error}"))?;
        #[cfg(not(unix))]
        return Err(format!("{path}: no link to {target} outside Unix"));
    }
    for path in &fixture.staged {
        git(repo, &["add", "--", path])?;
    }
    for path in &fixture.repositories {
        let nested = repo.join(path);
        std::fs::create_dir_all(&nested).map_err(|error| error.to_string())?;
        git(&nested, &["init", "-q"])?;
    }
    for args in &fixture.git {
        git(repo, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
    }
    if fixture.index_lock {
        std::fs::write(repo.join(".git/index.lock"), "").map_err(|error| error.to_string())?;
    }
    Ok(())
}
