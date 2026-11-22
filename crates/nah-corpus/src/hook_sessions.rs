//! Records a session through Nah's real hook, for the session replay's
//! differential test: each call is sent to `nah hook claude run` in a
//! scratch folder, as `hook_rows` sends one, and the test, never a shell,
//! puts on disk what a call the hook let run would have left. Before each
//! call and after each result the folder is captured as supplied state, so
//! the recording is a `nah/session/v2` file from the session's start. A debug build of the hook
//! writes the facts it computed to `NAH_DEBUG_FACTS`, which the test holds
//! the replay to.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use nah_corpus_schema::RepositoryFixture;
use nah_proto::effinterp_proto::content_digest;
use serde_json::{Value, json};

use crate::hook_rows::{build_repository, isolated, output_of};

/// The programs whose places on `PATH` a capture declares, present or
/// missing: those the sessions' commands name.
const PROGRAMS: &[&str] = &[
    "sh", "bash", "cat", "cp", "curl", "git", "make", "wc", "sleep", "echo", "env", "aws", "scp",
];

/// One session: what it starts from and its steps.
pub struct HookSession {
    pub id: &'static str,
    /// The text of `~/.nah/built-ins.json` for the session; `None` for the
    /// shipped defaults.
    pub settings: Option<&'static str>,
    pub repository: RepositoryFixture,
    /// Variables the hook's environment carries besides `HOME` and `PATH`.
    pub env: Vec<(&'static str, &'static str)>,
    pub steps: Vec<Step>,
}

/// One step. `{root}` and `{repo}` in any text stand for the scratch folder
/// and the repository in it.
pub enum Step {
    Prompt(&'static str),
    /// A tool call. When the hook lets it run and it is not denied, each
    /// `(path, content)` of `leaves` is written, or removed for `None`, and
    /// then its result is reported with `output` as what it printed.
    Call {
        tool: &'static str,
        input: Value,
        leaves: Vec<(&'static str, Option<&'static str>)>,
        output: &'static str,
        outcome: Outcome,
    },
    /// From here, a process runs whose command line names the file `path`,
    /// as a launch the session left running would. It is `sleep` under
    /// another name and runs nothing of the session's.
    Running(&'static str),
    /// The process `Running` started for `path` ends.
    Stopped(&'static str),
}

/// A process `Step::Running` started, stopped when dropped.
struct StandIn(std::process::Child);

impl Drop for StandIn {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy)]
pub enum Outcome {
    Succeeded,
    Failed,
    /// The user denied the call, so it never ran.
    Denied,
}

/// What recording a session produced.
pub struct Recorded {
    /// The `nah/session/v2` file.
    pub session: Value,
    /// The live hook's facts, one per pre-call and post-call event, in order.
    pub live: Vec<Value>,
    /// Whether the hook blocked each call, in order.
    pub blocked: Vec<bool>,
}

/// Records `session` through `nah`, a debug build of Nah's CLI.
pub fn record_hook_session(session: &HookSession, nah: &Path) -> Result<Recorded, String> {
    let temp = tempfile::tempdir().map_err(|error| format!("no scratch folder: {error}"))?;
    let root = std::fs::canonicalize(temp.path()).map_err(|error| error.to_string())?;
    let facts_folder = tempfile::tempdir().map_err(|error| error.to_string())?;
    let facts = facts_folder.path().join("facts.jsonl");
    let home = root.join("home");
    let repo = root.join("repo");
    std::fs::create_dir_all(home.join(".nah")).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(root.join("outside")).map_err(|error| error.to_string())?;
    build_repository(&repo, &home, &session.repository)?;
    if let Some(settings) = &session.settings {
        std::fs::write(home.join(".nah/built-ins.json"), format!("{settings}\n"))
            .map_err(|error| error.to_string())?;
    }
    let spell = |text: &str| {
        text.replace("{root}", &root.to_string_lossy())
            .replace("{repo}", &repo.to_string_lossy())
    };
    let spell_value = |value: &Value| -> Value {
        serde_json::from_str(&spell(&value.to_string())).expect("a spelled value is JSON")
    };
    let mut env = BTreeMap::from([
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
        (
            "PATH".to_owned(),
            std::env::var("PATH").map_err(|_| "no PATH")?,
        ),
    ]);
    for (name, value) in &session.env {
        env.insert((*name).to_owned(), (*value).to_owned());
    }
    // Every path a step names, so a capture declares it, present or missing,
    // and the pathspecs of each `git add`, whose staging it reads.
    let mut named = BTreeSet::new();
    let mut adds = BTreeSet::new();
    for step in &session.steps {
        let Step::Call { input, leaves, .. } = step else {
            continue;
        };
        named.extend(leaves.iter().map(|(path, _)| repo.join(spell(path))));
        let input = spell_value(input);
        if let Some(path) = input["file_path"].as_str() {
            named.insert(PathBuf::from(path));
        }
        let command = input["command"].as_str().unwrap_or_default();
        if let Some(rest) = command.strip_prefix("git add ") {
            adds.insert(
                rest.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
        }
        for word in command.split_whitespace() {
            let word = word.trim_matches(|c: char| "\"'();&|<>@".contains(c));
            if !word.is_empty() && !"-$=:".chars().any(|c| word.contains(c)) {
                named.insert(repo.join(word));
            }
        }
    }
    // The files the stand-in processes name, whose running processes each
    // capture declares as `ps` lists them.
    let watched: Vec<String> = session
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Running(path) => Some(repo.join(spell(path)).to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    // The shell profiles session memory reads for the files they source.
    for profile in [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
    ] {
        named.insert(home.join(profile));
    }
    let capture =
        |named: &BTreeSet<PathBuf>| capture(&root, &home, &repo, &env, named, &adds, &watched);
    let hook = |event: &Value| -> Result<Value, String> {
        let mut command = isolated(nah, &home);
        command
            .env_clear()
            .envs(&env)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NAH_DEBUG_FACTS", &facts)
            .args(["hook", "claude", "run"])
            .current_dir(&root);
        let output = output_of(command, &event.to_string())?;
        if !output.status.success() {
            return Err(format!("the hook failed: {output:?}"));
        }
        if output.stdout.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())
    };
    let mut events = Vec::new();
    let mut blocked = Vec::new();
    let mut running: Vec<(&str, StandIn)> = Vec::new();
    for (position, step) in session.steps.iter().enumerate() {
        let (tool, input, leaves, output, outcome) = match step {
            Step::Prompt(text) => {
                events.push(json!({"type": "user_prompt", "text": text}));
                continue;
            }
            Step::Running(path) => {
                let mut command = std::process::Command::new("sleep");
                #[cfg(unix)]
                std::os::unix::process::CommandExt::arg0(
                    &mut command,
                    format!("stand-in {}", repo.join(spell(path)).display()),
                );
                let child = command
                    .arg("600")
                    .spawn()
                    .map_err(|error| error.to_string())?;
                running.push((path, StandIn(child)));
                continue;
            }
            Step::Stopped(path) => {
                running.retain(|(name, _)| name != path);
                continue;
            }
            Step::Call {
                tool,
                input,
                leaves,
                output,
                outcome,
            } => (tool, spell_value(input), leaves, spell(output), *outcome),
        };
        let id = format!("toolu_{position:02}");
        let state = capture(&named)?;
        let pre = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
            "cwd": repo,
            "session_id": session.id,
            "tool_use_id": id,
        });
        let reply = hook(&pre)?;
        let denied = reply["hookSpecificOutput"]["permissionDecision"] == "deny";
        blocked.push(denied);
        events.push(json!({
            "type": "tool_call", "id": id, "tool": tool, "input": input, "state": state,
        }));
        // A blocked call never runs, and nothing reports it.
        if denied {
            continue;
        }
        let (name, result) = match outcome {
            Outcome::Denied => ("PostToolBatch", "not_run"),
            Outcome::Succeeded => ("PostToolUse", "succeeded"),
            Outcome::Failed => ("PostToolUseFailure", "failed"),
        };
        if !matches!(outcome, Outcome::Denied) {
            for (path, content) in leaves {
                let path = repo.join(spell(path));
                match content {
                    Some(content) => {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                        }
                        std::fs::write(&path, spell(content)).map_err(|error| error.to_string())?
                    }
                    None => std::fs::remove_file(&path).map_err(|error| error.to_string())?,
                }
            }
        }
        let response = if output.is_empty() {
            json!({})
        } else {
            json!({"stdout": output, "stderr": ""})
        };
        let mut post = pre.clone();
        post["hook_event_name"] = json!(name);
        post["tool_response"] = response.clone();
        if matches!(outcome, Outcome::Denied) {
            post["tool_calls"] = json!([{"tool_name": tool, "tool_input": input, "tool_use_id": id,
                "tool_response": "The user doesn't want to proceed with this tool use."}]);
        }
        hook(&post)?;
        events.push(json!({
            "type": "tool_result", "id": id, "outcome": result, "output": response, "state": capture(&named)?,
        }));
    }
    let live = std::fs::read_to_string(&facts)
        .map_err(|error| format!("the hook wrote no facts: {error}"))?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(|error| error.to_string()))
        .collect::<Result<Vec<Value>, String>>()?;
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let session = json!({
        "schema": "nah/session/v2",
        "runtime": "claude",
        "session_id": session.id,
        "from_start": true,
        "context": {
            "platform": platform,
            "home": home,
            "guard_settings": match session.settings {
                Some(settings) => {
                    let settings: Value = serde_json::from_str(settings).map_err(|error| error.to_string())?;
                    json!({"guards": settings["guards"], "rules": settings["rules"]})
                }
                None => json!("factory-defaults"),
            },
            "protected_paths": [home.join(".claude/settings.json")],
        },
        "events": events,
    });
    Ok(Recorded {
        session,
        live,
        blocked,
    })
}

/// The scratch folder as supplied state: every entry below `root` but Nah's
/// own state, the folders above it, the places on `PATH` of the programs
/// the sessions name, each `named` path that is missing, the hook's
/// environment, the repository's Git state, and, where the session runs
/// stand-in processes, the running processes that name a `watched` file.
fn capture(
    root: &Path,
    home: &Path,
    repo: &Path,
    env: &BTreeMap<String, String>,
    named: &BTreeSet<PathBuf>,
    adds: &BTreeSet<Vec<String>>,
    watched: &[String],
) -> Result<Value, String> {
    let mut paths = BTreeMap::new();
    let mut walk = vec![root.to_path_buf()];
    while let Some(path) = walk.pop() {
        if path == home.join(".nah") {
            continue;
        }
        let entry = declared(&path, Some(root))?;
        if path.is_dir() && !path.is_symlink() {
            for child in std::fs::read_dir(&path).map_err(|error| error.to_string())? {
                walk.push(child.map_err(|error| error.to_string())?.path());
            }
        }
        paths.insert(path, entry);
    }
    for ancestor in root.ancestors().skip(1) {
        paths.insert(ancestor.to_path_buf(), declared(ancestor, None)?);
    }
    for folder in std::env::split_paths(&env["PATH"]) {
        if !folder.is_absolute() || paths.contains_key(&folder) {
            continue;
        }
        if folder.is_dir() {
            paths.insert(folder.clone(), declared(&folder, None)?);
        }
        for program in PROGRAMS {
            let path = folder.join(program);
            paths.entry(path.clone()).or_insert(declared(&path, None)?);
        }
    }
    for path in named {
        if !paths.contains_key(path) {
            paths.insert(path.clone(), declared(path, Some(root))?);
        }
    }
    let git = |args: &[&str]| -> Result<Vec<u8>, String> {
        let mut command = isolated(Path::new("git"), home);
        command.arg("-C").arg(repo).args(args);
        let output = command.output().map_err(|error| error.to_string())?;
        Ok(output.stdout)
    };
    let listed = |args: &[&str]| -> Result<Vec<String>, String> {
        Ok(String::from_utf8_lossy(&git(args)?)
            .split('\0')
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect())
    };
    let blobs = |args: &[&str]| -> Result<BTreeMap<String, String>, String> {
        let mut digests = BTreeMap::new();
        for line in listed(args)? {
            // `<mode> <type or blob> <object>[ <stage>]\t<path>`.
            let (meta, path) = line.split_once('\t').ok_or("unlisted blob")?;
            let object = meta.split_whitespace().nth(2).ok_or("no object")?;
            digests.insert(
                path.to_owned(),
                content_digest(&git(&["cat-file", "blob", object])?),
            );
        }
        Ok(digests)
    };
    let changed = !isolated(Path::new("git"), home)
        .arg("-C")
        .arg(repo)
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
        .map_err(|error| error.to_string())?
        .success();
    let stash = !git(&["rev-parse", "-q", "--verify", "refs/stash"])?.is_empty();
    // What `git add PATHSPEC...` would stage that is named like a secret
    // file, as Nah's Git read answers it.
    let mut reads = Vec::new();
    for pathspecs in adds {
        let mut args = vec![
            "status",
            "--porcelain=v1",
            "-z",
            "--no-renames",
            "--untracked-files=all",
            "--ignored=no",
            "--",
        ];
        args.extend(pathspecs.iter().map(String::as_str));
        let staged: Vec<String> = listed(&args)?
            .iter()
            .filter_map(|entry| entry.get(3..))
            .filter(|path| {
                let name = path.rsplit('/').next().unwrap_or(path);
                name == ".env"
                    || name.starts_with(".env.")
                    || [
                        ".pypirc",
                        ".pgpass",
                        ".boto",
                        "id_rsa",
                        "id_dsa",
                        "id_ecdsa",
                        "id_ed25519",
                        ".netrc",
                        ".git-credentials",
                    ]
                    .contains(&name)
            })
            .map(|path| repo.join(path).to_string_lossy().into_owned())
            .collect();
        reads.push(json!({
            "path": repo,
            "selection": {"kind": "addable", "revisions": [], "revision_options": [],
                "pathspecs": pathspecs, "pathspec_options": []},
            "paths": staged,
        }));
    }
    let mut processes = None;
    if !watched.is_empty() {
        let output = std::process::Command::new("ps")
            .args(["-axww", "-o", "command="])
            .output()
            .map_err(|error| error.to_string())?;
        // Session memory asks whether a line names a file by its name.
        let names: Vec<&str> = watched
            .iter()
            .map(|path| path.rsplit('/').next().unwrap_or(path))
            .collect();
        processes = Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| names.iter().any(|name| line.contains(name)))
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
    }
    Ok(json!({
        "platform": if cfg!(target_os = "macos") { "macos" } else { "linux" },
        "processes": processes,
        "cwd": repo,
        "env": env,
        "paths": paths.into_values().collect::<Vec<_>>(),
        "roots": [{"kind": "project", "path": repo}],
        "git_state": [{
            "path": repo,
            "tracked_changes": changed,
            "stash_entries": stash,
            "untracked": listed(&["ls-files", "-z", "--others", "--exclude-standard"])?,
            "ignored": listed(&["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"])?,
            "moves_logged": true,
            "creates_reflogs": true,
            "index": blobs(&["ls-files", "-z", "--stage"])?,
            "head": blobs(&["ls-tree", "-z", "-r", "HEAD"])?,
        }],
        "git_hooks": repo.join(".git/hooks"),
        "git_reads": reads,
    }))
}

/// The path entry a capture declares for `path`. Inside `within`, a file's
/// text and a folder's complete inventory of regular files are declared too.
fn declared(path: &Path, within: Option<&Path>) -> Result<Value, String> {
    let inside = within.is_some_and(|within| path.starts_with(within));
    let spelled = path.to_string_lossy();
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        let mut entry = json!({
            "requested": spelled, "resolved": spelled, "kind": "missing", "exists": false,
        });
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
            && let Ok(parent) = std::fs::canonicalize(parent)
        {
            entry["followed"] = json!(parent.join(name));
        }
        return Ok(entry);
    };
    let realpath = std::fs::canonicalize(path).map_err(|error| error.to_string())?;
    let kind = |file_type: std::fs::FileType| {
        if file_type.is_symlink() {
            "symlink"
        } else if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else {
            "other"
        }
    };
    let mut entry = json!({
        "requested": spelled,
        "resolved": spelled,
        "realpath": realpath,
        "kind": kind(metadata.file_type()),
        "exists": true,
    });
    if let Ok(modified) = std::fs::metadata(path).and_then(|metadata| metadata.modified())
        && let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        entry["modified_ns"] = json!(since.as_nanos() as u64);
    }
    if metadata.file_type().is_symlink() {
        entry["target_kind"] = json!(
            std::fs::metadata(path)
                .map(|target| kind(target.file_type()))
                .unwrap_or("missing")
        );
    }
    #[cfg(unix)]
    if metadata.is_file() || metadata.file_type().is_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map_or(0, |target| target.permissions().mode());
        entry["executable"] = json!(mode & 0o111 != 0);
    }
    if metadata.is_file()
        && inside
        && let Ok(text) = std::fs::read_to_string(path)
    {
        entry["contents"] = json!(text);
    }
    if metadata.is_dir() && inside {
        let mut files = Vec::new();
        let mut walk = vec![path.to_path_buf()];
        while let Some(folder) = walk.pop() {
            for child in std::fs::read_dir(&folder).map_err(|error| error.to_string())? {
                let child = child.map_err(|error| error.to_string())?.path();
                let file_type = std::fs::symlink_metadata(&child)
                    .map_err(|error| error.to_string())?
                    .file_type();
                if file_type.is_dir() {
                    walk.push(child);
                } else if file_type.is_file() {
                    files.push(child.to_string_lossy().into_owned());
                }
            }
        }
        files.sort();
        entry["descendants"] = json!(files);
    }
    Ok(entry)
}
