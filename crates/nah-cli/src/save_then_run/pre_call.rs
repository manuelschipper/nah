//! Before a discard runs: make sure a snapshot holds everything it would
//! destroy, or say what it cannot hold. The save runs in a child process
//! the hook abandons at its deadline, so the hook answers in time whatever
//! the save meets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::ops::Bound;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use nah_proto::observation::RefDeletion;
use nah_snapshot::{
    Budget, Context, Deleting, DiscardResult, Freshness, Manifest, NotSaved, NotSavedReason,
    Origin, Refusal, Stage,
};
use serde::{Deserialize, Serialize};

use super::{Discard, DiscardKind, Discards, Moves, Saved, Selection, Writes};
use crate::commands::snapshot_context;

/// How long after the hook started its answer must be ready: Nah installs
/// each saving runtime's pre-call hook with a 5 s timeout, which also counts
/// launching nah and the work after the save.
const ANSWER_BY: Duration = Duration::from_millis(4000);

/// How long past the save's deadline the hook waits for a save child it
/// killed to be gone, and for the snapshots it was let publish to be found.
const REAP: Duration = Duration::from_millis(250);

/// An ignored file larger than this is not copied, nor are ignored files
/// beyond the total: a command that would delete them is blocked.
const IGNORED_FILE_BYTES: u64 = 1024 * 1024;
const IGNORED_TOTAL_BYTES: u64 = 20 * 1024 * 1024;

/// What the hook asks its save child to do, on one line of its input.
#[derive(Deserialize, Serialize)]
struct SaveRequest {
    discards: Vec<Discard>,
    command: String,
    /// The files the session labels as secret.
    labelled: Vec<PathBuf>,
    /// How long the save may take.
    within_ms: u64,
}

/// One line of the save child's output.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FromChild {
    /// It is about to make the snapshot that will be this folder visible,
    /// and waits for the hook's `go`.
    Publish(PathBuf),
    /// A snapshot that holds what some of the discards destroy, finished.
    Saved(Saved),
    /// Whether every discard was saved, or the reason to block.
    Done(Result<(), String>),
}

/// Saves what `found`'s discards would destroy, in the hook's save child
/// ([`run_save_child`]), for `dispatch.rs`'s `save_before_run`. Returns the
/// snapshots finished, which a block keeps too, and the reason to block if
/// any: something they would destroy that Nah did not or must not save, or
/// a save that did not finish in time.
/// `labelled` names the files the session labels as secret, which are never
/// copied: a discard that would destroy one is blocked like one of a secret
/// file.
pub(crate) fn save_discards(
    found: &Discards,
    command: &str,
    labelled: Vec<PathBuf>,
) -> (Vec<Saved>, Result<(), String>) {
    let (saved, result) = save_in_child(found, command, labelled);
    if !saved.is_empty() {
        let mut directories = found
            .discards
            .iter()
            .map(|discard| discard.directory.clone())
            .collect::<Vec<_>>();
        directories.sort();
        directories.dedup();
        super::retain_in_background(&directories);
    }
    (saved, result)
}

/// [`save_discards`] up to the snapshots finished and the answer.
fn save_in_child(
    found: &Discards,
    command: &str,
    labelled: Vec<PathBuf>,
) -> (Vec<Saved>, Result<(), String>) {
    let answer_by = *crate::dispatch::HOOK_STARTED + ANSWER_BY;
    let deadline = (Instant::now() + nah_snapshot::DEFAULT_DEADLINE).min(answer_by - REAP);
    let blocked = |why: &str| blocked(command, why);
    let request = SaveRequest {
        discards: found.discards.clone(),
        command: command.to_owned(),
        labelled,
        within_ms: deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64,
    };
    // In a process group of its own, so the git it starts ends with it.
    let spawned = std::env::current_exe().and_then(|executable| {
        Command::new(executable)
            .args(["hook", "claude", "run", "--save"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let why = format!("its save process could not start ({error})");
            return (Vec::new(), Err(blocked(&why)));
        }
    };
    let (answer, granted, saved) = converse(&mut child, &request, deadline);
    // The child and the git it started end here. Each snapshot it publishes
    // waits for a `go` given only before the deadline, so none appears after
    // the hook answers unless the child, let publish in time, is stuck where
    // even this signal cannot end it yet.
    let _ = rustix::process::kill_process_group(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::KILL,
    );
    let why = match answer {
        Answer::Done(result) => return (saved, result),
        Answer::Late => "saving took longer than the hook may wait, and nah stopped it",
        Answer::Gone(detail) => detail,
    };
    // Waiting for the child and looking for the snapshots it was let publish
    // touch the store, which may be what stalled: a thread the hook stops
    // waiting for shortly after the save's deadline does both.
    let (found, seen) = mpsc::channel();
    let folders = granted.clone();
    std::thread::spawn(move || {
        let _ = child.wait();
        store_stall_for_tests();
        let _ = found.send(folders.iter().map(|folder| folder.is_dir()).collect());
    });
    let published: Option<Vec<bool>> = seen
        .recv_timeout((deadline + REAP).saturating_duration_since(Instant::now()))
        .ok();
    let mut why = why.to_owned();
    for (index, folder) in granted.iter().enumerate() {
        let Some(id) = folder.file_name().and_then(|id| id.to_str()) else {
            continue;
        };
        // A finished snapshot holds all it was made for, and the decision
        // records it.
        if saved.iter().any(|saved| saved.snapshot == id) {
            continue;
        }
        match published.as_ref().map(|published| published[index]) {
            Some(true) => why.push_str(&format!(
                "; snapshot {id}, saved before then, may not hold all of it"
            )),
            // The child is gone without publishing it.
            Some(false) => {}
            None => why.push_str(&format!(
                "; snapshot {id} may be saved or may still appear, and may not hold all of it"
            )),
        }
    }
    (saved, Err(blocked(&why)))
}

/// How a save child ended its conversation with the hook.
enum Answer {
    Done(Result<(), String>),
    /// The deadline came first.
    Late,
    /// It stopped answering, as this says.
    Gone(&'static str),
}

/// Sends `request` to `child` and answers its requests to publish until it
/// is done, it stops answering or `deadline` comes. Returns how it ended,
/// the folders of the snapshots it was let publish, and the snapshots it
/// reported finished. Nothing here waits past `deadline`: a separate thread
/// writes to the child, which may not read.
fn converse(
    child: &mut Child,
    request: &SaveRequest,
    deadline: Instant,
) -> (Answer, Vec<PathBuf>, Vec<Saved>) {
    let (Some(mut input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
        return (
            Answer::Gone("its save process has no input or output"),
            Vec::new(),
            Vec::new(),
        );
    };
    let (to_child, outgoing) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        for bytes in outgoing {
            if input.write_all(&bytes).is_err() {
                break;
            }
        }
    });
    let mut line = serde_json::to_vec(request).expect("a save request serializes");
    line.push(b'\n');
    let _ = to_child.send(line);
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if line.map(|line| lines.send(line)).is_err() {
                break;
            }
        }
    });
    let mut granted = Vec::new();
    let mut saved = Vec::new();
    loop {
        let line = match received.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => line,
            Err(mpsc::RecvTimeoutError::Timeout) => return (Answer::Late, granted, saved),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return (
                    Answer::Gone("its save process ended without an answer"),
                    granted,
                    saved,
                );
            }
        };
        match serde_json::from_str(&line) {
            Ok(FromChild::Done(result)) => return (Answer::Done(result), granted, saved),
            Ok(FromChild::Saved(finished)) => saved.push(finished),
            Ok(FromChild::Publish(_)) if Instant::now() >= deadline => {
                return (Answer::Late, granted, saved);
            }
            Ok(FromChild::Publish(folder)) => {
                // A child that is gone takes no `go`, and so publishes nothing.
                let _ = to_child.send(b"go\n".to_vec());
                granted.push(folder);
            }
            Err(_) => {
                return (
                    Answer::Gone("its save process answered in a form nah does not read"),
                    granted,
                    saved,
                );
            }
        }
    }
}

/// The hook's save child: reads one [`SaveRequest`], saves, reports each
/// snapshot it finishes, and writes its [`FromChild::Done`] answer. It asks before each snapshot it publishes,
/// and publishes none the hook does not allow.
pub(crate) fn run_save_child() -> u8 {
    // The process's standard streams, shared by the request and the
    // questions asked while saving; `dispatch::run` holds their locks.
    let (Ok(input), Ok(output)) = (
        std::io::stdin().as_fd().try_clone_to_owned(),
        std::io::stdout().as_fd().try_clone_to_owned(),
    ) else {
        return 1;
    };
    let input = Arc::new(Mutex::new(BufReader::new(File::from(input))));
    let output = Arc::new(Mutex::new(File::from(output)));
    let mut line = String::new();
    let read = input
        .lock()
        .map_err(drop)
        .and_then(|mut input| input.read_line(&mut line).map_err(drop));
    let Some(request) = read
        .ok()
        .and_then(|_| serde_json::from_str::<SaveRequest>(&line).ok())
    else {
        return 1;
    };
    let within = Duration::from_millis(request.within_ms).min(ANSWER_BY);
    let deadline = Instant::now() + within;
    // Past its deadline the hook has stopped waiting; a save stuck where no
    // deadline reaches it must not hold the store's lock on.
    std::thread::spawn(move || {
        std::thread::sleep(within + Duration::from_secs(1));
        std::process::exit(1);
    });
    let say = {
        let output = Arc::clone(&output);
        move |message: &FromChild| {
            let mut line = serde_json::to_vec(message).expect("a child message serializes");
            line.push(b'\n');
            output
                .lock()
                .is_ok_and(|mut output| output.write_all(&line).is_ok())
        }
    };
    let may_publish = {
        let say = say.clone();
        move |folder: &Path| {
            stall_for_tests();
            let mut answer = String::new();
            let go = say(&FromChild::Publish(folder.to_path_buf()))
                && input
                    .lock()
                    .is_ok_and(|mut input| input.read_line(&mut answer).is_ok())
                && answer.trim_end() == "go";
            store_stall_for_tests();
            go
        }
    };
    let finished = |saved| {
        say(&FromChild::Saved(saved));
    };
    let result = save_all(&request, deadline, Box::new(may_publish), &finished);
    if say(&FromChild::Done(result)) { 0 } else { 1 }
}

/// What a dry run of the save of `found` can tell before it runs, reading
/// nothing it would copy: the reason it blocks when another Git process
/// holds a discarded repository's index lock.
pub(crate) fn save_preflight(found: &Discards, command: &str) -> Result<(), String> {
    let context = snapshot_context(|| Ok(Vec::new())).map_err(|error| blocked(command, &error))?;
    let deadline = Instant::now() + nah_snapshot::DEFAULT_DEADLINE;
    for discard in &found.discards {
        nah_snapshot::index_unlocked(&context, &discard.directory, deadline)
            .map_err(|refusal| blocked(command, &refusal.to_string()))?;
    }
    Ok(())
}

/// With `NAH_TEST_SAVE_STALL` naming a file, a debug build's save child
/// writes its process id there and stalls before it publishes, as a save
/// stuck past its deadline would.
fn stall_for_tests() {
    #[cfg(debug_assertions)]
    if let Some(file) = std::env::var_os("NAH_TEST_SAVE_STALL") {
        let _ = fs::write(file, std::process::id().to_string());
        std::thread::sleep(Duration::from_secs(60));
    }
}

/// With `NAH_TEST_STORE_STALL` set, a debug build stalls where it touches
/// the snapshot store once a publication was granted: the save child after
/// its `go`, and the hook looking for that snapshot and removing its marker,
/// as a store that stopped answering would.
pub(super) fn store_stall_for_tests() {
    #[cfg(debug_assertions)]
    if std::env::var_os("NAH_TEST_STORE_STALL").is_some() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

/// The reason to block a `command` whose discards could not all be saved,
/// for `why`; the decision names the rules.
fn blocked(command: &str, why: &str) -> String {
    format!(
        "nah could not first save everything `{}` would destroy: {why}. Save or move that work yourself, or ask the operator",
        short(command)
    )
}

/// The rules `discards` fall under.
fn rules(discards: &[&Discard]) -> Vec<String> {
    discards
        .iter()
        .map(|discard| discard.kind.rule())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// Saves what `request`'s discards would destroy by `deadline`, asking
/// `may_publish` before each snapshot it makes visible and handing each
/// finished snapshot to `finished` at once, so a later failure leaves the
/// earlier ones known.
fn save_all(
    request: &SaveRequest,
    deadline: Instant,
    may_publish: Box<dyn Fn(&Path) -> bool + Send + Sync>,
    finished: &dyn Fn(Saved),
) -> Result<(), String> {
    let command = &request.command;
    // Each snapshot names the rules of what it holds.
    let finish = |rules: Vec<String>, saved: Result<Saved, String>| {
        let saved = saved.map_err(|why| blocked(command, &why))?;
        finished(Saved {
            note: format!(
                "nah · {}: before `{}` ran, {}",
                rules.join(", "),
                short(command),
                saved.note
            ),
            rules,
            ..saved
        });
        Ok::<_, String>(())
    };
    // Labels another session records during the save count as well.
    let labelled = request.labelled.clone();
    let mut context = snapshot_context(move || {
        let mut now = labelled.clone();
        now.extend(crate::session_memory::labelled_paths()?);
        Ok(now)
    })
    .map_err(|error| format!("nah could not open its snapshot store ({error})"))?;
    context.may_publish = may_publish;
    context.undo_for = Some(short(command));
    let mut directories = request
        .discards
        .iter()
        .map(|discard| discard.directory.clone())
        .collect::<Vec<_>>();
    directories.sort();
    directories.dedup();
    for directory in directories {
        let (rewrites, discards): (Vec<_>, Vec<_>) = request
            .discards
            .iter()
            .filter(|discard| discard.directory == directory)
            .partition(|discard| matches!(discard.kind, DiscardKind::HistoryRewrite { .. }));
        let (commit_drops, discards): (Vec<_>, Vec<_>) =
            discards.into_iter().partition(|discard| {
                matches!(
                    discard.kind,
                    DiscardKind::StashDrop { .. } | DiscardKind::RefDelete
                )
            });
        let (ref_deletes, stash_drops): (Vec<_>, Vec<_>) = commit_drops
            .into_iter()
            .partition(|discard| discard.kind == DiscardKind::RefDelete);
        if !discards.is_empty() {
            let saved = if discards
                .iter()
                .all(|discard| matches!(discard.kind, DiscardKind::Delete { git: false, .. }))
            {
                save_folder(&context, &directory, &discards, deadline)
            } else {
                save(&context, &directory, &discards, deadline)
            };
            finish(rules(&discards), saved)?;
        }
        if !stash_drops.is_empty() {
            finish(
                rules(&stash_drops),
                save_stash(&context, &directory, &stash_drops, deadline),
            )?;
        }
        if !rewrites.is_empty() {
            finish(
                rules(&rewrites),
                save_rewrites(&context, &directory, &rewrites, deadline),
            )?;
        }
        if !ref_deletes.is_empty() {
            finish(
                rules(&ref_deletes),
                save_refs(&context, &directory, &ref_deletes, deadline),
            )?;
        }
    }
    Ok(())
}

/// What a discard reaches, by path relative to the work tree top.
enum Reach {
    All,
    /// These paths and what lies under them.
    Paths(BTreeSet<String>),
}

impl Reach {
    fn pathspecs(&self) -> Vec<&str> {
        match self {
            Reach::All => vec!["."],
            Reach::Paths(paths) => paths.iter().map(String::as_str).collect(),
        }
    }

    /// What `discard` reaches in the work tree `root`: git lists the files
    /// its pathspecs match now.
    fn of(
        context: &Context,
        root: &Path,
        discard: &Discard,
        latest: &Manifest,
        deadline: Instant,
    ) -> Result<Self, String> {
        // Git takes its pathspec modes from the environment and command
        // line of the agent's command; the save's own git inherits neither.
        let options = discard.pathspec_options.as_deref().unwrap_or_default();
        match &discard.selection {
            // A ref delete reaches no file.
            Selection::All | Selection::Refs(_) => Ok(Reach::All),
            _ if discard.pathspec_options.is_none() => Err(
                "nah cannot tell how git reads its pathspecs: a GIT_*_PATHSPECS variable has a value nah does not know".into(),
            ),
            Selection::Paths(_) if options.iter().any(|option| option == "--icase-pathspecs") => {
                Err("git matches its paths without regard to case (GIT_ICASE_PATHSPECS or --icase-pathspecs), so they may reach files nah does not list".into())
            }
            Selection::Paths(selections) => {
                let mut paths = BTreeSet::new();
                for selection in selections {
                    let selection = match discard.kind {
                        DiscardKind::Delete { .. } => entry_path(selection),
                        _ => fs::canonicalize(selection).unwrap_or_else(|_| selection.clone()),
                    };
                    if root.starts_with(&selection) {
                        return Ok(Reach::All);
                    }
                    // One outside the work tree, or under a name git cannot
                    // list, reaches nothing listed in it.
                    if let Some(path) = selection.strip_prefix(root).ok().and_then(Path::to_str) {
                        paths.insert(path.to_owned());
                    }
                }
                Ok(Reach::Paths(paths))
            }
            Selection::Pathspecs(pathspecs) => {
                if let Some(folder) = &discard.globbed_in {
                    let names = fs::read_dir(folder).map_err(|_| {
                        format!(
                            "nah could not read the names in {} that the shell expands its glob to",
                            folder.display()
                        )
                    })?;
                    if let Some(name) = names
                        .filter_map(Result::ok)
                        .map(|entry| entry.file_name())
                        .find(|name| name.as_encoded_bytes().starts_with(b":"))
                    {
                        return Err(format!(
                            "the shell may pass git `{}` from {}, which git reads as pathspec magic, so nah cannot tell which files it reaches",
                            name.to_string_lossy(),
                            folder.display()
                        ));
                    }
                }
                // The folders that hold untracked work, a repository of its
                // own or a submodule: one the pathspecs match by its own path
                // is reached whole.
                let folders = latest
                    .entries
                    .iter()
                    .filter(|entry| entry.origin == Origin::Untracked)
                    .map(|entry| entry.path.as_str())
                    .chain(
                        latest
                            .not_saved
                            .iter()
                            .filter(|left_out| {
                                untracked(left_out)
                                    || matches!(
                                        left_out.reason,
                                        NotSavedReason::NestedRepository
                                            | NotSavedReason::Submodule
                                    )
                            })
                            .map(|left_out| left_out.path.as_str()),
                    )
                    .flat_map(|path| {
                        let folder = path.ends_with('/').then(|| path.trim_end_matches('/'));
                        path.trim_end_matches('/')
                            .match_indices('/')
                            .map(move |(slash, _)| &path[..slash])
                            .chain(folder)
                    })
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let (_, files) = nah_snapshot::discard_reach::matching_files(
                    context,
                    &discard.directory,
                    pathspecs,
                    options,
                    &folders,
                    deadline,
                )
                .map_err(|refusal| {
                    format!("nah could not list what its pathspecs match: {refusal}")
                })?;
                Ok(Reach::Paths(
                    files
                        .into_iter()
                        .map(|path| path.trim_end_matches('/').to_owned())
                        .collect(),
                ))
            }
            Selection::Unknown(glob) => Err(format!(
                "nah cannot tell which files `{glob}` selects: git reads a name the shell expands it to that starts with `:` as pathspec magic"
            )),
        }
    }

    /// Whether it reaches `path`, relative to the top; a path ending in `/`
    /// is a folder.
    fn reaches(&self, path: &str) -> bool {
        let path = path.trim_end_matches('/');
        if self.includes(path) {
            return true;
        }
        let Reach::Paths(paths) = self else {
            return false;
        };
        paths
            .range::<str, _>((
                Bound::Included(format!("{path}/").as_str()),
                Bound::Unbounded,
            ))
            .next()
            .is_some_and(|under| within(under, path))
    }

    /// A path the selection includes, as opposed to its parent folder.
    fn includes(&self, path: &str) -> bool {
        let Reach::Paths(paths) = self else {
            return true;
        };
        path.match_indices('/')
            .map(|(slash, _)| &path[..slash])
            .chain([path])
            .any(|path| paths.contains(path))
    }
}

/// The snapshot of `directory`'s work tree that holds what `discards` would
/// destroy, saved now unless the latest one already does.
fn save(
    context: &Context,
    directory: &Path,
    discards: &[&Discard],
    deadline: Instant,
) -> Result<Saved, String> {
    let budget = Budget {
        bytes: nah_snapshot::DEFAULT_BUDGET_BYTES,
        deadline,
    };
    let refused = |refusal: Refusal| refusal.to_string();
    let (latest, how) =
        match nah_snapshot::unchanged(context, directory, deadline).map_err(refused)? {
            Some(latest) => (latest, "unchanged since nah's last check"),
            None => match nah_snapshot::fresh(context, directory, budget).map_err(refused)? {
                Freshness::Current { snapshot } => (snapshot, "already current"),
                Freshness::Saved { snapshot } => (snapshot, "saved now"),
            },
        };
    let root = PathBuf::from(&latest.root);
    // The skip list spares a folder's files a copy, never a repository of its
    // own inside one: an ignored folder hides it from status, so where a
    // discard may write over or clean away ignored work, git lists them.
    let mut latest = latest;
    if discards.iter().any(|discard| match discard.kind {
        DiscardKind::Clean { ignored, .. } => ignored,
        DiscardKind::Changes => !matches!(discard.writes, Writes::Current),
        DiscardKind::Delete { tracked_only, .. } => !tracked_only,
        DiscardKind::StashDrop { .. }
        | DiscardKind::RefDelete
        | DiscardKind::HistoryRewrite { .. } => false,
    }) {
        let folders = latest
            .not_saved
            .iter()
            .filter(|left_out| left_out.reason == NotSavedReason::SkipList)
            .map(|left_out| left_out.path.clone())
            .collect::<Vec<_>>();
        let found = nah_snapshot::discard_reach::nested_repositories(
            context, directory, &folders, deadline,
        )
        .map_err(|refusal| {
            format!(
                "nah could not tell whether {} holds a repository of its own: {refusal}",
                folders.join(", ")
            )
        })?;
        latest
            .not_saved
            .extend(found.into_iter().map(|path| NotSaved {
                path,
                reason: NotSavedReason::NestedRepository,
                origin: None,
            }));
    }
    let deletes = deleted_paths(&root, discards)?;
    let reaches = discards
        .iter()
        .map(|discard| Reach::of(context, &root, discard, &latest, deadline))
        .collect::<Result<Vec<_>, _>>()?;
    // A submodule keeps its own repository in its folder, or its work tree
    // there, which no snapshot of the superproject holds, clean or not.
    if !deletes.is_empty() {
        let at_risk = nah_snapshot::discard_reach::gitlinks(context, &root, deadline)
            .map_err(|refusal| refusal.to_string())?
            .into_iter()
            .filter(|path| {
                discards.iter().zip(&reaches).any(|(discard, reach)| {
                    matches!(discard.kind, DiscardKind::Delete { .. }) && reach.reaches(path)
                })
            })
            .map(|path| {
                describe(
                    &root,
                    &format!("{path}/"),
                    "a submodule, whose own repository and work tree nah does not save",
                )
            })
            .collect::<Vec<_>>();
        if !at_risk.is_empty() {
            return Err(at_risk.join("; "));
        }
    }
    let writes = overwritten(context, &root, discards, &reaches, &latest, deadline)?;
    let changed = changed_submodules(context, &root, discards, &reaches, &latest, deadline)?;
    let (at_risk, ignored) = destroyed(&root, discards, &reaches, &writes, &changed, &latest);
    let mut at_risk = at_risk;
    at_risk.extend(replaced_submodules(
        context, &root, discards, &reaches, deadline,
    )?);
    if !at_risk.is_empty() {
        return Err(at_risk.join("; "));
    }
    if ignored.is_empty() {
        return discard_note(context, latest, discards, &reaches, how, deadline);
    }
    // Ignored files, and those under a folder where a tracked file was, are
    // not part of the rolling copy: they are copied only now that a command
    // would destroy them.
    // Git lists an ignored folder as one entry, which may hold far more
    // than the discards reach.
    let reached = |path: &str| reaches.iter().any(|reach| reach.reaches(path));
    let (files, skipped) = ignored_files(&root, &ignored, &reached, deadline)?;
    // Git lists none of a skip-list folder's own repositories under an
    // ignored folder, so they are searched for here.
    let nested =
        nah_snapshot::discard_reach::nested_repositories(context, directory, &skipped, deadline)
            .map_err(|refusal| {
                format!(
                    "nah could not tell whether {} holds a repository of its own: {refusal}",
                    skipped.join(", ")
                )
            })?
            .into_iter()
            .filter(|path| reached(path))
            .map(|path| describe(&root, &path, "a repository of its own"))
            .collect::<Vec<_>>();
    if !nested.is_empty() {
        return Err(nested.join("; "));
    }
    let named = files.iter().map(|file| root.join(file)).collect::<Vec<_>>();
    let saved = nah_snapshot::save(context, directory, &named, budget).map_err(refused)?;
    let held = saved
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    // What the command would destroy now, against what the save holds: an
    // ignored folder stays listed after its files are saved, and a file may
    // have appeared in it meanwhile.
    let (mut missing, ignored) = destroyed(&root, discards, &reaches, &writes, &changed, &saved);
    for file in ignored_files(&root, &ignored, &reached, deadline)?.0 {
        if !held.contains(file.as_str()) {
            let secret = saved
                .not_saved
                .iter()
                .any(|left_out| left_out.path == file && left_out.reason == NotSavedReason::Secret);
            let why = if secret {
                "a secret file, which nah never copies"
            } else {
                "a file the save did not hold"
            };
            missing.push(describe(&root, &file, why));
        }
    }
    if !missing.is_empty() {
        return Err(missing.join("; "));
    }
    discard_note(
        context,
        saved,
        discards,
        &reaches,
        "saved now, with the untracked files it destroys",
        deadline,
    )
}

/// Record the version each path copy writes, independently of the rolling
/// snapshot. A later discard of the same path may write another version.
fn discard_note(
    context: &Context,
    mut snapshot: Manifest,
    discards: &[&Discard],
    reaches: &[Reach],
    how: &str,
    deadline: Instant,
) -> Result<Saved, String> {
    let root = PathBuf::from(&snapshot.root);
    let saved = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut results = BTreeMap::<String, DiscardResult>::new();
    let mut initial_index = BTreeMap::<String, Vec<Stage>>::new();
    let mut unknown = false;
    for (discard, reach) in discards.iter().zip(reaches) {
        // A recursive delete removes every tracked file it reaches and
        // leaves the index alone. Undo writes back a clean one from Git's
        // blob, which the snapshot refers to without copying.
        if matches!(discard.kind, DiscardKind::Delete { git: true, .. }) {
            let indexed = nah_snapshot::discard_reach::index_entries(
                context,
                &root,
                &reach.pathspecs(),
                deadline,
            )
            .map_err(|refusal| refusal.to_string())?;
            for path in indexed.keys() {
                results.insert(
                    path.clone(),
                    DiscardResult {
                        worktree: None,
                        index: None,
                    },
                );
            }
            initial_index.extend(indexed);
            continue;
        }
        if discard.kind != DiscardKind::Changes {
            continue;
        }
        match (discard.keeps_head, &discard.writes) {
            (true, Writes::Current) if discard.from_index => {
                // A previous copy may have staged a different blob or
                // changed only the worktree. Read the index that step left.
                for (path, result) in &mut results {
                    if reach.includes(path) {
                        let index = result
                            .index
                            .as_ref()
                            .or_else(|| initial_index.get(path))
                            .map_or(&[][..], Vec::as_slice);
                        match index {
                            [stage] if stage.stage == 0 => result.worktree = Some(stage.clone()),
                            [] if discard.source_no_overlay => result.worktree = None,
                            _ => {}
                        }
                    }
                }
            }
            (true, Writes::Tree(revision)) => {
                let paths = reach.pathspecs();
                let Some(blobs) = nah_snapshot::discard_reach::revision_blobs(
                    context, &root, revision, &paths, deadline,
                )
                .map_err(|refusal| refusal.to_string())?
                else {
                    unknown = true;
                    results.retain(|path, _| !reach.reaches(path));
                    continue;
                };
                let indexed =
                    nah_snapshot::discard_reach::index_entries(context, &root, &paths, deadline)
                        .map_err(|refusal| refusal.to_string())?;
                // An absent source deletes a selected index entry in
                // non-overlay mode. A file and a directory also cannot
                // occupy the same path in either mode.
                let replaced_by_file = |path: &str| {
                    let below = format!("{path}/");
                    path.match_indices('/')
                        .any(|(slash, _)| blobs.contains_key(&path[..slash]))
                        || blobs
                            .range(below.clone()..)
                            .next()
                            .is_some_and(|(path, _)| path.starts_with(&below))
                };
                let paths = blobs
                    .keys()
                    .chain(
                        indexed
                            .keys()
                            .filter(|path| discard.source_no_overlay || replaced_by_file(path)),
                    )
                    .chain(results.keys().filter(|path| {
                        reach.includes(path)
                            && (discard.source_no_overlay || replaced_by_file(path))
                    }))
                    .cloned()
                    .collect::<BTreeSet<_>>();
                for path in paths {
                    let worktree = blobs.get(&path);
                    if !saved.contains(path.as_str())
                        && !results.contains_key(&path)
                        && indexed
                            .get(&path)
                            .is_some_and(|index| index.iter().eq(worktree))
                    {
                        continue;
                    }
                    let result = results.entry(path).or_insert(DiscardResult {
                        worktree: None,
                        index: None,
                    });
                    if discard.writes_index {
                        result.index = Some(worktree.cloned().into_iter().collect());
                    }
                    result.worktree = worktree.cloned();
                }
                initial_index.extend(indexed);
            }
            _ => {
                unknown |= discard.keeps_head && discard.writes == Writes::Unknown;
                results.retain(|path, _| !reach.reaches(path));
            }
        }
    }
    if results.is_empty() {
        // The undo point is the rolling snapshot, which may have been saved
        // long ago; retention keeps it the full age from now.
        nah_snapshot::name_undo(context, &snapshot, deadline)
            .map_err(|refusal| refusal.to_string())?;
    } else {
        snapshot = nah_snapshot::save_discard(context, snapshot, results, initial_index, deadline)
            .map_err(|refusal| refusal.to_string())?;
    }
    // A delete runs only once the snapshot holds every path it reaches, but
    // what skip-list folders hold, which tools rebuild: a secret file among
    // them, clean or not, is never copied. Ignored files were checked
    // against the save that copied them.
    let held = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let left_out = snapshot
        .not_saved
        .iter()
        .filter(|left_out| {
            !matches!(
                left_out.reason,
                NotSavedReason::SkipList | NotSavedReason::Ignored
            ) && !held.contains(left_out.path.as_str())
                && discards.iter().zip(reaches).any(|(discard, reach)| {
                    let taken = match discard.kind {
                        DiscardKind::Delete { tracked_only, .. } => {
                            !tracked_only || left_out.origin == Some(Origin::Tracked)
                        }
                        _ => false,
                    };
                    taken && reach.reaches(&left_out.path)
                })
        })
        .map(|left_out| {
            let why = if left_out.reason == NotSavedReason::Secret {
                "a secret file, which nah never copies"
            } else {
                "a file the save did not hold"
            };
            describe(&root, &left_out.path, why)
        })
        .collect::<Vec<_>>();
    if !left_out.is_empty() {
        return Err(left_out.join("; "));
    }
    Ok(note(&snapshot, how, &root, unknown))
}

/// `path` with its folder resolved and its own name kept, as a delete takes
/// it: a link is deleted as the link, not what it leads to. On a filesystem
/// that ignores case, the name is spelled as the folder lists it, since Git
/// matches it by case.
fn entry_path(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
            let listed = fs::symlink_metadata(parent.join(name))
                .ok()
                .and_then(|_| fs::read_dir(&parent).ok())
                .and_then(|entries| {
                    let entries = entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.file_name())
                        .collect::<Vec<_>>();
                    (!entries.iter().any(|entry| entry == name))
                        .then(|| {
                            entries.into_iter().find(|entry| {
                                entry
                                    .as_encoded_bytes()
                                    .eq_ignore_ascii_case(name.as_encoded_bytes())
                            })
                        })
                        .flatten()
                });
            parent.join(listed.as_deref().unwrap_or(name))
        }
        _ => path.to_path_buf(),
    }
}

/// The paths the deletes among `discards` take, relative to `root`, the
/// work tree top or project folder. A delete of the folder itself, or in a
/// work tree of its `.git` folder, takes what no snapshot holds: the
/// repository's history, and the folder `nah undo` runs in.
fn deleted_paths(root: &Path, discards: &[&Discard]) -> Result<Vec<String>, String> {
    let mut deleted = Vec::new();
    for discard in discards {
        let (DiscardKind::Delete { git, .. }, Selection::Paths(paths)) =
            (discard.kind, &discard.selection)
        else {
            continue;
        };
        for path in paths {
            let path = entry_path(path);
            if root.starts_with(&path) {
                return Err(format!(
                    "it deletes the project folder {} itself{}",
                    root.display(),
                    if git {
                        ", with the repository's history in .git, which nah cannot save"
                    } else {
                        ", where `nah undo` would run"
                    }
                ));
            }
            let Some(relative) = path.strip_prefix(root).ok().and_then(Path::to_str) else {
                return Err(format!(
                    "{} lies outside the project folder",
                    path.display()
                ));
            };
            if git && within(relative, ".git") {
                return Err(format!(
                    "it deletes {relative}, the repository's own folder, whose history nah cannot save"
                ));
            }
            // Git and the folder copy both match names by their bytes.
            if !nah_observe::spelled_as_listed(root, &path) {
                return Err(format!(
                    "{relative} is not spelled as its folder lists it, so nah cannot tell which files it reaches"
                ));
            }
            deleted.push(relative.to_owned());
        }
    }
    Ok(deleted)
}

/// The snapshot of the project folder `directory`, no git work tree, that
/// holds every file the deletes `discards` take, saved now within the
/// budget: secret files, which nah never copies, and repositories of their
/// own block, and folders tools rebuild are left to the delete.
fn save_folder(
    context: &Context,
    directory: &Path,
    discards: &[&Discard],
    deadline: Instant,
) -> Result<Saved, String> {
    let root = fs::canonicalize(directory)
        .map_err(|error| format!("{} cannot be read: {error}", directory.display()))?;
    let subtrees = deleted_paths(&root, discards)?;
    let budget = Budget {
        bytes: nah_snapshot::DEFAULT_BUDGET_BYTES,
        deadline,
    };
    let saved = nah_snapshot::save_folder(context, &root, &subtrees, budget)
        .map_err(|refusal| refusal.to_string())?;
    let at_risk = saved
        .not_saved
        .iter()
        .filter_map(|left_out| match left_out.reason {
            NotSavedReason::Secret => Some(describe(
                &root,
                &left_out.path,
                "a secret file, which nah never copies",
            )),
            NotSavedReason::NestedRepository => {
                Some(describe(&root, &left_out.path, "a repository of its own"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if !at_risk.is_empty() {
        return Err(at_risk.join("; "));
    }
    Ok(note(&saved, "saved now", &root, false))
}

/// The snapshot of the commits that `stash_drops`, drops of the stash of
/// `directory`'s repository, would leave no ref reaching.
fn save_stash(
    context: &Context,
    directory: &Path,
    stash_drops: &[&Discard],
    deadline: Instant,
) -> Result<Saved, String> {
    let dropped = match stash_drops {
        [
            Discard {
                kind: DiscardKind::StashDrop { entry: Some(entry) },
                ..
            },
        ] => Deleting::StashEntry(*entry),
        // A later drop takes an entry an earlier one moved up.
        _ => Deleting::Stash,
    };
    let budget = Budget {
        bytes: nah_snapshot::DEFAULT_BUDGET_BYTES,
        deadline,
    };
    let saved = nah_snapshot::save_commits(context, directory, &[dropped], budget)
        .map_err(|refusal| refusal.to_string())?;
    let commits = saved.commits.as_ref().map_or(0, |commits| commits.count);
    let entries = saved
        .commits
        .as_ref()
        .map_or(0, |commits| commits.refs.len());
    let (id, root) = (&saved.id, &saved.root);
    let holds = format!(
        "{entries} stash {}, {commits} {}",
        if entries == 1 { "entry" } else { "entries" },
        if commits == 1 { "commit" } else { "commits" },
    );
    Ok(Saved {
        note: format!(
            "snapshot {id} of {root} holds {holds} only {} reached. Undo with: nah undo {id} (run in {root}); `nah snapshots` lists every snapshot",
            if entries == 1 { "it" } else { "they" },
        ),
        ..commits_saved(id, root, holds)
    })
}

/// A snapshot of commits, which `nah undo` brings back in place, before
/// `save_all` names its rules.
fn commits_saved(id: &str, root: &str, holds: String) -> Saved {
    Saved {
        rules: Vec::new(),
        snapshot: id.to_owned(),
        root: root.to_owned(),
        holds,
        apart: false,
        note: String::new(),
    }
}

/// The snapshot of the commits that `rewrites`, rewrites of the history of
/// `directory`'s repository, may leave no ref or reflog reaching.
fn save_rewrites(
    context: &Context,
    directory: &Path,
    rewrites: &[&Discard],
    deadline: Instant,
) -> Result<Saved, String> {
    let mut moved = rewrites
        .iter()
        .filter_map(|discard| match discard.kind {
            DiscardKind::HistoryRewrite { moves } => Some(match moves {
                Moves::Branches => Deleting::Branches,
                Moves::Backups => Deleting::Backups,
                Moves::History => Deleting::History,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    moved.dedup();
    let budget = Budget {
        bytes: nah_snapshot::DEFAULT_BUDGET_BYTES,
        deadline,
    };
    let saved = nah_snapshot::save_commits(context, directory, &moved, budget)
        .map_err(|refusal| refusal.to_string())?;
    let commits = saved.commits.as_ref().map_or(0, |commits| commits.count);
    let (id, root) = (&saved.id, &saved.root);
    let holds = format!(
        "{commits} {}",
        if commits == 1 { "commit" } else { "commits" }
    );
    Ok(Saved {
        note: format!(
            "snapshot {id} of {root} holds the {holds} it could leave unreached. Undo with: nah undo {id} (run in {root}), which brings them back under refs/nah/{id}/ and moves no branch; `nah snapshots` lists every snapshot",
        ),
        ..commits_saved(id, root, holds)
    })
}

/// The snapshot of the commits that `ref_deletes`, deletes of local refs in
/// `directory`'s repository, would leave no other ref reaching, with each
/// deleted ref.
fn save_refs(
    context: &Context,
    directory: &Path,
    ref_deletes: &[&Discard],
    deadline: Instant,
) -> Result<Saved, String> {
    let deleting = ref_deletes
        .iter()
        .flat_map(|discard| match &discard.selection {
            Selection::Refs(deleted) => deleted.clone(),
            _ => Vec::new(),
        })
        .map(|deleted| match deleted {
            RefDeletion::Ref(name) => Deleting::Ref(name),
            RefDeletion::Itself(name) => Deleting::Itself(name),
            RefDeletion::Remote(remote) => Deleting::Remote(remote),
        })
        .collect::<Vec<_>>();
    let budget = Budget {
        bytes: nah_snapshot::DEFAULT_BUDGET_BYTES,
        deadline,
    };
    let saved = nah_snapshot::save_commits(context, directory, &deleting, budget)
        .map_err(|refusal| refusal.to_string())?;
    let commits = saved.commits.as_ref().map_or(0, |commits| commits.count);
    let refs = saved
        .commits
        .as_ref()
        .map(|commits| {
            commits
                .refs
                .iter()
                .map(|saved| saved.name.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let (id, root) = (&saved.id, &saved.root);
    let commits = format!(
        "{commits} {}",
        if commits == 1 { "commit" } else { "commits" }
    );
    Ok(Saved {
        note: format!(
            "snapshot {id} of {root} holds {} and the {commits} only {} reached. Undo with: nah undo {id} (run in {root}); `nah snapshots` lists every snapshot",
            if refs.is_empty() {
                "no ref".to_owned()
            } else {
                refs.join(", ")
            },
            if refs.len() == 1 { "it" } else { "they" },
        ),
        ..commits_saved(
            id,
            root,
            format!(
                "{} {}, {commits}",
                refs.len(),
                if refs.len() == 1 { "ref" } else { "refs" }
            ),
        )
    })
}

/// Which untracked and ignored files a discard writes over, by the tree it
/// copies from: those the rolling copy left out, and for a discard that
/// keeps HEAD, those it holds too.
enum Overwrites {
    None,
    /// Those at or above the files its tree tracks, relative to the work
    /// tree.
    Files(BTreeSet<String>),
    /// Any of them: the tree is not known before the command runs.
    All,
}

/// For each of `discards`, what it writes over among the untracked files and
/// nested repositories of `latest`.
fn overwritten(
    context: &Context,
    root: &Path,
    discards: &[&Discard],
    reaches: &[Reach],
    latest: &Manifest,
    deadline: Instant,
) -> Result<Vec<Overwrites>, String> {
    discards
        .iter()
        .zip(reaches)
        .map(|(discard, reach)| {
            let revision = match &discard.writes {
                _ if discard.kind != DiscardKind::Changes => return Ok(Overwrites::None),
                Writes::Current => return Ok(Overwrites::None),
                Writes::Unknown => return Ok(Overwrites::All),
                Writes::Tree(revision) => revision,
            };
            let candidates = latest
                .not_saved
                .iter()
                .filter(|left_out| {
                    untracked(left_out) || left_out.reason == NotSavedReason::NestedRepository
                })
                .map(|left_out| &left_out.path)
                .chain(
                    latest
                        .entries
                        .iter()
                        .filter(|entry| discard.keeps_head && entry.origin == Origin::Untracked)
                        .map(|entry| &entry.path),
                )
                .filter(|path| reach.reaches(path))
                .cloned()
                .collect::<Vec<_>>();
            Ok(
                match nah_snapshot::discard_reach::tracked_by(
                    context,
                    root,
                    revision,
                    &candidates,
                    deadline,
                )
                .map_err(|refusal| refusal.to_string())?
                {
                    Some(files) => Overwrites::Files(files),
                    None => Overwrites::All,
                },
            )
        })
        .collect()
}

/// Whether a file the rolling copy left out is untracked or ignored, the
/// kind a checkout of another tree can write over.
fn untracked(left_out: &NotSaved) -> bool {
    match left_out.reason {
        NotSavedReason::Secret => left_out.origin != Some(Origin::Tracked),
        NotSavedReason::Ignored => true,
        _ => false,
    }
}

/// The submodules of `latest` a discard of tracked changes reaches whose own
/// work tree holds changes. Nah cannot tell whether the discard recurses
/// into submodules, by `--recurse-submodules` or `submodule.recurse`, and
/// discards those changes too.
fn changed_submodules(
    context: &Context,
    root: &Path,
    discards: &[&Discard],
    reaches: &[Reach],
    latest: &Manifest,
    deadline: Instant,
) -> Result<BTreeSet<String>, String> {
    let mut changed = BTreeSet::new();
    for left_out in &latest.not_saved {
        let reached = discards.iter().zip(reaches).any(|(discard, reach)| {
            discard.kind == DiscardKind::Changes && reach.reaches(&left_out.path)
        });
        if left_out.reason == NotSavedReason::Submodule
            && reached
            && nah_snapshot::discard_reach::submodule_changed(
                context,
                root,
                &left_out.path,
                deadline,
            )
            .map_err(|refusal| refusal.to_string())?
        {
            changed.insert(left_out.path.clone());
        }
    }
    Ok(changed)
}

/// Why `discards` would destroy a submodule's history: a discard copying
/// from another tree that tracks a file where the submodule stands replaces
/// its folder, `.git` folder and all when the submodule keeps its repository
/// there rather than under the superproject's `.git/modules`. Every gitlink
/// of the index counts, listed in `.gitmodules` or not; clean ones are in no
/// snapshot's list.
fn replaced_submodules(
    context: &Context,
    root: &Path,
    discards: &[&Discard],
    reaches: &[Reach],
    deadline: Instant,
) -> Result<Vec<String>, String> {
    let copying = discards
        .iter()
        .zip(reaches)
        .filter_map(|(discard, reach)| match &discard.writes {
            _ if discard.kind != DiscardKind::Changes => None,
            Writes::Tree(revision) => Some((Some(revision), reach)),
            // Another step moves the ref it lands on, or a pathspec copy
            // names no tree Nah reads: any tree may hold a file there.
            Writes::Unknown => Some((None, reach)),
            Writes::Current => None,
        })
        .collect::<Vec<_>>();
    if copying.is_empty() {
        return Ok(Vec::new());
    }
    let mut replaced = Vec::new();
    for path in nah_snapshot::discard_reach::gitlinks(context, root, deadline)
        .map_err(|refusal| refusal.to_string())?
    {
        let own_repository =
            fs::symlink_metadata(root.join(&path).join(".git")).is_ok_and(|found| found.is_dir());
        if !own_repository {
            continue;
        }
        for (revision, reach) in &copying {
            if !reach.reaches(&path) {
                continue;
            }
            let why = match revision {
                Some(revision) => {
                    if !nah_snapshot::discard_reach::replaces_submodule(context, root, revision, &path, deadline)
                        .map_err(|refusal| refusal.to_string())?
                    {
                        continue;
                    }
                    format!(
                        "a submodule that keeps its repository in its own folder, which `{revision}` writes a file over"
                    )
                }
                None => "a submodule that keeps its repository in its own folder, which the tree the command writes, one nah cannot name before it runs, may write a file over".to_owned(),
            };
            replaced.push(describe(root, &format!("{path}/"), &why));
            break;
        }
    }
    Ok(replaced)
}

/// What `discards` destroy that `manifest` does not hold: the reasons to
/// block, and the files and folders to copy first. `changed` names the
/// submodules whose own work tree holds changes.
fn destroyed(
    root: &Path,
    discards: &[&Discard],
    reaches: &[Reach],
    writes: &[Overwrites],
    changed: &BTreeSet<String>,
    manifest: &Manifest,
) -> (Vec<String>, Vec<String>) {
    let mut at_risk = Vec::new();
    let mut ignored = BTreeSet::new();
    for left_out in &manifest.not_saved {
        let path = left_out.path.as_str();
        let reached = discards
            .iter()
            .zip(reaches)
            .zip(writes)
            .any(|((discard, reach), writes)| {
                reach.reaches(path)
                    && match (discard.kind, left_out.reason, left_out.origin) {
                        (DiscardKind::Changes, NotSavedReason::Secret, Some(Origin::Tracked)) => {
                            true
                        }
                        (DiscardKind::Changes, ..) if untracked(left_out) => writes.over(path),
                        // A tree that tracks a file there writes it over the
                        // repository, history and all.
                        (DiscardKind::Changes, NotSavedReason::NestedRepository, _) => {
                            writes.over(path)
                        }
                        // A tree lists a submodule by its commit, which a
                        // discard of the superproject's changes stages
                        // without touching its work tree, unless it recurses
                        // into it, or writes there from a tree Nah cannot
                        // name.
                        (DiscardKind::Changes, NotSavedReason::Submodule, _) => {
                            changed.contains(path) || matches!(writes, Overwrites::All)
                        }
                        (
                            DiscardKind::Clean {
                                ignored_only: false,
                                ..
                            },
                            NotSavedReason::Secret,
                            Some(Origin::Untracked),
                        )
                        | (
                            DiscardKind::Clean {
                                ignored_only: false,
                                ..
                            },
                            NotSavedReason::NestedRepository,
                            _,
                        )
                        // One inside an ignored folder is cleaned with it.
                        | (
                            DiscardKind::Clean { ignored: true, .. },
                            NotSavedReason::NestedRepository,
                            _,
                        ) => true,
                        (
                            DiscardKind::Clean { ignored: true, .. },
                            NotSavedReason::Secret | NotSavedReason::Ignored,
                            None,
                        ) => true,
                        // A delete takes everything under its paths but the
                        // folders tools rebuild, which no copy holds; a
                        // forced `git rm` only the tracked files, and a
                        // submodule's work tree with its gitlink.
                        (
                            DiscardKind::Delete {
                                tracked_only: false,
                                ..
                            },
                            NotSavedReason::Secret
                            | NotSavedReason::Ignored
                            | NotSavedReason::NestedRepository
                            | NotSavedReason::Submodule,
                            _,
                        )
                        | (
                            DiscardKind::Delete {
                                tracked_only: true,
                                ..
                            },
                            NotSavedReason::Secret,
                            Some(Origin::Tracked),
                        )
                        | (
                            DiscardKind::Delete {
                                tracked_only: true,
                                ..
                            },
                            NotSavedReason::Submodule,
                            _,
                        ) => true,
                        _ => false,
                    }
            });
        if !reached {
            continue;
        }
        match left_out.reason {
            NotSavedReason::Secret => at_risk.push(describe(
                root,
                path,
                "a secret file, which nah never copies",
            )),
            // `git clean -ff` deletes a repository inside the project, which
            // a snapshot does not hold.
            NotSavedReason::NestedRepository => {
                at_risk.push(describe(root, path, "a repository of its own"));
            }
            NotSavedReason::Submodule => at_risk.push(describe(
                root,
                path,
                "a submodule, whose own work tree nah does not save",
            )),
            _ if kept_over(discards, reaches, writes, path) => {
                at_risk.push(describe(root, path, KEPT_OVER));
            }
            _ => {
                ignored.insert(path.to_owned());
            }
        }
    }
    for entry in &manifest.entries {
        if entry.origin == Origin::Untracked && kept_over(discards, reaches, writes, &entry.path) {
            at_risk.push(describe(root, &entry.path, KEPT_OVER));
        }
    }
    // A folder standing where a tracked file was: git status shows none of
    // its files, and a discard that writes the file back deletes them all.
    for entry in &manifest.entries {
        if (entry.head.is_some() || !entry.index.is_empty())
            && fs::symlink_metadata(root.join(&entry.path)).is_ok_and(|found| found.is_dir())
            && discards.iter().zip(reaches).any(|(discard, reach)| {
                discard.kind == DiscardKind::Changes && reach.reaches(&entry.path)
            })
        {
            ignored.insert(format!("{}/", entry.path));
        }
    }
    (at_risk, ignored.into_iter().collect())
}

/// Why an untracked file a discard that keeps HEAD writes over blocks it.
const KEPT_OVER: &str = "an untracked path a revision copy may replace";

/// Whether a discard of tracked changes that keeps HEAD writes over the
/// untracked `path`, which a path discard does not cover.
fn kept_over(discards: &[&Discard], reaches: &[Reach], writes: &[Overwrites], path: &str) -> bool {
    discards
        .iter()
        .zip(reaches)
        .zip(writes)
        .any(|((discard, reach), writes)| {
            discard.kind == DiscardKind::Changes
                && discard.keeps_head
                && reach.reaches(path)
                && writes.over(path)
        })
}

impl Overwrites {
    /// Whether it writes over the untracked `path`: something at the path,
    /// under it or on its way, which git writes in place of the whole entry.
    fn over(&self, path: &str) -> bool {
        match self {
            Overwrites::None => false,
            Overwrites::All => true,
            // Folded, as `tracked_by` matched them.
            Overwrites::Files(files) => {
                let entry = nah_snapshot::discard_reach::folded_path(path.trim_end_matches('/'));
                files.iter().any(|file| {
                    let file = nah_snapshot::discard_reach::folded_path(file);
                    within(&file, &entry) || within(&entry, &file)
                })
            }
        }
    }
}

/// Whether `path` is `folder` or lies under it.
fn within(path: &str, folder: &str) -> bool {
    path.strip_prefix(folder)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Every file of the ignored entries `ignored` (files, and folders ending in
/// `/`) relative to `root` that is `reached`, each and all within the caps
/// for copying them, and the reached skip-list folders among them, which
/// are not copied.
fn ignored_files(
    root: &Path,
    ignored: &[String],
    reached: &dyn Fn(&str) -> bool,
    deadline: Instant,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;
    let mut pending = ignored.to_vec();
    while let Some(path) = pending.pop() {
        if Instant::now() >= deadline {
            return Err(format!(
                "listing the ignored files took longer than allowed (at {path})"
            ));
        }
        let absolute = root.join(path.trim_end_matches('/'));
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("{path} cannot be read: {error}"))?;
        if metadata.is_dir() {
            let folder = path.trim_end_matches('/');
            let entries = fs::read_dir(&absolute)
                .map_err(|error| format!("{path} cannot be read: {error}"))?;
            for entry in entries {
                let entry = entry.map_err(|error| format!("{path} cannot be read: {error}"))?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    return Err(format!("{path} holds a name that is not UTF-8"));
                };
                // A repository inside keeps history that a copy of its files
                // does not hold.
                if name == ".git" {
                    return Err(describe(
                        root,
                        &path,
                        "a repository of its own, whose history nah cannot save",
                    ));
                }
                let path = format!("{folder}/{name}");
                if !reached(&path) {
                    continue;
                }
                // Dependency and build output can be regenerated.
                if nah_snapshot::SKIP_LIST.contains(&name.as_str()) {
                    skipped.push(path);
                } else {
                    pending.push(path);
                }
            }
            continue;
        }
        if !metadata.is_file() && !metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.len() > IGNORED_FILE_BYTES {
            return Err(describe(
                root,
                &path,
                "an ignored file over the 1 MB nah copies of one",
            ));
        }
        total += metadata.len();
        if total > IGNORED_TOTAL_BYTES {
            return Err(format!(
                "ignored files totalling over {} MB, the most nah copies",
                IGNORED_TOTAL_BYTES / (1024 * 1024)
            ));
        }
        files.push(path);
    }
    files.sort();
    Ok((files, skipped))
}

/// `path` with what it is and its size.
fn describe(root: &Path, path: &str, what: &str) -> String {
    let size = match fs::symlink_metadata(root.join(path.trim_end_matches('/'))) {
        Ok(metadata) if metadata.is_dir() => "a folder".to_owned(),
        Ok(metadata) => size(metadata.len()),
        Err(_) => "size unknown".to_owned(),
    };
    format!("{path} ({what}, {size})")
}

fn size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.1} KB", bytes as f64 / 1_000.0),
        _ => format!("{:.1} MB", bytes as f64 / 1_000_000.0),
    }
}

/// `snapshot` before `save_all` names its rules, and what the agent is told
/// about it: its id, what it holds, and how to restore it. A path copy whose
/// source tree is unknown is restored into a separate folder because undo
/// cannot identify the copied versions.
fn note(snapshot: &Manifest, how: &str, root: &Path, unknown: bool) -> Saved {
    let summary = &snapshot.summary;
    let mut paths = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .take(5)
        .collect::<Vec<_>>()
        .join(", ");
    if snapshot.entries.len() > 5 {
        paths.push_str(&format!(" and {} more", snapshot.entries.len() - 5));
    }
    let lines = summary
        .lines_changed
        .map_or_else(String::new, |lines| format!(", {lines} lines"));
    let (holds, listed) = if snapshot.entries.is_empty() {
        ("no unsaved work".to_owned(), String::new())
    } else {
        (
            format!(
                "{} {}{lines}",
                summary.files,
                if summary.files == 1 { "file" } else { "files" }
            ),
            format!(": {paths}"),
        )
    };
    let (id, root) = (&snapshot.id, root.display());
    let undo = if unknown {
        format!(
            "Nah could not identify the source tree, so recover the saved versions with: nah undo {id} --into DIR (run in {root}; DIR a new empty folder, with staged versions under DIR/.nah-index), then copy them back"
        )
    } else {
        format!("Undo with: nah undo {id} (run in {root})")
    };
    Saved {
        rules: Vec::new(),
        snapshot: id.clone(),
        root: root.to_string(),
        note: format!(
            "snapshot {id} of {root} ({how}) holds {holds}{listed}. {undo}; `nah snapshots` lists every snapshot"
        ),
        holds,
        apart: unknown,
    }
}

/// The first line of `command`, cut to 120 characters, as a note quotes it.
pub(super) fn short(command: &str) -> String {
    let line = command.lines().next().unwrap_or_default();
    if line.chars().count() > 120 || command.lines().nth(1).is_some() {
        format!("{}…", line.chars().take(120).collect::<String>())
    } else {
        line.to_owned()
    }
}
