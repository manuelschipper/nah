//! Snapshots of commits. Before a command deletes refs or stash entries, or
//! rewrites history, the commits only they reach are copied from the
//! project's object store into the store; an undo copies them back and
//! recreates what is missing, a ref the command moved under a recovery ref.

use crate::git::{self, GitFailure};
use crate::manifest::{
    Commits, Listed, MANIFEST_FORMAT, Manifest, SavedRef, StashEntry, Summary, Undoing, Written,
};
use crate::store::{Store, now_ns};
use crate::undo::{Conflict, UndoOutcome};
use crate::work_tree::Repository;
use crate::{Budget, Context, Project, Refusal, locate, store};
use nah_observe::ListedRef;
use nah_proto::observation::{ObservationFailure, RefDeletion};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// The ref git keeps the stash in: its reflog lists the entries.
const STASH: &str = "refs/stash";

/// The object name git reads as "no such ref" in a conditional update.
const NO_OBJECT: &str = "0000000000000000000000000000000000000000";

/// How long an undo may spend copying commits back and writing refs once
/// the state before it is saved.
const RESTORE_TIME: Duration = Duration::from_secs(3600);

/// What a command is about to delete, or move from the commits it names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Deleting {
    /// A ref, by its full name, such as `refs/heads/topic`, or `HEAD`: a
    /// symbolic one stands for the ref it names.
    Ref(String),
    /// A ref by its full name, itself even when symbolic, as `git branch
    /// -d` deletes one.
    Itself(String),
    /// The remote-tracking refs `git remote remove <name>` deletes.
    Remote(String),
    /// The stash entry `stash@{n}`.
    StashEntry(usize),
    /// Every stash entry.
    Stash,
    /// `HEAD` and every local branch, which a rebase, an amend or a reset
    /// may move: which branches a rebase moves Nah does not tell.
    Branches,
    /// Every ref under `refs/original/`, the backup an earlier
    /// `git filter-branch` left, which a forced one overwrites.
    Backups,
    /// Every ref, `HEAD`, and every commit a reflog records: `git
    /// filter-repo` expires the reflogs and may leave any of them unreached.
    History,
}

/// Where an undo recreates a ref the command moved, beside the ref itself:
/// `refs/nah/<snapshot>/` and its name below `refs/`, such as
/// `refs/nah/<snapshot>/heads/main`, or `HEAD`, or `reflog/<commit>` for a
/// commit only a reflog recorded.
pub(crate) fn recovery_ref(snapshot: &str, name: &str) -> String {
    format!(
        "refs/nah/{snapshot}/{}",
        name.strip_prefix("refs/").unwrap_or(name)
    )
}

/// Saves the commits that what `deleting` names reaches in the repository
/// holding `project` and that no ref the command keeps reaches, with what
/// each ref or stash entry was, as a new snapshot. A ref or entry that does
/// not exist is not saved; refs Nah cannot tell are refused. It writes
/// nothing to the repository.
pub fn save_commits(
    context: &Context,
    project: &Path,
    deleting: &[Deleting],
    budget: Budget,
) -> Result<Manifest, Refusal> {
    let project = locate(context, project, budget.deadline)?;
    let repository = in_repository(&project)?;
    let store = store::open(&context.snapshots_dir, &project.id, budget.deadline)?;
    let found = Refs::read(context, repository, budget.deadline)?;
    save(
        context, &store, &project, repository, &found, deleting, None, None, &budget,
    )
}

fn in_repository(project: &Project) -> Result<&Repository, Refusal> {
    project
        .repository
        .as_ref()
        .ok_or_else(|| Refusal::RepositoryUnreadable {
            detail: format!("{} is not in a git work tree", project.root.display()),
        })
}

/// The refs and stash entries of a repository.
struct Refs {
    /// Every ref but the stash and the symbolic ones, by full name, with the
    /// object it names.
    refs: Vec<(String, String)>,
    /// Every ref, symbolic ones and the stash included.
    listed: Vec<ListedRef>,
    /// HEAD's commit, `None` on an unborn branch.
    head: Option<String>,
    /// The branch a symbolic HEAD names, `None` for a detached one.
    head_ref: Option<String>,
    /// The commit `refs/stash` names, `None` when there is no stash.
    stash_tip: Option<String>,
    /// The stash entries, newest first.
    stash: Vec<Listed>,
}

impl Refs {
    fn read(
        context: &Context,
        repository: &Repository,
        deadline: Instant,
    ) -> Result<Self, Refusal> {
        let mut command = project_git(context, repository);
        command.args([
            "for-each-ref",
            "--format=%(objectname) %(refname) %(symref)",
        ]);
        let found = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
        let mut refs = Vec::new();
        let mut listed = Vec::new();
        let mut stash_tip = None;
        for line in String::from_utf8_lossy(&found).lines() {
            // A ref name holds no space.
            let [oid, name, symref] = line.splitn(3, ' ').collect::<Vec<_>>()[..] else {
                continue;
            };
            listed.push(ListedRef {
                name: name.to_owned(),
                oid: oid.to_owned(),
                symref: (!symref.is_empty()).then(|| symref.to_owned()),
            });
            if !symref.is_empty() {
                continue;
            }
            if name == STASH {
                stash_tip = Some(oid.to_owned());
            } else {
                refs.push((name.to_owned(), oid.to_owned()));
            }
        }
        let mut command = project_git(context, repository);
        command.args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]);
        let head = match git::output(command, Vec::new(), deadline) {
            Ok(head) => Some(String::from_utf8_lossy(&head).trim().to_owned()),
            Err(GitFailure::Deadline) => return Err(Refusal::OverDeadline),
            Err(GitFailure::Failed(_)) => None,
        };
        let mut command = project_git(context, repository);
        command.args(["symbolic-ref", "-q", "HEAD"]);
        let head_ref = match git::output(command, Vec::new(), deadline) {
            Ok(name) => Some(String::from_utf8_lossy(&name).trim().to_owned()),
            Err(GitFailure::Deadline) => return Err(Refusal::OverDeadline),
            Err(GitFailure::Failed(_)) => None,
        };
        let mut stash = Vec::new();
        if stash_tip.is_some() {
            let mut command = project_git(context, repository);
            command.args([
                "log",
                "--walk-reflogs",
                "--no-show-signature",
                "--date=raw",
                "--format=%H%x00%gn%x00%ge%x00%gd%x00%gs",
                STASH,
                "--",
            ]);
            let listed =
                git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
            // Git writes a reflog message on one line.
            for record in String::from_utf8_lossy(&listed).lines() {
                let fields = record.splitn(5, '\0').collect::<Vec<_>>();
                let [oid, name, email, selector, message] = fields[..] else {
                    continue;
                };
                // The selector is `stash@{<seconds> <zone>}` under `--date=raw`.
                let Some(date) = selector
                    .split_once("@{")
                    .and_then(|(_, date)| date.strip_suffix('}'))
                else {
                    continue;
                };
                stash.push(Listed {
                    oid: oid.to_owned(),
                    message: message.to_owned(),
                    name: name.to_owned(),
                    email: email.to_owned(),
                    date: date.to_owned(),
                });
            }
        }
        Ok(Refs {
            refs,
            listed,
            head,
            head_ref,
            stash_tip,
            stash,
        })
    }

    /// The object the ref `name` names; for `refs/stash`, its tip.
    fn named(&self, name: &str) -> Option<&str> {
        if name == STASH {
            return self.stash_tip.as_deref();
        }
        self.refs
            .iter()
            .find(|(listed, _)| listed == name)
            .map(|(_, oid)| oid.as_str())
    }

    /// Every commit a ref, HEAD or a stash entry names.
    fn tips(&self) -> BTreeSet<&str> {
        self.refs
            .iter()
            .map(|(_, oid)| oid.as_str())
            .chain(self.head.as_deref())
            .chain(self.stash_tip.as_deref())
            .chain(self.stash.iter().map(|entry| entry.oid.as_str()))
            .collect()
    }
}

/// Saves what `deleting` names among the refs `found` read from
/// `repository` into `store`, as the snapshot an undo of `undo_of` saves
/// before it writes what `undoing` says, when given.
#[allow(clippy::too_many_arguments)]
fn save(
    context: &Context,
    store: &Store,
    project: &Project,
    repository: &Repository,
    found: &Refs,
    deleting: &[Deleting],
    undo_of: Option<String>,
    undoing: Option<Undoing>,
    budget: &Budget,
) -> Result<Manifest, Refusal> {
    let started_ns = now_ns();
    let mut refs = Vec::new();
    let plain = |refs: &mut Vec<SavedRef>, name: &str| {
        if let Some(oid) = found.named(name)
            && !refs.iter().any(|saved: &SavedRef| saved.name == name)
        {
            refs.push(SavedRef {
                name: name.to_owned(),
                oid: oid.to_owned(),
                stash: None,
                moved: false,
            });
        }
    };
    let moved = |refs: &mut Vec<SavedRef>, name: &str, oid: &str| {
        if !refs.iter().any(|saved: &SavedRef| saved.name == name) {
            refs.push(SavedRef {
                name: name.to_owned(),
                oid: oid.to_owned(),
                stash: None,
                moved: true,
            });
        }
    };
    let deleted_refs = deleting
        .iter()
        .filter_map(|deleted| match deleted {
            Deleting::Ref(name) => Some(RefDeletion::Ref(name.clone())),
            Deleting::Itself(name) => Some(RefDeletion::Itself(name.clone())),
            Deleting::Remote(remote) => Some(RefDeletion::Remote(remote.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut fetch_refspecs = BTreeMap::new();
    for deletion in &deleted_refs {
        if let RefDeletion::Remote(remote) = deletion {
            fetch_refspecs.insert(
                remote.clone(),
                fetch_refspecs_of(context, repository, remote, budget.deadline)?,
            );
        }
    }
    let unresolved = |why: String| Refusal::Invalid {
        detail: format!("nah cannot tell which refs the command deletes: {why}"),
    };
    let deleted_names = nah_observe::deleted_refs(
        &found.listed,
        found.head_ref.as_deref(),
        &deleted_refs,
        &fetch_refspecs,
    )
    .map_err(unresolved)?;
    for name in &deleted_names {
        plain(&mut refs, name);
    }
    let deleted_reflogs = nah_observe::deleted_reflogs(
        &found.listed,
        found.head_ref.as_deref(),
        &deleted_refs,
        &fetch_refspecs,
    )
    .map_err(unresolved)?;
    let mut entries = BTreeSet::new();
    // Whether nothing the repository holds now is sure to survive.
    let everything = deleting.contains(&Deleting::History);
    let head_moves = everything || deleting.contains(&Deleting::Branches);
    for deleted in deleting {
        match deleted {
            Deleting::Branches | Deleting::History => {
                for (name, oid) in &found.refs {
                    if everything || name.starts_with("refs/heads/") {
                        moved(&mut refs, name, oid);
                    }
                }
                if everything && let Some(tip) = &found.stash_tip {
                    moved(&mut refs, STASH, tip);
                }
                // A branch it is on names its commit already.
                if let Some(head) = &found.head
                    && !refs.iter().any(|saved| &saved.oid == head)
                {
                    moved(&mut refs, "HEAD", head);
                }
            }
            Deleting::Backups => {
                for (name, oid) in &found.refs {
                    if name.starts_with("refs/original/") {
                        moved(&mut refs, name, oid);
                    }
                }
            }
            Deleting::Ref(_) | Deleting::Itself(_) | Deleting::Remote(_) => {}
            Deleting::StashEntry(position) if *position < found.stash.len() => {
                entries.insert(*position);
            }
            // A stash ref whose reflog expired lists no entry, yet names a
            // commit that dropping its newest entry or deleting it loses.
            Deleting::StashEntry(_) | Deleting::Stash if found.stash.is_empty() => {
                plain(&mut refs, STASH)
            }
            Deleting::StashEntry(_) => {}
            Deleting::Stash => entries.extend(0..found.stash.len()),
        }
    }
    // Dropping the newest entry moves the stash to the next one, so a tip
    // the reflog does not list is lost with any entry.
    if !entries.is_empty() && found.stash_tip.as_deref() != Some(found.stash[0].oid.as_str()) {
        return Err(Refusal::RepositoryUnreadable {
            detail: "refs/stash names a commit that is not its newest entry".to_owned(),
        });
    }
    for position in &entries {
        let listed = &found.stash[*position];
        refs.push(SavedRef {
            name: STASH.to_owned(),
            oid: listed.oid.clone(),
            stash: Some(StashEntry {
                message: listed.message.clone(),
                older: found.stash.len() - 1 - position,
            }),
            moved: false,
        });
    }
    // Every tip the command leaves, which keeps its commits reachable. HEAD
    // keeps nothing once it moves, or the branch it names is deleted.
    let deleted = |name: &String| refs.iter().any(|saved| &saved.name == name);
    let kept = found
        .refs
        .iter()
        .filter(|(name, _)| !deleted(name))
        .map(|(_, oid)| oid)
        .chain(
            found
                .head
                .iter()
                .filter(|_| !head_moves && !found.head_ref.as_ref().is_some_and(deleted)),
        )
        .chain(
            found
                .stash
                .iter()
                .enumerate()
                .filter(|(position, _)| !entries.contains(position))
                .map(|(_, listed)| &listed.oid),
        )
        .filter(|_| !everything)
        .collect::<BTreeSet<_>>();
    let pending = store.begin()?;
    // What the reflogs alone reach goes too, measured before anything
    // costlier: a whole history is often past the budget.
    if everything {
        measure_history(context, repository, budget)?;
        refs.extend(reflog_tips(context, repository, &refs, budget.deadline)?);
    } else if !deleted_reflogs.is_empty() {
        refs.extend(deleted_reflog_tips(
            context,
            repository,
            &deleted_reflogs,
            &refs,
            &kept,
            budget.deadline,
        )?);
    }
    let tips = refs.iter().map(|saved| &saved.oid).collect::<BTreeSet<_>>();
    let mut revisions = Vec::new();
    for tip in &tips {
        revisions.extend_from_slice(format!("{tip}\n").as_bytes());
    }
    for tip in &kept {
        revisions.extend_from_slice(format!("^{tip}\n").as_bytes());
    }
    let mut count = 0;
    let mut bytes = 0;
    let mut pack = None;
    if !tips.is_empty() {
        let mut command = project_git(context, repository);
        command.args(["rev-list", "--count", "--stdin"]);
        let counted = git::output(command, revisions.clone(), budget.deadline)
            .map_err(GitFailure::repository)?;
        count = String::from_utf8_lossy(&counted)
            .trim()
            .parse::<u64>()
            .map_err(|_| Refusal::RepositoryUnreadable {
                detail: "git counted the commits in a form nah does not read".to_owned(),
            })?;
        // What the objects take in the repository, which their pack about
        // matches: telling it costs no compression. It counts every object,
        // so an annotated tag on a kept commit is packed too.
        let mut command = project_git(context, repository);
        command.args(["rev-list", "--objects", "--disk-usage", "--stdin"]);
        let used = git::output(command, revisions.clone(), budget.deadline)
            .map_err(GitFailure::repository)?;
        let used = String::from_utf8_lossy(&used)
            .trim()
            .parse::<u64>()
            .map_err(|_| Refusal::RepositoryUnreadable {
                detail: "git measured the commits in a form nah does not read".to_owned(),
            })?;
        if used > budget.bytes {
            return Err(Refusal::OverBudget {
                bytes: used,
                budget_bytes: budget.bytes,
            });
        }
        if used > 0 {
            let mut command = project_git(context, repository);
            command.args(["pack-objects", "--revs", "--stdout", "-q"]);
            let packed = git::output_capped(command, revisions, budget.bytes, budget.deadline)
                .map_err(GitFailure::repository)?
                .ok_or(Refusal::OverBudget {
                    bytes: budget.bytes + 1,
                    budget_bytes: budget.bytes,
                })?;
            bytes = packed.len() as u64;
            let mut command = git::store(&context.git, &store.git_dir(), Some(&pending.objects()));
            command.args(["index-pack", "--stdin"]);
            git::output(command, packed, budget.deadline).map_err(GitFailure::store)?;
            pack = fs::read_dir(pending.objects().join("pack"))
                .map_err(crate::store_failure)?
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .find_map(|name| name.strip_suffix(".pack").map(str::to_owned));
        }
    }
    let manifest = Manifest {
        format: MANIFEST_FORMAT,
        id: String::new(),
        created_ms: 0,
        started_ns,
        root: project.root.display().to_string(),
        repository: None,
        entries: Vec::new(),
        not_saved: Vec::new(),
        deleted: Vec::new(),
        summary: Summary {
            files: 0,
            bytes,
            new_bytes: bytes,
            lines_changed: None,
        },
        undo_of,
        discard_results: BTreeMap::new(),
        commits: Some(Commits {
            refs,
            pack,
            count,
            stash: match entries.is_empty() {
                true => Vec::new(),
                false => found.stash.clone(),
            },
            undoing,
        }),
    };
    if Instant::now() >= budget.deadline {
        return Err(Refusal::OverDeadline);
    }
    store.publish(
        pending,
        manifest,
        context.may_publish.as_ref(),
        false,
        true,
        context.undo_for.as_deref(),
    )
}

/// Refuses as over `budget` a history whose objects, every one a ref, `HEAD`
/// or a reflog reaches, take more than its bytes in the repository. Git
/// lists them commit by commit, newest first, and the sizes add up as they
/// come, so a history far past the budget is refused once the first part
/// of it is: `rev-list --disk-usage` would walk all of it first.
fn measure_history(
    context: &Context,
    repository: &Repository,
    budget: &Budget,
) -> Result<(), Refusal> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use wait_timeout::ChildExt;
    let started = |mut command: Command, input: Stdio| {
        command
            .env("LC_ALL", "C")
            .stdin(input)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Refusal::RepositoryUnreadable {
                detail: format!("git could not start: {error}"),
            })
    };
    let mut command = project_git(context, repository);
    command.args([
        "rev-list",
        "--objects",
        "--no-object-names",
        "--all",
        "--reflog",
        "HEAD",
        "--",
    ]);
    let mut listing = started(command, Stdio::null())?;
    let listed = listing.stdout.take().expect("stdout is piped");
    let mut command = project_git(context, repository);
    command.args(["cat-file", "--batch-check=%(objectsize:disk)"]);
    let mut sizing = match started(command, Stdio::from(listed)) {
        Ok(sizing) => sizing,
        Err(refusal) => {
            let _ = listing.kill();
            let _ = listing.wait();
            return Err(refusal);
        }
    };
    let sizes = sizing.stdout.take().expect("stdout is piped");
    let (sender, summed) = std::sync::mpsc::channel();
    let limit = budget.bytes;
    std::thread::spawn(move || {
        let mut used = 0_u64;
        for line in BufReader::new(sizes).lines() {
            let Ok(size) = line
                .map_err(drop)
                .and_then(|line| line.parse::<u64>().map_err(drop))
            else {
                let _ = sender.send(None);
                return;
            };
            used += size;
            if used > limit {
                break;
            }
        }
        let _ = sender.send(Some(used));
    });
    let used = summed.recv_timeout(budget.deadline.saturating_duration_since(Instant::now()));
    let _ = listing.kill();
    let _ = sizing.kill();
    let ended = |child: &mut std::process::Child| {
        child
            .wait_timeout(budget.deadline.saturating_duration_since(Instant::now()))
            .ok()
            .flatten()
    };
    let (listed, sized) = (ended(&mut listing), ended(&mut sizing));
    match used {
        Ok(Some(used)) if used > budget.bytes => Err(Refusal::OverBudget {
            bytes: used,
            budget_bytes: budget.bytes,
        }),
        Ok(Some(_))
            if listed.is_some_and(|status| status.success())
                && sized.is_some_and(|status| status.success()) =>
        {
            Ok(())
        }
        Ok(_) => Err(Refusal::RepositoryUnreadable {
            detail: "git could not list the objects of the history".to_owned(),
        }),
        Err(_) => Err(Refusal::OverDeadline),
    }
}

/// Commits a reflog records that none of `refs` reaches, as refs named
/// `reflog/<commit>`: the fewest whose ancestors hold all of them.
fn reflog_tips(
    context: &Context,
    repository: &Repository,
    refs: &[SavedRef],
    deadline: Instant,
) -> Result<Vec<SavedRef>, Refusal> {
    let tips = refs
        .iter()
        .map(|saved| saved.oid.as_str())
        .collect::<BTreeSet<_>>();
    if tips.is_empty() {
        return Ok(Vec::new());
    }
    // The saved tips are listed too, so a repository without a single
    // reflog still names a revision, which rev-list requires.
    let mut command = project_git(context, repository);
    command
        .args(["rev-list", "--no-walk", "--reflog"])
        .args(&tips)
        .arg("--");
    let listed = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    let listed = String::from_utf8_lossy(&listed);
    let logged = listed
        .lines()
        .filter(|oid| !tips.contains(oid))
        .collect::<BTreeSet<_>>();
    if logged.is_empty() {
        return Ok(Vec::new());
    }
    let mut command = project_git(context, repository);
    command
        .args(["merge-base", "--independent"])
        .args(&tips)
        .args(&logged);
    let independent = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    Ok(String::from_utf8_lossy(&independent)
        .lines()
        .filter(|oid| logged.contains(oid))
        .map(|oid| SavedRef {
            name: format!("reflog/{oid}"),
            oid: oid.to_owned(),
            stash: None,
            moved: true,
        })
        .collect())
}

/// Commits the reflogs of the deleted refs `names` record, as an entry's
/// old value or its new one, that neither `refs` nor a ref the command
/// keeps (`kept`) reaches, as refs named `reflog/<commit>`: deleting a ref
/// deletes its reflog, so they go with it. The fewest whose ancestors hold
/// all of them.
fn deleted_reflog_tips(
    context: &Context,
    repository: &Repository,
    names: &BTreeSet<String>,
    refs: &[SavedRef],
    kept: &BTreeSet<&String>,
    deadline: Instant,
) -> Result<Vec<SavedRef>, Refusal> {
    let tips = refs
        .iter()
        .map(|saved| saved.oid.as_str())
        .collect::<BTreeSet<_>>();
    let mut logged = BTreeSet::new();
    let top = repository
        .top
        .to_str()
        .ok_or_else(|| Refusal::RepositoryUnreadable {
            detail: "the work tree's path is not Unicode".to_owned(),
        })?;
    for name in names {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(Refusal::OverDeadline);
        }
        let recorded =
            nah_observe::git_reflog_objects(&context.git, top, name, timeout).map_err(|error| {
                match error {
                    ObservationFailure::Timeout => Refusal::OverDeadline,
                    error => Refusal::RepositoryUnreadable {
                        detail: format!("reading the reflog of {name} failed: {error:?}"),
                    },
                }
            })?;
        logged.extend(
            recorded
                .into_iter()
                .filter(|oid| !tips.contains(oid.as_str())),
        );
    }
    if logged.is_empty() {
        return Ok(Vec::new());
    }
    let mut revisions = Vec::new();
    for oid in &logged {
        revisions.extend_from_slice(format!("{oid}\n").as_bytes());
    }
    for tip in kept.iter().map(|oid| oid.as_str()).chain(tips) {
        revisions.extend_from_slice(format!("^{tip}\n").as_bytes());
    }
    let mut command = project_git(context, repository);
    command.args(["rev-list", "--stdin"]);
    let unreached = git::output(command, revisions, deadline).map_err(GitFailure::repository)?;
    let unreached = String::from_utf8_lossy(&unreached);
    let unreached = unreached.lines().collect::<BTreeSet<_>>();
    logged.retain(|oid| unreached.contains(oid.as_str()));
    if logged.is_empty() {
        return Ok(Vec::new());
    }
    let mut command = project_git(context, repository);
    command.args(["merge-base", "--independent"]).args(&logged);
    let independent = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    Ok(String::from_utf8_lossy(&independent)
        .lines()
        .map(|oid| SavedRef {
            name: format!("reflog/{oid}"),
            oid: oid.to_owned(),
            stash: None,
            moved: true,
        })
        .collect())
}

/// Restores the snapshot of commits `manifest` in place: copies the
/// objects its refs need back into the repository's object store, from any
/// snapshot that holds them, recreates each saved ref that is missing, and
/// puts each missing stash entry back among the others. A ref that now
/// names another commit is left alone and reported. A ref the command moved
/// is left as it is too: its saved commit comes back under its recovery
/// ref, unless the ref names that commit again. Undoing the snapshot an
/// undo saved takes back what that undo wrote: it deletes the refs it
/// created where they still name what it wrote, recreates those it
/// deleted, and takes out the entries it put back. Before it writes a ref,
/// it saves what it replaces within `budget`, and stops if that save is
/// refused.
pub(crate) fn undo(
    context: &Context,
    store: &Store,
    project: &Project,
    manifest: &Manifest,
    commits: &Commits,
    into: Option<&Path>,
    budget: Budget,
) -> Result<UndoOutcome, Refusal> {
    let repository = in_repository(project)?;
    if into.is_some() {
        return Err(Refusal::Invalid {
            detail: format!(
                "snapshot `{}` holds commits, which an undo restores only in place",
                manifest.id
            ),
        });
    }
    let deadline = Instant::now() + RESTORE_TIME;
    let found = Refs::read(context, repository, budget.deadline)?;
    import(
        context, store, repository, &found, manifest, commits, deadline,
    )?;
    let mut outcome = UndoOutcome {
        snapshot: manifest.id.clone(),
        before_undo: None,
        written: Vec::new(),
        removed: Vec::new(),
        staged: Vec::new(),
        clean_restored: BTreeMap::new(),
        refs: Vec::new(),
        conflicts: Vec::new(),
    };
    // Plain refs: those to create, and those to delete, each with the
    // object it must name now.
    let mut create = Vec::new();
    let mut delete = Vec::new();
    for saved in commits.refs.iter().filter(|saved| saved.stash.is_none()) {
        let saved = &match saved.moved {
            false => saved.clone(),
            true => {
                let now = match saved.name.as_str() {
                    "HEAD" => found.head.as_deref(),
                    name => found.named(name),
                };
                if now == Some(saved.oid.as_str()) {
                    continue;
                }
                SavedRef {
                    name: recovery_ref(&manifest.id, &saved.name),
                    oid: saved.oid.clone(),
                    stash: None,
                    moved: false,
                }
            }
        };
        match found.named(&saved.name) {
            None => create.push(saved.clone()),
            Some(oid) if oid == saved.oid => {}
            Some(oid) => outcome.conflicts.push(Conflict {
                path: saved.name.clone(),
                reason: format!("it names another commit now ({oid})"),
            }),
        }
    }
    for created in commits.undoing.iter().flat_map(|undoing| &undoing.created) {
        match found.named(&created.name) {
            Some(oid) if oid == created.oid => delete.push(created),
            Some(_) => outcome.conflicts.push(Conflict {
                path: created.name.clone(),
                reason: "it changed since the undo restored it".to_owned(),
            }),
            None => {}
        }
    }
    let stash = restored_stash(commits, &found.stash);
    for (listed, current) in &stash {
        if current.is_none() {
            outcome.refs.push(format!(
                "restored stash entry {}: {}",
                listed.oid, listed.message
            ));
        }
    }
    for (position, listed) in found.stash.iter().enumerate() {
        if !stash.iter().any(|(_, current)| *current == Some(position)) {
            outcome.refs.push(format!(
                "dropped stash entry {}: {}",
                listed.oid, listed.message
            ));
        }
    }
    let mut rewrite_stash = stash
        .iter()
        .map(|(listed, _)| listed)
        .ne(found.stash.iter());
    if rewrite_stash && found.stash.is_empty() && found.stash_tip.is_some() {
        outcome.conflicts.push(Conflict {
            path: STASH.to_owned(),
            reason: "it names a commit no stash entry lists".to_owned(),
        });
        outcome.refs.clear();
        rewrite_stash = false;
    }
    if !rewrite_stash && create.is_empty() && delete.is_empty() {
        return Ok(outcome);
    }
    let mut replaced = delete
        .iter()
        .map(|saved| Deleting::Ref(saved.name.clone()))
        .collect::<Vec<_>>();
    if rewrite_stash {
        replaced.push(Deleting::Stash);
    }
    let undoing = Undoing {
        created: create.clone(),
        stash: rewrite_stash.then(|| {
            stash
                .iter()
                .map(|(entry, current)| Written {
                    entry: entry.clone(),
                    before: *current,
                })
                .collect()
        }),
    };
    let before = save(
        context,
        store,
        project,
        repository,
        &found,
        &replaced,
        Some(manifest.id.clone()),
        Some(undoing),
        &budget,
    )?;
    // A write that fails leaves the refs partly written: the snapshot saved
    // first puts them back.
    let stopped = |refusal: Refusal| Refusal::Invalid {
        detail: format!(
            "the undo stopped partway ({refusal}); undo snapshot {} to put back what it changed",
            before.id
        ),
    };
    let written = write_refs(
        context,
        repository,
        &found,
        &create,
        &delete,
        rewrite_stash.then_some(stash.as_slice()),
        deadline,
    )
    .map_err(stopped)?;
    outcome.refs.extend(written);
    outcome.before_undo = Some(before.id);
    Ok(outcome)
}

/// Creates `create`, deletes `delete`, and writes `stash` as the stash
/// when given; returns what it did.
fn write_refs(
    context: &Context,
    repository: &Repository,
    found: &Refs,
    create: &[SavedRef],
    delete: &[&SavedRef],
    stash: Option<&[(Listed, Option<usize>)]>,
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let mut written = Vec::new();
    let update = |args: &[&str]| {
        let mut command = project_git(context, repository);
        command.args(["update-ref"]).args(args);
        git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)
    };
    for saved in create {
        update(&[&saved.name, &saved.oid, NO_OBJECT])?;
        written.push(match saved.name.starts_with("refs/nah/") {
            true => format!("recovered {} as {}", saved.oid, saved.name),
            false => format!("restored {}", saved.name),
        });
    }
    for created in delete {
        update(&["-d", &created.name, &created.oid])?;
        written.push(format!("deleted {}", created.name));
    }
    if let Some(stash) = stash {
        write_stash(
            context,
            repository,
            found.stash_tip.as_deref(),
            stash,
            deadline,
        )?;
    }
    Ok(written)
}

/// The stash an undo of `commits` leaves, newest first, from the stash
/// `current` it finds: each entry with its position in `current`, or
/// `None` for one it puts back.
///
/// Git only drops entries and pushes new ones on top, so the entries of a
/// list saved earlier that remain are found in `current` in their order
/// (`matched`). A saved entry that is missing goes back right above the
/// entries that were older than it and remain, below every other. Undoing
/// an undo takes out what that undo put back and returns every entry of the
/// list it saved before it wrote that is missing, the same way.
fn restored_stash(commits: &Commits, current: &[Listed]) -> Vec<(Listed, Option<usize>)> {
    let saved = &commits.stash;
    // For each entry of `current`, its position in `saved` (`None`: an
    // entry not among them), or `Err` for one to take out.
    let (positions, put_back): (Vec<Result<Option<usize>, ()>>, Vec<usize>) = match commits
        .undoing
        .as_ref()
        .and_then(|undoing| undoing.stash.as_ref())
    {
        Some(written) => {
            let entries = written.iter().map(|w| w.entry.clone()).collect::<Vec<_>>();
            // Where entries alike leave it open, one stays: the undo put
            // back only those it must have.
            let positions = matched(current, &entries, |position| {
                written[position].before.is_some()
            })
            .into_iter()
            .map(|position| match position {
                Some(position) => written[position].before.map(Some).ok_or(()),
                None => Ok(None),
            })
            .collect();
            // Every entry of the list before, not only those it took out:
            // an undo stopped partway may have lost any of them.
            (positions, (0..saved.len()).collect())
        }
        None => {
            let dropped = commits
                .refs
                .iter()
                .filter_map(|saved_ref| saved_ref.stash.as_ref())
                .filter_map(|entry| saved.len().checked_sub(entry.older + 1))
                .collect::<Vec<_>>();
            // Where entries alike leave it open, a saved one is missing and
            // comes back: what remains is never fewer entries than were.
            let positions = matched(current, saved, |position| !dropped.contains(&position))
                .into_iter()
                .map(Ok)
                .collect();
            (positions, dropped)
        }
    };
    // Each entry left with its position in `current` and in `saved`.
    let mut stash = current
        .iter()
        .zip(positions)
        .enumerate()
        .filter_map(|(index, (listed, position))| {
            Some(((listed.clone(), Some(index)), position.ok()?))
        })
        .collect::<Vec<_>>();
    for position in put_back {
        if stash.iter().any(|(_, kept)| *kept == Some(position)) {
            continue;
        }
        let at = stash
            .iter()
            .position(|(_, kept)| kept.is_some_and(|kept| kept > position))
            .unwrap_or(stash.len());
        stash.insert(at, ((saved[position].clone(), None), Some(position)));
    }
    stash.into_iter().map(|(entry, _)| entry).collect()
}

/// For each entry of `current`, newest first, its position in `listed`, an
/// earlier list of the same stash: the most entries matched in order, and
/// among those matchings, the most at positions `kept` names.
fn matched(
    current: &[Listed],
    listed: &[Listed],
    kept: impl Fn(usize) -> bool,
) -> Vec<Option<usize>> {
    let (rows, columns) = (current.len(), listed.len());
    // best[i][j]: how many of current[i..] and listed[j..] match, and how
    // many of those at kept positions.
    let mut best = vec![vec![(0, 0); columns + 1]; rows + 1];
    let matching = |i: usize, j: usize, best: &[Vec<(usize, usize)>]| {
        (current[i] == listed[j]).then(|| {
            let (count, at_kept) = best[i + 1][j + 1];
            (count + 1, at_kept + usize::from(kept(j)))
        })
    };
    for i in (0..rows).rev() {
        for j in (0..columns).rev() {
            let skip = best[i + 1][j].max(best[i][j + 1]);
            best[i][j] = matching(i, j, &best).map_or(skip, |matched| matched.max(skip));
        }
    }
    let mut positions = vec![None; rows];
    let (mut i, mut j) = (0, 0);
    while i < rows && j < columns {
        if matching(i, j, &best) == Some(best[i][j]) {
            positions[i] = Some(j);
            i += 1;
            j += 1;
        } else if best[i + 1][j] == best[i][j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    positions
}

/// Writes `stash`, newest first, as the stash of `repository`, whose
/// `refs/stash` names `tip` now. `git stash store` only adds an entry on
/// top, so the stash is written again from its oldest entry, each with who
/// wrote it and when; deleting the ref deletes its reflog, the list of
/// entries, with it.
fn write_stash(
    context: &Context,
    repository: &Repository,
    tip: Option<&str>,
    stash: &[(Listed, Option<usize>)],
    deadline: Instant,
) -> Result<(), Refusal> {
    let run = |args: &[&str], by: Option<&Listed>| {
        let mut command = project_git(context, repository);
        if let Some(entry) = by {
            command
                .env("GIT_COMMITTER_NAME", &entry.name)
                .env("GIT_COMMITTER_EMAIL", &entry.email)
                .env("GIT_COMMITTER_DATE", &entry.date);
        }
        command.args(args);
        git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)
    };
    if let Some(tip) = tip {
        run(&["update-ref", "-d", STASH, tip], None)?;
    }
    // Git logs no entry for a ref set to the commit it names already, so
    // an entry of the same commit as the one below it goes on top of a
    // placeholder, the commit's tree, deleted after.
    let mut written = 0;
    let mut placeholders = Vec::new();
    let mut below: Option<&str> = None;
    for (entry, _) in stash.iter().rev() {
        if below == Some(entry.oid.as_str()) {
            let tree = format!("{}^{{tree}}", entry.oid);
            let tree = run(&["rev-parse", "--verify", &tree], None)?;
            let tree = String::from_utf8_lossy(&tree).trim().to_owned();
            run(&["update-ref", "-m", "nah placeholder", STASH, &tree], None)?;
            placeholders.push(written);
            written += 1;
        }
        // Git refuses an empty `-m`, and logs an empty message without one.
        let mut args = vec!["update-ref", "--create-reflog"];
        if !entry.message.is_empty() {
            args.extend(["-m", &entry.message]);
        }
        args.extend([STASH, &entry.oid]);
        run(&args, Some(entry))?;
        written += 1;
        below = Some(&entry.oid);
    }
    // The oldest first: deleting an entry leaves the positions of those
    // above it as they were.
    for placeholder in placeholders {
        let position = format!("{STASH}@{{{}}}", written - 1 - placeholder);
        run(&["reflog", "delete", "--rewrite", &position], None)?;
    }
    Ok(())
}

/// Copies into the repository the objects the refs of `commits` need and
/// it lacks, from every snapshot of `store`: two snapshots may each have
/// left out an object the other holds.
fn import(
    context: &Context,
    store: &Store,
    repository: &Repository,
    found: &Refs,
    manifest: &Manifest,
    commits: &Commits,
    deadline: Instant,
) -> Result<(), Refusal> {
    let oids = commits
        .refs
        .iter()
        .chain(commits.undoing.iter().flat_map(|undoing| &undoing.created))
        .map(|saved| saved.oid.as_str())
        .collect::<BTreeSet<_>>();
    if oids.is_empty() {
        return Ok(());
    }
    let lacking = |failure: GitFailure| match failure {
        GitFailure::Deadline => Refusal::OverDeadline,
        GitFailure::Failed(detail) => Refusal::Invalid {
            detail: format!(
                "the repository lacks objects the commits of snapshot `{}` need: {detail}",
                manifest.id
            ),
        },
    };
    let complete = || {
        let mut command = project_git(context, repository);
        command
            .args(["rev-list", "--objects", "--quiet"])
            .args(&oids)
            .args(["--not", "--all"]);
        git::output(command, Vec::new(), deadline)
    };
    if complete().is_ok() {
        return Ok(());
    }
    // What the refs reach and no tip of the repository does, read through
    // the store's objects as well as the repository's.
    let mut revisions = Vec::new();
    for oid in &oids {
        revisions.extend_from_slice(format!("{oid}\n").as_bytes());
    }
    for tip in found.tips() {
        revisions.extend_from_slice(format!("^{tip}\n").as_bytes());
    }
    let mut command = project_git(context, repository);
    command
        .env(
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            store.git_dir().join("objects"),
        )
        .args(["pack-objects", "--revs", "--stdout", "-q"]);
    let packed = git::output(command, revisions, deadline).map_err(lacking)?;
    let mut command = project_git(context, repository);
    command.args(["index-pack", "--stdin"]);
    git::output(command, packed, deadline).map_err(GitFailure::repository)?;
    complete().map(|_| ()).map_err(lacking)
}

/// The fetch refspecs of the remote `remote`: `git remote remove` deletes
/// the refs they map to.
fn fetch_refspecs_of(
    context: &Context,
    repository: &Repository,
    remote: &str,
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let mut command = project_git(context, repository);
    command.args(["config", "--get-all", &format!("remote.{remote}.fetch")]);
    match git::output(command, Vec::new(), deadline) {
        Ok(refspecs) => Ok(String::from_utf8_lossy(&refspecs)
            .lines()
            .map(str::to_owned)
            .collect()),
        Err(GitFailure::Deadline) => Err(Refusal::OverDeadline),
        // No such key: the remote maps no ref.
        Err(GitFailure::Failed(_)) => Ok(Vec::new()),
    }
}

/// Git run in the project's repository, where no hook it configures runs.
fn project_git(context: &Context, repository: &Repository) -> Command {
    git::repository(&context.git, &repository.top, &[])
}
