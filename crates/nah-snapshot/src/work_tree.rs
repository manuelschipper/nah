//! Lists what a git work tree holds that is in no commit, and reads the
//! repository's staged blobs, without writing to the repository.

use crate::git::{self, GitFailure};
use crate::manifest::{NotSaved, NotSavedReason, Origin, RepositoryState, Stage};
use crate::{Candidate, Context, Lookup, Refusal, SKIP_LIST, Scan, folder};
use nah_proto::observation::ObservationFailure;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Most tracked paths whose changed lines a save counts: the count runs one
/// more diff, whose pathspecs ride on its command line.
const LINE_COUNT_PATHS: usize = 1000;

/// The index mode of a submodule's commit.
pub(crate) const GITLINK: &str = "160000";

pub(crate) struct Repository {
    /// The canonical work tree top level.
    pub(crate) top: PathBuf,
    /// This work tree's own git directory, which holds its index.
    pub(crate) git_dir: PathBuf,
    /// The git directory linked worktrees share.
    pub(crate) common_dir: PathBuf,
}

/// The repository whose work tree holds `dir`. Only a repository with SHA-1
/// object names is supported: the store's objects share their names.
pub(crate) fn locate(
    context: &Context,
    dir: &Path,
    deadline: Instant,
) -> Result<Repository, Refusal> {
    let mut command = nah_observe::git_command(&context.git);
    command.arg("-C").arg(dir).args([
        "rev-parse",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
        "--show-object-format",
    ]);
    let output = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    let text = String::from_utf8(output).map_err(|_| Refusal::RepositoryUnreadable {
        detail: "git named the repository with a path that is not UTF-8".to_owned(),
    })?;
    let lines = text.lines().collect::<Vec<_>>();
    let [top, git_dir, common_dir, format] = lines[..] else {
        return Err(Refusal::RepositoryUnreadable {
            detail: format!("unexpected rev-parse output: {text}"),
        });
    };
    if format != "sha1" {
        return Err(Refusal::RepositoryUnreadable {
            detail: format!("the repository uses {format} object names; snapshots support sha1"),
        });
    }
    let canonical = |path: PathBuf| {
        fs::canonicalize(&path).map_err(|error| Refusal::RepositoryUnreadable {
            detail: format!("{}: {error}", path.display()),
        })
    };
    Ok(Repository {
        top: canonical(PathBuf::from(top))?,
        git_dir: canonical(PathBuf::from(git_dir))?,
        common_dir: canonical(dir.join(common_dir))?,
    })
}

/// The `-c` options that keep git from starting any filter driver the
/// repository names.
pub(crate) fn filters(
    context: &Context,
    repository: &Repository,
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let top = repository
        .top
        .to_str()
        .ok_or(Refusal::RepositoryUnreadable {
            detail: "the work tree path is not UTF-8".to_owned(),
        })?;
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(Refusal::OverDeadline);
    }
    let mut options = nah_observe::git_filter_drivers_disabled(&context.git, top, timeout)
        .map_err(|error| match error {
            ObservationFailure::Timeout => Refusal::OverDeadline,
            error => Refusal::RepositoryUnreadable {
                detail: format!("reading its filter drivers failed: {error:?}"),
            },
        })?;
    // Git fails a command that needs a driver marked required, as Git LFS
    // marks its own, once the driver is disabled; the raw bytes are what a
    // snapshot wants.
    let required = options
        .iter()
        .filter_map(|option| option.strip_prefix("filter.")?.strip_suffix(".clean="))
        .map(|driver| format!("filter.{driver}.required=false"))
        .collect::<Vec<_>>();
    for option in required {
        options.extend(["-c".to_owned(), option]);
    }
    // A later `-c` wins over the `core.fsmonitor=false` every command starts
    // with. Only git's own daemon is let back in, never a program the
    // configuration names.
    if context.builtin_fsmonitor && builtin_fsmonitor_enabled(context, repository, deadline)? {
        options.extend(["-c".to_owned(), "core.fsmonitor=true".to_owned()]);
    }
    Ok(options)
}

/// Whether the repository's configuration sets `core.fsmonitor` to a boolean
/// true, git's built-in daemon. A value naming a hook program is not one.
fn builtin_fsmonitor_enabled(
    context: &Context,
    repository: &Repository,
    deadline: Instant,
) -> Result<bool, Refusal> {
    // Reading configuration starts no program; `nah_observe::git_command`
    // is not used here because its own `core.fsmonitor=false` would answer.
    let mut command = Command::new(&context.git);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    command.arg("-C").arg(&repository.top).args([
        "config",
        "--type=bool",
        "--get",
        "core.fsmonitor",
    ]);
    match git::output(command, Vec::new(), deadline) {
        Ok(value) => Ok(value.trim_ascii() == b"true"),
        Err(GitFailure::Deadline) => Err(Refusal::OverDeadline),
        // Unset, or not a boolean.
        Err(GitFailure::Failed(_)) => Ok(false),
    }
}

/// Refuses while another Git process holds `repository`'s index lock: what
/// it writes may change what a save reads.
pub(crate) fn index_unlocked(repository: &Repository) -> Result<(), Refusal> {
    let lock = repository.git_dir.join("index.lock");
    if fs::symlink_metadata(&lock).is_ok() {
        return Err(Refusal::IndexLocked {
            path: lock.display().to_string(),
        });
    }
    Ok(())
}

/// Everything in the work tree a save considers: tracked paths that differ
/// from HEAD in the index or the work tree, untracked files git does not
/// ignore, and the `named` paths; and what it leaves out, with the reason.
/// With `only`, a path relative to the top, it looks at that path alone and
/// leaves the submodules unlisted.
pub(crate) fn scan(
    context: &Context,
    repository: &Repository,
    filters: &[String],
    named: &[PathBuf],
    only: Option<&str>,
    deadline: Instant,
) -> Result<Scan, Refusal> {
    index_unlocked(repository)?;
    // One status lists everything at once, which costs less than separate
    // listings of untracked and ignored files: git walks the tree once.
    let mut command = git::repository(&context.git, &repository.top, filters);
    command.args([
        "status",
        "--porcelain=v2",
        "-z",
        "--branch",
        "--untracked-files=all",
        "--ignored=matching",
        "--no-renames",
        "--ignore-submodules=dirty",
    ]);
    if let Some(only) = only {
        command.arg("--").arg(format!(":(literal){only}"));
    }
    let (status, warnings) =
        git::output_and_warnings(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    unopened(repository, &warnings)?;

    let mut scan = Scan::default();
    let mut repository_state = RepositoryState {
        head: None,
        branch: None,
    };
    let mut not_saved = Vec::new();
    for record in records(&status)? {
        if let Some(head) = record.strip_prefix("# branch.oid ") {
            repository_state.head = (head != "(initial)").then(|| head.to_owned());
        } else if let Some(branch) = record.strip_prefix("# branch.head ") {
            repository_state.branch = (branch != "(detached)").then(|| branch.to_owned());
        } else if record.starts_with("# ") {
        } else if let Some(path) = record.strip_prefix("? ") {
            if path.ends_with('/') {
                // Git names a repository inside the work tree, not its files,
                // in a skip-list folder too: its history cannot be rebuilt.
                not_saved.push(NotSaved {
                    path: path.to_owned(),
                    reason: NotSavedReason::NestedRepository,
                    origin: None,
                });
            } else if let Some(folder) = skip_folder(path) {
                not_saved.push(NotSaved {
                    path: folder,
                    reason: NotSavedReason::SkipList,
                    origin: None,
                });
            } else {
                scan.candidates
                    .push(Candidate::untracked(path, Origin::Untracked));
            }
        } else if let Some(path) = record.strip_prefix("! ") {
            not_saved.push(match skip_folder(path) {
                Some(folder) => NotSaved {
                    path: folder,
                    reason: NotSavedReason::SkipList,
                    origin: None,
                },
                None => NotSaved {
                    path: path.to_owned(),
                    reason: NotSavedReason::Ignored,
                    origin: None,
                },
            });
        } else if let Some(candidate) = tracked(record)? {
            if candidate
                .index
                .iter()
                .chain(&candidate.head)
                .any(|stage| stage.mode == GITLINK)
            {
                not_saved.push(NotSaved {
                    path: format!("{}/", candidate.path),
                    reason: NotSavedReason::Submodule,
                    origin: None,
                });
                // The submodule's files are its own repository's, but the
                // commit the superproject stages for it is saved, and so is a
                // file or link standing where its folder was.
                let replaced = fs::symlink_metadata(repository.top.join(&candidate.path))
                    .is_ok_and(|metadata| !metadata.is_dir());
                if candidate.staged || replaced {
                    scan.candidates.push(candidate);
                }
            } else {
                scan.candidates.push(candidate);
            }
        }
    }
    let listed = scan
        .candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<BTreeSet<_>>();
    scan.candidates.extend(hidden_changes(
        context, repository, filters, &listed, only, deadline,
    )?);
    scan.repository = Some(repository_state);
    // Status leaves out a submodule whose own work tree changed, which a save
    // does not hold either; the manifest names every submodule instead.
    if only.is_none() && fs::symlink_metadata(repository.top.join(".gitmodules")).is_ok() {
        let mut command = git::repository(&context.git, &repository.top, filters);
        command.args([
            "config",
            "-z",
            "--file",
            ".gitmodules",
            "--get-regexp",
            r"^submodule\..*\.path$",
        ]);
        let paths = match git::output(command, Vec::new(), deadline) {
            // Git exits 1, saying nothing, when no submodule is listed.
            Err(GitFailure::Failed(detail)) if detail.is_empty() => Vec::new(),
            result => result.map_err(GitFailure::repository)?,
        };
        for record in records(&paths)? {
            if let Some((_, path)) = record.split_once('\n') {
                not_saved.push(NotSaved {
                    path: format!("{path}/"),
                    reason: NotSavedReason::Submodule,
                    origin: None,
                });
            }
        }
    }
    let listed = scan
        .candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<BTreeSet<_>>();
    for path in named {
        for relative in named_files(&repository.top, path, deadline)? {
            if !listed.contains(&relative) {
                scan.candidates
                    .push(Candidate::untracked(&relative, Origin::Named));
            }
        }
    }
    // A named ignored file is saved, so it is no longer left out.
    let considered = scan
        .candidates
        .iter()
        .map(|candidate| candidate.path.as_str())
        .collect::<BTreeSet<_>>();
    not_saved.retain(|left_out| !considered.contains(left_out.path.as_str()));
    scan.not_saved = not_saved;
    scan.leave_out_secrets(context, &repository.top)?;
    Ok(scan)
}

/// Fails on a folder, or an ignore file, git only warned it could not read:
/// it lists what it can, and the files behind it would be missing.
fn unopened(repository: &Repository, warnings: &str) -> Result<(), Refusal> {
    for warning in warnings.lines() {
        if let Some(quoted) = [
            "warning: could not open directory '",
            "warning: unable to access '",
        ]
        .iter()
        .find_map(|prefix| warning.strip_prefix(prefix))
        {
            let (path, detail) = quoted.rsplit_once("': ").unwrap_or((quoted, warning));
            return Err(Refusal::Unreadable {
                path: repository.top.join(path).display().to_string(),
                detail: detail.to_owned(),
            });
        }
    }
    Ok(())
}

/// The repositories of their own inside `folders` (relative to the top),
/// which git names by their folder, ending in `/`, without listing their
/// files. No exclude file is read, so ignored folders are looked into too.
pub(crate) fn nested_repositories(
    context: &Context,
    repository: &Repository,
    folders: &[String],
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let filters = filters(context, repository, deadline)?;
    let mut command = git::repository(&context.git, &repository.top, &filters);
    command
        .args(["ls-files", "-z", "--others", "--full-name", "--"])
        .args(folders.iter().map(|folder| format!(":(literal){folder}")));
    let (listed, warnings) =
        git::output_and_warnings(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    unopened(repository, &warnings)?;
    Ok(records(&listed)?
        .into_iter()
        .filter(|path| path.ends_with('/'))
        .map(str::to_owned)
        .collect())
}

/// `paths` without those under another of them: a folder's pathspec also
/// selects everything under it, so each entry is then listed once, however
/// the paths split across commands.
fn uncovered<'a>(paths: &[&'a str]) -> Vec<&'a str> {
    let listed = paths.iter().copied().collect::<BTreeSet<_>>();
    listed
        .iter()
        .copied()
        .filter(|path| {
            !path
                .match_indices('/')
                .any(|(slash, _)| listed.contains(&path[..slash]))
        })
        .collect()
}

/// The tracked files among `paths`, relative to the work tree top `root`
/// (a folder standing for what it holds), whose kind, executable bit or
/// bytes on disk do not prove them their index entry's blob.
pub(crate) fn unproven_by_index(
    context: &Context,
    root: &Path,
    paths: &[&str],
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let top = root.to_str().ok_or(Refusal::RepositoryUnreadable {
        detail: "the work tree path is not UTF-8".to_owned(),
    })?;
    let mut unproven = Vec::new();
    for chunk in uncovered(paths).chunks(500) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(Refusal::OverDeadline);
        }
        let pathspecs = chunk
            .iter()
            .map(|path| format!(":(literal){path}"))
            .collect::<Vec<_>>();
        let pathspecs = pathspecs.iter().map(String::as_str).collect::<Vec<_>>();
        unproven.extend(
            nah_observe::git_unproven_by_index(&context.git, top, &pathspecs, timeout).map_err(
                |error| match error {
                    ObservationFailure::Timeout => Refusal::OverDeadline,
                    error => Refusal::RepositoryUnreadable {
                        detail: format!("hashing its clean files failed: {error:?}"),
                    },
                },
            )?,
        );
    }
    Ok(unproven)
}

/// The files `pathspecs` match when git runs in `directory`, by path
/// relative to the top: tracked ones, and untracked ones whether ignored or
/// not, since no exclude file is read. Among `folders`, those matched by
/// their own path, which a checkout of a file there replaces whole, end in
/// `/`: git lists no folder, so each is asked as a file of a scratch index
/// at `index`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn matching(
    context: &Context,
    repository: &Repository,
    directory: &Path,
    pathspecs: &[String],
    options: &[String],
    folders: &[String],
    index: &Path,
    deadline: Instant,
) -> Result<BTreeSet<String>, Refusal> {
    let filters = &filters(context, repository, deadline)?;
    let listed = |index: Option<&Path>| {
        let mut command = git::repository(&context.git, &repository.top, filters);
        if let Some(index) = index {
            command.env("GIT_INDEX_FILE", index);
        }
        command
            .arg("-C")
            .arg(directory)
            .args(options)
            .args(["ls-files", "-z", "--full-name"]);
        if index.is_none() {
            command.args(["--cached", "--others"]);
        }
        command.arg("--").args(pathspecs);
        let (listed, warnings) = git::output_and_warnings(command, Vec::new(), deadline)
            .map_err(GitFailure::repository)?;
        unopened(repository, &warnings)?;
        Ok::<_, Refusal>(
            records(&listed)?
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    };
    let mut matched = listed(None)?.into_iter().collect::<BTreeSet<_>>();
    if folders.is_empty() {
        return Ok(matched);
    }
    let mut command = git::repository(&context.git, &repository.top, filters);
    command.args(["hash-object", "-t", "blob", "--stdin"]);
    let empty = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    let empty = String::from_utf8_lossy(&empty).trim().to_owned();
    // A folder and one under it cannot both be files of one index.
    let mut by_depth = BTreeMap::<usize, Vec<&String>>::new();
    for folder in folders {
        by_depth
            .entry(folder.matches('/').count())
            .or_default()
            .push(folder);
    }
    for level in by_depth.values() {
        let _ = fs::remove_file(index);
        let mut input = Vec::new();
        for folder in level {
            input.extend_from_slice(format!("100644 {empty}\t{folder}").as_bytes());
            input.push(0);
        }
        let mut command = git::repository(&context.git, &repository.top, filters);
        command
            .env("GIT_INDEX_FILE", index)
            .args(["update-index", "-z", "--index-info"]);
        git::output(command, input, deadline).map_err(GitFailure::repository)?;
        matched.extend(listed(Some(index))?.into_iter().map(|folder| folder + "/"));
    }
    Ok(matched)
}

/// The tracked files status does not compare with the work tree, because
/// their index entry tells git to look away, that differ from it: entries
/// marked assume-unchanged, and skip-worktree entries, as a sparse checkout
/// marks the paths it leaves out, whose file is present anyway. Each such
/// entry's index matches HEAD, or status would have listed it. With `only`,
/// the entry of that path alone.
fn hidden_changes(
    context: &Context,
    repository: &Repository,
    filters: &[String],
    listed: &BTreeSet<String>,
    only: Option<&str>,
    deadline: Instant,
) -> Result<Vec<Candidate>, Refusal> {
    let mut command = git::repository(&context.git, &repository.top, filters);
    command.args(["ls-files", "-v", "-s", "-z"]);
    if let Some(only) = only {
        command.arg("--").arg(format!(":(literal){only}"));
    }
    let output = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    let mut lookup = Lookup::new(&repository.top);
    let mut changed = Vec::new();
    let mut to_hash = Vec::new();
    for record in records(&output)? {
        // `-v` tags an assume-unchanged entry in lower case, a skip-worktree
        // one `S`; `H` is an ordinary entry.
        let Some((tag, rest)) = record.split_once(' ') else {
            continue;
        };
        let assume_unchanged = tag.chars().all(|tag| tag.is_ascii_lowercase());
        if !assume_unchanged && tag != "S" {
            continue;
        }
        let Some((fields, path)) = rest.split_once('\t') else {
            continue;
        };
        let mut fields = fields.split(' ');
        let (Some(mode), Some(oid)) = (fields.next(), fields.next()) else {
            continue;
        };
        if mode == GITLINK || listed.contains(path) {
            continue;
        }
        let stage = Stage {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
            stage: 0,
        };
        let metadata = lookup.metadata(path).map_err(|error| Refusal::Unreadable {
            path: repository.top.join(path).display().to_string(),
            detail: error.to_string(),
        })?;
        let differs = match metadata {
            // A sparse checkout leaves its skip-worktree files out; an absent
            // assume-unchanged file was deleted.
            None => assume_unchanged,
            Some(metadata) if metadata.is_file() && !path.contains('\n') => {
                let executable = metadata.permissions().mode() & 0o100 != 0;
                // A link's index entry holds its target's bytes, which a file
                // replacing it can hold too.
                if mode != if executable { "100755" } else { "100644" } {
                    true
                } else {
                    to_hash.push((path, stage));
                    continue;
                }
            }
            Some(_) => true,
        };
        if differs {
            changed.push((path, stage));
        }
    }
    if !to_hash.is_empty() {
        let mut command = git::repository(&context.git, &repository.top, filters);
        command.args(["hash-object", "--no-filters", "--stdin-paths"]);
        let input = to_hash
            .iter()
            .flat_map(|(path, _)| format!("{path}\n").into_bytes())
            .collect();
        let output = git::output(command, input, deadline).map_err(GitFailure::repository)?;
        let oids = String::from_utf8_lossy(&output)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if oids.len() != to_hash.len() {
            return Err(Refusal::RepositoryUnreadable {
                detail: "git hashed fewer files than it was given".to_owned(),
            });
        }
        for ((path, stage), oid) in to_hash.into_iter().zip(oids) {
            if oid != stage.oid {
                changed.push((path, stage));
            }
        }
    }
    Ok(changed
        .into_iter()
        .map(|(path, stage)| Candidate {
            head: Some(stage.clone()),
            index: vec![stage],
            ..Candidate::untracked(path, Origin::Tracked)
        })
        .collect())
}

/// The index entries at or under each of `paths`, by path; a path the
/// index lacks has none.
pub(crate) fn index_entries(
    context: &Context,
    root: &Path,
    filters: &[String],
    paths: &[&str],
    deadline: Instant,
) -> Result<BTreeMap<String, Vec<Stage>>, Refusal> {
    let uncovered = uncovered(paths);
    let mut entries = BTreeMap::<String, Vec<Stage>>::new();
    for chunk in uncovered.chunks(500) {
        let mut command = git::repository(&context.git, root, filters);
        command.args(["ls-files", "-s", "-z", "--"]);
        command.args(chunk.iter().map(|path| format!(":(literal){path}")));
        let output = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
        for record in records(&output)? {
            let Some((fields, path)) = record.split_once('\t') else {
                continue;
            };
            let mut fields = fields.split(' ');
            if let (Some(mode), Some(oid), Some(stage)) =
                (fields.next(), fields.next(), fields.next())
            {
                entries.entry(path.to_owned()).or_default().push(Stage {
                    mode: mode.to_owned(),
                    oid: oid.to_owned(),
                    stage: stage.parse().unwrap_or(0),
                });
            }
        }
    }
    Ok(entries)
}

/// The NUL-terminated records git printed, each UTF-8.
fn records(output: &[u8]) -> Result<Vec<&str>, Refusal> {
    output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            std::str::from_utf8(record).map_err(|_| Refusal::Unreadable {
                path: String::from_utf8_lossy(record).into_owned(),
                detail: "its name is not UTF-8".to_owned(),
            })
        })
        .collect()
}

/// The candidate a `git status --porcelain=v2` change record names.
fn tracked(record: &str) -> Result<Option<Candidate>, Refusal> {
    let unexpected = || Refusal::RepositoryUnreadable {
        detail: format!("unexpected status record: {record}"),
    };
    let stage = |mode: &str, oid: &str, stage| {
        (mode != "000000").then(|| crate::manifest::Stage {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
            stage,
        })
    };
    if let Some(rest) = record.strip_prefix("1 ") {
        let fields = rest.splitn(8, ' ').collect::<Vec<_>>();
        let [
            xy,
            _submodule,
            head_mode,
            index_mode,
            _worktree_mode,
            head_oid,
            index_oid,
            path,
        ] = fields[..]
        else {
            return Err(unexpected());
        };
        let mut xy = xy.chars();
        let (Some(staged), Some(worktree)) = (xy.next(), xy.next()) else {
            return Err(unexpected());
        };
        return Ok(Some(Candidate {
            path: path.to_owned(),
            origin: Origin::Tracked,
            head: stage(head_mode, head_oid, 0),
            index: stage(index_mode, index_oid, 0).into_iter().collect(),
            staged: staged != '.',
            worktree_matches_index: worktree == '.',
            // Status shows an intent-to-add entry as added in the work tree
            // only, with no index version.
            intent_to_add: staged == '.' && worktree == 'A',
        }));
    }
    if let Some(rest) = record.strip_prefix("u ") {
        let fields = rest.splitn(10, ' ').collect::<Vec<_>>();
        let [
            _,
            _,
            base_mode,
            ours_mode,
            theirs_mode,
            _,
            base_oid,
            ours_oid,
            theirs_oid,
            path,
        ] = fields[..]
        else {
            return Err(unexpected());
        };
        let index = [
            stage(base_mode, base_oid, 1),
            stage(ours_mode, ours_oid, 2),
            stage(theirs_mode, theirs_oid, 3),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        // In a conflicted merge, "ours" is HEAD's version.
        let head = index
            .iter()
            .find(|stage| stage.stage == 2)
            .map(|ours| Stage {
                stage: 0,
                ..ours.clone()
            });
        return Ok(Some(Candidate {
            path: path.to_owned(),
            origin: Origin::Tracked,
            head,
            index,
            staged: true,
            worktree_matches_index: false,
            intent_to_add: false,
        }));
    }
    Err(unexpected())
}

/// The outermost skip-list folder holding a relative path, as `folder/`.
fn skip_folder(path: &str) -> Option<String> {
    let mut components = path.trim_end_matches('/').split('/').collect::<Vec<_>>();
    // The last component of a file is its name, not a folder.
    if !path.ends_with('/') {
        components.pop();
    }
    let depth = components
        .iter()
        .position(|component| SKIP_LIST.contains(component))?;
    Some(format!("{}/", components[..=depth].join("/")))
}

/// The files a named path covers, relative to `top`: the file itself, or
/// every file under a folder.
fn named_files(top: &Path, path: &Path, deadline: Instant) -> Result<Vec<String>, Refusal> {
    let invalid = |detail: &str| Refusal::Invalid {
        detail: format!("{}: {detail}", path.display()),
    };
    let name = path.file_name().ok_or_else(|| invalid("names no file"))?;
    let parent = path.parent().ok_or_else(|| invalid("names no file"))?;
    let parent = fs::canonicalize(parent).map_err(|error| invalid(&error.to_string()))?;
    let absolute = parent.join(name);
    let relative = absolute
        .strip_prefix(top)
        .map_err(|_| invalid("is outside the project"))?
        .to_str()
        .ok_or_else(|| invalid("is not UTF-8"))?
        .to_owned();
    if relative.is_empty() || relative.split('/').any(|component| component == ".git") {
        return Err(invalid("is not a work tree file"));
    }
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| invalid(&error.to_string()))?;
    if !metadata.is_dir() {
        return Ok(vec![relative]);
    }
    let mut files = Vec::new();
    folder::walk(
        &absolute,
        deadline,
        &mut |file| {
            files.push(format!("{relative}/{file}"));
        },
        &mut |_| {},
    )?;
    Ok(files)
}

/// The version HEAD holds of each of `paths`, files only, as a stage-0
/// entry; empty for a path it lacks or an unborn HEAD.
pub(crate) fn head_entries(
    context: &Context,
    repository: &Repository,
    filters: &[String],
    paths: &[&str],
    deadline: Instant,
) -> Result<BTreeMap<String, Stage>, Refusal> {
    tree_entries(
        context,
        &repository.top,
        filters,
        "HEAD",
        paths,
        false,
        deadline,
    )
}

pub(crate) fn tree_entries(
    context: &Context,
    root: &Path,
    filters: &[String],
    tree: &str,
    paths: &[&str],
    recursive: bool,
    deadline: Instant,
) -> Result<BTreeMap<String, Stage>, Refusal> {
    let mut entries = BTreeMap::new();
    for chunk in paths.chunks(500) {
        let mut command = git::repository(&context.git, root, filters);
        command.arg("--literal-pathspecs").args(["ls-tree", "-z"]);
        if recursive {
            command.arg("-r");
        }
        command.args([tree, "--"]).args(chunk);
        let output = match git::output(command, Vec::new(), deadline) {
            Ok(output) => output,
            Err(GitFailure::Deadline) => return Err(Refusal::OverDeadline),
            // No commit yet.
            Err(GitFailure::Failed(_)) if tree == "HEAD" => return Ok(entries),
            Err(error) => return Err(error.repository()),
        };
        for record in records(&output)? {
            let Some((fields, path)) = record.split_once('\t') else {
                continue;
            };
            let mut fields = fields.split(' ');
            if let (Some(mode), Some(kind), Some(oid)) =
                (fields.next(), fields.next(), fields.next())
                && kind != "tree"
            {
                entries.insert(
                    path.to_owned(),
                    Stage {
                        mode: mode.to_owned(),
                        oid: oid.to_owned(),
                        stage: 0,
                    },
                );
            }
        }
    }
    Ok(entries)
}

/// Lines added and removed between HEAD and the work tree across `paths`,
/// `None` when there are too many to count on one command line.
pub(crate) fn lines_against_head(
    context: &Context,
    repository: &Repository,
    filters: &[String],
    paths: &[&str],
    deadline: Instant,
) -> Result<Option<u64>, Refusal> {
    if paths.is_empty() {
        return Ok(Some(0));
    }
    if paths.len() > LINE_COUNT_PATHS {
        return Ok(None);
    }
    // `diff-index`, not `diff`: porcelain `diff` writes a refreshed index when
    // it meets a file whose metadata alone changed, whatever
    // `--no-optional-locks` says.
    let mut command = git::repository(&context.git, &repository.top, filters);
    command.args([
        "diff-index",
        "--numstat",
        "-z",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "HEAD",
        "--",
    ]);
    command.args(paths.iter().map(|path| format!(":(literal){path}")));
    let output = git::output(command, Vec::new(), deadline).map_err(GitFailure::repository)?;
    let mut lines = 0;
    for record in records(&output)? {
        let mut fields = record.splitn(3, '\t');
        for count in [fields.next(), fields.next()].into_iter().flatten() {
            // A binary file counts `-`.
            lines += count.parse::<u64>().unwrap_or(0);
        }
    }
    Ok(Some(lines))
}

/// The sizes of the repository's objects `oids`, in order.
pub(crate) fn object_sizes(
    command: Command,
    oids: &[&str],
    deadline: Instant,
) -> Result<Vec<Option<u64>>, GitFailure> {
    let mut command = command;
    command.args(["cat-file", "--batch-check"]);
    let input = oids
        .iter()
        .flat_map(|oid| format!("{oid}\n").into_bytes())
        .collect();
    let output = git::output(command, input, deadline)?;
    let text = String::from_utf8_lossy(&output);
    Ok(text
        .lines()
        .map(|line| {
            let mut fields = line.split(' ');
            match (fields.next(), fields.next(), fields.next()) {
                (Some(_), Some(_), Some(size)) => size.parse().ok(),
                _ => None,
            }
        })
        .collect())
}

/// The content of each object `oids` names, read through `command` (a `git`
/// invocation without its subcommand), in order.
pub(crate) fn read_objects(
    command: Command,
    oids: &[&str],
    deadline: Instant,
) -> Result<Vec<Vec<u8>>, Refusal> {
    let mut command = command;
    command.args(["cat-file", "--batch"]);
    let input = oids
        .iter()
        .flat_map(|oid| format!("{oid}\n").into_bytes())
        .collect();
    let output = git::output(command, input, deadline).map_err(GitFailure::repository)?;
    let mut rest = &output[..];
    let mut objects = Vec::with_capacity(oids.len());
    for oid in oids {
        let missing = || Refusal::RepositoryUnreadable {
            detail: format!("object {oid} is missing"),
        };
        let header_end = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(missing)?;
        let header = std::str::from_utf8(&rest[..header_end]).map_err(|_| missing())?;
        let size = header
            .split(' ')
            .nth(2)
            .and_then(|size| size.parse::<usize>().ok())
            .ok_or_else(missing)?;
        let body = rest
            .get(header_end + 1..header_end + 1 + size)
            .ok_or_else(missing)?;
        objects.push(body.to_vec());
        rest = rest.get(header_end + 2 + size..).unwrap_or_default();
    }
    Ok(objects)
}
