//! What a discard would reach or write in a Git repository, asked before
//! the save copies anything: the files a pathspec matches, the repositories
//! nested in skip-list folders, the paths a revision tracks, the index's and
//! a revision's entries, and whether a submodule holds work of its own or a
//! revision's tree writes over it. Each reads the repository and never
//! writes it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{Context, Refusal, Stage, git, locate, store, work_tree};

/// The files git's `pathspecs` match when run in `directory` with the
/// pathspec mode `options` (such as `--icase-pathspecs`), as a command
/// there would take them: tracked, untracked and ignored alike, by path
/// relative to the work tree top, which it also returns. Each of `folders`
/// (relative to the top) the pathspecs match by its own path is there too,
/// ending in `/`: a checkout of a file at that path replaces it whole.
pub fn matching_files(
    context: &Context,
    directory: &Path,
    pathspecs: &[String],
    options: &[String],
    folders: &[String],
    deadline: Instant,
) -> Result<(PathBuf, BTreeSet<String>), Refusal> {
    let project = locate(context, directory, deadline)?;
    let Some(repository) = &project.repository else {
        return Err(Refusal::RepositoryUnreadable {
            detail: format!("{} is not in a git work tree", directory.display()),
        });
    };
    let store = store::open(&context.snapshots_dir, &project.id, deadline)?;
    let pending = store.begin()?;
    let files = work_tree::matching(
        context,
        repository,
        directory,
        pathspecs,
        options,
        folders,
        &pending.scratch().join("index"),
        deadline,
    )?;
    Ok((project.root, files))
}

/// The repositories of their own inside `folders`, relative to the work
/// tree top of `directory`, each ending in `/`: those a snapshot's skip-list
/// folders hide, which git finds without listing their files.
pub fn nested_repositories(
    context: &Context,
    directory: &Path,
    folders: &[String],
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let project = locate(context, directory, deadline)?;
    match &project.repository {
        Some(repository) if !folders.is_empty() => {
            work_tree::nested_repositories(context, repository, folders, deadline)
        }
        _ => Ok(Vec::new()),
    }
}

/// Whether the submodule at `path`, relative to the work tree top `root`,
/// holds work of its own, which no snapshot saves: a changed, staged or
/// untracked file. One not checked out holds none; one git cannot read is
/// taken to hold some.
pub fn submodule_changed(
    context: &Context,
    root: &Path,
    path: &str,
    deadline: Instant,
) -> Result<bool, Refusal> {
    let folder = root.join(path.trim_end_matches('/'));
    if fs::symlink_metadata(folder.join(".git")).is_err() {
        return Ok(false);
    }
    let repository = match work_tree::locate(context, &folder, deadline) {
        Ok(repository) => repository,
        Err(Refusal::OverDeadline) => return Err(Refusal::OverDeadline),
        Err(_) => return Ok(true),
    };
    if fs::canonicalize(&folder).ok().as_ref() != Some(&repository.top) {
        return Ok(true);
    }
    let filters = work_tree::filters(context, &repository, deadline)?;
    let mut command = git::repository(&context.git, &repository.top, &filters);
    command.args([
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ]);
    match git::output(command, Vec::new(), deadline) {
        Ok(listed) => Ok(!listed.is_empty()),
        Err(git::GitFailure::Deadline) => Err(Refusal::OverDeadline),
        Err(git::GitFailure::Failed(_)) => Ok(true),
    }
}

/// The files among `paths` (relative to the work tree top `root`, a folder
/// standing for the files under it) that the tree `revision` names tracks,
/// and the folders on their way it tracks as a file instead: those a
/// checkout of it writes. `None` when `revision` names no tree. Paths match
/// by `folded_path`, as on a filesystem that folds case and Unicode
/// normalization, where a checkout of `build` writes over `Build/`; the
/// files come back as the tree spells them.
pub fn tracked_by(
    context: &Context,
    root: &Path,
    revision: &str,
    paths: &[String],
    deadline: Instant,
) -> Result<Option<BTreeSet<String>>, Refusal> {
    let Some(tree) = revision_tree(context, root, revision, deadline)? else {
        return Ok(None);
    };
    if paths.is_empty() {
        return Ok(Some(BTreeSet::new()));
    }
    // With -t each folder is listed as its own entry too: a tree, or a file
    // or submodule that a checkout writes in place of the folder.
    let mut command = nah_observe::git_command(&context.git);
    command
        .arg("-C")
        .arg(root)
        .args(["ls-tree", "-r", "-t", "-z", &tree]);
    let listed = git::output(command, Vec::new(), deadline).map_err(git::GitFailure::repository)?;
    let paths = paths
        .iter()
        .map(|path| folded_path(path.trim_end_matches('/')))
        .collect::<Vec<_>>();
    let within = |path: &str, folder: &str| {
        path.strip_prefix(folder)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    Ok(Some(
        listed
            .split(|byte| *byte == 0)
            .filter_map(|record| {
                let record = String::from_utf8_lossy(record);
                let (meta, name) = record.split_once('\t')?;
                let folded = folded_path(name);
                let file = meta.split(' ').nth(1) != Some("tree");
                (file
                    && paths
                        .iter()
                        .any(|path| within(&folded, path) || within(path, &folded)))
                .then(|| name.to_owned())
            })
            .collect(),
    ))
}

/// `path` as a filesystem that folds case and Unicode normalization, as
/// macOS's does, names it: two paths with one folded form may be one file.
pub fn folded_path(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    path.nfd()
        .collect::<String>()
        .to_lowercase()
        .nfd()
        .collect()
}

/// The entries a revision holds at and under these paths.
pub fn revision_blobs(
    context: &Context,
    root: &Path,
    revision: &str,
    paths: &[&str],
    deadline: Instant,
) -> Result<Option<BTreeMap<String, Stage>>, Refusal> {
    let Some(tree) = revision_tree(context, root, revision, deadline)? else {
        return Ok(None);
    };
    work_tree::tree_entries(context, root, &[], &tree, paths, true, deadline).map(Some)
}

/// The current index entries at and under these paths.
pub fn index_entries(
    context: &Context,
    root: &Path,
    paths: &[&str],
    deadline: Instant,
) -> Result<BTreeMap<String, Vec<Stage>>, Refusal> {
    work_tree::index_entries(context, root, &[], paths, deadline)
}

fn revision_tree(
    context: &Context,
    root: &Path,
    revision: &str,
    deadline: Instant,
) -> Result<Option<String>, Refusal> {
    let mut command = nah_observe::git_command(&context.git);
    command
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
        .arg(format!("{revision}^{{tree}}"));
    match git::output(command, Vec::new(), deadline) {
        Ok(tree) => Ok(Some(String::from_utf8_lossy(&tree).trim().to_owned())),
        Err(git::GitFailure::Deadline) => Err(Refusal::OverDeadline),
        Err(git::GitFailure::Failed(_)) => Ok(None),
    }
}

/// The paths of the submodule commits the index of the work tree at the top
/// `root` stages, relative to it.
pub fn gitlinks(context: &Context, root: &Path, deadline: Instant) -> Result<Vec<String>, Refusal> {
    let mut command = nah_observe::git_command(&context.git);
    command
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--stage", "-z"]);
    let listed = git::output(command, Vec::new(), deadline).map_err(git::GitFailure::repository)?;
    Ok(listed
        .split(|byte| *byte == 0)
        .filter_map(|record| {
            let record = String::from_utf8_lossy(record);
            let (meta, path) = record.split_once('\t')?;
            meta.starts_with("160000 ").then(|| path.to_owned())
        })
        .collect())
}

/// Whether a checkout of the tree `revision` names writes over the submodule
/// at `path`, relative to the work tree top `root`: the tree has something
/// other than a submodule commit at `path`, or other than a folder at a
/// folder on its way. `tracked_by` cannot tell a submodule's own commit entry
/// from a file there. A revision that names no tree may write anything.
pub fn replaces_submodule(
    context: &Context,
    root: &Path,
    revision: &str,
    path: &str,
    deadline: Instant,
) -> Result<bool, Refusal> {
    if revision.starts_with('-') {
        return Ok(true);
    }
    let mut command = nah_observe::git_command(&context.git);
    command
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("{revision}^{{tree}}"));
    let tree = match git::output(command, Vec::new(), deadline) {
        Ok(tree) => String::from_utf8_lossy(&tree).trim().to_owned(),
        Err(git::GitFailure::Deadline) => return Err(Refusal::OverDeadline),
        Err(git::GitFailure::Failed(_)) => return Ok(true),
    };
    let path = path.trim_end_matches('/');
    let mut command = nah_observe::git_command(&context.git);
    command
        .arg("--literal-pathspecs")
        .arg("-C")
        .arg(root)
        .args(["ls-tree", "-z", &tree, "--"])
        .args(path.match_indices('/').map(|(slash, _)| &path[..slash]))
        .arg(path);
    let listed = git::output(command, Vec::new(), deadline).map_err(git::GitFailure::repository)?;
    Ok(listed.split(|byte| *byte == 0).any(|record| {
        let record = String::from_utf8_lossy(record);
        record.split_once('\t').is_some_and(|(meta, listed)| {
            let kind = meta.split(' ').nth(1);
            if listed == path {
                kind != Some("commit")
            } else {
                kind != Some("tree")
            }
        })
    }))
}
