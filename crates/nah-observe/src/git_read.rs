//! Filename-only observations for Git commands that print file contents.

use crate::git_state::{REDIRECTING_VARIABLES, filter_drivers_disabled, git_exit_and_output};
use crate::io_paths::canonical_absolute;
use crate::roots::GitWait;
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{
    GitReadKind, GitReadSelection, MAX_GIT_STATE_ENTRIES, ObservationFailure, Observed,
};
use std::path::Path;

pub(crate) const MAX_BYTES: u64 = 1024 * 1024;
const MAX_HISTORY_COMMITS: usize = 64;

pub(crate) fn observe_git_read(
    directory: &str,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
) -> Observed<Vec<AbsolutePath>> {
    match selected_paths(directory, selection, git, wait) {
        Ok(value) => Observed::Ok { value },
        Err(error) => Observed::Error { error },
    }
}

pub(crate) fn selected_paths(
    directory: &str,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
) -> Result<Vec<AbsolutePath>, ObservationFailure> {
    use GitReadKind::*;
    if REDIRECTING_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
        || selection.pathspec_options.iter().any(|option| {
            !matches!(
                option.as_str(),
                "--literal-pathspecs"
                    | "--no-literal-pathspecs"
                    | "--glob-pathspecs"
                    | "--noglob-pathspecs"
                    | "--icase-pathspecs"
            )
        })
        || selection
            .pathspecs
            .iter()
            .any(|path| path.is_empty() || path.contains('\0'))
    {
        return Err(ObservationFailure::Unavailable);
    }
    if selection
        .revisions
        .iter()
        .any(|rev| rev.is_empty() || rev.starts_with('-') || rev.contains(['\0', ':']))
        || matches!(selection.kind, Stash | StashUntracked | StashOnlyUntracked)
            && selection.revisions.len() != 1
        || selection.kind == RevisionGrep && selection.revisions.is_empty()
    {
        return Err(ObservationFailure::Unavailable);
    }
    let run = |args: &[&str]| git_exit_and_output(git, directory, args, MAX_BYTES, wait, &[]);
    if !selection.changes.is_empty() {
        return crate::staged_after::staged_after(directory, selection, git, wait);
    }
    // No-index grep works outside a repository. Its empty pattern asks only
    // which nonempty files it can search, never prints their lines, and does
    // not request textconv or recurse into submodules.
    let no_index = matches!(selection.kind, Directory | DirectoryExcluded);
    let root = if no_index {
        canonical_absolute(Path::new(directory)).map_err(|_| ObservationFailure::Unavailable)?
    } else {
        let (code, bytes) = run(&["rev-parse", "--show-toplevel"])?;
        if code != Some(0) {
            return Err(ObservationFailure::Unavailable);
        }
        let text = String::from_utf8(bytes).map_err(|_| ObservationFailure::NonUnicode)?;
        canonical_absolute(Path::new(text.trim_end_matches(['\r', '\n'])))
            .map_err(|_| ObservationFailure::Unavailable)?
    };
    let mut pathspecs = command_pathspecs(directory, &root, selection)?;
    // Positive Git pathspecs are a union, so appending these to the user's
    // patterns would widen the search. Ask only for credential candidates,
    // then intersect that small answer with the original pathspecs below.
    let magic = if crate::io_paths::host_platform() == nah_proto::ctx::Platform::Windows {
        ":(glob,icase)"
    } else {
        ":(glob)"
    };
    // What `git add` or a commit stages is asked for every file a name alone
    // labels secret, a private key or stored credential too; a read that
    // prints contents only for environment files.
    let staging = matches!(
        selection.kind,
        Addable | AddableAll | AddableTracked | AddableHead | Renormalized
    );
    let names: &[&str] = if staging {
        &[
            ".env",
            ".env.*",
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
    } else {
        &[".env", ".env.*", ".pypirc", ".pgpass", ".boto"]
    };
    let candidates = names
        .iter()
        .map(|name| format!("{magic}**/{name}"))
        .collect::<Vec<_>>();
    let stash = matches!(selection.kind, Stash | StashUntracked | StashOnlyUntracked);
    let mut args = Vec::new();
    // Porcelain diff rewrites the index when a tracked file's metadata alone
    // changed, whatever `--no-optional-locks` says. Status compares the same
    // contents and honors it, so the changed paths come from status.
    let status = matches!(
        selection.kind,
        Diff | StagedDiff | HeadDiff | Addable | AddableAll | AddableTracked | AddableHead
    );
    let filters = if status {
        filter_drivers_disabled(git, directory, wait)?
    } else {
        Vec::new()
    };
    if status {
        args.extend(filters.iter().cloned());
        args.extend(
            [
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "-z",
                "--no-renames",
                "--ignore-submodules=all",
            ]
            .map(str::to_owned),
        );
        args.extend(
            match selection.kind {
                Addable => ["--untracked-files=all", "--ignored=no"],
                AddableAll => ["--untracked-files=all", "--ignored=traditional"],
                _ => ["--untracked-files=no", "--ignored=no"],
            }
            .map(str::to_owned),
        );
    } else if matches!(selection.kind, Commit | History | RevisionGrep) {
        // Historical reads are answered below without reading the worktree.
    } else if stash {
        // Stash show does not accept pathspecs. Its trees are queried below.
    } else if no_index {
        args.extend(
            ["grep", "--no-index", "--no-textconv", "-l", "-z", "-e", ""].map(str::to_owned),
        );
        if selection.kind == DirectoryExcluded {
            args.push("--exclude-standard".into());
        }
    } else {
        args.extend(["ls-files", "--cached", "--full-name", "-z"].map(str::to_owned));
        if matches!(selection.kind, Untracked | UntrackedAll) {
            args.push("--others".into());
        }
        if selection.kind == Untracked {
            args.push("--exclude-standard".into());
        }
    }
    args.push("--".into());
    args.extend(candidates.iter().cloned());
    args.splice(0..0, excludes_options(selection, git, directory, wait)?);
    // Diff/show without a pathspec range over the whole worktree, even from
    // a subdirectory. The matcher retains grep's implicit cwd restriction.
    let (code, bytes) = if matches!(selection.kind, Commit | History) {
        (
            Some(0),
            history_output(directory, root.as_str(), selection, git, wait, &candidates)?,
        )
    } else if selection.kind == RevisionGrep {
        (
            Some(0),
            revision_grep_output(root.as_str(), selection, git, wait, &candidates)?,
        )
    } else if stash {
        (
            Some(0),
            stash_output(root.as_str(), selection, git, wait, &candidates)?,
        )
    } else {
        git_exit_and_output(
            git,
            root.as_str(),
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            MAX_BYTES,
            wait,
            &[],
        )?
    };
    if code != Some(0) && !(no_index && code == Some(1)) {
        return Err(ObservationFailure::Unavailable);
    }
    let bytes = if status {
        status_paths(selection.kind, &bytes, |path| {
            worktree_matches_head(git, root.as_str(), path, &filters, wait)
        })?
    } else {
        bytes
    };
    let text = String::from_utf8(bytes).map_err(|_| ObservationFailure::NonUnicode)?;
    let secret = if staging {
        nah_proto::labels::sensitivity::secret_file
    } else {
        nah_proto::labels::sensitivity::environment_file
    };
    let mut paths = Vec::new();
    for path in text.split_terminator('\0') {
        if wait.timeout().is_zero() {
            return Err(ObservationFailure::Timeout);
        }
        // Git's repository paths are lexical: a deleted file still has a
        // credential name in the patch, and an index entry need not exist.
        if path.is_empty()
            || Path::new(path).is_absolute()
            || path.split('/').any(|part| part == "..")
        {
            return Err(ObservationFailure::Unavailable);
        }
        if !secret(path, crate::io_paths::host_platform())
            || !selection
                .revision_options
                .iter()
                .any(|option| option == "--follow")
                && pathspecs
                    .pattern_matching_relative_path(path.into(), Some(false), &mut |_, _, _, _| {
                        false
                    })
                    .is_none_or(|matched| matched.is_excluded())
        {
            continue;
        }
        let joined = Path::new(root.as_str()).join(path);
        // A diff counts a work-tree file it could not read as changed, as
        // it could not read a dataless one: whether that one changed is not
        // known. A git add selection keeps such a path, since staging it
        // reads the file and the selection's labels then fail closed.
        if matches!(selection.kind, Diff | HeadDiff)
            && std::fs::symlink_metadata(&joined)
                .is_ok_and(|metadata| crate::io_paths::dataless(&joined, &metadata))
        {
            return Err(ObservationFailure::Unavailable);
        }
        if matches!(
            selection.kind,
            Tracked
                | Renormalized
                | Untracked
                | UntrackedAll
                | Addable
                | AddableAll
                | AddableTracked
                | AddableHead
        ) && !std::fs::symlink_metadata(&joined).is_ok_and(|meta| meta.is_file())
        {
            continue;
        }
        paths.push(
            AbsolutePath::new(crate::io_paths::host_platform(), joined.to_string_lossy())
                .map_err(|_| ObservationFailure::Unavailable)?,
        );
    }
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_GIT_STATE_ENTRIES {
        return Err(ObservationFailure::Unavailable);
    }
    Ok(paths)
}

/// The options that leave a global excludes file's rules out of what Git
/// answers for `selection`, where the call changes which configuration
/// files Git reads: those rules can only leave files out, and the files the
/// call names are not the ones this process sees. The excludes file the
/// repository's own configuration names still decides, as it outranks
/// those files (`repository_excludes_file`).
pub(crate) fn excludes_options(
    selection: &GitReadSelection,
    git: &Path,
    directory: &str,
    wait: GitWait,
) -> Result<Vec<String>, ObservationFailure> {
    if !selection.user_configuration_changed {
        return Ok(Vec::new());
    }
    let file = repository_excludes_file(git, directory, wait)?;
    Ok(vec![
        "-c".into(),
        format!(
            "core.excludesFile={}",
            file.as_deref().unwrap_or("/dev/null")
        ),
    ])
}

/// The `core.excludesFile` the configuration of the repository at
/// `directory` itself sets, its local or worktree file, as `git config
/// --path` spells it (a relative path is Git's from the top level), and
/// none where only the global or system files set it.
pub(crate) fn repository_excludes_file(
    git: &Path,
    directory: &str,
    wait: GitWait,
) -> Result<Option<String>, ObservationFailure> {
    let (code, bytes) = git_exit_and_output(
        git,
        directory,
        &[
            "config",
            "--includes",
            "--show-scope",
            "--path",
            "-z",
            "--get-all",
            "core.excludesFile",
        ],
        MAX_BYTES,
        wait,
        &[],
    )?;
    match code {
        Some(0) => {}
        Some(1) => return Ok(None),
        _ => return Err(ObservationFailure::Unavailable),
    }
    let text = String::from_utf8(bytes).map_err(|_| ObservationFailure::NonUnicode)?;
    let fields = text.split_terminator('\0').collect::<Vec<_>>();
    if fields.len() % 2 != 0 {
        return Err(ObservationFailure::Unavailable);
    }
    // Scope and value in turn, lowest precedence first: the last one the
    // repository sets wins.
    Ok(fields
        .chunks(2)
        .filter(|pair| matches!(pair[0], "local" | "worktree"))
        .next_back()
        .map(|pair| pair[1].to_owned()))
}

/// The paths of a status listing that `kind` selects, NUL-terminated: a
/// diff's work tree changes, a cached diff's index changes, and for `git
/// add` every path whose work tree file differs from the index, untracked
/// (and with `AddableAll` ignored) ones included unless `AddableTracked`.
/// A diff against `HEAD`, and what a commit of pathspecs alone takes
/// (`AddableHead`), take a path changed on one side only; one changed
/// in both the index and the work tree may have returned to what `HEAD`
/// holds, which `same_as_head` answers.
fn status_paths(
    kind: GitReadKind,
    listing: &[u8],
    mut same_as_head: impl FnMut(&str) -> Result<bool, ObservationFailure>,
) -> Result<Vec<u8>, ObservationFailure> {
    let mut paths = Vec::new();
    for entry in listing
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let [index, worktree, b' ', path @ ..] = entry else {
            return Err(ObservationFailure::Unavailable);
        };
        let selected = match kind {
            GitReadKind::StagedDiff => *index != b' ',
            GitReadKind::HeadDiff | GitReadKind::AddableHead
                if *index != b' ' && *worktree != b' ' =>
            {
                !same_as_head(
                    std::str::from_utf8(path).map_err(|_| ObservationFailure::NonUnicode)?,
                )?
            }
            GitReadKind::HeadDiff | GitReadKind::AddableHead => *index != b' ' || *worktree != b' ',
            _ => *worktree != b' ',
        };
        if selected {
            paths.extend_from_slice(path);
            paths.push(0);
        }
    }
    Ok(paths)
}

/// Whether the work tree file at `path`, relative to the top level `root`,
/// holds what `HEAD` records there, compared as `git diff HEAD` compares
/// them: the file's bytes through the repository's conversions (with
/// `filters` disabling its drivers) against the recorded blob. A path one
/// side lacks differs unless both lack it; anything but a regular file is
/// taken to differ. Neither command writes the repository.
fn worktree_matches_head(
    git: &Path,
    root: &str,
    path: &str,
    filters: &[String],
    wait: GitWait,
) -> Result<bool, ObservationFailure> {
    let object = |args: &[&str]| -> Result<Option<Vec<u8>>, ObservationFailure> {
        match git_exit_and_output(git, root, args, MAX_BYTES, wait, &[])? {
            (Some(0), output) => Ok(Some(output)),
            (Some(1), _) => Ok(None),
            _ => Err(ObservationFailure::Unavailable),
        }
    };
    let head = object(&["rev-parse", "--verify", "--quiet", &format!("HEAD:{path}")])?;
    let worktree = match std::fs::symlink_metadata(Path::new(root).join(path)) {
        Ok(meta) if meta.is_file() => {
            let mut args = filters.iter().map(String::as_str).collect::<Vec<_>>();
            let named = format!("--path={path}");
            args.extend(["hash-object", &named, "--", path]);
            Some(object(&args)?.ok_or(ObservationFailure::Unavailable)?)
        }
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(ObservationFailure::Unavailable),
    };
    Ok(head == worktree)
}

/// Discover at most one more commit than we can inspect. Limiting after a
/// credential path filter would select older commits that `log -n` never reads.
fn history_output(
    directory: &str,
    root: &str,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
    candidates: &[String],
) -> Result<Vec<u8>, ObservationFailure> {
    let mut options = Vec::new();
    let mut limit = MAX_HISTORY_COMMITS + 1;
    let mut words = selection.revision_options.iter();
    while let Some(option) = words.next() {
        let (name, attached) = option
            .split_once('=')
            .map_or((option.as_str(), None), |(name, value)| (name, Some(value)));
        match name {
            "-n" | "--max-count" => {
                let value = attached
                    .or_else(|| words.next().map(String::as_str))
                    .ok_or(ObservationFailure::Unavailable)?;
                limit = value
                    .parse::<usize>()
                    .map_err(|_| ObservationFailure::Unavailable)?
                    .min(MAX_HISTORY_COMMITS + 1);
            }
            "--skip" | "--since" | "--after" | "--until" | "--before" => {
                options.push(option.as_str());
                if attached.is_none() {
                    options.push(
                        words
                            .next()
                            .ok_or(ObservationFailure::Unavailable)?
                            .as_str(),
                    );
                }
            }
            "--follow"
            | "--all"
            | "--branches"
            | "--tags"
            | "--remotes"
            | "--no-merges"
            | "--merges"
            | "--reverse"
            | "--topo-order"
            | "--date-order"
            | "--author-date-order" => options.push(option.as_str()),
            _ => {
                let value = option
                    .strip_prefix("-n")
                    .or_else(|| option.strip_prefix('-'))
                    .ok_or(ObservationFailure::Unavailable)?;
                limit = value
                    .parse::<usize>()
                    .map_err(|_| ObservationFailure::Unavailable)?
                    .min(MAX_HISTORY_COMMITS + 1);
            }
        }
    }
    let limit = format!("--max-count={limit}");
    let mut args = selection
        .pathspec_options
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    args.extend([
        "log",
        "--no-show-signature",
        "--no-ext-diff",
        "--no-textconv",
        "--no-decorate",
    ]);
    args.extend(options);
    args.push(&limit);
    // --max-count enables walking, so restore show's no-walk default after
    // it. Explicit ranges still enable a walk when Git parses the revisions.
    if selection.kind == GitReadKind::Commit {
        args.push("--no-walk=unsorted");
    }
    let format_at = args.len();
    args.extend(["--format=%H", "--no-patch"]);
    if selection.revisions.is_empty()
        && !selection.revision_options.iter().any(|option| {
            matches!(
                option.as_str(),
                "--all" | "--branches" | "--tags" | "--remotes"
            ) || option.starts_with("--branches=")
                || option.starts_with("--tags=")
                || option.starts_with("--remotes=")
        })
    {
        args.push("HEAD");
    }
    args.extend(selection.revisions.iter().map(String::as_str));
    args.push("--");
    args.extend(selection.pathspecs.iter().map(String::as_str));
    let run = |args: &[&str]| git_exit_and_output(git, directory, args, MAX_BYTES, wait, &[]);
    let (code, commits) = run(&args)?;
    if code != Some(0) {
        return Err(ObservationFailure::Unavailable);
    }
    let text = std::str::from_utf8(&commits).map_err(|_| ObservationFailure::NonUnicode)?;
    if text.lines().count() > MAX_HISTORY_COMMITS {
        return Err(ObservationFailure::Unavailable);
    }
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if selection
        .revision_options
        .iter()
        .any(|option| option == "--follow")
    {
        // Follow's selected path changes across renames. Let Git name both
        // sides, with the original pathspec, rather than matching old names
        // against the path that exists today.
        args[format_at] = "--format=";
        args[format_at + 1] = "--name-status";
        args.insert(format_at + 2, "-z");
        let (code, bytes) = run(&args)?;
        if code != Some(0) {
            return Err(ObservationFailure::Unavailable);
        }
        let mut output = Vec::new();
        let mut fields = bytes
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty());
        while let Some(status) = fields.next() {
            let count = if matches!(status.first(), Some(b'R' | b'C')) {
                2
            } else {
                1
            };
            for _ in 0..count {
                output.extend_from_slice(fields.next().ok_or(ObservationFailure::Unavailable)?);
                output.push(0);
            }
        }
        return Ok(output);
    }
    if !text.lines().all(|hash| {
        matches!(hash.len(), 40 | 64) && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(ObservationFailure::Unavailable);
    }
    let mut diff = vec![
        "diff-tree",
        "--stdin",
        "--root",
        "--no-commit-id",
        "-r",
        "--name-only",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--no-relative",
        "--ignore-submodules=all",
    ];
    diff.push(if selection.kind == GitReadKind::Commit {
        "--cc"
    } else {
        "--no-diff-merges"
    });
    diff.push("--");
    diff.extend(candidates.iter().map(String::as_str));
    let (code, bytes) = git_exit_and_output(git, root, &diff, MAX_BYTES, wait, &commits)?;
    if code != Some(0) {
        return Err(ObservationFailure::Unavailable);
    }
    Ok(bytes)
}

fn revision_grep_output(
    directory: &str,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
    candidates: &[String],
) -> Result<Vec<u8>, ObservationFailure> {
    let mut args = vec![
        "grep",
        "--no-textconv",
        "--no-recurse-submodules",
        "-l",
        "-z",
        "-e",
        "",
    ];
    args.extend(selection.revisions.iter().map(String::as_str));
    args.push("--");
    args.extend(candidates.iter().map(String::as_str));
    let (code, bytes) = git_exit_and_output(git, directory, &args, MAX_BYTES, wait, &[])?;
    if !matches!(code, Some(0 | 1)) {
        return Err(ObservationFailure::Unavailable);
    }
    let mut output = Vec::new();
    for path in bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
    {
        let colon = path
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(ObservationFailure::Unavailable)?;
        output.extend_from_slice(&path[colon + 1..]);
        output.push(0);
    }
    Ok(output)
}

fn stash_output(
    directory: &str,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
    candidates: &[String],
) -> Result<Vec<u8>, ObservationFailure> {
    if !selection.pathspecs.is_empty() {
        return Err(ObservationFailure::Unavailable);
    }
    let revision = &selection.revisions[0];
    let revision = if revision.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("stash@{{{revision}}}")
    } else {
        revision.to_owned()
    };
    let run = |args: &[&str]| git_exit_and_output(git, directory, args, MAX_BYTES, wait, &[]);
    // Like stash show, require a stash-like commit with an index parent.
    if run(&["rev-parse", "--verify", "--quiet", &format!("{revision}^2")])?.0 != Some(0) {
        return Err(ObservationFailure::Unavailable);
    }
    let include_untracked = match selection.kind {
        GitReadKind::Stash => {
            match run(&[
                "config",
                "--type=bool",
                "--get",
                "stash.showIncludeUntracked",
            ])? {
                (Some(0), value) if value == b"true\n" => true,
                (Some(0), value) if value == b"false\n" => false,
                (Some(1), _) => false,
                _ => return Err(ObservationFailure::Unavailable),
            }
        }
        _ => true,
    };
    let mut trees = Vec::new();
    if selection.kind != GitReadKind::StashOnlyUntracked {
        trees.push(vec![format!("{revision}^1"), revision.clone()]);
    }
    if include_untracked {
        let third_parent = format!("{revision}^3");
        match run(&["rev-parse", "--verify", "--quiet", &third_parent])?.0 {
            Some(0) => trees.push(vec![third_parent]),
            Some(1) => {}
            _ => return Err(ObservationFailure::Unavailable),
        }
    }
    let mut output = Vec::new();
    for tree in trees {
        let mut args = [
            "diff-tree",
            "--root",
            "--no-commit-id",
            "-r",
            "--name-only",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--no-relative",
            "--ignore-submodules=all",
        ]
        .map(str::to_owned)
        .to_vec();
        args.extend(tree);
        args.push("--".into());
        args.extend_from_slice(candidates);
        let (code, bytes) = run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        if code != Some(0) || output.len() + bytes.len() > MAX_BYTES as usize {
            return Err(ObservationFailure::Unavailable);
        }
        output.extend(bytes);
    }
    Ok(output)
}

pub(crate) fn command_pathspecs(
    directory: &str,
    root: &AbsolutePath,
    selection: &GitReadSelection,
) -> Result<gix_pathspec::Search, ObservationFailure> {
    use gix_pathspec::{Defaults, MagicSignature, SearchMode};
    let mut defaults = Defaults::default();
    let (mut glob, mut noglob) = (false, false);
    for option in &selection.pathspec_options {
        match option.as_str() {
            "--literal-pathspecs" => defaults.literal = true,
            "--no-literal-pathspecs" => defaults.literal = false,
            "--glob-pathspecs" => glob = true,
            "--noglob-pathspecs" => noglob = true,
            "--icase-pathspecs" => defaults.signature |= MagicSignature::ICASE,
            _ => return Err(ObservationFailure::Unavailable),
        }
    }
    if glob && noglob || defaults.literal && (glob || noglob) {
        return Err(ObservationFailure::Unavailable);
    }
    defaults.search_mode = if noglob {
        SearchMode::Literal
    } else if glob {
        SearchMode::PathAwareGlob
    } else {
        SearchMode::ShellGlob
    };
    let mut patterns = selection
        .pathspecs
        .iter()
        .map(|path| gix_pathspec::parse(path.as_bytes(), defaults))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ObservationFailure::Unavailable)?;
    // Attribute requirements need observed .gitattributes; a missing
    // attribute answer must not be mistaken for an empty selection.
    if patterns
        .iter()
        .any(|pattern| !pattern.attributes.is_empty())
    {
        return Err(ObservationFailure::Unavailable);
    }
    let prefix = canonical_absolute(Path::new(directory))?;
    let prefix = Path::new(prefix.as_str())
        .strip_prefix(root.as_str())
        .map_err(|_| ObservationFailure::Unavailable)?;
    let whole_tree = selection.pathspecs.is_empty()
        && matches!(
            selection.kind,
            GitReadKind::Diff
                | GitReadKind::StagedDiff
                | GitReadKind::HeadDiff
                | GitReadKind::Addable
                | GitReadKind::AddableAll
                | GitReadKind::AddableTracked
                | GitReadKind::AddableHead
                | GitReadKind::Commit
                | GitReadKind::History
                | GitReadKind::Stash
                | GitReadKind::StashUntracked
                | GitReadKind::StashOnlyUntracked
        );
    if matches!(
        selection.kind,
        GitReadKind::RevisionGrep
            | GitReadKind::Tracked
            | GitReadKind::Renormalized
            | GitReadKind::Cached
            | GitReadKind::Untracked
            | GitReadKind::UntrackedAll
    ) && patterns.iter().all(gix_pathspec::Pattern::is_excluded)
        && !patterns.is_empty()
    {
        // With exclusions alone grep still starts in its cwd; diff's
        // implicit positive selection instead spans the whole repository.
        patterns.push(gix_pathspec::Pattern::from_literal(
            b"",
            MagicSignature::empty(),
        ));
    }
    // A normalized root spelling such as "." means every path. Represent
    // it with an empty top-level pattern so it has no literal prefix.
    for pattern in &mut patterns {
        let mut normalized = pattern.clone();
        normalized
            .normalize(prefix, Path::new(root.as_str()))
            .map_err(|_| ObservationFailure::Unavailable)?;
        if normalized.is_nil() {
            let path = if normalized.path() == "." {
                b"".as_slice()
            } else {
                normalized.path().as_ref()
            };
            *pattern = gix_pathspec::Pattern::from_literal(
                path,
                (pattern.signature | MagicSignature::TOP) - MagicSignature::ICASE,
            );
        }
    }
    gix_pathspec::Search::from_specs(
        patterns,
        (!whole_tree).then_some(prefix),
        Path::new(root.as_str()),
    )
    .map_err(|_| ObservationFailure::Unavailable)
}
