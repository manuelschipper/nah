//! Observes what a Git repository holds that is in no commit.

use crate::io_paths::{canonical_absolute, dataless};
use crate::ref_deletion::{ListedRef, deleted_reflogs, deleted_refs};
use crate::roots::{ChildExt, GitWait, git_command};
use nah_proto::observation::{
    GitCleanIgnored, GitHistoryObservation, GitRestoreSource, GitStateObservation,
    MAX_GIT_STATE_ENTRIES, ObservationFailure, Observed, RefDeletion,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Instant;

/// Most bytes of `git status` output read: more is a tree too large to list.
const STATUS_MAX_BYTES: u64 = 1024 * 1024;

/// Most bytes of the index listing read, which names every tracked file.
const INDEX_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Git's options that set how it reads every pathspec.
const PATHSPEC_OPTIONS: [&str; 5] = [
    "--literal-pathspecs",
    "--no-literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
];

/// Most bytes of a ref listing read.
const REFS_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Variables that point Git at a repository other than the one found from
/// the directory it runs in.
pub(crate) const REDIRECTING_VARIABLES: [&str; 4] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
];

/// The state of the repository Git finds from `directory` that decides
/// whether a discard loses anything: whether the stash holds an entry, with
/// `restores`, whether a copy from that source would change nothing it
/// reaches (`restores_nothing`), and with `untracked`, whether Git lists an
/// untracked entry of that kind. It also says which stash entries another
/// ref reaches, whether the refs left after `deleted_refs` keep what those
/// reach, and with `inspect_history`, whether a rewrite of its history
/// leaves the commits it replaces in reach, and which of `head_targets`
/// already reach `HEAD`'s commit. With `pathspecs`, only what they match
/// counts, as Git reads them in `directory` by the pathspec mode options
/// `pathspec_options`; without, the whole tree.
///
/// Every answer comes from Git's plumbing (`ls-files`, `check-attr`,
/// `diff-index`), whose output no presentation setting changes, with the
/// settings that could narrow it turned off, and from the working copies'
/// own bytes, which `hash-object --no-filters` compares with the index:
/// never the metadata Git's own comparison trusts.
///
/// The commands a caller asks about inherit the caller's environment, which
/// this observation does not: when that environment points Git at another
/// repository, the state observed here is not the state they act on, so
/// nothing is reported.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_git_state(
    directory: &str,
    pathspecs: &[String],
    pathspec_options: &[String],
    restores: Option<&GitRestoreSource>,
    untracked: Option<GitCleanIgnored>,
    inspect_history: bool,
    head_targets: &[String],
    deleted_refs: &[RefDeletion],
    git: &Path,
    wait: GitWait,
) -> Observed<GitStateObservation> {
    let unavailable = |error| Observed::Error { error };
    // Git runs with these before its command, where any other word could
    // change what it runs.
    if REDIRECTING_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
        || !pathspec_options
            .iter()
            .all(|option| PATHSPEC_OPTIONS.contains(&option.as_str()))
    {
        return unavailable(ObservationFailure::Unavailable);
    }
    // A folder that holds a deleted path may be gone, or never was. With
    // only absolute pathspecs, which mean the same paths from any folder
    // whatever magic they carry, Git finds the same repository from the
    // nearest folder above it that exists.
    let directory = match pathspecs {
        [_, ..]
            if pathspecs.iter().all(|pathspec| {
                let path = match pathspec.strip_prefix(":(") {
                    Some(magic) => magic.split_once(')').map_or("", |(_, path)| path),
                    None => pathspec,
                };
                Path::new(path).is_absolute()
            }) =>
        {
            match Path::new(directory)
                .ancestors()
                .find(|folder| folder.is_dir())
                .and_then(Path::to_str)
            {
                Some(folder) => folder,
                None => return unavailable(ObservationFailure::Unavailable),
            }
        }
        _ => directory,
    };
    // The repository is the one Git finds above `directory`, so every later
    // answer is about the tree that starts at its top level, not at
    // `directory`. The same rev-parse prints the top level and the common
    // Git directory, then the stash commit, and exits 0 if the stash exists,
    // or prints only the first two and exits 1 if it does not. Other exits
    // leave the repository state unknown.
    let (top_level, stash_tip) = match git_exit_and_output(
        git,
        directory,
        &[
            "rev-parse",
            "--show-toplevel",
            "--git-common-dir",
            "--verify",
            "--quiet",
            "refs/stash",
        ],
        STATUS_MAX_BYTES,
        wait,
        &[],
    ) {
        Ok((Some(code @ (0 | 1)), output)) => {
            let stash_entries = code == 0;
            let lines = String::from_utf8(output).ok().and_then(|text| {
                let lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
                let expected = if stash_entries { 3 } else { 2 };
                (lines.len() == expected
                    && lines
                        .iter()
                        .all(|line| !line.is_empty() && !line.contains('\r')))
                .then_some(lines)
            });
            let Some(lines) = lines else {
                return unavailable(ObservationFailure::Unavailable);
            };
            // Git answers a stash reference it cannot read, as it cannot
            // read a dataless one, exactly as one that is not there, and the
            // filter list read below as empty for a configuration it cannot
            // read. Only the reference's absence from the common directory,
            // with a packed list and a configuration Git could read, shows
            // there is no stash and no filter.
            let common = Path::new(directory).join(&lines[1]);
            let is_dataless = |path: &Path| {
                fs::symlink_metadata(path).is_ok_and(|metadata| dataless(path, &metadata))
            };
            if is_dataless(&common.join("config"))
                || !stash_entries
                    && (fs::symlink_metadata(common.join("refs/stash")).is_ok()
                        || is_dataless(&common.join("packed-refs")))
            {
                return unavailable(ObservationFailure::Unavailable);
            }
            (
                canonical_absolute(Path::new(&lines[0])).ok(),
                stash_entries.then(|| lines[2].clone()),
            )
        }
        Ok(_) => (None, None),
        Err(error) => return unavailable(error),
    };
    let Some(top_level) = top_level else {
        return unavailable(ObservationFailure::Unavailable);
    };
    // Comparing a tracked file whose metadata changed reads its contents,
    // which runs the filter drivers the repository's configuration names.
    let filters = match filter_drivers_disabled(git, directory, wait) {
        Ok(filters) => filters,
        Err(error) => return unavailable(error),
    };
    // `--no-optional-locks` keeps Git from writing a refreshed index.
    // `diff.relative` would narrow a diff to the folder it runs in.
    let mut global = vec!["--no-optional-locks", "-c", "diff.relative=false"];
    global.extend(filters.iter().map(String::as_str));
    global.extend(pathspec_options.iter().map(String::as_str));
    let limit = std::iter::once("--")
        .chain(pathspecs.iter().map(String::as_str))
        .collect::<Vec<_>>();
    // Pathspecs are read where the discard runs; the whole tree is listed
    // from its top level.
    let run_in = if pathspecs.is_empty() {
        top_level.as_str()
    } else {
        directory
    };
    let run = |words: &[&str], max_bytes| {
        let mut args = global.clone();
        args.extend(words);
        args.extend(&limit);
        git_exit_and_output(git, run_in, &args, max_bytes, wait, &[])
    };
    let mut state = GitStateObservation::new(top_level.clone(), stash_tip.is_some());
    if let Some(restores) = restores {
        state = match restores_nothing(
            &run,
            &global,
            restores,
            git,
            run_in,
            top_level.as_str(),
            wait,
        ) {
            Ok(nothing) => state.with_restores_nothing(nothing),
            Err(error) => return unavailable(error),
        };
    }
    // Git matches a name by its bytes, ASCII letters aside under `icase`,
    // while a filesystem that folds case or normalises Unicode also reaches
    // an entry through another spelling, which Git then does not list.
    if restores.is_some()
        && !pathspecs.iter().all(|pathspec| {
            match pathspec
                .strip_prefix(":(")
                .and_then(|magic| magic.split_once(')'))
            {
                Some((magic, path))
                    if magic.split(',').any(|word| word == "literal")
                        && Path::new(path).is_absolute() =>
                {
                    spelled_as_listed(Path::new(top_level.as_str()), Path::new(path))
                }
                _ => true,
            }
        })
    {
        state = state.with_restores_nothing(false);
    }
    if let Some(kind) = untracked {
        // A folder none of whose contents are tracked is one entry; an
        // empty one holds nothing to lose.
        let mut listing = vec![
            "ls-files",
            "-z",
            "--others",
            "--directory",
            "--no-empty-directory",
        ];
        listing.extend(match kind {
            GitCleanIgnored::No => &["--exclude-standard"][..],
            GitCleanIgnored::Also => &[],
            GitCleanIgnored::Only => &["--ignored", "--exclude-standard"],
        });
        state = match run(&listing, STATUS_MAX_BYTES) {
            Ok((Some(0), listed)) => state.with_untracked(!listed.is_empty()),
            Ok(_) => return unavailable(ObservationFailure::Unavailable),
            Err(error) => return unavailable(error),
        };
    }
    if let Some(tip) = &stash_tip
        && let Some(reached) = stash_reached(git, directory, tip, wait)
    {
        match state.with_stash_reached(reached) {
            Ok(read) => state = read,
            Err(_) => return unavailable(ObservationFailure::Unavailable),
        }
    }
    if inspect_history {
        match history(git, directory, head_targets, wait) {
            Ok(history) => state = state.with_history(history),
            Err(error) => return unavailable(error),
        }
    }
    if !deleted_refs.is_empty()
        && let Some(reached) = deleted_refs_reached(git, directory, deleted_refs, wait)
    {
        state = state.with_deleted_refs_reached(reached);
    }
    Observed::Ok { value: state }
}

/// Runs Git with the observation's options, in its directory, on its
/// pathspecs, reading at most the bytes given: its exit code and output.
type GitRun<'a> = dyn Fn(&[&str], u64) -> Result<(Option<i32>, Vec<u8>), ObservationFailure> + 'a;

/// Whether a copy from `source` into what `run` limits Git to changes
/// nothing: every index entry there is a plain, merged file or symlink that
/// the index does not hide from comparison (assume-unchanged, skip-worktree)
/// and whose path no other entry could share on a case-folding or
/// normalizing filesystem, Git converts no bytes of it on the way to the
/// working tree, its working copy holds its bytes (`working_copies_match`),
/// and, for a tree, the index equals that tree. Any doubt answers `false`. `global` holds the options
/// `run` gives Git before its command, in `directory`; `top` is the top
/// level, from which the listed paths are named and their files read.
#[allow(clippy::too_many_arguments)]
fn restores_nothing(
    run: &GitRun<'_>,
    global: &[&str],
    source: &GitRestoreSource,
    git: &Path,
    directory: &str,
    top: &str,
    wait: GitWait,
) -> Result<bool, ObservationFailure> {
    // Named from the top level, as `hash-object --stdin-paths` reads a path
    // wherever it runs.
    let listed = match run(
        &["ls-files", "--full-name", "-v", "-s", "-z"],
        INDEX_MAX_BYTES,
    )? {
        (Some(0), listed) => listed,
        _ => return Err(ObservationFailure::Unavailable),
    };
    // Each name a path takes on a filesystem that folds case, and the
    // spelling it has there: a file and the folders above it.
    let mut spellings = std::collections::BTreeMap::<String, String>::new();
    let mut paths = Vec::new();
    let mut entries = Vec::new();
    for entry in listed
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        // `H <mode> <object> <stage>\t<path>`.
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            return Err(ObservationFailure::Unavailable);
        };
        let (fields, path) = (&entry[..tab], &entry[tab + 1..]);
        let fields = fields.split(|byte| *byte == b' ').collect::<Vec<_>>();
        let plain = matches!(
            &fields[..],
            [b"H", b"100644" | b"100755" | b"120000", _, b"0"]
        );
        if !plain || !path.is_ascii() {
            return Ok(false);
        }
        paths.extend(path.iter().chain([&0]));
        let path = String::from_utf8_lossy(path);
        entries.push((
            fields[1] == b"120000",
            fields[1] == b"100755",
            String::from_utf8_lossy(fields[2]).into_owned(),
            path.clone().into_owned(),
        ));
        let mut prefix = path.as_ref();
        loop {
            if spellings
                .insert(prefix.to_ascii_lowercase(), prefix.to_owned())
                .is_some_and(|seen| seen != prefix)
            {
                return Ok(false);
            }
            match prefix.rsplit_once('/') {
                Some((parent, _)) => prefix = parent,
                None => break,
            }
        }
    }
    // A file Git converts on its way to the working tree (end-of-line
    // conversion, an encoding, a filter, keyword expansion) may hold bytes
    // the comparison reads as equal yet a copy rewrites. `-text`, `-crlf`,
    // `-filter` and `-ident` convert nothing.
    if !paths.is_empty() {
        let mut args = global.to_vec();
        args.extend([
            "check-attr",
            "-z",
            "--stdin",
            "text",
            "eol",
            "crlf",
            "working-tree-encoding",
            "filter",
            "ident",
        ]);
        let reported = match git_exit_and_output(git, top, &args, INDEX_MAX_BYTES, wait, &paths)? {
            (Some(0), reported) => reported,
            _ => return Err(ObservationFailure::Unavailable),
        };
        // `<path>\0<attribute>\0<value>\0` for each path and attribute.
        let fields = reported.split(|byte| *byte == 0).collect::<Vec<_>>();
        if fields
            .chunks(3)
            .filter(|triple| triple.len() == 3)
            .any(|triple| !matches!(triple[2], b"unspecified" | b"unset"))
        {
            return Ok(false);
        }
        // Without any attribute, `core.autocrlf` converts too.
        match git_exit_and_output(
            git,
            directory,
            &["config", "--type=bool", "--get", "core.autocrlf"],
            STATUS_MAX_BYTES,
            wait,
            &[],
        )? {
            (Some(1), _) => {}
            (Some(0), value) if value.trim_ascii() == b"false" => {}
            _ => return Ok(false),
        }
    }
    if !working_copies_match(&entries, global, git, top, wait)? {
        return Ok(false);
    }
    // `--quiet` exits 1 on a difference.
    let differs = |words: &[&str]| match run(words, STATUS_MAX_BYTES)? {
        (Some(0), _) => Ok(false),
        (Some(1), _) => Ok(true),
        _ => Err(ObservationFailure::Unavailable),
    };
    let GitRestoreSource::Tree(revision) = source else {
        return Ok(true);
    };
    let spec = format!("{revision}^{{tree}}");
    let tree = match git_exit_and_output(
        git,
        directory,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ],
        STATUS_MAX_BYTES,
        wait,
        &[],
    )? {
        (Some(0), output) => String::from_utf8(output)
            .ok()
            .map(|tree| tree.trim_end().to_owned())
            .filter(|tree| !tree.is_empty() && tree.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(ObservationFailure::Unavailable)?,
        _ => return Err(ObservationFailure::Unavailable),
    };
    Ok(!differs(&[
        "diff-index",
        "--cached",
        "--quiet",
        "--ignore-submodules=none",
        &tree,
    ])?)
}

/// Whether each of `entries` (a symlink, an executable, its index object,
/// its path below `directory`) has a working copy of its own kind and mode
/// whose bytes Git hashes, unfiltered, to that object. The bytes decide, not
/// the metadata Git's own comparison trusts, which a racy timestamp leaves
/// matching over an edit.
fn working_copies_match(
    entries: &[(bool, bool, String, String)],
    global: &[&str],
    git: &Path,
    directory: &str,
    wait: GitWait,
) -> Result<bool, ObservationFailure> {
    let hash = |args: &[&str], input: &[u8]| {
        let mut words = global.to_vec();
        words.extend(args);
        match git_exit_and_output(git, directory, &words, INDEX_MAX_BYTES, wait, input)? {
            (Some(0), output) => {
                String::from_utf8(output).map_err(|_| ObservationFailure::NonUnicode)
            }
            _ => Err(ObservationFailure::Unavailable),
        }
    };
    let (mut files, mut objects) = (Vec::new(), Vec::new());
    for (symlink, executable, object, path) in entries {
        // `--stdin-paths` unquotes a path that starts with a quote and drops
        // a trailing carriage return, so it could hash another file.
        if path.starts_with('"') || path.contains(['\n', '\r']) {
            return Ok(false);
        }
        let file = Path::new(directory).join(path);
        let Ok(metadata) = fs::symlink_metadata(&file) else {
            return Ok(false);
        };
        if dataless(&file, &metadata) {
            return Err(ObservationFailure::Unavailable);
        }
        if *symlink {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                let target = match fs::read_link(&file) {
                    Ok(target) if metadata.is_symlink() => target,
                    _ => return Ok(false),
                };
                let hashed = hash(&["hash-object", "--stdin"], target.as_os_str().as_bytes())?;
                if hashed.trim_end() != object {
                    return Ok(false);
                }
                continue;
            }
            #[cfg(not(unix))]
            return Ok(false);
        }
        #[cfg(unix)]
        let mode_matches = {
            use std::os::unix::fs::PermissionsExt;
            (metadata.permissions().mode() & 0o111 != 0) == *executable
        };
        #[cfg(not(unix))]
        let mode_matches = !executable;
        if !metadata.is_file() || !mode_matches {
            return Ok(false);
        }
        files.extend(path.bytes().chain([b'\n']));
        objects.push(object.as_str());
    }
    if objects.is_empty() {
        return Ok(true);
    }
    let hashed = hash(&["hash-object", "--no-filters", "--stdin-paths"], &files)?;
    Ok(hashed.lines().eq(objects))
}

/// Whether the absolute `path` lies in the work tree `top_level` with every
/// name below it spelled byte for byte as its folder lists it, up to the
/// first one that is missing. A path a filesystem reaches only through a
/// case-folded or Unicode-normalised spelling is not, nor one outside
/// `top_level`, nor one whose folders cannot be read.
pub fn spelled_as_listed(top_level: &Path, path: &Path) -> bool {
    let mut folder = std::path::PathBuf::new();
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            folder.push(component);
            continue;
        };
        let inside = folder.starts_with(top_level);
        let entry = folder.join(name);
        match fs::symlink_metadata(&entry) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return inside,
            Err(_) => return false,
            Ok(_) => {}
        }
        if inside {
            let listed = fs::symlink_metadata(&folder)
                .ok()
                .filter(|metadata| !dataless(&folder, metadata))
                .and_then(|_| fs::read_dir(&folder).ok())
                .is_some_and(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .any(|listed| listed.file_name() == name)
                });
            if !listed {
                return false;
            }
        }
        // Each folder is read as resolved, so a link above or inside the
        // work tree leads where the filesystem takes it.
        folder = match canonical_absolute(&entry) {
            Ok(resolved) => resolved.as_str().into(),
            Err(_) => return false,
        };
    }
    folder.starts_with(top_level)
}

/// The tracked files `limit` names, as Git reads it in `directory` and by
/// path relative to it, whose working-tree entry their index entry does not
/// prove: one with conflict stages or the mode of no file or link, one whose
/// kind or executable bit on disk differs from its mode, and one whose bytes
/// `git hash-object --no-filters` does not hash to its blob. Status compares
/// metadata, so a timestamp-keeping edit, an assume-unchanged or
/// skip-worktree entry, or a filter can leave such a file clean to it. A
/// missing file holds nothing to prove.
fn unproven_by_index(
    git: &Path,
    directory: &str,
    top_level: &str,
    pathspec_options: &[String],
    limit: &[&str],
    wait: GitWait,
) -> Result<Vec<String>, ObservationFailure> {
    // Paths are listed, read and hashed from the work tree's top level, as
    // `hash-object` reads them wherever it runs.
    let mut listing = pathspec_options
        .iter()
        .map(String::as_str)
        .chain(["ls-files", "-s", "-z", "--full-name"])
        .collect::<Vec<_>>();
    listing.extend(limit);
    let (true, listed) = git_output(git, directory, &listing, INDEX_MAX_BYTES, wait)? else {
        return Err(ObservationFailure::Unavailable);
    };
    let mut stages = std::collections::BTreeMap::<&str, Vec<(&str, &str, &str)>>::new();
    for entry in listed
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = std::str::from_utf8(entry).map_err(|_| ObservationFailure::NonUnicode)?;
        let Some((fields, path)) = entry.split_once('\t') else {
            return Err(ObservationFailure::Unavailable);
        };
        let [mode, oid, stage] = fields.split(' ').collect::<Vec<_>>()[..] else {
            return Err(ObservationFailure::Unavailable);
        };
        stages.entry(path).or_default().push((mode, oid, stage));
    }
    let mut unproven = Vec::new();
    let mut hashed = Vec::new();
    for (path, entries) in stages {
        let [(mode, oid, "0")] = entries[..] else {
            unproven.push(path.to_owned());
            continue;
        };
        let file = Path::new(top_level).join(path);
        let metadata = match fs::symlink_metadata(&file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                unproven.push(path.to_owned());
                continue;
            }
            Ok(metadata) if dataless(&file, &metadata) => {
                unproven.push(path.to_owned());
                continue;
            }
            Ok(metadata) => metadata,
        };
        match mode {
            "120000" if metadata.file_type().is_symlink() => {
                let target = fs::read_link(&file).map_err(|_| ObservationFailure::Unavailable)?;
                let target = target.to_str().ok_or(ObservationFailure::NonUnicode)?;
                let (Some(0), blob) = git_exit_and_output(
                    git,
                    top_level,
                    &["hash-object", "--no-filters", "--stdin"],
                    1024,
                    wait,
                    target.as_bytes(),
                )?
                else {
                    return Err(ObservationFailure::Unavailable);
                };
                if blob.trim_ascii() != oid.as_bytes() {
                    unproven.push(path.to_owned());
                }
            }
            // `--stdin-paths` reads a line starting with a quote as a quoted
            // name and drops a carriage return, so such a path would hash
            // another file.
            "100644" | "100755"
                if metadata.is_file()
                    && executable(&metadata) == (mode == "100755")
                    && !path.starts_with('"')
                    && !path.contains(['\n', '\r']) =>
            {
                hashed.push((path, oid));
            }
            _ => unproven.push(path.to_owned()),
        }
    }
    if !hashed.is_empty() {
        let mut input = Vec::new();
        for (path, _) in &hashed {
            input.extend_from_slice(path.as_bytes());
            input.push(b'\n');
        }
        let (Some(0), blobs) = git_exit_and_output(
            git,
            top_level,
            &["hash-object", "--no-filters", "--stdin-paths"],
            INDEX_MAX_BYTES,
            wait,
            &input,
        )?
        else {
            return Err(ObservationFailure::Unavailable);
        };
        let blobs = blobs.split(|byte| *byte == b'\n').collect::<Vec<_>>();
        if blobs.len() != hashed.len() + 1 {
            return Err(ObservationFailure::Unavailable);
        }
        for ((path, oid), blob) in hashed.into_iter().zip(blobs) {
            if blob != oid.as_bytes() {
                unproven.push(path.to_owned());
            }
        }
    }
    unproven.sort();
    Ok(unproven)
}

/// Whether the owner may run the file `metadata` describes, as Git's
/// `100755` mode records it.
#[cfg(unix)]
fn executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn executable(_: &fs::Metadata) -> bool {
    false
}

/// `unproven_by_index` run at the work tree's top level `directory`, for a
/// caller outside observation, which waits at most `timeout` for Git.
pub fn git_unproven_by_index(
    git: &Path,
    directory: &str,
    limit: &[&str],
    timeout: std::time::Duration,
) -> Result<Vec<String>, ObservationFailure> {
    unproven_by_index(
        git,
        directory,
        directory,
        &[],
        limit,
        GitWait::per_spawn(timeout),
    )
}

/// For each stash entry of the repository Git finds from `directory`,
/// newest first, whether a ref other than the stash, or `HEAD`, reaches its
/// commit; `None` when Git cannot tell, or when `tip`, the commit the stash
/// names, is not its newest entry: a drop would lose that tip too. Another
/// stash entry does not count: dropping it in the same call is possible.
fn stash_reached(git: &Path, directory: &str, tip: &str, wait: GitWait) -> Option<Vec<bool>> {
    let listed = match git_output(
        git,
        directory,
        &[
            "log",
            "--walk-reflogs",
            "--no-show-signature",
            "--format=%H",
            "refs/stash",
            "--",
        ],
        STATUS_MAX_BYTES,
        wait,
    ) {
        Ok((true, listed)) => String::from_utf8(listed).ok()?,
        _ => return None,
    };
    let entries = listed.lines().collect::<Vec<_>>();
    if entries.first() != Some(&tip) || entries.len() > MAX_GIT_STATE_ENTRIES {
        return None;
    }
    // The commits no other ref reaches: an entry among them would be lost.
    let mut args = vec!["rev-list"];
    args.extend(&entries);
    args.extend(["--not", "--exclude=refs/stash", "--all", "--"]);
    let unreached = match git_output(git, directory, &args, STATUS_MAX_BYTES, wait) {
        Ok((true, unreached)) => String::from_utf8(unreached).ok()?,
        _ => return None,
    };
    let unreached = unreached.lines().collect::<std::collections::BTreeSet<_>>();
    Some(
        entries
            .iter()
            .map(|entry| !unreached.contains(entry))
            .collect(),
    )
}

/// What decides whether a rewrite of the history of the repository Git finds
/// from `directory` leaves the commits it replaces in reach.
///
/// Git records a ref's move in its reflog when the reflog exists, and with
/// `core.logAllRefUpdates` on (the default where there is a work tree) it
/// creates the reflogs of `HEAD` and of every branch first. A rebase, an
/// amend and a reset all move `HEAD` from the commit they replace, except
/// where an unfinished rebase goes on: it moves `HEAD` from its last replayed
/// commit and the branch it returns to from the old tip, which is safe only
/// where every such reflog is created. A `gc.reflogExpire` setting, plain or
/// for a pattern of refs, other than one that never expires, may expire the
/// recorded entry sooner than Git's defaults, so it counts as unsafe too.
fn history(
    git: &Path,
    directory: &str,
    head_targets: &[String],
    wait: GitWait,
) -> Result<GitHistoryObservation, ObservationFailure> {
    let settings = match git_exit_and_output(
        git,
        directory,
        &[
            "config",
            "-z",
            "--get-regexp",
            r"^(core\.logallrefupdates|gc\..*reflogexpire(unreachable)?)$",
        ],
        STATUS_MAX_BYTES,
        wait,
        &[],
    )? {
        (Some(0), settings) => {
            String::from_utf8(settings).map_err(|_| ObservationFailure::NonUnicode)?
        }
        // No key matches.
        (Some(1), _) => String::new(),
        _ => return Err(ObservationFailure::Unavailable),
    };
    // Each entry is its name, then a newline and its value unless it has
    // none; the last value of a key wins.
    let mut creates = true;
    let mut expires = false;
    let mut dated = Vec::new();
    for entry in settings.split_terminator('\0') {
        let (name, value) = match entry.split_once('\n') {
            Some((name, value)) => (name, Some(value.to_ascii_lowercase())),
            None => (entry, None),
        };
        match (name, value.as_deref()) {
            ("core.logallrefupdates", value) => {
                creates = matches!(value, None | Some("true" | "yes" | "on" | "1" | "always"));
            }
            (_, Some("never" | "false")) => {}
            (_, None | Some("now" | "all")) => expires = true,
            (_, Some(value)) => dated.push(format!("--since={value}")),
        }
    }
    // A dated expiry keeps the entry a rewrite replaces, which no longer
    // reaches the ref's tip, as long as Git's default for such entries, 30
    // days, unless its cutoff is later. Git reads each date as it would the
    // setting, the default's last, in one run, so all share one clock; one
    // it cannot read is now.
    if !expires && !dated.is_empty() {
        dated.push("--since=30.days.ago".to_owned());
        let mut args = vec!["rev-parse"];
        args.extend(dated.iter().map(String::as_str));
        let (true, cutoffs) = git_output(git, directory, &args, STATUS_MAX_BYTES, wait)? else {
            return Err(ObservationFailure::Unavailable);
        };
        let cutoffs = String::from_utf8(cutoffs)
            .map_err(|_| ObservationFailure::NonUnicode)?
            .lines()
            .map(|line| {
                line.strip_prefix("--max-age=")
                    .and_then(|seconds| seconds.parse::<i64>().ok())
            })
            .collect::<Option<Vec<_>>>()
            .filter(|cutoffs| cutoffs.len() == dated.len())
            .ok_or(ObservationFailure::Unavailable)?;
        let (default, settings) = cutoffs.split_last().expect("the default is listed");
        expires = settings.iter().any(|cutoff| cutoff > default);
    }
    let moves_logged = if expires {
        false
    } else if creates {
        true
    } else {
        let (true, paths) = git_output(
            git,
            directory,
            &[
                "rev-parse",
                "--git-path",
                "rebase-merge",
                "--git-path",
                "rebase-apply",
            ],
            STATUS_MAX_BYTES,
            wait,
        )?
        else {
            return Err(ObservationFailure::Unavailable);
        };
        let paths = String::from_utf8(paths).map_err(|_| ObservationFailure::NonUnicode)?;
        let rebasing = paths
            .lines()
            .any(|path| fs::symlink_metadata(Path::new(directory).join(path)).is_ok());
        !rebasing
            && match git_exit_and_output(
                git,
                directory,
                &["reflog", "exists", "HEAD"],
                STATUS_MAX_BYTES,
                wait,
                &[],
            )? {
                (Some(0), _) => true,
                (Some(1), _) => false,
                _ => return Err(ObservationFailure::Unavailable),
            }
    };
    let (true, backup) = git_output(
        git,
        directory,
        &[
            "for-each-ref",
            "--count=1",
            "--format=%(refname)",
            "refs/original/",
        ],
        STATUS_MAX_BYTES,
        wait,
    )?
    else {
        return Err(ObservationFailure::Unavailable);
    };
    let mut targets_holding_head = Vec::new();
    for target in head_targets {
        // A revision Git would read as an option, or cannot resolve to a
        // commit, holds nothing.
        if target.starts_with('-') {
            continue;
        }
        let (Some(0), commit) = git_exit_and_output(
            git,
            directory,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{target}^{{commit}}"),
            ],
            STATUS_MAX_BYTES,
            wait,
            &[],
        )?
        else {
            continue;
        };
        let commit = String::from_utf8(commit).map_err(|_| ObservationFailure::NonUnicode)?;
        if let (Some(0), _) = git_exit_and_output(
            git,
            directory,
            &["merge-base", "--is-ancestor", "HEAD", commit.trim()],
            STATUS_MAX_BYTES,
            wait,
            &[],
        )? {
            targets_holding_head.push(target.clone());
        }
    }
    Ok(GitHistoryObservation {
        moves_logged,
        creates_reflogs: moves_logged && creates,
        backups: !backup.is_empty(),
        targets_holding_head,
    })
}

/// Whether, in the repository Git finds from `directory`, the refs that
/// `deletions` leave, with a detached `HEAD`, reach every commit and tag
/// object the deleted refs name or their reflogs record; `None` when Git or
/// Nah cannot tell. A deleted ref's own reflog goes with it, so what only
/// that reflog records is lost too, and no other reflog counts: Git expires
/// their entries, so they keep nothing for good. The stash counts by its
/// newest entry, as any other ref.
fn deleted_refs_reached(
    git: &Path,
    directory: &str,
    deletions: &[RefDeletion],
    wait: GitWait,
) -> Option<bool> {
    let succeeded = |args: &[&str], input: &[u8]| match git_exit_and_output(
        git,
        directory,
        args,
        REFS_MAX_BYTES,
        wait,
        input,
    ) {
        Ok((code, output)) => Some((code, String::from_utf8(output).ok()?)),
        Err(_) => None,
    };
    let (Some(0), listing) = succeeded(
        &[
            "for-each-ref",
            "--format=%(objectname)%00%(objecttype)%00%(refname)%00%(symref)",
        ],
        &[],
    )?
    else {
        return None;
    };
    let mut listed = Vec::new();
    let mut tags = BTreeSet::new();
    for line in listing.lines() {
        let [oid, kind, name, symref] = line.split('\0').collect::<Vec<_>>()[..] else {
            return None;
        };
        if kind == "tag" {
            tags.insert(oid.to_owned());
        }
        listed.push(ListedRef {
            name: name.to_owned(),
            oid: oid.to_owned(),
            symref: (!symref.is_empty()).then(|| symref.to_owned()),
        });
    }
    // A symbolic HEAD keeps nothing its ref does not; a detached one keeps
    // its commit.
    let (head, detached) = match succeeded(&["symbolic-ref", "-q", "HEAD"], &[])? {
        (Some(0), head) => (Some(head.trim_end().to_owned()), None),
        (Some(1), _) => match succeeded(&["rev-parse", "--verify", "-q", "HEAD"], &[])? {
            (Some(0), oid) => (None, Some(oid.trim_end().to_owned())),
            _ => return None,
        },
        _ => return None,
    };
    let mut fetch_refspecs = BTreeMap::new();
    for deletion in deletions {
        let RefDeletion::Remote(remote) = deletion else {
            continue;
        };
        if remote.is_empty() || remote.contains(['\n', '\0']) {
            return None;
        }
        let key = format!("remote.{remote}.fetch");
        let refspecs = match succeeded(&["config", "--get-all", &key], &[])? {
            (Some(0), refspecs) => refspecs.lines().map(str::to_owned).collect(),
            (Some(1), _) => Vec::new(),
            _ => return None,
        };
        fetch_refspecs.insert(remote.clone(), refspecs);
    }
    let deleted = deleted_refs(&listed, head.as_deref(), deletions, &fetch_refspecs).ok()?;
    let kept = listed
        .iter()
        .filter(|listed| listed.symref.is_none() && !deleted.contains(&listed.name))
        .map(|listed| listed.oid.as_str())
        .chain(detached.as_deref())
        .collect::<BTreeSet<_>>();
    let mut logged = Vec::new();
    for name in deleted_reflogs(&listed, head.as_deref(), deletions, &fetch_refspecs).ok()? {
        logged.extend(reflog_objects(git, directory, &name, wait).ok()?);
    }
    let tips = listed
        .iter()
        .filter(|listed| deleted.contains(&listed.name))
        .map(|listed| listed.oid.as_str())
        .chain(logged.iter().map(String::as_str))
        .filter(|tip| !kept.contains(tip))
        .collect::<BTreeSet<_>>();
    // A tag object only the deleted ref names is lost with it.
    if tips.iter().any(|tip| tags.contains(*tip)) {
        return Some(false);
    }
    if tips.is_empty() {
        return Some(true);
    }
    let mut revisions = String::new();
    for tip in &tips {
        revisions.push_str(&format!("{tip}\n"));
    }
    for tip in &kept {
        revisions.push_str(&format!("^{tip}\n"));
    }
    match succeeded(
        &["rev-list", "--max-count=1", "--stdin"],
        revisions.as_bytes(),
    )? {
        (Some(0), unreached) => Some(unreached.is_empty()),
        _ => None,
    }
}

/// Every object the reflog of the ref `name` records, as an entry's old
/// value or its new one: Git keeps both reachable, and deleting the ref
/// deletes its reflog. Git's own listing shows only the new values, and an
/// expired entry leaves its old value only in the next one, so the reflog's
/// file is read. `Unavailable` where Git lists entries no file holds, as in
/// a repository that keeps its refs another way.
fn reflog_objects(
    git: &Path,
    directory: &str,
    name: &str,
    wait: GitWait,
) -> Result<Vec<String>, ObservationFailure> {
    let (Some(0), path) = git_exit_and_output(
        git,
        directory,
        &["rev-parse", "--git-path", &format!("logs/{name}")],
        STATUS_MAX_BYTES,
        wait,
        &[],
    )?
    else {
        return Err(ObservationFailure::Unavailable);
    };
    let path = String::from_utf8(path).map_err(|_| ObservationFailure::NonUnicode)?;
    let path = Path::new(directory).join(path.trim_end_matches('\n'));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (Some(0), listed) = git_exit_and_output(
                git,
                directory,
                &["log", "--walk-reflogs", "--format=%H", name, "--"],
                STATUS_MAX_BYTES,
                wait,
                &[],
            )?
            else {
                return Err(ObservationFailure::Unavailable);
            };
            return if listed.is_empty() {
                Ok(Vec::new())
            } else {
                Err(ObservationFailure::Unavailable)
            };
        }
        Err(_) => return Err(ObservationFailure::Unavailable),
    };
    if dataless(&path, &metadata) || !metadata.is_file() {
        return Err(ObservationFailure::Unavailable);
    }
    let mut text = Vec::new();
    fs::File::open(&path)
        .and_then(|file| file.take(REFS_MAX_BYTES + 1).read_to_end(&mut text))
        .map_err(|_| ObservationFailure::Unavailable)?;
    if text.len() as u64 > REFS_MAX_BYTES {
        return Err(ObservationFailure::Unavailable);
    }
    let text = String::from_utf8_lossy(&text);
    let mut objects = Vec::new();
    // `<old> <new> <who> <when>\t<message>`.
    for entry in text.lines() {
        let mut fields = entry.split(' ');
        for _ in 0..2 {
            let oid = fields.next().unwrap_or_default();
            if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ObservationFailure::Unavailable);
            }
            if oid.bytes().any(|byte| byte != b'0') {
                objects.push(oid.to_owned());
            }
        }
    }
    Ok(objects)
}

/// `reflog_objects` for a caller outside observation, which waits at most
/// `timeout` for Git.
pub fn git_reflog_objects(
    git: &Path,
    directory: &str,
    name: &str,
    timeout: std::time::Duration,
) -> Result<Vec<String>, ObservationFailure> {
    reflog_objects(git, directory, name, GitWait::per_spawn(timeout))
}

/// `filter_drivers_disabled` for a caller outside observation, which waits
/// at most `timeout` for Git.
pub fn git_filter_drivers_disabled(
    git: &Path,
    directory: &str,
    timeout: std::time::Duration,
) -> Result<Vec<String>, ObservationFailure> {
    filter_drivers_disabled(git, directory, GitWait::per_spawn(timeout))
}

/// The `-c` options that disable every filter driver the configuration of
/// the repository Git finds from `directory` names, so a command that reads
/// tracked files' contents starts none of them. A driver Git cannot be told
/// about on its command line, one whose name holds `=`, is a failure.
pub(crate) fn filter_drivers_disabled(
    git: &Path,
    directory: &str,
    wait: GitWait,
) -> Result<Vec<String>, ObservationFailure> {
    let names = match git_exit_and_output(
        git,
        directory,
        &["config", "-z", "--name-only", "--get-regexp", r"^filter\."],
        STATUS_MAX_BYTES,
        wait,
        &[],
    )? {
        (Some(0), names) => String::from_utf8(names).map_err(|_| ObservationFailure::NonUnicode)?,
        // No key matches.
        (Some(1), _) => return Ok(Vec::new()),
        _ => return Err(ObservationFailure::Unavailable),
    };
    // A key is `filter.<driver>.<setting>`; the driver name may hold dots.
    let drivers = names
        .split_terminator('\0')
        .filter_map(|name| name.strip_prefix("filter.")?.rsplit_once('.'))
        .map(|(driver, _)| driver)
        .collect::<std::collections::BTreeSet<_>>();
    if drivers.iter().any(|driver| driver.contains('=')) {
        return Err(ObservationFailure::Unavailable);
    }
    // An empty command is no filter. A driver the configuration marks
    // required then fails the command, which answers nothing.
    Ok(drivers
        .into_iter()
        .flat_map(|driver| {
            ["clean", "smudge", "process"].map(|setting| format!("filter.{driver}.{setting}="))
        })
        .flat_map(|option| ["-c".to_owned(), option])
        .collect())
}

/// What macOS's `strerror` gives for EDEADLK, the failure of a read that
/// would fetch a dataless File Provider item where materialization is off,
/// as it is for Git (`git_command`). Git names it in what it reports of a
/// file or directory it then passes over.
#[cfg(target_os = "macos")]
const REFUSED_FETCH: &[u8] = b"Resource deadlock avoided";

/// The most bytes of Git's diagnostics searched for a refused fetch.
#[cfg(target_os = "macos")]
const DIAGNOSTICS_MAX_BYTES: u64 = 1 << 16;

/// Runs `git -C directory args` with `input` as its standard input,
/// returning its exit code and what it printed. Output past `max_bytes`, a
/// run past the time `wait` leaves, and, on macOS, a run in which Git could
/// not read a dataless item are failures, never a partial answer.
pub(crate) fn git_exit_and_output(
    git: &Path,
    directory: &str,
    args: &[&str],
    max_bytes: u64,
    wait: GitWait,
    input: &[u8],
) -> Result<(Option<i32>, Vec<u8>), ObservationFailure> {
    if wait.timeout().is_zero() {
        return Err(ObservationFailure::Timeout);
    }
    let mut child = git_command(git)
        .args([OsStr::new("-C"), OsStr::new(directory)])
        .args(args)
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(if cfg!(target_os = "macos") {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()
        .map_err(|_| ObservationFailure::Unavailable)?;
    #[cfg(target_os = "macos")]
    let refused = {
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let (sender, refused) = mpsc::channel();
        std::thread::spawn(move || {
            let mut diagnostics = Vec::new();
            let _ = (&mut stderr)
                .take(DIAGNOSTICS_MAX_BYTES)
                .read_to_end(&mut diagnostics);
            // Drained, so Git never waits on a full pipe.
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            let _ = sender.send(
                diagnostics
                    .windows(REFUSED_FETCH.len())
                    .any(|window| window == REFUSED_FETCH),
            );
        });
        refused
    };
    // Written beside the read below, so neither pipe fills while Git waits
    // on the other. A child that exits early leaves the write to fail.
    if let Some(mut stdin) = child.stdin.take() {
        let input = input.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    // One deadline bounds the run and the collection of its output: a
    // process the child leaves behind can hold the pipe open after the child
    // exits, and is then left to finish alone.
    let stop = Instant::now() + wait.timeout();
    // Read while waiting, so a listing larger than the pipe does not stall
    // the child until the timeout.
    let stdout = child.stdout.take().expect("stdout is piped");
    let (sender, output) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = sender.send(
            stdout
                .take(max_bytes + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes),
        );
    });
    #[cfg(all(test, unix))]
    let child_wait = simulated::now_at(git, wait.deadline, stop, Some(&mut child));
    #[cfg(not(all(test, unix)))]
    let child_wait = Instant::now();
    let remaining = stop.saturating_duration_since(child_wait);
    // Even a zero-duration wait polls the child and can return a status
    // after the cutoff. Once the budget is exhausted, report the timeout.
    let status = if remaining.is_zero() {
        None
    } else {
        child
            .wait_timeout(remaining)
            .map_err(|_| ObservationFailure::Unavailable)?
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ObservationFailure::Timeout);
    };
    #[cfg(all(test, unix))]
    let output_wait = simulated::now_at(git, wait.deadline, stop, None);
    #[cfg(not(all(test, unix)))]
    let output_wait = Instant::now();
    let bytes = match output.recv_timeout(stop.saturating_duration_since(output_wait)) {
        Ok(Ok(bytes)) => bytes,
        Err(mpsc::RecvTimeoutError::Timeout) => return Err(ObservationFailure::Timeout),
        Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(ObservationFailure::Unavailable);
        }
    };
    if bytes.len() as u64 > max_bytes {
        return Err(ObservationFailure::Unavailable);
    }
    #[cfg(target_os = "macos")]
    match refused.recv_timeout(stop.saturating_duration_since(Instant::now())) {
        Ok(false) => {}
        Ok(true) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(ObservationFailure::Unavailable);
        }
        Err(mpsc::RecvTimeoutError::Timeout) => return Err(ObservationFailure::Timeout),
    }
    Ok((status.code(), bytes))
}

#[cfg(all(test, unix))]
pub(crate) mod simulated {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::process::Child;
    use std::sync::Mutex;
    use std::time::Instant;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Wait {
        Child,
        ChildAfterExit,
        Output,
    }

    struct Expiry {
        wait: Wait,
        cutoff: Instant,
        received: Option<(Option<Instant>, Instant)>,
    }

    // A test gives its fake Git a unique path. Its decision's worker uses
    // that path to find the clock armed by the caller.
    static EXPIRIES: Mutex<BTreeMap<PathBuf, Expiry>> = Mutex::new(BTreeMap::new());

    /// Let the decision's cutoff pass when Git reaches the selected wait.
    pub(crate) fn expire_at<T>(
        git: &Path,
        wait: Wait,
        cutoff: Instant,
        run: impl FnOnce() -> T,
    ) -> T {
        EXPIRIES.lock().unwrap().insert(
            git.to_path_buf(),
            Expiry {
                wait,
                cutoff,
                received: None,
            },
        );
        let result = run();
        let expiry = EXPIRIES.lock().unwrap().remove(git);
        let (deadline, stop) = expiry
            .and_then(|expiry| expiry.received)
            .unwrap_or_else(|| panic!("Git did not reach the {wait:?} wait"));
        assert_eq!(
            deadline,
            Some(cutoff),
            "Git must receive the decision's cutoff"
        );
        assert!(stop <= cutoff, "Git waited past the decision's cutoff");
        result
    }

    pub(super) fn now_at(
        git: &Path,
        deadline: Option<Instant>,
        stop: Instant,
        child: Option<&mut Child>,
    ) -> Instant {
        if let Some(pending) = EXPIRIES.lock().unwrap().get_mut(git)
            && child.is_some() == (pending.wait != Wait::Output)
            && pending.received.is_none()
        {
            pending.received = Some((deadline, stop));
            if pending.wait == Wait::ChildAfterExit {
                child.unwrap().wait().expect("fake Git exits");
            }
            return stop.max(pending.cutoff);
        }
        Instant::now()
    }
}

/// `git_exit_and_output` without input, as whether Git succeeded.
fn git_output(
    git: &Path,
    directory: &str,
    args: &[&str],
    max_bytes: u64,
    wait: GitWait,
) -> Result<(bool, Vec<u8>), ObservationFailure> {
    git_exit_and_output(git, directory, args, max_bytes, wait, &[])
        .map(|(code, output)| (code == Some(0), output))
}
