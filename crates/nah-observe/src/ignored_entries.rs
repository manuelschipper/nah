//! Observes which entries below a directory Git's ignore rules leave out of
//! a search that honours them, as ripgrep reads those rules.

use crate::git_state::git_exit_and_output;
use nah_proto::observation::{
    IgnoredEntriesObservation, IgnoredEntry, MAX_IGNORED_ENTRIES, ObservationFailure, Observed,
};
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Most bytes of an ignored-entry listing read: more is a tree too large to
/// answer for.
const LISTING_MAX_BYTES: u64 = 1024 * 1024;

/// Most bytes of one `.ignore` or `.rgignore` file read.
const IGNORE_FILE_MAX_BYTES: u64 = 64 * 1024;

/// The ignore files ripgrep reads beside `.gitignore`. Their rules outrank
/// Git's, so a `!` line in one can put an entry Git ignores back in a search.
const SEARCH_IGNORE_FILES: [&str; 2] = [".ignore", ".rgignore"];

/// The entries below `directory` that a search honouring ignore files does
/// not open, each with the rule that decides it.
///
/// Git answers for the rules ripgrep also reads: the `.gitignore` files from
/// the repository's top level down, its `info/exclude`, and the global
/// excludes file. ripgrep differs from Git in six ways, and each is kept on
/// the side of listing less:
///
/// - It finds the global excludes file in the user's own configuration only,
///   so Git is told to use that file whatever a repository or system
///   configuration names.
/// - It does not apply a rule to the directory it was pointed at, so a
///   `directory` that is itself ignored has every entry searched: nothing is
///   reported.
/// - It also reads `.ignore` and `.rgignore`, which Git does not. One in
///   `directory` or above it that holds a `!` line may re-include anything:
///   nothing is reported. One of either name, a link included, in a
///   directory between `directory` and an entry leaves that entry out.
/// - It matches a rule's letters as written, where Git folds case when the
///   repository's `core.ignorecase` says so. Git is told not to.
/// - It reads a `.gitignore` that is a symbolic link, which Git refuses to
///   follow, so the linked rules may re-include anything below them: such a
///   link above `directory` reports nothing, and one between `directory` and
///   an entry leaves that entry out.
/// - It skips a tracked file a rule matches, which Git keeps: such a file is
///   not listed.
///
/// A directory with no repository around it has no `.gitignore` ripgrep
/// would read, and Git fails there, so nothing is reported.
pub(crate) fn observe_ignored_entries(
    directory: &str,
    git: &Path,
    timeout: Duration,
) -> Observed<IgnoredEntriesObservation> {
    match ignored_entries(directory, git, timeout) {
        Ok(value) => Observed::Ok { value },
        Err(error) => Observed::Error { error },
    }
}

fn ignored_entries(
    directory: &str,
    git: &Path,
    timeout: Duration,
) -> Result<IgnoredEntriesObservation, ObservationFailure> {
    let unavailable = ObservationFailure::Unavailable;
    let real = fs::canonicalize(directory).map_err(|_| unavailable)?;
    for ancestor in real.ancestors().chain(Path::new(directory).ancestors()) {
        if !absent_or_plain(&ancestor.join(".gitignore"), false) {
            return Err(unavailable);
        }
        for name in SEARCH_IGNORE_FILES {
            if re_includes(&ancestor.join(name))? {
                return Err(unavailable);
            }
        }
    }
    let run = |args: &[&str], input: &[u8]| {
        git_exit_and_output(git, directory, args, LISTING_MAX_BYTES, timeout, input).and_then(
            |(code, output)| {
                String::from_utf8(output)
                    .map(|text| (code, text))
                    .map_err(|_| ObservationFailure::NonUnicode)
            },
        )
    };
    // Two questions that do not depend on each other, asked side by side to
    // keep a search's hook short: the top level and where `directory` lies
    // below it, which the rule files of a match are named from, and the file ripgrep
    // takes the global excludes from, the one the user's own configuration
    // names, without its includes, or Git's default.
    let (prefix, excludes) = std::thread::scope(|scope| {
        let prefix = scope.spawn(|| run(&["rev-parse", "--show-toplevel", "--show-prefix"], &[]));
        let excludes = run(
            &[
                "config",
                "--global",
                "--no-includes",
                "--type=path",
                "--get",
                "core.excludesFile",
            ],
            &[],
        );
        (prefix.join(), excludes)
    });
    let Ok((Some(0), located)) = prefix.map_err(|_| unavailable)? else {
        return Err(unavailable);
    };
    // The prefix is empty, or ends in `/`.
    let mut located = located.lines();
    let (Some(top_level), prefix) = (located.next(), located.next().unwrap_or_default()) else {
        return Err(unavailable);
    };
    let excludes = match excludes? {
        (Some(0), path) => path.trim_end_matches(['\r', '\n']).to_owned(),
        (Some(1), _) => std::env::var_os("XDG_CONFIG_HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .and_then(|home| home.join("git/ignore").to_str().map(str::to_owned))
            .unwrap_or_default(),
        _ => return Err(unavailable),
    };
    // Every file whose rules the answer rests on, as named and as resolved.
    let mut rule_files = std::collections::BTreeSet::new();
    let mut depends_on = |file: &Path| {
        for path in [Some(file.to_path_buf()), fs::canonicalize(file).ok()] {
            rule_files.extend(path.and_then(|path| path.to_str().map(str::to_owned)));
        }
    };
    if !excludes.is_empty() {
        depends_on(Path::new(&excludes));
    }
    let excludes = format!("core.excludesFile={excludes}");
    // ripgrep matches rules as written, whatever the repository says of case.
    const CASE: [&str; 2] = ["-c", "core.ignorecase=false"];
    let (Some(0), listing) = run(
        &[
            CASE[0],
            CASE[1],
            "-c",
            &excludes,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
        ],
        &[],
    )?
    else {
        return Err(unavailable);
    };
    // Git lists `./` for a directory that holds ignored entries only.
    let listed = listing
        .split_terminator('\0')
        .filter(|path| *path != "./")
        .collect::<Vec<_>>();
    if listed.is_empty() {
        return IgnoredEntriesObservation::new(Vec::new(), Vec::new()).map_err(|_| unavailable);
    }
    // Whether each directory below `directory` holds an ignore file that may
    // re-include what Git ignores beneath it.
    let mut overruled = std::collections::BTreeMap::<String, bool>::new();
    let mut may_be_overruled = |entry: &str| {
        let entry = entry.trim_end_matches('/');
        entry.match_indices('/').any(|(at, _)| {
            let below = &entry[..at];
            *overruled.entry(below.to_owned()).or_insert_with(|| {
                let held = Path::new(directory).join(below);
                !absent_or_plain(&held.join(".gitignore"), false)
                    || SEARCH_IGNORE_FILES
                        .iter()
                        .any(|name| !absent_or_plain(&held.join(name), true))
            })
        })
    };
    if listed.len() > MAX_IGNORED_ENTRIES {
        return Err(unavailable);
    }
    // The rule deciding each listed entry, and `directory` itself. Git
    // answers one `source NUL line NUL pattern NUL path NUL` record per path
    // in order, with an empty pattern where no rule matches.
    let mut asked = String::from(".\0");
    for path in &listed {
        asked.push_str(path);
        asked.push('\0');
    }
    let (Some(0 | 1), rules) = run(
        &[
            CASE[0],
            CASE[1],
            "-c",
            &excludes,
            "check-ignore",
            "--verbose",
            "--non-matching",
            "-z",
            "--stdin",
        ],
        asked.as_bytes(),
    )?
    else {
        return Err(unavailable);
    };
    let fields = rules.split_terminator('\0').collect::<Vec<_>>();
    if fields.len() != 4 * (listed.len() + 1) {
        return Err(unavailable);
    }
    let mut entries = Vec::new();
    for (record, path) in fields.chunks(4).zip(std::iter::once(&".").chain(&listed)) {
        let [source, _, pattern, answered] = record else {
            return Err(unavailable);
        };
        if answered != path {
            return Err(unavailable);
        }
        let matched = !pattern.is_empty() && !pattern.starts_with('!');
        if *path == "." {
            if matched {
                return Err(unavailable);
            }
            continue;
        }
        // A directory Git lists because everything in it is ignored has no
        // rule of its own; the entries inside it are listed beside it.
        if matched && !may_be_overruled(path) {
            let source = Path::new(source);
            if source.is_absolute() {
                depends_on(source);
            } else {
                depends_on(&Path::new(top_level).join(source));
            }
            let source = source.to_str().unwrap_or_default();
            entries.push(IgnoredEntry::new(
                (*path).to_owned(),
                (*pattern).to_owned(),
                (!Path::new(source).is_absolute())
                    .then(|| source.strip_prefix(prefix))
                    .flatten()
                    .map(str::to_owned),
            ));
        }
    }
    IgnoredEntriesObservation::new(entries, rule_files.into_iter().collect())
        .map_err(|_| unavailable)
}

/// Whether nothing is at `path`, or, unless `absent`, a regular file is. A
/// link, and an entry that cannot be examined, is neither.
fn absent_or_plain(path: &Path, absent: bool) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) => !absent && metadata.is_file(),
        Err(error) => matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory),
    }
}

/// Whether the ignore file at `path` holds a `!` line. A missing file holds
/// none; one that cannot be read whole is not answered for.
fn re_includes(path: &Path) -> Result<bool, ObservationFailure> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(false);
        }
        Err(_) => return Err(ObservationFailure::Unavailable),
    };
    let mut bytes = Vec::new();
    file.take(IGNORE_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ObservationFailure::Unavailable)?;
    if bytes.len() as u64 > IGNORE_FILE_MAX_BYTES {
        return Err(ObservationFailure::Unavailable);
    }
    Ok(bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line.first() == Some(&b'!')))
}
