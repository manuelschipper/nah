//! Observes which entries below a directory the ignore files leave out of a
//! search that honours them, read in this process as ripgrep reads them.

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder, Glob};
use nah_proto::observation::{
    IgnoredEntriesObservation, IgnoredEntry, MAX_DESCENDANT_DEPTH, MAX_IGNORED_ENTRIES,
    ObservationFailure, Observed,
};
use std::collections::{BTreeSet, HashMap};

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;

use crate::directory_entries::{DirectoryEntry, EntryKind, Listed, read_directory};
use crate::read_ahead::ReadAhead;

/// Most directory entries the walk below the observed directory reads: a
/// larger tree is answered for with nothing ignored.
const WALK_MAX_ENTRIES: usize = 50_000;

/// Most ignore files read for one observation.
const RULE_FILES_MAX: usize = 1_000;

/// Most bytes of one ignore file read.
const RULE_FILE_MAX_BYTES: u64 = 64 * 1024;

/// Most bytes of all the ignore files one observation reads.
const RULE_BYTES_MAX: u64 = 1024 * 1024;

/// Most bytes of a worktree's `.git` or `commondir` file read.
const GIT_POINTER_MAX_BYTES: u64 = 4096;

/// Most bytes of a Git configuration file read to find the global excludes
/// file.
const GIT_CONFIG_MAX_BYTES: u64 = 64 * 1024;

/// The entries of each directory a walk read whole, with their types, by the
/// directory's real path, so a later walk of the same tree in the same
/// observation reads none of them again.
pub(crate) type Listings = HashMap<PathBuf, Vec<DirectoryEntry>>;

/// The ignore files ripgrep reads beside `.gitignore`. Their rules outrank
/// Git's, so a `!` line in one can put an entry Git ignores back in a search.
const SEARCH_IGNORE_FILES: [&str; 2] = [".ignore", ".rgignore"];

/// The entries below `directory` that a search honouring ignore files does
/// not open, each with the rule that decides it.
///
/// The rules are read as ripgrep reads them, without Git: those of
/// `directory`, of the directories above it and of each directory the walk
/// enters, the nearest file of a kind first and its last matching line
/// deciding; `.rgignore` before `.ignore` before `.gitignore` before a
/// repository's `info/exclude` before the global excludes file; and
/// `.gitignore` and `info/exclude` only up to the nearest directory holding
/// `.git`. An ignored directory is listed and not walked. ripgrep also
/// skips a tracked file a rule matches, so such a file is listed. Where
/// versions of ripgrep read the rules differently, or what they read is not
/// established, each case is kept on the side of listing less:
///
/// - Versions find the global excludes file in different configuration
///   files, and match a line that holds a `/` from the directory they run
///   in, so its rules count only when no `GIT_CONFIG_GLOBAL`,
///   `GIT_CONFIG_SYSTEM` or `/etc/gitconfig` may name another file, the
///   user's configuration names it plainly or not at all, and none of its
///   lines holds a `/` before its end.
/// - A `directory` that a rule ignores, or that lies in an ignored
///   directory, reports nothing, though ripgrep searches a directory it was
///   pointed at.
/// - A `.ignore` or `.rgignore` in `directory` or above it that holds a `!`
///   line reports nothing, and nothing below a directory between
///   `directory` and an entry that holds either is listed.
/// - A `.gitignore` that is a symbolic link, whose rules another file
///   decides, reports nothing in `directory` or above it, and leaves out
///   what lies below a directory between.
/// - Newer versions take a `.jj` directory to mark a repository as `.git`
///   does: one in `directory` or above it reports nothing, and one below
///   leaves out what lies below it.
/// - A worktree's `.git` file that names its repository by a relative path
///   is read from where ripgrep runs: one in `directory` or above it
///   reports nothing, and one below leaves out what lies below it.
/// - An ignore file that is not a regular file read whole, holds a line
///   ripgrep could not parse, or does not fit the bounds on ignore files,
///   reports nothing, as does a walk that reads too many entries.
/// - Nothing inside `.git`, and no entry whose name is not Unicode, is
///   listed.
///
/// A directory with no `.git` at or above it has no `.gitignore` ripgrep
/// would read, so nothing is reported.
///
/// Each directory the walk reads whole is kept in `listings`.
pub(crate) fn observe_ignored_entries(
    directory: &str,
    listings: &mut Listings,
) -> Observed<IgnoredEntriesObservation> {
    observe_ignored_entries_within(directory, WALK_MAX_ENTRIES, listings)
}

/// Observes like [`observe_ignored_entries`], reading at most `walk_entries`
/// directory entries.
pub(crate) fn observe_ignored_entries_within(
    directory: &str,
    walk_entries: usize,
    listings: &mut Listings,
) -> Observed<IgnoredEntriesObservation> {
    match ignored_entries(directory, walk_entries, listings) {
        Ok(value) => Observed::Ok { value },
        Err(error) => Observed::Error { error },
    }
}

fn ignored_entries(
    directory: &str,
    walk_entries: usize,
    listings: &mut Listings,
) -> Result<IgnoredEntriesObservation, ObservationFailure> {
    let unavailable = ObservationFailure::Unavailable;
    if !Path::new(directory).is_absolute() {
        return Err(unavailable);
    }
    let real = fs::canonicalize(directory).map_err(|_| unavailable)?;
    let mut reader = RuleReader::default();
    for ancestor in real.ancestors().chain(Path::new(directory).ancestors()) {
        if !absent_or_plain(&ancestor.join(".gitignore"), false) {
            return Err(unavailable);
        }
        for name in SEARCH_IGNORE_FILES {
            let file = ancestor.join(name);
            if re_includes(&file)? {
                return Err(unavailable);
            }
            // A `!` line written into it later would re-include entries.
            if fs::symlink_metadata(&file).is_ok() {
                reader.depend(&file)?;
            }
        }
    }
    // The rules of the directories above `directory`, from the root of the
    // filesystem down, and then its own.
    let mut above = None;
    for ancestor in real
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let holds = |name: &str| fs::symlink_metadata(ancestor.join(name)).is_ok();
        let rules = reader
            .directory_rules(ancestor, &holds, above)?
            .ok_or(unavailable)?;
        above = Some(Rc::new(rules));
    }
    let remaining = AtomicUsize::new(walk_entries);
    let listing = listing(&real, &remaining)?.ok_or(unavailable)?;
    let rules = Rc::new(
        reader
            .directory_rules(&real, &|name| listed(&listing, name), above)?
            .ok_or(unavailable)?,
    );
    let global = reader.global_rules()?;
    // A rule ignoring `directory`, or a directory it lies in below the
    // repository's top level.
    let mut inner = &rules;
    let mut path = real.as_path();
    loop {
        if inner.repository {
            break;
        }
        let (Some(outer), Some(parent)) = (&inner.parent, path.parent()) else {
            return Err(unavailable);
        };
        if outer
            .decide(path, true)
            .or(global.matched(path, true))
            .is_ignore()
        {
            return Err(unavailable);
        }
        inner = outer;
        path = parent;
    }

    let mut entries = Vec::new();
    // Each directory to walk with the rules above it, and, for `directory`
    // itself, its own rules and entries. Another is read when it is walked,
    // or ahead of that.
    let mut pending = vec![(real.clone(), String::new(), rules, Some(listing), 0)];
    ReadAhead::run(
        |directory| self::listing(directory, &remaining),
        |read_ahead| {
            while let Some((directory, prefix, rules, listing, depth)) = pending.pop() {
                let (rules, listing) = match listing {
                    Some(listing) => (rules, listing),
                    None => {
                        // What cannot be read is not listed.
                        let Some(below) = read_ahead
                            .take(&directory)
                            .unwrap_or_else(|| self::listing(&directory, &remaining))?
                        else {
                            continue;
                        };
                        // A directory holding an ignore file that may
                        // re-include what an outer rule ignores, as named
                        // above.
                        let overruled = below.iter().any(|held| {
                            held.name == ".gitignore" && held.kind != EntryKind::File
                                || SEARCH_IGNORE_FILES.iter().any(|name| held.name == *name)
                        });
                        if overruled {
                            listings.insert(directory, below);
                            continue;
                        }
                        let Some(inner) = reader.directory_rules(
                            &directory,
                            &|name| listed(&below, name),
                            Some(rules),
                        )?
                        else {
                            listings.insert(directory, below);
                            continue;
                        };
                        (Rc::new(inner), below)
                    }
                };
                for entry in &listing {
                    let Some(name) = entry.name.to_str() else {
                        continue;
                    };
                    let path = directory.join(name);
                    let is_directory = entry.kind == EntryKind::Directory;
                    match rules
                        .decide(&path, is_directory)
                        .or(global.matched(&path, is_directory))
                    {
                        Match::Ignore(glob) => {
                            if entries.len() == MAX_IGNORED_ENTRIES {
                                return Err(unavailable);
                            }
                            let from = glob.from().ok_or(unavailable)?;
                            entries.push(IgnoredEntry::new(
                                format!("{prefix}{name}{}", if is_directory { "/" } else { "" }),
                                glob.original().to_owned(),
                                from.strip_prefix(&real).ok().and_then(slash_separated),
                            ));
                        }
                        _ if is_directory && name != ".git" && depth + 1 < MAX_DESCENDANT_DEPTH => {
                            read_ahead.ask(&path);
                            pending.push((
                                path,
                                format!("{prefix}{name}/"),
                                rules.clone(),
                                None,
                                depth + 1,
                            ));
                        }
                        _ => {}
                    }
                }
                listings.insert(directory, listing);
            }
            Ok(())
        },
    )?;
    IgnoredEntriesObservation::new(entries, reader.rule_files.into_iter().collect())
        .map_err(|_| unavailable)
}

/// The ignore rules one directory holds, and those of the directories above
/// it.
struct DirectoryRules {
    /// The directory holds `.git`, which ripgrep takes for a repository's
    /// top level: no `.gitignore` or `info/exclude` above it applies below
    /// it.
    repository: bool,
    rgignore: Gitignore,
    ignore: Gitignore,
    gitignore: Gitignore,
    exclude: Gitignore,
    parent: Option<Rc<DirectoryRules>>,
}

impl DirectoryRules {
    /// The rule that decides `path`, an entry of this directory or of one
    /// below it, as ripgrep picks it among the ignore files of this
    /// directory and those above it.
    fn decide(&self, path: &Path, is_directory: bool) -> Match<&Glob> {
        let (mut rgignore, mut ignore, mut gitignore, mut exclude) =
            (Match::None, Match::None, Match::None, Match::None);
        let mut past_repository = false;
        let mut rules = Some(self);
        while let Some(current) = rules {
            if rgignore.is_none() {
                rgignore = current.rgignore.matched(path, is_directory);
            }
            if ignore.is_none() {
                ignore = current.ignore.matched(path, is_directory);
            }
            if !past_repository {
                if gitignore.is_none() {
                    gitignore = current.gitignore.matched(path, is_directory);
                }
                if exclude.is_none() {
                    exclude = current.exclude.matched(path, is_directory);
                }
            }
            past_repository |= current.repository;
            rules = current.parent.as_deref();
        }
        rgignore.or(ignore).or(gitignore).or(exclude)
    }
}

/// Reads ignore files within the bounds of one observation.
#[derive(Default)]
struct RuleReader {
    files: usize,
    bytes: u64,
    /// Every file whose content could change what the rules leave out,
    /// deciding or not, as named and as resolved: a write to one in the same
    /// invocation voids the answer.
    rule_files: BTreeSet<String>,
}

impl RuleReader {
    /// Keeps `file` among the files the answer rests on, as named and as
    /// resolved through its links, or, where nothing is there yet, as its
    /// resolved directory names it. A link that leads nowhere is not
    /// answered for: the file it would lead to cannot be named.
    fn depend(&mut self, file: &Path) -> Result<(), ObservationFailure> {
        let resolved = match fs::canonicalize(file) {
            Ok(resolved) => resolved,
            Err(_) if fs::symlink_metadata(file).is_ok() => {
                return Err(ObservationFailure::Unavailable);
            }
            Err(_) => match (file.parent().map(fs::canonicalize), file.file_name()) {
                (Some(Ok(parent)), Some(name)) => parent.join(name),
                _ => file.to_path_buf(),
            },
        };
        for path in [file, &resolved] {
            self.rule_files.insert(
                path.to_str()
                    .ok_or(ObservationFailure::Unavailable)?
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// The rules of `directory`, whose entry `name` exists when `holds`
    /// says so, below the rules `parent`. None where ripgrep's reading of
    /// them is not established: the directory holds `.jj`, or a `.git` file
    /// that names its repository by a relative path.
    fn directory_rules(
        &mut self,
        directory: &Path,
        holds: &dyn Fn(&str) -> bool,
        parent: Option<Rc<DirectoryRules>>,
    ) -> Result<Option<DirectoryRules>, ObservationFailure> {
        if holds(".jj") {
            return Ok(None);
        }
        let mut read = |name: &str, file: &Path| {
            if holds(name) {
                self.rules(directory, file)
            } else {
                Ok(Gitignore::empty())
            }
        };
        let rgignore = read(".rgignore", &directory.join(".rgignore"))?;
        let ignore = read(".ignore", &directory.join(".ignore"))?;
        let gitignore = read(".gitignore", &directory.join(".gitignore"))?;
        let dot_git = directory.join(".git");
        let marker = holds(".git").then(|| fs::metadata(&dot_git).ok()).flatten();
        let exclude = match &marker {
            None => Gitignore::empty(),
            Some(metadata) if !metadata.is_file() => {
                self.rules(directory, &dot_git.join("info/exclude"))?
            }
            Some(_) => match self.common_directory(&dot_git)? {
                None => return Ok(None),
                Some(None) => Gitignore::empty(),
                Some(Some(common)) => self.rules(directory, &common.join("info/exclude"))?,
            },
        };
        Ok(Some(DirectoryRules {
            repository: marker.is_some(),
            rgignore,
            ignore,
            gitignore,
            exclude,
            parent,
        }))
    }

    /// The global excludes file's rules where every version of ripgrep
    /// reads the same file and matches it alike, and none otherwise.
    fn global_rules(&mut self) -> Result<Gitignore, ObservationFailure> {
        let Some((file, configuration_files)) = global_excludes_file() else {
            return Ok(Gitignore::empty());
        };
        for configuration in &configuration_files {
            self.depend(configuration)?;
        }
        self.depend(&file)?;
        // ripgrep reads the file only when it is a regular one.
        if !fs::metadata(&file).is_ok_and(|metadata| metadata.is_file()) {
            return Ok(Gitignore::empty());
        }
        let (rules, text) = self.read_rules(Path::new("/"), &file)?;
        Ok(if text.lines().all(unanchored) {
            rules
        } else {
            Gitignore::empty()
        })
    }

    /// The common directory a worktree's `.git` file names, read as ripgrep
    /// reads it: Ok(Some(None)) where ripgrep finds none and so reads no
    /// `info/exclude`, and Ok(None) where it would look from the directory
    /// it runs in or the files are not read whole.
    fn common_directory(
        &mut self,
        dot_git: &Path,
    ) -> Result<Option<Option<PathBuf>>, ObservationFailure> {
        self.depend(dot_git)?;
        let Some(first) = first_line(dot_git) else {
            return Ok(None);
        };
        let Some(first) = first else {
            return Ok(Some(None));
        };
        let Some(git_directory) = first.strip_prefix("gitdir: ") else {
            return Ok(Some(None));
        };
        let git_directory = Path::new(git_directory);
        if !git_directory.is_absolute() {
            return Ok(None);
        }
        let commondir = git_directory.join("commondir");
        self.depend(&commondir)?;
        let Some(common) = first_line(&commondir) else {
            return Ok(None);
        };
        let Some(common) = common else {
            return Ok(Some(None));
        };
        let common = if common.starts_with('.') {
            git_directory.join(common)
        } else {
            PathBuf::from(common)
        };
        Ok(common.is_absolute().then_some(Some(common)))
    }

    /// The rules of the ignore file at `file`, matched from `directory`. A
    /// missing file holds none.
    fn rules(&mut self, directory: &Path, file: &Path) -> Result<Gitignore, ObservationFailure> {
        self.read_rules(directory, file).map(|(rules, _)| rules)
    }

    /// The rules of the ignore file at `file`, matched from `directory`, and
    /// its text. One that cannot be read whole within the bounds, or holds a
    /// line ripgrep could not parse, is not answered for.
    fn read_rules(
        &mut self,
        directory: &Path,
        file: &Path,
    ) -> Result<(Gitignore, String), ObservationFailure> {
        let unavailable = ObservationFailure::Unavailable;
        self.depend(file)?;
        let Some(opened) = open_regular(file)? else {
            return Ok((Gitignore::empty(), String::new()));
        };
        self.files += 1;
        let mut bytes = Vec::new();
        opened
            .take(RULE_FILE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable)?;
        self.bytes += bytes.len() as u64;
        if self.files > RULE_FILES_MAX
            || bytes.len() as u64 > RULE_FILE_MAX_BYTES
            || self.bytes > RULE_BYTES_MAX
        {
            return Err(unavailable);
        }
        let text = String::from_utf8(bytes).map_err(|_| unavailable)?;
        let mut builder = GitignoreBuilder::new(directory);
        for (index, line) in text.lines().enumerate() {
            // ripgrep drops a byte order mark, as Git does.
            let line = if index == 0 {
                line.trim_start_matches('\u{feff}')
            } else {
                line
            };
            builder
                .add_line(Some(file.to_path_buf()), line)
                .map_err(|_| unavailable)?;
        }
        Ok((builder.build().map_err(|_| unavailable)?, text))
    }
}

/// Whether an ignore-file line matches the same entries wherever it is
/// matched from: a comment or blank line, or a pattern with no `/` but a
/// trailing one, which ripgrep matches against an entry's name alone.
fn unanchored(line: &str) -> bool {
    let line = line.trim_start_matches('\u{feff}');
    let pattern = line.strip_prefix('!').unwrap_or(line);
    line.starts_with('#') || !pattern.trim_end().trim_end_matches('/').contains('/')
}

/// The first line of the small file at `path`: Some(None) where ripgrep
/// reads none, None where it is not a regular file read whole or is not
/// Unicode.
fn first_line(path: &Path) -> Option<Option<String>> {
    let text = match small_text(path, GIT_POINTER_MAX_BYTES) {
        Ok(Some(text)) => text,
        // ripgrep reads no line from a file it cannot open.
        Ok(None) => return Some(None),
        Err(_) => return None,
    };
    Some(text.lines().next().map(str::to_owned))
}

/// The global excludes file ripgrep reads: the one `~/.gitconfig` names,
/// else the one `$XDG_CONFIG_HOME/git/config` (or `~/.config/git/config`)
/// names, else `git/ignore` in that configuration directory. None where
/// versions of ripgrep may read another file, because `GIT_CONFIG_GLOBAL`,
/// `GIT_CONFIG_SYSTEM` or `/etc/gitconfig` may name one, or where a
/// configuration file is not read whole or names it in a form other than a
/// plain `excludesfile = PATH` line. No configuration file is read before
/// those are ruled out. With it come the configuration files whose content
/// or creation could name another.
fn global_excludes_file() -> Option<(PathBuf, Vec<PathBuf>)> {
    let set = |name| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    if set("GIT_CONFIG_GLOBAL")
        || set("GIT_CONFIG_SYSTEM")
        || fs::symlink_metadata("/etc/gitconfig").is_ok()
    {
        return None;
    }
    // The home directory ripgrep reads, as `std::env::home_dir` answers it.
    let home = std::env::home_dir();
    let configuration = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|home| home.join(".config")));
    let configuration_files = [
        home.as_ref().map(|home| home.join(".gitconfig")),
        configuration
            .as_ref()
            .map(|directory| directory.join("git/config")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let mut named = None;
    for file in &configuration_files {
        let text = small_text(file, GIT_CONFIG_MAX_BYTES).ok()?;
        if let Some(line) = text.and_then(|text| excludes_file_line(&text, home.as_deref())) {
            named = Some(line?);
            break;
        }
    }
    let file = named.or_else(|| configuration.map(|directory| directory.join("git/ignore")))?;
    let consulted = configuration_files
        .into_iter()
        .chain([PathBuf::from("/etc/gitconfig")])
        .collect();
    Some((file, consulted))
}

/// The excludes file a configuration's text names, as ripgrep finds it:
/// the first line reading `excludesfile = PATH`, in any section and any
/// case, with each `~` in PATH replaced by `home`. Some(None) where a line
/// mentions it in any other form, which ripgrep's own reading may take
/// differently, or names a relative path; None where no line mentions it.
pub(crate) fn excludes_file_line(text: &str, home: Option<&Path>) -> Option<Option<PathBuf>> {
    // The whitespace ripgrep's pattern skips around the name and value.
    let space: &[char] = &[' ', '\t', '\n', '\r', '\x0b', '\x0c'];
    let line = text
        .lines()
        .find(|line| line.to_ascii_lowercase().contains("excludesfile"))?;
    let line = line.trim_matches(space);
    let value = line
        .get(.."excludesfile".len())
        .filter(|name| name.eq_ignore_ascii_case("excludesfile"))
        .and_then(|_| {
            line["excludesfile".len()..]
                .trim_start_matches(space)
                .strip_prefix('=')
        })
        .map(|value| value.trim_start_matches(space))
        .filter(|value| {
            !value.is_empty()
                && !value.contains(|character: char| character.is_whitespace() || character == '"')
        });
    let file = value.map(|value| match home.and_then(Path::to_str) {
        Some(home) => PathBuf::from(value.replace('~', home)),
        None => PathBuf::from(value),
    });
    Some(file.filter(|file| file.is_absolute()))
}

/// The text of the regular file at `path`, read whole within `max_bytes`:
/// Ok(None) where nothing is there, and unavailable where it is not a
/// regular file, is longer, or is not Unicode.
fn small_text(path: &Path, max_bytes: u64) -> Result<Option<String>, ObservationFailure> {
    let unavailable = ObservationFailure::Unavailable;
    let Some(file) = open_regular(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable)?;
    if bytes.len() as u64 > max_bytes {
        return Err(unavailable);
    }
    String::from_utf8(bytes).map(Some).map_err(|_| unavailable)
}

/// The regular file at `path`, opened through links without waiting on a
/// FIFO or a device: Ok(None) where nothing is there, and unavailable where
/// something other than a regular file is, or it cannot be opened.
fn open_regular(path: &Path) -> Result<Option<fs::File>, ObservationFailure> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(None);
        }
        Err(_) => return Err(ObservationFailure::Unavailable),
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(ObservationFailure::Unavailable);
    }
    Ok(Some(file))
}

/// The entries of `directory` with their types, as a walk that does not
/// follow links sees them, each taken from `remaining`: Ok(None) where the
/// directory cannot be read, and unavailable once `remaining` runs out.
fn listing(
    directory: &Path,
    remaining: &AtomicUsize,
) -> Result<Option<Vec<DirectoryEntry>>, ObservationFailure> {
    match read_directory(directory, remaining) {
        Err(_) => Ok(None),
        Ok(Listed { whole: false, .. }) => Err(ObservationFailure::Unavailable),
        Ok(Listed { entries, .. }) => Ok(entries.into_iter().collect::<Result<_, _>>().ok()),
    }
}

fn listed(listing: &[DirectoryEntry], name: &str) -> bool {
    listing.iter().any(|held| held.name == name)
}

/// `path` with its components joined by `/`, as entries are named.
fn slash_separated(path: &Path) -> Option<String> {
    path.components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
        .map(|components| components.join("/"))
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
/// none; one that is not a regular file read whole is not answered for.
fn re_includes(path: &Path) -> Result<bool, ObservationFailure> {
    let Some(file) = open_regular(path)? else {
        return Ok(false);
    };
    let mut bytes = Vec::new();
    file.take(RULE_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ObservationFailure::Unavailable)?;
    if bytes.len() as u64 > RULE_FILE_MAX_BYTES {
        return Err(ObservationFailure::Unavailable);
    }
    Ok(bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line.first() == Some(&b'!')))
}
