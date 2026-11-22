//! What a Git staging selection takes once the call's own earlier changes to
//! host files have run (`GitReadSelection::changes`). Git answers for the
//! disk, the index and the ignore rules as they stand; the changes are then
//! applied to that answer. Where a change rewrites or removes an ignore file,
//! the ignore rules are decided in this process the way Git decides them,
//! and that decision is first checked against Git's own for the rules as
//! they stand, so a rule this reading gets wrong is never trusted.

use crate::git_read::{
    MAX_BYTES, command_pathspecs, excludes_options, repository_excludes_file, selected_paths,
};
use crate::git_state::git_exit_and_output;
use crate::io_paths::{canonical_absolute, dataless, host_platform};
use crate::roots::GitWait;
use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{
    GitReadKind, GitReadSelection, MAX_GIT_STATE_ENTRIES, ObservationFailure, StagingOperation,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Most changes one answer applies.
const MAX_CHANGES: usize = 256;

/// Most bytes of one ignore file read.
const RULE_FILE_MAX_BYTES: u64 = 64 * 1024;

/// The text an ignore file holds before the changes it may have appended.
#[derive(Clone, PartialEq)]
enum RuleText {
    /// The file as it stands on disk.
    Disk,
    /// This text; empty once the file is removed.
    Known(String),
    /// Text this answer cannot know: the file is taken to re-include
    /// everything below its directory, which stages the most.
    Unknown,
}

/// One text an ignore file may hold once the changes before the staging
/// have run: `base`, then each text appended to it, with whether that
/// append surely ran (`true`) or may not have. Each appended text starts a
/// line of its own, so one that did not run leaves the others' lines as
/// they are, and the reading stands for every text its uncertain appends
/// can leave.
#[derive(Clone, PartialEq)]
struct Reading {
    base: RuleText,
    appended: Vec<(String, bool)>,
}

impl Reading {
    const UNKNOWN: Reading = Reading {
        base: RuleText::Unknown,
        appended: Vec::new(),
    };
}

/// Most readings of one ignore file kept before it is taken as unknown.
const MAX_READINGS: usize = 64;

/// Where a path stands once the changes before the staging have run. A
/// change that may not have finished first leaves a file that may be there.
#[derive(PartialEq)]
enum Fate {
    /// No change reaches it.
    Untouched,
    /// A change surely removed it and nothing wrote it again.
    Gone,
    /// A change wrote it, or may have.
    Written,
}

pub(crate) fn staged_after(
    directory: &str,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
) -> Result<Vec<AbsolutePath>, ObservationFailure> {
    use GitReadKind::*;
    let unavailable = ObservationFailure::Unavailable;
    if !matches!(
        selection.kind,
        Addable | AddableAll | AddableTracked | AddableHead | Renormalized
    ) || selection.changes.len() > MAX_CHANGES
    {
        return Err(unavailable);
    }
    let run = |at: &str, args: &[&str], input: &[u8]| {
        git_exit_and_output(git, at, args, MAX_BYTES, wait, input)
    };
    let (code, bytes) = run(
        directory,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--git-common-dir",
            "--absolute-git-dir",
        ],
        &[],
    )?;
    if code != Some(0) {
        return Err(unavailable);
    }
    let text = String::from_utf8(bytes).map_err(|_| ObservationFailure::NonUnicode)?;
    let [top, common, git_dir] = text.lines().collect::<Vec<_>>()[..] else {
        return Err(unavailable);
    };
    let root = canonical_absolute(Path::new(top))?;
    let root_path = PathBuf::from(root.as_str());
    let git_dirs = [
        canonical_absolute(Path::new(common))?,
        canonical_absolute(Path::new(git_dir))?,
    ]
    .map(|path| PathBuf::from(path.as_str()));
    let exclude = git_dirs[0].join("info/exclude");
    let excludes_file = excludes_file(&root, selection, git, wait)?;
    let ignore_case = {
        let (code, bytes) = run(
            root.as_str(),
            &["config", "--bool", "--get", "core.ignoreCase"],
            &[],
        )?;
        code == Some(0) && bytes.trim_ascii() == b"true"
    };
    let mut pathspecs = command_pathspecs(directory, &root, selection)?;

    // Each change at its real path, and where it falls.
    let mut changes = Vec::new();
    let mut rules_change = false;
    for change in &selection.changes {
        // A delete removes the entry it names, a link itself rather than
        // what the link points to; a write goes through the link.
        let real = match change.operation {
            StagingOperation::Delete { .. } => entry_path(Path::new(&change.path))?,
            StagingOperation::Write { .. } => real_path(Path::new(&change.path))?,
        };
        let rule = real.file_name().is_some_and(|name| name == ".gitignore")
            && real.starts_with(&root_path)
            || real == exclude
            || excludes_file.as_ref() == Some(&real);
        let deletes_rules = matches!(
            change.operation,
            StagingOperation::Delete { recursive: true }
        ) && [exclude.as_path()]
            .into_iter()
            .chain(excludes_file.as_deref())
            .any(|file| file.starts_with(&real));
        // A removed work tree or Git directory, a change elsewhere in the
        // Git directory, or one to a configuration file that may name other
        // ignore rules, is not answered for.
        if root_path.starts_with(&real)
            || !rule
                && (real.starts_with(root_path.join(".git"))
                    || git_dirs.iter().any(|git_dir| real.starts_with(git_dir)))
            || !real.starts_with(&root_path)
                && !rule
                && real
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with("config"))
        {
            return Err(unavailable);
        }
        rules_change |= rule
            || deletes_rules
            || matches!(
                change.operation,
                StagingOperation::Delete { recursive: true }
            ) && real.starts_with(&root_path);
        changes.push((real, change));
    }
    let fate = |path: &Path| {
        let mut fate = Fate::Untouched;
        for (real, change) in &changes {
            match &change.operation {
                StagingOperation::Write { .. } if real == path => fate = Fate::Written,
                StagingOperation::Delete { recursive }
                    if change.certain && (real == path || *recursive && path.starts_with(real)) =>
                {
                    fate = Fate::Gone
                }
                _ => {}
            }
        }
        fate
    };
    // The readings of the ignore file `file` once the changes have run. A
    // change that may not have run first leaves the reading before it beside
    // the one it makes, and a rewrite that may have failed an empty file
    // too; one that surely ran leaves only its own. An append adds to each
    // reading.
    let rule_readings = |file: &Path| -> Vec<Reading> {
        let mut readings = vec![Reading {
            base: RuleText::Disk,
            appended: Vec::new(),
        }];
        for (real, change) in &changes {
            let reaches = match &change.operation {
                StagingOperation::Write { .. } => real == file,
                StagingOperation::Delete { recursive } => {
                    real == file || *recursive && file.starts_with(real)
                }
            };
            if !reaches {
                continue;
            }
            let replaced = |text: RuleText| Reading {
                base: text,
                appended: Vec::new(),
            };
            let mut after = match &change.operation {
                // What a recursive delete reaches is not listed here, so
                // whether it ran is not read file by file.
                StagingOperation::Delete { recursive: true } if !change.certain => {
                    vec![Reading::UNKNOWN]
                }
                StagingOperation::Delete { .. } => vec![replaced(RuleText::Known(String::new()))],
                StagingOperation::Write { content: None, .. } => vec![Reading::UNKNOWN],
                StagingOperation::Write {
                    content: Some(content),
                    append: false,
                } if change.certain => vec![replaced(RuleText::Known(content.clone()))],
                StagingOperation::Write {
                    content: Some(content),
                    append: false,
                } => vec![
                    replaced(RuleText::Known(content.clone())),
                    replaced(RuleText::Known(String::new())),
                ],
                StagingOperation::Write {
                    content: Some(content),
                    append: true,
                } => readings
                    .iter()
                    .map(|reading| appended(reading, file, content, change.certain))
                    .collect(),
            };
            if !change.certain
                && !matches!(
                    change.operation,
                    StagingOperation::Write { append: true, .. }
                )
            {
                after.extend(readings);
            }
            readings = Vec::new();
            for reading in after {
                if !readings.contains(&reading) {
                    readings.push(reading);
                }
            }
            if readings.len() > MAX_READINGS || readings.contains(&Reading::UNKNOWN) {
                readings = vec![Reading::UNKNOWN];
            }
        }
        readings
    };

    let before = GitReadSelection {
        changes: Vec::new(),
        ..selection.clone()
    };
    let relative = |path: &Path| {
        path.strip_prefix(&root_path)
            .ok()
            .and_then(|rest| rest.to_str())
            .filter(|rest| !rest.is_empty())
            .map(str::to_owned)
    };
    // What the selection takes as the disk stands, and for `git add` what
    // its ignore rules leave out of it now.
    let mut candidates = BTreeMap::new();
    for path in selected_paths(directory, &before, git, wait)? {
        candidates.insert(
            PathBuf::from(path.as_str()),
            (path.as_str().to_owned(), true),
        );
    }
    if selection.kind == Addable {
        let all = GitReadSelection {
            kind: AddableAll,
            ..before.clone()
        };
        for path in selected_paths(directory, &all, git, wait)? {
            candidates
                .entry(PathBuf::from(path.as_str()))
                .or_insert((path.as_str().to_owned(), false));
        }
    }
    for (real, change) in &changes {
        if matches!(change.operation, StagingOperation::Write { .. })
            && !real.starts_with(root_path.join(".git"))
            && !git_dirs.iter().any(|git_dir| real.starts_with(git_dir))
            && let Some(rest) = relative(real)
            && pathspecs
                .pattern_matching_relative_path(
                    rest.as_str().into(),
                    Some(false),
                    &mut |_, _, _, _| false,
                )
                .is_some_and(|matched| !matched.is_excluded())
        {
            candidates
                .entry(real.clone())
                .or_insert((change.path.clone(), false));
        }
    }
    candidates.retain(|path, _| fate(path) != Fate::Gone);
    let relatives = candidates
        .keys()
        .map(|path| relative(path).ok_or(unavailable))
        .collect::<Result<Vec<_>, _>>()?;
    let listed = |args: &[&str]| -> Result<BTreeSet<String>, ObservationFailure> {
        let input = relatives.iter().fold(Vec::new(), |mut input, path| {
            input.extend_from_slice(path.as_bytes());
            input.push(0);
            input
        });
        let (code, bytes) = run(root.as_str(), args, &input)?;
        if !matches!(code, Some(0 | 1)) {
            return Err(unavailable);
        }
        Ok(String::from_utf8(bytes)
            .map_err(|_| ObservationFailure::NonUnicode)?
            .split_terminator('\0')
            .map(str::to_owned)
            .collect())
    };
    let tracked = if relatives.is_empty() {
        BTreeSet::new()
    } else {
        let mut args = vec!["ls-files", "--cached", "--full-name", "-z", "--"];
        let literal = relatives
            .iter()
            .map(|path| format!(":(literal){path}"))
            .collect::<Vec<_>>();
        args.extend(literal.iter().map(String::as_str));
        let (code, bytes) = run(root.as_str(), &args, &[])?;
        if code != Some(0) {
            return Err(unavailable);
        }
        String::from_utf8(bytes)
            .map_err(|_| ObservationFailure::NonUnicode)?
            .split_terminator('\0')
            .map(str::to_owned)
            .collect()
    };
    let ignored_now = if selection.kind == Addable && !relatives.is_empty() {
        let mut args = excludes_options(selection, git, root.as_str(), wait)?;
        args.extend(["check-ignore", "--no-index", "--stdin", "-z"].map(str::to_owned));
        listed(&args.iter().map(String::as_str).collect::<Vec<_>>())?
    } else {
        BTreeSet::new()
    };
    let mut rules = Rules {
        root: root_path.clone(),
        exclude,
        excludes_file,
        ignore_case,
        matchers: BTreeMap::new(),
    };
    let mut staged = Vec::new();
    for ((path, (spelled, selected)), rest) in candidates.iter().zip(&relatives) {
        let written = fate(path) == Fate::Written;
        let tracked = tracked.contains(rest);
        // An untracked file is staged unless the rules leave it out; a
        // tracked one when it changed, whatever they say.
        let takes = match selection.kind {
            Addable if tracked => *selected || written,
            Addable if rules_change => {
                let disk = |_: &Path| {
                    vec![Reading {
                        base: RuleText::Disk,
                        appended: Vec::new(),
                    }]
                };
                // Read as Git reads the rules now, or not at all.
                if rules.may_take(rest, &disk)? == ignored_now.contains(rest) {
                    return Err(unavailable);
                }
                rules.may_take(rest, &rule_readings)?
            }
            Addable => !ignored_now.contains(rest),
            AddableAll => true,
            _ => *selected || written && tracked,
        };
        if takes {
            staged.push(
                AbsolutePath::new(host_platform(), spelled.clone()).map_err(|_| unavailable)?,
            );
        }
    }
    staged.sort();
    staged.dedup();
    if staged.len() > MAX_GIT_STATE_ENTRIES {
        return Err(unavailable);
    }
    Ok(staged)
}

/// The global excludes file Git reads for `selection`: the one
/// `core.excludesFile` names, from the top level `root` where it is
/// relative, else `git/ignore` in the XDG configuration directory. Where the
/// call changes which configuration files Git reads, only one the
/// repository's own configuration names (`excludes_options`).
fn excludes_file(
    root: &AbsolutePath,
    selection: &GitReadSelection,
    git: &Path,
    wait: GitWait,
) -> Result<Option<PathBuf>, ObservationFailure> {
    let named = if selection.user_configuration_changed {
        repository_excludes_file(git, root.as_str(), wait)?
    } else {
        let (code, bytes) = git_exit_and_output(
            git,
            root.as_str(),
            &["config", "--path", "--get", "core.excludesFile"],
            MAX_BYTES,
            wait,
            &[],
        )?;
        match code {
            Some(0) => Some(
                String::from_utf8(bytes)
                    .map_err(|_| ObservationFailure::NonUnicode)?
                    .trim_end_matches(['\r', '\n'])
                    .to_owned(),
            ),
            Some(1) => None,
            _ => return Err(ObservationFailure::Unavailable),
        }
    };
    let named = match named {
        Some(named) => Path::new(root.as_str()).join(named),
        None if selection.user_configuration_changed => return Ok(None),
        None => match std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
            Some(configuration) => PathBuf::from(configuration).join("git/ignore"),
            None => match std::env::var_os("HOME") {
                Some(home) => PathBuf::from(home).join(".config/git/ignore"),
                None => return Ok(None),
            },
        },
    };
    if !named.is_absolute() {
        return Err(ObservationFailure::Unavailable);
    }
    real_path(&named).map(Some)
}

/// `reading` once `content` is appended to the ignore file `file` it reads,
/// by an append that surely ran (`certain`) or may not have. A sure append
/// with nothing uncertain before it joins the text as the file would; any
/// other starts a line of its own only where the text before it ends one,
/// and is otherwise not known.
fn appended(reading: &Reading, file: &Path, content: &str, certain: bool) -> Reading {
    let base = match &reading.base {
        RuleText::Disk => match read_rules(file) {
            Ok(on_disk) => on_disk,
            Err(_) => return Reading::UNKNOWN,
        },
        RuleText::Known(text) => text.clone(),
        RuleText::Unknown => return Reading::UNKNOWN,
    };
    if certain && reading.appended.is_empty() {
        return Reading {
            base: RuleText::Known(base + content),
            appended: Vec::new(),
        };
    }
    let before = reading
        .appended
        .last()
        .map_or(base.as_str(), |(text, _)| text.as_str());
    if !before.is_empty() && !before.ends_with('\n') {
        return Reading::UNKNOWN;
    }
    let mut reading = reading.clone();
    reading.appended.push((content.to_owned(), certain));
    reading
}

/// `path` with its parent resolved through links and its own name kept.
fn entry_path(path: &Path) -> Result<PathBuf, ObservationFailure> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Ok(real_path(parent)?.join(name)),
        _ => Err(ObservationFailure::Unavailable),
    }
}

/// `path` with its longest existing ancestor resolved through links, so
/// a path the call creates is placed where the disk puts it.
fn real_path(path: &Path) -> Result<PathBuf, ObservationFailure> {
    if !path.is_absolute() {
        return Err(ObservationFailure::Unavailable);
    }
    let mut rest = Vec::new();
    let mut existing = path;
    loop {
        match fs::canonicalize(existing) {
            Ok(real) => {
                return Ok(rest.iter().rev().fold(real, |real, name| real.join(name)));
            }
            Err(_) => match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    rest.push(name.to_owned());
                    existing = parent;
                }
                _ => return Err(ObservationFailure::Unavailable),
            },
        }
    }
}

/// The text of the ignore file `file` on disk: none where it is missing. A
/// link, a dataless item, or one that is too large or not Unicode is not
/// read.
fn read_rules(file: &Path) -> Result<String, ObservationFailure> {
    let unavailable = ObservationFailure::Unavailable;
    let metadata = match fs::symlink_metadata(file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(_) => return Err(unavailable),
    };
    if !metadata.is_file() || dataless(file, &metadata) || metadata.len() > RULE_FILE_MAX_BYTES {
        return Err(unavailable);
    }
    let mut bytes = Vec::new();
    fs::File::open(file)
        .map_err(|_| unavailable)?
        .take(RULE_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable)?;
    String::from_utf8(bytes).map_err(|_| unavailable)
}

/// Git's ignore rules for one work tree, each file's read once per text.
struct Rules {
    root: PathBuf,
    exclude: PathBuf,
    excludes_file: Option<PathBuf>,
    ignore_case: bool,
    matchers: BTreeMap<(PathBuf, Option<String>), Gitignore>,
}

/// What one ignore file may decide for an entry: leave it out, take it
/// back in, or say nothing so the next file decides.
#[derive(Default)]
struct Decisions {
    ignore: bool,
    include: bool,
    none: bool,
}

impl Rules {
    /// Whether Git may take the untracked file at `path`, relative to the
    /// top level, into `git add` with each ignore file holding one of the
    /// readings `readings` gives: no directory above it nor itself is
    /// surely left out. A file below an ignored directory is ignored whatever
    /// re-includes it, as Git never looks inside that directory. Each
    /// entry's readings are taken apart from the others', which may take a
    /// file no single set of texts takes, never the reverse.
    fn may_take(
        &mut self,
        path: &str,
        readings: &dyn Fn(&Path) -> Vec<Reading>,
    ) -> Result<bool, ObservationFailure> {
        let parts = path.split('/').collect::<Vec<_>>();
        for end in 1..=parts.len() {
            let is_directory = end < parts.len();
            if !self.may_keep(&parts[..end], is_directory, readings)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the entry `parts` below the top level may be left in, by
    /// the rules from the highest precedence down: the `.gitignore` of the
    /// directory holding it and then of each one above, `info/exclude`,
    /// then the global excludes file. The first file that decides it wins,
    /// and within one file the last matching line decides.
    fn may_keep(
        &mut self,
        parts: &[&str],
        is_directory: bool,
        readings: &dyn Fn(&Path) -> Vec<Reading>,
    ) -> Result<bool, ObservationFailure> {
        let path = parts
            .iter()
            .fold(self.root.clone(), |path, part| path.join(part));
        let mut sources = (0..parts.len())
            .rev()
            .map(|depth| {
                let base = parts[..depth]
                    .iter()
                    .fold(self.root.clone(), |base, part| base.join(part));
                (base.join(".gitignore"), base)
            })
            .collect::<Vec<_>>();
        sources.push((self.exclude.clone(), self.root.clone()));
        if let Some(file) = &self.excludes_file {
            sources.push((file.clone(), self.root.clone()));
        }
        for (file, base) in sources {
            let mut decisions = Decisions::default();
            for reading in readings(&file) {
                self.decisions(&file, &base, &reading, &path, is_directory, &mut decisions)?;
            }
            if decisions.include {
                return Ok(true);
            }
            if !decisions.none {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Adds to `decisions` what the ignore file `file`, holding `reading`,
    /// may decide for `path`: the last appended text that matches it and
    /// surely ran decides, and each later one that may have run may decide
    /// instead; with none that surely ran, the text before them may too.
    fn decisions(
        &mut self,
        file: &Path,
        base: &Path,
        reading: &Reading,
        path: &Path,
        is_directory: bool,
        decisions: &mut Decisions,
    ) -> Result<(), ObservationFailure> {
        let mut add = |decided: Match<&ignore::gitignore::Glob>| match decided {
            Match::Ignore(_) => decisions.ignore = true,
            Match::Whitelist(_) => decisions.include = true,
            Match::None => decisions.none = true,
        };
        for (text, certain) in reading.appended.iter().rev() {
            let decided = self
                .matcher(file, base, Some(text.clone()))?
                .matched(path, is_directory);
            let matched = !decided.is_none();
            if matched {
                add(decided);
            }
            if matched && *certain {
                return Ok(());
            }
        }
        match &reading.base {
            RuleText::Unknown => decisions.include = true,
            RuleText::Disk => add(self.matcher(file, base, None)?.matched(path, is_directory)),
            RuleText::Known(known) => add(self
                .matcher(file, base, Some(known.clone()))?
                .matched(path, is_directory)),
        }
        Ok(())
    }

    fn matcher(
        &mut self,
        file: &Path,
        base: &Path,
        known: Option<String>,
    ) -> Result<&Gitignore, ObservationFailure> {
        let key = (file.to_path_buf(), known);
        if !self.matchers.contains_key(&key) {
            let text = match &key.1 {
                Some(known) => known.clone(),
                None => read_rules(file)?,
            };
            let unavailable = ObservationFailure::Unavailable;
            let mut builder = GitignoreBuilder::new(base);
            builder
                .case_insensitive(self.ignore_case)
                .map_err(|_| unavailable)?;
            for (index, line) in text.lines().enumerate() {
                // Git drops a byte order mark.
                let line = if index == 0 {
                    line.trim_start_matches('\u{feff}')
                } else {
                    line
                };
                builder.add_line(None, line).map_err(|_| unavailable)?;
            }
            self.matchers
                .insert(key.clone(), builder.build().map_err(|_| unavailable)?);
        }
        Ok(&self.matchers[&key])
    }
}
