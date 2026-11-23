//! Supplied state: a frozen decision context and the host facts a call is
//! decided from, in the shape the corpus fixtures and session replay share.
//! Nothing here observes the host.

use std::collections::{BTreeMap, BTreeSet};

use nah_proto::ctx::{AbsolutePath, Ctx, GuardLevel, GuardSettings, Platform, SchemaVersion};
use nah_proto::effinterp_proto;
use nah_proto::labels::{lexical_path::same_path, lexically_contains};
use nah_proto::observation::{
    DescendantObservation, EnvObservation, GitHistoryObservation, GitStateObservation,
    IgnoredEntriesObservation, IgnoredEntry, NestedRepositoryObservation, Observation,
    ObservationFact, ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue,
    Observed, PathKind, PathObservation, Root, RootKind, SymlinkTraversal, UserHomeObservation,
};
use nah_proto::runtime_protection::SelfProtectionProjection;
use serde::Deserialize;

/// A frozen decision context: platform, home, guard settings and enforcement
/// posture.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFixture {
    platform: Platform,
    home: String,
    guard_settings: GuardPosture,
    /// The enforcement an operator's `nah nap` leaves in force. Replay takes it
    /// from the fixture, so a paused posture never reads or writes nap state.
    #[serde(default)]
    enforcement: EnforcementPosture,
    /// Hook files this fixture treats as installed. Absent means none: a write
    /// to another runtime's hook file then stays an ordinary path.
    #[serde(default)]
    protected_paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EnforcementPosture {
    #[default]
    Normal,
    SelfProtectionPaused,
    AllPaused,
}

/// The guard settings a fixture runs under: a fresh install (every guard at
/// core), every rule enabled, every guard off, or explicit settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", untagged)]
enum GuardPosture {
    Named(NamedPosture),
    Settings(GuardSettings),
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum NamedPosture {
    FactoryDefaults,
    AllEnabled,
    AllDisabled,
}

/// Frozen host facts for a corpus case; a path or user it does not declare cannot
/// be observed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFixture {
    platform: Platform,
    pub cwd: String,
    /// The project directories the runtime reports with the call, such as
    /// Claude Code's `CLAUDE_PROJECT_DIR` or a multi-root workspace's roots.
    #[serde(default)]
    pub project_dirs: Vec<String>,
    env: BTreeMap<String, Option<String>>,
    /// The home directory the account database records for each user a case
    /// expands with `~name`; `null` records a user the database has no entry
    /// for. Like an undeclared path, a user the fixture does not declare
    /// cannot be answered.
    #[serde(default)]
    users: BTreeMap<String, Option<String>>,
    #[serde(default)]
    process_identity: Option<effinterp_proto::ProcessIdentity>,
    paths: Vec<PathFixture>,
    roots: Vec<RootFixture>,
    /// What each Git repository holds that is in no commit, by the directory
    /// it is found from. A repository the fixture does not declare cannot be
    /// observed, as on a host where `git status` fails.
    #[serde(default)]
    git_state: Vec<GitStateFixture>,
    /// The directory the repository holding `cwd` runs its hooks from, as
    /// Git resolves its `core.hooksPath`. Absent, it cannot be observed.
    #[serde(default)]
    git_hooks: Option<String>,
    /// The packages each project directory has installed or locked, by
    /// ecosystem, each name with every version found. A directory and
    /// ecosystem the fixture does not declare cannot be observed.
    #[serde(default)]
    installed_packages: Vec<InstalledPackagesFixture>,
    /// The members of each archive file, as the host's reader lists them. An
    /// archive the fixture does not declare cannot be listed.
    #[serde(default)]
    archives: Vec<ArchiveFixture>,
    /// Exact filename-only Git read answers; absent queries are unobserved.
    #[serde(default)]
    git_reads: Vec<GitReadFixture>,
    /// The entries Git's ignore rules leave out of a search, by the
    /// directory searched. A directory the fixture does not declare cannot
    /// be observed, as one outside any repository.
    #[serde(default)]
    ignored_entries: Vec<IgnoredEntriesFixture>,
    /// The command lines of the running processes, as `ps -axww -o
    /// command=` lists them. Absent, they cannot be observed.
    #[serde(default)]
    processes: Option<Vec<String>>,
    /// The user's crontab; `null` for none. Absent, it cannot be observed.
    #[serde(default, deserialize_with = "present")]
    crontab: Option<Option<String>>,
}

/// A key that is present, even as `null`, is `Some`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledPackagesFixture {
    directory: String,
    ecosystem: nah_proto::labels::dependency::Ecosystem,
    packages: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveFixture {
    archive: String,
    members: Vec<nah_proto::observation::ArchiveMember>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IgnoredEntriesFixture {
    path: String,
    entries: Vec<IgnoredEntryFixture>,
    /// The files whose rules decide the entries, as absolute paths.
    #[serde(default)]
    rule_files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IgnoredEntryFixture {
    /// The entry's path below the searched directory; a directory ends in
    /// `/`.
    path: String,
    /// The ignore-file line that matches it.
    pattern: String,
    /// The file holding that line, as a path below the searched directory;
    /// absent for one above it or the global excludes file.
    #[serde(default)]
    rule_file: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitReadFixture {
    path: String,
    selection: nah_proto::observation::GitReadSelection,
    paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitStateFixture {
    path: String,
    /// The pathspecs, as Git reads them in `path` by the mode options
    /// `pathspec_options`, the state is limited to; it answers only a query
    /// naming exactly these. A state with none is the whole tree's, which
    /// also answers pathspecs that are plain absolute paths: Git's answer
    /// for them lists its untracked entries that lie at or below one, and
    /// keeps the whole tree's tracked changes.
    #[serde(default)]
    pathspecs: Vec<String>,
    #[serde(default)]
    pathspec_options: Vec<String>,
    /// The top level of the working tree found from `path`; absent, `path`
    /// is itself the top level.
    #[serde(default)]
    top_level: Option<String>,
    /// A tracked file differs from `HEAD`, so a copy from the index or
    /// `HEAD` may change one. A copy from another tree cannot be answered.
    #[serde(default)]
    tracked_changes: bool,
    /// The stash holds an entry.
    #[serde(default)]
    stash_entries: bool,
    /// Untracked entries no ignore rule matches, as paths below the top
    /// level; a directory ends in `/`.
    #[serde(default)]
    untracked: Vec<String>,
    /// Untracked entries an ignore rule matches, spelled the same way.
    #[serde(default)]
    ignored: Vec<String>,
    /// Git records the next move of `HEAD` in a reflog that no setting
    /// expires early.
    #[serde(default)]
    moves_logged: bool,
    /// Git creates a reflog for each ref it moves.
    #[serde(default)]
    creates_reflogs: bool,
    /// `refs/original/` holds a backup.
    #[serde(default)]
    backups: bool,
    /// The revisions whose history holds `HEAD`'s commit.
    #[serde(default)]
    targets_holding_head: Vec<String>,
    /// The content digest of each path the index holds, as a path below the
    /// top level. Absent, the index cannot be observed.
    #[serde(default)]
    index: Option<BTreeMap<String, String>>,
    /// The content digest of each path `HEAD`'s tree holds, spelled the same
    /// way. Absent, it cannot be observed.
    #[serde(default)]
    head: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathFixture {
    requested: String,
    resolved: String,
    #[serde(default)]
    realpath: Option<String>,
    kind: PathKind,
    #[serde(default)]
    target_kind: Option<PathKind>,
    exists: bool,
    /// Bytes a source request for this file is answered with, as UTF-8 text.
    /// Every source the corpus declares is text; no binary form is needed.
    #[serde(default)]
    contents: Option<String>,
    /// The file is larger than the engine's source limit, so a read refuses
    /// it unread and its bytes are not declared.
    #[serde(default)]
    oversize: bool,
    /// Every readable regular file beneath this directory, recursively. An
    /// absent list was never observed; an empty one was observed as empty.
    #[serde(default)]
    descendants: Option<Vec<String>>,
    #[serde(default)]
    descendants_incomplete: bool,
    /// Each link a link-following walk below this directory went through, as
    /// its path in the walk and the path it leads to.
    #[serde(default)]
    links: Vec<(String, String)>,
    /// The directory holds an entry the snapshot does not list: an
    /// unfollowed link or an empty directory.
    #[serde(default)]
    descendants_unlisted: bool,
    /// Whether the host reports this file as one a command search may
    /// execute. Absent, the replay does not say, so a PATH search that
    /// reaches the file certifies nothing.
    #[serde(default)]
    executable: Option<bool>,
    /// When the entry was last modified, in nanoseconds since the Unix
    /// epoch. Absent, it cannot be observed.
    #[serde(default)]
    modified_ns: Option<u64>,
    /// For a missing path, where a lookup through its existing parent's
    /// links lands. Absent, that identity is not observed.
    #[serde(default)]
    followed: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFixture {
    kind: RootKind,
    path: String,
}

impl ContextFixture {
    pub fn validate(&self) -> Result<(), String> {
        AbsolutePath::new(self.platform, &self.home)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn context(&self) -> Result<Ctx, String> {
        Ctx::new(
            self.platform,
            AbsolutePath::new(self.platform, &self.home).map_err(|error| error.to_string())?,
            match &self.guard_settings {
                GuardPosture::Named(NamedPosture::FactoryDefaults) => GuardSettings::default(),
                GuardPosture::Named(NamedPosture::AllEnabled) => crate::all_rules_enabled(),
                GuardPosture::Named(NamedPosture::AllDisabled) => {
                    GuardSettings::every_guard_at(GuardLevel::Off)
                }
                GuardPosture::Settings(settings) => settings.clone(),
            },
        )
        .map_err(|error| error.to_string())
    }

    /// The shipped rules a replay under this fixture runs, at least their
    /// core parts, or none when an all-enforcement nap is in force. A project
    /// declaration is not part of a fixture.
    pub fn enabled_rules(&self) -> Result<BTreeSet<String>, String> {
        if matches!(self.enforcement, EnforcementPosture::AllPaused) {
            return Ok(BTreeSet::new());
        }
        let ctx = self.context()?;
        let shipped = nah_policy::ShippedGuards::new();
        Ok(shipped
            .rule_ids()
            .iter()
            .filter(|rule| {
                let level = ctx.guard_settings().rule_level(rule);
                shipped.parts(rule).any(|part| level >= part.applies_at)
            })
            .map(|rule| (*rule).to_owned())
            .collect())
    }

    pub const fn platform(&self) -> Platform {
        self.platform
    }

    pub fn self_protection(&self) -> Result<SelfProtectionProjection, String> {
        let paths = self
            .protected_paths
            .iter()
            .map(|path| AbsolutePath::new(self.platform, path).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SelfProtectionProjection::new(paths))
    }

    pub const fn enforcement(&self) -> nah_policy::EnforcementMode {
        match self.enforcement {
            EnforcementPosture::Normal => nah_policy::EnforcementMode::Normal,
            EnforcementPosture::SelfProtectionPaused => {
                nah_policy::EnforcementMode::SelfProtectionPaused
            }
            EnforcementPosture::AllPaused => nah_policy::EnforcementMode::AllPaused,
        }
    }
}

impl ObservationFixture {
    pub const fn platform(&self) -> Platform {
        self.platform
    }

    /// What the fixture declares at `path`, by its requested or resolved
    /// spelling; `None` when it declares nothing there.
    pub fn declared_path(&self, path: &str) -> Option<DeclaredPath<'_>> {
        self.paths
            .iter()
            .find(|entry| entry.requested == path || entry.resolved == path)
            .map(|entry| DeclaredPath {
                resolved: &entry.resolved,
                realpath: entry.realpath.as_deref(),
                kind: entry.kind,
                contents: entry.contents.as_deref(),
                oversize: entry.oversize,
                modified_ns: entry.modified_ns,
                followed: entry.followed.as_deref(),
                links: &entry.links,
            })
    }

    /// The variable `name`: `Some(None)` when declared unset, `None` when
    /// not declared.
    pub fn declared_env(&self, name: &str) -> Option<Option<&str>> {
        self.env.get(name).map(Option::as_deref)
    }

    /// The Git state whose top level holds `path`, from a whole-tree entry.
    pub fn repository_holding(&self, path: &str) -> Option<DeclaredRepository<'_>> {
        self.git_state
            .iter()
            .filter(|state| state.pathspecs.is_empty())
            .map(|state| (state, state.top_level.as_ref().unwrap_or(&state.path)))
            .filter(|(_, top)| lexically_contains(top, path, self.platform))
            .max_by_key(|(_, top)| top.len())
            .map(|(state, top)| DeclaredRepository {
                top_level: top,
                ignored: &state.ignored,
                index: state.index.as_ref(),
                head: state.head.as_ref(),
            })
    }

    pub fn declared_processes(&self) -> Option<&[String]> {
        self.processes.as_deref()
    }

    /// The crontab: `Some(None)` for none, `None` when not declared.
    pub fn declared_crontab(&self) -> Option<Option<&str>> {
        self.crontab.as_ref().map(Option::as_deref)
    }

    pub fn validate(&self) -> Result<(), String> {
        AbsolutePath::new(self.platform, &self.cwd).map_err(|error| error.to_string())?;
        for path in self
            .users
            .values()
            .flatten()
            .chain(self.roots.iter().map(|root| &root.path))
        {
            AbsolutePath::new(self.platform, path).map_err(|error| error.to_string())?;
        }
        let mut aliases = BTreeMap::<&str, &PathFixture>::new();
        for path in &self.paths {
            if path.requested.is_empty()
                || path.exists != (path.kind != PathKind::Missing)
                || path.exists != path.realpath.is_some()
                || path.target_kind.is_some() && path.kind != PathKind::Symlink
                || path.contents.is_some() && path.kind != PathKind::File
                || path.oversize && (path.kind != PathKind::File || path.contents.is_some())
                || path.executable.is_some()
                    && !matches!(path.kind, PathKind::File | PathKind::Symlink)
                || path.followed.is_some() && path.exists
            {
                return Err(format!("inconsistent path fixture `{}`", path.requested));
            }
            AbsolutePath::new(self.platform, &path.resolved).map_err(|error| error.to_string())?;
            if let Some(realpath) = &path.realpath {
                AbsolutePath::new(self.platform, realpath).map_err(|error| error.to_string())?;
            }
            for descendant in path.descendants.iter().flatten() {
                AbsolutePath::new(self.platform, descendant).map_err(|error| error.to_string())?;
            }
            for alias in [&path.requested, &path.resolved] {
                if let Some(previous) = aliases.get(alias.as_str())
                    && !path.has_same_fact(previous)
                {
                    return Err(format!("conflicting path fixture alias `{alias}`"));
                }
                aliases.insert(alias, path);
            }
        }
        for directory in &self.paths {
            let Some((realpath, descendants)) = directory.complete_inventory() else {
                continue;
            };
            for file in self.paths.iter().filter(|path| path.kind == PathKind::File) {
                let file = file.realpath.as_deref().expect("validated file realpath");
                if lexically_contains(realpath, file, self.platform)
                    && !same_path(realpath, file, self.platform)
                    && !descendants
                        .iter()
                        .any(|descendant| same_path(descendant, file, self.platform))
                {
                    return Err(format!(
                        "complete descendant inventory for `{}` omits declared file `{file}`",
                        directory.requested
                    ));
                }
            }
        }
        Ok(())
    }

    /// The sources this fixture can answer a source request with, admitted
    /// beneath its own cwd — plus the Cargo install registry — exactly as
    /// production admits beneath the invocation cwd. A path the fixture does
    /// not declare does not exist, and any other declared path outside the cwd
    /// escapes it, so a replay never reads the analysing host's disk and never
    /// observes more than the invocation could.
    pub fn sources(&self) -> Result<crate::DeclaredSourceObservations, String> {
        use crate::DeclaredSource;

        let mut declared = BTreeMap::new();
        let mut listings = BTreeMap::new();
        let mut realpaths = BTreeMap::new();
        // Absolute on the fixture's platform, not the replaying host's: a
        // Linux fixture's `/work/...` names no drive, so Windows would call it
        // relative and serve none of its bytes.
        let absolute = |alias: &str| AbsolutePath::new(self.platform, alias).is_ok();
        for path in &self.paths {
            for alias in [&path.requested, &path.resolved] {
                if absolute(alias) {
                    realpaths.insert(
                        alias.clone(),
                        path.realpath
                            .clone()
                            .unwrap_or_else(|| path.resolved.clone()),
                    );
                }
            }
            let source = match (path.kind, &path.contents) {
                (PathKind::Missing, _) => continue,
                (PathKind::File, Some(contents)) => {
                    DeclaredSource::Contents(contents.clone().into_bytes())
                }
                (PathKind::File, None) if path.oversize => DeclaredSource::TooLarge,
                (PathKind::Directory, _) => DeclaredSource::NotAFile,
                // The path exists, so it is not missing; its bytes are simply
                // undeclared, and unproven bytes are never served as empty ones.
                _ => DeclaredSource::Unreadable,
            };
            let entries = path.listed_entries();
            for alias in [&path.requested, &path.resolved] {
                if absolute(alias) {
                    declared.insert(alias.clone(), source.clone());
                    if let Some(entries) = &entries {
                        listings.insert(alias.clone(), entries.clone());
                    }
                }
            }
        }
        Ok(crate::DeclaredSourceObservations::new(
            AbsolutePath::new(self.platform, &self.cwd).map_err(|error| error.to_string())?,
            declared,
            listings,
            realpaths,
        ))
    }

    /// Initial metadata for the engine, independent of source-byte admission.
    /// Undeclared queries remain unobserved; no path on the replay host is read.
    pub fn observations(&self) -> std::sync::Arc<dyn crate::ObservationResolver> {
        std::sync::Arc::new(FixtureObservations {
            paths: self.paths.clone(),
        })
    }

    pub fn observation(&self, request: &ObservationRequest) -> Result<Observation, String> {
        let absolute =
            |path: &str| AbsolutePath::new(self.platform, path).map_err(|error| error.to_string());
        let roots = self
            .roots
            .iter()
            .map(|root| Ok(Root::new(root.kind, absolute(&root.path)?)))
            .collect::<Result<Vec<_>, String>>()?;
        let mut facts = Vec::new();
        for query in request
            .queries()
            .iter()
            .filter(|query| !matches!(query, ObservationQuery::GrepNonMatching { .. }))
            .cloned()
        {
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute(&self.cwd)?,
                    },
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: roots.clone(),
                    },
                },
                // Every host has a PATH, so a fixture that declares none has
                // not observed one; answering unset would claim the shell's
                // default search instead.
                ObservationQuery::Env { name, .. }
                    if name == "PATH" && !self.env.contains_key(name) =>
                {
                    ObservationValue::Env {
                        observed: Observed::Error {
                            error: ObservationFailure::Unavailable,
                        },
                    }
                }
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: match self.env.get(name).and_then(Option::as_ref) {
                            Some(text) => EnvObservation::Value { text: text.clone() },
                            None => EnvObservation::Unset,
                        },
                    },
                },
                ObservationQuery::CredentialEnvironment { .. } => {
                    ObservationValue::CredentialEnvironment {
                        variables: self
                            .env
                            .iter()
                            .filter(|(name, _)| nah_proto::labels::is_credential_shaped_name(name))
                            .filter_map(|(name, value)| Some((name.clone(), value.clone()?)))
                            .collect(),
                    }
                }
                ObservationQuery::UserHome { name, .. } => ObservationValue::UserHome {
                    observed: Observed::Ok {
                        value: match self
                            .users
                            .get(name)
                            .ok_or_else(|| format!("fixture has no user `{name}`"))?
                        {
                            Some(home) => UserHomeObservation::Home {
                                path: absolute(home)?,
                            },
                            None => UserHomeObservation::NoSuchUser,
                        },
                    },
                },
                ObservationQuery::ProcessIdentity { .. } => ObservationValue::ProcessIdentity {
                    observed: match &self.process_identity {
                        Some(value) => Observed::Ok {
                            value: value.clone(),
                        },
                        None => Observed::Error {
                            error: ObservationFailure::Unavailable,
                        },
                    },
                },
                ObservationQuery::Path {
                    requested,
                    inspect_descendants,
                    symlink_traversal,
                    skip_ignored,
                    ..
                } => {
                    let path = self
                        .paths
                        .iter()
                        .find(|path| path.requested == *requested || path.resolved == *requested)
                        .ok_or_else(|| format!("fixture has no path `{requested}`"))?;
                    let mut value = PathObservation::new(
                        absolute(&path.resolved)?,
                        path.realpath.as_deref().map(absolute).transpose()?,
                        path.kind,
                    );
                    if let Some(target_kind) = path.target_kind {
                        value = value.with_target_kind(target_kind);
                    }
                    if *inspect_descendants {
                        // The declared links are the ones a link-following
                        // walk went through. A walk that leaves one unfollowed
                        // lists neither the link nor what it alone reaches,
                        // and marks the snapshot unlisted, as the host walk
                        // does.
                        let (followed, unfollowed): (Vec<_>, Vec<_>) =
                            path.links.iter().partition(|(visible, _)| {
                                *symlink_traversal == SymlinkTraversal::All
                                    || *symlink_traversal == SymlinkTraversal::Root
                                        && *visible == path.resolved
                            });
                        let root = path.realpath.as_deref().unwrap_or(&path.resolved);
                        let within = |entry: &str, base: &str| {
                            entry
                                .strip_prefix(base)
                                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                        };
                        let links = followed
                            .into_iter()
                            .map(|(visible, target)| Ok((absolute(visible)?, absolute(target)?)))
                            .collect::<Result<Vec<_>, String>>()?;
                        // A walk that skips ignored directories enters none
                        // the declared ignored entries name, as the host walk
                        // does.
                        let ignored_directories = self
                            .ignored_entries
                            .iter()
                            .filter(|ignored| *skip_ignored && ignored.path == *requested)
                            .flat_map(|ignored| &ignored.entries)
                            .filter_map(|entry| entry.path.strip_suffix('/'))
                            .map(|directory| format!("{}/{directory}", path.resolved))
                            .collect::<Vec<_>>();
                        let snapshot = DescendantObservation::new(
                            path.descendants
                                .iter()
                                .flatten()
                                .filter(|descendant| {
                                    !unfollowed.iter().any(|(visible, target)| {
                                        within(descendant, visible)
                                            || within(descendant, target)
                                                && !within(descendant, root)
                                    }) && !ignored_directories
                                        .iter()
                                        .any(|directory| within(descendant, directory))
                                })
                                .map(|descendant| absolute(descendant))
                                .collect::<Result<Vec<_>, _>>()?,
                            !path.descendants_incomplete,
                        )
                        .and_then(|descendants| descendants.with_links(links))
                        .map_err(|error| error.to_string())?
                        .with_ignored_directories(
                            ignored_directories
                                .iter()
                                .map(|directory| absolute(directory))
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                        .map_err(|error| error.to_string())?;
                        // A fixture declares every link below the path, so a
                        // walk that follows them all names every link.
                        let snapshot = if unfollowed.is_empty() {
                            snapshot.with_every_link_named()
                        } else {
                            snapshot
                        };
                        value = value.with_descendants(
                            if path.descendants_unlisted || !unfollowed.is_empty() {
                                snapshot.with_unlisted_entries()
                            } else {
                                snapshot
                            },
                        );
                    }
                    ObservationValue::Path {
                        observed: Observed::Ok { value },
                    }
                }
                ObservationQuery::GitState {
                    requested,
                    inspect_history,
                    head_targets,
                    pathspecs,
                    pathspec_options,
                    restores,
                    untracked,
                    ..
                } => ObservationValue::GitState {
                    observed: match self.git_state.iter().find(|state| {
                        &state.path == requested
                            && (state.pathspecs.is_empty()
                                && pathspecs
                                    .iter()
                                    .all(|pathspec| pathspec.starts_with('/') || pathspec == ":/")
                                || (&state.pathspecs, &state.pathspec_options)
                                    == (pathspecs, pathspec_options))
                    }) {
                        Some(state)
                            if !matches!(
                                restores,
                                Some(nah_proto::observation::GitRestoreSource::Tree(revision))
                                    if revision != "HEAD"
                            ) =>
                        {
                            use nah_proto::observation::GitCleanIgnored;
                            let top_level = state.top_level.as_ref().unwrap_or(&state.path);
                            // An entry at or below a pathspec, or a folder
                            // listed whole that holds one.
                            let under = |path: &str, folder: &str| {
                                let folder = folder.trim_end_matches('/');
                                path == folder || path.starts_with(&format!("{folder}/"))
                            };
                            let reaches = |entries: &[String]| {
                                entries.iter().any(|entry| {
                                    !state.pathspecs.is_empty()
                                        || pathspecs.is_empty()
                                        || pathspecs.iter().any(|pathspec| {
                                            if pathspec == ":/" {
                                                return true;
                                            }
                                            let entry = format!("{top_level}/{entry}");
                                            let entry = entry.trim_end_matches('/');
                                            under(entry, pathspec) || under(pathspec, entry)
                                        })
                                })
                            };
                            let mut value =
                                GitStateObservation::new(absolute(top_level)?, state.stash_entries);
                            if restores.is_some() {
                                value = value.with_restores_nothing(!state.tracked_changes);
                            }
                            if let Some(kind) = untracked {
                                value = value.with_untracked(
                                    *kind != GitCleanIgnored::Only && reaches(&state.untracked)
                                        || *kind != GitCleanIgnored::No && reaches(&state.ignored),
                                );
                            }
                            if *inspect_history {
                                value = value.with_history(GitHistoryObservation {
                                    moves_logged: state.moves_logged,
                                    creates_reflogs: state.creates_reflogs,
                                    backups: state.backups,
                                    targets_holding_head: head_targets
                                        .iter()
                                        .filter(|target| {
                                            state.targets_holding_head.contains(target)
                                        })
                                        .cloned()
                                        .collect(),
                                });
                            }
                            Observed::Ok { value }
                        }
                        _ => Observed::Error {
                            error: ObservationFailure::Unavailable,
                        },
                    },
                },
                ObservationQuery::GitHooks { .. } => ObservationValue::GitHooks {
                    observed: match &self.git_hooks {
                        Some(hooks) => Observed::Ok {
                            value: absolute(hooks)?,
                        },
                        None => Observed::Error {
                            error: ObservationFailure::Unavailable,
                        },
                    },
                },
                ObservationQuery::GitRead {
                    requested,
                    selection,
                    ..
                } => ObservationValue::GitRead {
                    observed: match self
                        .git_reads
                        .iter()
                        .find(|read| read.path == *requested && read.selection == *selection)
                    {
                        Some(read) => Observed::Ok {
                            value: read
                                .paths
                                .iter()
                                .map(|path| absolute(path))
                                .collect::<Result<_, _>>()?,
                        },
                        None => Observed::Error {
                            error: ObservationFailure::Unavailable,
                        },
                    },
                },
                ObservationQuery::IgnoredEntries { requested, .. } => {
                    ObservationValue::IgnoredEntries {
                        observed: match self
                            .ignored_entries
                            .iter()
                            .find(|ignored| &ignored.path == requested)
                        {
                            None => Observed::Error {
                                error: ObservationFailure::Unavailable,
                            },
                            Some(ignored) => Observed::Ok {
                                value: IgnoredEntriesObservation::new(
                                    ignored
                                        .entries
                                        .iter()
                                        .map(|entry| {
                                            IgnoredEntry::new(
                                                entry.path.clone(),
                                                entry.pattern.clone(),
                                                entry.rule_file.clone(),
                                            )
                                        })
                                        .collect(),
                                    ignored.rule_files.clone(),
                                )
                                .map_err(|error| error.to_string())?,
                            },
                        },
                    }
                }
                ObservationQuery::NestedRepository { requested, .. } => {
                    ObservationValue::NestedRepository {
                        observed: self.nested_repository(requested),
                    }
                }
                ObservationQuery::GrepNonMatching { .. } => {
                    unreachable!("handled after path observations")
                }
                ObservationQuery::InstalledPackages {
                    directory,
                    ecosystem,
                    names,
                    ..
                } => ObservationValue::InstalledPackages {
                    observed: match self.installed_packages.iter().find(|fixture| {
                        same_path(&fixture.directory, directory.as_str(), self.platform)
                            && fixture.ecosystem == *ecosystem
                    }) {
                        // As the host observer answers: only the packages
                        // named, or one edit from a name, asked about.
                        Some(fixture) => Observed::Ok {
                            value: fixture
                                .packages
                                .iter()
                                .filter(|(name, _)| {
                                    names.iter().any(|asked| {
                                        asked == *name
                                            || nah_proto::labels::dependency::one_edit_apart(
                                                asked, name,
                                            )
                                    })
                                })
                                .map(|(name, versions)| (name.clone(), versions.clone()))
                                .collect(),
                        },
                        None => Observed::Error {
                            error: ObservationFailure::Unavailable,
                        },
                    },
                },
                ObservationQuery::ArchiveMembers { archive, .. } => {
                    ObservationValue::ArchiveMembers {
                        observed: match self.archives.iter().find(|fixture| {
                            same_path(&fixture.archive, archive.as_str(), self.platform)
                        }) {
                            Some(fixture) => Observed::Ok {
                                value: fixture.members.clone(),
                            },
                            None => Observed::Error {
                                error: ObservationFailure::Unavailable,
                            },
                        },
                    }
                }
            };
            facts.push(ObservationFact::new(query, value).map_err(|error| error.to_string())?);
        }
        for query in request.queries() {
            if let ObservationQuery::GrepNonMatching {
                path_key, search, ..
            } = query
            {
                let paths = facts
                    .iter()
                    .find_map(|fact| match fact.value() {
                        ObservationValue::Path {
                            observed: Observed::Ok { value },
                        } if fact.query().key() == path_key => value.descendants(),
                        _ => None,
                    })
                    .map(|snapshot| {
                        search.non_matching_paths(snapshot, self.platform, |path| {
                            let file = self
                                .paths
                                .iter()
                                .find(|file| file.resolved == path.as_str())?;
                            let canonical = file.realpath.as_deref().unwrap_or(&file.resolved);
                            if !nah_proto::labels::lexically_contains(
                                &self.cwd,
                                canonical,
                                self.platform,
                            ) {
                                return None;
                            }
                            self.paths
                                .iter()
                                .find(|file| file.resolved == canonical)
                                .and_then(|file| file.contents.as_ref())
                                .map(|contents| contents.as_bytes().to_vec())
                        })
                    })
                    .unwrap_or_default();
                facts.push(
                    ObservationFact::new(
                        query.clone(),
                        ObservationValue::GrepNonMatching { paths },
                    )
                    .map_err(|error| error.to_string())?,
                );
            }
        }
        Observation::new(SchemaVersion::V1, request.request_id(), facts)
            .map_err(|error| error.to_string())
    }

    /// What a search below `requested` for an entry named `.git`, in any
    /// letter case, finds: a
    /// declared path, or a declared descendant, inside one below it. Like
    /// the replay's descendant walk, it knows only what the fixture
    /// declares, and cannot finish where the descendants are declared
    /// incomplete, or where the path is a link or undeclared.
    fn nested_repository(&self, requested: &str) -> Observed<NestedRepositoryObservation> {
        let unavailable = Observed::Error {
            error: ObservationFailure::Unavailable,
        };
        let Some(path) = self
            .paths
            .iter()
            .find(|path| path.requested == requested || path.resolved == requested)
        else {
            return unavailable;
        };
        match path.kind {
            PathKind::Directory => {}
            PathKind::Symlink => return unavailable,
            PathKind::Missing | PathKind::File | PathKind::Fifo | PathKind::Other => {
                return Observed::Ok {
                    value: NestedRepositoryObservation::Absent,
                };
            }
        }
        let separators = ['/', '\\'];
        let in_marker = |entry: &str| {
            entry
                .strip_prefix(path.resolved.as_str())
                .and_then(|rest| rest.strip_prefix(separators))
                .is_some_and(|rest| {
                    rest.split(separators)
                        .any(|name| name.eq_ignore_ascii_case(".git"))
                })
        };
        if self
            .paths
            .iter()
            .filter(|declared| declared.exists)
            .any(|declared| in_marker(&declared.resolved))
            || path
                .descendants
                .iter()
                .flatten()
                .any(|entry| in_marker(entry))
        {
            Observed::Ok {
                value: NestedRepositoryObservation::Found,
            }
        } else if path.descendants_incomplete {
            unavailable
        } else {
            Observed::Ok {
                value: NestedRepositoryObservation::Absent,
            }
        }
    }
}

/// The existing entries a fixture declares strictly beneath `directory`,
/// each spelled as one path below it, with its kind.
fn declared_beneath<'a>(
    directory: &str,
    declared: impl Iterator<Item = (bool, PathKind, &'a str)>,
) -> impl Iterator<Item = (&'a str, PathKind)> {
    let prefix = format!("{}/", directory.trim_end_matches('/'));
    declared.filter_map(move |(exists, kind, path)| {
        let below = path.strip_prefix(&prefix)?;
        (exists
            && kind != PathKind::Missing
            && below
                .split('/')
                .all(|name| !name.is_empty() && name != "." && name != ".."))
        .then_some((path, kind))
    })
}

impl PathFixture {
    fn complete_inventory(&self) -> Option<(&str, &[String])> {
        match (self.kind, self.target_kind) {
            (PathKind::Directory, _) | (PathKind::Symlink, Some(PathKind::Directory)) => {}
            _ => return None,
        }
        if self.descendants_incomplete || self.descendants_unlisted || !self.links.is_empty() {
            return None;
        }
        Some((self.realpath.as_deref()?, self.descendants.as_deref()?))
    }

    /// The entries this fixture proves sit directly inside the directory it
    /// declares, or None when it declares no complete inventory of one.
    ///
    /// A walk through a link can omit the link entry itself, so its inventory
    /// cannot prove which files the directory holds directly.
    fn listed_entries(&self) -> Option<Vec<String>> {
        let (directory, descendants) = self.complete_inventory()?;
        let directory = directory.trim_end_matches('/');
        Some(
            descendants
                .iter()
                .filter(|descendant| {
                    descendant
                        .rsplit_once('/')
                        .is_some_and(|(parent, _)| parent == directory)
                })
                .cloned()
                .collect(),
        )
    }

    /// The engine's listing of this directory, as the descendant snapshot
    /// answers it: an undeclared inventory holds the existing entries the
    /// fixture declares beneath the directory, and one that is incomplete,
    /// leaves an entry unlisted or went through a link is refused, since the
    /// fixture cannot say what else the directory holds.
    fn listing(
        &self,
        depth: Option<u32>,
        declared: &[PathFixture],
    ) -> effinterp_proto::ObservationOutcome {
        use effinterp_proto::{ListingFact, ObservationOutcome, ObservationRefusal};
        let directory = match (self.kind, self.target_kind, &self.realpath) {
            (PathKind::Directory, _, Some(realpath))
            | (PathKind::Symlink, Some(PathKind::Directory), Some(realpath)) => realpath,
            (_, _, None) => return ObservationOutcome::Refused(ObservationRefusal::Unobserved),
            _ => return ObservationOutcome::Refused(ObservationRefusal::Unsupported),
        };
        if self.descendants_incomplete || self.descendants_unlisted || !self.links.is_empty() {
            return ObservationOutcome::Refused(ObservationRefusal::Unobserved);
        }
        let listing = match &self.descendants {
            Some(descendants) => {
                ListingFact::of_files(directory, descendants.iter().map(String::as_str), depth)
            }
            None => ListingFact::of_entries(
                directory,
                declared_beneath(
                    directory,
                    declared
                        .iter()
                        .map(|path| (path.exists, path.kind, path.resolved.as_str())),
                )
                .map(|(path, kind)| {
                    (
                        path,
                        match kind {
                            PathKind::Directory => effinterp_proto::PathKind::Directory,
                            PathKind::Symlink => effinterp_proto::PathKind::Symlink,
                            PathKind::Fifo => effinterp_proto::PathKind::Fifo,
                            PathKind::Missing | PathKind::File => effinterp_proto::PathKind::File,
                            PathKind::Other => effinterp_proto::PathKind::Other,
                        },
                    )
                }),
                depth,
            ),
        };
        listing.map_or(
            ObservationOutcome::Refused(ObservationRefusal::Invalid),
            ObservationOutcome::Listing,
        )
    }

    fn has_same_fact(&self, other: &Self) -> bool {
        self.resolved == other.resolved
            && self.realpath == other.realpath
            && self.kind == other.kind
            && self.target_kind == other.target_kind
            && self.exists == other.exists
            && self.contents == other.contents
            && self.oversize == other.oversize
            && self.descendants == other.descendants
            && self.descendants_incomplete == other.descendants_incomplete
            && self.links == other.links
            && self.descendants_unlisted == other.descendants_unlisted
            && self.executable == other.executable
            && self.modified_ns == other.modified_ns
            && self.followed == other.followed
    }
}

/// One path a fixture declares, as session replay reads it.
pub struct DeclaredPath<'a> {
    pub resolved: &'a str,
    pub realpath: Option<&'a str>,
    pub kind: PathKind,
    pub contents: Option<&'a str>,
    pub oversize: bool,
    pub modified_ns: Option<u64>,
    /// For a missing path, where a lookup through its existing parent's
    /// links lands.
    pub followed: Option<&'a str>,
    /// Each link a link-following walk below this directory went through,
    /// with the path it leads to.
    pub links: &'a [(String, String)],
}

/// One repository's declared state, as session replay reads it.
pub struct DeclaredRepository<'a> {
    pub top_level: &'a str,
    /// Untracked entries an ignore rule matches, below the top level; a
    /// directory ends in `/`.
    pub ignored: &'a [String],
    pub index: Option<&'a BTreeMap<String, String>>,
    pub head: Option<&'a BTreeMap<String, String>>,
}

struct FixtureObservations {
    paths: Vec<PathFixture>,
}

impl crate::ObservationResolver for FixtureObservations {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        budget: crate::ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        if !effinterp_proto::valid_observation_query(query) {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Invalid,
            );
        }
        if budget.expired {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Limit {
                    limit: "invocation_deadline".into(),
                },
            );
        }
        let (effinterp_proto::ObservationQuery::Path { path }
        | effinterp_proto::ObservationQuery::Listing { path, .. }) = query;
        let Some(entry) = self
            .paths
            .iter()
            .find(|entry| entry.requested == *path || entry.resolved == *path)
        else {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            );
        };
        if let effinterp_proto::ObservationQuery::Listing { depth, .. } = query {
            return entry.listing(*depth, &self.paths);
        }
        let missing = entry.kind == PathKind::Missing;
        if missing == entry.exists {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Invalid,
            );
        }
        let kind = |kind| match kind {
            PathKind::Missing => effinterp_proto::PathKind::Missing,
            PathKind::File => effinterp_proto::PathKind::File,
            PathKind::Directory => effinterp_proto::PathKind::Directory,
            PathKind::Symlink => effinterp_proto::PathKind::Symlink,
            PathKind::Fifo => effinterp_proto::PathKind::Fifo,
            PathKind::Other => effinterp_proto::PathKind::Other,
        };
        let followed = if missing {
            // Absence is proven, but the identity a lookup lands on through
            // the parent is a fact of its own; a lexical spelling cannot
            // supply it.
            match &entry.followed {
                Some(followed) => effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
                    path: followed.clone(),
                    kind: effinterp_proto::Fact::Known(effinterp_proto::PathKind::Missing),
                }),
                None => effinterp_proto::Fact::Unavailable(
                    effinterp_proto::ObservationRefusal::Unsupported,
                ),
            }
        } else if let Some(realpath) = &entry.realpath {
            effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
                path: realpath.clone(),
                kind: if entry.kind == PathKind::Symlink {
                    entry.target_kind.map(kind).map_or(
                        effinterp_proto::Fact::Unavailable(
                            effinterp_proto::ObservationRefusal::Unobserved,
                        ),
                        effinterp_proto::Fact::Known,
                    )
                } else {
                    effinterp_proto::Fact::Known(kind(entry.kind))
                },
            })
        } else {
            effinterp_proto::Fact::Unavailable(effinterp_proto::ObservationRefusal::Unobserved)
        };
        effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
            entry: entry.resolved.clone(),
            kind: kind(entry.kind),
            followed,
            executable: entry.executable,
        })
    }
}

#[cfg(test)]
mod tests {
    use nah_proto::observation::SymlinkTraversal;

    use super::*;

    fn symlink_fixture() -> ObservationFixture {
        ObservationFixture {
            platform: Platform::Linux,
            cwd: "/repo".into(),
            project_dirs: Vec::new(),
            env: BTreeMap::new(),
            users: BTreeMap::new(),
            process_identity: None,
            paths: vec![PathFixture {
                requested: "link".into(),
                resolved: "/repo/link".into(),
                realpath: Some("/outside/target".into()),
                kind: PathKind::Symlink,
                target_kind: Some(PathKind::File),
                exists: true,
                contents: None,
                oversize: false,
                descendants: None,
                descendants_incomplete: false,
                links: Vec::new(),
                descendants_unlisted: false,
                executable: None,
                modified_ns: None,
                followed: None,
            }],
            roots: vec![],
            git_state: vec![],
            git_hooks: None,
            installed_packages: Vec::new(),
            archives: Vec::new(),
            git_reads: vec![],
            ignored_entries: vec![],
            processes: None,
            crontab: None,
        }
    }

    fn path_request(requested: &str) -> ObservationRequest {
        ObservationRequest::new(
            SchemaVersion::V1,
            "fixture-test",
            vec![
                ObservationQuery::Cwd {
                    key: "cwd".into(),
                    requested: AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
                },
                ObservationQuery::Roots {
                    key: "roots".into(),
                    cwd_key: "cwd".into(),
                },
                ObservationQuery::Path {
                    key: "path".into(),
                    requested: requested.into(),
                    cwd_key: "cwd".into(),
                    inspect_descendants: false,
                    symlink_traversal: SymlinkTraversal::None,
                    skip_ignored: false,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn resolved_alias_preserves_symlink_identity() {
        let observation = symlink_fixture()
            .observation(&path_request("/repo/link"))
            .unwrap();
        let value = observation
            .facts()
            .iter()
            .find_map(|fact| match fact.value() {
                ObservationValue::Path {
                    observed: Observed::Ok { value },
                } => Some(value),
                _ => None,
            })
            .unwrap();

        assert_eq!(value.resolved().as_str(), "/repo/link");
        assert_eq!(
            value.realpath().map(AbsolutePath::as_str),
            Some("/outside/target")
        );
        assert_eq!(value.kind(), PathKind::Symlink);
        assert_eq!(value.target_kind(), Some(PathKind::File));

        {
            let mut fixture = symlink_fixture();
            // The same declared entry remains admitted outside the invocation cwd.
            fixture.cwd = "/elsewhere".into();
            let answer = fixture.observations().observe(
                &effinterp_proto::ObservationQuery::Path {
                    path: "/repo/link".into(),
                },
                crate::ObservationBudget {
                    remaining_requests: 63,
                    remaining_bytes: 4096,
                    expired: false,
                },
            );
            assert_eq!(
                answer,
                effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
                    entry: "/repo/link".into(),
                    kind: effinterp_proto::PathKind::Symlink,
                    followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
                        path: "/outside/target".into(),
                        kind: effinterp_proto::Fact::Known(effinterp_proto::PathKind::File),
                    }),
                    executable: None,
                })
            );
        }
    }

    #[test]
    fn undeclared_path_variants_remain_unknown() {
        let fixture = symlink_fixture();

        assert_eq!(
            fixture.observation(&path_request("/repo/./link")),
            Err("fixture has no path `/repo/./link`".into())
        );
        assert_eq!(
            fixture.observation(&path_request("/outside/target")),
            Err("fixture has no path `/outside/target`".into())
        );
        {
            let budget = crate::ObservationBudget {
                remaining_requests: 63,
                remaining_bytes: 4096,
                expired: false,
            };
            let observations = fixture.observations();
            for path in ["/repo/./link", "/outside/target"] {
                assert_eq!(
                    observations.observe(
                        &effinterp_proto::ObservationQuery::Path { path: path.into() },
                        budget
                    ),
                    effinterp_proto::ObservationOutcome::Refused(
                        effinterp_proto::ObservationRefusal::Unobserved
                    )
                );
            }
            assert_eq!(
                observations.observe(
                    &effinterp_proto::ObservationQuery::Path {
                        path: "link".into()
                    },
                    budget
                ),
                effinterp_proto::ObservationOutcome::Refused(
                    effinterp_proto::ObservationRefusal::Invalid
                )
            );
            let mut missing = symlink_fixture();
            missing.paths[0].kind = PathKind::Missing;
            missing.paths[0].exists = false;
            missing.paths[0].realpath = None;
            missing.paths[0].target_kind = None;
            assert_eq!(
                missing.observations().observe(
                    &effinterp_proto::ObservationQuery::Path {
                        path: "/repo/link".into()
                    },
                    budget
                ),
                effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
                    entry: "/repo/link".into(),
                    kind: effinterp_proto::PathKind::Missing,
                    followed: effinterp_proto::Fact::Unavailable(
                        effinterp_proto::ObservationRefusal::Unsupported
                    ),
                    executable: None,
                })
            );
        }
    }

    #[test]
    fn only_a_complete_declared_inventory_lists_a_directory() {
        let directory = |path: &str, descendants, incomplete| PathFixture {
            requested: path.into(),
            resolved: path.into(),
            realpath: Some(path.into()),
            kind: PathKind::Directory,
            target_kind: None,
            exists: true,
            contents: None,
            oversize: false,
            descendants,
            descendants_incomplete: incomplete,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
            modified_ns: None,
            followed: None,
        };
        let descendants = Some(vec![
            "/repo/root/main.tf".to_owned(),
            "/repo/root/modules/nested.tf".to_owned(),
        ]);

        // A complete inventory proves which readable files sit directly inside.
        assert_eq!(
            directory("/repo/root", descendants.clone(), false).listed_entries(),
            Some(vec!["/repo/root/main.tf".to_owned()])
        );
        // An observed-empty directory is listed as empty.
        assert_eq!(
            directory("/repo/empty", Some(vec![]), false).listed_entries(),
            Some(vec![])
        );
        // An absent or truncated inventory proves nothing about the entries.
        assert_eq!(directory("/repo/root", None, false).listed_entries(), None);
        assert_eq!(
            directory("/repo/root", descendants.clone(), true).listed_entries(),
            None
        );

        let mut linked = directory(
            "/repo/linked",
            Some(vec!["/elsewhere/nested.tf".into()]),
            false,
        );
        linked
            .links
            .push(("/repo/linked/vendor".into(), "/elsewhere".into()));
        assert_eq!(linked.listed_entries(), None);
        assert_eq!(
            directory("/repo/root/", descendants, false).listed_entries(),
            Some(vec!["/repo/root/main.tf".into()])
        );
        assert_eq!(
            directory("/", Some(vec!["/main.tf".into()]), false).listed_entries(),
            Some(vec!["/main.tf".into()])
        );
    }

    #[test]
    fn complete_inventory_must_include_declared_nested_files() {
        let mut fixture = symlink_fixture();
        fixture.paths = serde_json::from_str(
            r#"[
                {"requested":"C:/repo/src", "resolved":"C:\\repo\\src", "realpath":"C:\\repo\\src",
                 "kind":"directory", "exists":true, "descendants":[]},
                {"requested":"C:/repo/src/pkg/lib.rs", "resolved":"C:\\repo\\src\\pkg\\lib.rs",
                 "realpath":"C:\\repo\\src\\pkg\\lib.rs", "kind":"file", "exists":true}
            ]"#,
        )
        .unwrap();
        fixture.platform = Platform::Windows;
        fixture.cwd = "C:/repo".into();
        assert!(
            fixture
                .validate()
                .unwrap_err()
                .contains("omits declared file")
        );

        fixture.paths[0].descendants_incomplete = true;
        fixture.validate().unwrap();
        fixture.paths[0].descendants_incomplete = false;
        fixture.paths[0].descendants = Some(vec!["c:/repo/src/pkg/lib.rs".into()]);
        fixture.validate().unwrap();
    }

    #[test]
    fn declared_contents_require_a_file() {
        let mut fixture = symlink_fixture();
        fixture.paths.push(PathFixture {
            requested: "/repo/absent.json".into(),
            resolved: "/repo/absent.json".into(),
            realpath: None,
            kind: PathKind::Missing,
            target_kind: None,
            exists: false,
            oversize: false,
            contents: Some("{}".into()),
            descendants: None,
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
            modified_ns: None,
            followed: None,
        });

        assert_eq!(
            fixture.validate(),
            Err("inconsistent path fixture `/repo/absent.json`".into())
        );
    }

    #[test]
    fn conflicting_aliases_are_rejected() {
        let mut fixture = symlink_fixture();
        fixture.paths.push(PathFixture {
            requested: "/repo/link".into(),
            resolved: "/repo/link".into(),
            realpath: Some("/repo/link".into()),
            kind: PathKind::File,
            target_kind: None,
            exists: true,
            oversize: false,
            contents: None,
            descendants: None,
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
            modified_ns: None,
            followed: None,
        });

        assert_eq!(
            fixture.validate(),
            Err("conflicting path fixture alias `/repo/link`".into())
        );
    }
}
