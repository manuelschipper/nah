//! Request-bound tool-world observation contracts.

use crate::ctx::AbsolutePath;
use crate::ctx::SchemaVersion;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ObservationQuery {
    Cwd {
        key: String,
        requested: AbsolutePath,
    },
    Roots {
        key: String,
        cwd_key: String,
    },
    Env {
        key: String,
        name: String,
    },
    ProcessIdentity {
        key: String,
    },
    /// The value of every environment variable whose name says it holds a
    /// credential (`labels::is_credential_shaped_name`), which no call names.
    CredentialEnvironment {
        key: String,
    },
    /// The home directory the host account database records for user `name`.
    UserHome {
        key: String,
        name: String,
    },
    Path {
        key: String,
        requested: String,
        cwd_key: String,
        inspect_descendants: bool,
        symlink_traversal: SymlinkTraversal,
        /// The descendant walk does not enter a directory that the ignore
        /// files of a search leave out, as the `IgnoredEntries` observation
        /// of the same `requested` directory lists it, and names it in
        /// `DescendantObservation::ignored_directories` instead.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        skip_ignored: bool,
    },
    /// What the Git repository found from the directory `requested` holds
    /// that a discard would lose, as Git's plumbing answers it.
    /// `inspect_history` also reads what decides whether a rewrite of its
    /// history leaves commits out of reach, and which of `head_targets`,
    /// the revisions a reset moves `HEAD` to, already reach `HEAD`'s commit.
    /// With `pathspecs`, only what they match when Git runs in `requested`
    /// with the pathspec mode options `pathspec_options` (such as
    /// `--icase-pathspecs`): what a discard limited to them reaches, as Git
    /// itself matches it. `restores` asks whether a copy from that source
    /// would change nothing; `untracked` whether Git lists an untracked
    /// entry of that kind.
    GitState {
        key: String,
        requested: String,
        cwd_key: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        inspect_history: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        head_targets: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pathspecs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pathspec_options: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restores: Option<GitRestoreSource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        untracked: Option<GitCleanIgnored>,
        /// The ref deletes whose commits, together, the state also says
        /// another ref keeps.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        deleted_refs: Vec<RefDeletion>,
    },
    /// The directory the Git repository holding the observed working
    /// directory runs its hooks from: its `core.hooksPath`, from any
    /// configuration file Git reads, or else the Git directory's `hooks`.
    GitHooks {
        key: String,
        cwd_key: String,
    },
    /// The paths whose contents a Git search or patch can print.
    GitRead {
        key: String,
        requested: String,
        cwd_key: String,
        selection: GitReadSelection,
    },
    /// The entries below the directory `requested` that Git's ignore rules
    /// leave out of a search that honours them, as ripgrep reads those rules.
    IgnoredEntries {
        key: String,
        requested: String,
        cwd_key: String,
    },
    /// Whether an entry named `.git` in any letter case, of any kind, lies
    /// anywhere below the directory `requested`: a repository, linked
    /// worktree or submodule that a recursive delete of the directory takes
    /// with it. The search follows no link and draws on the request's
    /// descendant entry budget.
    NestedRepository {
        key: String,
        requested: String,
        cwd_key: String,
    },
    /// Non-matching credential files in the descendant snapshot at `path_key`.
    GrepNonMatching {
        key: String,
        path_key: String,
        search: crate::literal_grep::LiteralGrep,
    },
    /// The packages of `ecosystem` the project in `directory` has, among
    /// those whose normalized name is one of `names` or one edit from one
    /// (`labels::dependency::one_edit_apart`): what its environment holds
    /// (`.venv` site-packages, `node_modules`) and what its lock files pin.
    InstalledPackages {
        key: String,
        directory: AbsolutePath,
        ecosystem: crate::labels::dependency::Ecosystem,
        names: BTreeSet<String>,
    },
}

impl ObservationQuery {
    pub fn key(&self) -> &str {
        match self {
            Self::Cwd { key, .. }
            | Self::Roots { key, .. }
            | Self::Env { key, .. }
            | Self::ProcessIdentity { key }
            | Self::CredentialEnvironment { key }
            | Self::UserHome { key, .. }
            | Self::Path { key, .. }
            | Self::GitState { key, .. }
            | Self::GitHooks { key, .. }
            | Self::GitRead { key, .. }
            | Self::IgnoredEntries { key, .. }
            | Self::NestedRepository { key, .. }
            | Self::GrepNonMatching { key, .. }
            | Self::InstalledPackages { key, .. } => key,
        }
    }

    fn validate_scalars(&self) -> Result<(), BindingError> {
        if self.key().is_empty() {
            return Err(BindingError::EmptyIdentifier);
        }
        let valid = match self {
            Self::Cwd { .. }
            | Self::ProcessIdentity { .. }
            | Self::CredentialEnvironment { .. } => true,
            Self::Roots { cwd_key, .. } | Self::GitHooks { cwd_key, .. } => !cwd_key.is_empty(),
            Self::Env { name, .. } | Self::UserHome { name, .. } => !name.is_empty(),
            Self::Path {
                requested, cwd_key, ..
            }
            | Self::GitState {
                requested, cwd_key, ..
            }
            | Self::GitRead {
                requested, cwd_key, ..
            }
            | Self::IgnoredEntries {
                requested, cwd_key, ..
            }
            | Self::NestedRepository {
                requested, cwd_key, ..
            } => !requested.is_empty() && !cwd_key.is_empty(),
            Self::GrepNonMatching {
                path_key, search, ..
            } => !path_key.is_empty() && !search.patterns.is_empty(),
            Self::InstalledPackages { names, .. } => {
                !names.is_empty() && names.iter().all(|name| !name.is_empty())
            }
        };
        if valid {
            Ok(())
        } else {
            Err(BindingError::EmptyIdentifier)
        }
    }
}

/// The attribute a `git.read` carries when Git takes the bytes it reads into
/// the object store, as `git add` stages what its pathspec selects. The
/// policy's staging selector (`flow_guards::git_staged`) matches it, and the
/// bridge's `git add` staleness rules (`stages_git_add_selection`) read it.
pub const GIT_STAGING_PURPOSE: (&str, &str) = ("access_purpose", "program_input");

/// A Git content selection. Pathspecs are passed to Git unchanged, including
/// exclusions; only the listed global pathspec switches are accepted.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GitReadSelection {
    pub kind: GitReadKind,
    pub revisions: Vec<String>,
    pub revision_options: Vec<String>,
    pub pathspecs: Vec<String>,
    pub pathspec_options: Vec<String>,
    /// For a staging selection, the changes the call makes to host files
    /// before Git stages, in the order it makes them. The answer is then
    /// what the selection takes once they have run: every file of it, the
    /// written ones whatever their names, and of the others those a name
    /// labels secret.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<StagingChange>,
    /// The call itself changes which global or system configuration files
    /// Git reads (`GIT_CONFIG_GLOBAL`, `HOME`, ...). The answer then leaves
    /// out the rules of any global excludes file, which can only leave
    /// files out of what Git takes, so the call's own files cannot hide one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub user_configuration_changed: bool,
}

/// A change a call makes to one host path before a Git staging selection.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct StagingChange {
    /// The absolute path changed.
    pub path: String,
    pub operation: StagingOperation,
    /// The change has surely finished before Git stages. One that may run
    /// beside it, after it or not at all is `false`.
    pub certain: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum StagingOperation {
    /// Removes the path, and with `recursive` everything below it.
    Delete {
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        recursive: bool,
    },
    /// Writes the file. `content` is the text written, given where the
    /// path may hold ignore rules and the text is known; `append` adds it
    /// to the end.
    Write {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        append: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitReadKind {
    Tracked,
    Cached,
    Untracked,
    UntrackedAll,
    Directory,
    DirectoryExcluded,
    Diff,
    StagedDiff,
    HeadDiff,
    Commit,
    History,
    RevisionGrep,
    Stash,
    StashUntracked,
    StashOnlyUntracked,
    /// What `git add` stages: changed and untracked files, ignore rules
    /// honored.
    Addable,
    /// What `git add --force` stages: ignored files too.
    AddableAll,
    /// What `git add --update` stages: changed tracked files that exist.
    AddableTracked,
    /// What `git add --renormalize` stages: every tracked file that exists.
    Renormalized,
    /// What a commit of pathspecs alone takes (`--only`): tracked files that
    /// exist and whose work tree differs from `HEAD`, whatever the index
    /// holds.
    AddableHead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservationRequest {
    v: SchemaVersion,
    request_id: String,
    queries: Vec<ObservationQuery>,
}

impl ObservationRequest {
    /// Accepts either a nonempty environment-only preflight request or exactly one
    /// cwd/roots spine, optionally with environment, user-home, and path
    /// queries.
    /// Roots and all paths must reference that cwd. Query keys must be unique,
    /// and identifiers must be nonempty.
    /// Path symlink traversal beyond `None` requires descendant inspection.
    /// Requires schema V1 and a nonempty request ID; sorts queries by key.
    /// See `BindingError` for rejection codes, including invalid references.
    pub fn new(
        v: SchemaVersion,
        request_id: impl Into<String>,
        mut queries: Vec<ObservationQuery>,
    ) -> Result<Self, BindingError> {
        require_v1(v)?;
        let request_id = non_empty_binding_identifier(request_id)?;
        validate_queries(&queries)?;
        queries.sort_by(|left, right| left.key().cmp(right.key()));
        Ok(Self {
            v,
            request_id,
            queries,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub const fn version(&self) -> SchemaVersion {
        self.v
    }

    pub fn queries(&self) -> &[ObservationQuery] {
        &self.queries
    }
}

#[derive(Deserialize)]
struct RawObservationRequest {
    v: SchemaVersion,
    request_id: String,
    queries: Vec<ObservationQuery>,
}

impl<'de> Deserialize<'de> for ObservationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let version = decode_version::<D::Error>(&value)?;
        if version != SchemaVersion::V1 {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        let raw = serde_json::from_value::<RawObservationRequest>(value)
            .map_err(serde::de::Error::custom)?;
        Self::new(raw.v, raw.request_id, raw.queries).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Observed<T> {
    Ok { value: T },
    Error { error: ObservationFailure },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationFailure {
    InvalidPath,
    NotFound,
    PermissionDenied,
    Timeout,
    Unavailable,
    NonUnicode,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootKind {
    Project,
    WorktreeMain,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Root {
    kind: RootKind,
    path: AbsolutePath,
}

impl Root {
    pub fn new(kind: RootKind, path: AbsolutePath) -> Self {
        Self { kind, path }
    }

    pub const fn kind(&self) -> RootKind {
        self.kind
    }

    pub fn path(&self) -> &AbsolutePath {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnvObservation {
    Value { text: String },
    Unset,
}

/// A user the account database has no entry for is observed absent, which is
/// distinct from a lookup that failed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UserHomeObservation {
    Home { path: AbsolutePath },
    NoSuchUser,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathKind {
    Missing,
    File,
    Directory,
    Symlink,
    Fifo,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathObservation {
    resolved: AbsolutePath,
    #[serde(skip_serializing_if = "Option::is_none")]
    realpath: Option<AbsolutePath>,
    kind: PathKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_kind: Option<PathKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descendants: Option<DescendantObservation>,
}

impl PathObservation {
    pub fn new(resolved: AbsolutePath, realpath: Option<AbsolutePath>, kind: PathKind) -> Self {
        Self {
            resolved,
            realpath,
            kind,
            target_kind: None,
            descendants: None,
        }
    }

    pub fn with_target_kind(mut self, target_kind: PathKind) -> Self {
        self.target_kind = Some(target_kind);
        self
    }

    pub fn with_descendants(mut self, descendants: DescendantObservation) -> Self {
        self.descendants = Some(descendants);
        self
    }

    pub fn resolved(&self) -> &AbsolutePath {
        &self.resolved
    }

    pub fn realpath(&self) -> Option<&AbsolutePath> {
        self.realpath.as_ref()
    }

    pub const fn kind(&self) -> PathKind {
        self.kind
    }

    pub const fn target_kind(&self) -> Option<PathKind> {
        self.target_kind
    }

    pub fn descendants(&self) -> Option<&DescendantObservation> {
        self.descendants.as_ref()
    }
}

/// Most paths one descendant snapshot may carry.
pub const MAX_DESCENDANT_PATHS: usize = 10_000;
/// Most bytes of path text one descendant snapshot may carry.
pub const MAX_DESCENDANT_PATH_BYTES: usize = 1024 * 1024;
/// Most directory entries one observation request may inspect across all its
/// descendant snapshots.
pub const MAX_DESCENDANT_ENTRIES: usize = 10_000;
/// Deepest directory level below the requested path a descendant snapshot
/// descends to.
pub const MAX_DESCENDANT_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymlinkTraversal {
    None,
    Root,
    All,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DescendantObservation {
    paths: Vec<AbsolutePath>,
    complete: bool,
    /// Each symbolic link a link-following walk went through, as its path in
    /// the walk and the path it leads to. A walk that follows no link has
    /// none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    links: Vec<(AbsolutePath, AbsolutePath)>,
    /// The snapshot lists regular files. An entry beneath the root it omits,
    /// a link it did not follow, an empty directory, a special file, or an
    /// entry it could not read or reach within its budget, leaves the entries
    /// beneath the root unknown even when the listed files are complete.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unlisted_entries: bool,
    /// The walk left no link unfollowed, so every link below the root is
    /// among `links` and an unlisted entry is not one. Unset, a link may be
    /// hidden among the unlisted entries.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    names_every_link: bool,
    /// The directories a walk that skips ignored directories did not enter.
    /// `complete` and `unlisted_entries` describe the rest of the tree, so
    /// the snapshot answers as incomplete, with unlisted entries, unless
    /// the reader shows its search leaves out each of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ignored_directories: Vec<AbsolutePath>,
}

impl DescendantObservation {
    pub fn new(mut paths: Vec<AbsolutePath>, complete: bool) -> Result<Self, BindingError> {
        Self::normalize_paths(&mut paths)?;
        Ok(Self {
            paths,
            complete,
            links: Vec::new(),
            unlisted_entries: false,
            names_every_link: false,
            ignored_directories: Vec::new(),
        })
    }

    pub fn with_links(
        mut self,
        links: Vec<(AbsolutePath, AbsolutePath)>,
    ) -> Result<Self, BindingError> {
        self.links = links;
        Self::normalize_links(&mut self.links)?;
        Ok(self)
    }

    pub fn with_every_link_named(mut self) -> Self {
        self.names_every_link = true;
        self
    }

    pub fn with_unlisted_entries(mut self) -> Self {
        self.unlisted_entries = true;
        self
    }

    pub fn with_ignored_directories(
        mut self,
        directories: Vec<AbsolutePath>,
    ) -> Result<Self, BindingError> {
        self.ignored_directories = directories;
        Self::normalize_paths(&mut self.ignored_directories)?;
        Ok(self)
    }

    fn normalize(&mut self) -> Result<(), BindingError> {
        Self::normalize_paths(&mut self.paths)?;
        Self::normalize_paths(&mut self.ignored_directories)?;
        Self::normalize_links(&mut self.links)
    }

    fn normalize_links(links: &mut [(AbsolutePath, AbsolutePath)]) -> Result<(), BindingError> {
        if links.len() > MAX_DESCENDANT_PATHS {
            return Err(BindingError::ExceedsLimit);
        }
        links.sort();
        if links.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(BindingError::Duplicate);
        }
        Ok(())
    }

    fn normalize_paths(paths: &mut [AbsolutePath]) -> Result<(), BindingError> {
        if paths.len() > MAX_DESCENDANT_PATHS
            || paths.iter().map(|path| path.as_str().len()).sum::<usize>()
                > MAX_DESCENDANT_PATH_BYTES
        {
            return Err(BindingError::ExceedsLimit);
        }
        if !paths.is_sorted() {
            paths.sort();
        }
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BindingError::Duplicate);
        }
        Ok(())
    }

    pub fn paths(&self) -> &[AbsolutePath] {
        &self.paths
    }

    pub fn complete(&self) -> bool {
        self.complete && self.ignored_directories.is_empty()
    }

    /// Whether the snapshot lists every file outside its ignored
    /// directories.
    pub const fn complete_beside_ignored(&self) -> bool {
        self.complete
    }

    pub fn ignored_directories(&self) -> &[AbsolutePath] {
        &self.ignored_directories
    }

    pub fn links(&self) -> &[(AbsolutePath, AbsolutePath)] {
        &self.links
    }

    /// Whether every link below the root is among [`Self::links`]: the walk
    /// left none unfollowed.
    pub const fn names_every_link(&self) -> bool {
        self.names_every_link
    }

    /// Whether the snapshot omits an entry beneath the root.
    pub fn unlisted_entries(&self) -> bool {
        self.unlisted_entries || !self.ignored_directories.is_empty()
    }
}

/// Most untracked or ignored entries one Git state observation may list.
pub const MAX_GIT_STATE_ENTRIES: usize = 1_000;

/// The refs one Git command deletes, as its request names them.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefDeletion {
    /// The ref of this name, such as `refs/heads/topic`: a symbolic one
    /// stands for the ref it names, as `git update-ref -d` takes it.
    Ref(String),
    /// The ref of this name itself: deleting a symbolic one leaves the ref
    /// it names, as `git branch -d`, `git tag -d` and `git update-ref -d
    /// --no-deref` do.
    Itself(String),
    /// The remote-tracking refs `git remote remove <name>` deletes: those the
    /// remote's fetch refspecs map to.
    Remote(String),
}

/// What a discard copies into the working tree.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitRestoreSource {
    /// The index.
    Index,
    /// The tree a revision names, such as `HEAD`, through the index.
    Tree(String),
}

/// Which untracked entries a `git clean` removes, or a listing reaches:
/// those no ignore rule matches (`No`), every one (`Also`, `-x`), or the
/// ignored ones (`Only`, `-X`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitCleanIgnored {
    No,
    Also,
    Only,
}

/// What a Git repository holds that is in no commit: the state a discard
/// destroys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitStateObservation {
    /// The top level of the working tree the state was read from: the whole
    /// tree a discard run anywhere inside it acts on.
    top_level: AbsolutePath,
    /// The stash holds an entry.
    stash_entries: bool,
    /// Every index entry the query's pathspecs match is a plain file or
    /// symlink whose working copy, and whose entry, equal what the query's
    /// source holds, and no two of them could name one file.
    #[serde(skip_serializing_if = "Option::is_none")]
    restores_nothing: Option<bool>,
    /// Git lists an untracked entry of the query's kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked: Option<bool>,
    /// For each stash entry, newest first, whether a ref other than the
    /// stash, or `HEAD`, reaches its commit, so dropping it loses nothing;
    /// `None` where that was not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stash_reached: Option<Vec<bool>>,
    /// Whether the refs the query's deletes leave, or a detached `HEAD`,
    /// reach every commit and tag object the deleted refs name, so deleting
    /// them loses nothing; `None` where that was not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted_refs_reached: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history: Option<GitHistoryObservation>,
}

/// What decides whether a rewrite of a repository's history leaves commits
/// out of the reach of every ref and reflog.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitHistoryObservation {
    /// Git records the next move of `HEAD` in a reflog, and of the branch an
    /// unfinished rebase returns to, and no setting expires reflog entries
    /// sooner than Git's defaults: the commit a rebase, an amend or a reset
    /// moves away from stays in reach.
    pub moves_logged: bool,
    /// Moves are logged because `core.logAllRefUpdates` makes Git create a
    /// reflog for each ref it moves, not only because one exists now. Git
    /// reads the setting when it starts, so a hook it runs cannot keep the
    /// move unlogged by removing a reflog or changing the setting.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub creates_reflogs: bool,
    /// `refs/original/` holds a ref, the backup an earlier
    /// `git filter-branch` left, which a forced one overwrites.
    pub backups: bool,
    /// The queried `head_targets` whose history holds `HEAD`'s commit, so a
    /// reset to one moves the branch forward and leaves nothing out of
    /// reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets_holding_head: Vec<String>,
}

impl GitStateObservation {
    pub fn new(top_level: AbsolutePath, stash_entries: bool) -> Self {
        Self {
            top_level,
            stash_entries,
            stash_reached: None,
            deleted_refs_reached: None,
            restores_nothing: None,
            untracked: None,
            history: None,
        }
    }

    pub fn with_history(mut self, history: GitHistoryObservation) -> Self {
        self.history = Some(history);
        self
    }

    pub fn with_restores_nothing(mut self, restores_nothing: bool) -> Self {
        self.restores_nothing = Some(restores_nothing);
        self
    }

    pub fn with_untracked(mut self, untracked: bool) -> Self {
        self.untracked = Some(untracked);
        self
    }

    pub fn with_stash_reached(mut self, reached: Vec<bool>) -> Result<Self, BindingError> {
        if reached.len() > MAX_GIT_STATE_ENTRIES {
            return Err(BindingError::ExceedsLimit);
        }
        self.stash_reached = Some(reached);
        Ok(self)
    }

    pub fn with_deleted_refs_reached(mut self, reached: bool) -> Self {
        self.deleted_refs_reached = Some(reached);
        self
    }

    pub fn top_level(&self) -> &AbsolutePath {
        &self.top_level
    }

    pub const fn stash_entries(&self) -> bool {
        self.stash_entries
    }

    pub fn stash_reached(&self) -> Option<&[bool]> {
        self.stash_reached.as_deref()
    }

    pub fn deleted_refs_reached(&self) -> Option<bool> {
        self.deleted_refs_reached
    }

    pub const fn restores_nothing(&self) -> Option<bool> {
        self.restores_nothing
    }

    pub const fn untracked(&self) -> Option<bool> {
        self.untracked
    }

    pub fn history(&self) -> Option<&GitHistoryObservation> {
        self.history.as_ref()
    }
}

/// Most ignored entries one observation may list.
pub const MAX_IGNORED_ENTRIES: usize = 10_000;

/// The entries below a directory in a Git repository that an ignore rule
/// matches: what a search that honours `.gitignore`, `.ignore` and
/// `.rgignore` files, the repository's `info/exclude` and the user's global
/// excludes file does not open.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IgnoredEntriesObservation {
    entries: Vec<IgnoredEntry>,
    /// The files whose rules decide the entries, and the global excludes
    /// file whether or not a rule of it matched: absolute paths, as named
    /// and as resolved. The entries stand only while these do.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rule_files: Vec<String>,
}

/// One ignored entry with the rule that decides it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct IgnoredEntry {
    /// The entry's path below the observed directory. A directory ends in
    /// `/`, and nothing it holds is listed.
    path: String,
    /// The ignore-file line that matches the entry, as written.
    pattern: String,
    /// The ignore file holding that line, as a path below the observed
    /// directory. None for a file outside it: one in a directory above, or
    /// the global excludes file.
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_file: Option<String>,
}

impl IgnoredEntry {
    pub fn new(path: String, pattern: String, rule_file: Option<String>) -> Self {
        Self {
            path,
            pattern,
            rule_file,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn rule_file(&self) -> Option<&str> {
        self.rule_file.as_deref()
    }
}

impl IgnoredEntriesObservation {
    pub fn new(
        mut entries: Vec<IgnoredEntry>,
        mut rule_files: Vec<String>,
    ) -> Result<Self, BindingError> {
        if entries.len() > MAX_IGNORED_ENTRIES || rule_files.len() > MAX_IGNORED_ENTRIES {
            return Err(BindingError::ExceedsLimit);
        }
        entries.sort();
        rule_files.sort();
        Ok(Self {
            entries,
            rule_files,
        })
    }

    pub fn rule_files(&self) -> &[String] {
        &self.rule_files
    }

    pub fn entries(&self) -> &[IgnoredEntry] {
        &self.entries
    }
}

/// What a [`ObservationQuery::NestedRepository`] search found below its
/// directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NestedRepositoryObservation {
    /// An entry named `.git` lies below the directory.
    Found,
    /// The search reached every entry below the directory, and none is
    /// named `.git`.
    Absent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ObservationValue {
    Cwd {
        #[serde(flatten)]
        observed: Observed<AbsolutePath>,
    },
    Roots {
        #[serde(flatten)]
        observed: Observed<Vec<Root>>,
    },
    Env {
        #[serde(flatten)]
        observed: Observed<EnvObservation>,
    },
    UserHome {
        #[serde(flatten)]
        observed: Observed<UserHomeObservation>,
    },
    ProcessIdentity {
        #[serde(flatten)]
        observed: Observed<crate::effinterp_proto::ProcessIdentity>,
    },
    /// Credential-shaped variables by name; a value that is not Unicode is
    /// left out.
    CredentialEnvironment {
        variables: std::collections::BTreeMap<String, String>,
    },
    Path {
        #[serde(flatten)]
        observed: Observed<PathObservation>,
    },
    GitState {
        #[serde(flatten)]
        observed: Observed<GitStateObservation>,
    },
    /// The hook directory as an absolute path through the observed working
    /// directory's real path. `NotFound` when the observed roots hold no
    /// repository for that directory, or when Git's answer exists and is no
    /// directory (`core.hooksPath = /dev/null`), so Git runs no hook.
    GitHooks {
        #[serde(flatten)]
        observed: Observed<AbsolutePath>,
    },
    GitRead {
        #[serde(flatten)]
        observed: Observed<Vec<AbsolutePath>>,
    },
    IgnoredEntries {
        #[serde(flatten)]
        observed: Observed<IgnoredEntriesObservation>,
    },
    /// A search that could not finish, for its budget, its deadline or an
    /// entry it could not read, is an error, never `Absent`.
    NestedRepository {
        #[serde(flatten)]
        observed: Observed<NestedRepositoryObservation>,
    },
    /// Only visible paths, never the credential bytes or their digest.
    GrepNonMatching { paths: Vec<AbsolutePath> },
    /// Each package found, by normalized name, with every version the
    /// project has of it. A project with neither an environment nor a lock
    /// file has none.
    InstalledPackages {
        #[serde(flatten)]
        observed: Observed<std::collections::BTreeMap<String, BTreeSet<String>>>,
    },
}

impl ObservationValue {
    fn matches_query(&self, query: &ObservationQuery) -> bool {
        match (query, self) {
            (ObservationQuery::Cwd { .. }, Self::Cwd { .. })
            | (ObservationQuery::Roots { .. }, Self::Roots { .. })
            | (ObservationQuery::Env { .. }, Self::Env { .. })
            | (ObservationQuery::ProcessIdentity { .. }, Self::ProcessIdentity { .. })
            | (
                ObservationQuery::CredentialEnvironment { .. },
                Self::CredentialEnvironment { .. },
            )
            | (ObservationQuery::UserHome { .. }, Self::UserHome { .. })
            | (ObservationQuery::GitHooks { .. }, Self::GitHooks { .. })
            | (ObservationQuery::GitRead { .. }, Self::GitRead { .. })
            | (ObservationQuery::IgnoredEntries { .. }, Self::IgnoredEntries { .. })
            | (ObservationQuery::NestedRepository { .. }, Self::NestedRepository { .. })
            | (ObservationQuery::GrepNonMatching { .. }, Self::GrepNonMatching { .. })
            | (ObservationQuery::InstalledPackages { .. }, Self::InstalledPackages { .. }) => true,
            (
                ObservationQuery::Path {
                    inspect_descendants,
                    ..
                },
                Self::Path {
                    observed: Observed::Ok { value },
                },
            ) => value.descendants.is_some() == *inspect_descendants,
            (
                ObservationQuery::Path { .. },
                Self::Path {
                    observed: Observed::Error { .. },
                },
            )
            | (
                ObservationQuery::GitState { .. },
                Self::GitState {
                    observed: Observed::Error { .. },
                },
            ) => true,
            (
                ObservationQuery::GitState {
                    restores,
                    untracked,
                    inspect_history,
                    ..
                },
                Self::GitState {
                    observed: Observed::Ok { value },
                },
            ) => {
                value.restores_nothing.is_some() == restores.is_some()
                    && value.untracked.is_some() == untracked.is_some()
                    && value.history.is_some() == *inspect_history
            }
            _ => false,
        }
    }

    fn normalize(&mut self) -> Result<(), BindingError> {
        match self {
            Self::Roots {
                observed: Observed::Ok { value },
            } => {
                reject_duplicates(value.iter())?;
                value.sort();
            }
            Self::Path {
                observed: Observed::Ok { value },
            } => {
                if let Some(descendants) = &mut value.descendants {
                    descendants.normalize()?;
                }
            }
            Self::IgnoredEntries {
                observed: Observed::Ok { value },
            } => {
                *value = IgnoredEntriesObservation::new(
                    std::mem::take(&mut value.entries),
                    std::mem::take(&mut value.rule_files),
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationFact {
    query: ObservationQuery,
    value: ObservationValue,
}

impl ObservationFact {
    pub fn new(query: ObservationQuery, value: ObservationValue) -> Result<Self, BindingError> {
        if !value.matches_query(&query) {
            return Err(BindingError::WrongValueKind);
        }
        Ok(Self { query, value })
    }

    pub fn query(&self) -> &ObservationQuery {
        &self.query
    }

    pub fn value(&self) -> &ObservationValue {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Observation {
    v: SchemaVersion,
    request_id: String,
    facts: Vec<ObservationFact>,
}

impl Observation {
    pub fn new(
        v: SchemaVersion,
        request_id: impl Into<String>,
        mut facts: Vec<ObservationFact>,
    ) -> Result<Self, BindingError> {
        require_v1(v)?;
        let request_id = non_empty_binding_identifier(request_id)?;
        validate_queries(
            &facts
                .iter()
                .map(|fact| fact.query.clone())
                .collect::<Vec<_>>(),
        )?;
        reject_duplicates(facts.iter().map(|fact| fact.query.key()))?;
        for fact in &mut facts {
            fact.query.validate_scalars()?;
            if !fact.value.matches_query(&fact.query) {
                return Err(BindingError::WrongValueKind);
            }
            fact.value.normalize()?;
        }
        facts.sort_by(|left, right| left.query.key().cmp(right.query.key()));
        Ok(Self {
            v,
            request_id,
            facts,
        })
    }

    pub fn facts(&self) -> &[ObservationFact] {
        &self.facts
    }

    pub const fn version(&self) -> SchemaVersion {
        self.v
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn bind(&self, request: &ObservationRequest) -> Result<(), BindingError> {
        if self.request_id != request.request_id || self.facts.len() != request.queries.len() {
            return Err(BindingError::RequestMismatch);
        }
        for (fact, query) in self.facts.iter().zip(&request.queries) {
            if &fact.query != query || !fact.value.matches_query(query) {
                return Err(BindingError::RequestMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawObservation {
    v: SchemaVersion,
    request_id: String,
    facts: Vec<ObservationFact>,
}

impl<'de> Deserialize<'de> for Observation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let version = decode_version::<D::Error>(&value)?;
        if version != SchemaVersion::V1 {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        let raw =
            serde_json::from_value::<RawObservation>(value).map_err(serde::de::Error::custom)?;
        Self::new(raw.v, raw.request_id, raw.facts).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    Duplicate,
    EmptyIdentifier,
    ExceedsLimit,
    InvalidReference,
    RequestMismatch,
    UnsupportedVersion,
    WrongValueKind,
}

impl BindingError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::EmptyIdentifier => "empty-identifier",
            Self::ExceedsLimit => "exceeds-limit",
            Self::InvalidReference => "invalid-reference",
            Self::RequestMismatch => "request-mismatch",
            Self::UnsupportedVersion => "unsupported-version",
            Self::WrongValueKind => "wrong-value-kind",
        }
    }
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

fn validate_queries(queries: &[ObservationQuery]) -> Result<(), BindingError> {
    for query in queries {
        query.validate_scalars()?;
    }
    reject_duplicates(queries.iter().map(ObservationQuery::key))?;
    if !queries.is_empty()
        && queries
            .iter()
            .all(|query| matches!(query, ObservationQuery::Env { .. }))
    {
        return Ok(());
    }
    let cwd = queries
        .iter()
        .filter(|query| matches!(query, ObservationQuery::Cwd { .. }))
        .collect::<Vec<_>>();
    let roots = queries
        .iter()
        .filter(|query| matches!(query, ObservationQuery::Roots { .. }))
        .count();
    if cwd.len() != 1 || roots != 1 {
        return Err(BindingError::InvalidReference);
    }
    let cwd_key = cwd[0].key();
    for query in queries {
        let valid = match query {
            ObservationQuery::Cwd { .. }
            | ObservationQuery::ProcessIdentity { .. }
            | ObservationQuery::CredentialEnvironment { .. }
            | ObservationQuery::Env { .. }
            | ObservationQuery::UserHome { .. }
            | ObservationQuery::InstalledPackages { .. } => true,
            ObservationQuery::Roots {
                cwd_key: reference, ..
            }
            | ObservationQuery::GitHooks {
                cwd_key: reference, ..
            }
            | ObservationQuery::Path {
                cwd_key: reference, ..
            }
            | ObservationQuery::GitState {
                cwd_key: reference, ..
            }
            | ObservationQuery::GitRead {
                cwd_key: reference, ..
            }
            | ObservationQuery::IgnoredEntries {
                cwd_key: reference, ..
            }
            | ObservationQuery::NestedRepository {
                cwd_key: reference, ..
            } => reference == cwd_key,
            ObservationQuery::GrepNonMatching { path_key, .. } => queries.iter().any(|query| {
                matches!(query,
                ObservationQuery::Path { key, inspect_descendants: true, .. } if key == path_key)
            }),
        };
        if !valid {
            return Err(BindingError::InvalidReference);
        }
        if matches!(
            query,
            ObservationQuery::Path {
                inspect_descendants: false,
                symlink_traversal: SymlinkTraversal::Root | SymlinkTraversal::All,
                ..
            }
        ) {
            return Err(BindingError::InvalidReference);
        }
    }
    Ok(())
}

fn non_empty_binding_identifier(value: impl Into<String>) -> Result<String, BindingError> {
    let value = value.into();
    if value.is_empty() {
        Err(BindingError::EmptyIdentifier)
    } else {
        Ok(value)
    }
}

fn reject_duplicates<'a, T: Ord + ?Sized + 'a>(
    values: impl IntoIterator<Item = &'a T>,
) -> Result<(), BindingError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(BindingError::Duplicate);
        }
    }
    Ok(())
}

fn require_v1(version: SchemaVersion) -> Result<(), BindingError> {
    if version == SchemaVersion::V1 {
        Ok(())
    } else {
        Err(BindingError::UnsupportedVersion)
    }
}

fn decode_version<E: serde::de::Error>(value: &serde_json::Value) -> Result<SchemaVersion, E> {
    value
        .get("v")
        .cloned()
        .ok_or_else(|| E::missing_field("v"))
        .and_then(|value| serde_json::from_value(value).map_err(E::custom))
}
