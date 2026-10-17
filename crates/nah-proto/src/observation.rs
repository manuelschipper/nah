//! Request-bound tool-world observation contracts.

use crate::ctx::AbsolutePath;
use crate::ctx::SchemaVersion;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
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
    },
    ProjectGuards {
        key: String,
        roots_key: String,
    },
    /// What the Git repository found from the directory `requested` holds
    /// that a discard would lose. `inspect_untracked` also lists its
    /// untracked and ignored entries, which a walk of the whole tree finds.
    GitState {
        key: String,
        requested: String,
        cwd_key: String,
        inspect_untracked: bool,
    },
    /// The entries below the directory `requested` that Git's ignore rules
    /// leave out of a search that honours them, as ripgrep reads those rules.
    IgnoredEntries {
        key: String,
        requested: String,
        cwd_key: String,
    },
}

impl ObservationQuery {
    pub fn key(&self) -> &str {
        match self {
            Self::Cwd { key, .. }
            | Self::Roots { key, .. }
            | Self::Env { key, .. }
            | Self::UserHome { key, .. }
            | Self::Path { key, .. }
            | Self::ProjectGuards { key, .. }
            | Self::GitState { key, .. }
            | Self::IgnoredEntries { key, .. } => key,
        }
    }

    fn validate_scalars(&self) -> Result<(), BindingError> {
        if self.key().is_empty() {
            return Err(BindingError::EmptyIdentifier);
        }
        let valid = match self {
            Self::Cwd { .. } => true,
            Self::Roots { cwd_key, .. } => !cwd_key.is_empty(),
            Self::Env { name, .. } | Self::UserHome { name, .. } => !name.is_empty(),
            Self::Path {
                requested, cwd_key, ..
            }
            | Self::GitState {
                requested, cwd_key, ..
            }
            | Self::IgnoredEntries {
                requested, cwd_key, ..
            } => !requested.is_empty() && !cwd_key.is_empty(),
            Self::ProjectGuards { roots_key, .. } => !roots_key.is_empty(),
        };
        if valid {
            Ok(())
        } else {
            Err(BindingError::EmptyIdentifier)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservationRequest {
    v: SchemaVersion,
    request_id: String,
    queries: Vec<ObservationQuery>,
}

impl ObservationRequest {
    /// Accepts either a nonempty environment-only preflight request or exactly one
    /// cwd/roots/project-guards spine, optionally with environment, user-home, and
    /// path queries.
    /// Roots and all paths must reference that cwd; project guards must reference
    /// those roots. Query keys must be unique, and identifiers must be nonempty.
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
}

impl DescendantObservation {
    pub fn new(mut paths: Vec<AbsolutePath>, complete: bool) -> Result<Self, BindingError> {
        Self::normalize_paths(&mut paths)?;
        Ok(Self {
            paths,
            complete,
            links: Vec::new(),
            unlisted_entries: false,
        })
    }

    pub fn with_links(
        mut self,
        links: Vec<(AbsolutePath, AbsolutePath)>,
    ) -> Result<Self, BindingError> {
        self.links = links;
        self.normalize()?;
        Ok(self)
    }

    pub fn with_unlisted_entries(mut self) -> Self {
        self.unlisted_entries = true;
        self
    }

    fn normalize(&mut self) -> Result<(), BindingError> {
        Self::normalize_paths(&mut self.paths)?;
        if self.links.len() > MAX_DESCENDANT_PATHS {
            return Err(BindingError::ExceedsLimit);
        }
        self.links.sort();
        if self.links.windows(2).any(|pair| pair[0].0 == pair[1].0) {
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

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn links(&self) -> &[(AbsolutePath, AbsolutePath)] {
        &self.links
    }

    /// Whether the snapshot omits an entry beneath the root.
    pub const fn unlisted_entries(&self) -> bool {
        self.unlisted_entries
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ProjectGuardDeclaration {
    Absent,
    Present { names: Vec<String> },
    ReadFailure,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectGuardObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<Root>,
    declaration: ProjectGuardDeclaration,
}

impl ProjectGuardObservation {
    pub fn new(
        root: Option<Root>,
        mut declaration: ProjectGuardDeclaration,
    ) -> Result<Self, BindingError> {
        if let ProjectGuardDeclaration::Present { names } = &mut declaration {
            if names.iter().any(String::is_empty) {
                return Err(BindingError::EmptyIdentifier);
            }
            reject_duplicates(names.iter())?;
            names.sort();
        }
        Ok(Self { root, declaration })
    }

    pub fn declaration(&self) -> &ProjectGuardDeclaration {
        &self.declaration
    }
}

/// Most untracked or ignored entries one Git state observation may list.
pub const MAX_GIT_STATE_ENTRIES: usize = 1_000;

/// What a Git repository holds that is in no commit: the state a discard
/// destroys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitStateObservation {
    /// The top level of the working tree the state was read from: the whole
    /// tree a discard run anywhere inside it acts on.
    top_level: AbsolutePath,
    /// A tracked file differs from `HEAD`, in the index or the working tree,
    /// or the index hides one from that comparison (assume-unchanged,
    /// skip-worktree), so an edit to it would not show.
    tracked_changes: bool,
    /// The stash holds an entry.
    stash_entries: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked: Option<GitUntrackedObservation>,
}

/// The entries of a working tree that Git does not track, as paths below its
/// top level. A directory none of whose contents are tracked is one entry
/// ending in `/`, so what it holds is not listed.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitUntrackedObservation {
    /// Entries no ignore rule matches.
    untracked: Vec<String>,
    /// Entries an ignore rule matches.
    ignored: Vec<String>,
}

impl GitUntrackedObservation {
    pub fn new(mut untracked: Vec<String>, mut ignored: Vec<String>) -> Result<Self, BindingError> {
        if untracked.len() > MAX_GIT_STATE_ENTRIES || ignored.len() > MAX_GIT_STATE_ENTRIES {
            return Err(BindingError::ExceedsLimit);
        }
        untracked.sort();
        ignored.sort();
        Ok(Self { untracked, ignored })
    }

    pub fn untracked(&self) -> &[String] {
        &self.untracked
    }

    pub fn ignored(&self) -> &[String] {
        &self.ignored
    }
}

impl GitStateObservation {
    pub fn new(top_level: AbsolutePath, tracked_changes: bool, stash_entries: bool) -> Self {
        Self {
            top_level,
            tracked_changes,
            stash_entries,
            untracked: None,
        }
    }

    pub fn with_untracked(mut self, untracked: GitUntrackedObservation) -> Self {
        self.untracked = Some(untracked);
        self
    }

    pub fn top_level(&self) -> &AbsolutePath {
        &self.top_level
    }

    pub const fn tracked_changes(&self) -> bool {
        self.tracked_changes
    }

    pub const fn stash_entries(&self) -> bool {
        self.stash_entries
    }

    pub fn untracked(&self) -> Option<&GitUntrackedObservation> {
        self.untracked.as_ref()
    }
}

/// Most ignored entries one observation may list.
pub const MAX_IGNORED_ENTRIES: usize = 10_000;

/// The entries below a directory that an ignore rule of its Git repository
/// matches: what a search that honours `.gitignore` files, the repository's
/// `info/exclude` and the user's global excludes file does not open.
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
    Path {
        #[serde(flatten)]
        observed: Observed<PathObservation>,
    },
    ProjectGuards {
        #[serde(flatten)]
        observation: ProjectGuardObservation,
    },
    GitState {
        #[serde(flatten)]
        observed: Observed<GitStateObservation>,
    },
    IgnoredEntries {
        #[serde(flatten)]
        observed: Observed<IgnoredEntriesObservation>,
    },
}

impl ObservationValue {
    fn matches_query(&self, query: &ObservationQuery) -> bool {
        match (query, self) {
            (ObservationQuery::Cwd { .. }, Self::Cwd { .. })
            | (ObservationQuery::Roots { .. }, Self::Roots { .. })
            | (ObservationQuery::Env { .. }, Self::Env { .. })
            | (ObservationQuery::UserHome { .. }, Self::UserHome { .. })
            | (ObservationQuery::ProjectGuards { .. }, Self::ProjectGuards { .. })
            | (ObservationQuery::IgnoredEntries { .. }, Self::IgnoredEntries { .. }) => true,
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
                    inspect_untracked, ..
                },
                Self::GitState {
                    observed: Observed::Ok { value },
                },
            ) => value.untracked.is_some() == *inspect_untracked,
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
            Self::ProjectGuards { observation } => {
                let normalized = ProjectGuardObservation::new(
                    observation.root.clone(),
                    observation.declaration.clone(),
                )?;
                *observation = normalized;
            }
            Self::Path {
                observed: Observed::Ok { value },
            } => {
                if let Some(descendants) = &mut value.descendants {
                    descendants.normalize()?;
                }
            }
            Self::GitState {
                observed: Observed::Ok { value },
            } => {
                if let Some(untracked) = value.untracked.take() {
                    value.untracked = Some(GitUntrackedObservation::new(
                        untracked.untracked,
                        untracked.ignored,
                    )?);
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
    #[serde(skip)]
    fingerprint: String,
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
        let fingerprint = observation_fingerprint(v, &request_id, &facts);
        let observation = Self {
            v,
            request_id,
            facts,
            fingerprint,
        };
        observation.validate_project_guards()?;
        Ok(observation)
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

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
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
        self.validate_project_guards()
    }

    pub fn project_guard_declaration(&self) -> Result<&ProjectGuardDeclaration, BindingError> {
        self.facts
            .iter()
            .find_map(|fact| match &fact.value {
                ObservationValue::ProjectGuards { observation } => Some(observation.declaration()),
                _ => None,
            })
            .ok_or(BindingError::MissingProjectGuards)
    }

    fn validate_project_guards(&self) -> Result<(), BindingError> {
        if self
            .facts
            .iter()
            .all(|fact| matches!(fact.query, ObservationQuery::Env { .. }))
        {
            return Ok(());
        }
        let roots = self.facts.iter().find_map(|fact| match &fact.value {
            ObservationValue::Roots { observed } => Some(observed),
            _ => None,
        });
        let guards = self.facts.iter().find_map(|fact| match &fact.value {
            ObservationValue::ProjectGuards { observation } => Some(observation),
            _ => None,
        });
        let (Some(roots), Some(guards)) = (roots, guards) else {
            return Err(BindingError::MissingProjectGuards);
        };
        match roots {
            Observed::Error { .. } => {
                if guards.root.is_none()
                    && guards.declaration == ProjectGuardDeclaration::ReadFailure
                {
                    Ok(())
                } else {
                    Err(BindingError::ProjectGuardMismatch)
                }
            }
            Observed::Ok { value } => {
                let projects = value
                    .iter()
                    .filter(|root| root.kind == RootKind::Project)
                    .collect::<Vec<_>>();
                match projects.as_slice() {
                    [] if guards.root.is_none()
                        && guards.declaration == ProjectGuardDeclaration::Absent =>
                    {
                        Ok(())
                    }
                    [project] if guards.root.as_ref() == Some(*project) => Ok(()),
                    _ => Err(BindingError::ProjectGuardMismatch),
                }
            }
        }
    }
}

fn observation_fingerprint(
    version: SchemaVersion,
    request_id: &str,
    facts: &[ObservationFact],
) -> String {
    fn update(digest: &mut Sha256, bytes: &[u8]) {
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }

    let mut digest = Sha256::new();
    update(
        &mut digest,
        &serde_json::to_vec(&version).expect("observation version serializes"),
    );
    update(&mut digest, request_id.as_bytes());
    for fact in facts {
        update(
            &mut digest,
            &serde_json::to_vec(fact.query()).expect("observation query serializes"),
        );
        match fact.value() {
            ObservationValue::Path {
                observed: Observed::Ok { value },
            } => {
                digest.update([1]);
                update(&mut digest, value.resolved().as_str().as_bytes());
                match value.realpath() {
                    Some(path) => {
                        digest.update([1]);
                        update(&mut digest, path.as_str().as_bytes());
                    }
                    None => digest.update([0]),
                }
                update(
                    &mut digest,
                    &serde_json::to_vec(&value.kind()).expect("path kind serializes"),
                );
                update(
                    &mut digest,
                    &serde_json::to_vec(&value.target_kind()).expect("target kind serializes"),
                );
                match value.descendants() {
                    Some(descendants) => {
                        digest.update([1, u8::from(descendants.complete())]);
                        digest.update((descendants.paths().len() as u64).to_le_bytes());
                        for path in descendants.paths() {
                            update(&mut digest, path.as_str().as_bytes());
                        }
                    }
                    None => digest.update([0]),
                }
            }
            value => {
                digest.update([0]);
                update(
                    &mut digest,
                    &serde_json::to_vec(value).expect("observation value serializes"),
                );
            }
        }
    }
    format!("{:x}", digest.finalize())
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
    MissingProjectGuards,
    ProjectGuardMismatch,
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
            Self::MissingProjectGuards => "missing-project-guards",
            Self::ProjectGuardMismatch => "project-guard-mismatch",
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
        .collect::<Vec<_>>();
    let project_guards = queries
        .iter()
        .filter(|query| matches!(query, ObservationQuery::ProjectGuards { .. }))
        .count();
    if cwd.len() != 1 || roots.len() != 1 || project_guards != 1 {
        return Err(BindingError::InvalidReference);
    }
    let cwd_key = cwd[0].key();
    let roots_key = roots[0].key();
    for query in queries {
        let valid = match query {
            ObservationQuery::Cwd { .. }
            | ObservationQuery::Env { .. }
            | ObservationQuery::UserHome { .. } => true,
            ObservationQuery::Roots {
                cwd_key: reference, ..
            }
            | ObservationQuery::Path {
                cwd_key: reference, ..
            }
            | ObservationQuery::GitState {
                cwd_key: reference, ..
            }
            | ObservationQuery::IgnoredEntries {
                cwd_key: reference, ..
            } => reference == cwd_key,
            ObservationQuery::ProjectGuards {
                roots_key: reference,
                ..
            } => reference == roots_key,
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
