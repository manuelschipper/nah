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
}

impl ObservationQuery {
    pub fn key(&self) -> &str {
        match self {
            Self::Cwd { key, .. }
            | Self::Roots { key, .. }
            | Self::Env { key, .. }
            | Self::Path { key, .. }
            | Self::ProjectGuards { key, .. } => key,
        }
    }

    fn validate_scalars(&self) -> Result<(), BindingError> {
        if self.key().is_empty() {
            return Err(BindingError::EmptyIdentifier);
        }
        let valid = match self {
            Self::Cwd { .. } => true,
            Self::Roots { cwd_key, .. } => !cwd_key.is_empty(),
            Self::Env { name, .. } => !name.is_empty(),
            Self::Path {
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
    pub fn new(
        v: SchemaVersion,
        request_id: impl Into<String>,
        mut queries: Vec<ObservationQuery>,
    ) -> Result<Self, BindingError> {
        require_v1(v)?;
        let request_id = non_empty(request_id)?;
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

pub const MAX_DESCENDANT_PATHS: usize = 10_000;
pub const MAX_DESCENDANT_PATH_BYTES: usize = 1024 * 1024;
pub const MAX_DESCENDANT_ENTRIES: usize = 10_000;
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
}

impl DescendantObservation {
    pub fn new(mut paths: Vec<AbsolutePath>, complete: bool) -> Result<Self, BindingError> {
        if paths.len() > MAX_DESCENDANT_PATHS
            || paths.iter().map(|path| path.as_str().len()).sum::<usize>()
                > MAX_DESCENDANT_PATH_BYTES
        {
            return Err(BindingError::ExceedsLimit);
        }
        reject_duplicates(paths.iter())?;
        paths.sort();
        Ok(Self { paths, complete })
    }

    pub fn paths(&self) -> &[AbsolutePath] {
        &self.paths
    }

    pub const fn complete(&self) -> bool {
        self.complete
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
    Path {
        #[serde(flatten)]
        observed: Observed<PathObservation>,
    },
    ProjectGuards {
        #[serde(flatten)]
        observation: ProjectGuardObservation,
    },
}

impl ObservationValue {
    fn matches_query(&self, query: &ObservationQuery) -> bool {
        match (query, self) {
            (ObservationQuery::Cwd { .. }, Self::Cwd { .. })
            | (ObservationQuery::Roots { .. }, Self::Roots { .. })
            | (ObservationQuery::Env { .. }, Self::Env { .. })
            | (ObservationQuery::ProjectGuards { .. }, Self::ProjectGuards { .. }) => true,
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
            ) => true,
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
                if let Some(descendants) = value.descendants.take() {
                    value.descendants = Some(DescendantObservation::new(
                        descendants.paths,
                        descendants.complete,
                    )?);
                }
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
        let request_id = non_empty(request_id)?;
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
        let observation = Self {
            v,
            request_id,
            facts,
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
            ObservationQuery::Cwd { .. } | ObservationQuery::Env { .. } => true,
            ObservationQuery::Roots {
                cwd_key: reference, ..
            }
            | ObservationQuery::Path {
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

fn non_empty(value: impl Into<String>) -> Result<String, BindingError> {
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
