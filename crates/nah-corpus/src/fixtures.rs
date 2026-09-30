//! Builds frozen contexts and observations for corpus cases; it does not observe the host.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use nah_proto::ctx::{
    AbsolutePath, Ctx, Platform, SchemaVersion, ShippedGuardState, TrustProjection,
};
use nah_proto::effinterp_proto;
use nah_proto::observation::{
    DescendantObservation, EnvObservation, Observation, ObservationFact, ObservationFailure,
    ObservationQuery, ObservationRequest, ObservationValue, Observed, PathKind, PathObservation,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind, SymlinkTraversal,
    UserHomeObservation,
};
use serde::Deserialize;

/// The named context and observation fixtures corpus cases refer to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRegistry {
    v: u32,
    pub(crate) ctx_fixtures: BTreeMap<String, ContextFixture>,
    pub(crate) observation_fixtures: BTreeMap<String, ObservationFixture>,
}

/// A frozen decision context: platform, home, shipped-guard posture and
/// enforcement posture.
///
/// Unsupported: custom guards and trust. The `extensions` and `trust` fields
/// exist so a fixture states their absence; validation rejects either one when
/// nonempty ("unsupported context fixture state"), and replay always builds a
/// context with no custom guards and an empty trust projection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFixture {
    platform: Platform,
    home: String,
    shipped_guards: ShippedGuardPosture,
    /// The enforcement an operator's `nah nap` leaves in force. Replay takes it
    /// from the fixture, so a paused posture never reads or writes nap state.
    #[serde(default)]
    enforcement: EnforcementPosture,
    extensions: Vec<serde_json::Value>,
    trust: Vec<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EnforcementPosture {
    #[default]
    Normal,
    SelfProtectionPaused,
    AllPaused,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ShippedGuardPosture {
    FactoryDefaults,
    FactoryDefaultsWithoutSecretsStoreRead,
    AllEnabled,
    AllDisabled,
    States(Vec<ShippedGuardState>),
}

/// Frozen host facts for a corpus case; a path or user it does not declare cannot
/// be observed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFixture {
    platform: Platform,
    pub(crate) cwd: String,
    env: BTreeMap<String, Option<String>>,
    /// The home directory the account database records for each user a case
    /// expands with `~name`. Like an undeclared path, a user the fixture does
    /// not declare cannot be answered.
    #[serde(default)]
    users: BTreeMap<String, String>,
    paths: Vec<PathFixture>,
    roots: Vec<RootFixture>,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFixture {
    kind: RootKind,
    path: String,
}

/// Reads and validates the fixture registry at `path`. A context fixture with
/// custom guards or trust entries is rejected as unsupported.
pub fn load_fixtures(path: &Path) -> Result<FixtureRegistry, String> {
    let registry: FixtureRegistry = serde_json::from_str(
        &std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read fixture registry: {error}"))?,
    )
    .map_err(|error| format!("invalid fixture registry: {error}"))?;
    registry.validate()?;
    Ok(registry)
}

impl FixtureRegistry {
    /// The context fixture a corpus case names in `ctx_fixture`.
    pub fn ctx_fixture(&self, name: &str) -> Option<&ContextFixture> {
        self.ctx_fixtures.get(name)
    }

    fn validate(&self) -> Result<(), String> {
        if self.v != 1 {
            return Err("fixture registry version is not 1".into());
        }
        for fixture in self.ctx_fixtures.values() {
            fixture.validate()?;
        }
        for fixture in self.observation_fixtures.values() {
            fixture.validate()?;
        }
        Ok(())
    }
}

impl ContextFixture {
    fn validate(&self) -> Result<(), String> {
        if !self.extensions.is_empty() || !self.trust.is_empty() {
            return Err("unsupported context fixture state".into());
        }
        AbsolutePath::new(self.platform, &self.home)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn context(&self) -> Result<Ctx, String> {
        Ctx::new(
            self.platform,
            AbsolutePath::new(self.platform, &self.home).map_err(|error| error.to_string())?,
            match &self.shipped_guards {
                ShippedGuardPosture::FactoryDefaults => nah_cli::shipped_guard_states(),
                ShippedGuardPosture::FactoryDefaultsWithoutSecretsStoreRead => {
                    nah_cli::shipped_guard_states()
                        .into_iter()
                        .map(|guard| {
                            if guard.name() == "secrets-store-read" {
                                nah_proto::ctx::ShippedGuardState::with_explicit_disable(
                                    guard.name(),
                                    false,
                                    true,
                                )
                                .expect("known shipped guard")
                            } else {
                                guard
                            }
                        })
                        .collect()
                }
                ShippedGuardPosture::AllEnabled => nah_cli::all_shipped_guard_states_enabled(),
                ShippedGuardPosture::AllDisabled => nah_policy::ShippedGuards::new()
                    .shipped_guard_ids()
                    .iter()
                    .map(|name| nah_proto::ctx::ShippedGuardState::new(*name, false))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?,
                ShippedGuardPosture::States(states) => states.clone(),
            },
            vec![],
            TrustProjection::new(vec![]).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }

    /// The shipped guards a replay under this fixture consults: those its
    /// shipped-guard posture enables, or none when an all-enforcement nap is in
    /// force.
    pub fn enabled_shipped_guards(&self) -> Result<BTreeSet<String>, String> {
        if matches!(self.enforcement, EnforcementPosture::AllPaused) {
            return Ok(BTreeSet::new());
        }
        Ok(self
            .context()?
            .shipped_guards()
            .iter()
            .filter(|guard| guard.enabled())
            .map(|guard| guard.name().to_owned())
            .collect())
    }

    pub(crate) const fn platform(&self) -> Platform {
        self.platform
    }

    pub(crate) const fn enforcement(&self) -> nah_policy::EnforcementMode {
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
    pub(crate) const fn platform(&self) -> Platform {
        self.platform
    }

    fn validate(&self) -> Result<(), String> {
        AbsolutePath::new(self.platform, &self.cwd).map_err(|error| error.to_string())?;
        for path in self
            .users
            .values()
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
        Ok(())
    }

    /// The sources this fixture can answer a source request with, admitted
    /// beneath its own cwd — plus the Cargo install registry — exactly as
    /// production admits beneath the invocation cwd. A path the fixture does
    /// not declare does not exist, and any other declared path outside the cwd
    /// escapes it, so a replay never reads the analysing host's disk and never
    /// observes more than the invocation could.
    pub(crate) fn sources(&self) -> Result<nah_cli::DeclaredSourceObservations, String> {
        use nah_cli::DeclaredSource;

        let mut declared = BTreeMap::new();
        let mut listings = BTreeMap::new();
        for path in &self.paths {
            let source = match (path.kind, &path.contents) {
                (PathKind::Missing, _) => continue,
                (PathKind::File, Some(contents)) => {
                    DeclaredSource::Contents(contents.clone().into_bytes())
                }
                (PathKind::Directory, _) => DeclaredSource::NotAFile,
                // The path exists, so it is not missing; its bytes are simply
                // undeclared, and unproven bytes are never served as empty ones.
                _ => DeclaredSource::Unreadable,
            };
            let entries = path.listed_entries();
            for alias in [&path.requested, &path.resolved] {
                if Path::new(alias).is_absolute() {
                    declared.insert(alias.clone(), source.clone());
                    if let Some(entries) = &entries {
                        listings.insert(alias.clone(), entries.clone());
                    }
                }
            }
        }
        Ok(nah_cli::DeclaredSourceObservations::new(
            AbsolutePath::new(self.platform, &self.cwd).map_err(|error| error.to_string())?,
            declared,
            listings,
        ))
    }

    /// Initial metadata for the engine, independent of source-byte admission.
    /// Undeclared queries remain unobserved; no path on the replay host is read.
    pub(crate) fn observations(&self) -> std::sync::Arc<dyn nah_cli::ObservationResolver> {
        std::sync::Arc::new(FixtureObservations {
            paths: self.paths.clone(),
        })
    }

    pub(crate) fn observation(&self, request: &ObservationRequest) -> Result<Observation, String> {
        let absolute =
            |path: &str| AbsolutePath::new(self.platform, path).map_err(|error| error.to_string());
        let roots = self
            .roots
            .iter()
            .map(|root| Ok(Root::new(root.kind, absolute(&root.path)?)))
            .collect::<Result<Vec<_>, String>>()?;
        let project = roots
            .iter()
            .find(|root| root.kind() == RootKind::Project)
            .cloned();
        let mut facts = Vec::new();
        for query in request.queries().iter().cloned() {
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
                ObservationQuery::UserHome { name, .. } => ObservationValue::UserHome {
                    observed: Observed::Ok {
                        value: UserHomeObservation::Home {
                            path: absolute(
                                self.users
                                    .get(name)
                                    .ok_or_else(|| format!("fixture has no user `{name}`"))?,
                            )?,
                        },
                    },
                },
                ObservationQuery::Path {
                    requested,
                    inspect_descendants,
                    symlink_traversal,
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
                        let snapshot = DescendantObservation::new(
                            path.descendants
                                .iter()
                                .flatten()
                                .filter(|descendant| {
                                    !unfollowed.iter().any(|(visible, target)| {
                                        within(descendant, visible)
                                            || within(descendant, target)
                                                && !within(descendant, root)
                                    })
                                })
                                .map(|descendant| absolute(descendant))
                                .collect::<Result<Vec<_>, _>>()?,
                            !path.descendants_incomplete,
                        )
                        .and_then(|descendants| descendants.with_links(links))
                        .map_err(|error| error.to_string())?;
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
                ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        project.clone(),
                        ProjectGuardDeclaration::Absent,
                    )
                    .map_err(|error| error.to_string())?,
                },
            };
            facts.push(ObservationFact::new(query, value).map_err(|error| error.to_string())?);
        }
        Observation::new(SchemaVersion::V1, request.request_id(), facts)
            .map_err(|error| error.to_string())
    }
}

impl PathFixture {
    /// The entries this fixture proves sit directly inside the directory it
    /// declares, or None when it declares no complete inventory of one.
    ///
    /// A complete recursive inventory of readable regular files determines
    /// exactly which of them a directory holds directly; an absent or truncated
    /// one proves nothing, so the directory stays unlisted rather than empty.
    fn listed_entries(&self) -> Option<Vec<String>> {
        let directory = match self.kind {
            PathKind::Directory => self.realpath.as_ref()?,
            PathKind::Symlink if self.target_kind == Some(PathKind::Directory) => {
                self.realpath.as_ref()?
            }
            _ => return None,
        };
        if self.descendants_incomplete || self.descendants_unlisted {
            return None;
        }
        Some(
            self.descendants
                .as_ref()?
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
    /// answers it: an undeclared inventory is empty, and one that is
    /// incomplete, leaves an entry unlisted or went through a link is refused,
    /// since the fixture cannot say what else the directory holds.
    fn listing(&self, depth: Option<u32>) -> effinterp_proto::ObservationOutcome {
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
        ListingFact::of_files(
            directory,
            self.descendants.iter().flatten().map(String::as_str),
            depth,
        )
        .map_or(
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
            && self.descendants == other.descendants
            && self.descendants_incomplete == other.descendants_incomplete
            && self.links == other.links
            && self.descendants_unlisted == other.descendants_unlisted
    }
}

struct FixtureObservations {
    paths: Vec<PathFixture>,
}

impl nah_cli::ObservationResolver for FixtureObservations {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        budget: nah_cli::ObservationBudget,
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
            return entry.listing(*depth);
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
            // The fixture proves absence but cannot declare an observed-parent
            // identity. A lexical spelling cannot supply that missing fact.
            effinterp_proto::Fact::Unavailable(effinterp_proto::ObservationRefusal::Unsupported)
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
            executable: None,
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
            env: BTreeMap::new(),
            users: BTreeMap::new(),
            paths: vec![PathFixture {
                requested: "link".into(),
                resolved: "/repo/link".into(),
                realpath: Some("/outside/target".into()),
                kind: PathKind::Symlink,
                target_kind: Some(PathKind::File),
                exists: true,
                contents: None,
                descendants: None,
                descendants_incomplete: false,
                links: Vec::new(),
                descendants_unlisted: false,
            }],
            roots: vec![],
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
                },
                ObservationQuery::ProjectGuards {
                    key: "project-guards".into(),
                    roots_key: "roots".into(),
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
                nah_cli::ObservationBudget {
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
            let budget = nah_cli::ObservationBudget {
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
        let directory = |descendants, incomplete| PathFixture {
            requested: "/repo/root".into(),
            resolved: "/repo/root".into(),
            realpath: Some("/repo/root".into()),
            kind: PathKind::Directory,
            target_kind: None,
            exists: true,
            contents: None,
            descendants,
            descendants_incomplete: incomplete,
            links: Vec::new(),
            descendants_unlisted: false,
        };
        let descendants = Some(vec![
            "/repo/root/main.tf".to_owned(),
            "/repo/root/modules/nested.tf".to_owned(),
        ]);

        // A complete inventory proves which readable files sit directly inside.
        assert_eq!(
            directory(descendants.clone(), false).listed_entries(),
            Some(vec!["/repo/root/main.tf".to_owned()])
        );
        // An observed-empty directory is listed as empty.
        assert_eq!(
            directory(Some(vec![]), false).listed_entries(),
            Some(vec![])
        );
        // An absent or truncated inventory proves nothing about the entries.
        assert_eq!(directory(None, false).listed_entries(), None);
        assert_eq!(directory(descendants, true).listed_entries(), None);
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
            contents: Some("{}".into()),
            descendants: None,
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
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
            contents: None,
            descendants: None,
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
        });

        assert_eq!(
            fixture.validate(),
            Err("conflicting path fixture alias `/repo/link`".into())
        );
    }
}
