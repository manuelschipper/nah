//! Builds frozen contexts and observations for corpus cases; it does not observe the host.

use std::collections::BTreeMap;
use std::path::Path;

use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    DescendantObservation, EnvObservation, Observation, ObservationFact, ObservationQuery,
    ObservationRequest, ObservationValue, Observed, PathKind, PathObservation,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRegistry {
    v: u32,
    pub(crate) ctx_fixtures: BTreeMap<String, ContextFixture>,
    pub(crate) observation_fixtures: BTreeMap<String, ObservationFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFixture {
    platform: Platform,
    home: String,
    all_shipped_guards_enabled: bool,
    extensions: Vec<serde_json::Value>,
    trust: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFixture {
    pub(crate) cwd: String,
    env: BTreeMap<String, Option<String>>,
    paths: Vec<PathFixture>,
    roots: Vec<RootFixture>,
}

#[derive(Debug, Deserialize)]
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
    #[serde(default)]
    descendants: Vec<String>,
    #[serde(default)]
    descendants_incomplete: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFixture {
    kind: RootKind,
    path: String,
}

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
        if !self.all_shipped_guards_enabled || !self.extensions.is_empty() || !self.trust.is_empty()
        {
            return Err("unsupported context fixture state".into());
        }
        AbsolutePath::new(self.platform, &self.home)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn context(&self) -> Result<Ctx, String> {
        Ctx::new(
            SchemaVersion::V1,
            self.platform,
            AbsolutePath::new(self.platform, &self.home).map_err(|error| error.to_string())?,
            nah_cli::all_shipped_guard_states_enabled(),
            vec![],
            TrustProjection::new(vec![]).map_err(|error| error.to_string())?,
            nah_cli::POLICY_VERSION,
        )
        .map_err(|error| error.to_string())
    }
}

impl ObservationFixture {
    fn validate(&self) -> Result<(), String> {
        AbsolutePath::new(Platform::Linux, &self.cwd).map_err(|error| error.to_string())?;
        for root in &self.roots {
            AbsolutePath::new(Platform::Linux, &root.path).map_err(|error| error.to_string())?;
        }
        for path in &self.paths {
            if path.requested.is_empty()
                || path.exists != (path.kind != PathKind::Missing)
                || path.exists != path.realpath.is_some()
                || path.target_kind.is_some() && path.kind != PathKind::Symlink
            {
                return Err(format!("inconsistent path fixture `{}`", path.requested));
            }
            AbsolutePath::new(Platform::Linux, &path.resolved)
                .map_err(|error| error.to_string())?;
            if let Some(realpath) = &path.realpath {
                AbsolutePath::new(Platform::Linux, realpath).map_err(|error| error.to_string())?;
            }
            for descendant in &path.descendants {
                AbsolutePath::new(Platform::Linux, descendant)
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    pub(crate) fn observation(&self, request: &ObservationRequest) -> Result<Observation, String> {
        let absolute = |path: &str| {
            AbsolutePath::new(Platform::Linux, path).map_err(|error| error.to_string())
        };
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
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: match self.env.get(name).and_then(Option::as_ref) {
                            Some(text) => EnvObservation::Value { text: text.clone() },
                            None => EnvObservation::Unset,
                        },
                    },
                },
                ObservationQuery::Path {
                    requested,
                    inspect_descendants,
                    ..
                } => {
                    let path = self
                        .paths
                        .iter()
                        .find(|path| path.requested == *requested)
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
                        value = value.with_descendants(
                            DescendantObservation::new(
                                path.descendants
                                    .iter()
                                    .map(|descendant| absolute(descendant))
                                    .collect::<Result<Vec<_>, _>>()?,
                                !path.descendants_incomplete,
                            )
                            .map_err(|error| error.to_string())?,
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
