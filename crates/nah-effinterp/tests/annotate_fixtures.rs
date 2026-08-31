//! Frozen effect plans plus observation facts pin the per-effect annotations
//! the guard rewrite will match on.
//!
//! Each fixture plan came from the pinned engine and was pruned to the fields
//! the annotation layer reads. Unsupported: the pinned engine does not resolve
//! `~` yet, so the two fixtures whose command wrote a home path carry the
//! resolved `fs_path` effectinterpsddr-91 will emit.
#![cfg(feature = "effinterp")]
// The fixture loader reads frozen JSON from disk; the crate itself stays pure.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use nah_effinterp::{annotate, request};
use nah_proto::action_v2::{EffectAnnotation, PathLabel};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    DescendantObservation, Observation, ObservationFact, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathKind, PathObservation, ProjectGuardDeclaration,
    ProjectGuardObservation, Root, RootKind,
};
use nah_proto::tool::CallSite;
use serde::Deserialize;

/// One frozen case: an effectinterp plan, the host facts nah observed for it,
/// and the annotation expected at each effect position.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnotationFixture {
    v: u32,
    context: ContextFixture,
    observation: ObservationFixture,
    plan: nah_effinterp::Plan,
    expected: Vec<EffectAnnotation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFixture {
    platform: Platform,
    home: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationFixture {
    cwd: String,
    roots: Vec<RootFixture>,
    paths: Vec<PathFixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFixture {
    kind: RootKind,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathFixture {
    requested: String,
    resolved: String,
    #[serde(default)]
    realpath: Option<String>,
    kind: PathKind,
    #[serde(default)]
    descendants: Vec<String>,
}

impl AnnotationFixture {
    fn load(name: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.json"));
        let fixture: Self = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|error| panic!("invalid fixture `{name}`: {error}"));
        assert_eq!(fixture.v, 1, "fixture `{name}` is not version 1");
        fixture
    }

    fn context(&self) -> Ctx {
        Ctx::new(
            self.context.platform,
            self.absolute(&self.context.home),
            vec![],
            vec![],
            TrustProjection::new(vec![]).unwrap(),
        )
        .unwrap()
    }

    fn absolute(&self, path: &str) -> AbsolutePath {
        AbsolutePath::new(self.context.platform, path).unwrap()
    }

    /// Answers the request nah derived from the plan with the frozen facts; a
    /// path query the fixture does not name is a fixture bug, not a miss.
    fn observation(&self, request: &ObservationRequest) -> Observation {
        let roots = self
            .observation
            .roots
            .iter()
            .map(|root| Root::new(root.kind, self.absolute(&root.path)))
            .collect::<Vec<_>>();
        let project = roots
            .iter()
            .find(|root| root.kind() == RootKind::Project)
            .cloned();
        let facts = request
            .queries()
            .iter()
            .cloned()
            .map(|query| {
                let value = match &query {
                    ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                        observed: Observed::Ok {
                            value: self.absolute(&self.observation.cwd),
                        },
                    },
                    ObservationQuery::Roots { .. } => ObservationValue::Roots {
                        observed: Observed::Ok {
                            value: roots.clone(),
                        },
                    },
                    ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                        observation: ProjectGuardObservation::new(
                            project.clone(),
                            ProjectGuardDeclaration::Absent,
                        )
                        .unwrap(),
                    },
                    ObservationQuery::Env { .. } => panic!("plan annotation reads no environment"),
                    ObservationQuery::Path {
                        requested,
                        inspect_descendants,
                        ..
                    } => {
                        let fixture = self
                            .observation
                            .paths
                            .iter()
                            .find(|path| &path.requested == requested)
                            .unwrap_or_else(|| panic!("fixture has no path `{requested}`"));
                        let mut value = PathObservation::new(
                            self.absolute(&fixture.resolved),
                            fixture.realpath.as_deref().map(|path| self.absolute(path)),
                            fixture.kind,
                        );
                        if *inspect_descendants {
                            value = value.with_descendants(
                                DescendantObservation::new(
                                    fixture
                                        .descendants
                                        .iter()
                                        .map(|path| self.absolute(path))
                                        .collect(),
                                    true,
                                )
                                .unwrap(),
                            );
                        }
                        ObservationValue::Path {
                            observed: Observed::Ok { value },
                        }
                    }
                };
                ObservationFact::new(query, value).unwrap()
            })
            .collect();
        Observation::new(SchemaVersion::V1, request.request_id(), facts).unwrap()
    }
}

fn annotations(
    name: &str,
    critical_paths: &[&str],
) -> (Vec<EffectAnnotation>, Vec<EffectAnnotation>) {
    let fixture = AnnotationFixture::load(name);
    let ctx = fixture.context();
    let critical_paths = critical_paths
        .iter()
        .map(|path| fixture.absolute(path))
        .collect::<Vec<_>>();
    let call_site = CallSite::new(fixture.context.platform, &fixture.observation.cwd).unwrap();
    let request = request(&fixture.plan, &call_site);
    let observation = fixture.observation(&request);
    observation
        .bind(&request)
        .unwrap_or_else(|error| panic!("fixture `{name}` observation does not bind: {error:?}"));
    (
        annotate(&fixture.plan, &observation, &ctx, &critical_paths),
        fixture.expected,
    )
}

fn assert_fixture(name: &str) {
    let (actual, expected) = annotations(name, &[]);
    assert_eq!(actual, expected, "{name}");
}

#[test]
fn recursive_home_delete_is_home_scoped_and_selects_home() {
    assert_fixture("rm-rf-home");
}

#[test]
fn project_dotenv_read_is_an_environment_secret() {
    assert_fixture("cat-dotenv");
}

#[test]
fn nah_trust_state_write_is_critical() {
    assert_fixture("write-nah-trust");
}

#[test]
fn runtime_hook_wiring_path_requires_the_critical_path_projection() {
    let path = "/home/test/.claude/hooks/nah";
    let (projected, expected) = annotations("write-claude-hook", &[path]);
    assert_eq!(projected, expected);

    let (unprojected, _) = annotations("write-claude-hook", &[]);
    assert!(matches!(
        unprojected.as_slice(),
        [EffectAnnotation {
            path: Some(PathLabel::Resolved {
                protection: None,
                ..
            }),
            runtime_cli: None,
        }]
    ));
}

#[test]
fn container_realm_effects_carry_no_labels_while_host_effects_do() {
    assert_fixture("docker-exec-and-host-rm");
}

#[test]
fn a_filesystem_target_without_host_context_is_unresolved() {
    assert_fixture("unresolved-dir");
}
