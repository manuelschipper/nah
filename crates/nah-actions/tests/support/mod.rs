#![allow(dead_code)]

use nah_actions::{AnalysisInput, SelfProtectionProjection, plan_with_self_protection};
use nah_parse::normalize;
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, PolicyVersion, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    DescendantObservation, EnvObservation, Observation, ObservationFact, ObservationFailure,
    ObservationQuery, ObservationRequest, ObservationValue, Observed, PathKind, PathObservation,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};

#[derive(Clone, Copy)]
pub(crate) enum Change {
    None,
    MissingPath,
    ChangedPath,
    ExtraEnv,
    CanonicalHomeAlias,
    AliasDirectory,
}

pub(crate) fn bash_plan(source: &str) -> nah_actions::AnalysisPlan {
    bash_plan_with_self_protection(source, SelfProtectionProjection::default())
}

pub(crate) fn bash_plan_with_self_protection(
    source: &str,
    self_protection: SelfProtectionProjection,
) -> nah_actions::AnalysisPlan {
    let syntax = normalize(source).unwrap();
    let input = nah_proto::tool::ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": source}),
        "/repo",
        None,
    )
    .unwrap();
    let call_site = input.call_site(Platform::Linux).unwrap();
    plan_with_self_protection(
        AnalysisInput::Bash(&syntax, &input),
        &ctx(),
        &call_site,
        &self_protection,
    )
}

pub(crate) fn ctx() -> Ctx {
    Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap()
}

pub(crate) fn observe(request: &ObservationRequest, env_program: &str) -> Observation {
    observe_with_descendants(request, env_program, &[], true)
}

pub(crate) fn observe_with_descendants(
    request: &ObservationRequest,
    env_program: &str,
    descendants: &[&str],
    complete: bool,
) -> Observation {
    let descendant_sets = [("", descendants)];
    observe_with_descendant_map(request, env_program, &descendant_sets, complete)
}

pub(crate) fn observe_with_descendant_map(
    request: &ObservationRequest,
    env_program: &str,
    descendant_sets: &[(&str, &[&str])],
    complete: bool,
) -> Observation {
    Observation::new(
        SchemaVersion::V1,
        request.request_id(),
        facts_with_descendants(
            request,
            env_program,
            Change::None,
            descendant_sets,
            complete,
        ),
    )
    .unwrap()
}

pub(crate) fn observe_with_descendant_error(request: &ObservationRequest) -> Observation {
    let facts = facts(request, "echo", Change::None)
        .into_iter()
        .map(|fact| {
            if matches!(
                fact.query(),
                ObservationQuery::Path {
                    inspect_descendants: true,
                    ..
                }
            ) {
                ObservationFact::new(
                    fact.query().clone(),
                    ObservationValue::Path {
                        observed: Observed::Error {
                            error: ObservationFailure::PermissionDenied,
                        },
                    },
                )
                .unwrap()
            } else {
                fact
            }
        })
        .collect();
    Observation::new(SchemaVersion::V1, request.request_id(), facts).unwrap()
}

pub(crate) fn observation_with(
    request: &ObservationRequest,
    request_id: &str,
    change: Change,
) -> Observation {
    Observation::new(
        SchemaVersion::V1,
        request_id,
        facts(request, "echo", change),
    )
    .unwrap()
}

pub(crate) fn facts(
    request: &ObservationRequest,
    env_program: &str,
    change: Change,
) -> Vec<ObservationFact> {
    facts_with_descendants(request, env_program, change, &[], true)
}

fn facts_with_descendants(
    request: &ObservationRequest,
    env_program: &str,
    change: Change,
    descendant_sets: &[(&str, &[&str])],
    descendants_complete: bool,
) -> Vec<ObservationFact> {
    let project = Root::new(RootKind::Project, absolute("/repo"));
    let mut facts = request
        .queries()
        .iter()
        .filter(|query| {
            !matches!(change, Change::MissingPath)
                || !matches!(query, ObservationQuery::Path { .. })
        })
        .cloned()
        .map(|mut query| {
            if matches!(change, Change::ChangedPath)
                && let ObservationQuery::Path { requested, .. } = &mut query
            {
                *requested = "/changed".into();
            }
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute("/repo"),
                    },
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![project.clone()],
                    },
                },
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Value {
                            text: if name == "TOOL" {
                                env_program.into()
                            } else {
                                "value".into()
                            },
                        },
                    },
                },
                ObservationQuery::Path {
                    requested,
                    inspect_descendants,
                    ..
                } => {
                    let realpath = matches!(change, Change::CanonicalHomeAlias)
                        .then(|| absolute("/private/home/test"));
                    let kind = if *inspect_descendants
                        || matches!(change, Change::AliasDirectory) && requested.ends_with("/alias")
                    {
                        PathKind::Directory
                    } else {
                        PathKind::Missing
                    };
                    let resolved = lexically_normalized(requested);
                    let mut value = PathObservation::new(absolute(&resolved), realpath, kind);
                    if *inspect_descendants {
                        let descendants = descendant_sets
                            .iter()
                            .find_map(|(target, paths)| {
                                (target.is_empty() || *target == requested).then_some(*paths)
                            })
                            .unwrap_or_default();
                        value = value.with_descendants(
                            DescendantObservation::new(
                                descendants.iter().map(|path| absolute(path)).collect(),
                                descendants_complete,
                            )
                            .unwrap(),
                        );
                    }
                    ObservationValue::Path {
                        observed: Observed::Ok { value },
                    }
                }
                ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        Some(project.clone()),
                        ProjectGuardDeclaration::Absent,
                    )
                    .unwrap(),
                },
            };
            ObservationFact::new(query, value).unwrap()
        })
        .collect::<Vec<_>>();
    if matches!(change, Change::ExtraEnv) {
        facts.push(
            ObservationFact::new(
                ObservationQuery::Env {
                    key: "extra".into(),
                    name: "EXTRA".into(),
                },
                ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Unset,
                    },
                },
            )
            .unwrap(),
        );
    }
    facts
}

pub(crate) fn absolute(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, value).unwrap()
}

fn lexically_normalized(value: &str) -> String {
    let mut normalized = std::path::PathBuf::new();
    for component in std::path::Path::new(value).components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    let normalized = normalized.to_string_lossy().into_owned();
    if normalized.is_empty() {
        "/".into()
    } else {
        normalized
    }
}
