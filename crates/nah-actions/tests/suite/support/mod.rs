#![allow(dead_code)]

use nah_actions::{AnalysisInput, SelfProtectionProjection, plan_with_self_protection};
use nah_parse::normalize;
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
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
    bash_plan_on(source, Platform::Linux)
}

pub(crate) fn bash_plan_on(source: &str, platform: Platform) -> nah_actions::AnalysisPlan {
    bash_plan_with_self_protection_on(source, SelfProtectionProjection::default(), platform)
}

pub(crate) fn bash_plan_with_self_protection(
    source: &str,
    self_protection: SelfProtectionProjection,
) -> nah_actions::AnalysisPlan {
    bash_plan_with_self_protection_on(source, self_protection, Platform::Linux)
}

fn bash_plan_with_self_protection_on(
    source: &str,
    self_protection: SelfProtectionProjection,
    platform: Platform,
) -> nah_actions::AnalysisPlan {
    let syntax = normalize(source).unwrap();
    let cwd = path_on(platform, "/repo");
    let input = nah_proto::tool::ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": source}),
        cwd,
        None,
    )
    .unwrap();
    let call_site = input.call_site(platform).unwrap();
    plan_with_self_protection(
        AnalysisInput::Bash(&syntax, &input),
        &ctx_on(platform),
        &call_site,
        &self_protection,
    )
}

pub(crate) fn ctx() -> Ctx {
    ctx_on(Platform::Linux)
}

fn ctx_on(platform: Platform) -> Ctx {
    Ctx::new(
        platform,
        absolute_on(platform, "/home/test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap()
}

pub(crate) fn observe(request: &ObservationRequest, env_program: &str) -> Observation {
    observe_on(request, env_program, Platform::Linux)
}

pub(crate) fn observe_on(
    request: &ObservationRequest,
    env_program: &str,
    platform: Platform,
) -> Observation {
    observe_with_descendants_on(request, env_program, &[], true, platform)
}

pub(crate) fn observe_with_descendants(
    request: &ObservationRequest,
    env_program: &str,
    descendants: &[&str],
    complete: bool,
) -> Observation {
    observe_with_descendants_on(request, env_program, descendants, complete, Platform::Linux)
}

fn observe_with_descendants_on(
    request: &ObservationRequest,
    env_program: &str,
    descendants: &[&str],
    complete: bool,
    platform: Platform,
) -> Observation {
    let descendant_sets = [("", descendants)];
    observe_with_descendant_map_on(request, env_program, &descendant_sets, complete, platform)
}

pub(crate) fn observe_with_descendant_map(
    request: &ObservationRequest,
    env_program: &str,
    descendant_sets: &[(&str, &[&str])],
    complete: bool,
) -> Observation {
    observe_with_descendant_map_on(
        request,
        env_program,
        descendant_sets,
        complete,
        Platform::Linux,
    )
}

fn observe_with_descendant_map_on(
    request: &ObservationRequest,
    env_program: &str,
    descendant_sets: &[(&str, &[&str])],
    complete: bool,
    platform: Platform,
) -> Observation {
    Observation::new(
        SchemaVersion::V1,
        request.request_id(),
        facts_with_descendants_on(
            request,
            env_program,
            Change::None,
            descendant_sets,
            complete,
            platform,
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

pub(crate) fn observe_with_path_error(
    request: &ObservationRequest,
    error: ObservationFailure,
) -> Observation {
    let facts = facts(request, "echo", Change::None)
        .into_iter()
        .map(|fact| {
            if matches!(fact.query(), ObservationQuery::Path { .. }) {
                ObservationFact::new(
                    fact.query().clone(),
                    ObservationValue::Path {
                        observed: Observed::Error { error },
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
    facts_with_descendants_on(
        request,
        env_program,
        change,
        descendant_sets,
        descendants_complete,
        Platform::Linux,
    )
}

fn facts_with_descendants_on(
    request: &ObservationRequest,
    env_program: &str,
    change: Change,
    descendant_sets: &[(&str, &[&str])],
    descendants_complete: bool,
    platform: Platform,
) -> Vec<ObservationFact> {
    let project = Root::new(RootKind::Project, absolute_on(platform, "/repo"));
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
                *requested = path_on(platform, "/changed");
            }
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute_on(platform, "/repo"),
                    },
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![project.clone()],
                    },
                },
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: if matches!(name.as_str(), "GIT_DIR" | "GIT_WORK_TREE") {
                            EnvObservation::Unset
                        } else {
                            EnvObservation::Value {
                                text: if name == "TOOL" {
                                    env_program.into()
                                } else {
                                    "value".into()
                                },
                            }
                        },
                    },
                },
                ObservationQuery::Path {
                    key,
                    requested,
                    inspect_descendants,
                    ..
                } => {
                    let resolved = lexically_normalized(platform, requested);
                    let child_cwd = key.starts_with("inline-child-cwd-");
                    let realpath = if child_cwd {
                        Some(absolute_on(platform, &resolved))
                    } else {
                        matches!(change, Change::CanonicalHomeAlias)
                            .then(|| absolute_on(platform, "/private/home/test"))
                    };
                    let kind = if child_cwd
                        || *inspect_descendants
                        || matches!(change, Change::AliasDirectory) && requested.ends_with("/alias")
                    {
                        PathKind::Directory
                    } else {
                        PathKind::Missing
                    };
                    let mut value =
                        PathObservation::new(absolute_on(platform, &resolved), realpath, kind);
                    if *inspect_descendants {
                        let descendants = descendant_sets
                            .iter()
                            .find_map(|(target, paths)| {
                                (target.is_empty() || *target == requested).then_some(*paths)
                            })
                            .unwrap_or_default();
                        value = value.with_descendants(
                            DescendantObservation::new(
                                descendants
                                    .iter()
                                    .map(|path| absolute_on(platform, path))
                                    .collect(),
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
    absolute_on(Platform::Linux, value)
}

fn absolute_on(platform: Platform, value: &str) -> AbsolutePath {
    AbsolutePath::new(platform, path_on(platform, value)).unwrap()
}

fn path_on(platform: Platform, value: &str) -> String {
    match platform {
        Platform::Windows if value.starts_with('/') => format!("C:{value}"),
        Platform::Linux | Platform::Macos if cfg!(windows) => value.replace('\\', "/"),
        _ => value.to_owned(),
    }
}

fn lexically_normalized(platform: Platform, value: &str) -> String {
    let value = value.replace('\\', "/");
    let (root, remainder) = match platform {
        Platform::Linux | Platform::Macos => ("/".to_owned(), value.trim_start_matches('/')),
        Platform::Windows if value.as_bytes().get(1) == Some(&b':') => {
            (value[..3].to_owned(), &value[3..])
        }
        Platform::Windows => ("//".to_owned(), value.trim_start_matches('/')),
    };
    let mut components = Vec::new();
    for component in remainder.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    format!("{root}{}", components.join("/"))
}
